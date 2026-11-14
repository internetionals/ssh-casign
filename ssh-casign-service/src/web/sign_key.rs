use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use ssh_casign_proto::{CertType, ErrorResponse, SignKeyRequest, SignedKeyResponse};

use crate::{
    audit,
    authority::{SignError, Signer},
    certificate::{
        key_id,
        policy::{self, Policies, Policy},
        profiles::TokenClaims,
        template,
    },
};

const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Random, non-zero serial number. With 64 random bits, collisions are not a
/// practical concern, and nothing has to be coordinated between instances.
fn new_serial() -> u64 {
    loop {
        let serial = rand::random::<u64>();
        if serial != 0 {
            return serial;
        }
    }
}

/// A request that didn't result in a certificate.
struct Failure {
    status: StatusCode,
    /// Shown to the client and recorded.
    message: String,
    /// Logged only (server errors may carry internal details).
    detail: Option<String>,
}

impl Failure {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            detail: None,
        }
    }

    fn internal(message: &str, detail: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.to_string(),
            detail: Some(detail.to_string()),
        }
    }
}

impl From<SignError> for Failure {
    fn from(err: SignError) -> Self {
        match err {
            SignError::UnsupportedCertType => Failure::new(
                StatusCode::FORBIDDEN,
                "Certificate type not supported by the authority",
            ),
            SignError::NoPrincipals => {
                Failure::new(StatusCode::FORBIDDEN, "No principals for client")
            }
            err => Failure::internal("Failed to generate certificate", err),
        }
    }
}

/// What the request resolved to, as far as it got; used for the audit record.
#[derive(Default)]
struct Context {
    oidc_id: Option<String>,
    profile: Option<String>,
    app_name: Option<String>,
}

/// An issued certificate and the details the audit record needs.
struct Certificate {
    openssh: String,
    certificate: ssh_key::Certificate,
    authority: String,
    fingerprint: String,
}

pub(super) async fn sign_key(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    claims: super::oidc::Claims<TokenClaims>,
    State(state): State<Arc<super::state::AppState>>,
    Json(payload): Json<SignKeyRequest>,
) -> Response {
    let request_id = audit::new_request_id();
    let mut context = Context {
        app_name: payload.app_name.clone(),
        ..Context::default()
    };
    let result = issue(&state, &claims, payload, &mut context).await;

    let client_address_header = state
        .config
        .audit
        .as_ref()
        .and_then(|audit| audit.client_address_header.as_deref());
    let (client_ip, client_port) = audit::client_address(peer, client_address_header, &headers);
    let requester = audit::Requester {
        request_id: &request_id,
        client_ip,
        client_port,
        issuer: state.config.oidc_provider.issuer(),
        subject: claims.get("sub").and_then(|sub| sub.as_str()),
        oidc_id: context.oidc_id.as_deref(),
        profile: context.profile.as_deref(),
        app_name: context.app_name.as_deref(),
    };

    let response = match result {
        Ok(issued) => match record_issued(&state, &requester, &issued).await {
            Ok(()) => (
                StatusCode::OK,
                Json(SignedKeyResponse {
                    certificate: issued.openssh,
                }),
            )
                .into_response(),
            Err(err) => {
                // Fail closed: no certificate without its audit record.
                tracing::error!(request_id, "audit log failed, certificate withheld: {err}");
                failure_response(&Failure::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Audit log unavailable",
                ))
            }
        },
        Err(failure) => {
            log_failure(&request_id, &failure);
            record_denied(&state, &requester, &failure).await;
            failure_response(&failure)
        }
    };
    with_request_id(response, &request_id)
}

async fn issue(
    state: &super::state::AppState,
    claims: &TokenClaims,
    payload: SignKeyRequest,
    context: &mut Context,
) -> Result<Certificate, Failure> {
    let client_public_key = ssh_key::PublicKey::from_openssh(&payload.public_key)
        .map_err(|_| Failure::new(StatusCode::BAD_REQUEST, "Not a valid ssh public key"))?;

    let cert_type = match payload.cert_type {
        // Issuing host certificates based on a user login needs its own trust
        // model; refuse until that is designed.
        CertType::Host => {
            return Err(Failure::new(
                StatusCode::NOT_IMPLEMENTED,
                "Host certificates are not supported yet",
            ))
        }
        CertType::User => ssh_key::certificate::CertType::User,
    };

    let oidc_id = key_id::oidc_id(claims, state.config.oidc_provider.id_claim())
        .map_err(|err| Failure::new(StatusCode::FORBIDDEN, err.to_string()))?;
    context.oidc_id = Some(oidc_id.clone());
    let profile =
        state.config.profiles.lookup(claims).ok_or_else(|| {
            Failure::new(StatusCode::FORBIDDEN, "No applicable profile for client")
        })?;
    context.profile = Some(profile.name.to_string());

    let template_context = |app_name, serial| template::Context {
        server_id: &state.server_id,
        profile: profile.name,
        oidc_id: &oidc_id,
        app_name,
        serial,
        claims,
    };
    let profile_policy = profile.settings.policy_for(&template_context(None, None));
    let token_policy: Policy = serde_json::from_value(serde_json::Value::Object(claims.clone()))
        .map_err(|err| {
            Failure::new(
                StatusCode::FORBIDDEN,
                format!("Invalid certificate claims in token: {err}"),
            )
        })?;
    let request = policy::Request {
        validity: payload.validity,
        principals: payload.principals,
        extensions: payload.extensions,
        critical_options: payload.critical_options,
        app_name: payload.app_name,
        comment: payload.comment,
    };
    let resolved = Policies {
        token: &token_policy,
        profile: &profile_policy,
    }
    .resolve(&request, cert_type)
    .map_err(|err| {
        let message = err.to_string();
        if matches!(err, policy::Error::Conflict(_) | policy::Error::NoValidity) {
            tracing::warn!("policy conflict for profile {}: {message}", profile.name);
        }
        Failure::new(StatusCode::FORBIDDEN, message)
    })?;

    let serial = new_serial();
    let key_id = profile
        .settings
        .key_id()
        .render(&template_context(
            resolved.app_name.as_deref(),
            Some(serial),
        ))
        .map_err(|err| Failure::new(StatusCode::FORBIDDEN, err.to_string()))?;
    let fingerprint = client_public_key
        .fingerprint(Default::default())
        .to_string();
    let options = resolved.into_options(client_public_key, cert_type, serial, key_id);
    let authority = profile.settings.ssh_ca();
    let provider = state
        .authorities
        .get(authority)
        .ok_or_else(|| {
            Failure::internal("Provider unavailable", format!("no authority {authority}"))
        })?
        .clone();

    let certificate = provider.sign(&options).await?;
    let openssh = certificate
        .to_openssh()
        .map_err(|err| Failure::internal("Failed to generate openssh certificate", err))?;
    Ok(Certificate {
        openssh,
        certificate,
        authority: authority.to_string(),
        fingerprint,
    })
}

async fn record_issued(
    state: &super::state::AppState,
    requester: &audit::Requester<'_>,
    issued: &Certificate,
) -> std::io::Result<()> {
    let certificate = &issued.certificate;
    tracing::info!(
        request_id = requester.request_id,
        serial = certificate.serial(),
        key_id = certificate.key_id(),
        profile = requester.profile,
        authority = issued.authority,
        principals = %certificate.valid_principals().join(","),
        validity_secs = certificate.valid_before() - certificate.valid_after(),
        fingerprint = issued.fingerprint,
        "issued certificate"
    );
    let Some(log) = &state.audit else {
        return Ok(());
    };
    let event = audit::Event {
        server_id: &state.server_id,
        requester,
        outcome: audit::Outcome::Issued(audit::Issued {
            serial: certificate.serial(),
            key_id: certificate.key_id(),
            authority: &issued.authority,
            cert_type: match certificate.cert_type() {
                ssh_key::certificate::CertType::Host => "host",
                ssh_key::certificate::CertType::User => "user",
            },
            principals: certificate.valid_principals(),
            valid_after: certificate.valid_after(),
            valid_before: certificate.valid_before(),
            extensions: certificate
                .extensions()
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect(),
            critical_options: certificate
                .critical_options()
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect(),
            public_key_fingerprint: issued.fingerprint.clone(),
            certificate: &issued.openssh,
        }),
    };
    log.record(&event).await
}

/// Record a denial of an authenticated request. Best effort: the request
/// fails anyway.
async fn record_denied(
    state: &super::state::AppState,
    requester: &audit::Requester<'_>,
    failure: &Failure,
) {
    let Some(log) = state.audit.as_ref().filter(|log| log.records_denials()) else {
        return;
    };
    let event = audit::Event {
        server_id: &state.server_id,
        requester,
        outcome: audit::Outcome::Denied {
            status: failure.status.as_u16(),
            reason: &failure.message,
        },
    };
    if let Err(err) = log.record(&event).await {
        tracing::error!(request_id = requester.request_id, "audit log failed: {err}");
    }
}

fn log_failure(request_id: &str, failure: &Failure) {
    match &failure.detail {
        Some(detail) => tracing::error!(
            request_id,
            "{} ({}): {detail}",
            failure.status,
            failure.message
        ),
        None if failure.status.is_server_error() => {
            tracing::error!(request_id, "{} ({})", failure.status, failure.message)
        }
        None => tracing::info!(request_id, "{} ({})", failure.status, failure.message),
    }
}

fn failure_response(failure: &Failure) -> Response {
    (
        failure.status,
        Json(ErrorResponse {
            error: failure.message.clone(),
        }),
    )
        .into_response()
}

fn with_request_id(mut response: Response, request_id: &str) -> Response {
    if let Ok(value) = HeaderValue::from_str(request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}
