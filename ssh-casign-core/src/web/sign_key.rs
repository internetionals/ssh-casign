use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use ssh_casign_proto::{CertType, ErrorResponse, SignKeyRequest, SignedKeyResponse};

use ssh_casign_ca::{self as authority_crate, SignError, SignatureAlgorithm};

use crate::{
    audit,
    certificate::{
        key_id,
        policy::{self, Policies, Policy},
        profiles, template,
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

/// The client's accepted CA signature algorithms. Unknown names are ignored
/// (newer clients may know more), but naming only unknown ones is an error.
fn parse_signature_algorithms(
    names: Option<&[String]>,
) -> Result<Option<Vec<SignatureAlgorithm>>, Failure> {
    let Some(names) = names else {
        return Ok(None);
    };
    let known: Vec<_> = names
        .iter()
        .filter_map(|name| SignatureAlgorithm::parse(name))
        .collect();
    if known.is_empty() {
        return Err(Failure::new(
            StatusCode::BAD_REQUEST,
            format!("no known CA signature algorithm in [{}]", names.join(", ")),
        ));
    }
    Ok(Some(known))
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
    /// The certificate as handed out (for `ssh-rsa`, only this has the real
    /// SHA-1 signature).
    openssh: String,
    /// The certificate's fields.
    certificate: ssh_key::Certificate,
    authority: String,
    fingerprint: String,
    key_type: String,
    signature_algorithm: String,
    /// Other owners the key is also certified for.
    shared_with: Vec<String>,
}

pub(super) async fn sign_key(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    auth: super::oidc::Authenticated,
    State(state): State<Arc<super::state::AppState>>,
    Json(payload): Json<SignKeyRequest>,
) -> Response {
    let request_id = audit::new_request_id();
    let mut context = Context {
        app_name: payload.app_name.clone(),
        ..Context::default()
    };
    let result = issue(&state, &auth, payload, &mut context).await;
    let claims = &auth.claims;

    let origin = state.origin.resolve(peer, &headers);
    let requester = audit::Requester {
        request_id: &request_id,
        client_ip: origin.client_ip,
        client_port: origin.client_port,
        proxy: origin.proxy,
        correlation_id: origin.correlation_id.as_deref(),
        issuer: &auth.issuer.issuer,
        subject: claims.get("sub").and_then(|sub| sub.as_str()),
        oidc_id: context.oidc_id.as_deref(),
        profile: context.profile.as_deref(),
        app_name: context.app_name.as_deref(),
    };

    let response = match result {
        Ok(issued) => match record_index(&state, &auth, &requester, &issued).await {
            Err(err) => {
                // Fail closed: without its index entry, the owner couldn't
                // find (and revoke) the certificate.
                tracing::error!(
                    request_id,
                    "issuance index failed, certificate withheld: {err}"
                );
                failure_response(&Failure::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Issuance index unavailable",
                ))
            }
            Ok(()) => match record_issued(&state, &requester, &issued).await {
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
    auth: &super::oidc::Authenticated,
    payload: SignKeyRequest,
    context: &mut Context,
) -> Result<Certificate, Failure> {
    let claims = &auth.claims;
    let client_public_key = ssh_key::PublicKey::from_openssh(&payload.public_key)
        .map_err(|_| Failure::new(StatusCode::BAD_REQUEST, "Not a valid ssh public key"))?;

    let requested_type = payload.cert_type;
    let cert_type = match requested_type {
        CertType::Host => ssh_key::certificate::CertType::Host,
        CertType::User => ssh_key::certificate::CertType::User,
    };
    let host = requested_type == CertType::Host;

    let accepted_algorithms =
        parse_signature_algorithms(payload.ca_signature_algorithms.as_deref())?;
    let oidc_id = key_id::oidc_id(claims, &auth.issuer.id_claim)
        .map_err(|err| Failure::new(StatusCode::FORBIDDEN, err.to_string()))?;
    context.oidc_id = Some(oidc_id.clone());
    let profile = state
        .config
        .profiles
        .lookup(&auth.issuer.name, claims, requested_type)
        .ok_or_else(|| {
            Failure::new(
                StatusCode::FORBIDDEN,
                format!(
                    "No profile issues {} certificates for this client",
                    profiles::cert_type_name(requested_type)
                ),
            )
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
    // Only issuers trusted with it may set policy through claims.
    let token_policy: Policy = if auth.issuer.token_policy {
        serde_json::from_value(serde_json::Value::Object(claims.clone())).map_err(|err| {
            Failure::new(
                StatusCode::FORBIDDEN,
                format!("Invalid certificate claims in token: {err}"),
            )
        })?
    } else {
        Policy::default()
    };
    let (profile_policy, token_policy, principals) = if host {
        let lowercase = |names: Vec<String>| names.iter().map(|name| name.to_lowercase()).collect();
        (
            profile_policy.for_host(),
            token_policy.for_host(),
            payload.principals.map(lowercase),
        )
    } else {
        (profile_policy, token_policy, payload.principals)
    };
    let request = policy::Request {
        validity: payload.validity,
        principals,
        extensions: payload.extensions,
        critical_options: payload.critical_options,
        app_name: payload.app_name,
        comment: payload.comment,
    };
    let policies = Policies {
        token: &token_policy,
        profile: &profile_policy,
    };
    policies
        .check_public_key(&client_public_key)
        .map_err(|err| Failure::new(StatusCode::FORBIDDEN, err.to_string()))?;
    let revocations = state.revocations.current();
    if revocations.key_revoked(&client_public_key) {
        return Err(Failure::new(StatusCode::FORBIDDEN, "This key is revoked"));
    }
    if let Err(weakness) = state.key_checks.check(client_public_key.key_data()) {
        return Err(Failure::new(
            StatusCode::FORBIDDEN,
            format!("Weak key: {weakness}"),
        ));
    }
    let fingerprint = client_public_key
        .fingerprint(Default::default())
        .to_string();
    let shared_with = shared_with(state, auth, &oidc_id, &fingerprint).await?;
    let resolved = policies.resolve(&request, cert_type).map_err(|err| {
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
    let key_type = client_public_key.algorithm().as_str().to_string();
    let (authority, provider, algorithm) = authority_crate::select(
        profile.settings.authorities(),
        &state.authorities,
        requested_type,
        accepted_algorithms.as_deref(),
    )
    .map_err(|err| {
        Failure::new(
            StatusCode::FORBIDDEN,
            format!("profile {}: {err}", profile.name),
        )
    })?;
    // A certificate with a revoked key ID would be refused everywhere.
    if revocations.key_id_revoked(authority, &key_id) {
        return Err(Failure::new(
            StatusCode::FORBIDDEN,
            format!("Key ID {key_id} is revoked"),
        ));
    }
    let options = resolved.into_options(client_public_key, cert_type, serial, key_id);

    let signed = provider.issue(&options, algorithm).await?;
    let (certificate, openssh) = (signed.certificate, signed.openssh);
    Ok(Certificate {
        openssh,
        certificate,
        authority: authority.to_string(),
        fingerprint,
        key_type,
        signature_algorithm: algorithm.to_string(),
        shared_with,
    })
}

/// Other owners this key is already certified for, per `key_checks.duplicates`:
/// `deny` refuses, `warn` logs and returns them for the audit record.
async fn shared_with(
    state: &super::state::AppState,
    auth: &super::oidc::Authenticated,
    oidc_id: &str,
    fingerprint: &str,
) -> Result<Vec<String>, Failure> {
    use crate::key_checks::Duplicates;
    let (Some(store), mode) = (&state.index, state.duplicates) else {
        return Ok(Vec::new());
    };
    if mode == Duplicates::Allow {
        return Ok(Vec::new());
    }
    let owners = match crate::index::key_owners(store.as_ref(), fingerprint).await {
        Ok(owners) => owners,
        Err(err) if mode == Duplicates::Deny => {
            return Err(Failure::internal("Issuance index unavailable", err));
        }
        Err(err) => {
            tracing::warn!("duplicate key check skipped: {err}");
            return Ok(Vec::new());
        }
    };
    let others: Vec<String> = owners
        .into_iter()
        .filter(|owner| owner.issuer != auth.issuer.issuer || owner.id != oidc_id)
        .map(|owner| format!("{} {}", owner.issuer, owner.id))
        .collect();
    if others.is_empty() {
        return Ok(others);
    }
    if mode == Duplicates::Deny {
        return Err(Failure::new(
            StatusCode::FORBIDDEN,
            "This key is already certified for another identity; use a key of your own",
        ));
    }
    tracing::warn!(
        "key {fingerprint} of {oidc_id} is also certified for {}",
        others.join(", ")
    );
    Ok(others)
}

/// Record the certificate in the issuance index, when it is on.
async fn record_index(
    state: &super::state::AppState,
    auth: &super::oidc::Authenticated,
    requester: &audit::Requester<'_>,
    issued: &Certificate,
) -> Result<(), ssh_casign_store::StoreError> {
    let Some(store) = &state.index else {
        return Ok(());
    };
    let certificate = &issued.certificate;
    let entry = ssh_casign_proto::revoke::IssuedCertificate {
        serial: certificate.serial().to_string(),
        authority: issued.authority.clone(),
        key_id: certificate.key_id().to_string(),
        cert_type: match certificate.cert_type() {
            ssh_key::certificate::CertType::Host => CertType::Host,
            ssh_key::certificate::CertType::User => CertType::User,
        },
        principals: certificate.valid_principals().to_vec(),
        valid_after: certificate.valid_after(),
        valid_before: certificate.valid_before(),
        fingerprint: issued.fingerprint.clone(),
        profile: requester.profile.unwrap_or_default().to_string(),
        app_name: requester.app_name.map(str::to_string),
        client_address: Some(requester.client_ip.to_string()),
        owner: ssh_casign_proto::revoke::Owner {
            issuer: auth.issuer.issuer.clone(),
            id: requester.oidc_id.unwrap_or_default().to_string(),
        },
        revoked: false,
    };
    crate::index::record(store.as_ref(), &entry).await?;
    crate::index::record_key_owner(store.as_ref(), &issued.fingerprint, &entry.owner).await
}

async fn record_issued(
    state: &super::state::AppState,
    requester: &audit::Requester<'_>,
    issued: &Certificate,
) -> std::io::Result<()> {
    let certificate = &issued.certificate;
    tracing::info!(
        request_id = requester.request_id,
        correlation_id = requester.correlation_id,
        serial = certificate.serial(),
        key_id = certificate.key_id(),
        profile = requester.profile,
        authority = issued.authority,
        principals = %certificate.valid_principals().join(","),
        validity_secs = certificate.valid_before() - certificate.valid_after(),
        fingerprint = issued.fingerprint,
        signature_algorithm = issued.signature_algorithm,
        "issued certificate"
    );
    let Some(log) = &state.audit else {
        return Ok(());
    };
    let event = audit::Event {
        server_id: &state.server_id,
        requester,
        outcome: audit::Outcome::Issued(audit::Issued {
            shared_with: &issued.shared_with,
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
            key_type: &issued.key_type,
            signature_algorithm: &issued.signature_algorithm,
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
