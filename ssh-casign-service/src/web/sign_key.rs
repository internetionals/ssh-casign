use std::sync::Arc;

use axum::{
    debug_handler,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use ssh_casign_proto::{CertType, ErrorResponse, SignKeyRequest, SignedKeyResponse};
use tracing::{event, span, Level};

use crate::{
    authority::{SignError, Signer},
    certificate::{
        key_id,
        policy::{self, Policies, Policy},
        profiles::TokenClaims,
        template,
    },
};

fn error_response(status_code: StatusCode, error: &str) -> Response {
    let level_error = status_code.is_server_error();
    if level_error {
        event!(Level::ERROR, "{} ({})", status_code, error);
    } else {
        event!(Level::INFO, "{} ({})", status_code, error);
    }
    let body = Json(ErrorResponse {
        error: error.to_string(),
    });
    (status_code, body).into_response()
}

fn log_error_response<Err: std::fmt::Display>(
    status_code: StatusCode,
    error: &'static str,
) -> impl FnOnce(Err) -> Response {
    move |e| {
        event!(Level::ERROR, "{}: {}", error, e);
        error_response(status_code, error)
    }
}

fn sign_error_response(err: SignError) -> Response {
    match err {
        SignError::UnsupportedCertType => log_error_response(
            StatusCode::FORBIDDEN,
            "Certificate type not supported by the authority",
        )(err),
        SignError::NoPrincipals => {
            log_error_response(StatusCode::FORBIDDEN, "No principals for client")(err)
        }
        err => log_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to generate certificate",
        )(err),
    }
}

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

#[debug_handler]
pub(super) async fn sign_key(
    claims: super::oidc::Claims<TokenClaims>,
    State(state): State<Arc<super::state::AppState>>,
    Json(payload): Json<SignKeyRequest>,
) -> Result<impl IntoResponse, Response> {
    let span = span!(Level::TRACE, "sign_key");
    let _guard = span.enter();

    let client_public_key = ssh_key::PublicKey::from_openssh(&payload.public_key).map_err(
        log_error_response(StatusCode::BAD_REQUEST, "Not a valid ssh public key"),
    )?;

    let cert_type = match payload.cert_type {
        // Issuing host certificates based on a user login needs its own trust
        // model; refuse until that is designed.
        CertType::Host => {
            return Err(error_response(
                StatusCode::NOT_IMPLEMENTED,
                "Host certificates are not supported yet",
            ))
        }
        CertType::User => ssh_key::certificate::CertType::User,
    };

    let profile =
        state.config.profiles.lookup(&claims).ok_or_else(|| {
            error_response(StatusCode::FORBIDDEN, "No applicable profile for client")
        })?;
    let oidc_id = key_id::oidc_id(&claims, state.config.oidc_provider.id_claim())
        .map_err(|err| error_response(StatusCode::FORBIDDEN, &err.to_string()))?;
    let template_context = |app_name, serial| template::Context {
        server_id: &state.server_id,
        profile: profile.name,
        oidc_id: &oidc_id,
        app_name,
        serial,
        claims: &claims,
    };
    let profile_policy = profile.settings.policy_for(&template_context(None, None));
    let token_policy: Policy = serde_json::from_value(serde_json::Value::Object((*claims).clone()))
        .map_err(|err| {
            error_response(
                StatusCode::FORBIDDEN,
                &format!("Invalid certificate claims in token: {err}"),
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
        error_response(StatusCode::FORBIDDEN, &message)
    })?;
    let serial = new_serial();
    let key_id = profile
        .settings
        .key_id()
        .render(&template_context(
            resolved.app_name.as_deref(),
            Some(serial),
        ))
        .map_err(|err| error_response(StatusCode::FORBIDDEN, &err.to_string()))?;
    let fingerprint = client_public_key.fingerprint(Default::default());
    let principals = resolved.principals.join(",");
    let validity = resolved.validity;
    let options = resolved.into_options(client_public_key, cert_type, serial, key_id.clone());
    let provider = state
        .authorities
        .get(profile.settings.ssh_ca())
        .ok_or_else(|| error_response(StatusCode::INTERNAL_SERVER_ERROR, "Provider unavailable"))?
        .clone();

    let certificate = provider
        .sign(&options)
        .await
        .map_err(sign_error_response)?
        .to_openssh()
        .map_err(log_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to generate openssh certificate",
        ))?;

    // Audit trail: everything needed to trace a certificate seen in sshd logs.
    tracing::info!(
        serial,
        key_id = %key_id,
        profile = profile.name,
        authority = profile.settings.ssh_ca(),
        principals = %principals,
        validity_secs = validity,
        fingerprint = %fingerprint,
        "issued certificate"
    );
    Ok((StatusCode::OK, Json(SignedKeyResponse { certificate })))
}
