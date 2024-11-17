use std::sync::Arc;

use axum::{
    debug_handler,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{event, span, Level};

use crate::{
    certificate_settings::CertificateClaims,
    ssh_ca::{CertificateOptions, SshCa},
};

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum CertType {
    Host,
    User,
}

#[derive(Deserialize)]
pub(super) struct SignKeyRequest {
    public_key: String,
    cert_type: CertType,
}

#[derive(Serialize)]
pub(super) struct SignedKeyResponse {
    certificate: String,
}

#[derive(Serialize)]
struct HttpError<'a> {
    error: &'a str,
}

fn log_error_response<ErrStr: AsRef<str>, Err: std::fmt::Display>(
    status_code: StatusCode,
    error: ErrStr,
) -> impl FnOnce(Err) -> Response {
    move |e| -> Response {
        let error = error.as_ref();
        event!(Level::ERROR, "{} ({}): {}", status_code, error, e);
        let body: Json<HttpError<'_>> = Json(HttpError { error });
        (status_code, body).into_response()
    }
}

fn error_response(status_code: StatusCode, error: &str) -> Response {
    event!(Level::ERROR, "{} ({})", status_code, error);
    let body: Json<HttpError<'_>> = Json(HttpError { error });
    (status_code, body).into_response()
}

#[debug_handler]
pub(super) async fn sign_key(
    claims: super::oidc::Claims<CertificateClaims>,
    State(state): State<Arc<super::state::AppState>>,
    Json(payload): Json<SignKeyRequest>,
) -> Result<impl IntoResponse, Response> {
    let span = span!(Level::TRACE, "sign_key");
    let _guard = span.enter();

    let client_public_key = ssh_key::PublicKey::from_openssh(&payload.public_key).map_err(
        log_error_response(StatusCode::BAD_REQUEST, "Not a valid ssh public key"),
    )?;

    let mut options = match payload.cert_type {
        CertType::Host => unimplemented!(),
        CertType::User => CertificateOptions::new_user(client_public_key),
    };

    let profile =
        state.config.profiles.lookup(&claims).ok_or_else(|| {
            error_response(StatusCode::FORBIDDEN, "No applicable profile for client")
        })?;
    profile
        .apply(&mut options, &claims)
        .map_err(log_error_response(
            StatusCode::FORBIDDEN,
            "No applicable profile for client",
        ))?;
    let ssh_ca = state
        .ssh_ca_providers
        .get(profile.ssh_ca())
        .ok_or_else(|| error_response(StatusCode::INTERNAL_SERVER_ERROR, "Provider unavailable"))?
        .clone();

    let certificate = ssh_ca
        .sign(&options)
        .await
        .map_err(log_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to generate certificate",
        ))?
        .to_openssh()
        .map_err(log_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to generate openssh certificate",
        ))?;

    Ok((StatusCode::OK, Json(SignedKeyResponse { certificate })))
}
