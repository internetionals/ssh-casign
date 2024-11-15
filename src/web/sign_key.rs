use std::{collections::HashMap, sync::Arc};

use axum::{
    debug_handler,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{event, span, Level};

#[derive(Debug, Deserialize)]
pub(crate) struct SignKeyClaims {
    pub(crate) validity: Option<u64>,
    pub(crate) key_id: Option<String>,
    pub(crate) valid_principals: Vec<String>,
    pub(crate) comment: Option<String>,
    pub(crate) critical_options: Option<HashMap<String, String>>,
    pub(crate) extensions: Option<HashMap<String, String>>,

    #[serde(flatten)]
    pub(crate) other: HashMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
pub(super) struct SignKeyRequest {
    public_key: String,
}

#[derive(Serialize)]
pub(super) struct SignedKeyResponse {
    certificate: String,
}

#[derive(Serialize)]
struct HttpError<'a> {
    error: &'a str,
}

fn http_error<ErrStr: AsRef<str>, Err: std::fmt::Display>(
    status_code: axum::http::StatusCode,
    error: ErrStr,
) -> impl FnOnce(Err) -> Response {
    move |e| -> Response {
        event!(Level::ERROR, "{} ({}): {}", status_code, error.as_ref(), e);
        (
            status_code,
            Json(HttpError {
                error: error.as_ref(),
            }),
        )
            .into_response()
    }
}

#[allow(dead_code)]
fn log_http_error<T: std::fmt::Display>(e: T) -> Response {
    event!(Level::ERROR, "Internal server error: {}", e);
    (StatusCode::INTERNAL_SERVER_ERROR, ()).into_response()
}

#[debug_handler]
pub(super) async fn sign_key(
    claims: super::oidc::Claims<SignKeyClaims>,
    State(state): State<Arc<super::state::AppState>>,
    Json(payload): Json<SignKeyRequest>,
) -> Result<impl IntoResponse, Response> {
    let span = span!(Level::TRACE, "sign_key");
    let _guard = span.enter();

    let client_public_key = ssh_key::PublicKey::from_openssh(&payload.public_key).map_err(
        http_error(StatusCode::BAD_REQUEST, "Not a valid ssh public key"),
    )?;

    let Some(profile) = state.config.profiles.lookup(&claims) else {
        return Err((
            StatusCode::FORBIDDEN,
            Json(HttpError {
                error: "No profile for client",
            }),
        )
            .into_response());
    };

    let sign_options = profile.sign_options(&claims).map_err(http_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Unable to apply certificate settings",
    ))?;
    let ssh_ca = state.ssh_ca.clone();
    let certificate = ssh_ca
        .sign(client_public_key, sign_options)
        .await
        .map_err(http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to generate certificate",
        ))?
        .to_openssh()
        .map_err(http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to generate openssh certificate",
        ))?;

    Ok((StatusCode::OK, Json(SignedKeyResponse { certificate })))
}
