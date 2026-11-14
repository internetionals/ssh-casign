use std::{ops::Deref, sync::Arc};

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    RequestPartsExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use oidc_jwt_validator::Validator;
use serde::Deserialize;

use super::state::AppState;

fn default_scopes() -> Vec<String> {
    vec!["openid".to_string()]
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// OpenID Connect issuer. Must match the `iss` claim of the tokens exactly.
    #[serde(alias = "url")]
    issuer: String,
    /// OAuth client ID that clients authenticate as. Published through the
    /// discovery document.
    client_id: String,
    /// Scopes clients should request. Published through the discovery document.
    #[serde(default = "default_scopes")]
    scopes: Vec<String>,
    /// Accepted values of the `aud` claim. Defaults to `[client_id]`, which is
    /// what ID tokens carry.
    audience: Option<Vec<String>>,
    /// Claim that identifies the user or client in the key ID (`{{oidc_id}}`).
    /// It must be unique and traceable by the IdP maintainer: `sub` (default),
    /// a UPN, a UUID or a pseudonymous ID.
    #[serde(default = "default_id_claim")]
    id_claim: String,
}

fn default_id_claim() -> String {
    "sub".to_string()
}

impl Config {
    pub(crate) fn issuer(&self) -> &str {
        &self.issuer
    }

    pub(crate) fn client_id(&self) -> &str {
        &self.client_id
    }

    pub(crate) fn id_claim(&self) -> &str {
        &self.id_claim
    }

    pub(crate) fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub(crate) async fn get_validator(&self) -> Result<Validator, Box<dyn std::error::Error>> {
        let http_client = reqwest::ClientBuilder::new().build()?;
        let mut validation_settings = oidc_jwt_validator::ValidationSettings::new();
        // Without listing them as required, `iss` and `aud` are only checked
        // when the token happens to contain them.
        validation_settings.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation_settings.validate_nbf = true;
        validation_settings.set_issuer(&[self.issuer.as_str()]);
        match &self.audience {
            Some(audience) => validation_settings.set_audience(audience),
            None => validation_settings.set_audience(&[self.client_id.as_str()]),
        }
        let validator = Validator::new(
            self.issuer.as_str(),
            http_client,
            oidc_jwt_validator::cache::Strategy::Automatic,
            validation_settings,
        )
        .await
        .map_err(|err| format!("OpenID Connect provider {}: {err}", self.issuer))?;
        Ok(validator)
    }
}

/// Claims<T> can be used to require OpenID Connect authorization
/// The supplied struct can be used to fetch possible relevant OpenID Connect claims
///
/// Usage: `async fn some_axum_handler(claims: Claims<MyClaims>)`
#[derive(Debug)]
pub(super) struct Claims<T: for<'de> Deserialize<'de>>(T);

impl<T: for<'de> Deserialize<'de>> Deref for Claims<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub(super) enum AuthError {
    InvalidToken(String),
}

/// Make `value` safe to use inside a quoted-string header parameter.
fn quote_header_param(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .flat_map(|c| match c {
            '"' | '\\' => vec!['\\', c],
            c => vec![c],
        })
        .collect()
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        match self {
            AuthError::InvalidToken(msg) => {
                tracing::info!("rejected token: {msg}");
                let challenge = format!(
                    r#"Bearer realm="ssh-casign", error="invalid_token", error_description="{}""#,
                    quote_header_param(&msg)
                );
                let challenge = HeaderValue::from_str(&challenge).unwrap_or_else(|_| {
                    HeaderValue::from_static(r#"Bearer realm="ssh-casign", error="invalid_token""#)
                });
                (
                    StatusCode::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, challenge)],
                )
                    .into_response()
            }
        }
    }
}

#[axum::async_trait]
impl<S, T: for<'de> Deserialize<'de>> FromRequestParts<S> for Claims<T>
where
    // Arc<Validator>: FromRef<S>,
    Arc<AppState>: FromRef<S>,
    S: Send + Sync,
{
    // If anything goes wrong or no session is found, redirect to the auth page
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|err| AuthError::InvalidToken(err.to_string()))?;

        // Validate token
        let state = Arc::<AppState>::from_ref(state);
        let token_data = state
            .oidc_validator
            .validate::<T>(bearer.token())
            .await
            .map_err(|err| AuthError::InvalidToken(err.to_string()))?;

        // Return claims
        Ok(Claims(token_data.claims))
    }
}
