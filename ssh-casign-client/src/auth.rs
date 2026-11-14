use color_eyre::eyre::{bail, eyre, WrapErr};
use serde::Deserialize;
use url::Url;

use crate::{config::SignInMethod, error::Result};

mod authorization_code;
mod device;

/// Environment variable with a ready-made bearer token. Skips the sign-in
/// flow; meant for testing and automation.
pub(crate) const TOKEN_ENV: &str = "SSH_CASIGN_TOKEN";

/// The parts of the OpenID Connect discovery document the client needs.
#[derive(Debug, Deserialize)]
struct ProviderMetadata {
    issuer: String,
    token_endpoint: Url,
    authorization_endpoint: Option<Url>,
    device_authorization_endpoint: Option<Url>,
}

impl ProviderMetadata {
    async fn discover(http: &reqwest::Client, issuer: &str) -> Result<Self> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let metadata: Self = http
            .get(&url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .wrap_err_with(|| format!("Failed to fetch OpenID Connect configuration {url}"))?
            .json()
            .await
            .wrap_err_with(|| format!("Invalid OpenID Connect configuration {url}"))?;
        if metadata.issuer != issuer {
            bail!(
                "OpenID Connect configuration {url} is for issuer {}, expected {issuer}",
                metadata.issuer
            );
        }
        Ok(metadata)
    }
}

/// What the client needs to know to sign the user in.
pub(crate) struct SignInRequest<'a> {
    pub(crate) method: SignInMethod,
    pub(crate) issuer: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) scopes: &'a [String],
}

/// Successful token endpoint response.
#[derive(Debug, Deserialize)]
pub(crate) struct TokenResponse {
    access_token: String,
    id_token: Option<String>,
}

impl TokenResponse {
    /// The token to present to the service. The ID token is preferred: its
    /// audience is the client ID (what the service checks by default), and
    /// unlike access tokens it is always a JWT.
    fn into_bearer(self) -> String {
        self.id_token.unwrap_or(self.access_token)
    }
}

/// OAuth 2.0 error response (RFC 6749 section 5.2).
#[derive(Debug, Deserialize)]
pub(crate) struct OAuthError {
    error: String,
    error_description: Option<String>,
}

impl OAuthError {
    async fn from_response(response: reqwest::Response) -> Self {
        let status = response.status();
        response.json().await.unwrap_or_else(|_| Self {
            error: status.to_string(),
            error_description: None,
        })
    }
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.error_description {
            Some(description) => write!(f, "{} ({description})", self.error),
            None => write!(f, "{}", self.error),
        }
    }
}

/// Sign the user in and return the bearer token for the service.
pub(crate) async fn sign_in(http: &reqwest::Client, request: &SignInRequest<'_>) -> Result<String> {
    if let Ok(token) = std::env::var(TOKEN_ENV) {
        tracing::debug!("using token from {TOKEN_ENV}");
        return Ok(token);
    }

    let provider = ProviderMetadata::discover(http, request.issuer).await?;
    tracing::debug!(
        "signing in as client {} with scopes {:?} at token endpoint {}",
        request.client_id,
        request.scopes,
        provider.token_endpoint
    );
    let token = match request.method {
        SignInMethod::Device => {
            let endpoint = provider
                .device_authorization_endpoint
                .as_ref()
                .ok_or_else(|| {
                    eyre!(
                        "{} does not support the device flow; try --sign-in authorization-code",
                        request.issuer
                    )
                })?;
            device::sign_in(
                http,
                endpoint,
                &provider.token_endpoint,
                request.client_id,
                request.scopes,
            )
            .await?
        }
        SignInMethod::AuthorizationCode => {
            let endpoint = provider.authorization_endpoint.as_ref().ok_or_else(|| {
                eyre!(
                    "{} does not support the authorization code flow; try --sign-in device",
                    request.issuer
                )
            })?;
            authorization_code::sign_in(
                http,
                endpoint,
                &provider.token_endpoint,
                request.client_id,
                request.scopes,
            )
            .await?
        }
    };
    Ok(token.into_bearer())
}
