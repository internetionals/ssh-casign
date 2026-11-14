use color_eyre::eyre::{bail, eyre, WrapErr};
use serde::Deserialize;
use url::Url;

use crate::{config::SignInMethod, error::Result, token_store::StoredToken};

mod authorization_code;
mod device;
pub(crate) mod machine;

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
    /// For the machine methods.
    pub(crate) machine: machine::MachineSettings<'a>,
}

/// Successful token endpoint response.
#[derive(Debug, Deserialize)]
pub(crate) struct TokenResponse {
    access_token: String,
    id_token: Option<String>,
    refresh_token: Option<String>,
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

/// How the bearer token was obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TokenSource {
    /// From `SSH_CASIGN_TOKEN`.
    Environment,
    /// With a cached refresh token, without user interaction.
    Refreshed,
    /// Through the interactive sign-in flow.
    Interactive,
    /// A machine or workload token (no person, nothing cached).
    Machine,
}

/// Sign the user in and return the bearer token for the service.
///
/// With `allow_refresh`, a cached refresh token is tried first. Refresh
/// tokens the IdP hands out are cached for the next run.
pub(crate) async fn sign_in(
    http: &reqwest::Client,
    request: &SignInRequest<'_>,
    stored: &StoredToken,
    allow_refresh: bool,
) -> Result<(String, TokenSource)> {
    if let Ok(token) = std::env::var(TOKEN_ENV) {
        tracing::debug!("using token from {TOKEN_ENV}");
        return Ok((token, TokenSource::Environment));
    }

    if request.method.is_machine() {
        let settings = &request.machine;
        let token = match request.method {
            SignInMethod::ClientCredentials => {
                let provider = ProviderMetadata::discover(http, settings.issuer).await?;
                machine::client_credentials(http, &provider.token_endpoint, settings).await?
            }
            SignInMethod::TokenFile => machine::token_file(settings)?,
            SignInMethod::GcpMetadata => machine::gcp_metadata(http, settings).await?,
            SignInMethod::AzureManagedIdentity => {
                machine::azure_managed_identity(http, settings).await?
            }
            SignInMethod::GithubActions => machine::github_actions(http, settings).await?,
            SignInMethod::Device | SignInMethod::AuthorizationCode => unreachable!(),
        };
        return Ok((token, TokenSource::Machine));
    }

    let provider = ProviderMetadata::discover(http, request.issuer).await?;
    if allow_refresh {
        if let Some(refresh_token) = stored.load() {
            match refresh(
                http,
                &provider.token_endpoint,
                request.client_id,
                &refresh_token,
            )
            .await
            {
                Ok(token) => {
                    tracing::debug!("signed in with the cached refresh token");
                    return Ok((store_and_take_bearer(token, stored), TokenSource::Refreshed));
                }
                Err(err) => {
                    tracing::info!("cached sign-in no longer valid, signing in again: {err:#}");
                    if let Err(err) = stored.delete() {
                        tracing::warn!("can't remove the cached refresh token: {err:#}");
                    }
                }
            }
        }
    }

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
        _ => unreachable!("machine methods are handled above"),
    };
    if token.refresh_token.is_none() {
        tracing::debug!(
            "the IdP returned no refresh token (does it need the offline_access scope?)"
        );
    }
    Ok((
        store_and_take_bearer(token, stored),
        TokenSource::Interactive,
    ))
}

/// Cache the (possibly rotated) refresh token and return the bearer token.
fn store_and_take_bearer(mut token: TokenResponse, stored: &StoredToken) -> String {
    if let Some(refresh_token) = token.refresh_token.take() {
        stored.save(&refresh_token);
    }
    token.into_bearer()
}

/// Refresh token grant (RFC 6749 section 6). The scope is left out, which
/// means the scope originally granted.
async fn refresh(
    http: &reqwest::Client,
    token_endpoint: &Url,
    client_id: &str,
    refresh_token: &str,
) -> Result<TokenResponse> {
    let response = http
        .post(token_endpoint.clone())
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ])
        .send()
        .await
        .wrap_err_with(|| format!("Token request to {token_endpoint} failed"))?;
    if !response.status().is_success() {
        let status = response.status();
        let error = OAuthError::from_response(response).await;
        bail!("Refresh rejected ({status}): {error}");
    }
    response.json().await.wrap_err("Invalid token response")
}
