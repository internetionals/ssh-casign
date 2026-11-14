//! Non-interactive sign-in for machines and workloads: hosts renewing their
//! own certificates, and orchestrators (a CMDB, a provisioning pipeline)
//! signing for the hosts they manage.
//!
//! | Method                   | Token                                                       |
//! |--------------------------|-------------------------------------------------------------|
//! | `client-credentials`     | OAuth 2.0 client credentials grant (a confidential client)  |
//! | `token-file`             | read from a file each time (Kubernetes projected token, ...) |
//! | `gcp-metadata`           | the GCE/GKE metadata server's identity token                |
//! | `azure-managed-identity` | Azure IMDS, or `IDENTITY_ENDPOINT` on App Service/Container Apps |
//! | `github-actions`         | the GitHub Actions OIDC token                               |
//!
//! The service must trust the token's issuer (`[issuers.<name>]`) and
//! audience.

use std::{path::Path, time::Duration};

use color_eyre::eyre::{bail, eyre, WrapErr};
use serde::Deserialize;

use crate::error::Result;

const METADATA_TIMEOUT: Duration = Duration::from_secs(10);

/// Settings the machine methods need, from the client profile.
pub(crate) struct MachineSettings<'a> {
    /// Token endpoint issuer for `client-credentials`.
    pub(crate) issuer: &'a str,
    pub(crate) client_id: Option<&'a str>,
    pub(crate) client_secret_file: Option<&'a Path>,
    pub(crate) scopes: Option<&'a [String]>,
    /// Audience to request a token for (the service's `issuers.*.audience`).
    pub(crate) audience: Option<&'a str>,
    pub(crate) token_file: Option<&'a Path>,
}

impl MachineSettings<'_> {
    fn audience(&self, method: &str) -> Result<&str> {
        self.audience
            .ok_or_else(|| eyre!("sign-in method {method} needs `audience` in the client profile"))
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

#[derive(Deserialize)]
struct AccessToken {
    access_token: String,
}

async fn json_or_error<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    what: &str,
) -> Result<T> {
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("{what} failed ({status}): {}", body.trim());
    }
    response
        .json()
        .await
        .wrap_err_with(|| format!("Invalid response from {what}"))
}

async fn text_or_error(response: reqwest::Response, what: &str) -> Result<String> {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("{what} failed ({status}): {}", body.trim());
    }
    Ok(body.trim().to_string())
}

/// OAuth 2.0 client credentials grant (RFC 6749 section 4.4), authenticating
/// with HTTP Basic (`client_secret_basic`). Returns the access token.
pub(crate) async fn client_credentials(
    http: &reqwest::Client,
    token_endpoint: &url::Url,
    settings: &MachineSettings<'_>,
) -> Result<String> {
    let client_id = settings
        .client_id
        .ok_or_else(|| eyre!("client-credentials needs `client_id` in the client profile"))?;
    let secret = match (env("SSH_CASIGN_CLIENT_SECRET"), settings.client_secret_file) {
        (Some(secret), _) => secret,
        (None, Some(file)) => std::fs::read_to_string(file)
            .wrap_err_with(|| format!("Failed to read client secret {}", file.display()))?
            .trim()
            .to_string(),
        (None, None) => bail!(
            "client-credentials needs `client_secret_file` in the client profile or \
             SSH_CASIGN_CLIENT_SECRET"
        ),
    };
    // RFC 6749 section 2.3.1: form-encode both before Basic authentication.
    let encode =
        |value: &str| url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>();
    let mut form = vec![("grant_type", "client_credentials".to_string())];
    if let Some(scopes) = settings.scopes.filter(|scopes| !scopes.is_empty()) {
        form.push(("scope", scopes.join(" ")));
    }
    if let Some(audience) = settings.audience {
        // Not standard, but how Auth0 and others select the API.
        form.push(("audience", audience.to_string()));
    }
    let response = http
        .post(token_endpoint.clone())
        .basic_auth(encode(client_id), Some(encode(&secret)))
        .form(&form)
        .send()
        .await
        .wrap_err_with(|| format!("Token request to {token_endpoint} failed"))?;
    let token: AccessToken = json_or_error(response, "client credentials grant").await?;
    Ok(token.access_token)
}

pub(crate) fn token_file(settings: &MachineSettings<'_>) -> Result<String> {
    let file = settings.token_file.ok_or_else(|| {
        eyre!("sign-in method token-file needs `token_file` in the client profile")
    })?;
    let token = std::fs::read_to_string(file)
        .wrap_err_with(|| format!("Failed to read token file {}", file.display()))?;
    let token = token.trim();
    if token.is_empty() {
        bail!("token file {} is empty", file.display());
    }
    Ok(token.to_string())
}

/// Identity token of the GCE/GKE instance's service account. `format=full`
/// adds the `google.compute_engine` claims (project, zone, instance name).
pub(crate) async fn gcp_metadata(
    http: &reqwest::Client,
    settings: &MachineSettings<'_>,
) -> Result<String> {
    let audience = settings.audience("gcp-metadata")?;
    let host = env("GCE_METADATA_HOST").unwrap_or_else(|| "metadata.google.internal".into());
    let url =
        format!("http://{host}/computeMetadata/v1/instance/service-accounts/default/identity");
    let response = http
        .get(&url)
        .query(&[("audience", audience), ("format", "full")])
        .header("Metadata-Flavor", "Google")
        .timeout(METADATA_TIMEOUT)
        .send()
        .await
        .wrap_err_with(|| format!("Request to the metadata server {host} failed"))?;
    text_or_error(response, "GCP metadata identity token").await
}

/// Access token of the Azure managed identity for `audience` (an application
/// ID URI or client ID). On App Service, Functions and Container Apps through
/// `IDENTITY_ENDPOINT`, else through IMDS. A user-assigned identity is chosen
/// with `client_id`.
pub(crate) async fn azure_managed_identity(
    http: &reqwest::Client,
    settings: &MachineSettings<'_>,
) -> Result<String> {
    let resource = settings.audience("azure-managed-identity")?;
    let mut query = vec![("resource", resource)];
    if let Some(client_id) = settings.client_id {
        query.push(("client_id", client_id));
    }
    let request = match (env("IDENTITY_ENDPOINT"), env("IDENTITY_HEADER")) {
        (Some(endpoint), Some(header)) => {
            query.push(("api-version", "2019-08-01"));
            http.get(endpoint).header("X-IDENTITY-HEADER", header)
        }
        _ => {
            query.push(("api-version", "2018-02-01"));
            http.get("http://169.254.169.254/metadata/identity/oauth2/token")
                .header("Metadata", "true")
        }
    };
    let response = request
        .query(&query)
        .timeout(METADATA_TIMEOUT)
        .send()
        .await
        .wrap_err("Request to the Azure managed identity endpoint failed")?;
    let token: AccessToken = json_or_error(response, "Azure managed identity").await?;
    Ok(token.access_token)
}

/// The GitHub Actions OIDC token (the job needs `permissions: id-token: write`).
pub(crate) async fn github_actions(
    http: &reqwest::Client,
    settings: &MachineSettings<'_>,
) -> Result<String> {
    let audience = settings.audience("github-actions")?;
    let (Some(url), Some(request_token)) = (
        env("ACTIONS_ID_TOKEN_REQUEST_URL"),
        env("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
    ) else {
        bail!(
            "ACTIONS_ID_TOKEN_REQUEST_URL is not set: not in GitHub Actions, or the job lacks \
             `permissions: id-token: write`"
        );
    };
    #[derive(Deserialize)]
    struct Value {
        value: String,
    }
    let response = http
        .get(url)
        .query(&[("audience", audience)])
        .bearer_auth(request_token)
        .send()
        .await
        .wrap_err("Request for the GitHub Actions OIDC token failed")?;
    let token: Value = json_or_error(response, "GitHub Actions OIDC token").await?;
    Ok(token.value)
}
