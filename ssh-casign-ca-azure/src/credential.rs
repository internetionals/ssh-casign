//! Microsoft Entra ID access tokens for Azure services (Key Vault, ...).
//!
//! Credentials, in the order `auto` tries them (like Azure's own SDKs):
//!
//! | Credential          | When                                    | How                                    |
//! |---------------------|-----------------------------------------|----------------------------------------|
//! | `workload_identity` | `AZURE_FEDERATED_TOKEN_FILE` is set (AKS) | client assertion from that file      |
//! | `client_secret`     | a client secret is configured           | service principal, client credentials  |
//! | `managed_identity`  | `IDENTITY_ENDPOINT` + `IDENTITY_HEADER` (App Service, Functions) | the platform's token endpoint |
//! | `managed_identity`  | otherwise (VMs, VM scale sets)          | the instance metadata service (IMDS)   |
//!
//! Tokens are cached until five minutes before they expire.

use std::{
    path::PathBuf,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;

const DEFAULT_AUTHORITY_HOST: &str = "https://login.microsoftonline.com";
const IMDS_ENDPOINT: &str = "http://169.254.169.254/metadata/identity/oauth2/token";
/// Renew tokens this long before they expire.
const RENEW_MARGIN: Duration = Duration::from_secs(300);

#[derive(Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    #[default]
    Auto,
    ManagedIdentity,
    ClientSecret,
    WorkloadIdentity,
}

/// Credential settings, flattened into a backend's config.
#[derive(Deserialize, Clone, Default)]
pub struct CredentialConfig {
    #[serde(default)]
    pub credential: CredentialKind,
    /// Client ID: of a user-assigned managed identity, or of the app
    /// registration (default: `AZURE_CLIENT_ID`).
    pub client_id: Option<String>,
    /// Tenant (default: `AZURE_TENANT_ID`).
    pub tenant_id: Option<String>,
    /// File with the client secret (default: `AZURE_CLIENT_SECRET`).
    pub client_secret_file: Option<PathBuf>,
    /// Entra ID endpoint (default: `AZURE_AUTHORITY_HOST`, else
    /// `https://login.microsoftonline.com`; other clouds differ).
    pub authority_host: Option<String>,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

#[derive(Debug)]
enum Source {
    WorkloadIdentity {
        token_url: String,
        client_id: String,
        token_file: PathBuf,
    },
    ClientSecret {
        token_url: String,
        client_id: String,
        secret: String,
    },
    AppService {
        endpoint: String,
        header: String,
        client_id: Option<String>,
    },
    Imds {
        endpoint: String,
        client_id: Option<String>,
    },
}

impl Source {
    fn describe(&self) -> &'static str {
        match self {
            Source::WorkloadIdentity { .. } => "workload identity",
            Source::ClientSecret { .. } => "client secret",
            Source::AppService { .. } => "managed identity (App Service)",
            Source::Imds { .. } => "managed identity (IMDS)",
        }
    }
}

/// Tokens for one resource (e.g. `https://vault.azure.net`).
pub struct Credential {
    http: reqwest::Client,
    source: Source,
    resource: String,
    cached: Mutex<Option<(String, SystemTime)>>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    /// Entra ID: seconds from now.
    expires_in: Option<serde_json::Value>,
    /// Managed identity endpoints: Unix time.
    expires_on: Option<serde_json::Value>,
}

/// Numbers come as numbers or strings depending on the endpoint.
fn number(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}

impl CredentialConfig {
    pub fn credential(&self, http: reqwest::Client, resource: &str) -> Result<Credential, String> {
        let client_id = self.client_id.clone().or_else(|| env("AZURE_CLIENT_ID"));
        let tenant = self.tenant_id.clone().or_else(|| env("AZURE_TENANT_ID"));
        let authority = self
            .authority_host
            .clone()
            .or_else(|| env("AZURE_AUTHORITY_HOST"))
            .unwrap_or_else(|| DEFAULT_AUTHORITY_HOST.to_string());
        let token_url = |tenant: &str| {
            format!(
                "{}/{tenant}/oauth2/v2.0/token",
                authority.trim_end_matches('/')
            )
        };
        let secret = || -> Result<Option<String>, String> {
            match &self.client_secret_file {
                Some(file) => std::fs::read_to_string(file)
                    .map(|secret| Some(secret.trim().to_string()))
                    .map_err(|err| format!("client secret {}: {err}", file.display())),
                None => Ok(env("AZURE_CLIENT_SECRET")),
            }
        };
        let need = |value: &Option<String>, name: &str| {
            value
                .clone()
                .ok_or_else(|| format!("{name} needed (in the config or the environment)"))
        };
        let federated = env("AZURE_FEDERATED_TOKEN_FILE");

        let workload = |token_file: String| -> Result<Source, String> {
            Ok(Source::WorkloadIdentity {
                token_url: token_url(&need(&tenant, "tenant_id")?),
                client_id: need(&client_id, "client_id")?,
                token_file: token_file.into(),
            })
        };
        let client_secret = |secret: String| -> Result<Source, String> {
            Ok(Source::ClientSecret {
                token_url: token_url(&need(&tenant, "tenant_id")?),
                client_id: need(&client_id, "client_id")?,
                secret,
            })
        };
        let managed = || match (env("IDENTITY_ENDPOINT"), env("IDENTITY_HEADER")) {
            (Some(endpoint), Some(header)) => Source::AppService {
                endpoint,
                header,
                client_id: client_id.clone(),
            },
            _ => Source::Imds {
                endpoint: IMDS_ENDPOINT.to_string(),
                client_id: client_id.clone(),
            },
        };

        let source = match self.credential {
            CredentialKind::WorkloadIdentity => {
                workload(federated.ok_or("AZURE_FEDERATED_TOKEN_FILE is not set")?)?
            }
            CredentialKind::ClientSecret => {
                client_secret(secret()?.ok_or("no client secret configured")?)?
            }
            CredentialKind::ManagedIdentity => managed(),
            CredentialKind::Auto => match (federated, secret()?) {
                (Some(file), _) => workload(file)?,
                (None, Some(secret)) => client_secret(secret)?,
                (None, None) => managed(),
            },
        };
        Ok(Credential {
            http,
            source,
            resource: resource.trim_end_matches('/').to_string(),
            cached: Mutex::new(None),
        })
    }
}

impl Credential {
    pub fn describe(&self) -> &'static str {
        self.source.describe()
    }

    /// A valid access token, from the cache or freshly requested.
    pub async fn token(&self) -> Result<String, String> {
        if let Some((token, expires)) = self
            .cached
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            if SystemTime::now() + RENEW_MARGIN < expires {
                return Ok(token);
            }
        }
        let (token, expires) = self.request().await?;
        *self.cached.lock().unwrap_or_else(|e| e.into_inner()) = Some((token.clone(), expires));
        Ok(token)
    }

    async fn request(&self) -> Result<(String, SystemTime), String> {
        let scope = format!("{}/.default", self.resource);
        let request = match &self.source {
            Source::WorkloadIdentity {
                token_url,
                client_id,
                token_file,
            } => {
                let assertion = std::fs::read_to_string(token_file)
                    .map_err(|err| format!("{}: {err}", token_file.display()))?;
                self.http.post(token_url).form(&[
                    ("grant_type", "client_credentials"),
                    ("client_id", client_id),
                    ("scope", &scope),
                    (
                        "client_assertion_type",
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    ),
                    ("client_assertion", assertion.trim()),
                ])
            }
            Source::ClientSecret {
                token_url,
                client_id,
                secret,
            } => self.http.post(token_url).form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                ("client_secret", secret),
                ("scope", &scope),
            ]),
            Source::AppService {
                endpoint,
                header,
                client_id,
            } => {
                let mut query = vec![
                    ("resource", self.resource.as_str()),
                    ("api-version", "2019-08-01"),
                ];
                if let Some(client_id) = client_id {
                    query.push(("client_id", client_id));
                }
                self.http
                    .get(endpoint)
                    .query(&query)
                    .header("X-IDENTITY-HEADER", header)
            }
            Source::Imds {
                endpoint,
                client_id,
            } => {
                let mut query = vec![
                    ("resource", self.resource.as_str()),
                    ("api-version", "2018-02-01"),
                ];
                if let Some(client_id) = client_id {
                    query.push(("client_id", client_id));
                }
                self.http
                    .get(endpoint)
                    .query(&query)
                    .header("Metadata", "true")
            }
        };
        let response = request
            .send()
            .await
            .map_err(|err| format!("{}: {err}", self.source.describe()))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(format!(
                "{}: {status}: {}",
                self.source.describe(),
                body.trim()
            ));
        }
        let token: TokenResponse = response
            .json()
            .await
            .map_err(|err| format!("{}: invalid token response: {err}", self.source.describe()))?;
        let now = SystemTime::now();
        let expires = match (
            token.expires_on.as_ref().and_then(number),
            token.expires_in.as_ref().and_then(number),
        ) {
            (Some(on), _) => UNIX_EPOCH + Duration::from_secs(on),
            (None, Some(seconds)) => now + Duration::from_secs(seconds),
            // Unknown: assume a short life rather than reuse it forever.
            (None, None) => now + RENEW_MARGIN * 2,
        };
        Ok((token.access_token, expires))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(config: &CredentialConfig) -> &'static str {
        config
            .credential(reqwest::Client::new(), "https://vault.azure.net")
            .map(|credential| credential.describe())
            .unwrap_or("error")
    }

    #[test]
    fn credential_selection() {
        // Explicit settings only, so the test doesn't depend on the
        // environment it runs in (except for IDENTITY_ENDPOINT).
        let secret_file = std::env::temp_dir().join(format!("azure-secret-{}", std::process::id()));
        std::fs::write(&secret_file, "s3cret\n").unwrap();
        let with_secret = CredentialConfig {
            client_id: Some("app".into()),
            tenant_id: Some("tenant".into()),
            client_secret_file: Some(secret_file.clone()),
            ..Default::default()
        };
        assert_eq!(kind(&with_secret), "client secret");
        let managed = CredentialConfig {
            credential: CredentialKind::ManagedIdentity,
            ..Default::default()
        };
        assert!(kind(&managed).starts_with("managed identity"));
        let incomplete = CredentialConfig {
            credential: CredentialKind::ClientSecret,
            client_secret_file: Some(secret_file.clone()),
            client_id: Some("app".into()),
            tenant_id: None,
            ..Default::default()
        };
        if env("AZURE_TENANT_ID").is_none() {
            assert_eq!(kind(&incomplete), "error");
        }
        std::fs::remove_file(secret_file).unwrap();
    }

    #[test]
    fn numbers_as_strings_or_numbers() {
        assert_eq!(number(&serde_json::json!(3600)), Some(3600));
        assert_eq!(
            number(&serde_json::json!("1700000000")),
            Some(1_700_000_000)
        );
        assert_eq!(number(&serde_json::json!("soon")), None);
    }
}
