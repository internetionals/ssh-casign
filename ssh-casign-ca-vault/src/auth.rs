//! How the service gets its Vault/OpenBao token.
//!
//! | `method`     | Token                                                                 |
//! |--------------|-----------------------------------------------------------------------|
//! | `token`      | from `token_file` (re-read on every request, so a Vault Agent sidecar can rotate it) or `VAULT_TOKEN` |
//! | `kubernetes` | login with the pod's service account token (`auth/kubernetes/login`)  |
//! | `jwt`        | login with a JWT from a file (`auth/jwt/login`): GKE, GitHub, any OIDC |
//! | `approle`    | login with a role ID and secret ID (`auth/approle/login`)             |
//!
//! Login tokens are renewed (`auth/token/renew-self`) after two thirds of
//! their lease; when renewing fails, or Vault rejects the token, the service
//! logs in again.

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use serde::Deserialize;

const KUBERNETES_TOKEN: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

fn kubernetes_mount() -> String {
    "kubernetes".into()
}

fn jwt_mount() -> String {
    "jwt".into()
}

fn approle_mount() -> String {
    "approle".into()
}

fn kubernetes_token() -> PathBuf {
    PathBuf::from(KUBERNETES_TOKEN)
}

/// `auth = { method = "...", ... }` in the authority's config.
#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum AuthConfig {
    Token {
        /// Default: `VAULT_TOKEN`.
        token_file: Option<PathBuf>,
    },
    Kubernetes {
        /// The Vault role bound to the service account.
        role: String,
        #[serde(default = "kubernetes_mount")]
        mount: String,
        /// Default: the pod's service account token.
        #[serde(default = "kubernetes_token")]
        token_file: PathBuf,
    },
    Jwt {
        role: String,
        #[serde(default = "jwt_mount")]
        mount: String,
        token_file: PathBuf,
    },
    Approle {
        /// The role ID, or a file with it.
        role_id: Option<String>,
        role_id_file: Option<PathBuf>,
        /// File with the secret ID (default: none, for roles without one).
        secret_id_file: Option<PathBuf>,
        #[serde(default = "approle_mount")]
        mount: String,
    },
}

fn read(path: &PathBuf, what: &str) -> Result<String, String> {
    let text =
        std::fs::read_to_string(path).map_err(|err| format!("{what} {}: {err}", path.display()))?;
    let text = text.trim();
    if text.is_empty() {
        return Err(format!("{what} {} is empty", path.display()));
    }
    Ok(text.to_string())
}

impl AuthConfig {
    pub(crate) fn describe(&self) -> String {
        match self {
            AuthConfig::Token {
                token_file: Some(file),
            } => format!("token {}", file.display()),
            AuthConfig::Token { token_file: None } => "VAULT_TOKEN".into(),
            AuthConfig::Kubernetes { role, mount, .. } => {
                format!("kubernetes login ({mount}, role {role})")
            }
            AuthConfig::Jwt { role, mount, .. } => format!("jwt login ({mount}, role {role})"),
            AuthConfig::Approle { mount, .. } => format!("approle login ({mount})"),
        }
    }

    /// The login request (`auth/<mount>/login` and its body); `None` for a
    /// plain token.
    fn login(&self) -> Result<Option<(String, serde_json::Value)>, String> {
        Ok(Some(match self {
            AuthConfig::Token { .. } => return Ok(None),
            AuthConfig::Kubernetes {
                role,
                mount,
                token_file,
            }
            | AuthConfig::Jwt {
                role,
                mount,
                token_file,
            } => (
                format!("auth/{}/login", mount.trim_matches('/')),
                serde_json::json!({ "role": role, "jwt": read(token_file, "token file")? }),
            ),
            AuthConfig::Approle {
                role_id,
                role_id_file,
                secret_id_file,
                mount,
            } => {
                let role_id = match (role_id, role_id_file) {
                    (Some(role_id), None) => role_id.clone(),
                    (None, Some(file)) => read(file, "role ID file")?,
                    _ => return Err("approle: set role_id or role_id_file".into()),
                };
                let mut body = serde_json::json!({ "role_id": role_id });
                if let Some(file) = secret_id_file {
                    body["secret_id"] = read(file, "secret ID file")?.into();
                }
                (format!("auth/{}/login", mount.trim_matches('/')), body)
            }
        }))
    }
}

#[derive(Deserialize)]
struct LoginResponse {
    auth: LoginAuth,
}

#[derive(Deserialize)]
struct LoginAuth {
    client_token: String,
    #[serde(default)]
    lease_duration: u64,
    #[serde(default)]
    renewable: bool,
}

struct Lease {
    token: String,
    /// When to renew (two thirds of the lease); `None`: doesn't expire.
    renew_at: Option<Instant>,
    expires: Option<Instant>,
    renewable: bool,
}

impl Lease {
    fn new(auth: LoginAuth) -> Self {
        let now = Instant::now();
        let lease = (auth.lease_duration > 0).then(|| Duration::from_secs(auth.lease_duration));
        Self {
            token: auth.client_token,
            renew_at: lease.map(|lease| now + lease * 2 / 3),
            expires: lease.map(|lease| now + lease),
            renewable: auth.renewable,
        }
    }
}

/// Tokens for one Vault server.
pub(crate) struct Auth {
    http: reqwest::Client,
    /// `<address>/v1`
    api: String,
    namespace: Option<String>,
    config: AuthConfig,
    lease: tokio::sync::Mutex<Option<Lease>>,
}

impl Auth {
    pub(crate) fn new(
        http: reqwest::Client,
        address: &str,
        namespace: Option<String>,
        config: AuthConfig,
    ) -> Self {
        Self {
            http,
            api: format!("{}/v1", address.trim_end_matches('/')),
            namespace,
            config,
            lease: tokio::sync::Mutex::new(None),
        }
    }

    pub(crate) fn describe(&self) -> String {
        self.config.describe()
    }

    async fn post(
        &self,
        path: &str,
        token: Option<&str>,
        body: serde_json::Value,
    ) -> Result<LoginAuth, String> {
        let url = format!("{}/{path}", self.api);
        let mut request = self.http.post(&url).json(&body);
        if let Some(token) = token {
            request = request.header("X-Vault-Token", token);
        }
        if let Some(namespace) = &self.namespace {
            request = request.header("X-Vault-Namespace", namespace);
        }
        let response = request
            .send()
            .await
            .map_err(|err| format!("{url}: {err}"))?;
        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(format!("{url}: {status}: {}", text.trim()));
        }
        let response: LoginResponse = response
            .json()
            .await
            .map_err(|err| format!("{url}: invalid response: {err}"))?;
        Ok(response.auth)
    }

    /// A token to use now.
    pub(crate) async fn token(&self) -> Result<String, String> {
        let Some((path, body)) = self.config.login()? else {
            return match &self.config {
                AuthConfig::Token {
                    token_file: Some(file),
                } => read(file, "token file"),
                _ => std::env::var("VAULT_TOKEN")
                    .ok()
                    .map(|token| token.trim().to_string())
                    .filter(|token| !token.is_empty())
                    .ok_or_else(|| "set token_file or VAULT_TOKEN".to_string()),
            };
        };
        let mut lease = self.lease.lock().await;
        let now = Instant::now();
        if let Some(current) = lease.as_ref() {
            if current.renew_at.is_none_or(|renew_at| now < renew_at) {
                return Ok(current.token.clone());
            }
            let alive = current.expires.is_none_or(|expires| now < expires);
            if current.renewable && alive {
                match self
                    .post(
                        "auth/token/renew-self",
                        Some(&current.token),
                        serde_json::json!({}),
                    )
                    .await
                {
                    Ok(auth) => {
                        let renewed = Lease::new(auth);
                        let token = renewed.token.clone();
                        *lease = Some(renewed);
                        return Ok(token);
                    }
                    Err(err) => {
                        tracing::info!("vault: renewing the token failed, logging in again: {err}")
                    }
                }
            }
        }
        let fresh = Lease::new(self.post(&path, None, body).await?);
        let token = fresh.token.clone();
        *lease = Some(fresh);
        Ok(token)
    }

    /// Vault rejected the token (403): forget it, so the next request logs in.
    /// Returns whether a retry can help.
    pub(crate) async fn rejected(&self) -> bool {
        if matches!(self.config, AuthConfig::Token { .. }) {
            // A token file may have been rotated meanwhile.
            return matches!(
                self.config,
                AuthConfig::Token {
                    token_file: Some(_)
                }
            );
        }
        *self.lease.lock().await = None;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configs() {
        let parse = |toml_text: &str| toml::from_str::<AuthConfig>(toml_text);
        let kubernetes = parse("method = \"kubernetes\"\nrole = \"ssh-casign\"\n").unwrap();
        assert!(matches!(
            &kubernetes,
            AuthConfig::Kubernetes { mount, token_file, .. }
                if mount == "kubernetes" && token_file.to_str() == Some(KUBERNETES_TOKEN)
        ));
        assert!(parse("method = \"approle\"\nrole_id = \"r\"\nsecret_id_file = \"/s\"\n").is_ok());
        assert!(parse("method = \"jwt\"\nrole = \"r\"\n").is_err()); // token_file required
        assert!(parse("method = \"ldap\"\n").is_err());
        let approle = parse("method = \"approle\"\n").unwrap();
        assert!(approle.login().unwrap_err().contains("role_id"));
    }
}
