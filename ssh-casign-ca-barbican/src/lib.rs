//! ssh-casign CA backend: the CA private key stored as a secret in OpenStack
//! Barbican, fetched with a Keystone token when the service starts.
//!
//! Barbican stores secrets but doesn't sign with them, so unlike the KMS
//! backends the key is in the service's memory while it runs (as with the
//! `file` backend); Barbican keeps it encrypted at rest and controls who may
//! read it.
//!
//! ```toml
//! [authorities.openstack]
//! provider = "barbican"
//! secret = "f3a1...-uuid"             # or the secret's full URL
//! auth_url = "https://keystone.example.com:5000/v3"   # default OS_AUTH_URL
//! # an application credential (recommended for services):
//! application_credential_id = "..."   # default OS_APPLICATION_CREDENTIAL_ID
//! application_credential_secret_file = "/run/secrets/app-credential"
//! # or a user:
//! # username = "ssh-casign"; password_file = "/run/secrets/os-password"
//! # project_name = "ssh"; user_domain_name / project_domain_name = "Default"
//! cert_types = ["user"]
//! ```
//!
//! The secret is an unencrypted OpenSSH private key, stored as is:
//! `openstack secret store --name ssh-ca --file ca --payload-content-type
//! application/octet-stream` (or `text/plain`).

#[cfg(not(any(feature = "native-tls", feature = "rustls")))]
compile_error!("enable a TLS feature: native-tls (default) or rustls");

use std::{path::PathBuf, time::Duration};

use serde::Deserialize;
use ssh_casign_ca::{Backend, BackendError, BoxFuture, SignatureAlgorithm};
use ssh_casign_ca_file::FileKey;
use ssh_key::public::KeyData;
use zeroize::Zeroizing;

/// The `provider` name of this backend.
pub const PROVIDER: &str = "barbican";

/// [`ssh_casign_ca::Loader`] for this backend.
pub fn load(config: toml::Table) -> BoxFuture<'static, Result<Box<dyn Backend>, String>> {
    Box::pin(async move {
        let config: Config = ssh_casign_ca::parse_config(config)?;
        Ok(Box::new(config.open().await?) as Box<dyn Backend>)
    })
}

fn default_domain() -> String {
    "Default".into()
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    /// The secret's UUID (found in the catalog's key-manager endpoint) or
    /// its URL.
    secret: String,
    /// Keystone v3; default `OS_AUTH_URL`.
    auth_url: Option<String>,
    /// Default `OS_APPLICATION_CREDENTIAL_ID`.
    application_credential_id: Option<String>,
    /// Default `OS_APPLICATION_CREDENTIAL_SECRET`.
    application_credential_secret_file: Option<PathBuf>,
    /// Default `OS_USERNAME`.
    username: Option<String>,
    /// Default `OS_PASSWORD`.
    password_file: Option<PathBuf>,
    #[serde(default = "default_domain")]
    user_domain_name: String,
    /// Default `OS_PROJECT_NAME`.
    project_name: Option<String>,
    #[serde(default = "default_domain")]
    project_domain_name: String,
    /// Catalog region; default `OS_REGION_NAME`, else the first.
    region: Option<String>,
    /// Catalog interface; default `OS_INTERFACE`, else `public`.
    interface: Option<String>,
    /// The Barbican endpoint, instead of the catalog's.
    endpoint_url: Option<String>,
    /// Extra CA certificate (PEM); default `OS_CACERT`.
    ca_cert_file: Option<PathBuf>,
}

fn read_secret(path: &PathBuf, what: &str) -> Result<Zeroizing<String>, String> {
    let text = Zeroizing::new(
        std::fs::read_to_string(path).map_err(|err| format!("{what} {}: {err}", path.display()))?,
    );
    let trimmed = Zeroizing::new(text.trim().to_string());
    if trimmed.is_empty() {
        return Err(format!("{what} {} is empty", path.display()));
    }
    Ok(trimmed)
}

#[derive(Deserialize)]
struct TokenBody {
    token: Token,
}

#[derive(Deserialize)]
struct Token {
    #[serde(default)]
    catalog: Vec<CatalogEntry>,
}

#[derive(Deserialize)]
struct CatalogEntry {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    endpoints: Vec<Endpoint>,
}

#[derive(Deserialize)]
struct Endpoint {
    interface: String,
    region_id: Option<String>,
    region: Option<String>,
    url: String,
}

#[derive(Deserialize)]
struct SecretMetadata {
    #[serde(default)]
    content_types: std::collections::BTreeMap<String, String>,
    status: Option<String>,
}

/// The Barbican endpoint from the catalog.
fn key_manager_endpoint(
    catalog: &[CatalogEntry],
    interface: &str,
    region: Option<&str>,
) -> Result<String, String> {
    let entry = catalog
        .iter()
        .find(|entry| entry.kind == "key-manager")
        .ok_or("the Keystone catalog has no key-manager (Barbican) service")?;
    entry
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.interface == interface
                && region.is_none_or(|region| {
                    endpoint.region_id.as_deref() == Some(region)
                        || endpoint.region.as_deref() == Some(region)
                })
        })
        .map(|endpoint| endpoint.url.trim_end_matches('/').to_string())
        .ok_or_else(|| {
            format!(
                "no {interface} key-manager endpoint{} in the Keystone catalog",
                region
                    .map(|r| format!(" in region {r}"))
                    .unwrap_or_default()
            )
        })
}

/// The secret's URL from its ID or URL and the endpoint.
fn secret_url(secret: &str, endpoint: &str) -> String {
    if secret.starts_with("http://") || secret.starts_with("https://") {
        return secret.trim_end_matches('/').to_string();
    }
    let base = endpoint.trim_end_matches('/');
    let base = if base.ends_with("/v1") {
        base.to_string()
    } else {
        format!("{base}/v1")
    };
    format!("{base}/secrets/{secret}")
}

impl Config {
    /// The Keystone v3 authentication request.
    fn auth_request(&self) -> Result<(serde_json::Value, String), String> {
        let credential_id = self
            .application_credential_id
            .clone()
            .or_else(|| env("OS_APPLICATION_CREDENTIAL_ID"));
        if let Some(id) = credential_id {
            let secret = match &self.application_credential_secret_file {
                Some(file) => read_secret(file, "application credential secret file")?,
                None => Zeroizing::new(env("OS_APPLICATION_CREDENTIAL_SECRET").ok_or(
                    "set application_credential_secret_file or OS_APPLICATION_CREDENTIAL_SECRET",
                )?),
            };
            let body = serde_json::json!({ "auth": { "identity": {
                "methods": ["application_credential"],
                "application_credential": { "id": id, "secret": secret.as_str() },
            }}});
            return Ok((body, format!("application credential {id}")));
        }
        let username = self
            .username
            .clone()
            .or_else(|| env("OS_USERNAME"))
            .ok_or("set application_credential_id or username (or OS_* variables)")?;
        let password = match &self.password_file {
            Some(file) => read_secret(file, "password file")?,
            None => Zeroizing::new(env("OS_PASSWORD").ok_or("set password_file or OS_PASSWORD")?),
        };
        let project = self
            .project_name
            .clone()
            .or_else(|| env("OS_PROJECT_NAME"))
            .ok_or("set project_name (or OS_PROJECT_NAME)")?;
        let body = serde_json::json!({ "auth": {
            "identity": {
                "methods": ["password"],
                "password": { "user": {
                    "name": username,
                    "domain": { "name": self.user_domain_name },
                    "password": password.as_str(),
                }},
            },
            "scope": { "project": { "name": project, "domain": { "name": self.project_domain_name } } },
        }});
        Ok((body, format!("user {username}, project {project}")))
    }

    async fn open(&self) -> Result<BarbicanKey, String> {
        let auth_url = self
            .auth_url
            .clone()
            .or_else(|| env("OS_AUTH_URL"))
            .ok_or("set auth_url (or OS_AUTH_URL)")?;
        let auth_url = auth_url.trim_end_matches('/');
        let auth_url = if auth_url.ends_with("/v3") {
            auth_url.to_string()
        } else {
            format!("{auth_url}/v3")
        };
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
        if let Some(file) = self
            .ca_cert_file
            .clone()
            .or_else(|| env("OS_CACERT").map(PathBuf::from))
        {
            let pem = std::fs::read(&file).map_err(|err| format!("{}: {err}", file.display()))?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|err| format!("{}: {err}", file.display()))?;
            builder = builder.add_root_certificate(certificate);
        }
        let http = builder.build().map_err(|err| err.to_string())?;

        // Keystone: a token and the catalog.
        let (body, identity) = self.auth_request()?;
        let url = format!("{auth_url}/auth/tokens");
        let response = http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|err| format!("Keystone {url}: {err}"))?;
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(format!("Keystone {url}: {status}: {}", text.trim()));
        }
        let token = Zeroizing::new(
            response
                .headers()
                .get("x-subject-token")
                .and_then(|value| value.to_str().ok())
                .ok_or("Keystone returned no X-Subject-Token")?
                .to_string(),
        );
        let token_body: TokenBody = response
            .json()
            .await
            .map_err(|err| format!("Keystone: invalid token response: {err}"))?;
        let endpoint = match &self.endpoint_url {
            Some(endpoint) => endpoint.clone(),
            None => key_manager_endpoint(
                &token_body.token.catalog,
                &self
                    .interface
                    .clone()
                    .or_else(|| env("OS_INTERFACE"))
                    .unwrap_or_else(|| "public".into()),
                self.region
                    .clone()
                    .or_else(|| env("OS_REGION_NAME"))
                    .as_deref(),
            )?,
        };
        let secret_url = secret_url(&self.secret, &endpoint);

        // Barbican: the secret's content type, then its payload.
        let metadata: SecretMetadata = get_json(&http, &secret_url, &token).await?;
        if metadata
            .status
            .as_deref()
            .is_some_and(|status| status != "ACTIVE")
        {
            return Err(format!("Barbican secret {secret_url} is not ACTIVE"));
        }
        let content_type = metadata
            .content_types
            .get("default")
            .cloned()
            .unwrap_or_else(|| "application/octet-stream".into());
        let payload_url = format!("{secret_url}/payload");
        let response = http
            .get(&payload_url)
            .header("X-Auth-Token", token.as_str())
            .header(reqwest::header::ACCEPT, content_type)
            .send()
            .await
            .map_err(|err| format!("Barbican {payload_url}: {err}"))?;
        if !response.status().is_success() {
            return Err(format!("Barbican {payload_url}: {}", response.status()));
        }
        let payload = Zeroizing::new(
            response
                .bytes()
                .await
                .map_err(|err| format!("Barbican {payload_url}: {err}"))?
                .to_vec(),
        );
        let text = std::str::from_utf8(&payload)
            .map_err(|_| "the Barbican secret is not an OpenSSH private key (not text)")?;
        let key = ssh_key::PrivateKey::from_openssh(text.trim()).map_err(|err| {
            format!("the Barbican secret is not an unencrypted OpenSSH private key: {err}")
        })?;
        if key.is_encrypted() {
            return Err("the Barbican secret is an encrypted private key".into());
        }
        let inner = FileKey::new(PathBuf::from(&secret_url), key)?;
        Ok(BarbicanKey {
            inner,
            description: format!("barbican {secret_url} ({identity})"),
        })
    }
}

async fn get_json<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
    token: &str,
) -> Result<T, String> {
    let response = http
        .get(url)
        .header("X-Auth-Token", token)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|err| format!("Barbican {url}: {err}"))?;
    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(format!("Barbican {url}: {status}: {}", text.trim()));
    }
    response
        .json()
        .await
        .map_err(|err| format!("Barbican {url}: invalid response: {err}"))
}

/// The CA key fetched from Barbican, signing in memory.
pub struct BarbicanKey {
    inner: FileKey,
    description: String,
}

impl Backend for BarbicanKey {
    fn describe(&self) -> String {
        self.description.clone()
    }

    fn public_key(&self) -> &KeyData {
        self.inner.public_key()
    }

    fn algorithms(&self) -> Vec<SignatureAlgorithm> {
        self.inner.algorithms()
    }

    fn sign<'a>(
        &'a self,
        algorithm: SignatureAlgorithm,
        data: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, BackendError>> {
        self.inner.sign(algorithm, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> Vec<CatalogEntry> {
        serde_json::from_value(serde_json::json!([
            { "type": "identity", "endpoints": [{ "interface": "public", "region_id": "r1", "url": "https://keystone" }] },
            { "type": "key-manager", "endpoints": [
                { "interface": "internal", "region_id": "r1", "url": "https://barbican-internal:9311" },
                { "interface": "public", "region_id": "r1", "url": "https://barbican-r1:9311/" },
                { "interface": "public", "region_id": "r2", "url": "https://barbican-r2:9311/v1" },
            ]},
        ]))
        .unwrap()
    }

    #[test]
    fn endpoints_and_secret_urls() {
        let catalog = catalog();
        assert_eq!(
            key_manager_endpoint(&catalog, "public", None).unwrap(),
            "https://barbican-r1:9311"
        );
        assert_eq!(
            key_manager_endpoint(&catalog, "public", Some("r2")).unwrap(),
            "https://barbican-r2:9311/v1"
        );
        assert_eq!(
            key_manager_endpoint(&catalog, "internal", None).unwrap(),
            "https://barbican-internal:9311"
        );
        assert!(key_manager_endpoint(&catalog, "admin", None).is_err());
        assert_eq!(
            secret_url("abc", "https://barbican:9311"),
            "https://barbican:9311/v1/secrets/abc"
        );
        assert_eq!(
            secret_url("abc", "https://barbican:9311/v1"),
            "https://barbican:9311/v1/secrets/abc"
        );
        assert_eq!(
            secret_url("https://elsewhere/v1/secrets/xyz/", "https://barbican:9311"),
            "https://elsewhere/v1/secrets/xyz"
        );
    }

    #[test]
    fn auth_requests() {
        let config = |toml_text: &str| -> Config { toml::from_str(toml_text).unwrap() };
        let dir = std::env::temp_dir().join(format!("ssh-casign-barbican-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let secret = dir.join("secret");
        std::fs::write(&secret, "s3cret\n").unwrap();
        let (body, identity) = config(&format!(
            "secret = \"x\"\napplication_credential_id = \"ac1\"\napplication_credential_secret_file = {:?}\n",
            secret.to_str().unwrap()
        ))
        .auth_request()
        .unwrap();
        assert_eq!(
            body["auth"]["identity"]["application_credential"]["secret"],
            "s3cret"
        );
        assert_eq!(identity, "application credential ac1");
        let (body, _) = config(&format!(
            "secret = \"x\"\nusername = \"u\"\npassword_file = {:?}\nproject_name = \"p\"\n",
            secret.to_str().unwrap()
        ))
        .auth_request()
        .unwrap();
        assert_eq!(
            body["auth"]["identity"]["password"]["user"]["password"],
            "s3cret"
        );
        assert_eq!(body["auth"]["scope"]["project"]["name"], "p");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Against the Keystone/Barbican mock: `SSH_CASIGN_TEST_KEYSTONE` (its
    /// auth URL), `SSH_CASIGN_TEST_BARBICAN_SECRET` (the secret ID) and
    /// `SSH_CASIGN_TEST_BARBICAN_DIR` with `app-secret`.
    #[tokio::test]
    #[ignore = "needs the Keystone/Barbican mock"]
    async fn mock_openstack() {
        let (Ok(auth_url), Ok(secret), Ok(dir)) = (
            std::env::var("SSH_CASIGN_TEST_KEYSTONE"),
            std::env::var("SSH_CASIGN_TEST_BARBICAN_SECRET"),
            std::env::var("SSH_CASIGN_TEST_BARBICAN_DIR"),
        ) else {
            return;
        };
        for credentials in [
            format!("application_credential_id = \"ac1\"\napplication_credential_secret_file = \"{dir}/app-secret\"\n"),
            format!("username = \"ssh-casign\"\npassword_file = \"{dir}/password\"\nproject_name = \"ssh\"\n"),
        ] {
            let config: toml::Table = toml::from_str(&format!(
                "secret = \"{secret}\"\nauth_url = \"{auth_url}\"\nregion = \"RegionOne\"\n{credentials}"
            ))
            .unwrap();
            let backend = load(config).await.unwrap_or_else(|err| panic!("{credentials}: {err}"));
            assert!(backend.describe().starts_with("barbican "));
            ssh_casign_ca::testing::issue_with_every_algorithm(backend.as_ref())
                .await
                .unwrap();
        }
    }
}
