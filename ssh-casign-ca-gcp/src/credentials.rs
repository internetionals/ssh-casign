//! Google access tokens, found the way Google's client libraries look for
//! "application default credentials":
//!
//! | Source              | When                                                          |
//! |---------------------|---------------------------------------------------------------|
//! | key file            | `credentials_file` in the config or `GOOGLE_APPLICATION_CREDENTIALS` |
//! | gcloud credentials  | `gcloud auth application-default login` (`authorized_user`)  |
//! | metadata server     | otherwise: Cloud Run, GCE, GKE (`GCE_METADATA_HOST` overrides) |
//!
//! Key files may be service account keys (`service_account`: the service
//! signs a JWT and exchanges it for a token) or user credentials
//! (`authorized_user`: a refresh token). Workload identity federation
//! (`external_account`) is not supported. Tokens are cached until five
//! minutes before they expire.

use std::{
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::Deserialize;

/// Cloud KMS scope.
const SCOPE: &str = "https://www.googleapis.com/auth/cloudkms";
const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
const METADATA_HOST: &str = "metadata.google.internal";
const RENEW_MARGIN: Duration = Duration::from_secs(300);

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// The credentials file `gcloud auth application-default login` writes.
fn gcloud_credentials_file() -> Option<PathBuf> {
    if let Some(dir) = env("CLOUDSDK_CONFIG") {
        return Some(PathBuf::from(dir).join("application_default_credentials.json"));
    }
    if cfg!(windows) {
        env("APPDATA")
            .map(|dir| PathBuf::from(dir).join("gcloud/application_default_credentials.json"))
    } else {
        env("HOME").map(|home| {
            PathBuf::from(home).join(".config/gcloud/application_default_credentials.json")
        })
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum KeyFile {
    ServiceAccount {
        client_email: String,
        private_key: String,
        private_key_id: Option<String>,
        token_uri: Option<String>,
    },
    AuthorizedUser {
        client_id: String,
        client_secret: String,
        refresh_token: String,
    },
    ExternalAccount {},
}

enum Source {
    ServiceAccount {
        email: String,
        key: Box<rsa::RsaPrivateKey>,
        key_id: Option<String>,
        token_uri: String,
    },
    AuthorizedUser {
        client_id: String,
        client_secret: String,
        refresh_token: String,
    },
    Metadata {
        host: String,
    },
}

/// Access tokens for Cloud KMS.
pub(crate) struct Credentials {
    http: reqwest::Client,
    source: Source,
    description: String,
    cached: Mutex<Option<(String, SystemTime)>>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<u64>,
}

fn load_key_file(path: &Path) -> Result<(Source, String), String> {
    let content =
        std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let file: KeyFile = serde_json::from_str(&content)
        .map_err(|err| format!("{}: not a Google credentials file: {err}", path.display()))?;
    Ok(match file {
        KeyFile::ServiceAccount {
            client_email,
            private_key,
            private_key_id,
            token_uri,
        } => {
            use rsa::pkcs8::DecodePrivateKey;
            let key = rsa::RsaPrivateKey::from_pkcs8_pem(&private_key)
                .map_err(|err| format!("{}: invalid private key: {err}", path.display()))?;
            let description = format!("service account {client_email}");
            (
                Source::ServiceAccount {
                    email: client_email,
                    key: Box::new(key),
                    key_id: private_key_id,
                    token_uri: token_uri.unwrap_or_else(|| DEFAULT_TOKEN_URI.into()),
                },
                description,
            )
        }
        KeyFile::AuthorizedUser {
            client_id,
            client_secret,
            refresh_token,
        } => (
            Source::AuthorizedUser {
                client_id,
                client_secret,
                refresh_token,
            },
            format!("user credentials {}", path.display()),
        ),
        KeyFile::ExternalAccount {} => {
            return Err(format!(
                "{}: workload identity federation (external_account) isn't supported",
                path.display()
            ))
        }
    })
}

/// A signed JWT asserting the service account, for the token endpoint.
fn service_account_assertion(
    email: &str,
    key: &rsa::RsaPrivateKey,
    key_id: Option<&str>,
    token_uri: &str,
    now: u64,
) -> String {
    use rsa::signature::{SignatureEncoding, Signer};
    let mut header = serde_json::json!({ "alg": "RS256", "typ": "JWT" });
    if let Some(key_id) = key_id {
        header["kid"] = key_id.into();
    }
    let claims = serde_json::json!({
        "iss": email,
        "scope": SCOPE,
        "aud": token_uri,
        "iat": now,
        "exp": now + 3600,
    });
    let signing_input = format!(
        "{}.{}",
        Base64UrlUnpadded::encode_string(header.to_string().as_bytes()),
        Base64UrlUnpadded::encode_string(claims.to_string().as_bytes())
    );
    let signature = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key.clone())
        .sign(signing_input.as_bytes())
        .to_vec();
    format!(
        "{signing_input}.{}",
        Base64UrlUnpadded::encode_string(&signature)
    )
}

impl Credentials {
    pub(crate) async fn new(
        http: reqwest::Client,
        credentials_file: Option<&Path>,
    ) -> Result<Self, String> {
        let file = credentials_file
            .map(Path::to_path_buf)
            .or_else(|| env("GOOGLE_APPLICATION_CREDENTIALS").map(PathBuf::from))
            .or_else(|| gcloud_credentials_file().filter(|path| path.exists()));
        let (source, description) = match file {
            Some(path) => load_key_file(&path)?,
            None => {
                let host = env("GCE_METADATA_HOST").unwrap_or_else(|| METADATA_HOST.into());
                (Source::Metadata { host }, "metadata server".to_string())
            }
        };
        let credentials = Credentials {
            http,
            source,
            description,
            cached: Mutex::new(None),
        };
        // Fail at startup rather than on the first request.
        credentials.token().await?;
        Ok(credentials)
    }

    pub(crate) fn describe(&self) -> &str {
        &self.description
    }

    /// A valid access token, from the cache or freshly requested.
    pub(crate) async fn token(&self) -> Result<String, String> {
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
        let response = self
            .request()
            .await
            .map_err(|err| format!("Google credentials ({}): {err}", self.description))?;
        let expires = SystemTime::now() + Duration::from_secs(response.expires_in.unwrap_or(600));
        *self.cached.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((response.access_token.clone(), expires));
        Ok(response.access_token)
    }

    async fn request(&self) -> Result<TokenResponse, String> {
        let request = match &self.source {
            Source::ServiceAccount {
                email,
                key,
                key_id,
                token_uri,
            } => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|err| err.to_string())?
                    .as_secs();
                let assertion =
                    service_account_assertion(email, key, key_id.as_deref(), token_uri, now);
                self.http.post(token_uri).form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                    ("assertion", assertion.as_str()),
                ])
            }
            Source::AuthorizedUser {
                client_id,
                client_secret,
                refresh_token,
            } => self.http.post(DEFAULT_TOKEN_URI).form(&[
                ("grant_type", "refresh_token"),
                ("client_id", client_id.as_str()),
                ("client_secret", client_secret.as_str()),
                ("refresh_token", refresh_token.as_str()),
            ]),
            Source::Metadata { host } => self
                .http
                .get(format!(
                    "http://{host}/computeMetadata/v1/instance/service-accounts/default/token"
                ))
                .query(&[("scopes", SCOPE)])
                .header("Metadata-Flavor", "Google")
                .timeout(Duration::from_secs(5)),
        };
        let response = request.send().await.map_err(|err| err.to_string())?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(format!("{status}: {}", body.trim()));
        }
        response
            .json()
            .await
            .map_err(|err| format!("invalid token response: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_account_jwt_verifies() {
        use rsa::signature::Verifier;
        let key = ssh_key::PrivateKey::from_openssh(ssh_casign_ca::testing::RSA_CA).unwrap();
        let ssh_key::private::KeypairData::Rsa(keypair) = key.key_data() else {
            unreachable!()
        };
        let private = ssh_casign_ca::encoding::rsa_private_key(keypair).unwrap();
        let jwt = service_account_assertion(
            "ca@project.iam.gserviceaccount.com",
            &private,
            Some("kid1"),
            DEFAULT_TOKEN_URI,
            1_800_000_000,
        );
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value =
            serde_json::from_slice(&Base64UrlUnpadded::decode_vec(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"], "kid1");
        let claims: serde_json::Value =
            serde_json::from_slice(&Base64UrlUnpadded::decode_vec(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "ca@project.iam.gserviceaccount.com");
        assert_eq!(claims["aud"], DEFAULT_TOKEN_URI);
        assert_eq!(claims["exp"], 1_800_003_600u64);
        let signature = rsa::pkcs1v15::Signature::try_from(
            Base64UrlUnpadded::decode_vec(parts[2]).unwrap().as_slice(),
        )
        .unwrap();
        rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(rsa::RsaPublicKey::from(&private))
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn key_file_types() {
        let dir = std::env::temp_dir();
        let write = |name: &str, content: &str| {
            let path = dir.join(format!("{name}-{}.json", std::process::id()));
            std::fs::write(&path, content).unwrap();
            path
        };
        let user = write(
            "user",
            r#"{"type":"authorized_user","client_id":"c","client_secret":"s","refresh_token":"r"}"#,
        );
        assert!(load_key_file(&user)
            .unwrap()
            .1
            .starts_with("user credentials"));
        let external = write("external", r#"{"type":"external_account","audience":"x"}"#);
        assert!(load_key_file(&external)
            .err()
            .unwrap()
            .contains("external_account"));
        let garbage = write("garbage", "{}");
        assert!(load_key_file(&garbage).is_err());
        for path in [user, external, garbage] {
            std::fs::remove_file(path).unwrap();
        }
    }
}
