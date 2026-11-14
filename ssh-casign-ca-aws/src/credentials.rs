//! AWS credentials, found the way AWS's SDKs look for them:
//!
//! | Source                | When                                                        |
//! |-----------------------|-------------------------------------------------------------|
//! | named profile         | `profile` in the config or `AWS_PROFILE` (static keys in `~/.aws/credentials`) |
//! | environment           | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (Lambda sets these) |
//! | web identity          | `AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN` (EKS IRSA)   |
//! | default profile       | `[default]` in `~/.aws/credentials`, if the file exists     |
//! | container credentials | `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` / `_FULL_URI` (ECS, EKS Pod Identity) |
//! | instance metadata     | IMDSv2 on EC2                                               |
//!
//! Temporary credentials are cached until five minutes before they expire.

use std::{
    path::PathBuf,
    sync::Mutex,
    time::{Duration, SystemTime},
};

use serde::Deserialize;

use crate::time::parse_iso8601;

const RENEW_MARGIN: Duration = Duration::from_secs(300);
const IMDS: &str = "http://169.254.169.254";
const ECS_HOST: &str = "http://169.254.170.2";

#[derive(Clone, Debug)]
pub(crate) struct Credentials {
    pub(crate) access_key_id: String,
    pub(crate) secret_access_key: String,
    pub(crate) session_token: Option<String>,
    /// `None`: doesn't expire (static keys).
    pub(crate) expires: Option<SystemTime>,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

#[derive(Debug)]
enum Source {
    Environment,
    WebIdentity {
        token_file: PathBuf,
        role_arn: String,
        session_name: String,
    },
    Profile {
        path: PathBuf,
        profile: String,
    },
    Container {
        uri: String,
    },
    Imds,
}

impl Source {
    fn describe(&self) -> String {
        match self {
            Source::Environment => "environment".into(),
            Source::WebIdentity { role_arn, .. } => format!("web identity ({role_arn})"),
            Source::Profile { profile, .. } => format!("profile {profile}"),
            Source::Container { .. } => "container credentials".into(),
            Source::Imds => "instance metadata (IMDSv2)".into(),
        }
    }
}

/// Credentials for requests to AWS, refreshed when they expire.
pub(crate) struct Provider {
    http: reqwest::Client,
    source: Source,
    region: String,
    cached: Mutex<Option<Credentials>>,
}

/// Static keys of a profile in an AWS credentials file.
fn profile_keys(content: &str, profile: &str) -> Option<Credentials> {
    let mut in_profile = false;
    let (mut key, mut secret, mut token) = (None, None, None);
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_profile = line[1..line.len() - 1].trim() == profile;
            continue;
        }
        if !in_profile {
            continue;
        }
        if let Some((name, value)) = line.split_once('=') {
            let value = value.trim().to_string();
            match name.trim() {
                "aws_access_key_id" => key = Some(value),
                "aws_secret_access_key" => secret = Some(value),
                "aws_session_token" => token = Some(value),
                _ => {}
            }
        }
    }
    Some(Credentials {
        access_key_id: key?,
        secret_access_key: secret?,
        session_token: token,
        expires: None,
    })
}

fn credentials_file() -> Option<PathBuf> {
    env("AWS_SHARED_CREDENTIALS_FILE")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".aws/credentials"))
        })
}

/// Credentials as the container and instance metadata endpoints return them.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct EndpointCredentials {
    access_key_id: String,
    secret_access_key: String,
    token: Option<String>,
    expiration: Option<String>,
}

impl From<EndpointCredentials> for Credentials {
    fn from(credentials: EndpointCredentials) -> Self {
        Credentials {
            access_key_id: credentials.access_key_id,
            secret_access_key: credentials.secret_access_key,
            session_token: credentials.token,
            expires: credentials.expiration.as_deref().and_then(parse_iso8601),
        }
    }
}

impl Provider {
    /// The first source that applies. `profile` overrides `AWS_PROFILE`.
    pub(crate) async fn new(
        http: reqwest::Client,
        region: &str,
        profile: Option<&str>,
    ) -> Result<Self, String> {
        let explicit_profile = profile.map(String::from).or_else(|| env("AWS_PROFILE"));
        let file = credentials_file();
        let source = if let Some(profile) = explicit_profile {
            let path = file.ok_or("no home directory for ~/.aws/credentials")?;
            Source::Profile { path, profile }
        } else if env("AWS_ACCESS_KEY_ID").is_some() && env("AWS_SECRET_ACCESS_KEY").is_some() {
            Source::Environment
        } else if let (Some(token_file), Some(role_arn)) =
            (env("AWS_WEB_IDENTITY_TOKEN_FILE"), env("AWS_ROLE_ARN"))
        {
            Source::WebIdentity {
                token_file: token_file.into(),
                role_arn,
                session_name: env("AWS_ROLE_SESSION_NAME").unwrap_or_else(|| "ssh-casign".into()),
            }
        } else if let Some(path) = file.filter(|path| path.exists()) {
            Source::Profile {
                path,
                profile: "default".into(),
            }
        } else if let Some(relative) = env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
            Source::Container {
                uri: format!("{ECS_HOST}{relative}"),
            }
        } else if let Some(uri) = env("AWS_CONTAINER_CREDENTIALS_FULL_URI") {
            Source::Container { uri }
        } else {
            Source::Imds
        };
        let provider = Provider {
            http,
            source,
            region: region.to_string(),
            cached: Mutex::new(None),
        };
        // Fail at startup rather than on the first request.
        provider.credentials().await?;
        Ok(provider)
    }

    pub(crate) fn describe(&self) -> String {
        self.source.describe()
    }

    /// Valid credentials, from the cache or freshly fetched.
    pub(crate) async fn credentials(&self) -> Result<Credentials, String> {
        if let Some(credentials) = self
            .cached
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            if credentials
                .expires
                .is_none_or(|expires| SystemTime::now() + RENEW_MARGIN < expires)
            {
                return Ok(credentials);
            }
        }
        let credentials = self
            .fetch()
            .await
            .map_err(|err| format!("AWS credentials from {}: {err}", self.source.describe()))?;
        *self.cached.lock().unwrap_or_else(|e| e.into_inner()) = Some(credentials.clone());
        Ok(credentials)
    }

    async fn fetch(&self) -> Result<Credentials, String> {
        match &self.source {
            Source::Environment => Ok(Credentials {
                access_key_id: env("AWS_ACCESS_KEY_ID").ok_or("AWS_ACCESS_KEY_ID is not set")?,
                secret_access_key: env("AWS_SECRET_ACCESS_KEY")
                    .ok_or("AWS_SECRET_ACCESS_KEY is not set")?,
                session_token: env("AWS_SESSION_TOKEN"),
                expires: None,
            }),
            Source::Profile { path, profile } => {
                let content = std::fs::read_to_string(path)
                    .map_err(|err| format!("{}: {err}", path.display()))?;
                profile_keys(&content, profile).ok_or_else(|| {
                    format!(
                        "no static keys for profile {profile} in {} (SSO and role profiles aren't supported)",
                        path.display()
                    )
                })
            }
            Source::WebIdentity {
                token_file,
                role_arn,
                session_name,
            } => {
                self.assume_role_with_web_identity(token_file, role_arn, session_name)
                    .await
            }
            Source::Container { uri } => {
                let mut request = self.http.get(uri).timeout(Duration::from_secs(5));
                let token = match env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") {
                    Some(file) => Some(
                        std::fs::read_to_string(&file).map_err(|err| format!("{file}: {err}"))?,
                    ),
                    None => env("AWS_CONTAINER_AUTHORIZATION_TOKEN"),
                };
                if let Some(token) = token {
                    request = request.header("Authorization", token.trim());
                }
                let credentials: EndpointCredentials = Self::json(request).await?;
                Ok(credentials.into())
            }
            Source::Imds => {
                let timeout = Duration::from_secs(1);
                let token = self
                    .http
                    .put(format!("{IMDS}/latest/api/token"))
                    .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
                    .timeout(timeout)
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status)
                    .map_err(|err| format!("no credentials found (IMDS: {err})"))?
                    .text()
                    .await
                    .map_err(|err| err.to_string())?;
                let base = format!("{IMDS}/latest/meta-data/iam/security-credentials/");
                let role = self
                    .http
                    .get(&base)
                    .header("X-aws-ec2-metadata-token", &token)
                    .timeout(timeout)
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status)
                    .map_err(|err| format!("no instance role (IMDS: {err})"))?
                    .text()
                    .await
                    .map_err(|err| err.to_string())?;
                let role = role.lines().next().unwrap_or_default().trim();
                let request = self
                    .http
                    .get(format!("{base}{role}"))
                    .header("X-aws-ec2-metadata-token", &token)
                    .timeout(timeout);
                let credentials: EndpointCredentials = Self::json(request).await?;
                Ok(credentials.into())
            }
        }
    }

    async fn json<T: serde::de::DeserializeOwned>(
        request: reqwest::RequestBuilder,
    ) -> Result<T, String> {
        let response = request.send().await.map_err(|err| err.to_string())?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(format!("{status}: {}", body.trim()));
        }
        response
            .json()
            .await
            .map_err(|err| format!("invalid response: {err}"))
    }

    /// STS `AssumeRoleWithWebIdentity`; the request itself is unsigned.
    async fn assume_role_with_web_identity(
        &self,
        token_file: &PathBuf,
        role_arn: &str,
        session_name: &str,
    ) -> Result<Credentials, String> {
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Response {
            assume_role_with_web_identity_response: ResponseInner,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct ResponseInner {
            assume_role_with_web_identity_result: Result_,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Result_ {
            credentials: StsCredentials,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct StsCredentials {
            access_key_id: String,
            secret_access_key: String,
            session_token: String,
            /// Seconds since the epoch in JSON responses.
            expiration: serde_json::Value,
        }
        let token = std::fs::read_to_string(token_file)
            .map_err(|err| format!("{}: {err}", token_file.display()))?;
        let endpoint = env("AWS_ENDPOINT_URL_STS")
            .unwrap_or_else(|| format!("https://sts.{}.amazonaws.com", self.region));
        let request = self
            .http
            .get(format!("{}/", endpoint.trim_end_matches('/')))
            .query(&[
                ("Action", "AssumeRoleWithWebIdentity"),
                ("Version", "2011-06-15"),
                ("RoleArn", role_arn),
                ("RoleSessionName", session_name),
                ("WebIdentityToken", token.trim()),
            ])
            .header("Accept", "application/json")
            .timeout(Duration::from_secs(10));
        let response: Response = Self::json(request).await?;
        let credentials = response
            .assume_role_with_web_identity_response
            .assume_role_with_web_identity_result
            .credentials;
        let expires = match &credentials.expiration {
            serde_json::Value::Number(secs) => secs
                .as_f64()
                .map(|secs| SystemTime::UNIX_EPOCH + Duration::from_secs_f64(secs)),
            serde_json::Value::String(value) => parse_iso8601(value),
            _ => None,
        };
        Ok(Credentials {
            access_key_id: credentials.access_key_id,
            secret_access_key: credentials.secret_access_key,
            session_token: Some(credentials.session_token),
            expires,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_parsing() {
        let content = "[default]\naws_access_key_id = AKIA1\naws_secret_access_key = s1\n\n[ci]\naws_access_key_id=AKIA2\naws_secret_access_key=s2\naws_session_token = t2\n[sso]\nsso_start_url = https://x\n";
        let default = profile_keys(content, "default").unwrap();
        assert_eq!(
            (default.access_key_id.as_str(), default.session_token),
            ("AKIA1", None)
        );
        let ci = profile_keys(content, "ci").unwrap();
        assert_eq!(
            (ci.secret_access_key.as_str(), ci.session_token.as_deref()),
            ("s2", Some("t2"))
        );
        assert!(profile_keys(content, "sso").is_none());
        assert!(profile_keys(content, "missing").is_none());
    }

    #[test]
    fn endpoint_credentials() {
        let credentials: Credentials = serde_json::from_str::<EndpointCredentials>(
            r#"{"Code":"Success","AccessKeyId":"ASIA","SecretAccessKey":"s","Token":"t","Expiration":"2026-11-14T13:00:00Z"}"#,
        )
        .unwrap()
        .into();
        assert_eq!(credentials.session_token.as_deref(), Some("t"));
        assert_eq!(credentials.expires, parse_iso8601("2026-11-14T13:00:00Z"));
    }
}
