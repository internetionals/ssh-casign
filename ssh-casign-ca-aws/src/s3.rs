//! An S3 bucket as the ssh-casign store (revocations, issuance index), with
//! the same AWS credentials as the KMS backend. Conditional writes use S3's
//! `If-None-Match: *` and `If-Match: <etag>`.
//!
//! ```toml
//! [store]
//! type = "s3"
//! bucket = "ssh-casign-state"
//! prefix = "prod/"              # optional
//! # region = "eu-west-1"        # default: AWS_REGION
//! # endpoint_url = "http://localhost:4566"   # LocalStack, MinIO: path-style
//! ```
//!
//! The function's role needs `s3:GetObject`, `s3:PutObject`,
//! `s3:DeleteObject` on `<bucket>/<prefix>*` and `s3:ListBucket` on the
//! bucket.

use std::{path::PathBuf, time::Duration};

use serde::Deserialize;
use ssh_casign_store::{check_key, BoxFuture, Object, Precondition, Store, StoreError};

use crate::{credentials::Provider, env, sigv4};

pub const STORE_TYPE: &str = "s3";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    bucket: String,
    #[serde(default)]
    prefix: String,
    region: Option<String>,
    /// Default `AWS_ENDPOINT_URL_S3`, `AWS_ENDPOINT_URL`, else AWS
    /// (virtual-hosted style). A configured endpoint uses path-style.
    endpoint_url: Option<String>,
    profile: Option<String>,
    ca_cert_file: Option<PathBuf>,
}

pub struct S3Store {
    http: reqwest::Client,
    credentials: Provider,
    region: String,
    /// `scheme://host` of requests.
    origin: String,
    host: String,
    /// Path to the bucket: `/<bucket>` (path-style) or empty.
    bucket_path: String,
    bucket: String,
    prefix: String,
}

pub fn load_store(config: toml::Table) -> BoxFuture<'static, Result<Box<dyn Store>, String>> {
    Box::pin(async move {
        let config: Config = ssh_casign_store::parse_config(config)?;
        let store = S3Store::open(config).await?;
        Ok(Box::new(store) as Box<dyn Store>)
    })
}

fn failed(what: &str, err: impl std::fmt::Display) -> StoreError {
    StoreError::Other(format!("S3 {what}: {err}"))
}

/// `<Key>...</Key>` and the continuation token from a ListObjectsV2 reply.
/// (Keys are limited to characters XML doesn't escape.)
fn parse_list(xml: &str) -> (Vec<String>, Option<String>) {
    let values = |tag: &str| -> Vec<String> {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        xml.split(&open)
            .skip(1)
            .filter_map(|rest| rest.split_once(&close).map(|(value, _)| value.to_string()))
            .collect()
    };
    let truncated = values("IsTruncated").first().is_some_and(|v| v == "true");
    let token = truncated
        .then(|| values("NextContinuationToken").into_iter().next())
        .flatten();
    (values("Key"), token)
}

impl S3Store {
    async fn open(config: Config) -> Result<Self, String> {
        if config.bucket.is_empty() {
            return Err("bucket is empty".into());
        }
        if !config.prefix.is_empty() {
            check_key(config.prefix.trim_end_matches('/'))
                .map_err(|_| format!("invalid prefix '{}'", config.prefix))?;
        }
        let region = config
            .region
            .clone()
            .or_else(|| env("AWS_REGION"))
            .or_else(|| env("AWS_DEFAULT_REGION"))
            .ok_or("set region (or AWS_REGION)")?;
        let custom = config
            .endpoint_url
            .clone()
            .or_else(|| env("AWS_ENDPOINT_URL_S3"))
            .or_else(|| env("AWS_ENDPOINT_URL"));
        let (origin, bucket_path) = match custom {
            Some(endpoint) => (
                endpoint.trim_end_matches('/').to_string(),
                format!("/{}", config.bucket),
            ),
            None => (
                format!("https://{}.s3.{region}.amazonaws.com", config.bucket),
                String::new(),
            ),
        };
        let host = origin
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(&origin)
            .to_string();
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
        if let Some(file) = &config.ca_cert_file {
            let pem = std::fs::read(file).map_err(|err| format!("{}: {err}", file.display()))?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|err| format!("{}: {err}", file.display()))?;
            builder = builder.add_root_certificate(certificate);
        }
        let http = builder.build().map_err(|err| err.to_string())?;
        let credentials = Provider::new(http.clone(), &region, config.profile.as_deref()).await?;
        let mut prefix = config.prefix;
        if !prefix.is_empty() && !prefix.ends_with('/') {
            prefix.push('/');
        }
        let store = Self {
            http,
            credentials,
            region,
            origin,
            host,
            bucket_path,
            bucket: config.bucket,
            prefix,
        };
        // Fail at startup if the bucket can't be read.
        store
            .list("ssh-casign-startup-check/")
            .await
            .map_err(|err| err.to_string())?;
        Ok(store)
    }

    /// Send a signed request; `path` is relative to the bucket.
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        query: &str,
        headers: &[(&str, String)],
        body: Vec<u8>,
    ) -> Result<reqwest::Response, StoreError> {
        let credentials = self
            .credentials
            .credentials()
            .await
            .map_err(StoreError::Other)?;
        let full_path = format!("{}{path}", self.bucket_path);
        let full_path = if full_path.is_empty() {
            "/".to_string()
        } else {
            full_path
        };
        let request = sigv4::Request {
            method: method.as_str(),
            host: &self.host,
            path: &full_path,
            query,
            headers,
            body: &body,
        };
        let signed = sigv4::sign_request(
            &credentials,
            &self.region,
            "s3",
            &request,
            std::time::SystemTime::now(),
        );
        let url = if query.is_empty() {
            format!("{}{full_path}", self.origin)
        } else {
            format!("{}{full_path}?{query}", self.origin)
        };
        let mut builder = self.http.request(method, url).body(body);
        for (name, value) in headers {
            builder = builder.header(*name, value);
        }
        for (name, value) in signed {
            builder = builder.header(name, value);
        }
        builder.send().await.map_err(|err| failed("request", err))
    }

    fn object_path(&self, key: &str) -> Result<String, StoreError> {
        check_key(key)?;
        // Key characters need no encoding.
        Ok(format!("/{}{key}", self.prefix))
    }
}

async fn error_text(response: reqwest::Response) -> String {
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    let code = text
        .split_once("<Code>")
        .and_then(|(_, rest)| rest.split_once("</Code>"))
        .map(|(code, _)| code.to_string());
    match code {
        Some(code) => format!("{status}: {code}"),
        None => status.to_string(),
    }
}

fn etag(response: &reqwest::Response) -> Result<String, StoreError> {
    response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| failed("response", "no ETag"))
}

impl Store for S3Store {
    fn describe(&self) -> String {
        format!("s3 bucket {}/{}", self.bucket, self.prefix)
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Object>, StoreError>> {
        Box::pin(async move {
            let path = self.object_path(key)?;
            let response = self
                .send(reqwest::Method::GET, &path, "", &[], Vec::new())
                .await?;
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !response.status().is_success() {
                return Err(failed(&format!("GET {key}"), error_text(response).await));
            }
            let version = etag(&response)?;
            let data = response
                .bytes()
                .await
                .map_err(|err| failed(&format!("GET {key}"), err))?;
            Ok(Some(Object {
                data: data.to_vec(),
                version,
            }))
        })
    }

    fn put<'a>(
        &'a self,
        key: &'a str,
        data: Vec<u8>,
        precondition: Precondition,
    ) -> BoxFuture<'a, Result<String, StoreError>> {
        Box::pin(async move {
            let path = self.object_path(key)?;
            let mut headers = vec![("content-type", "application/json".to_string())];
            match &precondition {
                Precondition::None => {}
                Precondition::Absent => headers.push(("if-none-match", "*".into())),
                Precondition::Version(version) => headers.push(("if-match", version.clone())),
            }
            let response = self
                .send(reqwest::Method::PUT, &path, "", &headers, data)
                .await?;
            match response.status() {
                // 412: the precondition failed; 409: a concurrent
                // conditional write is in progress.
                reqwest::StatusCode::PRECONDITION_FAILED | reqwest::StatusCode::CONFLICT => {
                    Err(StoreError::Conflict)
                }
                status if status.is_success() => etag(&response),
                _ => Err(failed(&format!("PUT {key}"), error_text(response).await)),
            }
        })
    }

    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<String>, StoreError>> {
        Box::pin(async move {
            let full_prefix = format!("{}{prefix}", self.prefix);
            let mut keys = Vec::new();
            let mut token: Option<String> = None;
            loop {
                let mut pairs = vec![("list-type", "2"), ("prefix", full_prefix.as_str())];
                if let Some(token) = &token {
                    pairs.push(("continuation-token", token.as_str()));
                }
                let query = sigv4::canonical_query(&pairs);
                let response = self
                    .send(reqwest::Method::GET, "", &query, &[], Vec::new())
                    .await?;
                if !response.status().is_success() {
                    return Err(failed("ListObjectsV2", error_text(response).await));
                }
                let xml = response
                    .text()
                    .await
                    .map_err(|err| failed("ListObjectsV2", err))?;
                let (page, next) = parse_list(&xml);
                keys.extend(
                    page.into_iter()
                        .filter_map(|key| key.strip_prefix(&self.prefix).map(str::to_string)),
                );
                match next {
                    Some(next) => token = Some(next),
                    None => break,
                }
            }
            keys.sort();
            Ok(keys)
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let path = self.object_path(key)?;
            let response = self
                .send(reqwest::Method::DELETE, &path, "", &[], Vec::new())
                .await?;
            if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND
            {
                Ok(())
            } else {
                Err(failed(&format!("DELETE {key}"), error_text(response).await))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_response() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult><Name>b</Name><Prefix>p/issued/</Prefix><KeyCount>2</KeyCount>
<IsTruncated>true</IsTruncated><NextContinuationToken>1ueGcxL</NextContinuationToken>
<Contents><Key>p/issued/a/1.json</Key><ETag>"x"</ETag></Contents>
<Contents><Key>p/issued/b/2.json</Key></Contents></ListBucketResult>"#;
        let (keys, token) = parse_list(xml);
        assert_eq!(keys, ["p/issued/a/1.json", "p/issued/b/2.json"]);
        assert_eq!(token.as_deref(), Some("1ueGcxL"));
        let (_, token) = parse_list("<IsTruncated>false</IsTruncated>");
        assert!(token.is_none());
    }

    /// Against LocalStack: `SSH_CASIGN_TEST_S3=http://localhost:4566` with a
    /// bucket `ssh-casign-test`.
    #[tokio::test]
    #[ignore = "needs LocalStack"]
    async fn localstack() {
        let Ok(endpoint) = std::env::var("SSH_CASIGN_TEST_S3") else {
            return;
        };
        let config: toml::Table = toml::from_str(&format!(
            "bucket = \"ssh-casign-test\"\nprefix = \"t{}\"\nregion = \"eu-west-1\"\nendpoint_url = \"{endpoint}\"\n",
            std::process::id()
        ))
        .unwrap();
        let store = load_store(config).await.unwrap();
        ssh_casign_store::testing::exercise(store.as_ref(), "")
            .await
            .unwrap();
    }
}
