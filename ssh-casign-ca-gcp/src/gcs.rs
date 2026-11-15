//! A Cloud Storage bucket as the ssh-casign store (revocations, issuance
//! index), with the same Google credentials as the KMS backend. Versions are
//! object generations; conditional writes use `ifGenerationMatch` (`0`: the
//! object must not exist).
//!
//! ```toml
//! [store]
//! type = "gcs"
//! bucket = "ssh-casign-state"
//! prefix = "prod/"            # optional
//! ```
//!
//! The service account needs `roles/storage.objectUser` on the bucket (or
//! get, create, delete and list on objects). With `STORAGE_EMULATOR_HOST`
//! set (as Google's client libraries do), requests go there without
//! credentials.

use std::{path::PathBuf, time::Duration};

use serde::Deserialize;
use ssh_casign_store::{check_key, BoxFuture, Object, Precondition, Store, StoreError};

use crate::credentials::{Credentials, STORAGE_SCOPE};

pub const STORE_TYPE: &str = "gcs";
const DEFAULT_ENDPOINT: &str = "https://storage.googleapis.com";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    bucket: String,
    #[serde(default)]
    prefix: String,
    credentials_file: Option<PathBuf>,
    endpoint_url: Option<String>,
    ca_cert_file: Option<PathBuf>,
}

pub struct GcsStore {
    http: reqwest::Client,
    /// `None` for an emulator.
    credentials: Option<Credentials>,
    endpoint: String,
    bucket: String,
    prefix: String,
}

pub fn load_store(config: toml::Table) -> BoxFuture<'static, Result<Box<dyn Store>, String>> {
    Box::pin(async move {
        let config: Config = ssh_casign_store::parse_config(config)?;
        let store = GcsStore::open(config).await?;
        Ok(Box::new(store) as Box<dyn Store>)
    })
}

/// A multipart boundary that won't occur in the data.
fn rand_u128() -> u128 {
    use std::hash::{BuildHasher, Hasher};
    let mut value = 0u128;
    for _ in 0..2 {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u128(value);
        value = (value << 64) | u128::from(hasher.finish());
    }
    value
}

fn failed(what: &str, err: impl std::fmt::Display) -> StoreError {
    StoreError::Other(format!("GCS {what}: {err}"))
}

/// Percent-encode an object name for a URL path segment.
fn encode(name: &str) -> String {
    name.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

#[derive(Deserialize)]
struct ObjectResource {
    generation: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListResponse {
    #[serde(default)]
    items: Vec<ListItem>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct ListItem {
    name: String,
}

impl GcsStore {
    async fn open(config: Config) -> Result<Self, String> {
        if config.bucket.is_empty() {
            return Err("bucket is empty".into());
        }
        if !config.prefix.is_empty() {
            check_key(config.prefix.trim_end_matches('/'))
                .map_err(|_| format!("invalid prefix '{}'", config.prefix))?;
        }
        let emulator = std::env::var("STORAGE_EMULATOR_HOST")
            .ok()
            .filter(|host| !host.is_empty());
        let endpoint = match (&config.endpoint_url, &emulator) {
            (Some(endpoint), _) => endpoint.clone(),
            (None, Some(host)) if host.contains("://") => host.clone(),
            (None, Some(host)) => format!("http://{host}"),
            (None, None) => DEFAULT_ENDPOINT.to_string(),
        };
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
        if let Some(file) = &config.ca_cert_file {
            let pem = std::fs::read(file).map_err(|err| format!("{}: {err}", file.display()))?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|err| format!("{}: {err}", file.display()))?;
            builder = builder.add_root_certificate(certificate);
        }
        let http = builder.build().map_err(|err| err.to_string())?;
        let credentials = match emulator {
            Some(_) => None,
            None => Some(
                Credentials::new(
                    http.clone(),
                    config.credentials_file.as_deref(),
                    STORAGE_SCOPE,
                )
                .await?,
            ),
        };
        let mut prefix = config.prefix;
        if !prefix.is_empty() && !prefix.ends_with('/') {
            prefix.push('/');
        }
        let store = Self {
            http,
            credentials,
            endpoint: endpoint.trim_end_matches('/').to_string(),
            bucket: config.bucket,
            prefix,
        };
        store
            .list("ssh-casign-startup-check/")
            .await
            .map_err(|err| err.to_string())?;
        Ok(store)
    }

    async fn request(
        &self,
        method: reqwest::Method,
        url: String,
    ) -> Result<reqwest::RequestBuilder, StoreError> {
        let builder = self.http.request(method, url);
        Ok(match &self.credentials {
            Some(credentials) => {
                builder.bearer_auth(credentials.token().await.map_err(StoreError::Other)?)
            }
            None => builder,
        })
    }

    fn object_url(&self, key: &str) -> Result<String, StoreError> {
        check_key(key)?;
        Ok(format!(
            "{}/storage/v1/b/{}/o/{}",
            self.endpoint,
            encode(&self.bucket),
            encode(&format!("{}{key}", self.prefix))
        ))
    }
}

async fn error_text(response: reqwest::Response) -> String {
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    let message = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|value| value["error"]["message"].as_str().map(str::to_string));
    match message {
        Some(message) => format!("{status}: {message}"),
        None => status.to_string(),
    }
}

impl Store for GcsStore {
    fn describe(&self) -> String {
        format!("gcs bucket {}/{}", self.bucket, self.prefix)
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Object>, StoreError>> {
        Box::pin(async move {
            let url = format!("{}?alt=media", self.object_url(key)?);
            let response = self
                .request(reqwest::Method::GET, url)
                .await?
                .send()
                .await
                .map_err(|err| failed(&format!("GET {key}"), err))?;
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !response.status().is_success() {
                return Err(failed(&format!("GET {key}"), error_text(response).await));
            }
            let version = response
                .headers()
                .get("x-goog-generation")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
                .ok_or_else(|| failed(&format!("GET {key}"), "no x-goog-generation"))?;
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
            check_key(key)?;
            let name = format!("{}{key}", self.prefix);
            let mut query = vec![("uploadType", "multipart".to_string())];
            match &precondition {
                Precondition::None => {}
                Precondition::Absent => query.push(("ifGenerationMatch", "0".into())),
                Precondition::Version(generation) => {
                    query.push(("ifGenerationMatch", generation.clone()))
                }
            }
            // A multipart upload (metadata, then the data): every upload type
            // honours ifGenerationMatch on GCS, and emulators do for this one.
            let boundary = format!("ssh-casign-{:032x}", rand_u128());
            let metadata = serde_json::json!({ "name": name, "contentType": "application/json" });
            let mut body = format!(
                "--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{metadata}\r\n\
                 --{boundary}\r\nContent-Type: application/json\r\n\r\n"
            )
            .into_bytes();
            body.extend_from_slice(&data);
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let url = format!(
                "{}/upload/storage/v1/b/{}/o",
                self.endpoint,
                encode(&self.bucket)
            );
            let response = self
                .request(reqwest::Method::POST, url)
                .await?
                .query(&query)
                .header(
                    reqwest::header::CONTENT_TYPE,
                    format!("multipart/related; boundary={boundary}"),
                )
                .body(body)
                .send()
                .await
                .map_err(|err| failed(&format!("PUT {key}"), err))?;
            match response.status() {
                reqwest::StatusCode::PRECONDITION_FAILED => Err(StoreError::Conflict),
                status if status.is_success() => {
                    let object: ObjectResource = response
                        .json()
                        .await
                        .map_err(|err| failed(&format!("PUT {key}"), err))?;
                    Ok(object.generation)
                }
                _ => Err(failed(&format!("PUT {key}"), error_text(response).await)),
            }
        })
    }

    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<String>, StoreError>> {
        Box::pin(async move {
            let full_prefix = format!("{}{prefix}", self.prefix);
            let url = format!("{}/storage/v1/b/{}/o", self.endpoint, encode(&self.bucket));
            let mut keys = Vec::new();
            let mut page_token: Option<String> = None;
            loop {
                let mut query = vec![("prefix", full_prefix.clone())];
                if let Some(token) = &page_token {
                    query.push(("pageToken", token.clone()));
                }
                let response = self
                    .request(reqwest::Method::GET, url.clone())
                    .await?
                    .query(&query)
                    .send()
                    .await
                    .map_err(|err| failed("list", err))?;
                if !response.status().is_success() {
                    return Err(failed("list", error_text(response).await));
                }
                let page: ListResponse =
                    response.json().await.map_err(|err| failed("list", err))?;
                keys.extend(
                    page.items.into_iter().filter_map(|item| {
                        item.name.strip_prefix(&self.prefix).map(str::to_string)
                    }),
                );
                match page.next_page_token {
                    Some(token) => page_token = Some(token),
                    None => break,
                }
            }
            keys.sort();
            Ok(keys)
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let url = self.object_url(key)?;
            let response = self
                .request(reqwest::Method::DELETE, url)
                .await?
                .send()
                .await
                .map_err(|err| failed(&format!("DELETE {key}"), err))?;
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
    fn object_names_are_encoded() {
        assert_eq!(
            encode("prod/issued/ab/1.json"),
            "prod%2Fissued%2Fab%2F1.json"
        );
    }

    /// Against fake-gcs-server: `STORAGE_EMULATOR_HOST=localhost:4443` with a
    /// bucket `ssh-casign-test`.
    #[tokio::test]
    #[ignore = "needs fake-gcs-server"]
    async fn emulator() {
        if std::env::var("STORAGE_EMULATOR_HOST").is_err() {
            return;
        }
        let config: toml::Table = toml::from_str(&format!(
            "bucket = \"ssh-casign-test\"\nprefix = \"t{}\"\n",
            std::process::id()
        ))
        .unwrap();
        let store = load_store(config).await.unwrap();
        ssh_casign_store::testing::exercise(store.as_ref(), "")
            .await
            .unwrap();
    }
}
