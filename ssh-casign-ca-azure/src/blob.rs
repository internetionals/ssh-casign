//! An Azure Blob Storage container as the ssh-casign store (revocations,
//! issuance index). Versions are ETags; conditional writes use `If-Match`
//! and `If-None-Match: *`.
//!
//! ```toml
//! [store]
//! type = "azure_blob"
//! account_url = "https://sshcasign.blob.core.windows.net"
//! container = "ssh-casign"
//! prefix = "prod/"          # optional
//! # Entra ID, like the Key Vault backend (managed identity, workload
//! # identity, client secret); the identity needs "Storage Blob Data
//! # Contributor" on the container. Or a storage account key:
//! # account_key_file = "/etc/ssh-casign/storage-key"
//! ```

use std::{path::PathBuf, time::Duration};

use base64ct::{Base64, Encoding as _};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use ssh_casign_store::{check_key, BoxFuture, Object, Precondition, Store, StoreError};

use crate::credential::{Credential, CredentialConfig};

pub const STORE_TYPE: &str = "azure_blob";
/// Blob service REST API version.
const API_VERSION: &str = "2021-08-06";
const STORAGE_RESOURCE: &str = "https://storage.azure.com";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    /// `https://<account>.blob.core.windows.net` (or an emulator's URL with
    /// the account in the path: `http://127.0.0.1:10000/devstoreaccount1`).
    account_url: String,
    container: String,
    #[serde(default)]
    prefix: String,
    /// Shared Key authentication: a file with the account key (base64).
    account_key_file: Option<PathBuf>,
    /// The account name for Shared Key (default: from `account_url`).
    account_name: Option<String>,
    ca_cert_file: Option<PathBuf>,
    #[serde(flatten)]
    credential: CredentialConfig,
}

enum Auth {
    Entra(Credential),
    SharedKey { account: String, key: Vec<u8> },
}

pub struct BlobStore {
    http: reqwest::Client,
    auth: Auth,
    /// `account_url/container`, without a trailing slash.
    container_url: String,
    /// The URL path of the container (for Shared Key's canonical resource).
    container_path: String,
    prefix: String,
}

pub fn load_store(config: toml::Table) -> BoxFuture<'static, Result<Box<dyn Store>, String>> {
    Box::pin(async move {
        let config: Config = ssh_casign_store::parse_config(config)?;
        let store = BlobStore::open(config).await?;
        Ok(Box::new(store) as Box<dyn Store>)
    })
}

fn failed(what: &str, err: impl std::fmt::Display) -> StoreError {
    StoreError::Other(format!("Azure Blob {what}: {err}"))
}

/// RFC 1123 date for `x-ms-date`.
fn http_date(time: std::time::SystemTime) -> String {
    let secs = time
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let days = (secs / 86_400) as i64;
    let weekday = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][days.rem_euclid(7) as usize];
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(month - 1) as usize];
    let rem = secs % 86_400;
    format!(
        "{weekday}, {day:02} {month} {year} {:02}:{:02}:{:02} GMT",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

/// The Shared Key string to sign (Blob service, version 2015-02-21 and
/// later): standard headers, `x-ms-*` headers, then the canonical resource.
fn string_to_sign(
    method: &str,
    headers: &[(&str, String)],
    account: &str,
    path: &str,
    query: &[(&str, String)],
) -> String {
    let header = |name: &str| {
        headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .unwrap_or("")
    };
    let content_length = match header("content-length") {
        "0" => "",
        other => other,
    };
    let mut ms: Vec<(String, &str)> = headers
        .iter()
        .filter(|(name, _)| name.to_ascii_lowercase().starts_with("x-ms-"))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim()))
        .collect();
    ms.sort();
    let canonical_headers: String = ms
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect();
    let mut params: Vec<(String, &str)> = query
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.as_str()))
        .collect();
    params.sort();
    let canonical_query: String = params
        .iter()
        .map(|(name, value)| format!("\n{name}:{value}"))
        .collect();
    format!(
        "{method}\n\n\n{content_length}\n\n{}\n\n\n{}\n{}\n\n\n{canonical_headers}/{account}{path}{canonical_query}",
        header("content-type"),
        header("if-match"),
        header("if-none-match"),
    )
}

/// `%`-encode a query value.
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

/// `<Name>` of each blob and the `<NextMarker>` of a List Blobs reply.
fn parse_list(xml: &str) -> (Vec<String>, Option<String>) {
    let values = |tag: &str| -> Vec<String> {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        xml.split(&open)
            .skip(1)
            .filter_map(|rest| rest.split_once(&close).map(|(value, _)| value.to_string()))
            .collect()
    };
    let names = xml
        .split("<Blob>")
        .skip(1)
        .filter_map(|blob| {
            blob.split_once("<Name>")
                .and_then(|(_, rest)| rest.split_once("</Name>"))
                .map(|(name, _)| name.to_string())
        })
        .collect();
    let marker = values("NextMarker").into_iter().find(|m| !m.is_empty());
    (names, marker)
}

impl BlobStore {
    async fn open(config: Config) -> Result<Self, String> {
        let account_url = config.account_url.trim_end_matches('/').to_string();
        let url_path = account_url
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(&account_url)
            .split_once('/')
            .map(|(_, path)| format!("/{path}"))
            .unwrap_or_default();
        if config.container.is_empty() {
            return Err("container is empty".into());
        }
        if !config.prefix.is_empty() {
            check_key(config.prefix.trim_end_matches('/'))
                .map_err(|_| format!("invalid prefix '{}'", config.prefix))?;
        }
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
        if let Some(file) = &config.ca_cert_file {
            let pem = std::fs::read(file).map_err(|err| format!("{}: {err}", file.display()))?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|err| format!("{}: {err}", file.display()))?;
            builder = builder.add_root_certificate(certificate);
        }
        let http = builder.build().map_err(|err| err.to_string())?;
        let auth = match &config.account_key_file {
            Some(file) => {
                let text = std::fs::read_to_string(file)
                    .map_err(|err| format!("{}: {err}", file.display()))?;
                let key = Base64::decode_vec(text.trim())
                    .map_err(|_| format!("{}: not a base64 account key", file.display()))?;
                let account = match &config.account_name {
                    Some(account) => account.clone(),
                    None => account_url
                        .split_once("://")
                        .map(|(_, rest)| rest)
                        .unwrap_or(&account_url)
                        .split(['.', '/'])
                        .next()
                        .unwrap_or_default()
                        .to_string(),
                };
                Auth::SharedKey { account, key }
            }
            None => Auth::Entra(
                config
                    .credential
                    .credential(http.clone(), STORAGE_RESOURCE)?,
            ),
        };
        let mut prefix = config.prefix;
        if !prefix.is_empty() && !prefix.ends_with('/') {
            prefix.push('/');
        }
        let store = Self {
            http,
            auth,
            container_url: format!("{account_url}/{}", config.container),
            container_path: format!("{url_path}/{}", config.container),
            prefix,
        };
        store
            .list("ssh-casign-startup-check/")
            .await
            .map_err(|err| err.to_string())?;
        Ok(store)
    }

    /// Send a request to `<container><path>` with `query` and `headers`.
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        query: &[(&str, String)],
        extra: &[(&str, String)],
        body: Vec<u8>,
    ) -> Result<reqwest::Response, StoreError> {
        let mut headers: Vec<(&str, String)> = vec![
            ("x-ms-date", http_date(std::time::SystemTime::now())),
            ("x-ms-version", API_VERSION.to_string()),
        ];
        headers.extend(extra.iter().cloned());
        if method == reqwest::Method::PUT {
            headers.push(("content-length", body.len().to_string()));
        }
        let authorization = match &self.auth {
            Auth::Entra(credential) => format!(
                "Bearer {}",
                credential.token().await.map_err(StoreError::Other)?
            ),
            Auth::SharedKey { account, key } => {
                let to_sign = string_to_sign(
                    method.as_str(),
                    &headers,
                    account,
                    &format!("{}{path}", self.container_path),
                    query,
                );
                let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("any key length");
                mac.update(to_sign.as_bytes());
                format!(
                    "SharedKey {account}:{}",
                    Base64::encode_string(&mac.finalize().into_bytes())
                )
            }
        };
        let query_string = query
            .iter()
            .map(|(name, value)| format!("{name}={}", encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        let url = if query_string.is_empty() {
            format!("{}{path}", self.container_url)
        } else {
            format!("{}{path}?{query_string}", self.container_url)
        };
        let mut builder = self
            .http
            .request(method, url)
            .header(reqwest::header::AUTHORIZATION, authorization)
            .body(body);
        for (name, value) in headers {
            if name != "content-length" {
                builder = builder.header(name, value);
            }
        }
        builder.send().await.map_err(|err| failed("request", err))
    }

    fn blob_path(&self, key: &str) -> Result<String, StoreError> {
        check_key(key)?;
        Ok(format!("/{}{key}", self.prefix))
    }
}

async fn error_text(response: reqwest::Response) -> String {
    let status = response.status();
    let code = response
        .headers()
        .get("x-ms-error-code")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
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

impl Store for BlobStore {
    fn describe(&self) -> String {
        format!(
            "azure blob container {}/{}",
            self.container_url, self.prefix
        )
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Object>, StoreError>> {
        Box::pin(async move {
            let path = self.blob_path(key)?;
            let response = self
                .send(reqwest::Method::GET, &path, &[], &[], Vec::new())
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
            let path = self.blob_path(key)?;
            let mut headers = vec![
                ("content-type", "application/json".to_string()),
                ("x-ms-blob-type", "BlockBlob".to_string()),
            ];
            match &precondition {
                Precondition::None => {}
                Precondition::Absent => headers.push(("if-none-match", "*".into())),
                Precondition::Version(version) => headers.push(("if-match", version.clone())),
            }
            let response = self
                .send(reqwest::Method::PUT, &path, &[], &headers, data)
                .await?;
            match response.status() {
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
            let mut marker: Option<String> = None;
            loop {
                let mut query = vec![
                    ("comp", "list".to_string()),
                    ("prefix", full_prefix.clone()),
                    ("restype", "container".to_string()),
                ];
                if let Some(marker) = &marker {
                    query.push(("marker", marker.clone()));
                }
                let response = self
                    .send(reqwest::Method::GET, "", &query, &[], Vec::new())
                    .await?;
                if !response.status().is_success() {
                    return Err(failed("List Blobs", error_text(response).await));
                }
                let xml = response
                    .text()
                    .await
                    .map_err(|err| failed("List Blobs", err))?;
                let (names, next) = parse_list(&xml);
                keys.extend(
                    names
                        .into_iter()
                        .filter_map(|name| name.strip_prefix(&self.prefix).map(str::to_string)),
                );
                match next {
                    Some(next) => marker = Some(next),
                    None => break,
                }
            }
            keys.sort();
            Ok(keys)
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let path = self.blob_path(key)?;
            let response = self
                .send(reqwest::Method::DELETE, &path, &[], &[], Vec::new())
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
    fn dates() {
        let time = std::time::UNIX_EPOCH + Duration::from_secs(1_794_731_988);
        assert_eq!(http_date(time), "Sun, 15 Nov 2026 08:39:48 GMT");
        assert_eq!(
            http_date(std::time::UNIX_EPOCH),
            "Thu, 01 Jan 1970 00:00:00 GMT"
        );
    }

    #[test]
    fn list_response() {
        let xml = "<EnumerationResults><Blobs><Blob><Name>p/a.json</Name><Properties/></Blob>\
                   <Blob><Name>p/b.json</Name></Blob></Blobs><NextMarker>m2</NextMarker></EnumerationResults>";
        assert_eq!(
            parse_list(xml),
            (
                vec!["p/a.json".into(), "p/b.json".into()],
                Some("m2".into())
            )
        );
        assert_eq!(parse_list("<NextMarker />").1, None);
    }

    /// Against Azurite: `SSH_CASIGN_TEST_AZURITE=http://127.0.0.1:10000/devstoreaccount1`
    /// with a container `ssh-casign-test` (Shared Key, the well-known key).
    #[tokio::test]
    #[ignore = "needs Azurite"]
    async fn azurite() {
        let Ok(url) = std::env::var("SSH_CASIGN_TEST_AZURITE") else {
            return;
        };
        let key_file = std::env::temp_dir().join(format!("azurite-key-{}", std::process::id()));
        std::fs::write(
            &key_file,
            "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",
        )
        .unwrap();
        let config: toml::Table = toml::from_str(&format!(
            "account_url = \"{url}\"\ncontainer = \"ssh-casign-test\"\nprefix = \"t{}\"\n\
             account_key_file = {:?}\naccount_name = \"devstoreaccount1\"\n",
            std::process::id(),
            key_file.to_str().unwrap()
        ))
        .unwrap();
        // Create the container (signed like every other request).
        let creator = BlobStore {
            http: reqwest::Client::new(),
            auth: Auth::SharedKey {
                account: "devstoreaccount1".into(),
                key: Base64::decode_vec(std::fs::read_to_string(&key_file).unwrap().trim())
                    .unwrap(),
            },
            container_url: format!("{url}/ssh-casign-test"),
            container_path: "/devstoreaccount1/ssh-casign-test".into(),
            prefix: String::new(),
        };
        let response = creator
            .send(
                reqwest::Method::PUT,
                "",
                &[("restype", "container".to_string())],
                &[],
                Vec::new(),
            )
            .await
            .unwrap();
        assert!(
            response.status().is_success() || response.status() == reqwest::StatusCode::CONFLICT,
            "create container: {}",
            response.status()
        );
        let store = load_store(config).await.unwrap();
        ssh_casign_store::testing::exercise(store.as_ref(), "")
            .await
            .unwrap();
        std::fs::remove_file(key_file).unwrap();
    }
}
