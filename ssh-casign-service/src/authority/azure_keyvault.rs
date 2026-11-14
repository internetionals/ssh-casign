//! CA key in Azure Key Vault or Azure Managed HSM.
//!
//! The key never leaves the vault; the service hashes the certificate and
//! asks Key Vault to sign the hash. Key types: EC (P-256, P-384, P-521) and
//! RSA, software- or HSM-protected. Key Vault has no Ed25519 and no SHA-1
//! RSA signatures, so `ssh-rsa` needs an authority on another backend.
//!
//! The key version is fixed when the service starts (the current one, or
//! `key_version`), so the advertised public key always matches the
//! signatures; after rotating the key, restart the service.

use std::{path::PathBuf, time::Duration};

use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::Deserialize;
use ssh_key::public::{EcdsaPublicKey, KeyData, RsaPublicKey};

use super::{encoding, signing::SignatureAlgorithm, Backend, BackendError, BoxFuture};
use crate::azure::{Credential, CredentialConfig};

const API_VERSION: &str = "7.4";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// e.g. `https://my-vault.vault.azure.net` or
    /// `https://my-hsm.managedhsm.azure.net`
    vault_url: String,
    /// Key name.
    key: String,
    /// Key version; default: the current version at startup.
    key_version: Option<String>,
    /// Extra CA certificate (PEM) to trust, e.g. for an emulator.
    ca_cert_file: Option<PathBuf>,
    #[serde(flatten)]
    credential: CredentialConfig,
}

/// JSON Web Key as Key Vault returns it.
#[derive(Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

#[derive(Deserialize)]
struct KeyBundle {
    key: Jwk,
}

#[derive(Deserialize)]
struct SignResult {
    value: String,
}

/// Base64url, with or without padding (Key Vault omits it).
fn base64url(value: &str) -> Result<Vec<u8>, String> {
    Base64UrlUnpadded::decode_vec(value.trim_end_matches('='))
        .map_err(|err| format!("invalid base64url: {err}"))
}

/// The SSH public key and the signature algorithms of a JWK.
fn public_key(jwk: &Jwk) -> Result<(KeyData, Vec<SignatureAlgorithm>), String> {
    let field = |value: &Option<String>, name: &str| {
        value
            .as_deref()
            .ok_or_else(|| format!("key without '{name}'"))
            .and_then(base64url)
    };
    match jwk.kty.as_str() {
        "EC" | "EC-HSM" => {
            let (algorithm, size) = match jwk.crv.as_deref() {
                Some("P-256") => (SignatureAlgorithm::EcdsaP256, 32),
                Some("P-384") => (SignatureAlgorithm::EcdsaP384, 48),
                Some("P-521") => (SignatureAlgorithm::EcdsaP521, 66),
                other => return Err(format!("unsupported curve {other:?}")),
            };
            let (x, y) = (field(&jwk.x, "x")?, field(&jwk.y, "y")?);
            // Coordinates are fixed-size; pad in case leading zeros were dropped.
            let pad = |coordinate: Vec<u8>| -> Result<Vec<u8>, String> {
                if coordinate.len() > size {
                    return Err("EC coordinate too long".into());
                }
                let mut padded = vec![0; size - coordinate.len()];
                padded.extend(coordinate);
                Ok(padded)
            };
            let mut point = vec![0x04];
            point.extend(pad(x)?);
            point.extend(pad(y)?);
            let key = EcdsaPublicKey::from_sec1_bytes(&point)
                .map_err(|err| format!("invalid EC key: {err}"))?;
            Ok((KeyData::Ecdsa(key), vec![algorithm]))
        }
        "RSA" | "RSA-HSM" => {
            let mpint = |bytes: Vec<u8>| {
                ssh_key::Mpint::from_positive_bytes(&bytes).map_err(|err| err.to_string())
            };
            let key = RsaPublicKey {
                e: mpint(field(&jwk.e, "e")?)?,
                n: mpint(field(&jwk.n, "n")?)?,
            };
            Ok((
                KeyData::Rsa(key),
                vec![SignatureAlgorithm::RsaSha512, SignatureAlgorithm::RsaSha256],
            ))
        }
        other => Err(format!("key type {other} can't be used as an SSH CA key")),
    }
}

/// Key Vault's name for a signature algorithm.
fn jws_algorithm(algorithm: SignatureAlgorithm) -> Option<&'static str> {
    Some(match algorithm {
        SignatureAlgorithm::EcdsaP256 => "ES256",
        SignatureAlgorithm::EcdsaP384 => "ES384",
        SignatureAlgorithm::EcdsaP521 => "ES512",
        SignatureAlgorithm::RsaSha256 => "RS256",
        SignatureAlgorithm::RsaSha512 => "RS512",
        SignatureAlgorithm::Ed25519 | SignatureAlgorithm::SshRsa => return None,
    })
}

/// Token audience for a vault URL.
fn resource(vault_url: &str) -> &'static str {
    if vault_url.contains(".managedhsm.") {
        "https://managedhsm.azure.net"
    } else {
        "https://vault.azure.net"
    }
}

impl Config {
    pub(super) async fn load(&self) -> Result<KeyVaultKey, String> {
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
        if let Some(file) = &self.ca_cert_file {
            let pem = std::fs::read(file).map_err(|err| format!("{}: {err}", file.display()))?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|err| format!("{}: {err}", file.display()))?;
            builder = builder.add_root_certificate(certificate);
        }
        let http = builder.build().map_err(|err| err.to_string())?;
        let vault_url = self.vault_url.trim_end_matches('/').to_string();
        let credential = self
            .credential
            .credential(http.clone(), resource(&vault_url))?;
        let mut key = KeyVaultKey {
            http,
            credential,
            key_url: String::new(),
            public_key: KeyData::Ed25519(ssh_key::public::Ed25519PublicKey([0; 32])),
            algorithms: Vec::new(),
        };
        let url = match &self.key_version {
            Some(version) => format!("{vault_url}/keys/{}/{version}", self.key),
            None => format!("{vault_url}/keys/{}", self.key),
        };
        let bundle: KeyBundle = key
            .request(reqwest::Method::GET, &url, None)
            .await
            .map_err(|err| err.0)?;
        let (public_key, algorithms) = public_key(&bundle.key)?;
        // The kid names the version; sign with exactly that one.
        key.key_url = bundle.key.kid.trim_end_matches('/').to_string();
        key.public_key = public_key;
        key.algorithms = algorithms;
        Ok(key)
    }
}

pub(crate) struct KeyVaultKey {
    http: reqwest::Client,
    credential: Credential,
    /// `<vault>/keys/<name>/<version>`
    key_url: String,
    public_key: KeyData,
    algorithms: Vec<SignatureAlgorithm>,
}

#[derive(Deserialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Deserialize)]
struct ErrorDetail {
    code: String,
    message: String,
}

impl KeyVaultKey {
    async fn request<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T, BackendError> {
        let token = self.credential.token().await.map_err(BackendError::new)?;
        let mut request = self
            .http
            .request(method, url)
            .query(&[("api-version", API_VERSION)])
            .bearer_auth(token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .map_err(|err| BackendError::new(format!("{url}: {err}")))?;
        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            let detail = serde_json::from_str::<ErrorBody>(&text)
                .map(|body| format!("{}: {}", body.error.code, body.error.message))
                .unwrap_or_else(|_| text.trim().to_string());
            return Err(BackendError::new(format!("{url}: {status}: {detail}")));
        }
        response
            .json()
            .await
            .map_err(|err| BackendError::new(format!("{url}: invalid response: {err}")))
    }
}

impl Backend for KeyVaultKey {
    fn describe(&self) -> String {
        format!(
            "azure_keyvault {} ({})",
            self.key_url,
            self.credential.describe()
        )
    }

    fn public_key(&self) -> &KeyData {
        &self.public_key
    }

    fn algorithms(&self) -> Vec<SignatureAlgorithm> {
        self.algorithms.clone()
    }

    fn sign<'a>(
        &'a self,
        algorithm: SignatureAlgorithm,
        data: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, BackendError>> {
        Box::pin(async move {
            let alg = jws_algorithm(algorithm).ok_or_else(|| {
                BackendError::new(format!("Key Vault can't sign with {algorithm}"))
            })?;
            let body = serde_json::json!({
                "alg": alg,
                "value": Base64UrlUnpadded::encode_string(&encoding::digest(algorithm, data)),
            });
            let result: SignResult = self
                .request(
                    reqwest::Method::POST,
                    &format!("{}/sign", self.key_url),
                    Some(body),
                )
                .await?;
            let raw = base64url(&result.value).map_err(BackendError::new)?;
            match algorithm {
                SignatureAlgorithm::EcdsaP256
                | SignatureAlgorithm::EcdsaP384
                | SignatureAlgorithm::EcdsaP521 => {
                    encoding::ecdsa_signature_from_raw(&raw).map_err(BackendError::new)
                }
                _ => Ok(raw),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwk(json: serde_json::Value) -> Jwk {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn ec_and_rsa_keys_from_jwk() {
        // A P-256 point from p256's test vectors.
        let secret = p256_secret();
        let (key, algorithms) = public_key(&jwk(serde_json::json!({
            "kid": "https://v.vault.azure.net/keys/k/1",
            "kty": "EC-HSM", "crv": "P-256",
            "x": Base64UrlUnpadded::encode_string(&secret.0),
            "y": Base64UrlUnpadded::encode_string(&secret.1),
        })))
        .unwrap();
        assert_eq!(algorithms, [SignatureAlgorithm::EcdsaP256]);
        assert_eq!(key.algorithm().as_str(), "ecdsa-sha2-nistp256");

        let (key, algorithms) = public_key(&jwk(serde_json::json!({
            "kid": "x", "kty": "RSA", "n": "AQAB", "e": "AQAB",
        })))
        .unwrap();
        assert!(matches!(key, KeyData::Rsa(_)));
        assert_eq!(
            algorithms,
            [SignatureAlgorithm::RsaSha512, SignatureAlgorithm::RsaSha256]
        );

        assert!(public_key(&jwk(serde_json::json!({ "kid": "x", "kty": "oct" }))).is_err());
        assert!(public_key(&jwk(
            serde_json::json!({ "kid": "x", "kty": "EC", "crv": "P-192" })
        ))
        .is_err());
    }

    /// x and y of the P-256 generator point.
    fn p256_secret() -> (Vec<u8>, Vec<u8>) {
        let hex = |s: &str| {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        (
            hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
            hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
        )
    }

    #[test]
    fn algorithms_and_resources() {
        assert_eq!(jws_algorithm(SignatureAlgorithm::EcdsaP384), Some("ES384"));
        assert_eq!(jws_algorithm(SignatureAlgorithm::RsaSha256), Some("RS256"));
        assert_eq!(jws_algorithm(SignatureAlgorithm::SshRsa), None);
        assert_eq!(
            resource("https://x.vault.azure.net"),
            "https://vault.azure.net"
        );
        assert_eq!(
            resource("https://x.managedhsm.azure.net"),
            "https://managedhsm.azure.net"
        );
        assert_eq!(base64url("AQAB").unwrap(), [1, 0, 1]);
        assert_eq!(base64url("AQAB==").unwrap(), [1, 0, 1]);
    }
}
