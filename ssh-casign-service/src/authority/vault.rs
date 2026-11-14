//! CA key in the transit secrets engine of OpenBao or HashiCorp Vault.
//!
//! The key never leaves Vault; the service asks Vault to sign. Supported key
//! types: `ed25519`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `rsa-2048`,
//! `rsa-3072`, `rsa-4096`. RSA keys can sign with SHA-512, SHA-256 and SHA-1
//! (`ssh-rsa`).
//!
//! The key version is fixed when the service starts (the latest one, or
//! `key_version`), so the advertised public key always matches the
//! signatures; after rotating the key in Vault, restart the service.

use std::{path::PathBuf, time::Duration};

use base64ct::{Base64, Encoding as _};
use serde::Deserialize;
use ssh_key::public::{EcdsaPublicKey, Ed25519PublicKey, KeyData, RsaPublicKey};

use super::{encoding, signing::SignatureAlgorithm, Backend, BackendError, BoxFuture};

fn default_mount() -> String {
    "transit".to_string()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// e.g. `https://vault.example.com:8200`
    address: String,
    /// Mount path of the transit engine.
    #[serde(default = "default_mount")]
    mount: String,
    /// Name of the transit key.
    key: String,
    /// Key version to use; default: the latest at startup.
    key_version: Option<u64>,
    /// File with the Vault token; default: the `VAULT_TOKEN` variable.
    token_file: Option<PathBuf>,
    /// Vault Enterprise / OpenBao namespace.
    namespace: Option<String>,
    /// Extra CA certificate (PEM) to trust for the Vault server.
    ca_cert_file: Option<PathBuf>,
}

#[derive(Deserialize)]
struct Response<T> {
    data: T,
}

#[derive(Deserialize)]
struct KeyInfo {
    #[serde(rename = "type")]
    key_type: String,
    latest_version: u64,
    keys: std::collections::BTreeMap<String, KeyVersion>,
}

#[derive(Deserialize)]
struct KeyVersion {
    public_key: String,
}

#[derive(Deserialize)]
struct SignResult {
    signature: String,
}

fn ec_key(pem: &str, key_type: &str) -> Result<KeyData, String> {
    use p256::pkcs8::DecodePublicKey;
    let point = match key_type {
        "ecdsa-p256" => p256::PublicKey::from_public_key_pem(pem)
            .map(|key| p256::EncodedPoint::from(key).as_bytes().to_vec()),
        "ecdsa-p384" => p384::PublicKey::from_public_key_pem(pem)
            .map(|key| p384::EncodedPoint::from(key).as_bytes().to_vec()),
        "ecdsa-p521" => p521::PublicKey::from_public_key_pem(pem)
            .map(|key| p521::EncodedPoint::from(key).as_bytes().to_vec()),
        other => return Err(format!("unexpected key type {other}")),
    }
    .map_err(|err| format!("invalid {key_type} public key: {err}"))?;
    EcdsaPublicKey::from_sec1_bytes(&point)
        .map(KeyData::Ecdsa)
        .map_err(|err| format!("invalid {key_type} public key: {err}"))
}

/// The SSH public key for a transit key's `public_key` field.
fn public_key(key_type: &str, public_key: &str) -> Result<KeyData, String> {
    match key_type {
        "ed25519" => {
            let bytes = Base64::decode_vec(public_key.trim())
                .map_err(|err| format!("invalid ed25519 public key: {err}"))?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "ed25519 public key isn't 32 bytes".to_string())?;
            Ok(KeyData::Ed25519(Ed25519PublicKey(bytes)))
        }
        "ecdsa-p256" | "ecdsa-p384" | "ecdsa-p521" => ec_key(public_key, key_type),
        "rsa-2048" | "rsa-3072" | "rsa-4096" => {
            use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts};
            let key = rsa::RsaPublicKey::from_public_key_pem(public_key)
                .map_err(|err| format!("invalid RSA public key: {err}"))?;
            let mpint = |n: &rsa::BigUint| ssh_key::Mpint::from_positive_bytes(&n.to_bytes_be());
            Ok(KeyData::Rsa(RsaPublicKey {
                e: mpint(key.e()).map_err(|err| err.to_string())?,
                n: mpint(key.n()).map_err(|err| err.to_string())?,
            }))
        }
        other => Err(format!(
            "transit key type {other} can't be used as an SSH CA key"
        )),
    }
}

impl Config {
    pub(super) async fn load(&self) -> Result<VaultKey, String> {
        let token = match &self.token_file {
            Some(file) => std::fs::read_to_string(file)
                .map_err(|err| format!("token file {}: {err}", file.display()))?,
            None => std::env::var("VAULT_TOKEN")
                .map_err(|_| "set token_file or VAULT_TOKEN".to_string())?,
        }
        .trim()
        .to_string();

        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
        if let Some(file) = &self.ca_cert_file {
            let pem = std::fs::read(file).map_err(|err| format!("{}: {err}", file.display()))?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|err| format!("{}: {err}", file.display()))?;
            builder = builder.add_root_certificate(certificate);
        }
        let http = builder.build().map_err(|err| err.to_string())?;
        let base = format!(
            "{}/v1/{}",
            self.address.trim_end_matches('/'),
            self.mount.trim_matches('/')
        );
        let mut key = VaultKey {
            http,
            base,
            name: self.key.clone(),
            token,
            namespace: self.namespace.clone(),
            version: 0,
            key_type: String::new(),
            public_key: KeyData::Ed25519(Ed25519PublicKey([0; 32])),
        };

        let info: KeyInfo = key
            .request(reqwest::Method::GET, &format!("keys/{}", self.key), None)
            .await
            .map_err(|err| err.0)?;
        let version = self.key_version.unwrap_or(info.latest_version);
        let version_info = info
            .keys
            .get(&version.to_string())
            .ok_or_else(|| format!("transit key {} has no version {version}", self.key))?;
        key.public_key = public_key(&info.key_type, &version_info.public_key)?;
        key.key_type = info.key_type;
        key.version = version;
        Ok(key)
    }
}

pub(crate) struct VaultKey {
    http: reqwest::Client,
    /// `<address>/v1/<mount>`
    base: String,
    name: String,
    token: String,
    namespace: Option<String>,
    version: u64,
    key_type: String,
    public_key: KeyData,
}

impl VaultKey {
    async fn request<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T, BackendError> {
        let url = format!("{}/{path}", self.base);
        let mut request = self
            .http
            .request(method, &url)
            .header("X-Vault-Token", &self.token);
        if let Some(namespace) = &self.namespace {
            request = request.header("X-Vault-Namespace", namespace);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .map_err(|err| BackendError::new(format!("{url}: {err}")))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(BackendError::new(format!(
                "{url}: {status}: {}",
                body.trim()
            )));
        }
        let response: Response<T> = response
            .json()
            .await
            .map_err(|err| BackendError::new(format!("{url}: invalid response: {err}")))?;
        Ok(response.data)
    }
}

impl Backend for VaultKey {
    fn describe(&self) -> String {
        format!(
            "vault {}/keys/{} version {} ({})",
            self.base, self.name, self.version, self.key_type
        )
    }

    fn public_key(&self) -> &KeyData {
        &self.public_key
    }

    fn algorithms(&self) -> Vec<SignatureAlgorithm> {
        // Transit can sign with every algorithm the key type allows.
        SignatureAlgorithm::for_key(&self.public_key)
            .map(|(possible, _)| possible)
            .unwrap_or_default()
    }

    fn sign<'a>(
        &'a self,
        algorithm: SignatureAlgorithm,
        data: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, BackendError>> {
        Box::pin(async move {
            let mut body = serde_json::json!({
                "input": Base64::encode_string(data),
                "key_version": self.version,
                "marshaling_algorithm": "asn1",
            });
            let hash = match algorithm {
                SignatureAlgorithm::Ed25519 => None,
                SignatureAlgorithm::EcdsaP256 | SignatureAlgorithm::RsaSha256 => Some("sha2-256"),
                SignatureAlgorithm::EcdsaP384 => Some("sha2-384"),
                SignatureAlgorithm::EcdsaP521 | SignatureAlgorithm::RsaSha512 => Some("sha2-512"),
                SignatureAlgorithm::SshRsa => Some("sha1"),
            };
            if let Some(hash) = hash {
                body["hash_algorithm"] = hash.into();
            }
            if matches!(
                algorithm,
                SignatureAlgorithm::RsaSha512
                    | SignatureAlgorithm::RsaSha256
                    | SignatureAlgorithm::SshRsa
            ) {
                body["signature_algorithm"] = "pkcs1v15".into();
            }
            let result: SignResult = self
                .request(
                    reqwest::Method::POST,
                    &format!("sign/{}", self.name),
                    Some(body),
                )
                .await?;
            // "vault:v<version>:<base64>"
            let encoded = result
                .signature
                .rsplit(':')
                .next()
                .ok_or_else(|| BackendError::new("unexpected signature format"))?;
            let raw = Base64::decode_vec(encoded)
                .map_err(|err| BackendError::new(format!("invalid signature encoding: {err}")))?;
            match algorithm {
                SignatureAlgorithm::EcdsaP256
                | SignatureAlgorithm::EcdsaP384
                | SignatureAlgorithm::EcdsaP521 => {
                    encoding::ecdsa_signature_from_der(&raw).map_err(BackendError::new)
                }
                _ => Ok(raw),
            }
        })
    }
}

#[cfg(all(test, feature = "ca-file"))]
mod tests {
    use super::*;

    #[test]
    fn public_keys_from_transit() {
        let ed25519 = public_key("ed25519", &Base64::encode_string(&[7u8; 32])).unwrap();
        assert_eq!(ed25519, KeyData::Ed25519(Ed25519PublicKey([7; 32])));

        use rsa::pkcs8::EncodePublicKey;
        let key = ssh_key::PrivateKey::from_openssh(include_str!("testdata/rsa-ca")).unwrap();
        let ssh_key::private::KeypairData::Rsa(keypair) = key.key_data() else {
            unreachable!()
        };
        let private = super::super::file::rsa_private_key(keypair).unwrap();
        let pem = rsa::RsaPublicKey::from(&private)
            .to_public_key_pem(Default::default())
            .unwrap();
        assert_eq!(
            &public_key("rsa-2048", &pem).unwrap(),
            key.public_key().key_data()
        );

        assert!(public_key("aes256-gcm96", "x").is_err());
        assert!(public_key("ed25519", "AAAA").is_err());
    }
}
