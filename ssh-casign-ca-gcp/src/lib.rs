//! ssh-casign CA backend: CA key in Google Cloud KMS.
//!
//! The key never leaves Cloud KMS. A Cloud KMS key version has one algorithm,
//! which decides the signature algorithms it offers:
//!
//! | Cloud KMS algorithm                     | SSH signature algorithms                     |
//! |-----------------------------------------|----------------------------------------------|
//! | `EC_SIGN_ED25519`                       | `ssh-ed25519` (the certificate is signed as is) |
//! | `EC_SIGN_P256_SHA256`                   | `ecdsa-sha2-nistp256`                        |
//! | `EC_SIGN_P384_SHA384`                   | `ecdsa-sha2-nistp384`                        |
//! | `RSA_SIGN_PKCS1_*_SHA256`               | `rsa-sha2-256`                               |
//! | `RSA_SIGN_PKCS1_4096_SHA512`            | `rsa-sha2-512`                               |
//! | `RSA_SIGN_RAW_PKCS1_2048/3072/4096`     | `rsa-sha2-512`, `rsa-sha2-256`, `ssh-rsa` (the service builds the `DigestInfo`) |
//!
//! ```toml
//! [authorities.gcp]
//! provider = "gcp_kms"
//! key_version = "projects/p/locations/europe-west1/keyRings/ssh/cryptoKeys/ca/cryptoKeyVersions/1"
//! cert_types = ["user"]
//! ```

#[cfg(not(any(feature = "native-tls", feature = "rustls")))]
compile_error!("enable a TLS feature: native-tls (default) or rustls");

use std::{path::PathBuf, time::Duration};

use base64ct::{Base64, Encoding as _};
use serde::Deserialize;
use ssh_casign_ca::{encoding, Backend, BackendError, BoxFuture, SignatureAlgorithm};
use ssh_key::public::{EcdsaPublicKey, Ed25519PublicKey, KeyData, RsaPublicKey};

mod credentials;
pub mod gcs;

use credentials::Credentials;

/// The `provider` name of this backend.
pub const PROVIDER: &str = "gcp_kms";

const DEFAULT_ENDPOINT: &str = "https://cloudkms.googleapis.com";

/// [`ssh_casign_ca::Loader`] for this backend.
pub fn load(config: toml::Table) -> BoxFuture<'static, Result<Box<dyn Backend>, String>> {
    Box::pin(async move {
        let config: Config = ssh_casign_ca::parse_config(config)?;
        Ok(Box::new(config.open().await?) as Box<dyn Backend>)
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    /// Full resource name of the key version:
    /// `projects/…/locations/…/keyRings/…/cryptoKeys/…/cryptoKeyVersions/…`
    key_version: String,
    /// Service account key or gcloud credentials file; default:
    /// `GOOGLE_APPLICATION_CREDENTIALS`, the gcloud file, else the metadata
    /// server.
    credentials_file: Option<PathBuf>,
    /// Default `https://cloudkms.googleapis.com` (e.g. a regional or private
    /// endpoint, or a test server).
    endpoint_url: Option<String>,
    /// Extra CA certificate (PEM) to trust for the endpoint.
    ca_cert_file: Option<PathBuf>,
}

#[derive(Deserialize)]
struct PublicKeyResponse {
    pem: String,
    algorithm: String,
    name: String,
}

#[derive(Deserialize)]
struct SignResponse {
    signature: String,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: ErrorDetail,
}

#[derive(Deserialize)]
struct ErrorDetail {
    status: Option<String>,
    message: String,
}

/// How a Cloud KMS algorithm signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Input {
    /// `data`: the message itself (Ed25519).
    Message,
    /// `digest.<hash>`: a hash computed here.
    Digest,
    /// `data`: a PKCS#1 `DigestInfo` built here (raw RSA keys).
    DigestInfo,
}

/// SSH signature algorithms and input kind for a Cloud KMS algorithm.
fn algorithms(kms_algorithm: &str) -> Option<(Vec<SignatureAlgorithm>, Input)> {
    use SignatureAlgorithm::*;
    Some(match kms_algorithm {
        "EC_SIGN_ED25519" => (vec![Ed25519], Input::Message),
        "EC_SIGN_P256_SHA256" => (vec![EcdsaP256], Input::Digest),
        "EC_SIGN_P384_SHA384" => (vec![EcdsaP384], Input::Digest),
        "RSA_SIGN_PKCS1_2048_SHA256"
        | "RSA_SIGN_PKCS1_3072_SHA256"
        | "RSA_SIGN_PKCS1_4096_SHA256" => (vec![RsaSha256], Input::Digest),
        "RSA_SIGN_PKCS1_4096_SHA512" => (vec![RsaSha512], Input::Digest),
        "RSA_SIGN_RAW_PKCS1_2048" | "RSA_SIGN_RAW_PKCS1_3072" | "RSA_SIGN_RAW_PKCS1_4096" => {
            (vec![RsaSha512, RsaSha256, SshRsa], Input::DigestInfo)
        }
        _ => return None,
    })
}

/// Name of the digest field for a signature algorithm.
fn digest_field(algorithm: SignatureAlgorithm) -> &'static str {
    match algorithm {
        SignatureAlgorithm::EcdsaP384 => "sha384",
        SignatureAlgorithm::RsaSha512 | SignatureAlgorithm::EcdsaP521 => "sha512",
        _ => "sha256",
    }
}

/// The SSH public key for a Cloud KMS public key in PEM.
fn public_key(kms_algorithm: &str, pem: &str) -> Result<KeyData, String> {
    let invalid =
        |err: &dyn std::fmt::Display| format!("invalid {kms_algorithm} public key: {err}");
    if kms_algorithm == "EC_SIGN_ED25519" {
        // SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING { 0, key } }
        const PREFIX: &[u8] = &[
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let der = Base64::decode_vec(body.trim()).map_err(|err| invalid(&err))?;
        let key = der
            .strip_prefix(PREFIX)
            .filter(|key| key.len() == 32)
            .ok_or_else(|| invalid(&"not an Ed25519 SubjectPublicKeyInfo"))?;
        return Ok(KeyData::Ed25519(Ed25519PublicKey(
            key.try_into().expect("32 bytes"),
        )));
    }
    if kms_algorithm.starts_with("EC_SIGN_P256") || kms_algorithm.starts_with("EC_SIGN_P384") {
        let point = if kms_algorithm.starts_with("EC_SIGN_P256") {
            use p256::pkcs8::DecodePublicKey;
            p256::PublicKey::from_public_key_pem(pem)
                .map(|key| p256::EncodedPoint::from(key).as_bytes().to_vec())
                .map_err(|err| invalid(&err))?
        } else {
            use p384::pkcs8::DecodePublicKey;
            p384::PublicKey::from_public_key_pem(pem)
                .map(|key| p384::EncodedPoint::from(key).as_bytes().to_vec())
                .map_err(|err| invalid(&err))?
        };
        return EcdsaPublicKey::from_sec1_bytes(&point)
            .map(KeyData::Ecdsa)
            .map_err(|err| invalid(&err));
    }
    use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts};
    let key = rsa::RsaPublicKey::from_public_key_pem(pem).map_err(|err| invalid(&err))?;
    let mpint = |n: &rsa::BigUint| {
        ssh_key::Mpint::from_positive_bytes(&n.to_bytes_be()).map_err(|err| invalid(&err))
    };
    Ok(KeyData::Rsa(RsaPublicKey {
        e: mpint(key.e())?,
        n: mpint(key.n())?,
    }))
}

impl Config {
    async fn open(&self) -> Result<KmsKey, String> {
        if !self.key_version.contains("/cryptoKeyVersions/") {
            return Err(format!(
                "key_version must be a full key version name (…/cryptoKeyVersions/<n>), not {}",
                self.key_version
            ));
        }
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
        if let Some(file) = &self.ca_cert_file {
            let pem = std::fs::read(file).map_err(|err| format!("{}: {err}", file.display()))?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|err| format!("{}: {err}", file.display()))?;
            builder = builder.add_root_certificate(certificate);
        }
        let http = builder.build().map_err(|err| err.to_string())?;
        let credentials = Credentials::new(
            http.clone(),
            self.credentials_file.as_deref(),
            credentials::KMS_SCOPE,
        )
        .await?;
        let endpoint = self
            .endpoint_url
            .clone()
            .unwrap_or_else(|| DEFAULT_ENDPOINT.into())
            .trim_end_matches('/')
            .to_string();
        let mut key = KmsKey {
            http,
            credentials,
            url: format!("{endpoint}/v1/{}", self.key_version.trim_matches('/')),
            name: self.key_version.clone(),
            kms_algorithm: String::new(),
            input: Input::Digest,
            public_key: KeyData::Ed25519(Ed25519PublicKey([0; 32])),
            algorithms: Vec::new(),
        };
        let response: PublicKeyResponse = key
            .request(
                reqwest::Method::GET,
                &format!("{}/publicKey", key.url),
                None,
            )
            .await
            .map_err(|err| err.0)?;
        let (algorithms, input) = algorithms(&response.algorithm).ok_or_else(|| {
            format!(
                "Cloud KMS algorithm {} can't be used for an SSH CA key",
                response.algorithm
            )
        })?;
        key.public_key = public_key(&response.algorithm, &response.pem)?;
        key.algorithms = algorithms;
        key.input = input;
        key.kms_algorithm = response.algorithm;
        key.name = response.name;
        Ok(key)
    }
}

pub struct KmsKey {
    http: reqwest::Client,
    credentials: Credentials,
    /// `<endpoint>/v1/<key version name>`
    url: String,
    name: String,
    kms_algorithm: String,
    input: Input,
    public_key: KeyData,
    algorithms: Vec<SignatureAlgorithm>,
}

impl KmsKey {
    async fn request<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T, BackendError> {
        let token = self.credentials.token().await.map_err(BackendError::new)?;
        let mut request = self.http.request(method, url).bearer_auth(token);
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
            let detail = serde_json::from_str::<ErrorResponse>(&text)
                .map(|body| {
                    format!(
                        "{}: {}",
                        body.error.status.unwrap_or_default(),
                        body.error.message
                    )
                })
                .unwrap_or_else(|_| text.trim().to_string());
            return Err(BackendError::new(format!("{url}: {status}: {detail}")));
        }
        response
            .json()
            .await
            .map_err(|err| BackendError::new(format!("{url}: invalid response: {err}")))
    }
}

impl Backend for KmsKey {
    fn describe(&self) -> String {
        format!(
            "gcp_kms {} ({}, {})",
            self.name,
            self.kms_algorithm,
            self.credentials.describe()
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
            if !self.algorithms.contains(&algorithm) {
                return Err(BackendError::new(format!(
                    "{} can't sign with {algorithm}",
                    self.kms_algorithm
                )));
            }
            let body = match self.input {
                Input::Message => serde_json::json!({ "data": Base64::encode_string(data) }),
                Input::DigestInfo => {
                    let info =
                        encoding::rsa_digest_info(algorithm, data).map_err(BackendError::new)?;
                    serde_json::json!({ "data": Base64::encode_string(&info) })
                }
                Input::Digest => serde_json::json!({
                    "digest": {
                        digest_field(algorithm): Base64::encode_string(&encoding::digest(algorithm, data))
                    }
                }),
            };
            let response: SignResponse = self
                .request(
                    reqwest::Method::POST,
                    &format!("{}:asymmetricSign", self.url),
                    Some(body),
                )
                .await?;
            let raw = Base64::decode_vec(&response.signature)
                .map_err(|err| BackendError::new(format!("invalid signature encoding: {err}")))?;
            match algorithm {
                SignatureAlgorithm::EcdsaP256 | SignatureAlgorithm::EcdsaP384 => {
                    encoding::ecdsa_signature_from_der(&raw).map_err(BackendError::new)
                }
                _ => Ok(raw),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_table() {
        use SignatureAlgorithm::*;
        assert_eq!(
            algorithms("EC_SIGN_ED25519"),
            Some((vec![Ed25519], Input::Message))
        );
        assert_eq!(
            algorithms("RSA_SIGN_PKCS1_3072_SHA256"),
            Some((vec![RsaSha256], Input::Digest))
        );
        assert_eq!(
            algorithms("RSA_SIGN_RAW_PKCS1_2048"),
            Some((vec![RsaSha512, RsaSha256, SshRsa], Input::DigestInfo))
        );
        assert_eq!(algorithms("RSA_SIGN_PSS_2048_SHA256"), None);
        assert_eq!(algorithms("EC_SIGN_SECP256K1_SHA256"), None);
        assert_eq!(digest_field(EcdsaP384), "sha384");
        assert_eq!(digest_field(RsaSha512), "sha512");
    }

    #[test]
    fn public_keys_from_pem() {
        use rsa::pkcs8::EncodePublicKey;
        let key = ssh_key::PrivateKey::from_openssh(ssh_casign_ca::testing::RSA_CA).unwrap();
        let ssh_key::private::KeypairData::Rsa(keypair) = key.key_data() else {
            unreachable!()
        };
        let private = encoding::rsa_private_key(keypair).unwrap();
        let pem = rsa::RsaPublicKey::from(&private)
            .to_public_key_pem(Default::default())
            .unwrap();
        assert_eq!(
            &public_key("RSA_SIGN_RAW_PKCS1_2048", &pem).unwrap(),
            key.public_key().key_data()
        );

        let mut der = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        der.extend([9u8; 32]);
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            Base64::encode_string(&der)
        );
        assert_eq!(
            public_key("EC_SIGN_ED25519", &pem).unwrap(),
            KeyData::Ed25519(Ed25519PublicKey([9; 32]))
        );
        assert!(public_key("EC_SIGN_P256_SHA256", &pem).is_err());
    }
}

#[cfg(test)]
mod federation_tests {
    /// Against the federation mock: `SSH_CASIGN_TEST_GCP_WIF=<dir>` with
    /// `file-impersonate.json` and `url-direct.json` (external_account
    /// files) and the mock's KMS at `SSH_CASIGN_TEST_GCP_ENDPOINT`.
    #[tokio::test]
    #[ignore = "needs the workload identity federation mock"]
    async fn workload_identity_federation() {
        let (Ok(dir), Ok(endpoint)) = (
            std::env::var("SSH_CASIGN_TEST_GCP_WIF"),
            std::env::var("SSH_CASIGN_TEST_GCP_ENDPOINT"),
        ) else {
            return;
        };
        for file in ["file-impersonate.json", "url-direct.json"] {
            let config: toml::Table = toml::from_str(&format!(
                "key_version = \"projects/p/locations/europe-west1/keyRings/ssh/cryptoKeys/ed/cryptoKeyVersions/1\"\n\
                 endpoint_url = \"{endpoint}\"\ncredentials_file = \"{dir}/{file}\"\n"
            ))
            .unwrap();
            let backend = super::load(config)
                .await
                .unwrap_or_else(|err| panic!("{file}: {err}"));
            assert!(backend.describe().contains("workload identity federation"));
            ssh_casign_ca::testing::issue_with_every_algorithm(backend.as_ref())
                .await
                .unwrap_or_else(|err| panic!("{file}: {err}"));
        }
    }
}
