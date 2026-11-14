//! ssh-casign CA backend: CA key in AWS KMS.
//!
//! The key never leaves KMS. Key specs: `ECC_NIST_EDWARDS25519` (Ed25519,
//! message signed as is, at most 4096 bytes), `ECC_NIST_P256/P384/P521`
//! and `RSA_2048/3072/4096` (the service hashes, KMS signs the digest). KMS
//! has no SHA-1 RSA signatures, so `ssh-rsa` needs an authority on another
//! backend.
//!
//! ```toml
//! [authorities.kms]
//! provider = "aws_kms"
//! key_id = "alias/ssh-ca"   # key ID, key ARN or alias (ARN)
//! # region = "eu-west-1"     # default: from the ARN, else AWS_REGION / AWS_DEFAULT_REGION
//! cert_types = ["user"]
//! ```
//!
//! Requests are signed with AWS Signature Version 4; credentials come from
//! the usual places (see [`credentials`]). Aliases are resolved once at
//! startup: the service signs with the key it advertises, even if the alias
//! is moved later.

#[cfg(not(any(feature = "native-tls", feature = "rustls")))]
compile_error!("enable a TLS feature: native-tls (default) or rustls");

use std::{path::PathBuf, time::Duration};

use base64ct::{Base64, Encoding as _};
use serde::Deserialize;
use ssh_casign_ca::{encoding, Backend, BackendError, BoxFuture, SignatureAlgorithm};
use ssh_key::public::{EcdsaPublicKey, Ed25519PublicKey, KeyData, RsaPublicKey};

mod credentials;
mod sigv4;
mod time;

use credentials::Provider;

/// The `provider` name of this backend.
pub const PROVIDER: &str = "aws_kms";

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
    /// Key ID, key ARN, alias name (`alias/...`) or alias ARN.
    key_id: String,
    /// Default: the region in an ARN `key_id`, else `AWS_REGION` or
    /// `AWS_DEFAULT_REGION`.
    region: Option<String>,
    /// e.g. a VPC endpoint, a FIPS endpoint, or LocalStack; default
    /// `AWS_ENDPOINT_URL_KMS`, `AWS_ENDPOINT_URL`, else
    /// `https://kms.<region>.amazonaws.com`.
    endpoint_url: Option<String>,
    /// Profile in `~/.aws/credentials` (default: `AWS_PROFILE`, else the
    /// credential chain).
    profile: Option<String>,
    /// Extra CA certificate (PEM) to trust for the endpoint.
    ca_cert_file: Option<PathBuf>,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// `arn:aws:kms:<region>:<account>:key/...` → region.
fn region_from_arn(key_id: &str) -> Option<String> {
    let mut parts = key_id.split(':');
    (parts.next()? == "arn").then_some(())?;
    let _partition = parts.next()?;
    (parts.next()? == "kms").then_some(())?;
    parts
        .next()
        .filter(|region| !region.is_empty())
        .map(String::from)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetPublicKeyResponse {
    key_id: String,
    public_key: String,
    key_spec: String,
    signing_algorithms: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SignResponse {
    signature: String,
}

#[derive(Deserialize)]
struct ErrorResponse {
    #[serde(rename = "__type")]
    kind: Option<String>,
    message: Option<String>,
    #[serde(rename = "Message")]
    message_upper: Option<String>,
}

/// KMS signing algorithm and message type for an SSH signature algorithm.
fn kms_algorithm(algorithm: SignatureAlgorithm) -> Option<(&'static str, &'static str)> {
    Some(match algorithm {
        SignatureAlgorithm::Ed25519 => ("ED25519_SHA_512", "RAW"),
        SignatureAlgorithm::EcdsaP256 => ("ECDSA_SHA_256", "DIGEST"),
        SignatureAlgorithm::EcdsaP384 => ("ECDSA_SHA_384", "DIGEST"),
        SignatureAlgorithm::EcdsaP521 => ("ECDSA_SHA_512", "DIGEST"),
        SignatureAlgorithm::RsaSha256 => ("RSASSA_PKCS1_V1_5_SHA_256", "DIGEST"),
        SignatureAlgorithm::RsaSha512 => ("RSASSA_PKCS1_V1_5_SHA_512", "DIGEST"),
        SignatureAlgorithm::SshRsa => return None,
    })
}

/// The SSH public key for a KMS key's DER `SubjectPublicKeyInfo`.
fn public_key(key_spec: &str, der: &[u8]) -> Result<KeyData, String> {
    let ec_point = |result: Result<Vec<u8>, String>| -> Result<KeyData, String> {
        let point = result?;
        EcdsaPublicKey::from_sec1_bytes(&point)
            .map(KeyData::Ecdsa)
            .map_err(|err| format!("invalid {key_spec} key: {err}"))
    };
    match key_spec {
        "ECC_NIST_EDWARDS25519" => {
            // SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING { 0, key } }
            const PREFIX: &[u8] = &[
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
            ];
            let key = der
                .strip_prefix(PREFIX)
                .filter(|key| key.len() == 32)
                .ok_or("invalid Ed25519 public key")?;
            Ok(KeyData::Ed25519(Ed25519PublicKey(
                key.try_into().expect("32 bytes"),
            )))
        }
        "ECC_NIST_P256" => ec_point({
            use p256::pkcs8::DecodePublicKey;
            p256::PublicKey::from_public_key_der(der)
                .map(|key| p256::EncodedPoint::from(key).as_bytes().to_vec())
                .map_err(|err| err.to_string())
        }),
        "ECC_NIST_P384" => ec_point({
            use p384::pkcs8::DecodePublicKey;
            p384::PublicKey::from_public_key_der(der)
                .map(|key| p384::EncodedPoint::from(key).as_bytes().to_vec())
                .map_err(|err| err.to_string())
        }),
        "ECC_NIST_P521" => ec_point({
            use p521::pkcs8::DecodePublicKey;
            p521::PublicKey::from_public_key_der(der)
                .map(|key| p521::EncodedPoint::from(key).as_bytes().to_vec())
                .map_err(|err| err.to_string())
        }),
        "RSA_2048" | "RSA_3072" | "RSA_4096" => {
            use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts};
            let key = rsa::RsaPublicKey::from_public_key_der(der)
                .map_err(|err| format!("invalid RSA public key: {err}"))?;
            let mpint = |n: &rsa::BigUint| {
                ssh_key::Mpint::from_positive_bytes(&n.to_bytes_be()).map_err(|err| err.to_string())
            };
            Ok(KeyData::Rsa(RsaPublicKey {
                e: mpint(key.e())?,
                n: mpint(key.n())?,
            }))
        }
        other => Err(format!(
            "KMS key spec {other} can't be used as an SSH CA key"
        )),
    }
}

impl Config {
    async fn open(&self) -> Result<KmsKey, String> {
        let region = self
            .region
            .clone()
            .or_else(|| region_from_arn(&self.key_id))
            .or_else(|| env("AWS_REGION"))
            .or_else(|| env("AWS_DEFAULT_REGION"))
            .ok_or("set region (or AWS_REGION)")?;
        let endpoint = self
            .endpoint_url
            .clone()
            .or_else(|| env("AWS_ENDPOINT_URL_KMS"))
            .or_else(|| env("AWS_ENDPOINT_URL"))
            .unwrap_or_else(|| format!("https://kms.{region}.amazonaws.com"));
        let endpoint = endpoint.trim_end_matches('/').to_string();
        let host = endpoint
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(&endpoint)
            .split('/')
            .next()
            .unwrap_or_default()
            .to_string();

        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
        if let Some(file) = &self.ca_cert_file {
            let pem = std::fs::read(file).map_err(|err| format!("{}: {err}", file.display()))?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|err| format!("{}: {err}", file.display()))?;
            builder = builder.add_root_certificate(certificate);
        }
        let http = builder.build().map_err(|err| err.to_string())?;
        let credentials = Provider::new(http.clone(), &region, self.profile.as_deref()).await?;

        let mut key = KmsKey {
            http,
            credentials,
            region,
            endpoint,
            host,
            key_arn: self.key_id.clone(),
            public_key: KeyData::Ed25519(Ed25519PublicKey([0; 32])),
            algorithms: Vec::new(),
        };
        let response: GetPublicKeyResponse = key
            .call("GetPublicKey", serde_json::json!({ "KeyId": self.key_id }))
            .await
            .map_err(|err| err.0)?;
        let der = Base64::decode_vec(&response.public_key)
            .map_err(|err| format!("invalid public key encoding: {err}"))?;
        key.public_key = public_key(&response.key_spec, &der)?;
        let offered = response.signing_algorithms.unwrap_or_default();
        key.algorithms = SignatureAlgorithm::for_key(&key.public_key)?
            .0
            .into_iter()
            .filter(|algorithm| {
                kms_algorithm(*algorithm)
                    .is_some_and(|(name, _)| offered.iter().any(|offered| offered == name))
            })
            .collect();
        key.key_arn = response.key_id;
        Ok(key)
    }
}

pub struct KmsKey {
    http: reqwest::Client,
    credentials: Provider,
    region: String,
    endpoint: String,
    host: String,
    /// The resolved key ARN; signing uses exactly this key.
    key_arn: String,
    public_key: KeyData,
    algorithms: Vec<SignatureAlgorithm>,
}

impl KmsKey {
    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        action: &str,
        body: serde_json::Value,
    ) -> Result<T, BackendError> {
        let credentials = self
            .credentials
            .credentials()
            .await
            .map_err(BackendError::new)?;
        let body = serde_json::to_vec(&body).map_err(BackendError::new)?;
        let headers = sigv4::sign(
            &credentials,
            &self.region,
            "kms",
            &self.host,
            &format!("TrentService.{action}"),
            &body,
            std::time::SystemTime::now(),
        );
        let mut request = self.http.post(format!("{}/", self.endpoint)).body(body);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let response = request
            .send()
            .await
            .map_err(|err| BackendError::new(format!("KMS {action}: {err}")))?;
        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            let detail = serde_json::from_str::<ErrorResponse>(&text)
                .ok()
                .map(|error| {
                    format!(
                        "{}: {}",
                        error
                            .kind
                            .unwrap_or_default()
                            .rsplit('#')
                            .next()
                            .unwrap_or_default(),
                        error.message.or(error.message_upper).unwrap_or_default()
                    )
                })
                .unwrap_or_else(|| text.trim().to_string());
            return Err(BackendError::new(format!(
                "KMS {action}: {status}: {detail}"
            )));
        }
        response
            .json()
            .await
            .map_err(|err| BackendError::new(format!("KMS {action}: invalid response: {err}")))
    }
}

impl Backend for KmsKey {
    fn describe(&self) -> String {
        format!("aws_kms {} ({})", self.key_arn, self.credentials.describe())
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
            let (kms_algorithm, message_type) = kms_algorithm(algorithm)
                .ok_or_else(|| BackendError::new(format!("KMS can't sign with {algorithm}")))?;
            let message = if message_type == "RAW" {
                if data.len() > 4096 {
                    return Err(BackendError::new(format!(
                        "certificate too large for KMS Ed25519 signing ({} bytes, at most 4096)",
                        data.len()
                    )));
                }
                data.to_vec()
            } else {
                encoding::digest(algorithm, data)
            };
            let response: SignResponse = self
                .call(
                    "Sign",
                    serde_json::json!({
                        "KeyId": self.key_arn,
                        "Message": Base64::encode_string(&message),
                        "MessageType": message_type,
                        "SigningAlgorithm": kms_algorithm,
                    }),
                )
                .await?;
            let raw = Base64::decode_vec(&response.signature)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regions_from_arns() {
        assert_eq!(
            region_from_arn("arn:aws:kms:eu-west-1:111122223333:key/1234").as_deref(),
            Some("eu-west-1")
        );
        assert_eq!(
            region_from_arn("arn:aws-us-gov:kms:us-gov-west-1:1:alias/x").as_deref(),
            Some("us-gov-west-1")
        );
        assert_eq!(region_from_arn("alias/ssh-ca"), None);
        assert_eq!(
            region_from_arn("1234abcd-12ab-34cd-56ef-1234567890ab"),
            None
        );
    }

    #[test]
    fn public_keys_from_spki() {
        let mut der = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        der.extend([7u8; 32]);
        assert_eq!(
            public_key("ECC_NIST_EDWARDS25519", &der).unwrap(),
            KeyData::Ed25519(Ed25519PublicKey([7; 32]))
        );
        assert!(public_key("ECC_NIST_EDWARDS25519", &der[..40]).is_err());

        use rsa::pkcs8::EncodePublicKey;
        let key = ssh_key::PrivateKey::from_openssh(ssh_casign_ca::testing::RSA_CA).unwrap();
        let ssh_key::private::KeypairData::Rsa(keypair) = key.key_data() else {
            unreachable!()
        };
        let private = encoding::rsa_private_key(keypair).unwrap();
        let der = rsa::RsaPublicKey::from(&private)
            .to_public_key_der()
            .unwrap();
        assert_eq!(
            &public_key("RSA_2048", der.as_bytes()).unwrap(),
            key.public_key().key_data()
        );
        assert!(public_key("ECC_SECG_P256K1", &[]).is_err());
    }

    #[test]
    fn algorithm_mapping() {
        assert_eq!(
            kms_algorithm(SignatureAlgorithm::Ed25519),
            Some(("ED25519_SHA_512", "RAW"))
        );
        assert_eq!(
            kms_algorithm(SignatureAlgorithm::EcdsaP384),
            Some(("ECDSA_SHA_384", "DIGEST"))
        );
        assert_eq!(kms_algorithm(SignatureAlgorithm::SshRsa), None);
    }
}
