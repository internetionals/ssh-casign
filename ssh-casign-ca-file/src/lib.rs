//! ssh-casign CA backend: CA key in an OpenSSH private key file (unencrypted).
//!
//! ```toml
//! [authorities.ed25519]
//! provider = "file"
//! private_key_file = "/etc/ssh-casign/ca"
//! cert_types = ["user"]
//! ```

use rsa::{
    pkcs1v15,
    signature::{SignatureEncoding, Signer as _},
};
use serde::Deserialize;
use ssh_casign_ca::{
    encoding::rsa_private_key, Backend, BackendError, BoxFuture, SignatureAlgorithm,
};
use ssh_key::{private::KeypairData, public::KeyData, PrivateKey};
use std::path::PathBuf;

/// The `provider` name of this backend.
pub const PROVIDER: &str = "file";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    private_key_file: PathBuf,
}

/// [`ssh_casign_ca::Loader`] for this backend.
pub fn load(config: toml::Table) -> BoxFuture<'static, Result<Box<dyn Backend>, String>> {
    Box::pin(async move {
        let config: Config = ssh_casign_ca::parse_config(config)?;
        Ok(Box::new(FileKey::load(config.private_key_file)?) as Box<dyn Backend>)
    })
}

pub struct FileKey {
    path: PathBuf,
    key: PrivateKey,
    rsa: Option<rsa::RsaPrivateKey>,
}

impl FileKey {
    pub fn load(path: PathBuf) -> Result<Self, String> {
        let key = PrivateKey::read_openssh_file(&path)
            .map_err(|err| format!("failed to read CA private key {}: {err}", path.display()))?;
        Self::new(path, key)
    }

    pub fn new(path: PathBuf, key: PrivateKey) -> Result<Self, String> {
        let rsa = match key.key_data() {
            KeypairData::Rsa(keypair) => Some(rsa_private_key(keypair)?),
            _ => None,
        };
        Ok(Self { path, key, rsa })
    }

    fn sign_now(
        &self,
        algorithm: SignatureAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, BackendError> {
        if let Some(private) = &self.rsa {
            let private = private.clone();
            return Ok(match algorithm {
                SignatureAlgorithm::RsaSha512 => pkcs1v15::SigningKey::<sha2::Sha512>::new(private)
                    .sign(data)
                    .to_vec(),
                SignatureAlgorithm::RsaSha256 => pkcs1v15::SigningKey::<sha2::Sha256>::new(private)
                    .sign(data)
                    .to_vec(),
                SignatureAlgorithm::SshRsa => pkcs1v15::SigningKey::<sha1::Sha1>::new(private)
                    .sign(data)
                    .to_vec(),
                other => {
                    return Err(BackendError::new(format!(
                        "an RSA key can't sign with {other}"
                    )))
                }
            });
        }
        // Ed25519 and ECDSA: ssh-key signs these itself, in SSH encoding.
        let signature = signature::Signer::<ssh_key::Signature>::try_sign(&self.key, data)
            .map_err(BackendError::new)?;
        if signature.algorithm().as_str() != algorithm.as_str() {
            return Err(BackendError::new(format!(
                "key signs with {}, not {algorithm}",
                signature.algorithm()
            )));
        }
        Ok(signature.as_bytes().to_vec())
    }
}

impl Backend for FileKey {
    fn describe(&self) -> String {
        format!("file {}", self.path.display())
    }

    fn public_key(&self) -> &KeyData {
        self.key.public_key().key_data()
    }

    fn algorithms(&self) -> Vec<SignatureAlgorithm> {
        SignatureAlgorithm::for_key(self.public_key())
            .map(|(possible, _)| possible)
            .unwrap_or_default()
    }

    fn sign<'a>(
        &'a self,
        algorithm: SignatureAlgorithm,
        data: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, BackendError>> {
        // Local and fast (RSA takes a few milliseconds), so no blocking pool.
        Box::pin(async move { self.sign_now(algorithm, data) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_casign_ca::{encoding, signing, testing};

    fn rsa_ca() -> FileKey {
        let key = PrivateKey::from_openssh(testing::RSA_CA).unwrap();
        FileKey::new("testdata/rsa-ca".into(), key).unwrap()
    }

    fn ed25519_ca() -> FileKey {
        let key = PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[2; 32]));
        FileKey::new("test".into(), key).unwrap()
    }

    /// Issue with each algorithm; `signing::issue` verifies every signature.
    #[tokio::test]
    async fn issues_with_every_algorithm_of_each_key_type() {
        let ecdsa = FileKey::new(
            "test".into(),
            PrivateKey::random(
                &mut rand::rngs::OsRng,
                ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP384,
                },
            )
            .unwrap(),
        )
        .unwrap();
        for (backend, expected) in [
            (&ed25519_ca(), vec!["ssh-ed25519"]),
            (&ecdsa, vec!["ecdsa-sha2-nistp384"]),
            (&rsa_ca(), vec!["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]),
        ] {
            let algorithms = backend.algorithms();
            assert_eq!(
                algorithms.iter().map(|a| a.as_str()).collect::<Vec<_>>(),
                expected
            );
            testing::issue_with_every_algorithm(backend).await.unwrap();
            for algorithm in algorithms {
                let signed = signing::issue(backend, &testing::options(), algorithm)
                    .await
                    .unwrap();
                use base64ct::Encoding as _;
                let blob = base64ct::Base64::decode_vec(signed.openssh.split(' ').nth(1).unwrap())
                    .unwrap();
                let name = algorithm.as_str().as_bytes();
                assert!(
                    blob.windows(name.len() + 4)
                        .any(|w| w[4..] == *name && w[..4] == (name.len() as u32).to_be_bytes()),
                    "{algorithm} named in the signature"
                );
            }
        }
    }

    #[tokio::test]
    async fn wrong_algorithm_for_key_fails() {
        assert!(signing::issue(
            &ed25519_ca(),
            &testing::options(),
            SignatureAlgorithm::RsaSha256
        )
        .await
        .is_err());
    }

    /// The DigestInfo that raw-RSA backends (PKCS#11) sign must give exactly
    /// the rsa crate's PKCS#1 v1.5 signature (it is deterministic).
    #[test]
    fn raw_digest_info_signatures_match() {
        let rsa = rsa_ca();
        let private = rsa.rsa.as_ref().unwrap();
        for algorithm in [
            SignatureAlgorithm::RsaSha512,
            SignatureAlgorithm::RsaSha256,
            SignatureAlgorithm::SshRsa,
        ] {
            let info = encoding::rsa_digest_info(algorithm, b"to be signed").unwrap();
            let raw = private
                .sign(rsa::Pkcs1v15Sign::new_unprefixed(), &info)
                .unwrap();
            assert_eq!(
                raw,
                rsa.sign_now(algorithm, b"to be signed").unwrap(),
                "{algorithm}"
            );
        }
    }

    #[tokio::test]
    async fn loader_reads_its_config() {
        let mut config = toml::Table::new();
        config.insert("private_key_file".into(), "/nonexistent".into());
        let err = load(config).await.err().unwrap();
        assert!(err.contains("/nonexistent"), "{err}");
        let mut config = toml::Table::new();
        config.insert("bogus".into(), 1.into());
        assert!(load(config).await.is_err());
    }
}
