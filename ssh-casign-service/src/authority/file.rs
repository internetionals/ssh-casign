//! CA key in an OpenSSH private key file (unencrypted).

use rsa::{
    pkcs1v15,
    signature::{SignatureEncoding, Signer as _},
};
use serde::Deserialize;
use ssh_key::{private::KeypairData, public::KeyData, PrivateKey};
use std::path::PathBuf;

use super::{signing::SignatureAlgorithm, Backend, BackendError, BoxFuture};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    private_key_file: PathBuf,
}

impl Config {
    pub(super) fn load(&self) -> Result<FileKey, String> {
        let key = PrivateKey::read_openssh_file(&self.private_key_file).map_err(|err| {
            format!(
                "failed to read CA private key {}: {err}",
                self.private_key_file.display()
            )
        })?;
        let rsa = match key.key_data() {
            KeypairData::Rsa(keypair) => Some(rsa_private_key(keypair)?),
            _ => None,
        };
        Ok(FileKey {
            path: self.private_key_file.clone(),
            key,
            rsa,
        })
    }
}

/// The `rsa` crate's private key for an ssh-key RSA keypair.
///
/// Not `rsa::RsaPrivateKey::try_from(keypair)`: ssh-key 0.6.7 passes the
/// prime `p` twice instead of `p` and `q` there, which the `rsa` crate (since
/// it validates keys in `from_components`) rejects. That also breaks
/// ssh-key's own RSA signing, so RSA signing is done here.
pub(crate) fn rsa_private_key(
    keypair: &ssh_key::private::RsaKeypair,
) -> Result<rsa::RsaPrivateKey, String> {
    let uint = |mpint: &ssh_key::Mpint| {
        mpint
            .as_positive_bytes()
            .map(rsa::BigUint::from_bytes_be)
            .ok_or_else(|| "invalid RSA key".to_string())
    };
    rsa::RsaPrivateKey::from_components(
        uint(&keypair.public.n)?,
        uint(&keypair.public.e)?,
        uint(&keypair.private.d)?,
        vec![uint(&keypair.private.p)?, uint(&keypair.private.q)?],
    )
    .map_err(|err| format!("invalid RSA key: {err}"))
}

pub(crate) struct FileKey {
    path: PathBuf,
    key: PrivateKey,
    rsa: Option<rsa::RsaPrivateKey>,
}

impl FileKey {
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
    use crate::{
        authority::{encoding, signing},
        certificate::options::CertificateOptions,
    };
    use base64ct::{Base64, Encoding as _};

    /// A fixed RSA key (generated with ssh-keygen; only used by tests), so the
    /// tests don't spend seconds generating RSA keys.
    fn rsa_ca() -> FileKey {
        let key = PrivateKey::from_openssh(include_str!("testdata/rsa-ca")).unwrap();
        let KeypairData::Rsa(keypair) = key.key_data() else {
            unreachable!()
        };
        let rsa = Some(rsa_private_key(keypair).unwrap());
        FileKey {
            path: "testdata/rsa-ca".into(),
            key,
            rsa,
        }
    }

    fn file_key(key: PrivateKey) -> FileKey {
        FileKey {
            path: "test".into(),
            key,
            rsa: None,
        }
    }

    fn options() -> CertificateOptions {
        let user = ssh_key::private::Ed25519Keypair::from_seed(&[1; 32]);
        let mut options =
            CertificateOptions::new_user(ssh_key::PublicKey::from(KeyData::Ed25519(user.public)));
        options.add_principal("alice");
        options.set_validity(3600);
        options.set_serial(7);
        options.set_key_id("test");
        options
    }

    /// Issue with each algorithm; `signing::issue` verifies every signature.
    #[tokio::test]
    async fn issues_with_every_algorithm_of_each_key_type() {
        let ed25519 = file_key(PrivateKey::from(
            ssh_key::private::Ed25519Keypair::from_seed(&[2; 32]),
        ));
        let ecdsa = file_key(
            PrivateKey::random(
                &mut rand::rngs::OsRng,
                ssh_key::Algorithm::Ecdsa {
                    curve: ssh_key::EcdsaCurve::NistP384,
                },
            )
            .unwrap(),
        );
        let rsa = rsa_ca();
        for (backend, expected) in [
            (&ed25519, vec!["ssh-ed25519"]),
            (&ecdsa, vec!["ecdsa-sha2-nistp384"]),
            (&rsa, vec!["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]),
        ] {
            let algorithms = backend.algorithms();
            assert_eq!(
                algorithms.iter().map(|a| a.as_str()).collect::<Vec<_>>(),
                expected
            );
            for algorithm in algorithms {
                let signed = signing::issue(backend, &options(), algorithm)
                    .await
                    .unwrap();
                assert_eq!(signed.certificate.serial(), 7);
                assert_eq!(signed.certificate.valid_principals(), ["alice"]);
                let blob = Base64::decode_vec(signed.openssh.split(' ').nth(1).unwrap()).unwrap();
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
        let ed25519 = file_key(PrivateKey::from(
            ssh_key::private::Ed25519Keypair::from_seed(&[2; 32]),
        ));
        assert!(
            signing::issue(&ed25519, &options(), SignatureAlgorithm::RsaSha256)
                .await
                .is_err()
        );
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
}
