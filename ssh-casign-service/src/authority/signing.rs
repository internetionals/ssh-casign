//! CA signature algorithms and signing with a chosen algorithm.
//!
//! A certificate carries one CA signature, so the signature algorithm is what
//! a server has to support. For Ed25519 and ECDSA it follows from the key; an
//! RSA key can sign as `rsa-sha2-512`, `rsa-sha2-256` or the legacy `ssh-rsa`
//! (SHA-1, which OpenSSH refuses by default since 8.2, but which some
//! embedded systems still require).

use std::sync::Mutex;

use base64ct::{Base64, Encoding};

use rsa::{
    pkcs1v15,
    signature::{SignatureEncoding, Signer as _},
};
use serde::{Deserialize, Serialize};
use ssh_key::{
    certificate::Builder, private::KeypairData, public::KeyData, Algorithm, Certificate,
    EcdsaCurve, HashAlg, PrivateKey, Signature,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum SignatureAlgorithm {
    #[serde(rename = "ssh-ed25519")]
    Ed25519,
    #[serde(rename = "ecdsa-sha2-nistp256")]
    EcdsaP256,
    #[serde(rename = "ecdsa-sha2-nistp384")]
    EcdsaP384,
    #[serde(rename = "ecdsa-sha2-nistp521")]
    EcdsaP521,
    #[serde(rename = "rsa-sha2-512")]
    RsaSha512,
    #[serde(rename = "rsa-sha2-256")]
    RsaSha256,
    /// RSA with SHA-1. Only used when an authority enables it explicitly.
    #[serde(rename = "ssh-rsa")]
    SshRsa,
}

impl SignatureAlgorithm {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SignatureAlgorithm::Ed25519 => "ssh-ed25519",
            SignatureAlgorithm::EcdsaP256 => "ecdsa-sha2-nistp256",
            SignatureAlgorithm::EcdsaP384 => "ecdsa-sha2-nistp384",
            SignatureAlgorithm::EcdsaP521 => "ecdsa-sha2-nistp521",
            SignatureAlgorithm::RsaSha512 => "rsa-sha2-512",
            SignatureAlgorithm::RsaSha256 => "rsa-sha2-256",
            SignatureAlgorithm::SshRsa => "ssh-rsa",
        }
    }

    pub(crate) fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "ssh-ed25519" => SignatureAlgorithm::Ed25519,
            "ecdsa-sha2-nistp256" => SignatureAlgorithm::EcdsaP256,
            "ecdsa-sha2-nistp384" => SignatureAlgorithm::EcdsaP384,
            "ecdsa-sha2-nistp521" => SignatureAlgorithm::EcdsaP521,
            "rsa-sha2-512" => SignatureAlgorithm::RsaSha512,
            "rsa-sha2-256" => SignatureAlgorithm::RsaSha256,
            "ssh-rsa" => SignatureAlgorithm::SshRsa,
            _ => return None,
        })
    }

    /// Algorithms a CA key can produce, and which of them are used when the
    /// authority doesn't configure `signature_algorithms` (strongest first;
    /// never `ssh-rsa`).
    pub(crate) fn for_key(key: &KeyData) -> Result<(Vec<Self>, Vec<Self>), String> {
        let single = |algorithm| Ok((vec![algorithm], vec![algorithm]));
        match key {
            KeyData::Ed25519(_) => single(SignatureAlgorithm::Ed25519),
            KeyData::Ecdsa(key) => match key.curve() {
                EcdsaCurve::NistP256 => single(SignatureAlgorithm::EcdsaP256),
                EcdsaCurve::NistP384 => single(SignatureAlgorithm::EcdsaP384),
                EcdsaCurve::NistP521 => single(SignatureAlgorithm::EcdsaP521),
            },
            KeyData::Rsa(_) => Ok((
                vec![
                    SignatureAlgorithm::RsaSha512,
                    SignatureAlgorithm::RsaSha256,
                    SignatureAlgorithm::SshRsa,
                ],
                vec![SignatureAlgorithm::RsaSha512, SignatureAlgorithm::RsaSha256],
            )),
            other => Err(format!(
                "CA keys of type {} are not supported",
                other.algorithm().as_str()
            )),
        }
    }
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A signed certificate.
pub(crate) struct Signed {
    /// The certificate's fields. For `ssh-rsa` this is the same certificate
    /// signed with SHA-512: ssh-key can't represent SHA-1 signatures, so only
    /// [`Signed::openssh`] has the real one.
    pub(crate) certificate: Certificate,
    /// The certificate as handed out, in OpenSSH format.
    pub(crate) openssh: String,
}

/// Sign `builder` with `key` using `algorithm`, which must be one the key
/// supports (see [`SignatureAlgorithm::for_key`]).
pub(crate) fn sign(
    builder: Builder,
    key: &PrivateKey,
    algorithm: SignatureAlgorithm,
) -> Result<Signed, ssh_key::Error> {
    let certificate = match (key.key_data(), algorithm) {
        (KeypairData::Rsa(keypair), SignatureAlgorithm::RsaSha512) => {
            builder.sign(&RsaSigner::new(keypair, Some(HashAlg::Sha512))?)?
        }
        (KeypairData::Rsa(keypair), SignatureAlgorithm::RsaSha256) => {
            builder.sign(&RsaSigner::new(keypair, Some(HashAlg::Sha256))?)?
        }
        (KeypairData::Rsa(keypair), SignatureAlgorithm::SshRsa) => {
            return sign_ssh_rsa(builder, keypair)
        }
        // Ed25519 and ECDSA: ssh-key signs these itself.
        _ => builder.sign(key)?,
    };
    let openssh = certificate.to_openssh()?;
    Ok(Signed {
        certificate,
        openssh,
    })
}

/// The `rsa` crate's private key for an ssh-key RSA keypair.
///
/// Not `rsa::RsaPrivateKey::try_from(keypair)`: ssh-key 0.6.7 passes the
/// prime `p` twice instead of `p` and `q` there, which the `rsa` crate (since
/// it validates keys in `from_components`) rejects. That also breaks
/// ssh-key's own RSA signing, which is why all RSA signing goes through
/// [`RsaSigner`].
fn rsa_private_key(
    keypair: &ssh_key::private::RsaKeypair,
) -> Result<rsa::RsaPrivateKey, ssh_key::Error> {
    let uint = |mpint: &ssh_key::Mpint| {
        mpint
            .as_positive_bytes()
            .map(rsa::BigUint::from_bytes_be)
            .ok_or(ssh_key::Error::Crypto)
    };
    rsa::RsaPrivateKey::from_components(
        uint(&keypair.public.n)?,
        uint(&keypair.public.e)?,
        uint(&keypair.private.d)?,
        vec![uint(&keypair.private.p)?, uint(&keypair.private.q)?],
    )
    .map_err(|_| ssh_key::Error::Crypto)
}

/// RSA signer for a chosen hash. With `None` (SHA-1) it signs with SHA-512
/// instead and keeps the to-be-signed data, see [`sign_ssh_rsa`].
struct RsaSigner {
    public: KeyData,
    private: rsa::RsaPrivateKey,
    hash: Option<HashAlg>,
    signed_data: Mutex<Option<Vec<u8>>>,
}

impl RsaSigner {
    fn new(
        keypair: &ssh_key::private::RsaKeypair,
        hash: Option<HashAlg>,
    ) -> Result<Self, ssh_key::Error> {
        Ok(Self {
            public: KeyData::Rsa(keypair.public.clone()),
            private: rsa_private_key(keypair)?,
            hash,
            signed_data: Mutex::new(None),
        })
    }

    /// Raw PKCS#1 v1.5 signature; `None` is SHA-1.
    fn raw_signature(
        &self,
        hash: Option<HashAlg>,
        message: &[u8],
    ) -> Result<Vec<u8>, ssh_key::Error> {
        let private = self.private.clone();
        Ok(match hash {
            Some(HashAlg::Sha256) => pkcs1v15::SigningKey::<sha2::Sha256>::new(private)
                .sign(message)
                .to_vec(),
            Some(HashAlg::Sha512) => pkcs1v15::SigningKey::<sha2::Sha512>::new(private)
                .sign(message)
                .to_vec(),
            None => pkcs1v15::SigningKey::<sha1::Sha1>::new(private)
                .sign(message)
                .to_vec(),
            Some(_) => return Err(ssh_key::Error::AlgorithmUnknown),
        })
    }
}

impl signature::Signer<Signature> for RsaSigner {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, signature::Error> {
        let hash = match self.hash {
            Some(hash) => Some(hash),
            None => {
                *self.signed_data.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(message.to_vec());
                Some(HashAlg::Sha512)
            }
        };
        self.raw_signature(hash, message)
            .and_then(|data| Signature::new(Algorithm::Rsa { hash }, data))
            .map_err(|_| signature::Error::new())
    }
}

impl From<&RsaSigner> for KeyData {
    fn from(signer: &RsaSigner) -> Self {
        signer.public.clone()
    }
}

/// `ssh-rsa` certificates. ssh-key can neither verify nor represent SHA-1
/// signatures, and its builder checks the new certificate in debug builds.
/// So the builder signs with SHA-512 while the to-be-signed data is captured;
/// that data is then signed with SHA-1 and encoded by hand, with the SHA-1
/// signature as the certificate's last field.
fn sign_ssh_rsa(
    builder: Builder,
    keypair: &ssh_key::private::RsaKeypair,
) -> Result<Signed, ssh_key::Error> {
    let signer = RsaSigner::new(keypair, None)?;
    let certificate = builder.sign(&signer)?;
    let signed_data = signer
        .signed_data
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .ok_or(ssh_key::Error::Crypto)?;
    let signature = signer.raw_signature(None, &signed_data)?;

    let mut blob = Vec::new();
    put_string(&mut blob, b"ssh-rsa");
    put_string(&mut blob, &signature);
    let mut encoded = signed_data;
    put_string(&mut encoded, &blob);
    let openssh = format!(
        "{} {}",
        certificate.algorithm().to_certificate_type(),
        Base64::encode_string(&encoded)
    );
    Ok(Signed {
        certificate,
        openssh,
    })
}

fn put_string(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::signature::Verifier as _;

    fn builder(public_key: KeyData) -> Builder {
        let mut builder =
            Builder::new(vec![7; 32], public_key, 1_800_000_000, 1_800_003_600).unwrap();
        builder.valid_principal("alice").unwrap();
        builder
    }

    fn user_key() -> KeyData {
        KeyData::Ed25519(ssh_key::private::Ed25519Keypair::from_seed(&[1; 32]).public)
    }

    /// The signed data, signature algorithm and raw signature of a
    /// certificate in OpenSSH format. The signature is the last field:
    /// string(string(algorithm), string(signature)).
    fn split_signature(openssh: &str) -> (Vec<u8>, String, Vec<u8>) {
        let bytes = Base64::decode_vec(openssh.split(' ').nth(1).unwrap()).unwrap();
        let read = |buf: &[u8], at: usize| -> Option<(Vec<u8>, usize)> {
            let len = u32::from_be_bytes(buf.get(at..at + 4)?.try_into().ok()?) as usize;
            Some((buf.get(at + 4..at + 4 + len)?.to_vec(), at + 4 + len))
        };
        // RSA signature of a 2048-bit key: 256 bytes, so the field's length
        // only depends on the algorithm name.
        for algorithm_len in ["ssh-rsa".len(), "rsa-sha2-256".len()] {
            let start = bytes.len() - (4 + 4 + algorithm_len + 4 + 256);
            let Some((blob, end)) = read(&bytes, start) else {
                continue;
            };
            if end != bytes.len() {
                continue;
            }
            let (algorithm, at) = read(&blob, 0).unwrap();
            let (signature, _) = read(&blob, at).unwrap();
            return (
                bytes[..start].to_vec(),
                String::from_utf8(algorithm).unwrap(),
                signature,
            );
        }
        panic!("no RSA signature field at the end");
    }

    #[test]
    fn algorithms_for_keys() {
        let (possible, default) = SignatureAlgorithm::for_key(&user_key()).unwrap();
        assert_eq!(possible, [SignatureAlgorithm::Ed25519]);
        assert_eq!(default, [SignatureAlgorithm::Ed25519]);
        for name in [
            "ssh-ed25519",
            "ecdsa-sha2-nistp384",
            "rsa-sha2-256",
            "ssh-rsa",
        ] {
            assert_eq!(SignatureAlgorithm::parse(name).unwrap().as_str(), name);
        }
        assert!(SignatureAlgorithm::parse("ssh-dss").is_none());
    }

    #[test]
    fn ed25519_signature() {
        let ca = PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[2; 32]));
        let signed = sign(builder(user_key()), &ca, SignatureAlgorithm::Ed25519).unwrap();
        assert_eq!(
            signed.certificate.signature().algorithm().as_str(),
            "ssh-ed25519"
        );
        assert_eq!(signed.openssh, signed.certificate.to_openssh().unwrap());
    }

    #[test]
    fn rsa_signatures_with_each_hash() {
        // A fixed key (generated with ssh-keygen; used only by these tests),
        // so the tests don't spend seconds generating RSA keys.
        let ca = PrivateKey::from_openssh(include_str!("testdata/rsa-ca")).unwrap();
        let KeypairData::Rsa(keypair) = ca.key_data() else {
            unreachable!()
        };
        let rsa_key = rsa_private_key(keypair).unwrap();
        let (possible, default) = SignatureAlgorithm::for_key(ca.public_key().key_data()).unwrap();
        assert!(possible.contains(&SignatureAlgorithm::SshRsa));
        assert!(
            !default.contains(&SignatureAlgorithm::SshRsa),
            "SHA-1 only when enabled"
        );

        let public = rsa::RsaPublicKey::from(&rsa_key);
        for (algorithm, name) in [
            (SignatureAlgorithm::RsaSha512, "rsa-sha2-512"),
            (SignatureAlgorithm::RsaSha256, "rsa-sha2-256"),
            (SignatureAlgorithm::SshRsa, "ssh-rsa"),
        ] {
            let signed = sign(builder(user_key()), &ca, algorithm).unwrap();
            let certificate = &signed.certificate;
            assert_eq!(certificate.valid_principals(), ["alice"]);
            assert_eq!(certificate.signature_key(), ca.public_key().key_data());
            assert!(signed
                .openssh
                .starts_with("ssh-ed25519-cert-v01@openssh.com "));

            let (signed_data, blob_algorithm, signature) = split_signature(&signed.openssh);
            assert_eq!(blob_algorithm, name);
            let signature = rsa::pkcs1v15::Signature::try_from(signature.as_slice()).unwrap();
            let verified = match algorithm {
                SignatureAlgorithm::RsaSha512 => {
                    rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(public.clone())
                        .verify(&signed_data, &signature)
                }
                SignatureAlgorithm::RsaSha256 => {
                    rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public.clone())
                        .verify(&signed_data, &signature)
                }
                _ => rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(public.clone())
                    .verify(&signed_data, &signature),
            };
            assert!(verified.is_ok(), "{name} signature must verify");
        }
    }
}
