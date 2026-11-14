//! CA signature algorithms, and issuing certificates with a backend.
//!
//! A certificate carries one CA signature, so the signature algorithm is what
//! a server has to support. For Ed25519 and ECDSA it follows from the key; an
//! RSA key can sign as `rsa-sha2-512`, `rsa-sha2-256` or the legacy `ssh-rsa`
//! (SHA-1, which OpenSSH refuses by default since 8.2, but which some
//! embedded systems still require).
//!
//! Certificates are encoded here and only the signing is left to the
//! backend, so every backend just signs bytes. Every certificate is verified
//! before it is handed out.

use base64ct::{Base64, Encoding as _};
use serde::{Deserialize, Serialize};
use ssh_encoding::Encode;
use ssh_key::{certificate::CertType, public::KeyData, Certificate, EcdsaCurve};

use crate::{
    encoding::{put_string, put_u32, put_u64},
    options::CertificateOptions,
    Backend, SignError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
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
    pub fn as_str(self) -> &'static str {
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

    pub fn parse(name: &str) -> Option<Self> {
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
    /// never `ssh-rsa`). Backends may support fewer.
    pub fn for_key(key: &KeyData) -> Result<(Vec<Self>, Vec<Self>), String> {
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

/// An issued certificate.
pub struct Signed {
    /// The certificate's fields. For `ssh-rsa` the signature's algorithm name
    /// is relabeled in this view: ssh-key can't represent SHA-1 signatures.
    pub certificate: Certificate,
    /// The certificate as handed out, in OpenSSH format.
    pub openssh: String,
}

/// Algorithm name used for the view of an `ssh-rsa` signed certificate.
const VIEW_ALGORITHM: &str = "rsa-sha2-512";

fn encode_err(err: impl std::fmt::Display) -> SignError {
    SignError::Encoding(err.to_string())
}

/// A public key in SSH encoding (algorithm name, then its fields).
fn encode_key(key: &KeyData) -> Result<Vec<u8>, SignError> {
    let mut encoded = Vec::new();
    key.encode(&mut encoded).map_err(encode_err)?;
    Ok(encoded)
}

/// Encoded public key without its leading algorithm name, as certificates
/// contain it.
fn key_fields(key: &KeyData) -> Result<Vec<u8>, SignError> {
    let encoded = encode_key(key)?;
    let name_len = u32::from_be_bytes(encoded[..4].try_into().expect("4 bytes")) as usize;
    Ok(encoded[4 + name_len..].to_vec())
}

/// Critical options or extensions: sorted, flags with empty data, values as
/// a nested string.
fn encode_options<'a>(options: impl Iterator<Item = (&'a str, &'a str)>) -> Vec<u8> {
    let mut sorted: Vec<_> = options.collect();
    sorted.sort();
    let mut buf = Vec::new();
    for (name, value) in sorted {
        put_string(&mut buf, name.as_bytes());
        if value.is_empty() {
            put_u32(&mut buf, 0);
        } else {
            let mut nested = Vec::new();
            put_string(&mut nested, value.as_bytes());
            put_string(&mut buf, &nested);
        }
    }
    buf
}

/// The to-be-signed part of a certificate (PROTOCOL.certkeys).
fn encode_tbs(
    options: &CertificateOptions,
    ca_key: &KeyData,
    nonce: &[u8],
    valid_after: u64,
    valid_before: u64,
) -> Result<Vec<u8>, SignError> {
    let public_key = options.public_key().key_data();
    let mut buf = Vec::new();
    put_string(
        &mut buf,
        public_key.algorithm().to_certificate_type().as_bytes(),
    );
    put_string(&mut buf, nonce);
    buf.extend(key_fields(public_key)?);
    put_u64(&mut buf, options.serial().unwrap_or_default());
    put_u32(
        &mut buf,
        match options.cert_type() {
            CertType::User => 1,
            CertType::Host => 2,
        },
    );
    put_string(&mut buf, options.key_id().unwrap_or_default().as_bytes());
    let mut principals = Vec::new();
    for principal in options.principals() {
        put_string(&mut principals, principal.as_bytes());
    }
    put_string(&mut buf, &principals);
    put_u64(&mut buf, valid_after);
    put_u64(&mut buf, valid_before);
    put_string(&mut buf, &encode_options(options.critical_options()));
    put_string(&mut buf, &encode_options(options.extensions()));
    put_string(&mut buf, b"");
    put_string(&mut buf, &encode_key(ca_key)?);
    Ok(buf)
}

fn signature_field(algorithm: &str, data: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    put_string(&mut blob, algorithm.as_bytes());
    put_string(&mut blob, data);
    let mut field = Vec::new();
    put_string(&mut field, &blob);
    field
}

/// Check an `ssh-rsa` signature, which ssh-key can't verify.
fn verify_ssh_rsa(ca_key: &KeyData, tbs: &[u8], signature: &[u8]) -> Result<(), SignError> {
    use rsa::signature::Verifier;
    let KeyData::Rsa(key) = ca_key else {
        return Err(SignError::Verification(
            "ssh-rsa signature by a non-RSA key".into(),
        ));
    };
    let uint = |mpint: &ssh_key::Mpint| {
        mpint
            .as_positive_bytes()
            .map(rsa::BigUint::from_bytes_be)
            .ok_or_else(|| SignError::Verification("invalid RSA public key".into()))
    };
    let public = rsa::RsaPublicKey::new(uint(&key.n)?, uint(&key.e)?)
        .map_err(|err| SignError::Verification(err.to_string()))?;
    let signature = rsa::pkcs1v15::Signature::try_from(signature)
        .map_err(|err| SignError::Verification(err.to_string()))?;
    rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(public)
        .verify(tbs, &signature)
        .map_err(|err| SignError::Verification(err.to_string()))
}

/// Issue a certificate: encode it, let `backend` sign it with `algorithm`,
/// and verify the result.
pub async fn issue(
    backend: &dyn Backend,
    options: &CertificateOptions,
    algorithm: SignatureAlgorithm,
) -> Result<Signed, SignError> {
    let ca_key = backend.public_key();
    let valid_after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let valid_before = valid_after + options.validity().ok_or(SignError::UnknownValidity)?;
    let nonce: [u8; 32] = rand::random();
    let tbs = encode_tbs(options, ca_key, &nonce, valid_after, valid_before)?;

    let signature = backend
        .sign(algorithm, &tbs)
        .await
        .map_err(SignError::Backend)?;

    let mut blob = tbs.clone();
    blob.extend(signature_field(algorithm.as_str(), &signature));
    let certificate = if algorithm == SignatureAlgorithm::SshRsa {
        verify_ssh_rsa(ca_key, &tbs, &signature)?;
        let mut view = tbs;
        view.extend(signature_field(VIEW_ALGORITHM, &signature));
        Certificate::from_bytes(&view).map_err(encode_err)?
    } else {
        let certificate = Certificate::from_bytes(&blob).map_err(encode_err)?;
        certificate
            .verify_signature()
            .map_err(|err| SignError::Verification(format!("{algorithm}: {err}")))?;
        certificate
    };
    if certificate.signature_key() != ca_key {
        return Err(SignError::Verification("signed by another key".into()));
    }

    let mut openssh = format!(
        "{} {}",
        certificate.algorithm().to_certificate_type(),
        Base64::encode_string(&blob)
    );
    if let Some(comment) = options.comment() {
        openssh.push(' ');
        openssh.push_str(comment);
    }
    Ok(Signed {
        certificate,
        openssh,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_names() {
        for name in [
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "rsa-sha2-512",
            "rsa-sha2-256",
            "ssh-rsa",
        ] {
            assert_eq!(SignatureAlgorithm::parse(name).unwrap().as_str(), name);
        }
        assert!(SignatureAlgorithm::parse("ssh-dss").is_none());
    }

    #[test]
    fn options_are_sorted_and_values_nested() {
        let encoded =
            encode_options([("permit-pty", ""), ("force-command", "/bin/true")].into_iter());
        let mut expected = Vec::new();
        put_string(&mut expected, b"force-command");
        let mut nested = Vec::new();
        put_string(&mut nested, b"/bin/true");
        put_string(&mut expected, &nested);
        put_string(&mut expected, b"permit-pty");
        put_u32(&mut expected, 0);
        assert_eq!(encoded, expected);
    }

    /// Our encoding must match ssh-key's byte for byte.
    #[test]
    fn tbs_matches_ssh_key() {
        let ca = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[2; 32]));
        let user = ssh_key::private::Ed25519Keypair::from_seed(&[3; 32]);
        let mut options =
            CertificateOptions::new_user(ssh_key::PublicKey::from(KeyData::Ed25519(user.public)));
        options.add_principal("alice");
        options.add_principal("deploy");
        options.set_key_id("ca1:default:alice:-");
        options.set_serial(42);
        options.set_validity(3600);
        options.set_extension("permit-pty", "");
        options.set_extension("permit-agent-forwarding", "");
        options.set_critical_option("source-address", "10.0.0.0/8");

        let nonce = [9u8; 32];
        let tbs = encode_tbs(&options, ca.public_key().key_data(), &nonce, 1000, 4600).unwrap();

        let mut builder = ssh_key::certificate::Builder::new(
            nonce.to_vec(),
            KeyData::Ed25519(user.public),
            1000,
            4600,
        )
        .unwrap();
        builder.serial(42).unwrap();
        builder.key_id("ca1:default:alice:-").unwrap();
        builder.valid_principal("alice").unwrap();
        builder.valid_principal("deploy").unwrap();
        builder.extension("permit-pty", "").unwrap();
        builder.extension("permit-agent-forwarding", "").unwrap();
        builder
            .critical_option("source-address", "10.0.0.0/8")
            .unwrap();
        let reference = builder.sign(&ca).unwrap().to_bytes().unwrap();
        assert!(
            reference.starts_with(&tbs),
            "TBS differs from ssh-key's encoding"
        );
        let signature = &reference[tbs.len()..];
        let len = u32::from_be_bytes(signature[..4].try_into().unwrap()) as usize;
        assert_eq!(signature.len(), 4 + len, "only the signature follows");
    }
}
