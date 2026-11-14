//! SSH certificates as received from the service, including `ssh-rsa`
//! (SHA-1) signed ones, which ssh-key can't represent.
//!
//! The original bytes are kept and used for everything that leaves the
//! client (files, ssh-agent). For reading fields, ssh-key parses a view; for
//! `ssh-rsa` certificates only the signature's algorithm name is relabeled
//! for that view, the bytes that are handed on are never changed.

use base64ct::{Base64, Encoding};
use color_eyre::eyre::{bail, WrapErr};
use ssh_key::Certificate as SshCertificate;

use crate::error::Result;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Certificate {
    /// The certificate's fields (signature algorithm possibly relabeled).
    view: SshCertificate,
    /// The certificate as issued (OpenSSH wire format).
    blob: Vec<u8>,
    /// The real CA signature algorithm, e.g. `ssh-rsa`.
    signature_algorithm: String,
}

/// Algorithm name used for the view of an `ssh-rsa` signed certificate.
const VIEW_ALGORITHM: &[u8] = b"rsa-sha2-512";

fn put_string(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn u32_at(bytes: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?) as usize)
}

/// Find the trailing signature field of an `ssh-rsa` signed certificate:
/// string(string("ssh-rsa"), string(signature)). Returns where it starts and
/// the raw signature.
fn ssh_rsa_signature(blob: &[u8]) -> Option<(usize, &[u8])> {
    const ALGORITHM: &[u8] = b"\0\0\0\x07ssh-rsa";
    // Candidates from the end; the lengths must line up exactly.
    let mut search_end = blob.len();
    while let Some(position) = blob[..search_end]
        .windows(ALGORITHM.len())
        .rposition(|window| window == ALGORITHM)
    {
        search_end = position + ALGORITHM.len() - 1;
        let field_start = position.checked_sub(4)?;
        let signature_len = u32_at(blob, position + ALGORITHM.len())?;
        let signature_start = position + ALGORITHM.len() + 4;
        if signature_start + signature_len == blob.len()
            && u32_at(blob, field_start)? == blob.len() - position
        {
            return Some((field_start, &blob[signature_start..]));
        }
    }
    None
}

impl Certificate {
    pub(crate) fn from_blob(blob: Vec<u8>) -> Result<Self> {
        if let Ok(view) = SshCertificate::from_bytes(&blob) {
            let signature_algorithm = view.signature().algorithm().as_str().to_string();
            return Ok(Self {
                view,
                blob,
                signature_algorithm,
            });
        }
        let Some((field_start, signature)) = ssh_rsa_signature(&blob) else {
            bail!("Not a valid SSH certificate");
        };
        let mut relabeled = blob[..field_start].to_vec();
        let mut signature_blob = Vec::new();
        put_string(&mut signature_blob, VIEW_ALGORITHM);
        put_string(&mut signature_blob, signature);
        put_string(&mut relabeled, &signature_blob);
        let view =
            SshCertificate::from_bytes(&relabeled).wrap_err("Not a valid SSH certificate")?;
        Ok(Self {
            view,
            blob,
            signature_algorithm: "ssh-rsa".to_string(),
        })
    }

    /// Parse `<type> <base64> [comment]`.
    pub(crate) fn from_openssh(text: &str) -> Result<Self> {
        let mut fields = text.split_whitespace();
        let (Some(_), Some(data)) = (fields.next(), fields.next()) else {
            bail!("Not an OpenSSH certificate");
        };
        let blob = Base64::decode_vec(data).wrap_err("Not an OpenSSH certificate")?;
        Self::from_blob(blob)
    }

    /// `<type> <base64>`, from the original bytes.
    pub(crate) fn to_openssh(&self) -> String {
        format!(
            "{} {}",
            self.view.algorithm().to_certificate_type(),
            Base64::encode_string(&self.blob)
        )
    }

    /// The certificate's fields. Don't use its signature for anything.
    pub(crate) fn view(&self) -> &SshCertificate {
        &self.view
    }

    /// The certificate as issued.
    pub(crate) fn blob(&self) -> &[u8] {
        &self.blob
    }

    pub(crate) fn signature_algorithm(&self) -> &str {
        &self.signature_algorithm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{private::Ed25519Keypair, public::KeyData};

    fn ed25519_signed() -> SshCertificate {
        let ca = ssh_key::PrivateKey::from(Ed25519Keypair::from_seed(&[5; 32]));
        let key = Ed25519Keypair::from_seed(&[6; 32]);
        let mut builder = ssh_key::certificate::Builder::new(
            vec![0; 16],
            KeyData::Ed25519(key.public),
            1_800_000_000,
            1_800_003_600,
        )
        .unwrap();
        builder.valid_principal("alice").unwrap();
        builder.key_id("ca1:default:alice:-").unwrap();
        builder.sign(&ca).unwrap()
    }

    #[test]
    fn regular_certificates_roundtrip() {
        let certificate = ed25519_signed();
        let parsed = Certificate::from_openssh(&certificate.to_openssh().unwrap()).unwrap();
        assert_eq!(parsed.view(), &certificate);
        assert_eq!(parsed.signature_algorithm(), "ssh-ed25519");
        assert_eq!(parsed.blob(), certificate.to_bytes().unwrap());
        assert_eq!(
            Certificate::from_openssh(&parsed.to_openssh()).unwrap(),
            parsed
        );
    }

    #[test]
    fn ssh_rsa_signed_certificates_keep_their_bytes() {
        // Replace the signature with an ssh-rsa one (contents don't matter for
        // parsing; an "ssh-rsa" pattern inside the signature must not confuse
        // the search either).
        let certificate = ed25519_signed();
        let bytes = certificate.to_bytes().unwrap();
        let mut signature_field = Vec::new();
        put_string(
            &mut signature_field,
            certificate.signature().algorithm().as_str().as_bytes(),
        );
        put_string(&mut signature_field, certificate.signature().as_bytes());
        let mut field = Vec::new();
        put_string(&mut field, &signature_field);
        let tbs = &bytes[..bytes.len() - field.len()];

        let mut raw_signature = vec![0xab; 256];
        raw_signature[10..21].copy_from_slice(b"\0\0\0\x07ssh-rsa");
        let mut blob_field = Vec::new();
        put_string(&mut blob_field, b"ssh-rsa");
        put_string(&mut blob_field, &raw_signature);
        let mut blob = tbs.to_vec();
        put_string(&mut blob, &blob_field);

        let parsed = Certificate::from_blob(blob.clone()).unwrap();
        assert_eq!(parsed.signature_algorithm(), "ssh-rsa");
        assert_eq!(parsed.blob(), blob);
        assert_eq!(parsed.view().key_id(), "ca1:default:alice:-");
        assert_eq!(parsed.view().valid_principals(), ["alice"]);
        assert_eq!(parsed.view().valid_before(), 1_800_003_600);
        let reparsed = Certificate::from_openssh(&parsed.to_openssh()).unwrap();
        assert_eq!(reparsed.blob(), blob);
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(Certificate::from_blob(vec![1, 2, 3]).is_err());
        assert!(Certificate::from_openssh("ssh-ed25519-cert-v01@openssh.com !!!").is_err());
        assert!(Certificate::from_openssh("").is_err());
    }
}
