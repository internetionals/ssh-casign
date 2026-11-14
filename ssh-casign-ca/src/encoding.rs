//! SSH wire encoding and signature format helpers shared by the backends.
//!

use sha2::Digest;

use crate::signing::SignatureAlgorithm;

pub fn put_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

pub fn put_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

pub fn put_string(buf: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(buf, bytes.len() as u32);
    buf.extend_from_slice(bytes);
}

/// SSH `mpint` of an unsigned big-endian integer.
pub fn put_mpint(buf: &mut Vec<u8>, unsigned: &[u8]) {
    let trimmed = match unsigned.iter().position(|byte| *byte != 0) {
        Some(start) => &unsigned[start..],
        None => &[],
    };
    if trimmed.first().is_some_and(|byte| byte & 0x80 != 0) {
        put_u32(buf, trimmed.len() as u32 + 1);
        buf.push(0);
        buf.extend_from_slice(trimmed);
    } else {
        put_string(buf, trimmed);
    }
}

/// SSH ECDSA signature data from `r` and `s`: mpint(r) mpint(s).
pub fn ecdsa_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    put_mpint(&mut data, r);
    put_mpint(&mut data, s);
    data
}

/// SSH ECDSA signature data from a fixed-size `r || s` (PKCS#11, JOSE).
pub fn ecdsa_signature_from_raw(raw: &[u8]) -> Result<Vec<u8>, String> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return Err(format!("ECDSA signature of odd length {}", raw.len()));
    }
    let (r, s) = raw.split_at(raw.len() / 2);
    Ok(ecdsa_signature(r, s))
}

/// SSH ECDSA signature data from a DER `SEQUENCE { INTEGER r, INTEGER s }`
/// (Vault, cloud KMSs).
pub fn ecdsa_signature_from_der(der: &[u8]) -> Result<Vec<u8>, String> {
    fn take<'a>(input: &mut &'a [u8], tag: u8) -> Result<&'a [u8], String> {
        let invalid = || "invalid DER ECDSA signature".to_string();
        let (&found, rest) = input.split_first().ok_or_else(invalid)?;
        if found != tag {
            return Err(invalid());
        }
        let (&first, mut rest) = rest.split_first().ok_or_else(invalid)?;
        let len = if first < 0x80 {
            first as usize
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 2 || rest.len() < count {
                return Err(invalid());
            }
            let len = rest[..count]
                .iter()
                .fold(0usize, |acc, byte| acc << 8 | *byte as usize);
            rest = &rest[count..];
            len
        };
        if rest.len() < len {
            return Err(invalid());
        }
        let (value, rest) = rest.split_at(len);
        *input = rest;
        Ok(value)
    }
    let mut input = der;
    let mut sequence = take(&mut input, 0x30)?;
    let r = take(&mut sequence, 0x02)?;
    let s = take(&mut sequence, 0x02)?;
    if !sequence.is_empty() || !input.is_empty() {
        return Err("trailing data in DER ECDSA signature".to_string());
    }
    Ok(ecdsa_signature(r, s))
}

/// The `rsa` crate's private key for an ssh-key RSA keypair.
///
/// Not `rsa::RsaPrivateKey::try_from(keypair)`: ssh-key 0.6.7 passes the
/// prime `p` twice instead of `p` and `q` there, which the `rsa` crate (since
/// it validates keys in `from_components`) rejects. That also breaks
/// ssh-key's own RSA signing, so backends sign RSA with this key instead.
pub fn rsa_private_key(
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

/// The digest an ECDSA or RSA signature algorithm signs.
pub fn digest(algorithm: SignatureAlgorithm, data: &[u8]) -> Vec<u8> {
    use SignatureAlgorithm::*;
    match algorithm {
        EcdsaP256 | RsaSha256 => sha2::Sha256::digest(data).to_vec(),
        EcdsaP384 => sha2::Sha384::digest(data).to_vec(),
        EcdsaP521 | RsaSha512 => sha2::Sha512::digest(data).to_vec(),
        SshRsa => sha1::Sha1::digest(data).to_vec(),
        // Ed25519 signs the message itself.
        Ed25519 => data.to_vec(),
    }
}

/// PKCS#1 v1.5 `DigestInfo` for an RSA signature algorithm: what a raw RSA
/// signing mechanism (PKCS#11 `CKM_RSA_PKCS`) has to sign.
pub fn rsa_digest_info(algorithm: SignatureAlgorithm, data: &[u8]) -> Result<Vec<u8>, String> {
    const SHA1: &[u8] = &[
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];
    const SHA256: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    const SHA512: &[u8] = &[
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40,
    ];
    let prefix = match algorithm {
        SignatureAlgorithm::SshRsa => SHA1,
        SignatureAlgorithm::RsaSha256 => SHA256,
        SignatureAlgorithm::RsaSha512 => SHA512,
        other => return Err(format!("{other} is not an RSA signature algorithm")),
    };
    let mut info = prefix.to_vec();
    info.extend(digest(algorithm, data));
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mpint_encoding() {
        let mpint = |bytes: &[u8]| {
            let mut buf = Vec::new();
            put_mpint(&mut buf, bytes);
            buf
        };
        assert_eq!(mpint(&[0x00, 0x00]), [0, 0, 0, 0]);
        assert_eq!(mpint(&[0x00, 0x7f]), [0, 0, 0, 1, 0x7f]);
        assert_eq!(mpint(&[0x80]), [0, 0, 0, 2, 0x00, 0x80]);
    }

    #[test]
    fn der_and_raw_ecdsa_agree() {
        // DER with a leading zero on r (high bit set) and short s.
        let der = [0x30, 0x08, 0x02, 0x02, 0x00, 0x81, 0x02, 0x02, 0x01, 0x02];
        let raw = [0x81, 0x00, 0x01, 0x02];
        let raw_padded = [0x00, 0x81, 0x01, 0x02];
        assert_eq!(
            ecdsa_signature_from_der(&der).unwrap(),
            ecdsa_signature_from_raw(&raw_padded).unwrap()
        );
        assert_ne!(
            ecdsa_signature_from_der(&der).unwrap(),
            ecdsa_signature_from_raw(&raw).unwrap()
        );
        assert!(ecdsa_signature_from_der(&der[..9]).is_err());
        assert!(ecdsa_signature_from_raw(&[1, 2, 3]).is_err());
    }

    #[test]
    fn digest_info_structure() {
        // Signing with a real key is checked against the rsa crate in the
        // file backend's tests.
        for (algorithm, len) in [
            (SignatureAlgorithm::SshRsa, 15 + 20),
            (SignatureAlgorithm::RsaSha256, 19 + 32),
            (SignatureAlgorithm::RsaSha512, 19 + 64),
        ] {
            let info = rsa_digest_info(algorithm, b"data").unwrap();
            assert_eq!(info.len(), len);
            assert_eq!(info[1] as usize, len - 2, "outer DER length");
        }
        assert!(rsa_digest_info(SignatureAlgorithm::Ed25519, b"x").is_err());
    }
}
