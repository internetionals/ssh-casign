//! Checks for obviously weak public keys: keys whose private key may be
//! known or computable, judged from the public key alone.
//!
//! | Check            | Catches                                                           |
//! |------------------|-------------------------------------------------------------------|
//! | ROCA             | RSA keys from Infineon chips (CVE-2017-15361): older YubiKey 4, TPMs, smart cards |
//! | Fermat           | RSA keys with primes too close together (CVE-2022-26320)          |
//! | RSA sanity       | even modulus, small prime factors, exponent 1 or even             |
//! | Ed25519 points   | invalid, low-order or mixed-order points, non-canonical encodings |
//! | ECDSA points     | points not on the curve, the identity                             |
//! | blocklists       | listed keys: the Debian OpenSSL keys (CVE-2008-0166), published or test keys, keys from firmware dumps, ... |
//!
//! Blocklist files have one key per line, as a fingerprint: `SHA256:<base64>`
//! (as `ssh-keygen -l` shows it), 64 hex digits (SHA-256), 32 hex digits
//! (MD5), or 20 hex digits: the last 80 bits of the MD5 fingerprint, the
//! format of Debian's `openssh-blacklist` files (`blacklist.RSA-2048`, ...).
//! A public key in OpenSSH format also works. `#` starts a comment.

use std::{collections::HashSet, path::Path};

use base64ct::{Base64Unpadded, Encoding as _};
use num_bigint_dig::BigUint;
use num_traits::{One, ToPrimitive, Zero};
use sha2::Digest as _;
use ssh_key::public::KeyData;

/// What is wrong with a key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Weakness {
    #[error(
        "RSA key from a chip with the ROCA flaw (CVE-2017-15361); its private key can be computed"
    )]
    Roca,
    #[error("RSA key whose primes are too close together (Fermat factorization, CVE-2022-26320)")]
    Fermat,
    #[error("RSA modulus with the small factor {0}")]
    SmallFactor(u32),
    #[error("RSA public exponent {0} is unusable")]
    Exponent(String),
    #[error("not a valid {0} public key")]
    InvalidPoint(&'static str),
    #[error("Ed25519 key of low order or with a torsion component; any signature may verify")]
    WeakPoint,
    #[error("Ed25519 key in a non-canonical encoding")]
    NonCanonical,
    #[error("key is on the blocklist {0}")]
    Blocklisted(String),
}

/// Small primes for trial division (all below 2000).
fn small_primes() -> Vec<u32> {
    let mut primes = Vec::new();
    for n in 2u32..2000 {
        if primes.iter().all(|p| n % p != 0) {
            primes.push(n);
        }
    }
    primes
}

/// `n mod m` for a small `m`.
fn mod_small(n: &BigUint, m: u32) -> u32 {
    (n % BigUint::from(m)).to_u32().unwrap_or(0)
}

/// The primes of the ROCA fingerprint (the detector of the paper's authors).
const ROCA_PRIMES: [u32; 38] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
];

/// ROCA moduli are, modulo every small prime, in the group that 65537
/// generates (their primes are `k*M + 65537^a mod M`). For other moduli that
/// happens with negligible probability.
fn roca(n: &BigUint) -> bool {
    ROCA_PRIMES.iter().all(|&p| {
        let residue = mod_small(n, p);
        let generator = 65537 % p;
        let mut power = 1;
        loop {
            if power == residue {
                return true;
            }
            power = power * generator % p;
            if power == 1 {
                return false;
            }
        }
    })
}

/// Fermat's method finds `p` and `q` quickly when `|p - q|` is small
/// (badkeys tries 100 steps).
fn fermat(n: &BigUint) -> bool {
    let mut a = n.sqrt();
    if &(&a * &a) < n {
        a += 1u32;
    }
    for _ in 0..100 {
        let b2 = &a * &a - n;
        let b = b2.sqrt();
        if &b * &b == b2 {
            return true;
        }
        a += 1u32;
    }
    false
}

fn check_rsa(key: &ssh_key::public::RsaPublicKey) -> Result<(), Weakness> {
    let n = BigUint::from_bytes_be(key.n.as_positive_bytes().unwrap_or_default());
    let e = BigUint::from_bytes_be(key.e.as_positive_bytes().unwrap_or_default());
    if e.is_zero() || e.is_one() || (&e % 2u32).is_zero() {
        return Err(Weakness::Exponent(e.to_string()));
    }
    if (&n % 2u32).is_zero() {
        return Err(Weakness::SmallFactor(2));
    }
    for p in small_primes() {
        if mod_small(&n, p) == 0 {
            return Err(Weakness::SmallFactor(p));
        }
    }
    if roca(&n) {
        return Err(Weakness::Roca);
    }
    if fermat(&n) {
        return Err(Weakness::Fermat);
    }
    Ok(())
}

fn check_ed25519(bytes: &[u8; 32]) -> Result<(), Weakness> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let point = CompressedEdwardsY(*bytes)
        .decompress()
        .ok_or(Weakness::InvalidPoint("Ed25519"))?;
    if point.compress().as_bytes() != bytes {
        return Err(Weakness::NonCanonical);
    }
    if point.is_small_order() || !point.is_torsion_free() {
        return Err(Weakness::WeakPoint);
    }
    Ok(())
}

fn check_ecdsa(key: &ssh_key::public::EcdsaPublicKey) -> Result<(), Weakness> {
    use ssh_key::public::EcdsaPublicKey;
    // `from_sec1_bytes` checks that the point is on the curve and not the
    // identity.
    let (valid, name) = match key {
        EcdsaPublicKey::NistP256(point) => (
            p256::PublicKey::from_sec1_bytes(point.as_bytes()).is_ok(),
            "ecdsa-sha2-nistp256",
        ),
        EcdsaPublicKey::NistP384(point) => (
            p384::PublicKey::from_sec1_bytes(point.as_bytes()).is_ok(),
            "ecdsa-sha2-nistp384",
        ),
        EcdsaPublicKey::NistP521(point) => (
            p521::PublicKey::from_sec1_bytes(point.as_bytes()).is_ok(),
            "ecdsa-sha2-nistp521",
        ),
    };
    if valid {
        Ok(())
    } else {
        Err(Weakness::InvalidPoint(name))
    }
}

/// The built-in checks.
pub fn check(key: &KeyData) -> Result<(), Weakness> {
    match key {
        KeyData::Rsa(rsa) => check_rsa(rsa),
        KeyData::Ed25519(key) => check_ed25519(&key.0),
        KeyData::SkEd25519(key) => check_ed25519(&key.public_key().0),
        KeyData::Ecdsa(key) => check_ecdsa(key),
        KeyData::SkEcdsaSha2NistP256(key) => {
            check_ecdsa(&ssh_key::public::EcdsaPublicKey::NistP256(*key.ec_point()))
        }
        _ => Ok(()),
    }
}

fn key_blob(key: &KeyData) -> Vec<u8> {
    ssh_key::PublicKey::from(key.clone())
        .to_bytes()
        .unwrap_or_default()
}

/// A blocklist of keys (see the module documentation for the format).
#[derive(Default)]
pub struct Blocklist {
    name: String,
    sha256: HashSet<[u8; 32]>,
    md5: HashSet<[u8; 16]>,
    /// The last 80 bits of MD5 fingerprints (Debian's openssh-blacklist).
    md5_tail: HashSet<[u8; 10]>,
}

fn hex(text: &str) -> Option<Vec<u8>> {
    text.len().is_multiple_of(2).then_some(())?;
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

impl Blocklist {
    pub fn parse(name: &str, text: &str) -> Result<Self, String> {
        let mut list = Blocklist {
            name: name.to_string(),
            ..Self::default()
        };
        for (number, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let invalid = || format!("{name}:{}: not a fingerprint or public key", number + 1);
            if let Some(encoded) = line.strip_prefix("SHA256:") {
                let bytes = Base64Unpadded::decode_vec(encoded.trim_end_matches('='))
                    .map_err(|_| invalid())?;
                list.sha256.insert(bytes.try_into().map_err(|_| invalid())?);
            } else if line.contains(' ') {
                let key = ssh_key::PublicKey::from_openssh(line).map_err(|_| invalid())?;
                list.sha256
                    .insert(sha2::Sha256::digest(key_blob(key.key_data())).into());
            } else {
                let bytes = hex(&line.replace(':', "").to_ascii_lowercase()).ok_or_else(invalid)?;
                match bytes.len() {
                    32 => {
                        list.sha256.insert(bytes.try_into().expect("32 bytes"));
                    }
                    16 => {
                        list.md5.insert(bytes.try_into().expect("16 bytes"));
                    }
                    10 => {
                        list.md5_tail.insert(bytes.try_into().expect("10 bytes"));
                    }
                    _ => return Err(invalid()),
                }
            }
        }
        Ok(list)
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text =
            std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
        // Named by file name: the name shows up in refusals to clients.
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        Self::parse(&name, &text)
    }

    pub fn len(&self) -> usize {
        self.sha256.len() + self.md5.len() + self.md5_tail.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, key: &KeyData) -> bool {
        let blob = key_blob(key);
        if self
            .sha256
            .contains(&<[u8; 32]>::from(sha2::Sha256::digest(&blob)))
        {
            return true;
        }
        if self.md5.is_empty() && self.md5_tail.is_empty() {
            return false;
        }
        let md5: [u8; 16] = md5::Md5::digest(&blob).into();
        self.md5.contains(&md5)
            || self
                .md5_tail
                .contains(&<[u8; 10]>::try_from(&md5[6..]).expect("10 bytes"))
    }
}

/// The built-in checks (unless turned off) and the blocklists.
pub struct KeyChecks {
    pub builtin: bool,
    pub blocklists: Vec<Blocklist>,
}

impl Default for KeyChecks {
    fn default() -> Self {
        Self {
            builtin: true,
            blocklists: Vec::new(),
        }
    }
}

impl KeyChecks {
    pub fn check(&self, key: &KeyData) -> Result<(), Weakness> {
        if self.builtin {
            check(key)?;
        }
        match self.blocklists.iter().find(|list| list.contains(key)) {
            Some(list) => Err(Weakness::Blocklisted(list.name.clone())),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint_dig::prime::probably_prime;

    fn rsa(n: &BigUint, e: u32) -> KeyData {
        KeyData::Rsa(ssh_key::public::RsaPublicKey {
            e: ssh_key::Mpint::from_positive_bytes(&BigUint::from(e).to_bytes_be()).unwrap(),
            n: ssh_key::Mpint::from_positive_bytes(&n.to_bytes_be()).unwrap(),
        })
    }

    /// A deterministic pseudo-random number of `bits` bits.
    fn number(seed: u64, bits: usize) -> BigUint {
        let mut bytes = Vec::new();
        let mut state = seed;
        while bytes.len() * 8 < bits {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            bytes.extend_from_slice(&state.to_be_bytes());
        }
        let n = BigUint::from_bytes_be(&bytes) >> (bytes.len() * 8 - bits);
        n | (BigUint::one() << (bits - 1))
    }

    fn next_prime(mut n: BigUint) -> BigUint {
        if (&n % 2u32).is_zero() {
            n += 1u32;
        }
        while !probably_prime(&n, 20) {
            n += 2u32;
        }
        n
    }

    #[test]
    fn good_keys_pass() {
        let rsa_key = ssh_key::PrivateKey::from_openssh(crate::testing::RSA_CA).unwrap();
        assert_eq!(check(rsa_key.public_key().key_data()), Ok(()));
        let ed = ssh_key::private::Ed25519Keypair::from_seed(&[7; 32]);
        assert_eq!(check(&KeyData::Ed25519(ed.public)), Ok(()));
        let p = next_prime(number(1, 512));
        let q = next_prime(number(2, 512));
        assert_eq!(check(&rsa(&(&p * &q), 65537)), Ok(()));
    }

    #[test]
    fn rsa_weaknesses() {
        let p = next_prime(number(3, 512));
        let q = next_prime(number(4, 512));
        let n = &p * &q;
        assert!(matches!(check(&rsa(&n, 1)), Err(Weakness::Exponent(_))));
        assert!(matches!(check(&rsa(&n, 65536)), Err(Weakness::Exponent(_))));
        assert_eq!(
            check(&rsa(&(&n * 1009u32), 65537)),
            Err(Weakness::SmallFactor(1009))
        );
        // Two primes in a row: Fermat finds them at once.
        let close = next_prime(&p + 2u32);
        assert_eq!(check(&rsa(&(&p * &close), 65537)), Err(Weakness::Fermat));
    }

    #[test]
    fn roca_fingerprint() {
        // Primes with ROCA's structure: k*M + 65537^a mod M, M the product
        // of the fingerprint's primes.
        let m: BigUint = ROCA_PRIMES.iter().fold(BigUint::one(), |m, &p| m * p);
        let roca_prime = |seed: u64| {
            let mut a = seed;
            loop {
                let p =
                    number(seed, 300) * &m + BigUint::from(65537u32).modpow(&BigUint::from(a), &m);
                if probably_prime(&p, 20) {
                    return p;
                }
                a += 1;
            }
        };
        let n = roca_prime(11) * roca_prime(12);
        assert!(roca(&n));
        assert_eq!(check(&rsa(&n, 65537)), Err(Weakness::Roca));
        // Ordinary moduli don't match.
        for seed in 20..30 {
            let n = next_prime(number(seed, 512)) * next_prime(number(seed + 100, 512));
            assert!(!roca(&n));
        }
    }

    #[test]
    fn ed25519_points() {
        let weak = |hex_text: &str| {
            let bytes: [u8; 32] = hex(hex_text).unwrap().try_into().unwrap();
            check(&KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(bytes)))
        };
        // The identity, and a point of order 8.
        assert_eq!(
            weak("0100000000000000000000000000000000000000000000000000000000000000"),
            Err(Weakness::WeakPoint)
        );
        assert_eq!(
            weak("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
            Err(Weakness::WeakPoint)
        );
        // y = p (non-canonical encoding of the order-1 point... or invalid).
        assert!(weak("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f").is_err());
        // A valid key plus a torsion component.
        use curve25519_dalek::edwards::CompressedEdwardsY;
        let good = ssh_key::private::Ed25519Keypair::from_seed(&[9; 32])
            .public
            .0;
        let torsion = CompressedEdwardsY(
            hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .decompress()
        .unwrap();
        let mixed = CompressedEdwardsY(good).decompress().unwrap() + torsion;
        assert_eq!(
            check(&KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(
                mixed.compress().to_bytes()
            ))),
            Err(Weakness::WeakPoint)
        );
    }

    #[test]
    fn blocklist_formats() {
        let key = KeyData::Ed25519(ssh_key::private::Ed25519Keypair::from_seed(&[5; 32]).public);
        let public = ssh_key::PublicKey::from(key.clone());
        let blob = key_blob(&key);
        let sha256 = public.fingerprint(ssh_key::HashAlg::Sha256).to_string();
        let md5: String = md5::Md5::digest(&blob)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let sha_hex: String = sha2::Sha256::digest(&blob)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        for line in [
            sha256.clone(),
            sha_hex,
            md5.clone(),
            md5[12..].to_string(),
            public.to_openssh().unwrap(),
        ] {
            let list = Blocklist::parse("test", &format!("# comment\n\n{line}  # why\n")).unwrap();
            assert!(list.contains(&key), "{line}");
            let other =
                KeyData::Ed25519(ssh_key::private::Ed25519Keypair::from_seed(&[6; 32]).public);
            assert!(!list.contains(&other));
        }
        assert!(Blocklist::parse("test", "nonsense\n").is_err());
        let checks = KeyChecks {
            builtin: true,
            blocklists: vec![Blocklist::parse("debian", &md5[12..]).unwrap()],
        };
        assert_eq!(
            checks.check(&key),
            Err(Weakness::Blocklisted("debian".into()))
        );
    }
}
