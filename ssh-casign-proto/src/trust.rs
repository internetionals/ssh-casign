//! Signed trust statements: which CA keys a service's users and hosts should
//! trust, signed so that servers and clients can follow changes safely.
//!
//! A client pins a statement once. It then accepts a new one only if:
//!
//! - its `id` is the pinned one;
//! - it hasn't expired;
//! - `threshold` of the **pinned** signers signed it (the change is
//!   authorised by what the client already trusts);
//! - `threshold` of its **own** signers signed it (whoever it names as
//!   signers holds those keys);
//! - its `version` is higher, or equal with the same content (only `expires`
//!   may change without a new version), so old statements can't be replayed.
//!
//! The statement travels as a string, and signatures (SSHSIG, namespace
//! [`TRUST_NAMESPACE`], as `ssh-keygen -Y sign` makes them) cover exactly
//! those bytes. Statements must be in canonical form ([`TrustStatement::canonical`]),
//! so a statement has one encoding and everyone signs the same bytes.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use ssh_key::PublicKey;

use crate::CertType;

/// SSHSIG namespace of trust statement signatures.
pub const TRUST_NAMESPACE: &str = "ssh-casign-trust";
/// SSHSIG namespace of KRL signatures.
pub const KRL_NAMESPACE: &str = "ssh-casign-krl";

fn is_false(value: &bool) -> bool {
    !*value
}

/// What a service's servers and clients should trust.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustStatement {
    /// Name of the trust domain; pinned by clients.
    pub id: String,
    /// Increases with every change of the authorities or signers.
    pub version: u64,
    /// Unix time after which the statement is not accepted.
    pub expires: u64,
    /// The CA keys, sorted by name.
    pub authorities: Vec<TrustedAuthority>,
    /// Who must sign the next statement.
    pub signers: Signers,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustedAuthority {
    pub name: String,
    /// `<algorithm> <base64>`, without comment.
    pub public_key: String,
    pub cert_types: Vec<CertType>,
    /// `known_hosts` pattern list for host CAs (`*.example.com`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_hosts_pattern: Option<String>,
    /// No longer signs certificates, but its certificates are still valid.
    #[serde(default, skip_serializing_if = "is_false")]
    pub retired: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Signers {
    /// Public keys (`<algorithm> <base64>`), sorted.
    pub keys: Vec<String>,
    /// How many of them must sign.
    pub threshold: usize,
}

/// A statement with its signatures, as published in the discovery document.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignedTrust {
    /// The canonical JSON of a [`TrustStatement`].
    pub statement: String,
    /// Armored SSHSIG signatures over `statement`.
    pub signatures: Vec<String>,
}

/// `<algorithm> <base64>` of an OpenSSH public key, without comment.
pub fn normalize_key(text: &str) -> Result<String, String> {
    let key = PublicKey::from_openssh(text.trim())
        .map_err(|err| format!("invalid public key '{}': {err}", text.trim()))?;
    let encoded = key.to_openssh().map_err(|err| err.to_string())?;
    Ok(encoded
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" "))
}

/// `SHA256:...` fingerprint of a public key.
pub fn fingerprint(text: &str) -> Result<String, String> {
    let key = PublicKey::from_openssh(text.trim()).map_err(|err| err.to_string())?;
    Ok(key.fingerprint(ssh_key::HashAlg::Sha256).to_string())
}

impl TrustStatement {
    /// Check and normalise: keys without comments, authorities sorted by
    /// name, signer keys sorted, a sensible threshold.
    pub fn normalized(mut self) -> Result<Self, String> {
        if self.id.trim().is_empty() {
            return Err("trust statement: id must not be empty".into());
        }
        let mut names = BTreeSet::new();
        for authority in &mut self.authorities {
            if !names.insert(authority.name.clone()) {
                return Err(format!(
                    "trust statement: duplicate authority '{}'",
                    authority.name
                ));
            }
            authority.public_key = normalize_key(&authority.public_key)?;
            authority.cert_types.sort();
            authority.cert_types.dedup();
            if authority.cert_types.is_empty() {
                return Err(format!(
                    "trust statement: authority '{}' has no cert_types",
                    authority.name
                ));
            }
            if let Some(pattern) = &authority.known_hosts_pattern {
                if pattern.is_empty() || pattern.chars().any(char::is_whitespace) {
                    return Err(format!(
                        "trust statement: authority '{}': known_hosts_pattern must be a pattern \
                         list without spaces",
                        authority.name
                    ));
                }
            }
        }
        self.authorities.sort_by(|a, b| a.name.cmp(&b.name));
        self.signers.keys = self
            .signers
            .keys
            .iter()
            .map(|key| normalize_key(key))
            .collect::<Result<_, _>>()?;
        self.signers.keys.sort();
        self.signers.keys.dedup();
        if self.signers.threshold == 0 || self.signers.threshold > self.signers.keys.len() {
            return Err(format!(
                "trust statement: threshold {} with {} signer key(s)",
                self.signers.threshold,
                self.signers.keys.len()
            ));
        }
        Ok(self)
    }

    /// The bytes that are signed: compact JSON in field order.
    pub fn canonical(&self) -> String {
        serde_json::to_string(self).expect("a trust statement always serializes")
    }

    /// Equal except for `expires`.
    pub fn same_content(&self, other: &Self) -> bool {
        self.id == other.id
            && self.version == other.version
            && self.authorities == other.authorities
            && self.signers == other.signers
    }

    /// Signer fingerprints, for display and for pinning by fingerprint.
    pub fn signer_fingerprints(&self) -> Vec<String> {
        self.signers
            .keys
            .iter()
            .filter_map(|key| fingerprint(key).ok())
            .collect()
    }
}

/// The keys (normalised) whose signatures over `message` in `namespace` are
/// valid. Invalid or unparsable signatures are skipped.
pub fn valid_signers(namespace: &str, message: &[u8], signatures: &[String]) -> BTreeSet<String> {
    signatures
        .iter()
        .filter_map(|armored| {
            let sshsig = ssh_key::SshSig::from_pem(armored.trim()).ok()?;
            let key = PublicKey::from(sshsig.public_key().clone());
            key.verify(namespace, message, &sshsig).ok()?;
            normalize_key(&key.to_openssh().ok()?).ok()
        })
        .collect()
}

/// Split concatenated armored signatures (as in a `.sig` file).
pub fn split_signatures(text: &str) -> Vec<String> {
    const END: &str = "-----END SSH SIGNATURE-----";
    text.split_inclusive(END)
        .map(str::trim)
        .filter(|block| block.contains("-----BEGIN SSH SIGNATURE-----"))
        .map(str::to_string)
        .collect()
}

fn count_signed(signers: &Signers, signed: &BTreeSet<String>) -> usize {
    signers
        .keys
        .iter()
        .filter(|key| signed.contains(*key))
        .count()
}

/// A statement that passed [`verify`].
#[derive(Debug)]
pub struct Verified {
    pub statement: TrustStatement,
    /// Fingerprints of the keys that signed it.
    pub signed_by: Vec<String>,
}

/// Verify `signed` against the `pinned` statement (none: only its own
/// signers are checked, for pinning the first time). `now` is Unix time.
pub fn verify(
    signed: &SignedTrust,
    pinned: Option<&TrustStatement>,
    now: u64,
) -> Result<Verified, String> {
    let statement: TrustStatement = serde_json::from_str(&signed.statement)
        .map_err(|err| format!("invalid trust statement: {err}"))?;
    let normalized = statement.clone().normalized()?;
    if normalized.canonical() != signed.statement {
        return Err("trust statement is not in canonical form".into());
    }
    if now >= statement.expires {
        return Err(format!(
            "trust statement {} version {} has expired",
            statement.id, statement.version
        ));
    }
    let signed_by = valid_signers(
        TRUST_NAMESPACE,
        signed.statement.as_bytes(),
        &signed.signatures,
    );
    let own = count_signed(&statement.signers, &signed_by);
    if own < statement.signers.threshold {
        return Err(format!(
            "trust statement version {} is signed by {own} of its own signers, needs {}",
            statement.version, statement.signers.threshold
        ));
    }
    if let Some(pinned) = pinned {
        if statement.id != pinned.id {
            return Err(format!(
                "trust statement is for '{}', pinned is '{}'",
                statement.id, pinned.id
            ));
        }
        if statement.version < pinned.version {
            return Err(format!(
                "trust statement version {} is older than the pinned version {} (replayed?)",
                statement.version, pinned.version
            ));
        }
        if statement.version == pinned.version && !statement.same_content(pinned) {
            return Err(format!(
                "trust statement version {} differs from the pinned one with the same version \
                 (a change needs a higher version)",
                statement.version
            ));
        }
        let by_pinned = count_signed(&pinned.signers, &signed_by);
        if by_pinned < pinned.signers.threshold {
            return Err(format!(
                "trust statement version {} is signed by {by_pinned} of the pinned signers, \
                 needs {}",
                statement.version, pinned.signers.threshold
            ));
        }
    }
    Ok(Verified {
        signed_by: signed_by
            .iter()
            .filter_map(|key| fingerprint(key).ok())
            .collect(),
        statement,
    })
}

/// The human-edited form of a statement (TOML), for signing ceremonies.
///
/// ```toml
/// id = "example"
/// version = 4
/// expires = 2027-11-14           # a date, a date-time, or Unix seconds
///
/// [signers]
/// threshold = 2
/// keys = ["sk-ssh-ed25519@openssh.com AAAA... alice", "...", "..."]
///
/// [[authorities]]
/// name = "users"
/// public_key = "ssh-ed25519 AAAA..."
/// cert_types = ["user"]
/// ```
pub fn statement_from_toml(text: &str) -> Result<TrustStatement, String> {
    let mut table: toml::Table = toml::from_str(text).map_err(|err| err.to_string())?;
    let expires = match table.remove("expires") {
        Some(toml::Value::Integer(seconds)) if seconds > 0 => seconds as u64,
        Some(toml::Value::Datetime(datetime)) => unix_from_datetime(&datetime)?,
        Some(other) => return Err(format!("expires: not a date or Unix time: {other}")),
        None => return Err("expires is missing".into()),
    };
    table.insert("expires".into(), toml::Value::Integer(expires as i64));
    let statement: TrustStatement = toml::Value::Table(table)
        .try_into()
        .map_err(|err: toml::de::Error| err.to_string())?;
    statement.normalized()
}

/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let month = i64::from(month);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn unix_from_datetime(datetime: &toml::value::Datetime) -> Result<u64, String> {
    let date = datetime
        .date
        .ok_or_else(|| "expires: needs a date".to_string())?;
    let mut seconds =
        days_from_civil(i64::from(date.year), date.month.into(), date.day.into()) * 86_400;
    if let Some(time) = datetime.time {
        seconds +=
            i64::from(time.hour) * 3600 + i64::from(time.minute) * 60 + i64::from(time.second);
    }
    if let Some(toml::value::Offset::Custom { minutes }) = datetime.offset {
        seconds -= i64::from(minutes) * 60;
    }
    u64::try_from(seconds).map_err(|_| "expires: before 1970".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{private::Ed25519Keypair, HashAlg, LineEnding, PrivateKey};

    fn key(seed: u8) -> PrivateKey {
        PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
    }

    fn public(seed: u8) -> String {
        normalize_key(&key(seed).public_key().to_openssh().unwrap()).unwrap()
    }

    fn statement(
        version: u64,
        signers: &[u8],
        threshold: usize,
        authorities: &[u8],
    ) -> TrustStatement {
        TrustStatement {
            id: "example".into(),
            version,
            expires: 2_000_000_000,
            authorities: authorities
                .iter()
                .map(|seed| TrustedAuthority {
                    name: format!("ca{seed}"),
                    public_key: public(*seed),
                    cert_types: vec![CertType::User],
                    known_hosts_pattern: None,
                    retired: false,
                })
                .collect(),
            signers: Signers {
                keys: signers.iter().map(|seed| public(*seed)).collect(),
                threshold,
            },
        }
        .normalized()
        .unwrap()
    }

    fn sign(statement: &TrustStatement, by: &[u8]) -> SignedTrust {
        let canonical = statement.canonical();
        SignedTrust {
            signatures: by
                .iter()
                .map(|seed| {
                    key(*seed)
                        .sign(TRUST_NAMESPACE, HashAlg::Sha512, canonical.as_bytes())
                        .unwrap()
                        .to_pem(LineEnding::LF)
                        .unwrap()
                })
                .collect(),
            statement: canonical,
        }
    }

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn two_of_three_rotation() {
        // Trust keys 1, 2, 3 (2 of 3); CA 10.
        let v1 = statement(1, &[1, 2, 3], 2, &[10]);
        assert!(verify(&sign(&v1, &[1, 2]), None, NOW).is_ok());
        assert!(verify(&sign(&v1, &[1]), None, NOW)
            .unwrap_err()
            .contains("1 of its own"));
        // Duplicate signatures by one key count once.
        assert!(verify(&sign(&v1, &[1, 1]), None, NOW).is_err());
        // A CA rotation: v2 adds CA 11, signed by 2 and 3.
        let v2 = statement(2, &[1, 2, 3], 2, &[10, 11]);
        assert!(verify(&sign(&v2, &[2, 3]), Some(&v1), NOW).is_ok());
        // A forger with one trust key and a key of their own as new signers.
        let forged = statement(3, &[1, 9], 2, &[10, 66]);
        let err = verify(&sign(&forged, &[1, 9]), Some(&v2), NOW).unwrap_err();
        assert!(err.contains("1 of the pinned signers"), "{err}");
        // Replacing a lost trust key: v3 swaps 3 for 4, signed by 1, 2 (old)
        // and 1, 4 (new): 1, 2 and 4.
        let v3 = statement(3, &[1, 2, 4], 2, &[10, 11]);
        assert!(verify(&sign(&v3, &[1, 2, 4]), Some(&v2), NOW).is_ok());
        assert!(verify(&sign(&v3, &[1, 2]), Some(&v2), NOW).is_ok()); // 1 and 2 are in both
        assert!(verify(&sign(&v3, &[2, 4]), Some(&v2), NOW)
            .unwrap_err()
            .contains("pinned"));
    }

    #[test]
    fn rollback_expiry_and_versions() {
        let v1 = statement(1, &[1, 2, 3], 2, &[10]);
        let v2 = statement(2, &[1, 2, 3], 2, &[10, 11]);
        assert!(verify(&sign(&v1, &[1, 2]), Some(&v2), NOW)
            .unwrap_err()
            .contains("older"));
        // Same version, other content.
        let v2b = statement(2, &[1, 2, 3], 2, &[10]);
        assert!(verify(&sign(&v2b, &[1, 2]), Some(&v2), NOW)
            .unwrap_err()
            .contains("higher version"));
        // Same version, later expiry: a refresh.
        let refreshed = TrustStatement {
            expires: 2_100_000_000,
            ..v2.clone()
        };
        assert!(verify(&sign(&refreshed, &[1, 2]), Some(&v2), NOW).is_ok());
        assert!(verify(&sign(&v2, &[1, 2]), None, 2_000_000_000)
            .unwrap_err()
            .contains("expired"));
        let other = TrustStatement {
            id: "other".into(),
            ..v2.clone()
        };
        assert!(verify(&sign(&other, &[1, 2]), Some(&v2), NOW)
            .unwrap_err()
            .contains("pinned is"));
    }

    #[test]
    fn signatures_must_match_bytes_and_namespace() {
        let v1 = statement(1, &[1, 2, 3], 2, &[10]);
        let mut signed = sign(&v1, &[1, 2]);
        // Other namespace.
        signed.signatures[1] = key(2)
            .sign("file", HashAlg::Sha512, signed.statement.as_bytes())
            .unwrap()
            .to_pem(LineEnding::LF)
            .unwrap();
        assert!(verify(&signed, None, NOW).is_err());
        // Non-canonical encoding of the same statement.
        let mut pretty = sign(&v1, &[1, 2]);
        pretty.statement = serde_json::to_string_pretty(&v1).unwrap();
        assert!(verify(&pretty, None, NOW)
            .unwrap_err()
            .contains("canonical"));
    }

    #[test]
    fn toml_spec() {
        let spec = format!(
            r#"
            id = "example"
            version = 4
            expires = 2027-11-14
            [signers]
            threshold = 2
            keys = ["{} alice", "{}", "{}"]
            [[authorities]]
            name = "users"
            public_key = "{} users-ca"
            cert_types = ["user"]
            [[authorities]]
            name = "hosts"
            public_key = "{}"
            cert_types = ["host"]
            known_hosts_pattern = "*.example.com"
            "#,
            public(1),
            public(2),
            public(3),
            public(10),
            public(11)
        );
        let statement = statement_from_toml(&spec).unwrap();
        assert_eq!(statement.expires, 1_826_150_400); // 2027-11-14T00:00:00Z
        assert_eq!(statement.authorities[0].name, "hosts");
        assert!(!statement.signers.keys[0].contains("alice"));
        assert!(!statement.canonical().contains("retired"));
        let with_time = spec.replace("2027-11-14", "2027-11-14T12:00:00+01:00");
        assert_eq!(
            statement_from_toml(&with_time).unwrap().expires,
            1_826_150_400 + 11 * 3600
        );
        let bad = spec.replace("threshold = 2", "threshold = 4");
        assert!(statement_from_toml(&bad).unwrap_err().contains("threshold"));
    }

    #[test]
    fn split_armored() {
        let v1 = statement(1, &[1, 2, 3], 2, &[10]);
        let signed = sign(&v1, &[1, 2]);
        let joined = signed.signatures.join("\n");
        assert_eq!(
            split_signatures(&joined),
            signed
                .signatures
                .iter()
                .map(|s| s.trim().to_string())
                .collect::<Vec<_>>()
        );
    }
}
