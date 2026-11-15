//! The revocation API: `POST <revoke_endpoint>` and `GET
//! <certificates_endpoint>`.
//!
//! Three ways to be allowed to revoke:
//!
//! | Who                   | Proves                         | May revoke                          |
//! |-----------------------|--------------------------------|-------------------------------------|
//! | administrator         | a token matching `admins`      | anything                            |
//! | signed-in user        | a token (any trusted issuer)   | own certificates (issuance index)   |
//! | holder of a key       | an SSHSIG made with that key   | that key (and all its certificates) |

use serde::{Deserialize, Serialize};

/// SSHSIG namespace of proof-of-possession signatures.
pub const POSSESSION_NAMESPACE: &str = "ssh-casign-revoke";
/// How far a possession signature's time may be from the service's clock.
pub const POSSESSION_MAX_SKEW: u64 = 600;

/// Body of `POST <revoke_endpoint>`. Set exactly one target: `serial` (with
/// `authority`), `key_id`, `fingerprint`, `certificate`, `all` (the caller's
/// own certificates) or `matching` (administrators: every unexpired
/// certificate the filter matches).
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeRequest {
    /// Decimal, as a string (64-bit serials don't fit JSON numbers safely).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// `SHA256:...` of a key: revokes the key and all its certificates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// A certificate (OpenSSH format) the service issued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// Every unexpired certificate of the caller.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub all: bool,
    /// Administrators: every unexpired certificate this matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matching: Option<CertificateFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Revoke the key this proves possession of, without a token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub possession: Option<Possession>,
}

/// Whose certificates (for administrators): the token issuer URL and the
/// IdP-determined ID (`{{oidc_id}}`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Owner {
    pub issuer: String,
    pub id: String,
}

/// Which certificates of the issuance index. Every field that is set must
/// match; an empty filter matches nothing.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CertificateFilter {
    /// Issuer URL and IdP-determined ID of the owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    /// One of the certificate's principals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// `SHA256:...` of the certified key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// The exact key ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    /// The client address the certificate was requested from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_address: Option<String>,
}

impl CertificateFilter {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The owner, when the filter names one completely.
    pub fn owner(&self) -> Option<Owner> {
        Some(Owner {
            issuer: self.owner_issuer.clone()?,
            id: self.owner_id.clone()?,
        })
    }

    pub fn matches(&self, certificate: &IssuedCertificate) -> bool {
        fn check(want: &Option<String>, have: Option<&str>) -> bool {
            want.as_deref().is_none_or(|want| have == Some(want))
        }
        !self.is_empty()
            && check(&self.owner_issuer, Some(&certificate.owner.issuer))
            && check(&self.owner_id, Some(&certificate.owner.id))
            && self
                .principal
                .as_ref()
                .is_none_or(|principal| certificate.principals.contains(principal))
            && check(&self.fingerprint, Some(&certificate.fingerprint))
            && check(&self.key_id, Some(&certificate.key_id))
            && check(&self.profile, Some(&certificate.profile))
            && check(&self.authority, Some(&certificate.authority))
            && check(&self.app_name, certificate.app_name.as_deref())
            && check(&self.client_address, certificate.client_address.as_deref())
    }
}

/// Proof of holding a private key: an SSHSIG by it over
/// [`possession_message`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Possession {
    /// The key (`<algorithm> <base64>`).
    pub public_key: String,
    /// Unix time of the signature.
    pub time: u64,
    /// Armored SSHSIG, namespace [`POSSESSION_NAMESPACE`].
    pub signature: String,
}

/// What a key holder signs: the action, the key, the service's trust domain
/// (so a signature for one service doesn't revoke at another) and the time.
pub fn possession_message(public_key: &str, service: &str, time: u64) -> String {
    serde_json::json!({
        "action": "revoke-key",
        "public_key": public_key,
        "service": service,
        "time": time,
    })
    .to_string()
}

/// One revocation, as stored and as reported.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RevokedEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Unix time.
    pub revoked_at: u64,
    /// Who revoked it: `admin <issuer> <id>`, `<issuer> <id>` or `key holder`.
    pub revoked_by: String,
}

impl RevokedEntry {
    /// The same target (serial and authority, key ID, or fingerprint).
    pub fn same_target(&self, other: &Self) -> bool {
        self.serial == other.serial
            && self.authority == other.authority
            && self.key_id == other.key_id
            && self.fingerprint == other.fingerprint
    }
}

/// Response of `POST <revoke_endpoint>`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RevokeResponse {
    /// Newly revoked.
    pub revoked: Vec<RevokedEntry>,
    /// Targets that were already revoked.
    pub already_revoked: usize,
}

/// A certificate from the issuance index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuedCertificate {
    pub serial: String,
    pub authority: String,
    pub key_id: String,
    pub cert_type: crate::CertType,
    pub principals: Vec<String>,
    pub valid_after: u64,
    pub valid_before: u64,
    /// `SHA256:...` of the certified key.
    pub fingerprint: String,
    pub profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    /// Where it was requested from (as the audit log records it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_address: Option<String>,
    /// Whose it is.
    pub owner: Owner,
    /// Set in listings.
    #[serde(default)]
    pub revoked: bool,
}

/// Response of `GET <certificates_endpoint>`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CertificatesResponse {
    pub certificates: Vec<IssuedCertificate>,
}
