//! Wire types shared between `ssh-casign-service` and `ssh-casign-client`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Path of the service discovery document, relative to the service base URL.
pub const DISCOVERY_PATH: &str = ".well-known/ssh-casign";

/// SSH certificate type.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CertType {
    Host,
    #[default]
    User,
}

/// Body of `POST <sign_endpoint>`.
///
/// Every optional field is a request: when omitted, the token's value is used,
/// then the service profile's. Requested values must lie within the limits of
/// both the token and the profile, or the request is rejected.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SignKeyRequest {
    /// Public key in OpenSSH format (`ssh-ed25519 AAAA... comment`).
    pub public_key: String,
    pub cert_type: CertType,
    /// Validity in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principals: Option<Vec<String>>,
    /// Extensions (name → value, usually empty). Replaces the defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<BTreeMap<String, String>>,
    /// Critical options (name → value). Replaces the defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical_options: Option<BTreeMap<String, String>>,
    /// Name of the client workload (`ssh`, `ansible`, `terraform`, ...), like
    /// PostgreSQL's `application_name`. Becomes part of the key ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// CA signature algorithms the target servers accept (e.g. `ssh-rsa` for
    /// old embedded systems). The service uses the first authority of the
    /// profile that offers one of them. Default: any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_signature_algorithms: Option<Vec<String>>,
}

/// Successful response of `POST <sign_endpoint>`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedKeyResponse {
    /// Certificate in OpenSSH format.
    pub certificate: String,
}

/// Error response body of the service.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Service discovery document, served at [`DISCOVERY_PATH`].
///
/// Tells the client how to obtain a token and where to send sign requests, so
/// the client only needs to be configured with the service base URL.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// OpenID Connect issuer; `<issuer>/.well-known/openid-configuration` is the
    /// IdP discovery document.
    pub issuer: String,
    /// OAuth client ID the client should authenticate as (a public client).
    pub client_id: String,
    /// Scopes to request.
    pub scopes: Vec<String>,
    /// Sign endpoint; may be relative to the discovery document URL.
    pub sign_endpoint: String,
    /// Signing authorities, so clients and servers can set up trust.
    #[serde(default)]
    pub authorities: BTreeMap<String, AuthorityInfo>,
}

/// Public information about a signing authority.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorityInfo {
    /// CA public key in OpenSSH format (for `TrustedUserCAKeys` or
    /// `@cert-authority` lines in `known_hosts`).
    pub public_key: String,
    /// Certificate types this authority signs.
    pub cert_types: Vec<CertType>,
    /// CA signature algorithms it offers, in order of preference.
    #[serde(default)]
    pub signature_algorithms: Vec<String>,
}
