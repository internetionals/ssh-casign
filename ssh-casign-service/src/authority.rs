//! Signing authorities: a CA key in a backend, the certificate types it
//! signs, and the signature algorithms it offers.
//!
//! Backends are Cargo features, so a build only contains the ones that make
//! sense for its platform:
//!
//! | `provider` | Feature     | Keys                                          |
//! |------------|-------------|-----------------------------------------------|
//! | `file`     | `ca-file`   | OpenSSH private key file                      |
//! | `pkcs11`   | `ca-pkcs11` | PKCS#11 token (YubiKey, OpenSC, SoftHSM, HSM) |
//! | `vault`    | `ca-vault`  | OpenBao / HashiCorp Vault transit engine      |

use serde::Deserialize;
use ssh_casign_proto::CertType;
use ssh_key::{public::KeyData, PublicKey};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::Arc,
};

use crate::certificate::options::CertificateOptions;

pub(crate) mod encoding;
#[cfg(feature = "ca-file")]
pub(crate) mod file;
#[cfg(feature = "ca-pkcs11")]
pub(crate) mod pkcs11;
pub(crate) mod signing;
#[cfg(feature = "ca-vault")]
pub(crate) mod vault;

use signing::{SignatureAlgorithm, Signed};

pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A failure inside a backend (unreachable service, wrong PIN, ...).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct BackendError(pub(crate) String);

impl BackendError {
    #[allow(dead_code)] // unused in a build without backends
    pub(crate) fn new(message: impl std::fmt::Display) -> Self {
        Self(message.to_string())
    }
}

/// A CA key in some backend. Backends only sign bytes; certificates are
/// encoded and verified in [`signing`].
pub(crate) trait Backend: Send + Sync {
    /// For logs, e.g. `file /etc/ssh-casign/ca`.
    fn describe(&self) -> String;

    fn public_key(&self) -> &KeyData;

    /// Signature algorithms the backend can produce with this key.
    fn algorithms(&self) -> Vec<SignatureAlgorithm>;

    /// Sign `data`, returning the signature data as SSH encodes it (raw for
    /// RSA and Ed25519, `mpint r || mpint s` for ECDSA).
    fn sign<'a>(
        &'a self,
        algorithm: SignatureAlgorithm,
        data: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, BackendError>>;
}

/// Configuration of a backend this build doesn't include: accepted by the
/// parser, so the error can say which feature is missing.
#[derive(Deserialize)]
#[allow(dead_code)] // unused when every backend is compiled in
pub(crate) struct Unavailable {}

#[derive(Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
enum BackendConfig {
    #[cfg(feature = "ca-file")]
    File(file::Config),
    #[cfg(not(feature = "ca-file"))]
    File(Unavailable),
    #[cfg(feature = "ca-pkcs11")]
    Pkcs11(pkcs11::Config),
    #[cfg(not(feature = "ca-pkcs11"))]
    Pkcs11(Unavailable),
    #[cfg(feature = "ca-vault")]
    Vault(vault::Config),
    #[cfg(not(feature = "ca-vault"))]
    Vault(Unavailable),
}

#[allow(dead_code)]
fn unavailable(provider: &str, feature: &str) -> Box<dyn std::error::Error> {
    format!("provider '{provider}' is not part of this build (enable the '{feature}' feature)")
        .into()
}

impl BackendConfig {
    async fn load(&self) -> Result<Box<dyn Backend>, Box<dyn std::error::Error>> {
        match self {
            #[cfg(feature = "ca-file")]
            BackendConfig::File(config) => Ok(Box::new(config.load()?)),
            #[cfg(not(feature = "ca-file"))]
            BackendConfig::File(_) => Err(unavailable("file", "ca-file")),
            #[cfg(feature = "ca-pkcs11")]
            BackendConfig::Pkcs11(config) => Ok(Box::new(config.load().await?)),
            #[cfg(not(feature = "ca-pkcs11"))]
            BackendConfig::Pkcs11(_) => Err(unavailable("pkcs11", "ca-pkcs11")),
            #[cfg(feature = "ca-vault")]
            BackendConfig::Vault(config) => Ok(Box::new(config.load().await?)),
            #[cfg(not(feature = "ca-vault"))]
            BackendConfig::Vault(_) => Err(unavailable("vault", "ca-vault")),
        }
    }
}

#[derive(Deserialize)]
struct AuthorityConfig {
    cert_types: HashSet<CertType>,
    /// Signature algorithms to offer, in order of preference. Default: all
    /// the key and backend support except `ssh-rsa` (SHA-1), which must be
    /// listed here explicitly to be used.
    signature_algorithms: Option<Vec<SignatureAlgorithm>>,
    #[serde(flatten)]
    backend: BackendConfig,
}

#[derive(Deserialize)]
#[serde(transparent)]
pub(crate) struct Config {
    authorities: HashMap<Arc<str>, AuthorityConfig>,
}

/// A loaded authority.
pub(crate) struct Authority {
    backend: Box<dyn Backend>,
    public_key: PublicKey,
    cert_types: Vec<CertType>,
    signature_algorithms: Vec<SignatureAlgorithm>,
}

pub(crate) type SshCaProviders = HashMap<Arc<str>, Arc<Authority>>;

impl Config {
    pub(crate) async fn load(&self) -> Result<SshCaProviders, Box<dyn std::error::Error>> {
        let mut authorities = HashMap::new();
        for (name, config) in &self.authorities {
            let authority = config
                .load()
                .await
                .map_err(|err| format!("authority {name}: {err}"))?;
            tracing::info!(
                "authority {name}: {} ({})",
                authority.backend.describe(),
                authority
                    .signature_algorithms
                    .iter()
                    .map(|algorithm| algorithm.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            authorities.insert(name.clone(), Arc::new(authority));
        }
        Ok(authorities)
    }
}

impl AuthorityConfig {
    async fn load(&self) -> Result<Authority, Box<dyn std::error::Error>> {
        let backend = self.backend.load().await?;
        let (possible, default) = SignatureAlgorithm::for_key(backend.public_key())?;
        let capable = backend.algorithms();
        let possible: Vec<_> = possible
            .into_iter()
            .filter(|a| capable.contains(a))
            .collect();
        let signature_algorithms = match &self.signature_algorithms {
            None => default
                .into_iter()
                .filter(|a| capable.contains(a))
                .collect(),
            Some(configured) => {
                if configured.is_empty() {
                    return Err("signature_algorithms must not be empty".into());
                }
                if let Some(unsupported) = configured.iter().find(|a| !possible.contains(a)) {
                    return Err(
                        format!("this key and backend can't sign with {unsupported}").into(),
                    );
                }
                configured.clone()
            }
        };
        if signature_algorithms.is_empty() {
            return Err(format!(
                "{} offers no usable signature algorithm for this key",
                backend.describe()
            )
            .into());
        }
        let mut cert_types: Vec<CertType> = self.cert_types.iter().copied().collect();
        cert_types.sort();
        Ok(Authority {
            public_key: PublicKey::from(backend.public_key().clone()),
            backend,
            cert_types,
            signature_algorithms,
        })
    }
}

impl Authority {
    /// Public key of the CA, i.e. what servers and clients need to trust.
    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Certificate types this CA is configured to sign.
    pub(crate) fn cert_types(&self) -> &[CertType] {
        &self.cert_types
    }

    /// Signature algorithms this CA offers, in order of preference.
    pub(crate) fn signature_algorithms(&self) -> &[SignatureAlgorithm] {
        &self.signature_algorithms
    }

    pub(crate) async fn issue(
        &self,
        options: &CertificateOptions,
        algorithm: SignatureAlgorithm,
    ) -> Result<Signed, SignError> {
        let cert_type = match options.cert_type() {
            ssh_key::certificate::CertType::User => CertType::User,
            ssh_key::certificate::CertType::Host => CertType::Host,
        };
        if !self.cert_types.contains(&cert_type) {
            return Err(SignError::UnsupportedCertType);
        }
        if options.principals().next().is_none() {
            return Err(SignError::NoPrincipals);
        }
        if !self.signature_algorithms.contains(&algorithm) {
            return Err(SignError::UnsupportedSignatureAlgorithm(algorithm));
        }
        signing::issue(self.backend.as_ref(), options, algorithm).await
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SignError {
    #[error("certificate type not supported")]
    UnsupportedCertType,
    #[error("signature algorithm {0} not offered by this authority")]
    UnsupportedSignatureAlgorithm(SignatureAlgorithm),
    #[error("certificate without principals")]
    NoPrincipals,
    #[error("No certificate validity known")]
    UnknownValidity,
    #[error("CA backend: {0}")]
    Backend(BackendError),
    #[error("certificate encoding: {0}")]
    Encoding(String),
    /// The backend's signature doesn't verify: a backend or configuration
    /// problem (e.g. the configured key isn't the one that signed).
    #[error("certificate signature doesn't verify: {0}")]
    Verification(String),
    #[error("invalid timestamp")]
    SystemTime(#[from] std::time::SystemTimeError),
}

/// The authority and signature algorithm for a request: the first authority
/// in the profile's order that offers one of the `accepted` algorithms (any,
/// if the client didn't say), with its most preferred such algorithm.
pub(crate) fn select<'a>(
    profile_authorities: &'a [Arc<str>],
    providers: &SshCaProviders,
    accepted: Option<&[SignatureAlgorithm]>,
) -> Result<(&'a str, Arc<Authority>, SignatureAlgorithm), String> {
    for name in profile_authorities {
        let Some(provider) = providers.get(name) else {
            continue;
        };
        let algorithm = provider
            .signature_algorithms()
            .iter()
            .copied()
            .find(|algorithm| accepted.is_none_or(|accepted| accepted.contains(algorithm)));
        if let Some(algorithm) = algorithm {
            return Ok((name, provider.clone(), algorithm));
        }
    }
    let offered: Vec<String> = profile_authorities
        .iter()
        .filter_map(|name| providers.get(name))
        .flat_map(|provider| {
            provider
                .signature_algorithms()
                .iter()
                .map(|a| a.to_string())
        })
        .collect();
    let requested = accepted
        .map(|accepted| {
            accepted
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    Err(format!(
        "no authority of this profile signs with any of [{requested}]; available: [{}]",
        offered.join(", ")
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Backend for tests: an Ed25519 key that claims any algorithm list.
    struct TestBackend(KeyData, Vec<SignatureAlgorithm>);

    impl Backend for TestBackend {
        fn describe(&self) -> String {
            "test".into()
        }
        fn public_key(&self) -> &KeyData {
            &self.0
        }
        fn algorithms(&self) -> Vec<SignatureAlgorithm> {
            self.1.clone()
        }
        fn sign<'a>(
            &'a self,
            _: SignatureAlgorithm,
            _: &'a [u8],
        ) -> BoxFuture<'a, Result<Vec<u8>, BackendError>> {
            Box::pin(async { Err(BackendError::new("test backend doesn't sign")) })
        }
    }

    pub(crate) fn authority(seed: u8, algorithms: &[SignatureAlgorithm]) -> Authority {
        let key = KeyData::Ed25519(ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]).public);
        Authority {
            public_key: PublicKey::from(key.clone()),
            backend: Box::new(TestBackend(key, algorithms.to_vec())),
            cert_types: vec![CertType::User],
            signature_algorithms: algorithms.to_vec(),
        }
    }

    #[test]
    fn selection_follows_profile_order_and_accepted_algorithms() {
        use SignatureAlgorithm::*;
        let providers: SshCaProviders = [
            ("ed25519", authority(1, &[Ed25519])),
            ("rsa", authority(2, &[RsaSha512, RsaSha256])),
            ("legacy", authority(3, &[SshRsa])),
        ]
        .into_iter()
        .map(|(name, authority)| (Arc::from(name), Arc::new(authority)))
        .collect();
        let profile: Vec<Arc<str>> = ["ed25519", "rsa", "legacy"]
            .into_iter()
            .map(Arc::from)
            .collect();
        let pick = |accepted: Option<&[SignatureAlgorithm]>| {
            select(&profile, &providers, accepted)
                .map(|(name, _, algorithm)| (name.to_string(), algorithm))
        };
        assert_eq!(pick(None).unwrap(), ("ed25519".into(), Ed25519));
        assert_eq!(
            pick(Some(&[RsaSha256, SshRsa])).unwrap(),
            ("rsa".into(), RsaSha256)
        );
        // The authority's preference wins within the accepted set.
        assert_eq!(
            pick(Some(&[RsaSha256, RsaSha512])).unwrap(),
            ("rsa".into(), RsaSha512)
        );
        assert_eq!(pick(Some(&[SshRsa])).unwrap(), ("legacy".into(), SshRsa));
        let err = pick(Some(&[EcdsaP256])).unwrap_err();
        assert!(
            err.contains("ecdsa-sha2-nistp256")
                && err.contains("available: [ssh-ed25519, rsa-sha2-512"),
            "{err}"
        );
    }

    #[cfg(not(feature = "ca-vault"))]
    #[tokio::test]
    async fn missing_backend_names_the_feature() {
        let config: Config = toml::from_str(
            "[ca]\nprovider = \"vault\"\ncert_types = [\"user\"]\naddress = \"http://x\"\n",
        )
        .unwrap();
        let err = config.load().await.err().unwrap().to_string();
        assert!(err.contains("enable the 'ca-vault' feature"), "{err}");
    }
}
