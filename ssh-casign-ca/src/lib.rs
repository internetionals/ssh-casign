//! SSH certificate authorities with pluggable key backends.
//!
//! This crate turns [`CertificateOptions`] into a correct, verified OpenSSH
//! certificate ([`signing::issue`]). The CA key lives in a [`Backend`], which
//! only has to sign bytes; backends are separate crates
//! (`ssh-casign-ca-file`, `-pkcs11`, `-vault`, `-azure`, ...) that register a
//! loader for their `provider` name in a [`Registry`].
//!
//! An authority is configured as a TOML table: the common keys
//! (`provider`, `cert_types`, `signature_algorithms`) are read here, the
//! rest is handed to the backend's loader.

use serde::Deserialize;
use ssh_casign_proto::CertType;
use ssh_key::{public::KeyData, PublicKey};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::Arc,
};

pub mod encoding;
pub mod options;
pub mod signing;

pub use options::CertificateOptions;
pub use signing::{SignatureAlgorithm, Signed};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A failure inside a backend (unreachable service, wrong PIN, ...).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct BackendError(pub String);

impl BackendError {
    pub fn new(message: impl std::fmt::Display) -> Self {
        Self(message.to_string())
    }
}

/// A CA key in some backend. Backends only sign bytes; certificates are
/// encoded and verified in [`signing`].
pub trait Backend: Send + Sync {
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

/// Loads a backend from its configuration: the authority's TOML table
/// without the common keys.
pub type Loader = fn(toml::Table) -> BoxFuture<'static, Result<Box<dyn Backend>, String>>;

/// Deserialize a backend's configuration from the table a [`Loader`] gets.
pub fn parse_config<T: serde::de::DeserializeOwned>(config: toml::Table) -> Result<T, String> {
    toml::Value::Table(config)
        .try_into()
        .map_err(|err: toml::de::Error| err.message().to_string())
}

/// The backends a build contains, by `provider` name.
#[derive(Default)]
pub struct Registry {
    loaders: BTreeMap<&'static str, Loader>,
    /// Providers this build lacks, with the Cargo feature that adds them.
    unavailable: BTreeMap<&'static str, &'static str>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, provider: &'static str, loader: Loader) -> &mut Self {
        self.loaders.insert(provider, loader);
        self
    }

    /// Note a provider this build doesn't include, for a helpful error.
    pub fn unavailable(&mut self, provider: &'static str, feature: &'static str) -> &mut Self {
        self.unavailable.insert(provider, feature);
        self
    }

    pub fn providers(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.loaders.keys().copied()
    }

    async fn load(&self, provider: &str, config: toml::Table) -> Result<Box<dyn Backend>, String> {
        if let Some(loader) = self.loaders.get(provider) {
            return loader(config).await;
        }
        let available = self.providers().collect::<Vec<_>>().join(", ");
        Err(match self.unavailable.get(provider) {
            Some(feature) => format!(
                "provider '{provider}' is not part of this build (enable the '{feature}' feature)"
            ),
            None => format!("unknown provider '{provider}' (this build has: {available})"),
        })
    }
}

#[derive(Deserialize)]
struct AuthorityConfig {
    provider: String,
    cert_types: HashSet<CertType>,
    /// Signature algorithms to offer, in order of preference. Default: all
    /// the key and backend support except `ssh-rsa` (SHA-1), which must be
    /// listed here explicitly to be used.
    signature_algorithms: Option<Vec<SignatureAlgorithm>>,
    /// Everything else is the backend's configuration.
    #[serde(flatten)]
    backend: toml::Table,
}

/// The `[authorities]` section: authority name → configuration.
#[derive(Deserialize)]
#[serde(transparent)]
pub struct Config {
    authorities: HashMap<Arc<str>, AuthorityConfig>,
}

/// A loaded authority.
pub struct Authority {
    backend: Box<dyn Backend>,
    public_key: PublicKey,
    cert_types: Vec<CertType>,
    signature_algorithms: Vec<SignatureAlgorithm>,
}

/// Loaded authorities by name.
pub type Authorities = HashMap<Arc<str>, Arc<Authority>>;

impl Config {
    pub async fn load(
        &self,
        registry: &Registry,
    ) -> Result<Authorities, Box<dyn std::error::Error>> {
        let mut authorities = HashMap::new();
        for (name, config) in &self.authorities {
            let authority = config
                .load(registry)
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
    async fn load(&self, registry: &Registry) -> Result<Authority, Box<dyn std::error::Error>> {
        let backend = registry.load(&self.provider, self.backend.clone()).await?;
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
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Certificate types this CA is configured to sign.
    pub fn cert_types(&self) -> &[CertType] {
        &self.cert_types
    }

    /// Signature algorithms this CA offers, in order of preference.
    pub fn signature_algorithms(&self) -> &[SignatureAlgorithm] {
        &self.signature_algorithms
    }

    pub async fn issue(
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
pub enum SignError {
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
pub fn select<'a>(
    profile_authorities: &'a [Arc<str>],
    authorities: &Authorities,
    accepted: Option<&[SignatureAlgorithm]>,
) -> Result<(&'a str, Arc<Authority>, SignatureAlgorithm), String> {
    for name in profile_authorities {
        let Some(authority) = authorities.get(name) else {
            continue;
        };
        let algorithm = authority
            .signature_algorithms()
            .iter()
            .copied()
            .find(|algorithm| accepted.is_none_or(|accepted| accepted.contains(algorithm)));
        if let Some(algorithm) = algorithm {
            return Ok((name, authority.clone(), algorithm));
        }
    }
    let offered: Vec<String> = profile_authorities
        .iter()
        .filter_map(|name| authorities.get(name))
        .flat_map(|authority| {
            authority
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

/// Test helpers for backend crates.
pub mod testing {
    use super::*;

    /// A certificate request for an Ed25519 user key with principal `alice`.
    pub fn options() -> CertificateOptions {
        let user = ssh_key::private::Ed25519Keypair::from_seed(&[1; 32]);
        let mut options =
            CertificateOptions::new_user(PublicKey::from(KeyData::Ed25519(user.public)));
        options.add_principal("alice");
        options.set_validity(3600);
        options.set_serial(7);
        options.set_key_id("test");
        options
    }

    /// Issue a certificate with every algorithm `backend` offers;
    /// [`signing::issue`] verifies each signature.
    pub async fn issue_with_every_algorithm(backend: &dyn Backend) -> Result<(), String> {
        let algorithms = backend.algorithms();
        if algorithms.is_empty() {
            return Err(format!("{}: no algorithms", backend.describe()));
        }
        for algorithm in algorithms {
            let signed = signing::issue(backend, &options(), algorithm)
                .await
                .map_err(|err| format!("{}: {algorithm}: {err}", backend.describe()))?;
            if signed.certificate.valid_principals() != ["alice"] {
                return Err(format!("{algorithm}: wrong principals"));
            }
        }
        Ok(())
    }

    /// A fixed 2048-bit RSA key (generated with ssh-keygen; only for tests),
    /// so tests don't spend seconds generating RSA keys.
    pub const RSA_CA: &str = include_str!("../testdata/rsa-ca");
}

#[cfg(test)]
mod tests {
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

    fn authority(seed: u8, algorithms: &[SignatureAlgorithm]) -> Authority {
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
        let authorities: Authorities = [
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
            select(&profile, &authorities, accepted)
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

    fn test_loader(config: toml::Table) -> BoxFuture<'static, Result<Box<dyn Backend>, String>> {
        Box::pin(async move {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct TestConfig {
                seed: u8,
            }
            let config: TestConfig = parse_config(config)?;
            let key = KeyData::Ed25519(
                ssh_key::private::Ed25519Keypair::from_seed(&[config.seed; 32]).public,
            );
            Ok(Box::new(TestBackend(key, vec![SignatureAlgorithm::Ed25519])) as Box<dyn Backend>)
        })
    }

    #[tokio::test]
    async fn registry_loads_and_explains_missing_providers() {
        let mut registry = Registry::new();
        registry
            .register("test", test_loader)
            .unavailable("vault", "ca-vault");
        let config: Config =
            toml::from_str("[ok]\nprovider = \"test\"\ncert_types = [\"user\"]\nseed = 4\n")
                .unwrap();
        let authorities = config.load(&registry).await.unwrap();
        assert_eq!(
            authorities["ok"].signature_algorithms(),
            [SignatureAlgorithm::Ed25519]
        );

        let load_err = |toml: &str| {
            let registry = &registry;
            let toml = toml.to_string();
            async move {
                let config: Config = toml::from_str(&toml).unwrap();
                config.load(registry).await.err().unwrap().to_string()
            }
        };
        let err = load_err("[v]\nprovider = \"vault\"\ncert_types = [\"user\"]\n").await;
        assert!(err.contains("enable the 'ca-vault' feature"), "{err}");
        let err = load_err("[x]\nprovider = \"nope\"\ncert_types = [\"user\"]\n").await;
        assert!(
            err.contains("unknown provider 'nope' (this build has: test)"),
            "{err}"
        );
        let err =
            load_err("[t]\nprovider = \"test\"\ncert_types = [\"user\"]\nseed = 1\nbogus = 2\n")
                .await;
        assert!(
            err.contains("bogus"),
            "backend config keeps deny_unknown_fields: {err}"
        );
    }
}
