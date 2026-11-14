use serde::Deserialize;
use ssh_casign_proto::CertType;
use ssh_key::PublicKey;
use std::{collections::HashMap, sync::Arc};

use crate::certificate::options::CertificateOptions;

pub(crate) mod file;
pub(crate) mod signing;

use signing::SignatureAlgorithm;

#[derive(Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub(crate) enum ProviderConfig {
    File(file::Config),
}

#[derive(Deserialize)]
#[serde(transparent)]
pub(crate) struct Config {
    providers: HashMap<Arc<str>, ProviderConfig>,
}

pub(crate) enum Provider {
    File(Arc<file::State>),
}

impl Provider {
    /// Public key of the CA, i.e. what servers and clients need to trust.
    pub(crate) fn public_key(&self) -> &PublicKey {
        match self {
            Provider::File(file) => file.public_key(),
        }
    }

    /// Certificate types this CA is configured to sign.
    pub(crate) fn cert_types(&self) -> &[CertType] {
        match self {
            Provider::File(file) => file.cert_types(),
        }
    }

    /// Signature algorithms this CA offers, in order of preference.
    pub(crate) fn signature_algorithms(&self) -> &[SignatureAlgorithm] {
        match self {
            Provider::File(file) => file.signature_algorithms(),
        }
    }
}

pub(crate) type SshCaProviders = HashMap<Arc<str>, Arc<Provider>>;

impl Config {
    pub fn load(&self) -> Result<SshCaProviders, Box<dyn std::error::Error>> {
        let mut providers = HashMap::new();
        for (name, provider_config) in &self.providers {
            let provider = match provider_config {
                ProviderConfig::File(file_config) => Provider::File(
                    file_config
                        .load()
                        .map_err(|err| format!("authority {name}: {err}"))?,
                ),
            };
            providers.insert(name.clone(), Arc::new(provider));
        }
        Ok(providers)
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
    #[error("unable to generate certificate")]
    Certificate(#[from] ssh_key::Error),
    #[error("invalid timestamp")]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error("tokio join error")]
    Join(#[from] tokio::task::JoinError),
}
pub(crate) trait Signer {
    async fn sign(
        self: Arc<Self>,
        options: &CertificateOptions,
        algorithm: SignatureAlgorithm,
    ) -> Result<signing::Signed, SignError>;
}

impl Signer for Provider {
    async fn sign(
        self: Arc<Self>,
        options: &CertificateOptions,
        algorithm: SignatureAlgorithm,
    ) -> Result<signing::Signed, SignError> {
        match self.as_ref() {
            Provider::File(file) => file.clone().sign(options, algorithm).await,
        }
    }
}

/// The authority and signature algorithm for a request: the first authority
/// in the profile's order that offers one of the `accepted` algorithms (any,
/// if the client didn't say), with its most preferred such algorithm.
pub(crate) fn select<'a>(
    profile_authorities: &'a [Arc<str>],
    providers: &SshCaProviders,
    accepted: Option<&[SignatureAlgorithm]>,
) -> Result<(&'a str, Arc<Provider>, SignatureAlgorithm), String> {
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
mod tests {
    use super::*;

    /// Providers offering these algorithms, by name.
    fn providers(offers: &[(&str, &[SignatureAlgorithm])]) -> SshCaProviders {
        offers
            .iter()
            .enumerate()
            .map(|(i, (name, algorithms))| {
                let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(
                    &[i as u8 + 1; 32],
                ));
                (
                    Arc::from(*name),
                    Arc::new(Provider::File(Arc::new(file::State::for_test(
                        key,
                        algorithms.to_vec(),
                    )))),
                )
            })
            .collect()
    }

    #[test]
    fn selection_follows_profile_order_and_accepted_algorithms() {
        use SignatureAlgorithm::*;
        let providers = providers(&[
            ("ed25519", &[Ed25519]),
            ("rsa", &[RsaSha512, RsaSha256]),
            ("legacy", &[SshRsa]),
        ]);
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
}
