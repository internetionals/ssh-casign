use serde::Deserialize;
use ssh_casign_proto::CertType;
use ssh_key::{Certificate, PublicKey};
use std::{collections::HashMap, sync::Arc};

use crate::certificate::options::CertificateOptions;

pub(crate) mod file;

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
    async fn sign(self: Arc<Self>, options: &CertificateOptions) -> Result<Certificate, SignError>;
}

impl Signer for Provider {
    async fn sign(self: Arc<Self>, options: &CertificateOptions) -> Result<Certificate, SignError> {
        match self.as_ref() {
            Provider::File(file) => file.clone().sign(options).await,
        }
    }
}
