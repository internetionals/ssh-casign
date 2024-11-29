use serde::Deserialize;
use ssh_key::Certificate;
use std::{collections::HashMap, sync::Arc};

use crate::certificate::options::CertificateOptions;

pub(crate) mod file;

#[derive(Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub(crate) enum ProviderConfig {
    File(file::Config),
}

#[derive(Deserialize)]
pub(crate) struct Config {
    #[serde(flatten)]
    providers: HashMap<Arc<str>, ProviderConfig>,
}

pub(crate) enum Provider {
    File(Arc<file::State>),
}

pub(crate) type SshCaProviders = HashMap<Arc<str>, Arc<Provider>>;

impl Config {
    pub fn load(&self) -> Result<SshCaProviders, Box<dyn std::error::Error>> {
        let mut providers = HashMap::new();
        for (name, provider_config) in &self.providers {
            let provider = match provider_config {
                ProviderConfig::File(file_config) => Provider::File(file_config.load()?),
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
pub trait Signer {
    async fn sign(self: Arc<Self>, options: &CertificateOptions) -> Result<Certificate, SignError>;
}

impl Signer for Provider {
    async fn sign(self: Arc<Self>, options: &CertificateOptions) -> Result<Certificate, SignError> {
        match self.as_ref() {
            Provider::File(file) => file.clone().sign(options).await,
        }
    }
}
