use serde::Deserialize;
use ssh_key::{certificate::CertType, Certificate, PublicKey};
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;

pub(crate) mod file;

/// Certificate options describe all the parameters that are needed to
/// generate a certificate.
pub struct CertificateOptions {
    pub public_key: PublicKey,
    pub cert_type: CertType,
    pub validity: Option<u64>,
    pub principals: Vec<Arc<str>>,
    pub key_id: Option<Arc<str>>,
    pub comment: Option<Arc<str>>,
    pub extensions: HashMap<Arc<str>, Arc<str>>,
    pub critical_options: HashMap<Arc<str>, Arc<str>>,
}

#[allow(dead_code)]
impl<'a> CertificateOptions {
    pub fn new(public_key: PublicKey, cert_type: CertType) -> Self {
        Self {
            public_key,
            cert_type,
            principals: Vec::new(),
            validity: None,
            key_id: None,
            comment: None,
            extensions: HashMap::new(),
            critical_options: HashMap::new(),
        }
    }

    pub fn new_user(public_key: PublicKey) -> Self {
        Self::new(public_key, CertType::User)
    }

    pub fn new_host(public_key: PublicKey) -> Self {
        Self::new(public_key, CertType::Host)
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn cert_type(&self) -> CertType {
        self.cert_type
    }

    pub fn add_principal<T: Into<Arc<str>>>(&mut self, principal: T) {
        self.principals.push(principal.into());
    }

    pub fn clear_principals(&mut self) {
        self.principals.clear();
    }

    pub fn principals(&self) -> impl Iterator<Item = &str> {
        self.principals.iter().map(Arc::as_ref)
    }

    pub fn set_validity(&mut self, validity: u64) {
        self.validity = Some(validity);
    }

    pub fn clear_validity(&mut self) {
        self.validity.take();
    }

    pub fn validity(&self) -> Option<u64> {
        self.validity
    }

    pub fn set_key_id<T: Into<Arc<str>>>(&'a mut self, key_id: T) {
        self.key_id = Some(key_id.into());
    }

    pub fn clear_key_id(&mut self) {
        self.key_id = None;
    }

    pub fn key_id(&'a self) -> Option<&'a str> {
        self.key_id.as_deref()
    }

    pub fn set_comment<T: Into<Arc<str>>>(&mut self, comment: T) {
        self.comment = Some(comment.into());
    }

    pub fn clear_comment(&mut self) {
        self.comment = None;
    }

    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    pub fn set_extension<K: Into<Arc<str>>, V: Into<Arc<str>>>(
        &'a mut self,
        extension: K,
        value: V,
    ) {
        self.extensions.insert(extension.into(), value.into());
    }

    pub fn unset_extension(&mut self, extension: &str) {
        self.extensions.remove(extension);
    }

    pub fn clear_extensions(&mut self) {
        self.extensions.clear();
    }

    pub fn extensions(&'a self) -> impl Iterator<Item = (&str, &str)> {
        self.extensions
            .iter()
            .map(|(k, v)| (k.as_ref(), v.as_ref()))
    }

    pub fn set_critical_option<K: Into<Arc<str>>, V: Into<Arc<str>>>(
        &'a mut self,
        critical_option: K,
        value: V,
    ) {
        self.critical_options
            .insert(critical_option.into(), value.into());
    }

    pub fn unset_critical_option(&mut self, critical_option: &str) {
        self.critical_options.remove(critical_option);
    }

    pub fn clear_critical_options(&mut self) {
        self.critical_options.clear();
    }

    pub fn critical_options(&'a self) -> impl Iterator<Item = (&str, &str)> {
        self.critical_options
            .iter()
            .map(|(k, v)| (k.as_ref(), v.as_ref()))
    }
}

#[derive(Debug, Error)]
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

#[derive(Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub(crate) enum SshCaProviderConfig {
    File(file::Config),
}

#[derive(Deserialize)]
pub(crate) struct Config {
    #[serde(flatten)]
    providers: HashMap<Arc<str>, SshCaProviderConfig>,
}

pub(crate) enum SshCaProvider {
    File(Arc<file::State>),
}

pub(crate) type SshCaProviders = HashMap<Arc<str>, Arc<SshCaProvider>>;

impl Config {
    pub fn load(&self) -> Result<SshCaProviders, Box<dyn std::error::Error>> {
        let mut providers = HashMap::new();
        for (name, provider_config) in &self.providers {
            let provider = match provider_config {
                SshCaProviderConfig::File(file_config) => SshCaProvider::File(file_config.load()?),
            };
            providers.insert(name.clone(), Arc::new(provider));
        }
        Ok(providers)
    }
}

pub trait SshCa {
    async fn sign(self: Arc<Self>, options: &CertificateOptions) -> Result<Certificate, SignError>;
}

impl SshCa for SshCaProvider {
    async fn sign(self: Arc<Self>, options: &CertificateOptions) -> Result<Certificate, SignError> {
        match self.as_ref() {
            SshCaProvider::File(file) => file.clone().sign(options).await,
        }
    }
}
