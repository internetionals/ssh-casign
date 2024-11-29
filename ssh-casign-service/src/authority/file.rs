use rand::{distributions::Standard, Rng};
use serde::Deserialize;
use ssh_key::{certificate::CertType, Certificate, PrivateKey};
use std::{collections::HashSet, path::PathBuf, sync::Arc};

use super::{CertificateOptions, SignError};

fn gen_nonce(len: usize) -> Vec<u8> {
    rand::thread_rng().sample_iter(Standard).take(len).collect()
}

#[derive(Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
enum SupportedCertType {
    Host,
    User,
}

#[derive(Deserialize)]
pub(crate) struct Config {
    private_key_file: PathBuf,
    cert_types: HashSet<SupportedCertType>,
}

impl Config {
    pub(super) fn load(&self) -> Result<Arc<State>, Box<dyn std::error::Error>> {
        Ok(Arc::new(State {
            private_key: Arc::new(PrivateKey::read_openssh_file(&self.private_key_file)?),
            cert_types: self
                .cert_types
                .iter()
                .map(|cert_type| match cert_type {
                    SupportedCertType::Host => CertType::Host,
                    SupportedCertType::User => CertType::User,
                })
                .collect(),
        }))
    }
}

pub(crate) struct State {
    private_key: Arc<PrivateKey>,
    cert_types: Vec<ssh_key::certificate::CertType>,
}

impl super::Signer for State {
    async fn sign(self: Arc<Self>, options: &CertificateOptions) -> Result<Certificate, SignError> {
        if options.principals().next().is_none() {
            return Err(SignError::NoPrincipals);
        }
        let valid_after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let valid_before = valid_after + options.validity().ok_or(SignError::UnknownValidity)?;
        let mut cert_builder = ssh_key::certificate::Builder::new(
            gen_nonce(32),
            options.public_key(),
            valid_after,
            valid_before,
        )?;
        if !self.cert_types.contains(&options.cert_type()) {
            return Err(SignError::UnsupportedCertType);
        }
        cert_builder.cert_type(options.cert_type())?;
        for principal in options.principals() {
            cert_builder.valid_principal(principal)?;
        }
        if let Some(key_id) = options.key_id() {
            cert_builder.key_id(key_id)?;
        }
        if let Some(comment) = options.comment() {
            cert_builder.comment(comment)?;
        }
        for (name, data) in options.extensions() {
            cert_builder.extension(name, data)?;
        }
        for (name, data) in options.critical_options() {
            cert_builder.critical_option(name, data)?;
        }
        let certificate =
            tokio::task::spawn_blocking(move || cert_builder.sign(self.private_key.as_ref()))
                .await??;
        Ok(certificate)
    }
}
