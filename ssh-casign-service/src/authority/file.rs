use rand::{distributions::Standard, Rng};
use serde::Deserialize;
use ssh_casign_proto::CertType;
use ssh_key::{PrivateKey, PublicKey};
use std::{collections::HashSet, path::PathBuf, sync::Arc};

use super::{signing::SignatureAlgorithm, CertificateOptions, SignError};

fn gen_nonce(len: usize) -> Vec<u8> {
    rand::thread_rng().sample_iter(Standard).take(len).collect()
}

fn to_ssh_cert_type(cert_type: CertType) -> ssh_key::certificate::CertType {
    match cert_type {
        CertType::Host => ssh_key::certificate::CertType::Host,
        CertType::User => ssh_key::certificate::CertType::User,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    private_key_file: PathBuf,
    cert_types: HashSet<CertType>,
    /// Signature algorithms to offer, in order of preference. Default: all
    /// the key supports except `ssh-rsa` (SHA-1), which must be listed here
    /// explicitly to be used.
    signature_algorithms: Option<Vec<SignatureAlgorithm>>,
}

impl Config {
    pub(super) fn load(&self) -> Result<Arc<State>, Box<dyn std::error::Error>> {
        let private_key = PrivateKey::read_openssh_file(&self.private_key_file).map_err(|err| {
            format!(
                "failed to read CA private key {}: {err}",
                self.private_key_file.display()
            )
        })?;
        let mut cert_types: Vec<CertType> = self.cert_types.iter().copied().collect();
        cert_types.sort();
        let (possible, default) = SignatureAlgorithm::for_key(private_key.public_key().key_data())?;
        let signature_algorithms = match &self.signature_algorithms {
            None => default,
            Some(configured) => {
                if configured.is_empty() {
                    return Err("signature_algorithms must not be empty".into());
                }
                if let Some(unsupported) = configured.iter().find(|a| !possible.contains(a)) {
                    return Err(format!("this CA key can't sign with {unsupported}").into());
                }
                configured.clone()
            }
        };
        Ok(Arc::new(State {
            private_key: Arc::new(private_key),
            cert_types,
            signature_algorithms,
        }))
    }
}

pub(crate) struct State {
    private_key: Arc<PrivateKey>,
    cert_types: Vec<CertType>,
    signature_algorithms: Vec<SignatureAlgorithm>,
}

impl State {
    #[cfg(test)]
    pub(super) fn for_test(
        private_key: PrivateKey,
        signature_algorithms: Vec<SignatureAlgorithm>,
    ) -> Self {
        Self {
            private_key: Arc::new(private_key),
            cert_types: vec![CertType::User],
            signature_algorithms,
        }
    }

    pub(super) fn public_key(&self) -> &PublicKey {
        self.private_key.public_key()
    }

    pub(super) fn cert_types(&self) -> &[CertType] {
        &self.cert_types
    }

    pub(super) fn signature_algorithms(&self) -> &[SignatureAlgorithm] {
        &self.signature_algorithms
    }
}

impl super::Signer for State {
    async fn sign(
        self: Arc<Self>,
        options: &CertificateOptions,
        algorithm: SignatureAlgorithm,
    ) -> Result<super::signing::Signed, SignError> {
        if !self.signature_algorithms.contains(&algorithm) {
            return Err(SignError::UnsupportedSignatureAlgorithm(algorithm));
        }
        let cert_type = options.cert_type();
        if !self
            .cert_types
            .iter()
            .any(|supported| to_ssh_cert_type(*supported) == cert_type)
        {
            return Err(SignError::UnsupportedCertType);
        }
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
        cert_builder.cert_type(cert_type)?;
        for principal in options.principals() {
            cert_builder.valid_principal(principal)?;
        }
        if let Some(serial) = options.serial() {
            cert_builder.serial(serial)?;
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
        let certificate = tokio::task::spawn_blocking(move || {
            super::signing::sign(cert_builder, self.private_key.as_ref(), algorithm)
        })
        .await??;
        Ok(certificate)
    }
}
