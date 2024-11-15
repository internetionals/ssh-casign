use rand::{distributions::Standard, Rng};
use ssh_key::{Certificate, PrivateKey, PublicKey};
use std::{collections::HashMap, path::Path, sync::Arc};
use thiserror::Error;

pub struct CertificateOptions {
    pub valid_principals: Vec<String>,
    pub key_id: Option<String>,
    pub comment: Option<String>,
    pub extensions: Option<HashMap<String, String>>,
    pub critical_options: Option<HashMap<String, String>>,
}

pub struct SignOptions {
    pub validity: u64,
    pub certificate: CertificateOptions,
}

pub(crate) struct SshCa {
    private_key: Arc<PrivateKey>,
}

#[derive(Debug, Error)]
pub(crate) enum SignError {
    #[error("unable to generate certificate")]
    CertificateError(#[from] ssh_key::Error),
    #[error("invalid timestamp")]
    SystemTimeError(#[from] std::time::SystemTimeError),
}

fn gen_nonce(len: usize) -> Vec<u8> {
    rand::thread_rng().sample_iter(Standard).take(len).collect()
}

impl SshCa {
    pub(crate) fn new(private_key_file: &str) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        Ok(Arc::new(Self {
            private_key: Arc::new(PrivateKey::read_openssh_file(Path::new(private_key_file))?),
        }))
    }

    pub(crate) async fn sign(
        self: Arc<Self>,
        client_public_key: PublicKey,
        sign_options: SignOptions,
    ) -> Result<Certificate, SignError> {
        let valid_after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let valid_before = valid_after + sign_options.validity;
        let mut cert_builder = ssh_key::certificate::Builder::new(
            gen_nonce(32),
            client_public_key,
            valid_after,
            valid_before,
        )
        .expect("certificate builder");
        for principal in &sign_options.certificate.valid_principals {
            cert_builder.valid_principal(principal)?;
        }
        if let Some(key_id) = &sign_options.certificate.key_id {
            cert_builder.key_id(key_id)?;
        }
        if let Some(comment) = &sign_options.certificate.comment {
            cert_builder.comment(comment)?;
        }
        if let Some(extensions) = &sign_options.certificate.extensions {
            for (name, data) in extensions {
                cert_builder.extension(name, data)?;
            }
        }
        if let Some(critical_options) = &sign_options.certificate.critical_options {
            for (name, data) in critical_options {
                cert_builder.critical_option(name, data)?;
            }
        }
        let certificate =
            tokio::task::spawn_blocking(move || cert_builder.sign(self.private_key.as_ref()))
                .await
                .expect("Threading error")?;
        Ok(certificate)
    }
}
