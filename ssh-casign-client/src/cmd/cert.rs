use std::{
    io::Read,
    path::{Path, PathBuf},
};

use color_eyre::eyre::WrapErr;
use ssh_casign_proto::CertType;

use super::request::{obtain_certificate, RequestArgs};
use crate::error::Result;

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum CliCertType {
    User,
    Host,
}

impl From<CliCertType> for CertType {
    fn from(cert_type: CliCertType) -> Self {
        match cert_type {
            CliCertType::User => CertType::User,
            CliCertType::Host => CertType::Host,
        }
    }
}

#[derive(clap::Args, Clone, Debug)]
pub(super) struct Args {
    /// Certificate type
    #[arg(short = 't', long = "type", value_enum, default_value = "user")]
    cert_type: CliCertType,

    /// Where to write the certificate, '-' for stdout [default: <key>-cert.pub
    /// next to the public key, or stdout when the key is read from stdin]
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Public key to sign (OpenSSH format); '-' or omitted reads stdin
    public_key_file: Option<PathBuf>,

    #[command(flatten)]
    request: RequestArgs,
}

/// OpenSSH's naming convention: `id_ed25519.pub` → `id_ed25519-cert.pub`.
pub(super) fn certificate_file_for(public_key_file: &Path) -> PathBuf {
    let name = public_key_file.to_string_lossy();
    let stem = name.strip_suffix(".pub").unwrap_or(&name);
    PathBuf::from(format!("{stem}-cert.pub"))
}

pub(super) fn read_public_key(public_key_file: Option<&Path>) -> Result<ssh_key::PublicKey> {
    let public_key_data = match public_key_file {
        Some(file) => std::fs::read_to_string(file)
            .wrap_err_with(|| format!("Failed to read public key {}", file.display()))?,
        None => {
            let mut data = String::new();
            std::io::stdin()
                .read_to_string(&mut data)
                .wrap_err("Failed to read public key from stdin")?;
            data
        }
    };
    ssh_key::PublicKey::from_openssh(public_key_data.trim()).wrap_err("Not an OpenSSH public key")
}

pub(super) fn run(args: &Args, target: &super::Target) -> super::CmdResult {
    let public_key_file = args
        .public_key_file
        .as_deref()
        .filter(|file| *file != Path::new("-"));
    let public_key = read_public_key(public_key_file)?;
    let sign_key_request =
        args.request
            .sign_key_request(&public_key, args.cert_type.into(), target)?;
    let output = match (&args.output, public_key_file) {
        (Some(output), _) if output == Path::new("-") => None,
        (Some(output), _) => Some(output.clone()),
        (None, Some(public_key_file)) => Some(certificate_file_for(public_key_file)),
        (None, None) => None,
    };

    let certificate = obtain_certificate(target, &sign_key_request)?;

    let cert_data = certificate.to_openssh() + "\n";
    match output {
        Some(certificate_file) => {
            std::fs::write(&certificate_file, cert_data).wrap_err_with(|| {
                format!("Failed to write certificate {}", certificate_file.display())
            })?;
            tracing::info!("wrote certificate to {}", certificate_file.display());
            Ok(None)
        }
        None => Ok(Some(cert_data)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_file_naming() {
        assert_eq!(
            certificate_file_for(Path::new("/home/u/.ssh/id_ed25519.pub")),
            PathBuf::from("/home/u/.ssh/id_ed25519-cert.pub")
        );
        assert_eq!(
            certificate_file_for(Path::new("key")),
            PathBuf::from("key-cert.pub")
        );
    }
}
