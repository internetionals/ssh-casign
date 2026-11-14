use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
};

use color_eyre::eyre::WrapErr;
use ssh_casign_proto::{CertType, SignKeyRequest};

use crate::{auth, discovery, error::Result};

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

    /// Request a validity, e.g. 300, 30m, 8h, 1d or 1h30m
    #[arg(short = 'V', long, value_parser = parse_duration)]
    validity: Option<u64>,

    /// Request principals (repeatable or comma-separated)
    #[arg(short = 'n', long = "principal", value_delimiter = ',')]
    principals: Vec<String>,

    /// Request an extension, NAME or NAME=VALUE (repeatable); replaces the defaults
    #[arg(long = "extension", value_parser = parse_option)]
    extensions: Vec<(String, String)>,

    /// Request a certificate without extensions (except required ones)
    #[arg(long, conflicts_with = "extensions")]
    no_extensions: bool,

    /// Request a critical option, NAME=VALUE (repeatable); replaces the defaults
    #[arg(long = "critical-option", value_parser = parse_option)]
    critical_options: Vec<(String, String)>,

    /// Request a certificate without critical options (except required ones)
    #[arg(long, conflicts_with = "critical_options")]
    no_critical_options: bool,

    /// Name of this workload (ssh, ansible, terraform, ...); becomes part of
    /// the certificate's key ID [default: from the config, else ssh-casign-client]
    #[arg(short = 'I', long, env = "SSH_CASIGN_APP_NAME")]
    app_name: Option<String>,

    /// Request a certificate comment
    #[arg(short = 'C', long)]
    comment: Option<String>,
}

/// Parse `300`, `30m`, `1h30m`, ... into seconds (units: s, m, h, d, w).
fn parse_duration(input: &str) -> std::result::Result<u64, String> {
    let invalid = || format!("invalid duration '{input}' (examples: 300, 30m, 8h, 1d, 1h30m)");
    let mut total: u64 = 0;
    let mut digits = String::new();
    for c in input.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let unit = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            'w' => 604800,
            _ => return Err(invalid()),
        };
        let value: u64 = digits.parse().map_err(|_| invalid())?;
        total = value
            .checked_mul(unit)
            .and_then(|seconds| total.checked_add(seconds))
            .ok_or_else(invalid)?;
        digits.clear();
    }
    if !digits.is_empty() {
        let value: u64 = digits.parse().map_err(|_| invalid())?;
        total = total.checked_add(value).ok_or_else(invalid)?;
    } else if input.is_empty() {
        return Err(invalid());
    }
    Ok(total)
}

/// Parse `NAME` or `NAME=VALUE`.
fn parse_option(input: &str) -> std::result::Result<(String, String), String> {
    let (name, value) = input.split_once('=').unwrap_or((input, ""));
    if name.is_empty() {
        return Err(format!("invalid option '{input}': empty name"));
    }
    Ok((name.to_string(), value.to_string()))
}

/// `Some(map)` when requested (possibly empty), `None` to use the defaults.
fn requested_map(
    values: &[(String, String)],
    none_requested: bool,
) -> Option<BTreeMap<String, String>> {
    (none_requested || !values.is_empty()).then(|| values.iter().cloned().collect())
}

impl Args {
    fn sign_key_request(
        &self,
        public_key: &ssh_key::PublicKey,
        target: &super::Target,
    ) -> Result<SignKeyRequest> {
        Ok(SignKeyRequest {
            public_key: public_key.to_openssh()?,
            cert_type: self.cert_type.into(),
            validity: self.validity,
            principals: (!self.principals.is_empty()).then(|| self.principals.clone()),
            extensions: requested_map(&self.extensions, self.no_extensions),
            critical_options: requested_map(&self.critical_options, self.no_critical_options),
            app_name: Some(
                self.app_name
                    .clone()
                    .or_else(|| target.app_name.clone())
                    .unwrap_or_else(|| DEFAULT_APP_NAME.to_string()),
            ),
            comment: self.comment.clone(),
        })
    }
}

/// Application name when none is configured.
const DEFAULT_APP_NAME: &str = "ssh-casign-client";

/// OpenSSH's naming convention: `id_ed25519.pub` → `id_ed25519-cert.pub`.
fn certificate_file_for(public_key_file: &Path) -> PathBuf {
    let name = public_key_file.to_string_lossy();
    let stem = name.strip_suffix(".pub").unwrap_or(&name);
    PathBuf::from(format!("{stem}-cert.pub"))
}

fn read_public_key(public_key_file: Option<&Path>) -> Result<ssh_key::PublicKey> {
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
    let sign_key_request = args.sign_key_request(&public_key, target)?;
    let output = match (&args.output, public_key_file) {
        (Some(output), _) if output == Path::new("-") => None,
        (Some(output), _) => Some(output.clone()),
        (None, Some(public_key_file)) => Some(certificate_file_for(public_key_file)),
        (None, None) => None,
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .wrap_err("Failed to create tokio runtime")?;
    let certificate = rt.block_on(async {
        let http = reqwest::Client::new();
        let service = discovery::discover(&http, &target.url).await?;
        let scopes = target.scopes.as_ref().unwrap_or(&service.info.scopes);
        let token = auth::sign_in(
            &http,
            &auth::SignInRequest {
                method: target.sign_in,
                issuer: &service.info.issuer,
                client_id: target.client_id.as_ref().unwrap_or(&service.info.client_id),
                scopes,
            },
        )
        .await?;
        crate::sign::sign(&http, &service.sign_endpoint, &token, &sign_key_request).await
    })?;

    let cert_data = certificate.to_openssh()? + "\n";
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
    fn durations() {
        assert_eq!(parse_duration("300"), Ok(300));
        assert_eq!(parse_duration("30m"), Ok(1800));
        assert_eq!(parse_duration("1h30m"), Ok(5400));
        assert_eq!(parse_duration("1d"), Ok(86400));
        assert_eq!(parse_duration("1w2d"), Ok(777600));
        assert!(parse_duration("").is_err());
        assert!(parse_duration("1x").is_err());
        assert!(parse_duration("h").is_err());
    }

    #[test]
    fn options() {
        assert_eq!(
            parse_option("permit-pty"),
            Ok(("permit-pty".into(), "".into()))
        );
        assert_eq!(
            parse_option("source-address=10.0.0.0/8"),
            Ok(("source-address".into(), "10.0.0.0/8".into()))
        );
        assert!(parse_option("=x").is_err());
    }

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
