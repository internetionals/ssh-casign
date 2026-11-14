//! `login`: sign in and load a certificate into ssh-agent.
//!
//! By default a fresh Ed25519 key is generated in memory and added to the
//! agent together with its certificate; it never touches the disk. With
//! `--key`, an existing key is used: its certificate is written next to it and
//! `ssh-add` loads both (and asks for the passphrase if needed). Either way
//! the agent forgets the key when the certificate expires.

use std::path::{Path, PathBuf};

use color_eyre::eyre::{bail, WrapErr};
use rand::RngCore;
use ssh_casign_proto::CertType;
use ssh_key::{private::Ed25519Keypair, public::KeyData, Certificate, PublicKey};
use zeroize::Zeroizing;

use super::{
    cert::{certificate_file_for, read_public_key},
    request::{obtain_certificate, RequestArgs},
};
use crate::{agent, error::Result};

#[derive(clap::Args, Clone, Debug)]
pub(super) struct Args {
    /// Use this private key instead of a new in-memory one: KEY.pub is signed,
    /// the certificate is written to KEY-cert.pub and `ssh-add` loads both
    #[arg(short, long, value_name = "KEY")]
    key: Option<PathBuf>,

    #[command(flatten)]
    request: RequestArgs,
}

pub(super) fn run(args: &Args, target: &super::Target) -> super::CmdResult {
    let (certificate, lifetime) = match &args.key {
        None => login_ephemeral(args, target)?,
        Some(key) => login_with_key_file(args, target, key)?,
    };
    Ok(Some(summary(&certificate, lifetime)))
}

fn login_ephemeral(args: &Args, target: &super::Target) -> Result<(Certificate, u32)> {
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(seed.as_mut());
    let keypair = Ed25519Keypair::from_seed(&seed);
    let public_key = PublicKey::new(KeyData::Ed25519(keypair.public), "");

    let request = args
        .request
        .sign_key_request(&public_key, CertType::User, target)?;
    let certificate = obtain_certificate(target, &request)?;
    let lifetime = remaining_lifetime(&certificate)?;
    agent::add_certificate(&keypair, &certificate, certificate.key_id(), lifetime)?;
    Ok((certificate, lifetime))
}

fn login_with_key_file(
    args: &Args,
    target: &super::Target,
    key: &Path,
) -> Result<(Certificate, u32)> {
    let public_key_file = PathBuf::from(format!("{}.pub", key.display()));
    let public_key = read_public_key(Some(&public_key_file))?;
    let request = args
        .request
        .sign_key_request(&public_key, CertType::User, target)?;
    let certificate = obtain_certificate(target, &request)?;

    let certificate_file = certificate_file_for(&public_key_file);
    std::fs::write(&certificate_file, certificate.to_openssh()? + "\n")
        .wrap_err_with(|| format!("Failed to write certificate {}", certificate_file.display()))?;

    // ssh-add picks up KEY-cert.pub by itself and handles passphrases.
    let lifetime = remaining_lifetime(&certificate)?;
    let status = std::process::Command::new("ssh-add")
        .arg("-t")
        .arg(lifetime.to_string())
        .arg(key)
        .status()
        .wrap_err("Failed to run ssh-add")?;
    if !status.success() {
        bail!(
            "ssh-add failed ({status}); the certificate was written to {}",
            certificate_file.display()
        );
    }
    Ok((certificate, lifetime))
}

/// Seconds until the certificate expires, as the agent's key lifetime.
fn remaining_lifetime(certificate: &Certificate) -> Result<u32> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let remaining = certificate.valid_before().saturating_sub(now);
    if remaining == 0 {
        bail!("The certificate has already expired");
    }
    Ok(u32::try_from(remaining).unwrap_or(u32::MAX))
}

fn format_duration(secs: u32) -> String {
    let (days, hours, minutes, seconds) =
        (secs / 86400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    match (days, hours, minutes) {
        (0, 0, 0) => format!("{seconds}s"),
        (0, 0, _) => format!("{minutes}m{seconds:02}s"),
        (0, _, _) => format!("{hours}h{minutes:02}m"),
        _ => format!("{days}d{hours:02}h"),
    }
}

fn summary(certificate: &Certificate, lifetime: u32) -> String {
    format!(
        "Added certificate to ssh-agent\n  key ID:     {}\n  principals: {}\n  expires in: {}\n",
        certificate.key_id(),
        certificate.valid_principals().join(", "),
        format_duration(lifetime)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(format_duration(42), "42s");
        assert_eq!(format_duration(299), "4m59s");
        assert_eq!(format_duration(3600), "1h00m");
        assert_eq!(format_duration(28799), "7h59m");
        assert_eq!(format_duration(90000), "1d01h");
    }
}
