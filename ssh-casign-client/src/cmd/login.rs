//! `login`: sign in and load a certificate into ssh-agent.
//!
//! By default a fresh Ed25519 key is generated in memory and added to the
//! agent together with its certificate; it never touches the disk. With
//! `--key`, an existing key is used: its certificate is written next to it and
//! `ssh-add` loads both (and asks for the passphrase if needed). Either way
//! the agent forgets the key when the certificate expires.
//!
//! A still-valid certificate is reused instead of signing in again, when it
//! was issued by one of the service's authorities, has at least
//! `--min-remaining` left (default: 5 minutes, or half the certificate's
//! validity if that is shorter), and the request is plain (no explicit validity,
//! principals, extensions, critical options or comment). Without `--key` it
//! must also have been loaded for the same application name, which `login`
//! records in the agent comment. `--new` always gets a new certificate.
//!
//! When a new in-memory key is added, earlier ones that `login` added for the
//! same application name are removed from the agent.

use std::path::{Path, PathBuf};

use color_eyre::eyre::{bail, WrapErr};
use rand::RngCore;
use ssh_casign_proto::CertType;
use ssh_key::{
    certificate::CertType as SshCertType, private::Ed25519Keypair, public::KeyData, PublicKey,
};
use zeroize::Zeroizing;

use super::{
    cert::{certificate_file_for, read_public_key},
    request::{
        discover_service, obtain_certificate, parse_duration, service_authorities, RequestArgs,
    },
};
use crate::{agent, certificate::Certificate, error::Result};

/// Prefix of the agent comment of identities added by `login`.
const COMMENT_PREFIX: &str = "ssh-casign:";

#[derive(clap::Args, Clone, Debug)]
pub(super) struct Args {
    /// Use this private key instead of a new in-memory one: KEY.pub is signed,
    /// the certificate is written to KEY-cert.pub and `ssh-add` loads both
    #[arg(short, long, value_name = "KEY")]
    key: Option<PathBuf>,

    /// Always sign in for a new certificate, even if a usable one is loaded
    #[arg(long)]
    new: bool,

    /// Reuse a loaded certificate only if it is valid for at least this long
    /// [default: 5m, or half the certificate's validity if that is shorter]
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    min_remaining: Option<u64>,

    #[command(flatten)]
    request: RequestArgs,
}

/// What `login` did.
enum Outcome {
    Added,
    Reused,
    Reloaded,
}

pub(super) fn run(args: &Args, target: &super::Target) -> super::CmdResult {
    if let Some((certificate, outcome)) = try_reuse(args, target) {
        return Ok(Some(summary(&certificate, outcome)));
    }
    let certificate = match &args.key {
        None => login_ephemeral(args, target)?,
        Some(key) => login_with_key_file(args, target, key)?,
    };
    Ok(Some(summary(&certificate, Outcome::Added)))
}

/// Reuse a certificate if possible. Any problem (no agent, service not
/// reachable, ...) just means a normal login.
fn try_reuse(args: &Args, target: &super::Target) -> Option<(Certificate, Outcome)> {
    if args.new {
        return None;
    }
    if !args.request.is_plain() {
        tracing::debug!("not reusing a certificate: specific values were requested");
        return None;
    }
    let found = (|| -> Result<Option<(Certificate, Outcome)>> {
        let authorities = service_authorities(&discover_service(target)?)?;
        let criteria = Criteria {
            authorities: &authorities,
            now: now()?,
            min_remaining: args.min_remaining,
            signature_algorithms: args.request.ca_signature_algorithms(target),
        };
        let identities = agent::list_identities()?;
        match &args.key {
            None => Ok(
                find_in_agent(&identities, &args.request.app_name(target), &criteria)
                    .map(|certificate| (certificate, Outcome::Reused)),
            ),
            Some(key) => reuse_key_file(key, &identities, &criteria),
        }
    })();
    match found {
        Ok(found) => found,
        Err(err) => {
            tracing::debug!("not reusing a certificate: {err:#}");
            None
        }
    }
}

/// Default for `--min-remaining`: this, or half the certificate's validity
/// if that is shorter (so short-lived certificates can be reused too).
const DEFAULT_MIN_REMAINING: u64 = 300;

/// When a certificate is good enough to reuse.
struct Criteria<'a> {
    authorities: &'a [KeyData],
    now: u64,
    /// `None`: [`DEFAULT_MIN_REMAINING`], capped at half the validity.
    min_remaining: Option<u64>,
    /// CA signature algorithms the certificate must have, if restricted.
    signature_algorithms: Option<&'a [String]>,
}

impl Criteria<'_> {
    fn accepts(&self, certificate: &Certificate) -> bool {
        let validity = certificate
            .view()
            .valid_before()
            .saturating_sub(certificate.view().valid_after());
        let min_remaining = self
            .min_remaining
            .unwrap_or_else(|| DEFAULT_MIN_REMAINING.min(validity / 2));
        certificate.view().cert_type() == SshCertType::User
            && self
                .authorities
                .contains(certificate.view().signature_key())
            && certificate.view().valid_after() <= self.now
            && certificate.view().valid_before() >= self.now.saturating_add(min_remaining)
            && self.signature_algorithms.is_none_or(|accepted| {
                accepted
                    .iter()
                    .any(|algorithm| algorithm == certificate.signature_algorithm())
            })
    }
}

/// The longest-valid certificate in the agent that `login` added for this
/// application name and that meets the criteria.
fn find_in_agent(
    identities: &[agent::Identity],
    app_name: &str,
    criteria: &Criteria<'_>,
) -> Option<Certificate> {
    identities
        .iter()
        .filter(|identity| comment_app_name(&identity.comment).as_deref() == Some(app_name))
        .filter_map(agent::Identity::certificate)
        .filter(|certificate| criteria.accepts(certificate))
        .max_by_key(|certificate| certificate.view().valid_before())
}

/// With `--key`: reuse KEY-cert.pub if it is good enough, loading it into the
/// agent again only if it isn't there.
fn reuse_key_file(
    key: &Path,
    identities: &[agent::Identity],
    criteria: &Criteria<'_>,
) -> Result<Option<(Certificate, Outcome)>> {
    let public_key_file = public_key_file_for(key);
    let certificate_file = certificate_file_for(&public_key_file);
    let Ok(data) = std::fs::read_to_string(&certificate_file) else {
        return Ok(None);
    };
    let certificate = Certificate::from_openssh(data.trim())?;
    let public_key = read_public_key(Some(&public_key_file))?;
    if certificate.view().public_key() != public_key.key_data() || !criteria.accepts(&certificate) {
        return Ok(None);
    }
    if identities
        .iter()
        .any(|identity| identity.key_blob == certificate.blob())
    {
        return Ok(Some((certificate, Outcome::Reused)));
    }
    ssh_add(key, remaining_lifetime(&certificate)?, &certificate_file)?;
    Ok(Some((certificate, Outcome::Reloaded)))
}

fn login_ephemeral(args: &Args, target: &super::Target) -> Result<Certificate> {
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(seed.as_mut());
    let keypair = Ed25519Keypair::from_seed(&seed);
    let public_key = PublicKey::new(KeyData::Ed25519(keypair.public), "");

    let request = args
        .request
        .sign_key_request(&public_key, CertType::User, target)?;
    let certificate = obtain_certificate(target, &request)?;
    let lifetime = remaining_lifetime(&certificate)?;
    let app_name = args.request.app_name(target);
    let superseded = superseded_identities(&app_name);
    let comment = agent_comment(&app_name, certificate.view().key_id());
    agent::add_certificate(&keypair, &certificate, &comment, lifetime)?;
    remove_identities(&superseded);
    Ok(certificate)
}

fn login_with_key_file(args: &Args, target: &super::Target, key: &Path) -> Result<Certificate> {
    let public_key_file = public_key_file_for(key);
    let public_key = read_public_key(Some(&public_key_file))?;
    let request = args
        .request
        .sign_key_request(&public_key, CertType::User, target)?;
    let certificate = obtain_certificate(target, &request)?;

    let certificate_file = certificate_file_for(&public_key_file);
    std::fs::write(&certificate_file, certificate.to_openssh() + "\n")
        .wrap_err_with(|| format!("Failed to write certificate {}", certificate_file.display()))?;
    ssh_add(key, remaining_lifetime(&certificate)?, &certificate_file)?;
    Ok(certificate)
}

/// Identities that `login` added earlier for this application name. They are
/// removed once the new certificate is in, so the agent doesn't pile up keys
/// (servers stop after MaxAuthTries attempts).
fn superseded_identities(app_name: &str) -> Vec<Vec<u8>> {
    match agent::list_identities() {
        Ok(identities) => identities
            .into_iter()
            .filter(|identity| comment_app_name(&identity.comment).as_deref() == Some(app_name))
            .map(|identity| identity.key_blob)
            .collect(),
        Err(err) => {
            tracing::debug!("not listing ssh-agent identities: {err:#}");
            Vec::new()
        }
    }
}

fn remove_identities(key_blobs: &[Vec<u8>]) {
    for key_blob in key_blobs {
        if let Err(err) = agent::remove_identity(key_blob) {
            tracing::debug!("failed to remove a superseded identity: {err:#}");
        }
    }
}

fn public_key_file_for(key: &Path) -> PathBuf {
    PathBuf::from(format!("{}.pub", key.display()))
}

/// Load KEY and KEY-cert.pub with `ssh-add`, which handles passphrases.
fn ssh_add(key: &Path, lifetime: u32, certificate_file: &Path) -> Result<()> {
    let status = std::process::Command::new("ssh-add")
        .arg("-t")
        .arg(lifetime.to_string())
        .arg(key)
        .status()
        .wrap_err("Failed to run ssh-add")?;
    if !status.success() {
        bail!(
            "ssh-add failed ({status}); the certificate is in {}",
            certificate_file.display()
        );
    }
    Ok(())
}

/// Agent comment: `ssh-casign:<app_name> <key_id>`. The application name is
/// percent-encoded so it can't contain the separator.
fn agent_comment(app_name: &str, key_id: &str) -> String {
    let mut comment = String::from(COMMENT_PREFIX);
    for c in app_name.chars() {
        if c == '%' || c.is_whitespace() || c.is_control() {
            let mut buf = [0; 4];
            for byte in c.encode_utf8(&mut buf).bytes() {
                comment.push_str(&format!("%{byte:02X}"));
            }
        } else {
            comment.push(c);
        }
    }
    comment.push(' ');
    comment.push_str(key_id);
    comment
}

/// The application name from a comment written by [`agent_comment`].
pub(super) fn comment_app_name(comment: &str) -> Option<String> {
    let encoded = comment.strip_prefix(COMMENT_PREFIX)?.split(' ').next()?;
    let mut bytes = Vec::new();
    let mut rest = encoded.as_bytes();
    while let Some((&byte, tail)) = rest.split_first() {
        if byte == b'%' && tail.len() >= 2 {
            let hex = std::str::from_utf8(&tail[..2]).ok()?;
            bytes.push(u8::from_str_radix(hex, 16).ok()?);
            rest = &tail[2..];
        } else {
            bytes.push(byte);
            rest = tail;
        }
    }
    String::from_utf8(bytes).ok()
}

fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

/// Seconds until the certificate expires, as the agent's key lifetime.
fn remaining_lifetime(certificate: &Certificate) -> Result<u32> {
    let remaining = certificate.view().valid_before().saturating_sub(now()?);
    if remaining == 0 {
        bail!("The certificate has already expired");
    }
    Ok(u32::try_from(remaining).unwrap_or(u32::MAX))
}

fn format_duration(secs: u64) -> String {
    let (days, hours, minutes, seconds) =
        (secs / 86400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    match (days, hours, minutes) {
        (0, 0, 0) => format!("{seconds}s"),
        (0, 0, _) => format!("{minutes}m{seconds:02}s"),
        (0, _, _) => format!("{hours}h{minutes:02}m"),
        _ => format!("{days}d{hours:02}h"),
    }
}

fn summary(certificate: &Certificate, outcome: Outcome) -> String {
    let headline = match outcome {
        Outcome::Added => "Added certificate to ssh-agent",
        Outcome::Reused => "Reusing certificate in ssh-agent",
        Outcome::Reloaded => "Reloaded certificate into ssh-agent",
    };
    let remaining = now()
        .map(|now| certificate.view().valid_before().saturating_sub(now))
        .unwrap_or_default();
    format!(
        "{headline}\n  key ID:     {}\n  principals: {}\n  expires in: {}\n",
        certificate.view().key_id(),
        certificate.view().valid_principals().join(", "),
        format_duration(remaining)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn ca(seed: u8) -> ssh_key::PrivateKey {
        ssh_key::PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
    }

    fn certificate(
        ca: &ssh_key::PrivateKey,
        cert_type: SshCertType,
        valid: (u64, u64),
    ) -> Certificate {
        let key = Ed25519Keypair::from_seed(&[9; 32]);
        let mut builder = ssh_key::certificate::Builder::new(
            vec![0; 16],
            KeyData::Ed25519(key.public),
            valid.0,
            valid.1,
        )
        .unwrap();
        builder.cert_type(cert_type).unwrap();
        builder.valid_principal("alice").unwrap();
        Certificate::from_blob(builder.sign(ca).unwrap().to_bytes().unwrap()).unwrap()
    }

    fn identity(certificate: &Certificate, comment: &str) -> agent::Identity {
        agent::Identity {
            key_blob: certificate.blob().to_vec(),
            comment: comment.to_string(),
        }
    }

    #[test]
    fn criteria() {
        let service_ca = ca(1);
        let authorities = [service_ca.public_key().key_data().clone()];
        let criteria = Criteria {
            authorities: &authorities,
            now: NOW,
            min_remaining: Some(300),
            signature_algorithms: None,
        };
        let user = |valid| certificate(&service_ca, SshCertType::User, valid);
        assert!(criteria.accepts(&user((NOW - 60, NOW + 3600))));
        assert!(criteria.accepts(&user((NOW - 60, NOW + 300))));
        assert!(
            !criteria.accepts(&user((NOW - 60, NOW + 299))),
            "too little left"
        );
        assert!(
            !criteria.accepts(&user((NOW + 60, NOW + 3600))),
            "not yet valid"
        );
        assert!(
            !criteria.accepts(&certificate(
                &ca(2),
                SshCertType::User,
                (NOW - 60, NOW + 3600)
            )),
            "other CA"
        );
        assert!(
            !criteria.accepts(&certificate(
                &service_ca,
                SshCertType::Host,
                (NOW - 60, NOW + 3600)
            )),
            "host certificate"
        );
    }

    #[test]
    fn signature_algorithm_restriction() {
        let service_ca = ca(1);
        let authorities = [service_ca.public_key().key_data().clone()];
        let certificate = certificate(&service_ca, SshCertType::User, (NOW - 60, NOW + 3600));
        assert_eq!(certificate.signature_algorithm(), "ssh-ed25519");
        let accepts = |accepted: &[&str]| {
            let accepted: Vec<String> = accepted.iter().map(|a| a.to_string()).collect();
            Criteria {
                authorities: &authorities,
                now: NOW,
                min_remaining: Some(300),
                signature_algorithms: Some(&accepted),
            }
            .accepts(&certificate)
        };
        assert!(accepts(&["ssh-rsa", "ssh-ed25519"]));
        assert!(!accepts(&["ssh-rsa"]));
    }

    #[test]
    fn default_min_remaining_adapts_to_short_certificates() {
        let service_ca = ca(1);
        let authorities = [service_ca.public_key().key_data().clone()];
        let criteria = Criteria {
            authorities: &authorities,
            now: NOW,
            min_remaining: None,
            signature_algorithms: None,
        };
        let user = |valid| certificate(&service_ca, SshCertType::User, valid);
        // 1 hour certificate: needs 5 minutes left.
        assert!(criteria.accepts(&user((NOW - 3000, NOW + 600))));
        assert!(!criteria.accepts(&user((NOW - 3400, NOW + 200))));
        // 5 minute certificate: needs half of that, 150 seconds.
        assert!(criteria.accepts(&user((NOW - 100, NOW + 200))));
        assert!(!criteria.accepts(&user((NOW - 200, NOW + 100))));
    }

    #[test]
    fn find_in_agent_matches_app_name_and_prefers_longest() {
        let service_ca = ca(1);
        let authorities = [service_ca.public_key().key_data().clone()];
        let criteria = Criteria {
            authorities: &authorities,
            now: NOW,
            min_remaining: Some(300),
            signature_algorithms: None,
        };
        let short = certificate(&service_ca, SshCertType::User, (NOW - 60, NOW + 1000));
        let long = certificate(&service_ca, SshCertType::User, (NOW - 60, NOW + 5000));
        let identities = [
            identity(&short, &agent_comment("laptop", "a")),
            identity(&long, &agent_comment("laptop", "b")),
            identity(&long, &agent_comment("ansible", "c")),
            identity(&long, "someone else's key"),
        ];
        let found = find_in_agent(&identities, "laptop", &criteria).unwrap();
        assert_eq!(found.view().valid_before(), NOW + 5000);
        assert!(find_in_agent(&identities, "terraform", &criteria).is_none());
    }

    #[test]
    fn agent_comment_roundtrip() {
        for app_name in ["laptop", "vs code", "50%", "ünïcode"] {
            let comment = agent_comment(app_name, "ca1:default:alice:x y");
            assert_eq!(
                comment_app_name(&comment).as_deref(),
                Some(app_name),
                "{comment}"
            );
        }
        assert_eq!(agent_comment("vs code", "id"), "ssh-casign:vs%20code id");
        assert_eq!(comment_app_name("my laptop key"), None);
    }

    #[test]
    fn durations() {
        assert_eq!(format_duration(42), "42s");
        assert_eq!(format_duration(299), "4m59s");
        assert_eq!(format_duration(3600), "1h00m");
        assert_eq!(format_duration(28799), "7h59m");
        assert_eq!(format_duration(90000), "1d01h");
    }
}
