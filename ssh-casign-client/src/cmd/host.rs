//! `host`: sign this machine's host keys and install the certificates next to
//! them (`ssh_host_ed25519_key-cert.pub`, ...), for sshd's `HostCertificate`.
//!
//! Meant to run from a timer: a certificate is only renewed when less than a
//! third of its lifetime remains (or `--renew-before`), or when it no longer
//! fits (another key, an authority the service no longer has, other
//! requested names). `--on-change` runs only when something was written.

use std::path::{Path, PathBuf};

use color_eyre::eyre::{bail, WrapErr};
use ssh_casign_proto::{CertType, SignKeyRequest};
use ssh_key::public::KeyData;

use super::{
    cert::{certificate_file_for, read_public_key},
    request::{discover_service, obtain_certificates, parse_duration},
};
use crate::{certificate::Certificate, error::Result};

/// Application name (part of the key ID) when none is configured.
const DEFAULT_APP_NAME: &str = "ssh-casign-host";

/// Host key types, in the order sshd offers them.
const HOST_KEY_NAMES: &[&str] = &["ed25519", "ecdsa", "rsa"];

#[derive(clap::Args, Clone, Debug)]
pub(super) struct Args {
    /// Host public keys [default: the ssh_host_*_key.pub files in /etc/ssh, or
    /// %ProgramData%\ssh on Windows]
    keys: Vec<PathBuf>,

    /// Host names to request (repeatable or comma-separated) [default: what
    /// the service's profile derives from the token]
    #[arg(short = 'n', long = "principal", value_delimiter = ',')]
    principals: Vec<String>,

    /// Request a validity, e.g. 30d
    #[arg(short = 'V', long, value_parser = parse_duration)]
    validity: Option<u64>,

    /// Renew when less than this remains [default: a third of the
    /// certificate's lifetime]
    #[arg(long, value_parser = parse_duration)]
    renew_before: Option<u64>,

    /// Renew even if the certificates are still good
    #[arg(long)]
    force: bool,

    /// Command to run when a certificate was written, e.g. "systemctl reload
    /// ssh" (sshd only reads host certificates at startup and reload)
    #[arg(long)]
    on_change: Option<String>,

    /// Name of this workload; becomes part of the certificate's key ID
    /// [default: from the config, else ssh-casign-host]
    #[arg(short = 'I', long, env = "SSH_CASIGN_APP_NAME")]
    app_name: Option<String>,

    /// CA signature algorithm the connecting clients accept, e.g. ssh-rsa
    /// (repeatable or comma-separated) [default: from the profile, else any]
    #[arg(long = "ca-signature-algorithm", value_delimiter = ',')]
    ca_signature_algorithms: Vec<String>,
}

fn default_key_dir() -> PathBuf {
    if cfg!(windows) {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("ssh")
    } else {
        PathBuf::from("/etc/ssh")
    }
}

fn default_keys() -> Result<Vec<PathBuf>> {
    let dir = default_key_dir();
    let keys: Vec<PathBuf> = HOST_KEY_NAMES
        .iter()
        .map(|name| dir.join(format!("ssh_host_{name}_key.pub")))
        .filter(|path| path.exists())
        .collect();
    if keys.is_empty() {
        bail!("no host keys (ssh_host_*_key.pub) in {}", dir.display());
    }
    Ok(keys)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

/// What a still-installed certificate must satisfy to be kept.
struct Keep<'a> {
    key: &'a KeyData,
    authorities: &'a [KeyData],
    principals: Option<&'a [String]>,
    renew_before: Option<u64>,
    now: u64,
}

impl Keep<'_> {
    /// `None` if the certificate can stay, else why it is renewed.
    fn renewal_reason(&self, certificate: &Certificate) -> Option<String> {
        let view = certificate.view();
        if view.public_key() != self.key {
            return Some("it is for another key".into());
        }
        if view.cert_type() != ssh_key::certificate::CertType::Host {
            return Some("it is not a host certificate".into());
        }
        if !self.authorities.contains(view.signature_key()) {
            return Some("its authority is not one of the service's host authorities".into());
        }
        if let Some(principals) = self.principals {
            let mut wanted: Vec<String> = principals.iter().map(|p| p.to_lowercase()).collect();
            let mut have = view.valid_principals().to_vec();
            wanted.sort();
            have.sort();
            if wanted != have {
                return Some("other host names were requested".into());
            }
        }
        let lifetime = view.valid_before().saturating_sub(view.valid_after());
        let margin = self.renew_before.unwrap_or(lifetime / 3);
        if view.valid_before() <= self.now.saturating_add(margin) {
            return Some(if view.valid_before() <= self.now {
                "it has expired".into()
            } else {
                "it expires soon".into()
            });
        }
        None
    }
}

/// Write `content` to `path` atomically (temporary file and rename), readable
/// by everyone like the public key next to it.
pub(crate) fn write_atomically(path: &Path, content: impl AsRef<[u8]>) -> Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let temporary = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    std::fs::write(&temporary, content)
        .wrap_err_with(|| format!("Failed to write {}", temporary.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o644))?;
    }
    std::fs::rename(&temporary, path).wrap_err_with(|| {
        let _ = std::fs::remove_file(&temporary);
        format!("Failed to replace {}", path.display())
    })
}

pub(crate) fn run_on_change(command: &str) -> Result<()> {
    tracing::info!("running {command}");
    let status = if cfg!(windows) {
        std::process::Command::new("cmd")
            .args(["/C", command])
            .status()
    } else {
        std::process::Command::new("sh")
            .args(["-c", command])
            .status()
    }
    .wrap_err_with(|| format!("Failed to run {command}"))?;
    if !status.success() {
        bail!("{command} failed ({status})");
    }
    Ok(())
}

fn describe(certificate: &Certificate, now: u64) -> String {
    let view = certificate.view();
    let days = view.valid_before().saturating_sub(now) / 86_400;
    format!("{}, {days} days left", view.valid_principals().join(", "))
}

pub(super) fn run(args: &Args, target: &super::Target) -> super::CmdResult {
    let keys = if args.keys.is_empty() {
        default_keys()?
    } else {
        args.keys.clone()
    };
    let service = discover_service(target)?;
    let authorities: Vec<KeyData> = service
        .info
        .authorities
        .values()
        .filter(|authority| authority.cert_types.contains(&CertType::Host))
        .map(|authority| {
            Ok(ssh_key::PublicKey::from_openssh(&authority.public_key)
                .wrap_err("Invalid CA public key in service discovery document")?
                .key_data()
                .clone())
        })
        .collect::<Result<_>>()?;
    if authorities.is_empty() {
        bail!("the service has no authority for host certificates");
    }

    let principals = (!args.principals.is_empty()).then_some(args.principals.as_slice());
    let now = now();
    let mut report = Vec::new();
    let mut pending = Vec::new();
    for key_file in &keys {
        let public_key = read_public_key(Some(key_file))?;
        let certificate_file = certificate_file_for(key_file);
        let keep = Keep {
            key: public_key.key_data(),
            authorities: &authorities,
            principals,
            renew_before: args.renew_before,
            now,
        };
        let existing = std::fs::read_to_string(&certificate_file)
            .ok()
            .and_then(|text| Certificate::from_openssh(text.trim()).ok());
        let reason = match &existing {
            None => Some("there is none".to_string()),
            Some(_) if args.force => Some("--force".to_string()),
            Some(certificate) => keep.renewal_reason(certificate),
        };
        match (reason, existing) {
            (None, Some(certificate)) => report.push(format!(
                "kept {} ({})",
                certificate_file.display(),
                describe(&certificate, now)
            )),
            (reason, existing) => {
                tracing::info!(
                    "signing {}: {}",
                    key_file.display(),
                    reason.unwrap_or_default()
                );
                pending.push((public_key, certificate_file, existing.is_none()));
            }
        }
    }

    if !pending.is_empty() {
        let app_name = args
            .app_name
            .clone()
            .or_else(|| target.app_name.clone())
            .unwrap_or_else(|| DEFAULT_APP_NAME.to_string());
        let ca_signature_algorithms = if args.ca_signature_algorithms.is_empty() {
            target.ca_signature_algorithms.clone()
        } else {
            Some(args.ca_signature_algorithms.clone())
        };
        let requests = pending
            .iter()
            .map(|(public_key, _, _)| {
                Ok(SignKeyRequest {
                    public_key: public_key.to_openssh()?,
                    cert_type: CertType::Host,
                    validity: args.validity,
                    principals: principals.map(<[String]>::to_vec),
                    app_name: Some(app_name.clone()),
                    ca_signature_algorithms: ca_signature_algorithms.clone(),
                    ..SignKeyRequest::default()
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let certificates = obtain_certificates(target, &requests)?;
        for ((public_key, certificate_file, new), certificate) in pending.iter().zip(certificates) {
            let view = certificate.view();
            if view.public_key() != public_key.key_data()
                || view.cert_type() != ssh_key::certificate::CertType::Host
            {
                bail!("the service returned a certificate for another key or type");
            }
            write_atomically(certificate_file, &(certificate.to_openssh() + "\n"))?;
            report.push(format!(
                "wrote {} ({})",
                certificate_file.display(),
                describe(&certificate, now)
            ));
            if *new {
                report.push(format!(
                    "  sshd_config needs: HostCertificate {}",
                    certificate_file.display()
                ));
            }
        }
        if let Some(command) = &args.on_change {
            run_on_change(command)?;
        }
    }
    Ok(Some(report.join("\n") + "\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{
        certificate::{Builder, CertType as SshCertType},
        private::Ed25519Keypair,
        PrivateKey,
    };

    const NOW: u64 = 1_800_000_000;

    fn ca(seed: u8) -> PrivateKey {
        PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
    }

    fn host_key() -> KeyData {
        KeyData::Ed25519(Ed25519Keypair::from_seed(&[9; 32]).public)
    }

    fn certificate(
        ca: &PrivateKey,
        cert_type: SshCertType,
        after: u64,
        before: u64,
    ) -> Certificate {
        let mut builder = Builder::new([0; 16], host_key(), after, before).unwrap();
        builder.cert_type(cert_type).unwrap();
        builder.valid_principal("web-1.example.com").unwrap();
        let signed = builder.sign(ca).unwrap();
        Certificate::from_openssh(&signed.to_openssh().unwrap()).unwrap()
    }

    #[test]
    fn renewal_reasons() {
        let service_ca = ca(1);
        let authorities = [service_ca.public_key().key_data().clone()];
        let key = host_key();
        let keep = Keep {
            key: &key,
            authorities: &authorities,
            principals: None,
            renew_before: None,
            now: NOW,
        };
        let day = 86_400;
        // 30 days, 20 left: keep. 30 days, 5 left: renew (under a third).
        let fresh = certificate(
            &service_ca,
            SshCertType::Host,
            NOW - 10 * day,
            NOW + 20 * day,
        );
        assert_eq!(keep.renewal_reason(&fresh), None);
        let old = certificate(
            &service_ca,
            SshCertType::Host,
            NOW - 25 * day,
            NOW + 5 * day,
        );
        assert_eq!(keep.renewal_reason(&old).unwrap(), "it expires soon");
        let expired = certificate(&service_ca, SshCertType::Host, NOW - 30 * day, NOW - 1);
        assert_eq!(keep.renewal_reason(&expired).unwrap(), "it has expired");
        let user = certificate(&service_ca, SshCertType::User, NOW, NOW + 30 * day);
        assert!(keep.renewal_reason(&user).unwrap().contains("not a host"));
        let foreign = certificate(&ca(2), SshCertType::Host, NOW, NOW + 30 * day);
        assert!(keep.renewal_reason(&foreign).unwrap().contains("authority"));
        // An explicit margin.
        let keep_week = Keep {
            renew_before: Some(7 * day),
            ..keep
        };
        assert_eq!(keep_week.renewal_reason(&old).unwrap(), "it expires soon");
        let keep_day = Keep {
            renew_before: Some(day),
            ..keep_week
        };
        assert_eq!(keep_day.renewal_reason(&old), None);
        // Other requested names.
        let names = ["WEB-1.example.com".to_string()];
        let same = Keep {
            principals: Some(&names),
            ..keep_day
        };
        assert_eq!(same.renewal_reason(&fresh), None);
        let other_names = ["web-2.example.com".to_string()];
        let other = Keep {
            principals: Some(&other_names),
            ..same
        };
        assert!(other.renewal_reason(&fresh).unwrap().contains("host names"));
    }

    #[test]
    fn atomic_write_replaces() {
        let dir = std::env::temp_dir().join(format!("ssh-casign-host-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ssh_host_ed25519_key-cert.pub");
        write_atomically(&path, "one\n").unwrap();
        write_atomically(&path, "two\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "two\n");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
