//! `ca-keys`: the service's CA public keys, ready for sshd's
//! `TrustedUserCAKeys` file (user authorities) or for `known_hosts` as
//! `@cert-authority` lines (host authorities). Needs no sign-in.
//!
//! With a pinned trust statement (`trust pin`), the keys come from the
//! service's statement after it passed the pin, so a forged discovery
//! document can't add a CA. Without a pin, the unsigned list is used, with a
//! warning.

use std::path::PathBuf;

use color_eyre::eyre::bail;
use ssh_casign_proto::CertType;

use super::{
    host::{run_on_change, write_atomically},
    request::discover_service,
};
use crate::trust_pin;

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum Kind {
    /// For TrustedUserCAKeys on servers
    User,
    /// @cert-authority lines for known_hosts on clients
    Host,
}

#[derive(clap::Args, Clone, Debug)]
pub(super) struct Args {
    /// Which authorities
    #[arg(short = 't', long = "type", value_enum, default_value = "user")]
    kind: Kind,

    /// Host name pattern for the @cert-authority lines, e.g. "*.example.com"
    /// [default: each authority's known_hosts_pattern]
    #[arg(long)]
    hosts: Option<String>,

    /// Write to this file (replaced only when it changed) instead of stdout,
    /// e.g. /etc/ssh/trusted-user-ca-keys or /etc/ssh/ssh_known_hosts.d/ssh-casign
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Command to run when the file changed
    #[arg(long, requires = "output")]
    on_change: Option<String>,
}

/// An authority as the output needs it.
struct Authority {
    name: String,
    public_key: String,
    cert_types: Vec<CertType>,
    known_hosts_pattern: Option<String>,
}

/// One line per authority that signs `kind`; the comment is the authority's
/// name. Retired authorities stay: their certificates are still valid.
fn lines(authorities: &[Authority], kind: CertType, hosts: Option<&str>) -> Vec<String> {
    authorities
        .iter()
        .filter(|authority| authority.cert_types.contains(&kind))
        .map(|authority| {
            // Drop the key's own comment; name the authority instead.
            let key: Vec<&str> = authority.public_key.split_whitespace().take(2).collect();
            let key = key.join(" ");
            match kind {
                CertType::User => format!("{key} {}", authority.name),
                CertType::Host => {
                    let pattern = hosts
                        .or(authority.known_hosts_pattern.as_deref())
                        .unwrap_or_else(|| {
                            tracing::warn!(
                                "authority {} has no known_hosts_pattern; trusting it for every \
                                 host ('*'); pass --hosts",
                                authority.name
                            );
                            "*"
                        });
                    format!("@cert-authority {pattern} {key} {}", authority.name)
                }
            }
        })
        .collect()
}

pub(super) fn run(args: &Args, target: &super::Target) -> super::CmdResult {
    if args
        .hosts
        .as_deref()
        .is_some_and(|hosts| hosts.chars().any(char::is_whitespace))
    {
        bail!("--hosts must not contain whitespace (separate patterns with commas)");
    }
    let service = discover_service(target)?;
    let authorities: Vec<Authority> = match trust_pin::check(target, &service.info)? {
        Some(statement) => statement
            .authorities
            .into_iter()
            .map(|authority| Authority {
                name: authority.name,
                public_key: authority.public_key,
                cert_types: authority.cert_types,
                known_hosts_pattern: authority.known_hosts_pattern,
            })
            .collect(),
        None => {
            tracing::warn!(
                "no trust statement pinned for {}: using the unsigned list (run `trust pin`)",
                target.url
            );
            service
                .info
                .authorities
                .into_iter()
                .map(|(name, authority)| Authority {
                    name,
                    public_key: authority.public_key,
                    cert_types: authority.cert_types,
                    known_hosts_pattern: authority.known_hosts_pattern,
                })
                .collect()
        }
    };
    let (kind, kind_name) = match args.kind {
        Kind::User => (CertType::User, "user"),
        Kind::Host => (CertType::Host, "host"),
    };
    let lines = lines(&authorities, kind, args.hosts.as_deref());
    if lines.is_empty() {
        bail!("the service has no authority for {kind_name} certificates");
    }
    let content = lines.join("\n") + "\n";
    let Some(output) = &args.output else {
        return Ok(Some(content));
    };
    if std::fs::read_to_string(output).is_ok_and(|existing| existing == content) {
        return Ok(None);
    }
    write_atomically(output, &content)?;
    if let Some(command) = &args.on_change {
        run_on_change(command)?;
    }
    Ok(Some(format!("updated {}\n", output.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_hosts_and_trusted_user_ca_lines() {
        let authorities = [
            Authority {
                name: "users".into(),
                public_key: "ssh-ed25519 AAAAuser comment".into(),
                cert_types: vec![CertType::User],
                known_hosts_pattern: None,
            },
            Authority {
                name: "hosts".into(),
                public_key: "ssh-ed25519 AAAAhost".into(),
                cert_types: vec![CertType::Host],
                known_hosts_pattern: Some("*.example.com".into()),
            },
        ];
        assert_eq!(
            lines(&authorities, CertType::User, None),
            ["ssh-ed25519 AAAAuser users"]
        );
        assert_eq!(
            lines(&authorities, CertType::Host, None),
            ["@cert-authority *.example.com ssh-ed25519 AAAAhost hosts"]
        );
        assert_eq!(
            lines(
                &authorities,
                CertType::Host,
                Some("*.prod.example.com,10.0.0.*")
            ),
            ["@cert-authority *.prod.example.com,10.0.0.* ssh-ed25519 AAAAhost hosts"]
        );
    }
}
