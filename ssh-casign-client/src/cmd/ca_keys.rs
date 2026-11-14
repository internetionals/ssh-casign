//! `ca-keys`: the service's CA public keys, ready for sshd's
//! `TrustedUserCAKeys` file (user authorities) or for `known_hosts` as
//! `@cert-authority` lines (host authorities). Needs no sign-in.

use color_eyre::eyre::bail;
use ssh_casign_proto::CertType;

use super::request::discover_service;

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
    #[arg(long, default_value = "*")]
    hosts: String,
}

/// One line per authority that signs `kind`; the comment is the authority's
/// name.
fn lines(info: &ssh_casign_proto::ServiceInfo, kind: CertType, hosts: &str) -> Vec<String> {
    info.authorities
        .iter()
        .filter(|(_, authority)| authority.cert_types.contains(&kind))
        .map(|(name, authority)| {
            // Drop the key's own comment; name the authority instead.
            let key: Vec<&str> = authority.public_key.split_whitespace().take(2).collect();
            let key = key.join(" ");
            match kind {
                CertType::User => format!("{key} {name}"),
                CertType::Host => format!("@cert-authority {hosts} {key} {name}"),
            }
        })
        .collect()
}

pub(super) fn run(args: &Args, target: &super::Target) -> super::CmdResult {
    if args.hosts.chars().any(char::is_whitespace) {
        bail!("--hosts must not contain whitespace (separate patterns with commas)");
    }
    let service = discover_service(target)?;
    let kind = match args.kind {
        Kind::User => CertType::User,
        Kind::Host => CertType::Host,
    };
    let lines = lines(&service.info, kind, &args.hosts);
    if lines.is_empty() {
        let kind = match args.kind {
            Kind::User => "user",
            Kind::Host => "host",
        };
        bail!("the service has no authority for {kind} certificates");
    }
    Ok(Some(lines.join("\n") + "\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_casign_proto::{AuthorityInfo, ServiceInfo};

    #[test]
    fn known_hosts_and_trusted_user_ca_lines() {
        let authority = |key: &str, cert_types| AuthorityInfo {
            public_key: key.to_string(),
            cert_types,
            signature_algorithms: vec![],
        };
        let info = ServiceInfo {
            issuer: "https://idp".into(),
            client_id: "c".into(),
            scopes: vec![],
            sign_endpoint: "../sign".into(),
            revocation_list: None,
            authorities: [
                (
                    "users".to_string(),
                    authority("ssh-ed25519 AAAAuser comment", vec![CertType::User]),
                ),
                (
                    "hosts".to_string(),
                    authority("ssh-ed25519 AAAAhost", vec![CertType::Host]),
                ),
            ]
            .into(),
        };
        assert_eq!(
            lines(&info, CertType::User, "*"),
            ["ssh-ed25519 AAAAuser users"]
        );
        assert_eq!(
            lines(&info, CertType::Host, "*.example.com,10.0.0.*"),
            ["@cert-authority *.example.com,10.0.0.* ssh-ed25519 AAAAhost hosts"]
        );
    }
}
