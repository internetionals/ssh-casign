//! `logout`: forget the cached sign-in for the service's IdP, and remove the
//! keys `login` added to ssh-agent for this service.

use super::{
    login::comment_app_name,
    request::{discover_service, service_authorities, stored_token},
};
use crate::agent;

#[derive(clap::Args, Clone, Debug)]
pub(super) struct Args {
    /// Keep the keys in ssh-agent; only forget the cached sign-in
    #[arg(long)]
    keep_agent: bool,
}

pub(super) fn run(args: &Args, target: &super::Target) -> super::CmdResult {
    let service = discover_service(target)?;
    let mut report = String::new();

    let forgot = stored_token(target, &service).delete()?;
    report.push_str(&if forgot {
        format!("Forgot the sign-in at {}\n", service.info.issuer)
    } else {
        format!("No cached sign-in for {}\n", service.info.issuer)
    });

    if !args.keep_agent {
        let removed = remove_login_identities(&service_authorities(&service)?)?;
        report.push_str(&format!("Removed {removed} key(s) from ssh-agent\n"));
    }
    Ok(Some(report))
}

/// Remove agent identities that `login` added with a certificate from one of
/// these authorities. Other keys in the agent are left alone.
fn remove_login_identities(
    authorities: &[ssh_key::public::KeyData],
) -> crate::error::Result<usize> {
    let identities = match agent::list_identities() {
        Ok(identities) => identities,
        Err(err) => {
            tracing::debug!("not removing keys from ssh-agent: {err:#}");
            return Ok(0);
        }
    };
    let mut removed = 0;
    for identity in identities {
        let ours = comment_app_name(&identity.comment).is_some()
            && identity.certificate().is_some_and(|certificate| {
                authorities.contains(certificate.view().signature_key())
            });
        if ours {
            agent::remove_identity(&identity.key_blob)?;
            removed += 1;
        }
    }
    Ok(removed)
}
