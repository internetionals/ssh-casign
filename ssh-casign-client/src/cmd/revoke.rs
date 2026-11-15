//! `revoke` and `certificates`: the service's revocation API.
//!
//! - `revoke --key ~/.ssh/id_ed25519`: revoke a key you hold (proof of
//!   possession, no sign-in).
//! - `revoke --all`, `--serial N --authority A`, `--certificate FILE`:
//!   revoke your own certificates (signed in).
//! - Administrators: also `--key-id`, `--fingerprint`, and `--where
//!   FIELD=VALUE` to revoke everything a search of the issuance index
//!   matches.
//! - `certificates`: your unexpired certificates; administrators can search
//!   everyone's with `--where`.

use std::{io::Write, path::PathBuf, process::Stdio};

use color_eyre::eyre::{bail, eyre, WrapErr};
use ssh_casign_proto::{
    revoke::{
        possession_message, CertificateFilter, CertificatesResponse, Possession, RevokeRequest,
        RevokeResponse, POSSESSION_NAMESPACE,
    },
    trust, ErrorResponse,
};

use super::request::{runtime, sign_in_request, stored_token};
use crate::{auth, discovery, error::Result, trust_pin::format_date};

/// `FIELD=VALUE` for a [`CertificateFilter`].
fn parse_where(input: &str) -> std::result::Result<(String, String), String> {
    let (field, value) = input
        .split_once('=')
        .ok_or_else(|| format!("'{input}' is not FIELD=VALUE"))?;
    Ok((field.trim().to_string(), value.trim().to_string()))
}

fn filter(conditions: &[(String, String)]) -> Result<CertificateFilter> {
    let map: serde_json::Map<String, serde_json::Value> = conditions
        .iter()
        .map(|(field, value)| (field.clone(), serde_json::Value::String(value.clone())))
        .collect();
    serde_json::from_value(serde_json::Value::Object(map)).map_err(|err| {
        eyre!(
            "{err} (fields: owner_issuer, owner_id, principal, fingerprint, key_id, profile, \
             authority, app_name, client_address)"
        )
    })
}

#[derive(clap::Args, Clone, Debug)]
pub(super) struct RevokeArgs {
    /// Revoke the key in this file (private key, or .pub for a key in
    /// ssh-agent) by proving you hold it; no sign-in
    #[arg(long, value_name = "FILE")]
    key: Option<PathBuf>,
    /// All your unexpired certificates
    #[arg(long)]
    all: bool,
    /// A certificate by serial (with --authority)
    #[arg(long, requires = "authority")]
    serial: Option<String>,
    /// The authority of --serial (or limits --key-id to one)
    #[arg(long)]
    authority: Option<String>,
    /// A certificate file the service issued
    #[arg(long, value_name = "FILE")]
    certificate: Option<PathBuf>,
    /// Administrators: every certificate with this key ID
    #[arg(long)]
    key_id: Option<String>,
    /// Administrators: a key (SHA256:...) and all its certificates
    #[arg(long)]
    fingerprint: Option<String>,
    /// Administrators: every unexpired certificate matching FIELD=VALUE
    /// (repeatable; all must match), e.g. principal=root
    #[arg(long = "where", value_name = "FIELD=VALUE", value_parser = parse_where)]
    conditions: Vec<(String, String)>,
    /// Why (recorded with the revocation)
    #[arg(long)]
    reason: Option<String>,
}

#[derive(clap::Args, Clone, Debug)]
pub(super) struct CertificatesArgs {
    /// Administrators: search everyone's certificates by FIELD=VALUE
    /// (repeatable), e.g. client_address=203.0.113.9
    #[arg(long = "where", value_name = "FIELD=VALUE", value_parser = parse_where)]
    conditions: Vec<(String, String)>,
    /// Print JSON
    #[arg(long)]
    json: bool,
}

/// A proof of possession of the key in `file`, signed with ssh-keygen.
fn possession(file: &PathBuf, service_id: &str) -> Result<Possession> {
    let public_file = if file.extension().is_some_and(|ext| ext == "pub") {
        file.clone()
    } else {
        PathBuf::from(format!("{}.pub", file.display()))
    };
    let text = std::fs::read_to_string(&public_file)
        .wrap_err_with(|| format!("Failed to read {}", public_file.display()))?;
    let public_key = trust::normalize_key(&text).map_err(|err| eyre!(err))?;
    let time = crate::trust_pin::now();
    let message = possession_message(&public_key, service_id, time);
    let mut command = std::process::Command::new("ssh-keygen");
    command.args(["-q", "-Y", "sign", "-n", POSSESSION_NAMESPACE, "-f"]);
    command.arg(file);
    if file == &public_file {
        // The private key is in ssh-agent.
        command.arg("-U");
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .wrap_err("Failed to run ssh-keygen")?;
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(message.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!("ssh-keygen -Y sign failed ({})", output.status);
    }
    Ok(Possession {
        public_key,
        time,
        signature: String::from_utf8(output.stdout)?,
    })
}

/// The service's trust domain (what proofs of possession are bound to).
fn service_id(service: &discovery::Service) -> String {
    service
        .info
        .trust
        .as_ref()
        .and_then(|signed| serde_json::from_str::<trust::TrustStatement>(&signed.statement).ok())
        .map(|statement| statement.id)
        .unwrap_or_else(|| "ssh-casign".into())
}

fn endpoint(url: Option<&url::Url>, what: &str) -> Result<url::Url> {
    url.cloned()
        .ok_or_else(|| eyre!("the service has no {what} (it needs a [store])"))
}

async fn token(
    http: &reqwest::Client,
    target: &super::Target,
    service: &discovery::Service,
) -> Result<String> {
    let stored = stored_token(target, service);
    let request = sign_in_request(target, service);
    Ok(auth::sign_in(http, &request, &stored, true).await?.0)
}

async fn error_of(response: reqwest::Response) -> color_eyre::Report {
    let status = response.status();
    match response.json::<ErrorResponse>().await {
        Ok(error) => eyre!("{status}: {}", error.error),
        Err(_) => eyre!("{status}"),
    }
}

fn describe_revoked(response: &RevokeResponse) -> String {
    let mut out = String::new();
    for entry in &response.revoked {
        let target = match (&entry.serial, &entry.key_id, &entry.fingerprint) {
            (Some(serial), _, _) => format!(
                "serial {serial} of {}",
                entry.authority.as_deref().unwrap_or("?")
            ),
            (_, Some(key_id), _) => format!("key ID {key_id}"),
            (_, _, Some(fingerprint)) => format!("key {fingerprint}"),
            _ => "?".into(),
        };
        out += &format!("revoked {target}\n");
    }
    if response.already_revoked > 0 {
        out += &format!("{} already revoked\n", response.already_revoked);
    }
    if out.is_empty() {
        out = "nothing to revoke\n".into();
    }
    out
}

pub(super) fn revoke(args: &RevokeArgs, target: &super::Target) -> super::CmdResult {
    runtime()?.block_on(async {
        let http = reqwest::Client::new();
        let service = discovery::discover(&http, &target.url).await?;
        let url = endpoint(service.revoke_endpoint.as_ref(), "revocation API")?;
        let matching = (!args.conditions.is_empty())
            .then(|| filter(&args.conditions))
            .transpose()?;
        let certificate = args
            .certificate
            .as_ref()
            .map(|file| {
                std::fs::read_to_string(file)
                    .wrap_err_with(|| format!("Failed to read {}", file.display()))
            })
            .transpose()?;
        let mut request = RevokeRequest {
            serial: args.serial.clone(),
            authority: args.authority.clone(),
            key_id: args.key_id.clone(),
            fingerprint: args.fingerprint.clone(),
            certificate,
            all: args.all,
            matching,
            reason: args.reason.clone(),
            possession: None,
        };
        let mut post = http.post(url.clone());
        match &args.key {
            Some(key) => request.possession = Some(possession(key, &service_id(&service))?),
            None => post = post.bearer_auth(token(&http, target, &service).await?),
        }
        let response = post
            .json(&request)
            .send()
            .await
            .wrap_err_with(|| format!("Revoke request to {url} failed"))?;
        if !response.status().is_success() {
            return Err(error_of(response).await.wrap_err("Revocation refused"));
        }
        let response: RevokeResponse = response.json().await.wrap_err("Invalid response")?;
        Ok(Some(describe_revoked(&response)))
    })
}

pub(super) fn certificates(args: &CertificatesArgs, target: &super::Target) -> super::CmdResult {
    runtime()?.block_on(async {
        let http = reqwest::Client::new();
        let service = discovery::discover(&http, &target.url).await?;
        let url = endpoint(
            service.certificates_endpoint.as_ref(),
            "certificate listing",
        )?;
        let query: Vec<(String, String)> = args.conditions.clone();
        filter(&query)?; // check the fields before asking
        let response = http
            .get(url.clone())
            .query(&query)
            .bearer_auth(token(&http, target, &service).await?)
            .send()
            .await
            .wrap_err_with(|| format!("Request to {url} failed"))?;
        if !response.status().is_success() {
            return Err(error_of(response).await);
        }
        let response: CertificatesResponse = response.json().await.wrap_err("Invalid response")?;
        if args.json {
            return Ok(Some(
                serde_json::to_string_pretty(&response.certificates)? + "\n",
            ));
        }
        if response.certificates.is_empty() {
            return Ok(Some("no unexpired certificates\n".into()));
        }
        let mut out = String::new();
        for certificate in &response.certificates {
            out += &format!(
                "{} {:<20} {} until {}{}\n  key ID {}, principals {}, from {}\n",
                certificate.authority,
                certificate.serial,
                match certificate.cert_type {
                    ssh_casign_proto::CertType::User => "user",
                    ssh_casign_proto::CertType::Host => "host",
                },
                format_date(certificate.valid_before),
                if certificate.revoked { ", REVOKED" } else { "" },
                certificate.key_id,
                certificate.principals.join(","),
                certificate.client_address.as_deref().unwrap_or("?"),
            );
        }
        Ok(Some(out))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn where_conditions() {
        let conditions = [
            parse_where("principal=root").unwrap(),
            parse_where("client_address = 203.0.113.9").unwrap(),
        ];
        let filter = filter(&conditions).unwrap();
        assert_eq!(filter.principal.as_deref(), Some("root"));
        assert_eq!(filter.client_address.as_deref(), Some("203.0.113.9"));
        assert!(parse_where("principal").is_err());
        assert!(super::filter(&[("bogus".into(), "x".into())]).is_err());
    }
}
