//! Request options shared by `cert` and `login`, and the sequence that turns
//! a sign request into a certificate: discover the service, sign in, sign.

use std::collections::BTreeMap;

use color_eyre::eyre::WrapErr;
use ssh_casign_proto::{CertType, SignKeyRequest};
use ssh_key::{public::KeyData, Certificate, PublicKey};

use crate::{auth, discovery, error::Result, sign, token_store::StoredToken};

/// Application name when none is configured.
const DEFAULT_APP_NAME: &str = "ssh-casign-client";

#[derive(clap::Args, Clone, Debug)]
pub(super) struct RequestArgs {
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
pub(super) fn parse_duration(input: &str) -> std::result::Result<u64, String> {
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

impl RequestArgs {
    /// True when nothing specific is requested (the application name aside),
    /// so any valid certificate from the service will do.
    pub(super) fn is_plain(&self) -> bool {
        self.validity.is_none()
            && self.principals.is_empty()
            && self.extensions.is_empty()
            && !self.no_extensions
            && self.critical_options.is_empty()
            && !self.no_critical_options
            && self.comment.is_none()
    }

    /// The application name: command line/environment, then config, then
    /// the default.
    pub(super) fn app_name(&self, target: &super::Target) -> String {
        self.app_name
            .clone()
            .or_else(|| target.app_name.clone())
            .unwrap_or_else(|| DEFAULT_APP_NAME.to_string())
    }

    pub(super) fn sign_key_request(
        &self,
        public_key: &ssh_key::PublicKey,
        cert_type: CertType,
        target: &super::Target,
    ) -> Result<SignKeyRequest> {
        Ok(SignKeyRequest {
            public_key: public_key.to_openssh()?,
            cert_type,
            validity: self.validity,
            principals: (!self.principals.is_empty()).then(|| self.principals.clone()),
            extensions: requested_map(&self.extensions, self.no_extensions),
            critical_options: requested_map(&self.critical_options, self.no_critical_options),
            app_name: Some(self.app_name(target)),
            comment: self.comment.clone(),
        })
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .wrap_err("Failed to create tokio runtime")
}

/// The service's discovery document (no sign-in needed).
pub(super) fn discover_service(target: &super::Target) -> Result<discovery::Service> {
    runtime()?.block_on(discovery::discover(&reqwest::Client::new(), &target.url))
}

/// Public keys of the service's signing authorities.
pub(super) fn service_authorities(service: &discovery::Service) -> Result<Vec<KeyData>> {
    service
        .info
        .authorities
        .values()
        .map(|authority| {
            Ok(PublicKey::from_openssh(&authority.public_key)
                .wrap_err("Invalid CA public key in service discovery document")?
                .key_data()
                .clone())
        })
        .collect()
}

/// Where the refresh token for this service's IdP is kept.
pub(super) fn stored_token(target: &super::Target, service: &discovery::Service) -> StoredToken {
    StoredToken::new(
        target.token_store,
        &service.info.issuer,
        target.client_id.as_ref().unwrap_or(&service.info.client_id),
    )
}

/// Discover the service, sign in and request the certificate.
///
/// If the service rejects a token obtained with a cached refresh token, the
/// cache is dropped and the user signs in interactively once.
pub(super) fn obtain_certificate(
    target: &super::Target,
    sign_key_request: &SignKeyRequest,
) -> Result<Certificate> {
    runtime()?.block_on(async {
        let http = reqwest::Client::new();
        let service = discovery::discover(&http, &target.url).await?;
        let stored = stored_token(target, &service);
        let request = auth::SignInRequest {
            method: target.sign_in,
            issuer: &service.info.issuer,
            client_id: target.client_id.as_ref().unwrap_or(&service.info.client_id),
            scopes: target.scopes.as_ref().unwrap_or(&service.info.scopes),
        };
        let (token, source) = auth::sign_in(&http, &request, &stored, true).await?;
        match sign::sign(&http, &service.sign_endpoint, &token, sign_key_request).await {
            Err(err)
                if source == auth::TokenSource::Refreshed
                    && err.downcast_ref::<sign::Unauthorized>().is_some() =>
            {
                tracing::info!("the service rejected the refreshed token, signing in again: {err}");
                if let Err(err) = stored.delete() {
                    tracing::warn!("can't remove the cached refresh token: {err:#}");
                }
                let (token, _) = auth::sign_in(&http, &request, &stored, false).await?;
                sign::sign(&http, &service.sign_endpoint, &token, sign_key_request).await
            }
            result => result,
        }
    })
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
}
