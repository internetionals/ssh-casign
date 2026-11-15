//! `krl`: fetch the service's KRL (OpenSSH key revocation list) into a file,
//! for sshd's `RevokedKeys` (revoked user certificates and keys) and ssh's
//! `RevokedHostKeys` (revoked host certificates). Needs no sign-in.
//!
//! Meant for a timer: the file is only replaced when the list changed, and
//! a failed download leaves the old file in place. With a pinned trust
//! statement, the KRL must be signed by every authority in it that isn't
//! retired, so an emptied or replaced list (which would un-revoke
//! certificates) is refused.

use std::path::PathBuf;

use color_eyre::eyre::{bail, eyre, WrapErr};
use ssh_casign_proto::trust::{self, TrustStatement, KRL_NAMESPACE};

use super::{
    host::{run_on_change, write_atomically},
    request::runtime,
};
use crate::{discovery, error::Result, trust_pin};

const KRL_MAGIC: &[u8] = b"SSHKRL\n\0";

#[derive(clap::Args, Clone, Debug)]
pub(super) struct Args {
    /// Where to write the KRL, e.g. /etc/ssh/revoked.krl; '-' for stdout
    #[arg(short, long)]
    output: PathBuf,

    /// Command to run when the file changed
    #[arg(long)]
    on_change: Option<String>,
}

async fn get(http: &reqwest::Client, url: &url::Url) -> Result<(Vec<u8>, Option<String>)> {
    let response = http
        .get(url.clone())
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .wrap_err_with(|| format!("Failed to fetch {url}"))?;
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body = response
        .bytes()
        .await
        .wrap_err_with(|| format!("Failed to fetch {url}"))?;
    Ok((body.to_vec(), etag))
}

/// Check that every authority of `statement` that isn't retired signed
/// `krl`.
fn check_signatures(krl: &[u8], signatures: &[u8], statement: &TrustStatement) -> Result<()> {
    let text = String::from_utf8_lossy(signatures);
    let signed_by = trust::valid_signers(KRL_NAMESPACE, krl, &trust::split_signatures(&text));
    let missing: Vec<&str> = statement
        .authorities
        .iter()
        .filter(|authority| !authority.retired && !signed_by.contains(&authority.public_key))
        .map(|authority| authority.name.as_str())
        .collect();
    if !missing.is_empty() {
        bail!(
            "the KRL is not signed by authorities {}",
            missing.join(", ")
        );
    }
    Ok(())
}

async fn fetch(target: &super::Target) -> Result<Vec<u8>> {
    let http = reqwest::Client::new();
    let service = discovery::discover(&http, &target.url).await?;
    let statement = trust_pin::check(target, &service.info)?;
    let url = service
        .revocation_list
        .clone()
        .ok_or_else(|| eyre!("the service doesn't publish a revocation list"))?;
    let Some(statement) = statement else {
        tracing::warn!(
            "no trust statement pinned for {}: the KRL's signatures are not checked (run \
             `trust pin`)",
            target.url
        );
        let (krl, _) = get(&http, &url).await?;
        if !krl.starts_with(KRL_MAGIC) {
            bail!("{url} is not a KRL");
        }
        return Ok(krl);
    };
    let signatures_url = service
        .revocation_list_signatures
        .clone()
        .ok_or_else(|| eyre!("the service doesn't publish KRL signatures"))?;
    // The list can change between the two requests; then try once more.
    let mut last_error = None;
    for _ in 0..2 {
        let (krl, krl_etag) = get(&http, &url).await?;
        let (signatures, signatures_etag) = get(&http, &signatures_url).await?;
        if !krl.starts_with(KRL_MAGIC) {
            bail!("{url} is not a KRL");
        }
        match check_signatures(&krl, &signatures, &statement) {
            Ok(()) => return Ok(krl),
            Err(err) if krl_etag != signatures_etag => last_error = Some(err),
            Err(err) => return Err(err),
        }
    }
    Err(last_error.expect("set in the loop"))
}

pub(super) fn run(args: &Args, target: &super::Target) -> super::CmdResult {
    let krl = runtime()?.block_on(fetch(target))?;
    if args.output == std::path::Path::new("-") {
        use std::io::Write;
        std::io::stdout().write_all(&krl)?;
        return Ok(None);
    }
    if std::fs::read(&args.output).is_ok_and(|existing| existing == krl) {
        tracing::info!("{} is up to date", args.output.display());
        return Ok(None);
    }
    write_atomically(&args.output, &krl)?;
    tracing::info!("wrote {}", args.output.display());
    if let Some(command) = &args.on_change {
        run_on_change(command)?;
    }
    Ok(Some(format!("updated {}\n", args.output.display())))
}
