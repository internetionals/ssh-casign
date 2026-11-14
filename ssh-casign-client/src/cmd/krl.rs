//! `krl`: fetch the service's KRL (OpenSSH key revocation list) into a file,
//! for sshd's `RevokedKeys` (revoked user certificates and keys) and ssh's
//! `RevokedHostKeys` (revoked host certificates). Needs no sign-in.
//!
//! Meant for a timer: the file is only replaced when the list changed, and
//! a failed download leaves the old file in place.

use std::path::PathBuf;

use color_eyre::eyre::{bail, eyre, WrapErr};

use super::{
    host::{run_on_change, write_atomically},
    request::runtime,
};
use crate::{discovery, error::Result};

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

async fn fetch(target: &super::Target) -> Result<Vec<u8>> {
    let http = reqwest::Client::new();
    let service = discovery::discover(&http, &target.url).await?;
    let url = service
        .revocation_list
        .ok_or_else(|| eyre!("the service doesn't publish a revocation list"))?;
    let krl = http
        .get(url.clone())
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .wrap_err_with(|| format!("Failed to fetch {url}"))?
        .bytes()
        .await
        .wrap_err_with(|| format!("Failed to fetch {url}"))?;
    if !krl.starts_with(KRL_MAGIC) {
        bail!("{url} is not a KRL");
    }
    Ok(krl.to_vec())
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
