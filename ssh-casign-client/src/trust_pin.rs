//! The pinned trust statement of a service: what `ca-keys` and `krl` check
//! the service's statement against (see `ssh_casign_proto::trust`).
//!
//! The pin is the last accepted statement, kept in a file per service URL
//! (`trust_store` in the client profile, else
//! `<data dir>/ssh-casign-client/trust/<service>.json`). Every accepted newer
//! statement replaces it, so the client follows rotations step by step.

use std::path::{Path, PathBuf};

use color_eyre::eyre::{eyre, WrapErr};
use serde::{Deserialize, Serialize};
use ssh_casign_proto::{
    trust::{self, TrustStatement},
    ServiceInfo,
};

use crate::{cmd::Target, error::Result};

#[derive(Serialize, Deserialize)]
struct PinFile {
    url: String,
    /// The accepted statement, exactly as signed.
    statement: String,
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

/// The pin file for `target`.
pub(crate) fn pin_file(target: &Target) -> PathBuf {
    if let Some(path) = &target.trust_store {
        return path.clone();
    }
    let slug: String = format!(
        "{}_{}{}",
        target.url.host_str().unwrap_or("service"),
        target.url.port_or_known_default().unwrap_or(0),
        target.url.path()
    )
    .chars()
    .map(|c| {
        if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
            c
        } else {
            '_'
        }
    })
    .collect();
    dirs::data_local_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("ssh-casign-client")
        .join("trust")
        .join(format!("{}.json", slug.trim_end_matches('_')))
}

/// The pinned statement, if any (its signatures were checked when it was
/// pinned).
pub(crate) fn load(path: &Path) -> Result<Option<TrustStatement>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).wrap_err_with(|| format!("Failed to read {}", path.display())),
    };
    let file: PinFile = serde_json::from_str(&text)
        .wrap_err_with(|| format!("Invalid pin file {}", path.display()))?;
    let statement: TrustStatement = serde_json::from_str(&file.statement)
        .wrap_err_with(|| format!("Invalid pinned statement in {}", path.display()))?;
    Ok(Some(statement))
}

pub(crate) fn save(path: &Path, url: &str, statement: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .wrap_err_with(|| format!("Failed to create {}", dir.display()))?;
    }
    let content = serde_json::to_string_pretty(&PinFile {
        url: url.to_string(),
        statement: statement.to_string(),
    })?;
    crate::cmd::write_atomically(path, content + "\n")
}

/// Check the service's statement against the pin and follow it. `None`
/// when nothing is pinned for this service (nothing is verified then).
pub(crate) fn check(target: &Target, info: &ServiceInfo) -> Result<Option<TrustStatement>> {
    let path = pin_file(target);
    let Some(pinned) = load(&path)? else {
        return Ok(None);
    };
    let signed = info.trust.as_ref().ok_or_else(|| {
        eyre!(
            "the service publishes no trust statement, but one is pinned in {}",
            path.display()
        )
    })?;
    let verified = trust::verify(signed, Some(&pinned), now())
        .map_err(|err| eyre!("{err} (pinned: {})", path.display()))?;
    if verified.statement != pinned {
        if verified.statement.version != pinned.version {
            tracing::warn!(
                "trust statement {} updated from version {} to {} (signed by {})",
                verified.statement.id,
                pinned.version,
                verified.statement.version,
                verified.signed_by.join(", ")
            );
        }
        save(&path, target.url.as_str(), &signed.statement)?;
    }
    Ok(Some(verified.statement))
}

/// `YYYY-MM-DD` (UTC) for Unix time `secs`.
pub(crate) fn format_date(secs: u64) -> String {
    let days = (secs / 86_400) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    #[test]
    fn dates() {
        assert_eq!(super::format_date(0), "1970-01-01");
        assert_eq!(super::format_date(1_826_150_400), "2027-11-14");
    }
}
