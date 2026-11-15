//! `[key_checks]`: refusing obviously weak keys (see
//! `ssh_casign_ca::keycheck`), for client keys when signing and for the CA
//! keys at startup, and noticing one key certified for several owners.
//!
//! ```toml
//! [key_checks]
//! builtin = true                       # default: ROCA, Fermat, RSA sanity, curve points
//! blocklists = ["/etc/ssh-casign/blocklist.txt"]
//! duplicates = "warn"                  # allow, warn (default) or deny; needs the issuance index
//! ```

use std::path::PathBuf;

use serde::Deserialize;
use ssh_casign_ca::keycheck::{Blocklist, KeyChecks};

fn default_true() -> bool {
    true
}

/// What to do when a key is already certified for another owner.
#[derive(Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Duplicates {
    Allow,
    /// Log and audit it, and issue anyway.
    #[default]
    Warn,
    Deny,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    #[serde(default = "default_true")]
    builtin: bool,
    #[serde(default)]
    blocklists: Vec<PathBuf>,
    #[serde(default)]
    pub(crate) duplicates: Duplicates,
}

impl Config {
    pub(crate) fn load(&self) -> Result<KeyChecks, String> {
        let mut blocklists = Vec::new();
        for path in &self.blocklists {
            let list = Blocklist::load(path).map_err(|err| format!("key_checks: {err}"))?;
            tracing::info!("key blocklist {}: {} entries", path.display(), list.len());
            blocklists.push(list);
        }
        if !self.builtin {
            tracing::warn!("key_checks.builtin = false: weak client keys are not detected");
        }
        Ok(KeyChecks {
            builtin: self.builtin,
            blocklists,
        })
    }
}

/// The checks for a config without `[key_checks]`.
pub(crate) fn defaults() -> Config {
    Config {
        builtin: true,
        ..Config::default()
    }
}

/// Refuse to run with a weak or blocklisted CA key.
pub(crate) fn check_authorities(
    checks: &KeyChecks,
    authorities: &ssh_casign_ca::Authorities,
) -> Result<(), String> {
    for (name, authority) in authorities {
        if let Err(weakness) = checks.check(authority.public_key().key_data()) {
            return Err(format!("authority {name}: {weakness}"));
        }
    }
    Ok(())
}
