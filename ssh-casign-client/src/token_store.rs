//! Storage for refresh tokens, so a new certificate needs no browser or
//! device code while the IdP session lasts.
//!
//! Tokens are stored per IdP issuer and client ID:
//!
//! - `keyring` (default): the OS credential store (macOS Keychain, Windows
//!   Credential Manager, Linux kernel keyring; on Linux it lasts until the
//!   session ends or the machine reboots).
//! - `file`: `refresh-tokens.json` in the cache directory
//!   (`$SSH_CASIGN_CACHE_DIR`, else e.g. `~/Library/Caches/ssh-casign-client`
//!   or `~/.cache/ssh-casign-client`), readable only by the user.
//! - `none`: don't store refresh tokens.
//!
//! Failing to store a token is never fatal: the next run signs in again.

use std::{collections::BTreeMap, path::PathBuf};

use color_eyre::eyre::WrapErr;
use serde::Deserialize;

use crate::error::Result;

/// Service name in the OS credential store.
const KEYRING_SERVICE: &str = "ssh-casign-client";
const CACHE_DIR_ENV: &str = "SSH_CASIGN_CACHE_DIR";
const TOKEN_FILE: &str = "refresh-tokens.json";

#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TokenStore {
    /// The OS credential store
    #[default]
    Keyring,
    /// A file only the user can read, in the cache directory
    File,
    /// Don't store refresh tokens
    None,
}

/// Where a refresh token for one IdP and client is kept.
pub(crate) struct StoredToken {
    store: TokenStore,
    account: String,
}

impl StoredToken {
    pub(crate) fn new(store: TokenStore, issuer: &str, client_id: &str) -> Self {
        Self {
            store,
            account: format!("{client_id}@{issuer}"),
        }
    }

    pub(crate) fn load(&self) -> Option<String> {
        let result = match self.store {
            TokenStore::Keyring => {
                self.keyring_entry()
                    .and_then(|entry| match entry.get_password() {
                        Ok(token) => Ok(Some(token)),
                        Err(keyring::Error::NoEntry) => Ok(None),
                        Err(err) => Err(err.into()),
                    })
            }
            TokenStore::File => read_file().map(|mut tokens| tokens.remove(&self.account)),
            TokenStore::None => Ok(None),
        };
        result.unwrap_or_else(|err| {
            tracing::warn!("can't read the cached refresh token: {err:#}");
            None
        })
    }

    pub(crate) fn save(&self, token: &str) {
        let result = match self.store {
            TokenStore::Keyring => self
                .keyring_entry()
                .and_then(|entry| Ok(entry.set_password(token)?)),
            TokenStore::File => read_file().and_then(|mut tokens| {
                tokens.insert(self.account.clone(), token.to_string());
                write_file(&tokens)
            }),
            TokenStore::None => Ok(()),
        };
        if let Err(err) = result {
            tracing::warn!("can't cache the refresh token: {err:#}");
        }
    }

    /// Forget the token; returns whether there was one.
    pub(crate) fn delete(&self) -> Result<bool> {
        match self.store {
            TokenStore::Keyring => match self.keyring_entry()?.delete_credential() {
                Ok(()) => Ok(true),
                Err(keyring::Error::NoEntry) => Ok(false),
                Err(err) => Err(err.into()),
            },
            TokenStore::File => {
                let mut tokens = read_file()?;
                let existed = tokens.remove(&self.account).is_some();
                if existed {
                    write_file(&tokens)?;
                }
                Ok(existed)
            }
            TokenStore::None => Ok(false),
        }
    }

    fn keyring_entry(&self) -> Result<keyring::Entry> {
        Ok(keyring::Entry::new(KEYRING_SERVICE, &self.account)?)
    }
}

fn cache_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(CACHE_DIR_ENV).filter(|dir| !dir.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    dirs::cache_dir()
        .map(|dir| dir.join("ssh-casign-client"))
        .ok_or_else(|| color_eyre::eyre::eyre!("No cache directory; set {CACHE_DIR_ENV}"))
}

fn read_file() -> Result<BTreeMap<String, String>> {
    let path = cache_dir()?.join(TOKEN_FILE);
    match std::fs::read_to_string(&path) {
        Ok(data) => serde_json::from_str(&data)
            .wrap_err_with(|| format!("Invalid token cache {}", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(err) => Err(err).wrap_err_with(|| format!("Failed to read {}", path.display())),
    }
}

/// Write the tokens to a new file only the user can read, then move it into
/// place, so a crash never leaves a truncated or world-readable file.
fn write_file(tokens: &BTreeMap<String, String>) -> Result<()> {
    use std::io::Write;

    let dir = cache_dir()?;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(&dir)
        .wrap_err_with(|| format!("Failed to create {}", dir.display()))?;

    let path = dir.join(TOKEN_FILE);
    let temporary = dir.join(format!("{TOKEN_FILE}.{}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let result = options
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(serde_json::to_string_pretty(tokens)?.as_bytes())?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&temporary, &path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.wrap_err_with(|| format!("Failed to write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// File store tests share the process environment, so they run as one.
    #[test]
    fn file_store_roundtrip_and_permissions() {
        let dir = std::env::temp_dir().join(format!("ssh-casign-test-{}", std::process::id()));
        std::env::set_var(CACHE_DIR_ENV, &dir);

        let a = StoredToken::new(TokenStore::File, "https://idp.example.com", "cli");
        let b = StoredToken::new(TokenStore::File, "https://other.example.com", "cli");
        assert_eq!(a.load(), None);
        a.save("token-a");
        b.save("token-b");
        assert_eq!(a.load().as_deref(), Some("token-a"));
        a.save("token-a2");
        assert_eq!(a.load().as_deref(), Some("token-a2"));
        assert!(a.delete().unwrap());
        assert!(!a.delete().unwrap());
        assert_eq!(a.load(), None);
        assert_eq!(b.load().as_deref(), Some("token-b"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(TOKEN_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let none = StoredToken::new(TokenStore::None, "https://idp.example.com", "cli");
        none.save("ignored");
        assert_eq!(none.load(), None);

        std::env::remove_var(CACHE_DIR_ENV);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
