//! The signed trust statement in the discovery document (see
//! `ssh_casign_proto::trust`): which authorities servers and clients should
//! trust, and who must sign changes.
//!
//! Two modes:
//!
//! - **Automatic** (default): the service builds the statement from its
//!   authorities and signs it with all of them. The signers are the
//!   authorities that still sign (not retired), and all of them must sign the
//!   next statement. This protects against forgery on the way (DNS, TLS
//!   interception, a CDN), not against someone who controls the service or
//!   its configuration: the service signs whatever it is configured with.
//! - **Offline**: the statement is a file (`statement`), signed outside the
//!   service by trust keys the service doesn't have (`signatures`, e.g. 2 of
//!   3 administrators' YubiKeys with `ssh-keygen -Y sign`). A change of the
//!   authorities then needs those people. The service checks that the file
//!   matches its configuration.
//!
//! In both modes the service adds signatures by all its authorities,
//! retired ones included: clients pinned to an automatic statement (or
//! following a CA rotation) need them to accept the next one.

use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use ssh_casign_ca::Authorities;
use ssh_casign_proto::trust::{
    self, split_signatures, SignedTrust, Signers, TrustStatement, TrustedAuthority, TRUST_NAMESPACE,
};

const DEFAULT_ID: &str = "ssh-casign";
const DEFAULT_VALIDITY: u64 = 90 * 86_400;
/// Warn when an offline statement expires within this time.
const EXPIRY_WARNING: u64 = 30 * 86_400;

/// `[trust]` in the service config.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// Automatic mode: the trust domain's name, the same on every instance.
    id: Option<String>,
    /// Automatic mode: increase it whenever the authorities change.
    version: Option<u64>,
    /// Automatic mode: how long a statement is valid, in seconds (re-signed
    /// at half of it).
    validity: Option<u64>,
    /// Offline mode: the statement (TOML).
    statement: Option<PathBuf>,
    /// Offline mode: files with the trust keys' signatures over it.
    #[serde(default)]
    signatures: Vec<PathBuf>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn public_key(authority: &ssh_casign_ca::Authority) -> Result<String, String> {
    let text = authority
        .public_key()
        .to_openssh()
        .map_err(|err| err.to_string())?;
    trust::normalize_key(&text)
}

/// The authorities as the statement lists them.
fn trusted_authorities(authorities: &Authorities) -> Result<Vec<TrustedAuthority>, String> {
    authorities
        .iter()
        .map(|(name, authority)| {
            Ok(TrustedAuthority {
                name: name.to_string(),
                public_key: public_key(authority)?,
                cert_types: authority.cert_types().to_vec(),
                known_hosts_pattern: authority.known_hosts_pattern().map(str::to_string),
                retired: authority.retired(),
            })
        })
        .collect()
}

/// Signatures over `statement` by every authority.
async fn sign_with_authorities(
    statement: &str,
    authorities: &Authorities,
) -> Result<Vec<String>, String> {
    let mut names: Vec<_> = authorities.keys().collect();
    names.sort();
    let mut signatures = Vec::new();
    for name in names {
        let signature = authorities[name]
            .sign_sshsig(TRUST_NAMESPACE, statement.as_bytes())
            .await
            .map_err(|err| format!("trust statement: authority {name} can't sign: {err}"))?;
        signatures.push(signature);
    }
    Ok(signatures)
}

enum Mode {
    Automatic {
        id: String,
        version: u64,
        validity: u64,
    },
    Offline {
        statement: TrustStatement,
        signatures: Vec<String>,
    },
}

/// The current signed statement.
pub(crate) struct Trust {
    current: RwLock<(SignedTrust, u64)>,
}

impl Trust {
    pub(crate) async fn start(
        config: Option<&Config>,
        authorities: &Authorities,
    ) -> Result<Arc<Self>, String> {
        let default = Config::default();
        let config = config.unwrap_or(&default);
        let mode = Self::mode(config)?;
        let (signed, expires) = Self::build(&mode, authorities).await?;
        match &mode {
            Mode::Automatic { id, version, .. } => tracing::info!(
                "trust statement {id} version {version}, signed by the {} authorities",
                authorities.len()
            ),
            Mode::Offline { statement, .. } => {
                tracing::info!(
                    "trust statement {} version {} from {}, signers {} of {}",
                    statement.id,
                    statement.version,
                    config
                        .statement
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                    statement.signers.threshold,
                    statement.signers.keys.len()
                );
                let left = statement.expires.saturating_sub(now());
                if left < EXPIRY_WARNING {
                    tracing::warn!(
                        "the trust statement expires in {} days; sign a new one",
                        left / 86_400
                    );
                }
            }
        }
        let trust = Arc::new(Self {
            current: RwLock::new((signed, expires)),
        });
        if let Mode::Automatic { validity, .. } = mode {
            // Re-sign when half the validity has passed.
            let weak = Arc::downgrade(&trust);
            let authorities = authorities.clone();
            tokio::spawn(async move {
                let mut timer = tokio::time::interval(Duration::from_secs(3600));
                loop {
                    timer.tick().await;
                    let Some(trust) = weak.upgrade() else {
                        return;
                    };
                    let expires = trust.current.read().unwrap_or_else(|e| e.into_inner()).1;
                    if expires.saturating_sub(now()) > validity / 2 {
                        continue;
                    }
                    match Self::build(&mode, &authorities).await {
                        Ok(current) => {
                            *trust.current.write().unwrap_or_else(|e| e.into_inner()) = current;
                            tracing::info!("trust statement re-signed");
                        }
                        Err(err) => tracing::error!("trust statement not re-signed: {err}"),
                    }
                }
            });
        }
        Ok(trust)
    }

    fn mode(config: &Config) -> Result<Mode, String> {
        let Some(path) = &config.statement else {
            if !config.signatures.is_empty() {
                return Err("trust: signatures without statement".into());
            }
            let validity = config.validity.unwrap_or(DEFAULT_VALIDITY);
            if validity < 2 * 3600 {
                return Err("trust: validity must be at least two hours".into());
            }
            return Ok(Mode::Automatic {
                id: config.id.clone().unwrap_or_else(|| DEFAULT_ID.to_string()),
                version: config.version.unwrap_or(1),
                validity,
            });
        };
        if config.id.is_some() || config.version.is_some() || config.validity.is_some() {
            return Err(
                "trust: id, version and validity come from the statement file in offline mode"
                    .into(),
            );
        }
        let describe = |path: &PathBuf, err: &dyn std::fmt::Display| {
            format!("trust: {}: {err}", path.display())
        };
        let text = std::fs::read_to_string(path).map_err(|err| describe(path, &err))?;
        let statement = trust::statement_from_toml(&text).map_err(|err| describe(path, &err))?;
        let mut signatures = Vec::new();
        for file in &config.signatures {
            let text = std::fs::read_to_string(file).map_err(|err| describe(file, &err))?;
            signatures.extend(split_signatures(&text));
        }
        Ok(Mode::Offline {
            statement,
            signatures,
        })
    }

    async fn build(mode: &Mode, authorities: &Authorities) -> Result<(SignedTrust, u64), String> {
        match mode {
            Mode::Automatic {
                id,
                version,
                validity,
            } => {
                let mut keys = Vec::new();
                for authority in authorities.values().filter(|a| !a.retired()) {
                    keys.push(public_key(authority)?);
                }
                if keys.is_empty() {
                    return Err("trust: no authority that isn't retired".into());
                }
                let threshold = keys.len();
                let statement = TrustStatement {
                    id: id.clone(),
                    version: *version,
                    expires: now() + validity,
                    authorities: trusted_authorities(authorities)?,
                    signers: Signers { keys, threshold },
                }
                .normalized()?;
                let canonical = statement.canonical();
                let signatures = sign_with_authorities(&canonical, authorities).await?;
                Ok((
                    SignedTrust {
                        statement: canonical,
                        signatures,
                    },
                    statement.expires,
                ))
            }
            Mode::Offline {
                statement,
                signatures,
            } => {
                check_matches_config(statement, authorities)?;
                let canonical = statement.canonical();
                let mut signed = SignedTrust {
                    statement: canonical,
                    signatures: signatures.clone(),
                };
                // The trust keys' own threshold must already be met.
                trust::verify(&signed, None, now()).map_err(|err| {
                    format!("trust: the statement file isn't validly signed: {err}")
                })?;
                signed
                    .signatures
                    .extend(sign_with_authorities(&signed.statement, authorities).await?);
                Ok((signed, statement.expires))
            }
        }
    }

    /// The trust domain's name (for proofs of possession).
    pub(crate) fn id(&self) -> String {
        serde_json::from_str::<TrustStatement>(&self.current().statement)
            .map(|statement| statement.id)
            .unwrap_or_default()
    }

    pub(crate) fn current(&self) -> SignedTrust {
        self.current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .0
            .clone()
    }
}

/// An offline statement must list exactly the authorities that sign
/// (same names and keys, not retired), so servers trust what the service
/// actually uses. Configured retired authorities should be listed too.
fn check_matches_config(
    statement: &TrustStatement,
    authorities: &Authorities,
) -> Result<(), String> {
    for (name, authority) in authorities {
        let key = public_key(authority)?;
        let listed = statement
            .authorities
            .iter()
            .find(|listed| listed.name == name.as_ref());
        match listed {
            Some(listed) if listed.public_key != key => {
                return Err(format!(
                    "trust: authority {name} has another key in the statement file"
                ))
            }
            Some(listed) if listed.retired && !authority.retired() => {
                return Err(format!(
                    "trust: authority {name} is retired in the statement file but not in the \
                     config"
                ))
            }
            Some(_) => {}
            None if authority.retired() => tracing::warn!(
                "trust: retired authority {name} is not in the statement file; servers that \
                 refresh will stop trusting its certificates"
            ),
            None => {
                return Err(format!(
                    "trust: authority {name} is not in the statement file; get a new statement \
                     signed before using it"
                ))
            }
        }
    }
    for listed in statement
        .authorities
        .iter()
        .filter(|listed| !listed.retired)
    {
        if !authorities.contains_key(listed.name.as_str()) {
            return Err(format!(
                "trust: the statement file lists authority {}, which isn't configured",
                listed.name
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{private::Ed25519Keypair, HashAlg, LineEnding, PrivateKey};

    fn trust_key(seed: u8) -> PrivateKey {
        PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
    }

    fn openssh(key: &PrivateKey) -> String {
        key.public_key().to_openssh().unwrap()
    }

    #[tokio::test]
    async fn automatic_statement_is_signed_by_all_authorities() {
        let authorities = ssh_casign_ca::testing::authorities(&["users", "hosts"]);
        let trust = Trust::start(None, &authorities).await.unwrap();
        let signed = trust.current();
        let verified = trust::verify(&signed, None, now()).unwrap();
        assert_eq!(verified.statement.id, "ssh-casign");
        assert_eq!(verified.statement.authorities.len(), 2);
        assert_eq!(verified.statement.signers.threshold, 2);
        assert_eq!(verified.signed_by.len(), 2);
        assert!(verified.statement.expires > now() + 89 * 86_400);
    }

    fn write(dir: &std::path::Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[tokio::test]
    async fn offline_statement_two_of_three() {
        let dir = std::env::temp_dir().join(format!("ssh-casign-trust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let authorities = ssh_casign_ca::testing::authorities(&["users"]);
        let users = openssh(&PrivateKey::from(ssh_casign_ca::testing::authority_key(0)));
        let spec = format!(
            "id = \"example\"\nversion = 3\nexpires = 2099-01-01\n\
             [signers]\nthreshold = 2\nkeys = [\"{}\", \"{}\", \"{}\"]\n\
             [[authorities]]\nname = \"users\"\npublic_key = \"{users}\"\ncert_types = [\"user\"]\n",
            openssh(&trust_key(1)),
            openssh(&trust_key(2)),
            openssh(&trust_key(3)),
        );
        let statement_file = write(&dir, "trust.toml", &spec);
        let canonical = trust::statement_from_toml(&spec).unwrap().canonical();
        let sig = |seed: u8| {
            trust_key(seed)
                .sign(TRUST_NAMESPACE, HashAlg::Sha512, canonical.as_bytes())
                .unwrap()
                .to_pem(LineEnding::LF)
                .unwrap()
        };
        let one = write(&dir, "1.sig", &sig(1));
        let three = write(&dir, "3.sig", &sig(3));
        let config = |signatures: Vec<PathBuf>| Config {
            statement: Some(statement_file.clone()),
            signatures,
            ..Config::default()
        };
        // One trust key isn't enough.
        let err = Trust::start(Some(&config(vec![one.clone()])), &authorities)
            .await
            .err()
            .unwrap();
        assert!(err.contains("isn't validly signed"), "{err}");
        let trust = Trust::start(Some(&config(vec![one, three])), &authorities)
            .await
            .unwrap();
        let signed = trust.current();
        let verified = trust::verify(&signed, None, now()).unwrap();
        assert_eq!(verified.statement.version, 3);
        // Two trust keys and the authority.
        assert_eq!(verified.signed_by.len(), 3);
        // An authority missing from the statement stops the service.
        let more = ssh_casign_ca::testing::authorities(&["users", "extra"]);
        let err = Trust::start(Some(&config(vec![])), &more)
            .await
            .err()
            .unwrap();
        assert!(err.contains("extra"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
