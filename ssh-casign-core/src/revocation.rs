//! Revocations: the list of revoked certificates and keys, the OpenSSH KRL
//! built from it (served at `/revoked.krl` for sshd's `RevokedKeys` and ssh's
//! `RevokedHostKeys`), and the checks that keep the service from signing what
//! is revoked.
//!
//! An entry revokes one of:
//!
//! | Key                         | Revokes                                               |
//! |-----------------------------|-------------------------------------------------------|
//! | `serial` + `authority`      | the certificate with that serial from that authority  |
//! | `key_id` (+ `authority`)    | certificates with that key ID (from every authority)  |
//! | `fingerprint`/`public_key`  | a key, with every certificate for it                  |
//!
//! Entries come from a [`Source`]: today the revocation file and inline
//! entries in the config; a storage backend with a revoke API can implement
//! the same trait later.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64ct::{Base64Unpadded, Encoding as _};
use serde::Deserialize;
use sha2::Digest as _;
use ssh_casign_ca::Authorities;

/// KRL format (OpenSSH PROTOCOL.krl).
const KRL_MAGIC: &[u8; 8] = b"SSHKRL\n\0";
const KRL_FORMAT_VERSION: u32 = 1;
const KRL_SECTION_CERTIFICATES: u8 = 1;
const KRL_SECTION_FINGERPRINT_SHA256: u8 = 5;
const KRL_SECTION_CERT_SERIAL_LIST: u8 = 0x20;
const KRL_SECTION_CERT_KEY_ID: u8 = 0x23;

fn default_reload_interval() -> u64 {
    60
}

/// `[revocation]` in the service config.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// Revocation file (TOML with `[[revoked]]` entries).
    file: Option<PathBuf>,
    /// Entries in the config itself (e.g. for `SSH_CASIGN_CONFIG_TOML`).
    #[serde(default)]
    revoked: Vec<RawEntry>,
    /// How often to check the file for changes, in seconds (0: never).
    #[serde(default = "default_reload_interval")]
    reload_interval: u64,
}

/// One revocation as written in the file.
/// A serial as a TOML integer or, since TOML integers are signed 64-bit and
/// half of all random serials are larger, as a decimal string.
fn deserialize_serial<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Serial {
        Number(u64),
        Text(String),
    }
    match Option::<Serial>::deserialize(deserializer)? {
        None => Ok(None),
        Some(Serial::Number(serial)) => Ok(Some(serial)),
        Some(Serial::Text(text)) => text.trim().parse().map(Some).map_err(|_| {
            serde::de::Error::custom(format!("serial '{text}' is not a 64-bit unsigned number"))
        }),
    }
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawEntry {
    /// A number, or a quoted decimal string above 9223372036854775807.
    #[serde(default, deserialize_with = "deserialize_serial")]
    serial: Option<u64>,
    key_id: Option<String>,
    /// `SHA256:...`, as `ssh-keygen -l` and the audit log (`cs6`) show it.
    fingerprint: Option<String>,
    public_key: Option<String>,
    /// The authority (name in `[authorities]`) whose certificates are meant.
    authority: Option<String>,
    // Informational, for whoever reads the file.
    #[allow(dead_code)]
    reason: Option<String>,
    #[allow(dead_code)]
    revoked_at: Option<toml::Value>,
    #[allow(dead_code)]
    revoked_by: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(default)]
    revoked: Vec<RawEntry>,
}

/// Entries from a source, with when they last changed.
pub(crate) struct Loaded {
    pub(crate) entries: Vec<RawEntry>,
    /// Seconds since the epoch; the KRL's version and date.
    pub(crate) changed: u64,
}

/// Where revocations come from.
pub(crate) trait Source: Send + Sync {
    fn describe(&self) -> String;
    /// A cheap version check: changes whenever the entries may have.
    fn version(&self) -> Result<u64, String>;
    fn load(&self) -> Result<Loaded, String>;
}

/// The revocation file plus inline entries.
struct FileSource {
    file: Option<PathBuf>,
    inline: Vec<RawEntry>,
    /// When the inline entries were loaded (service start).
    started: u64,
}

fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

impl Source for FileSource {
    fn describe(&self) -> String {
        match &self.file {
            Some(file) => format!("revocation file {}", file.display()),
            None => "revocations in the config".into(),
        }
    }

    fn version(&self) -> Result<u64, String> {
        match &self.file {
            Some(file) => std::fs::metadata(file)
                .and_then(|metadata| metadata.modified())
                .map(|modified| unix_secs(modified).max(1))
                .map_err(|err| format!("{}: {err}", file.display())),
            None => Ok(self.started),
        }
    }

    fn load(&self) -> Result<Loaded, String> {
        let mut entries = self.inline.clone();
        let changed = self.version()?;
        if let Some(file) = &self.file {
            let describe = |err: &dyn std::fmt::Display| format!("{}: {err}", file.display());
            let text = std::fs::read_to_string(file).map_err(|err| describe(&err))?;
            let raw: RawFile = toml::from_str(&text).map_err(|err| {
                let mut message = describe(&err);
                if message.contains("number too large") {
                    message.push_str(
                        "\n(serials above 9223372036854775807 must be quoted: serial = \"...\")",
                    );
                }
                message
            })?;
            entries.extend(raw.revoked);
        }
        Ok(Loaded { entries, changed })
    }
}

/// Validated revocations and the KRL built from them.
pub(crate) struct Snapshot {
    changed: u64,
    count: usize,
    /// Revoked keys: SHA-256 of the public key blob.
    fingerprints: BTreeSet<[u8; 32]>,
    /// Per authority: revoked key IDs. (Revoked serials are only in the KRL:
    /// new serials are random, so they don't collide with them.)
    key_ids: BTreeMap<String, BTreeSet<String>>,
    krl: Arc<[u8]>,
    etag: String,
    /// SSHSIG signatures of the KRL by every authority.
    signatures: Arc<str>,
}

/// `SHA256:<base64>` to the raw hash.
fn parse_fingerprint(text: &str) -> Result<[u8; 32], String> {
    let encoded = text
        .strip_prefix("SHA256:")
        .ok_or_else(|| format!("fingerprint '{text}' is not SHA256:..."))?;
    let bytes = Base64Unpadded::decode_vec(encoded.trim_end_matches('='))
        .map_err(|_| format!("fingerprint '{text}' is not valid base64"))?;
    bytes
        .try_into()
        .map_err(|_| format!("fingerprint '{text}' is not a SHA-256 hash"))
}

fn key_hash(key: &ssh_key::PublicKey) -> Result<[u8; 32], String> {
    let blob = key.to_bytes().map_err(|err| err.to_string())?;
    Ok(sha2::Sha256::digest(blob).into())
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

fn put_section(out: &mut Vec<u8>, kind: u8, data: &[u8]) {
    out.push(kind);
    put_string(out, data);
}

impl Snapshot {
    /// Validate `entries` against the authorities and build the KRL.
    fn build(loaded: Loaded, authorities: &Authorities) -> Result<Self, String> {
        let mut fingerprints = BTreeSet::new();
        let mut serials: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
        let mut key_ids: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let all: Vec<String> = authorities.keys().map(|name| name.to_string()).collect();
        for (index, entry) in loaded.entries.iter().enumerate() {
            let context = |message: String| format!("revocation {}: {message}", index + 1);
            let what = [
                entry.serial.is_some(),
                entry.key_id.is_some(),
                entry.fingerprint.is_some(),
                entry.public_key.is_some(),
            ];
            if what.iter().filter(|set| **set).count() != 1 {
                return Err(context(
                    "set exactly one of serial, key_id, fingerprint or public_key".into(),
                ));
            }
            if let Some(authority) = &entry.authority {
                if !authorities.contains_key(authority.as_str()) {
                    return Err(context(format!("unknown authority '{authority}'")));
                }
            }
            let scope = match &entry.authority {
                Some(authority) => vec![authority.clone()],
                None => all.clone(),
            };
            if let Some(serial) = entry.serial {
                let Some(authority) = &entry.authority else {
                    return Err(context(
                        "a serial needs the authority that issued it (serials are per CA)".into(),
                    ));
                };
                if serial == 0 {
                    return Err(context("serial 0 is never issued".into()));
                }
                serials.entry(authority.clone()).or_default().insert(serial);
            }
            if let Some(key_id) = &entry.key_id {
                if key_id.is_empty() {
                    return Err(context("empty key_id".into()));
                }
                for authority in scope {
                    key_ids.entry(authority).or_default().insert(key_id.clone());
                }
            }
            if entry.authority.is_some()
                && (entry.fingerprint.is_some() || entry.public_key.is_some())
            {
                return Err(context(
                    "a revoked key is revoked for every authority; drop `authority`".into(),
                ));
            }
            if let Some(fingerprint) = &entry.fingerprint {
                fingerprints.insert(parse_fingerprint(fingerprint).map_err(context)?);
            }
            if let Some(public_key) = &entry.public_key {
                let key = ssh_key::PublicKey::from_openssh(public_key.trim())
                    .map_err(|err| context(format!("invalid public key: {err}")))?;
                fingerprints.insert(key_hash(&key).map_err(context)?);
            }
        }
        let krl = encode_krl(
            loaded.changed,
            &fingerprints,
            &serials,
            &key_ids,
            authorities,
        )?;
        let etag = format!(
            "\"{}\"",
            sha2::Sha256::digest(&krl)
                .iter()
                .take(16)
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        Ok(Self {
            changed: loaded.changed,
            count: loaded.entries.len(),
            fingerprints,
            key_ids,
            krl: krl.into(),
            etag,
            signatures: Arc::from(""),
        })
    }

    pub(crate) fn key_revoked(&self, key: &ssh_key::PublicKey) -> bool {
        key_hash(key).is_ok_and(|hash| self.fingerprints.contains(&hash))
    }

    pub(crate) fn key_id_revoked(&self, authority: &str, key_id: &str) -> bool {
        self.key_ids
            .get(authority)
            .is_some_and(|ids| ids.contains(key_id))
    }

    pub(crate) fn krl(&self) -> Arc<[u8]> {
        self.krl.clone()
    }

    /// The authorities' signatures over the KRL, concatenated.
    pub(crate) fn signatures(&self) -> Arc<str> {
        self.signatures.clone()
    }

    pub(crate) fn etag(&self) -> &str {
        &self.etag
    }
}

/// The KRL: one certificate section per authority with revocations, and a
/// SHA-256 fingerprint section for revoked keys. Lists are sorted, so equal
/// revocations give equal bytes on every instance.
fn encode_krl(
    changed: u64,
    fingerprints: &BTreeSet<[u8; 32]>,
    serials: &BTreeMap<String, BTreeSet<u64>>,
    key_ids: &BTreeMap<String, BTreeSet<String>>,
    authorities: &Authorities,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend_from_slice(KRL_MAGIC);
    put_u32(&mut out, KRL_FORMAT_VERSION);
    put_u64(&mut out, changed); // krl_version
    put_u64(&mut out, changed); // generated_date
    put_u64(&mut out, 0); // flags
    put_string(&mut out, b""); // reserved
    put_string(&mut out, b"ssh-casign");

    let names: BTreeSet<&String> = serials.keys().chain(key_ids.keys()).collect();
    for name in names {
        let authority = authorities
            .get(name.as_str())
            .ok_or_else(|| format!("unknown authority '{name}'"))?;
        let ca_key = authority
            .public_key()
            .to_bytes()
            .map_err(|err| err.to_string())?;
        let mut section = Vec::new();
        put_string(&mut section, &ca_key);
        put_string(&mut section, b""); // reserved
        if let Some(serials) = serials.get(name).filter(|serials| !serials.is_empty()) {
            let mut data = Vec::new();
            for serial in serials {
                put_u64(&mut data, *serial);
            }
            put_section(&mut section, KRL_SECTION_CERT_SERIAL_LIST, &data);
        }
        if let Some(ids) = key_ids.get(name).filter(|ids| !ids.is_empty()) {
            let mut data = Vec::new();
            for id in ids {
                put_string(&mut data, id.as_bytes());
            }
            put_section(&mut section, KRL_SECTION_CERT_KEY_ID, &data);
        }
        put_section(&mut out, KRL_SECTION_CERTIFICATES, &section);
    }
    if !fingerprints.is_empty() {
        let mut data = Vec::new();
        for hash in fingerprints {
            put_string(&mut data, hash);
        }
        put_section(&mut out, KRL_SECTION_FINGERPRINT_SHA256, &data);
    }
    Ok(out)
}

/// Build the snapshot and sign the KRL with every authority, so clients
/// can tell it from a forged or emptied list.
async fn build_signed(loaded: Loaded, authorities: &Authorities) -> Result<Snapshot, String> {
    let mut snapshot = Snapshot::build(loaded, authorities)?;
    let mut names: Vec<_> = authorities.keys().collect();
    names.sort();
    let mut signatures = String::new();
    for name in names {
        let signature = authorities[name]
            .sign_sshsig(ssh_casign_proto::trust::KRL_NAMESPACE, &snapshot.krl)
            .await
            .map_err(|err| format!("KRL: authority {name} can't sign: {err}"))?;
        signatures.push_str(&signature);
        if !signatures.ends_with('\n') {
            signatures.push('\n');
        }
    }
    snapshot.signatures = Arc::from(signatures);
    Ok(snapshot)
}

/// The current revocations, reloaded from the source in the background.
pub(crate) struct Revocations {
    current: RwLock<Arc<Snapshot>>,
    /// The last version tried (loaded or not) and the last error, so a
    /// broken file is reported once rather than on every check.
    tried: tokio::sync::Mutex<(u64, Option<String>)>,
}

impl Revocations {
    /// Load the revocations (errors are fatal at startup) and start the
    /// reload task.
    pub(crate) async fn start(
        config: Option<&Config>,
        authorities: &Authorities,
    ) -> Result<Arc<Self>, String> {
        let default = Config::default();
        let config = config.unwrap_or(&default);
        let source: Arc<dyn Source> = Arc::new(FileSource {
            file: config.file.clone(),
            inline: config.revoked.clone(),
            started: unix_secs(SystemTime::now()),
        });
        let loaded = source.load()?;
        let snapshot = build_signed(loaded, authorities).await?;
        if snapshot.count > 0 || config.file.is_some() {
            tracing::info!(
                "{} revocation(s) from {}",
                snapshot.count,
                source.describe()
            );
        }
        let revocations = Arc::new(Self {
            tried: tokio::sync::Mutex::new((snapshot.changed, None)),
            current: RwLock::new(Arc::new(snapshot)),
        });
        if config.file.is_some() && config.reload_interval > 0 {
            let interval = Duration::from_secs(config.reload_interval);
            let authorities = authorities.clone();
            let weak = Arc::downgrade(&revocations);
            tokio::spawn(async move {
                let mut timer = tokio::time::interval(interval);
                timer.tick().await;
                loop {
                    timer.tick().await;
                    let Some(revocations) = weak.upgrade() else {
                        return;
                    };
                    revocations.reload(source.as_ref(), &authorities).await;
                }
            });
        }
        Ok(revocations)
    }

    /// Reload from `source` if it changed. A broken list keeps the previous
    /// one: new revocations then don't apply until it's fixed, so this logs
    /// an error.
    async fn reload(&self, source: &dyn Source, authorities: &Authorities) {
        let mut tried = self.tried.lock().await;
        let result = match source.version() {
            Ok(version) if version == tried.0 => Ok(None),
            Ok(version) => {
                tried.0 = version;
                match source.load() {
                    Ok(loaded) => build_signed(loaded, authorities).await.map(Some),
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        };
        match result {
            Ok(Some(snapshot)) => {
                tracing::info!(
                    "reloaded {} revocation(s) from {}",
                    snapshot.count,
                    source.describe()
                );
                *self.current.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(snapshot);
                tried.1 = None;
            }
            Ok(None) => {}
            Err(err) if tried.1.as_ref() == Some(&err) => {}
            Err(err) => {
                tracing::error!("revocations not reloaded, keeping the previous list: {err}");
                tried.1 = Some(err);
            }
        }
    }

    pub(crate) fn current(&self) -> Arc<Snapshot> {
        self.current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorities() -> Authorities {
        ssh_casign_ca::testing::authorities(&["users", "hosts"])
    }

    fn entries(toml: &str) -> Vec<RawEntry> {
        toml::from_str::<RawFile>(toml).unwrap().revoked
    }

    fn build(toml: &str) -> Result<Snapshot, String> {
        Snapshot::build(
            Loaded {
                entries: entries(toml),
                changed: 1_800_000_000,
            },
            &authorities(),
        )
    }

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDMWPNAT5YdP24QTg1F3Xlfh42hMUjC6PAg9YbAfTO30";

    #[test]
    fn lookups() {
        let key = ssh_key::PublicKey::from_openssh(KEY).unwrap();
        let fingerprint = key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
        let snapshot = build(&format!(
            r#"
            [[revoked]]
            serial = 42
            authority = "hosts"
            reason = "decommissioned"
            revoked_at = 2026-11-14

            [[revoked]]
            key_id = "ca1:default:alice@example.com:laptop"

            [[revoked]]
            key_id = "ca1:cmdb:cmdb:x"
            authority = "hosts"

            [[revoked]]
            fingerprint = "{fingerprint}"
            "#
        ))
        .unwrap();
        assert!(snapshot.key_id_revoked("users", "ca1:default:alice@example.com:laptop"));
        assert!(snapshot.key_id_revoked("hosts", "ca1:default:alice@example.com:laptop"));
        assert!(snapshot.key_id_revoked("hosts", "ca1:cmdb:cmdb:x"));
        assert!(!snapshot.key_id_revoked("users", "ca1:cmdb:cmdb:x"));
        assert!(snapshot.key_revoked(&key));
        // The same key given as public_key.
        let by_key = build(&format!("[[revoked]]\npublic_key = \"{KEY}\"\n")).unwrap();
        assert!(by_key.key_revoked(&key));
        assert_eq!(by_key.fingerprints, snapshot.fingerprints);
    }

    #[tokio::test]
    async fn reload_only_on_change_and_report_errors_once() {
        let dir = std::env::temp_dir().join(format!("ssh-casign-krl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("revocations.toml");
        std::fs::write(&file, "").unwrap();
        let config: Config = toml::from_str(&format!(
            "file = {:?}\nreload_interval = 0\n",
            file.to_str().unwrap()
        ))
        .unwrap();
        let authorities = authorities();
        let revocations = Revocations::start(Some(&config), &authorities)
            .await
            .unwrap();
        let source = FileSource {
            file: Some(file.clone()),
            inline: vec![],
            started: 0,
        };
        let set_mtime = |secs: u64| {
            std::fs::File::options()
                .write(true)
                .open(&file)
                .unwrap()
                .set_modified(UNIX_EPOCH + Duration::from_secs(secs))
                .unwrap();
        };
        std::fs::write(&file, "[[revoked]]\nkey_id = \"x\"\n").unwrap();
        set_mtime(2_000_000_000);
        revocations.reload(&source, &authorities).await;
        assert!(revocations.current().key_id_revoked("hosts", "x"));
        // Broken: the previous list stays, the error is remembered.
        std::fs::write(&file, "[[revoked]]\nserail = 1\n").unwrap();
        set_mtime(2_000_000_100);
        revocations.reload(&source, &authorities).await;
        assert!(revocations.current().key_id_revoked("hosts", "x"));
        assert!(revocations.tried.lock().await.1.is_some());
        // Fixed: reloaded.
        std::fs::write(&file, "[[revoked]]\nkey_id = \"y\"\n").unwrap();
        set_mtime(2_000_000_200);
        revocations.reload(&source, &authorities).await;
        assert!(revocations.current().key_id_revoked("hosts", "y"));
        assert!(!revocations.current().key_id_revoked("hosts", "x"));
        assert!(revocations.tried.lock().await.1.is_none());
        // The KRL is signed by every authority.
        let current = revocations.current();
        let signatures = ssh_casign_proto::trust::split_signatures(&current.signatures());
        assert_eq!(
            ssh_casign_proto::trust::valid_signers(
                ssh_casign_proto::trust::KRL_NAMESPACE,
                &current.krl(),
                &signatures
            )
            .len(),
            2
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn large_serials_as_strings() {
        let snapshot =
            build("[[revoked]]\nserial = \"16361417745147627987\"\nauthority = \"hosts\"\n")
                .unwrap();
        assert!(snapshot
            .krl()
            .ends_with(&16361417745147627987u64.to_be_bytes()));
        assert!(toml::from_str::<RawFile>("[[revoked]]\nserial = \"-1\"\n").is_err());
        assert!(toml::from_str::<RawFile>("[[revoked]]\nserial = 16361417745147627987\n").is_err());
    }

    #[test]
    fn invalid_entries() {
        for (toml, message) in [
            ("[[revoked]]\nserial = 1\n", "authority"),
            (
                "[[revoked]]\nserial = 1\nauthority = \"nope\"\n",
                "unknown authority",
            ),
            (
                "[[revoked]]\nserial = 1\nkey_id = \"x\"\nauthority = \"hosts\"\n",
                "exactly one",
            ),
            ("[[revoked]]\nreason = \"nothing\"\n", "exactly one"),
            ("[[revoked]]\nfingerprint = \"MD5:aa\"\n", "SHA256"),
            ("[[revoked]]\nfingerprint = \"SHA256:abc\"\n", "SHA-256"),
            ("[[revoked]]\npublic_key = \"nope\"\n", "invalid public key"),
            (
                "[[revoked]]\nserial = 0\nauthority = \"hosts\"\n",
                "serial 0",
            ),
        ] {
            let err = build(toml).err().unwrap_or_default();
            assert!(err.contains(message), "{toml}: {err}");
            assert!(err.starts_with("revocation 1:"), "{err}");
        }
        assert!(toml::from_str::<RawFile>("[[revoked]]\nserail = 1\n").is_err());
    }

    #[test]
    fn krl_layout() {
        let snapshot = build(
            r#"
            [[revoked]]
            serial = 7
            authority = "hosts"
            [[revoked]]
            serial = 3
            authority = "hosts"
            "#,
        )
        .unwrap();
        let krl = snapshot.krl();
        assert_eq!(&krl[..8], KRL_MAGIC);
        assert_eq!(&krl[8..12], &1u32.to_be_bytes());
        assert_eq!(&krl[12..20], &1_800_000_000u64.to_be_bytes());
        // Header strings: reserved (empty) and comment.
        let mut at = 36;
        assert_eq!(&krl[at..at + 4], &0u32.to_be_bytes());
        at += 4;
        assert_eq!(&krl[at..at + 4], &10u32.to_be_bytes());
        at += 4 + 10;
        assert_eq!(krl[at], KRL_SECTION_CERTIFICATES);
        // Serials sorted at the end of the section: 3 then 7.
        assert_eq!(
            &krl[krl.len() - 16..],
            [3u64.to_be_bytes(), 7u64.to_be_bytes()].concat()
        );
        // Deterministic.
        assert_eq!(build("[[revoked]]\nserial = 3\nauthority = \"hosts\"\n[[revoked]]\nserial = 7\nauthority = \"hosts\"\n").unwrap().krl(), krl);
        // Empty list: header only.
        assert_eq!(build("").unwrap().krl().len(), at);
    }
}
