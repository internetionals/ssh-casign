//! The issuance index: every issued certificate, by owner, in the store, so
//! a signed-in user can list and revoke their own certificates from any
//! device (after losing a laptop, say).
//!
//! Keys are `issued/<owner>/<valid_before>.<authority>.<serial>.json`, where
//! `<owner>` is a hash of the token issuer and the IdP-determined ID. Listing
//! an owner reads only their entries; expired ones are skipped by name and
//! deleted when a listing passes them a week after expiry. Stores with
//! lifecycle rules can expire `issued/` objects themselves.

use sha2::Digest as _;
use ssh_casign_proto::revoke::{CertificateFilter, IssuedCertificate, Owner};
use ssh_casign_store::{Precondition, Store, StoreError};

const PREFIX: &str = "issued/";
/// Expired entries are deleted this long after expiry.
const CLEANUP_AFTER: u64 = 7 * 86_400;

fn short_hash(text: &str) -> String {
    let digest = sha2::Sha256::digest(text.as_bytes());
    digest.iter().take(16).map(|b| format!("{b:02x}")).collect()
}

fn owner_hash(owner: &Owner) -> String {
    short_hash(&format!("{}\n{}", owner.issuer, owner.id))
}

fn owner_prefix(owner: &Owner) -> String {
    format!("{PREFIX}{}/", owner_hash(owner))
}

/// `keys/<fingerprint>/<owner>.json`: who a key was certified for, to notice
/// one key used by several owners.
fn key_prefix(fingerprint: &str) -> String {
    format!("keys/{}/", short_hash(fingerprint))
}

pub(crate) async fn record_key_owner(
    store: &dyn Store,
    fingerprint: &str,
    owner: &Owner,
) -> Result<(), StoreError> {
    let data = serde_json::to_vec(owner).map_err(|err| StoreError::Other(err.to_string()))?;
    let key = format!("{}{}.json", key_prefix(fingerprint), owner_hash(owner));
    store.put(&key, data, Precondition::None).await?;
    Ok(())
}

/// Everyone a key was certified for.
pub(crate) async fn key_owners(
    store: &dyn Store,
    fingerprint: &str,
) -> Result<Vec<Owner>, StoreError> {
    let mut owners = Vec::new();
    for key in store.list(&key_prefix(fingerprint)).await? {
        if let Some(object) = store.get(&key).await? {
            if let Ok(owner) = serde_json::from_slice::<Owner>(&object.data) {
                owners.push(owner);
            }
        }
    }
    Ok(owners)
}

/// A key segment from a free-form name.
fn segment(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn key(certificate: &IssuedCertificate) -> String {
    format!(
        "{}{}.{}.{}.json",
        owner_prefix(&certificate.owner),
        certificate.valid_before,
        segment(&certificate.authority),
        certificate.serial
    )
}

/// `valid_before` from a key's file name.
fn valid_before(key: &str) -> Option<u64> {
    key.rsplit('/').next()?.split('.').next()?.parse().ok()
}

pub(crate) async fn record(
    store: &dyn Store,
    certificate: &IssuedCertificate,
) -> Result<(), StoreError> {
    let data = serde_json::to_vec(certificate).map_err(|err| StoreError::Other(err.to_string()))?;
    store
        .put(&key(certificate), data, Precondition::None)
        .await?;
    Ok(())
}

/// The owner's unexpired certificates, oldest expiry first.
pub(crate) async fn list(
    store: &dyn Store,
    owner: &Owner,
    now: u64,
) -> Result<Vec<IssuedCertificate>, StoreError> {
    let filter = CertificateFilter {
        owner_issuer: Some(owner.issuer.clone()),
        owner_id: Some(owner.id.clone()),
        ..CertificateFilter::default()
    };
    search(store, &filter, now).await
}

/// The unexpired certificates `filter` matches. With an owner in the
/// filter, only that owner's entries are read; otherwise all of them (an
/// administrator's search: one read per unexpired certificate).
pub(crate) async fn search(
    store: &dyn Store,
    filter: &CertificateFilter,
    now: u64,
) -> Result<Vec<IssuedCertificate>, StoreError> {
    let prefix = match filter.owner() {
        Some(owner) => owner_prefix(&owner),
        None => PREFIX.to_string(),
    };
    let mut certificates = Vec::new();
    for key in store.list(&prefix).await? {
        let Some(valid_before) = valid_before(&key) else {
            continue;
        };
        if valid_before <= now {
            if valid_before + CLEANUP_AFTER <= now {
                if let Err(err) = store.delete(&key).await {
                    tracing::warn!("issuance index: can't delete expired {key}: {err}");
                }
            }
            continue;
        }
        let Some(object) = store.get(&key).await? else {
            continue;
        };
        match serde_json::from_slice::<IssuedCertificate>(&object.data) {
            // (Also checks the owner: the hash could collide.)
            Ok(certificate) if filter.matches(&certificate) => certificates.push(certificate),
            Ok(_) => {}
            Err(err) => tracing::warn!("issuance index: {key}: {err}"),
        }
    }
    Ok(certificates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_casign_proto::CertType;

    fn certificate(owner: &str, serial: u64, valid_before: u64) -> IssuedCertificate {
        IssuedCertificate {
            serial: serial.to_string(),
            authority: "users ca".into(),
            key_id: format!("ca1:default:{owner}:laptop"),
            cert_type: CertType::User,
            principals: vec![owner.into()],
            valid_after: valid_before - 3600,
            valid_before,
            fingerprint: "SHA256:abc".into(),
            profile: "default".into(),
            app_name: Some("laptop".into()),
            client_address: Some("192.0.2.7".into()),
            owner: Owner {
                issuer: "https://idp.example.com".into(),
                id: owner.into(),
            },
            revoked: false,
        }
    }

    #[tokio::test]
    async fn record_list_and_cleanup() {
        let dir = std::env::temp_dir().join(format!("ssh-casign-index-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = ssh_casign_store::file::FileStore::new(dir.clone()).unwrap();
        let now = 1_800_000_000;
        for certificate in [
            certificate("alice", 1, now + 3600),
            certificate("alice", 2, now + 60),
            certificate("alice", 3, now - 60),
            certificate("alice", 4, now - CLEANUP_AFTER - 1),
            certificate("bob", 5, now + 3600),
        ] {
            record(&store, &certificate).await.unwrap();
        }
        let alice = certificate("alice", 0, now).owner;
        let listed = list(&store, &alice, now).await.unwrap();
        let serials: Vec<&str> = listed.iter().map(|c| c.serial.as_str()).collect();
        assert_eq!(serials, ["2", "1"]);
        // The long-expired entry was deleted, the recently expired one kept.
        let keys = store.list(&owner_prefix(&alice)).await.unwrap();
        assert_eq!(keys.len(), 3);
        assert!(keys.iter().all(|key| key.contains(".users_ca.")));
        // An administrator's search across owners.
        let by_principal = CertificateFilter {
            principal: Some("bob".into()),
            ..CertificateFilter::default()
        };
        let found = search(&store, &by_principal, now).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].serial, "5");
        let by_address = CertificateFilter {
            client_address: Some("192.0.2.7".into()),
            ..CertificateFilter::default()
        };
        assert_eq!(search(&store, &by_address, now).await.unwrap().len(), 3);
        assert!(search(&store, &CertificateFilter::default(), now)
            .await
            .unwrap()
            .is_empty());
        // Key owners.
        let bob = certificate("bob", 0, now).owner;
        record_key_owner(&store, "SHA256:abc", &alice)
            .await
            .unwrap();
        record_key_owner(&store, "SHA256:abc", &alice)
            .await
            .unwrap();
        record_key_owner(&store, "SHA256:abc", &bob).await.unwrap();
        let mut owners: Vec<String> = key_owners(&store, "SHA256:abc")
            .await
            .unwrap()
            .into_iter()
            .map(|owner| owner.id)
            .collect();
        owners.sort();
        assert_eq!(owners, ["alice", "bob"]);
        assert!(key_owners(&store, "SHA256:other").await.unwrap().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
