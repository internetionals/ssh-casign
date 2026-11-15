//! Shared storage for ssh-casign: the revocations document and the issuance
//! index, kept where every instance of the service can reach them.
//!
//! The interface is a small object store: `get`, conditional `put`, `list`
//! by prefix and `delete`. Conditional writes (only if absent, or only if the
//! version is unchanged) make concurrent updates by several instances safe:
//! a writer that lost the race gets [`StoreError::Conflict`] and retries.
//! S3, GCS and Azure Blob offer exactly these operations; the file backend
//! here uses a lock file.
//!
//! Backends are registered by `type` in a [`Registry`], like the CA backends,
//! so builds only contain the ones their platform needs.

use std::{collections::BTreeMap, future::Future, pin::Pin};

pub mod file;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// An object and its version (ETag, generation, content hash).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    pub data: Vec<u8>,
    pub version: String,
}

/// When a `put` may happen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Precondition {
    /// Always.
    None,
    /// Only if the object doesn't exist.
    Absent,
    /// Only if the object still has this version.
    Version(String),
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The precondition failed: someone else wrote first.
    #[error("the object changed (concurrent update)")]
    Conflict,
    #[error("{0}")]
    Other(String),
}

impl From<std::io::Error> for StoreError {
    fn from(err: std::io::Error) -> Self {
        Self::Other(err.to_string())
    }
}

pub trait Store: Send + Sync {
    /// For logs, e.g. `s3 bucket ssh-casign`.
    fn describe(&self) -> String;

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Object>, StoreError>>;

    /// Write `data`; returns the new version.
    fn put<'a>(
        &'a self,
        key: &'a str,
        data: Vec<u8>,
        precondition: Precondition,
    ) -> BoxFuture<'a, Result<String, StoreError>>;

    /// Keys starting with `prefix`, sorted.
    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<String>, StoreError>>;

    /// Delete `key`; deleting a missing key is not an error.
    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), StoreError>>;
}

/// Keys are `/`-separated segments of `A-Za-z0-9._-`, so every backend can
/// store them as they are.
pub fn check_key(key: &str) -> Result<(), StoreError> {
    let valid = !key.is_empty()
        && key.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        });
    if valid {
        Ok(())
    } else {
        Err(StoreError::Other(format!("invalid store key '{key}'")))
    }
}

/// Loads a store from its configuration (the `[store]` table without `type`).
pub type Loader = fn(toml::Table) -> BoxFuture<'static, Result<Box<dyn Store>, String>>;

/// Deserialize a store's configuration from the table a [`Loader`] gets.
pub fn parse_config<T: serde::de::DeserializeOwned>(config: toml::Table) -> Result<T, String> {
    toml::Value::Table(config)
        .try_into()
        .map_err(|err: toml::de::Error| err.message().to_string())
}

/// The store backends a build contains, by `type`.
#[derive(Default)]
pub struct Registry {
    loaders: BTreeMap<&'static str, Loader>,
    unavailable: BTreeMap<&'static str, &'static str>,
}

impl Registry {
    /// A registry with the file backend.
    pub fn new() -> Self {
        let mut registry = Self::default();
        registry.register(file::TYPE, file::load);
        registry
    }

    pub fn register(&mut self, kind: &'static str, loader: Loader) -> &mut Self {
        self.loaders.insert(kind, loader);
        self
    }

    /// Note a store type this build doesn't include, for a helpful error.
    pub fn unavailable(&mut self, kind: &'static str, feature: &'static str) -> &mut Self {
        self.unavailable.insert(kind, feature);
        self
    }

    /// Load the store configured in `table` (`type` plus the backend's keys).
    pub async fn load(&self, mut table: toml::Table) -> Result<Box<dyn Store>, String> {
        let kind = match table.remove("type") {
            Some(toml::Value::String(kind)) => kind,
            _ => return Err("store: `type` is missing".into()),
        };
        if let Some(loader) = self.loaders.get(kind.as_str()) {
            return loader(table)
                .await
                .map_err(|err| format!("store ({kind}): {err}"));
        }
        let available = self.loaders.keys().copied().collect::<Vec<_>>().join(", ");
        Err(match self.unavailable.get(kind.as_str()) {
            Some(feature) => format!(
                "store type '{kind}' is not part of this build (enable the '{feature}' feature)"
            ),
            None => format!("unknown store type '{kind}' (this build has: {available})"),
        })
    }
}

/// Shared tests every backend should pass.
pub mod testing {
    use super::*;

    /// Exercise `store`: conditional puts, get, list and delete, under
    /// `prefix` (which should be empty in the store).
    pub async fn exercise(store: &dyn Store, prefix: &str) -> Result<(), String> {
        let key = format!("{prefix}doc.json");
        let fail = |what: &str| Err(format!("{}: {what}", store.describe()));
        if store.get(&key).await.map_err(|e| e.to_string())?.is_some() {
            return fail("object exists before the test");
        }
        let v1 = store
            .put(&key, b"one".to_vec(), Precondition::Absent)
            .await
            .map_err(|e| e.to_string())?;
        match store
            .put(&key, b"again".to_vec(), Precondition::Absent)
            .await
        {
            Err(StoreError::Conflict) => {}
            other => return fail(&format!("put if absent over an object: {other:?}")),
        }
        let object = store.get(&key).await.map_err(|e| e.to_string())?;
        if object.as_ref().map(|o| (&o.data[..], &o.version[..])) != Some((b"one", &v1[..])) {
            return fail(&format!("get returned {object:?}"));
        }
        let v2 = store
            .put(&key, b"two".to_vec(), Precondition::Version(v1.clone()))
            .await
            .map_err(|e| e.to_string())?;
        if v2 == v1 {
            return fail("the version didn't change");
        }
        match store
            .put(&key, b"stale".to_vec(), Precondition::Version(v1))
            .await
        {
            Err(StoreError::Conflict) => {}
            other => return fail(&format!("put with a stale version: {other:?}")),
        }
        let other = format!("{prefix}index/a/b.json");
        store
            .put(&other, b"{}".to_vec(), Precondition::None)
            .await
            .map_err(|e| e.to_string())?;
        let listed = store
            .list(&format!("{prefix}index/"))
            .await
            .map_err(|e| e.to_string())?;
        if listed != [other.clone()] {
            return fail(&format!("list returned {listed:?}"));
        }
        for key in [&key, &other] {
            store.delete(key).await.map_err(|e| e.to_string())?;
        }
        store.delete(&key).await.map_err(|e| e.to_string())?;
        if store.get(&key).await.map_err(|e| e.to_string())?.is_some() {
            return fail("object still there after delete");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        assert!(check_key("revocations.json").is_ok());
        assert!(check_key("issued/abc123/1800000000.users.42.json").is_ok());
        for bad in ["", "/a", "a/", "a//b", "../x", "a/./b", "a b", "a\\b"] {
            assert!(check_key(bad).is_err(), "{bad}");
        }
    }
}
