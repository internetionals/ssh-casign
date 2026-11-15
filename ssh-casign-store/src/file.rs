//! A store in a directory, for standalone servers (or several servers
//! sharing one file system).
//!
//! ```toml
//! [store]
//! type = "file"
//! path = "/var/lib/ssh-casign"
//! ```
//!
//! Versions are content hashes. Writes go through a temporary file and a
//! rename, under an exclusive lock on `.lock` in the directory, so
//! conditional writes are safe between processes.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::Digest as _;

use crate::{check_key, BoxFuture, Object, Precondition, Store, StoreError};

pub const TYPE: &str = "file";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    path: PathBuf,
}

pub struct FileStore {
    root: PathBuf,
}

pub fn load(config: toml::Table) -> BoxFuture<'static, Result<Box<dyn Store>, String>> {
    Box::pin(async move {
        let config: Config = crate::parse_config(config)?;
        let store = FileStore::new(config.path)?;
        Ok(Box::new(store) as Box<dyn Store>)
    })
}

fn version(data: &[u8]) -> String {
    sha2::Sha256::digest(data)
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl FileStore {
    pub fn new(root: PathBuf) -> Result<Self, String> {
        std::fs::create_dir_all(&root).map_err(|err| format!("{}: {err}", root.display()))?;
        Ok(Self { root })
    }

    fn path(&self, key: &str) -> Result<PathBuf, StoreError> {
        check_key(key)?;
        Ok(self.root.join(key))
    }

    /// Run `f` under the directory's exclusive lock (blocking; called from
    /// `spawn_blocking`).
    fn locked<T>(root: &Path, f: impl FnOnce() -> Result<T, StoreError>) -> Result<T, StoreError> {
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(root.join(".lock"))?;
        lock.lock()?;
        let result = f();
        let _ = lock.unlock();
        result
    }
}

fn read(path: &Path) -> Result<Option<Vec<u8>>, StoreError> {
    match std::fs::read(path) {
        Ok(data) => Ok(Some(data)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
) -> Result<T, StoreError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|err| StoreError::Other(err.to_string()))?
}

impl Store for FileStore {
    fn describe(&self) -> String {
        format!("file store {}", self.root.display())
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Object>, StoreError>> {
        Box::pin(async move {
            let path = self.path(key)?;
            blocking(move || {
                Ok(read(&path)?.map(|data| Object {
                    version: version(&data),
                    data,
                }))
            })
            .await
        })
    }

    fn put<'a>(
        &'a self,
        key: &'a str,
        data: Vec<u8>,
        precondition: Precondition,
    ) -> BoxFuture<'a, Result<String, StoreError>> {
        Box::pin(async move {
            let path = self.path(key)?;
            let root = self.root.clone();
            blocking(move || {
                Self::locked(&root, || {
                    let current = read(&path)?;
                    let allowed = match (&precondition, &current) {
                        (Precondition::None, _) => true,
                        (Precondition::Absent, current) => current.is_none(),
                        (Precondition::Version(expected), Some(current)) => {
                            version(current) == *expected
                        }
                        (Precondition::Version(_), None) => false,
                    };
                    if !allowed {
                        return Err(StoreError::Conflict);
                    }
                    if let Some(dir) = path.parent() {
                        std::fs::create_dir_all(dir)?;
                    }
                    let name = path.file_name().unwrap_or_default().to_string_lossy();
                    let temporary =
                        path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
                    std::fs::write(&temporary, &data)?;
                    std::fs::File::open(&temporary)?.sync_all()?;
                    std::fs::rename(&temporary, &path)?;
                    Ok(version(&data))
                })
            })
            .await
        })
    }

    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<String>, StoreError>> {
        Box::pin(async move {
            let root = self.root.clone();
            let prefix = prefix.to_string();
            blocking(move || {
                // Walk the directory that contains the prefix.
                let base = match prefix.rfind('/') {
                    Some(at) => &prefix[..at],
                    None => "",
                };
                let mut keys = Vec::new();
                let mut pending = vec![base.to_string()];
                while let Some(dir) = pending.pop() {
                    let entries = match std::fs::read_dir(root.join(&dir)) {
                        Ok(entries) => entries,
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(err) => return Err(err.into()),
                    };
                    for entry in entries {
                        let entry = entry?;
                        let name = entry.file_name().to_string_lossy().into_owned();
                        if name.starts_with('.') {
                            continue;
                        }
                        let key = if dir.is_empty() {
                            name
                        } else {
                            format!("{dir}/{name}")
                        };
                        if entry.file_type()?.is_dir() {
                            pending.push(key);
                        } else if key.starts_with(&prefix) {
                            keys.push(key);
                        }
                    }
                }
                keys.sort();
                Ok(keys)
            })
            .await
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let path = self.path(key)?;
            blocking(move || match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err.into()),
            })
            .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ssh-casign-store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[tokio::test]
    async fn file_store_passes_the_shared_tests() {
        let root = dir("shared");
        let store = FileStore::new(root.clone()).unwrap();
        crate::testing::exercise(&store, "t/").await.unwrap();
        assert!(store.get("../escape").await.is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn concurrent_updates_lose_nothing() {
        // 8 writers each add 10 lines with read, modify, conditional write.
        let root = dir("concurrent");
        let store = std::sync::Arc::new(FileStore::new(root.clone()).unwrap());
        let mut tasks = Vec::new();
        for writer in 0..8 {
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                for n in 0..10 {
                    loop {
                        let current = store.get("doc").await.unwrap();
                        let (mut data, precondition) = match current {
                            Some(object) => (object.data, Precondition::Version(object.version)),
                            None => (Vec::new(), Precondition::Absent),
                        };
                        data.extend(format!("{writer}-{n}\n").bytes());
                        match store.put("doc", data, precondition).await {
                            Ok(_) => break,
                            Err(StoreError::Conflict) => continue,
                            Err(err) => panic!("{err}"),
                        }
                    }
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        let data = store.get("doc").await.unwrap().unwrap().data;
        assert_eq!(String::from_utf8(data).unwrap().lines().count(), 80);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
