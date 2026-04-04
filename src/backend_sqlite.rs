use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::backend::{RawSecret, SecretBackend};

pub struct SqliteBackend {
    conn: Mutex<Connection>,
    path: PathBuf,
}

impl SqliteBackend {
    /// Open (or create) a SQLite vault at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory: {}", parent.display()))?;
        }

        let conn = Connection::open(path)
            .with_context(|| format!("failed to open sqlite db: {}", path.display()))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                key TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(service, key)
            );"
        ).context("failed to create secrets table")?;

        // Enable WAL mode for better concurrent read performance
        conn.pragma_update(None, "journal_mode", "WAL")?;

        Ok(Self {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
        })
    }
}

#[async_trait]
impl SecretBackend for SqliteBackend {
    async fn list_all(&self) -> Result<Vec<RawSecret>> {
        let conn = self.conn.lock().map_err(|e| anyhow!("lock poisoned: {}", e))?;

        let mut stmt = conn.prepare(
            "SELECT id, service, key, ciphertext, created_at FROM secrets ORDER BY service, key"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(RawSecret {
                id: row.get(0)?,
                service: row.get(1)?,
                key: row.get(2)?,
                ciphertext: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;

        let mut secrets = Vec::new();
        for row in rows {
            secrets.push(row?);
        }
        Ok(secrets)
    }

    async fn store(&self, service: &str, key: &str, ciphertext: &str) -> Result<u64> {
        let conn = self.conn.lock().map_err(|e| anyhow!("lock poisoned: {}", e))?;

        conn.execute(
            "INSERT INTO secrets (service, key, ciphertext)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(service, key) DO UPDATE SET
                ciphertext = excluded.ciphertext,
                created_at = datetime('now')",
            rusqlite::params![service, key, ciphertext],
        )?;

        let id: u64 = conn.query_row(
            "SELECT id FROM secrets WHERE service = ?1 AND key = ?2",
            rusqlite::params![service, key],
            |row| row.get(0),
        )?;

        Ok(id)
    }

    async fn get(&self, service: &str, key: &str) -> Result<RawSecret> {
        let conn = self.conn.lock().map_err(|e| anyhow!("lock poisoned: {}", e))?;

        conn.query_row(
            "SELECT id, service, key, ciphertext, created_at FROM secrets WHERE service = ?1 AND key = ?2",
            rusqlite::params![service, key],
            |row| {
                Ok(RawSecret {
                    id: row.get(0)?,
                    service: row.get(1)?,
                    key: row.get(2)?,
                    ciphertext: row.get(3)?,
                    created_at: row.get(4)?,
                })
            },
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                anyhow!("secret not found: {}/{}", service, key)
            }
            other => anyhow!("sqlite error: {}", other),
        })
    }

    async fn delete(&self, service: &str, key: &str) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow!("lock poisoned: {}", e))?;

        let affected = conn.execute(
            "DELETE FROM secrets WHERE service = ?1 AND key = ?2",
            rusqlite::params![service, key],
        )?;

        if affected == 0 {
            return Err(anyhow!("secret not found: {}/{}", service, key));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn temp_db() -> PathBuf {
        let dir = env::temp_dir().join(format!("cred-test-{}-{}", std::process::id(), rand_suffix()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("test-vault.db")
    }

    fn rand_suffix() -> u64 {
        use std::time::SystemTime;
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    #[tokio::test]
    async fn test_store_and_get() {
        let path = temp_db();
        let backend = SqliteBackend::open(&path).unwrap();

        let id = backend.store("myservice", "mykey", "deadbeef1234").await.unwrap();
        assert!(id > 0);

        let raw = backend.get("myservice", "mykey").await.unwrap();
        assert_eq!(raw.service, "myservice");
        assert_eq!(raw.key, "mykey");
        assert_eq!(raw.ciphertext, "deadbeef1234");

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn test_list_all() {
        let path = temp_db();
        let backend = SqliteBackend::open(&path).unwrap();

        backend.store("alpha", "key1", "aaa").await.unwrap();
        backend.store("beta", "key2", "bbb").await.unwrap();
        backend.store("alpha", "key3", "ccc").await.unwrap();

        let all = backend.list_all().await.unwrap();
        assert_eq!(all.len(), 3);
        // Should be sorted by service, key
        assert_eq!(all[0].service, "alpha");
        assert_eq!(all[0].key, "key1");
        assert_eq!(all[1].service, "alpha");
        assert_eq!(all[1].key, "key3");
        assert_eq!(all[2].service, "beta");

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn test_store_upsert() {
        let path = temp_db();
        let backend = SqliteBackend::open(&path).unwrap();

        backend.store("svc", "k", "old_cipher").await.unwrap();
        backend.store("svc", "k", "new_cipher").await.unwrap();

        let raw = backend.get("svc", "k").await.unwrap();
        assert_eq!(raw.ciphertext, "new_cipher");

        let all = backend.list_all().await.unwrap();
        assert_eq!(all.len(), 1); // No duplicates

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn test_delete() {
        let path = temp_db();
        let backend = SqliteBackend::open(&path).unwrap();

        backend.store("svc", "k", "cipher").await.unwrap();
        backend.delete("svc", "k").await.unwrap();

        let result = backend.get("svc", "k").await;
        assert!(result.is_err());

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn test_delete_nonexistent() {
        let path = temp_db();
        let backend = SqliteBackend::open(&path).unwrap();

        let result = backend.delete("nope", "nope").await;
        assert!(result.is_err());

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn test_get_nonexistent() {
        let path = temp_db();
        let backend = SqliteBackend::open(&path).unwrap();

        let result = backend.get("nope", "nope").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}
