// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Hash Pin Store — immutable hash verification for stored artifacts.
//!
//! Records SHA-256 hashes on every `Storage::put()` and verifies them on
//! `Storage::get()`. Detects tampering at the storage layer (e.g. direct
//! filesystem modification bypassing NORA).
//!
//! Persistence: append-only NDJSON file (`.nora-pins.ndjson`) compacted on
//! startup. Each line: `{"k":"storage/key","h":"sha256hex"}`. An empty `h`
//! marks a deletion (tombstone).

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use tracing::warn;

#[derive(Serialize, Deserialize)]
struct PinEntry {
    k: String,
    h: String,
}

pub struct HashPinStore {
    pins: RwLock<HashMap<String, String>>,
    path: PathBuf,
}

impl HashPinStore {
    /// Load (or create) a pin store backed by the given NDJSON file.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let mut pins = HashMap::new();

        // Replay NDJSON log — last entry per key wins
        if let Ok(file) = std::fs::File::open(&path) {
            let reader = std::io::BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                if let Ok(entry) = serde_json::from_str::<PinEntry>(&line) {
                    if entry.h.is_empty() {
                        pins.remove(&entry.k);
                    } else {
                        pins.insert(entry.k, entry.h);
                    }
                }
            }
        }

        let store = Self {
            pins: RwLock::new(pins),
            path,
        };

        // Compact on startup to remove tombstones and duplicates
        store.compact();
        store
    }

    /// Compute SHA-256 hex digest.
    fn sha256_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Record the hash for a storage key. Called on every `put()`.
    ///
    /// If the key is new, the hash is pinned. If the key exists with the same
    /// hash, this is a no-op. If the hash changed (normal metadata update),
    /// the pin is updated.
    ///
    /// File I/O is dispatched to a blocking thread to avoid holding the
    /// write lock during disk writes on the tokio runtime.
    pub fn record(&self, key: &str, data: &[u8]) {
        let hash = Self::sha256_hex(data);
        let should_write = {
            let mut pins = self.pins.write();
            let changed = pins.get(key).is_none_or(|existing| *existing != hash);
            if changed {
                pins.insert(key.to_string(), hash.clone());
            }
            changed
        };
        if should_write {
            let path = self.path.clone();
            let key = key.to_string();
            std::thread::spawn(move || {
                Self::append_to_file(&path, &key, &hash);
            });
        }
    }

    /// Verify data integrity against pinned hash. Called on every `get()`.
    ///
    /// Returns `true` if the hash matches or no pin exists for this key.
    /// Returns `false` and logs a warning if tampering is detected.
    pub fn verify(&self, key: &str, data: &[u8]) -> bool {
        let pins = self.pins.read();
        if let Some(expected) = pins.get(key) {
            let actual = Self::sha256_hex(data);
            if *expected != actual {
                warn!(
                    key = key,
                    expected = expected.as_str(),
                    actual = actual.as_str(),
                    "INTEGRITY VIOLATION: stored artifact hash mismatch"
                );
                return false;
            }
        }
        true
    }

    /// Remove a pin entry. Called on `delete()`.
    ///
    /// File I/O is dispatched to a separate thread.
    pub fn remove(&self, key: &str) {
        let removed = {
            let mut pins = self.pins.write();
            pins.remove(key).is_some()
        };
        if removed {
            let path = self.path.clone();
            let key = key.to_string();
            std::thread::spawn(move || {
                Self::append_to_file(&path, &key, "");
            });
        }
    }

    /// Number of pinned entries.
    pub fn len(&self) -> usize {
        self.pins.read().len()
    }

    /// Compact the NDJSON file: rewrite with only live entries.
    fn compact(&self) {
        let pins = self.pins.read();
        if pins.is_empty() {
            // Remove empty file
            let _ = std::fs::remove_file(&self.path);
            return;
        }

        let temp_path = self.path.with_extension("ndjson.tmp");
        if let Ok(mut file) = std::fs::File::create(&temp_path) {
            for (key, hash) in pins.iter() {
                let entry = PinEntry {
                    k: key.clone(),
                    h: hash.clone(),
                };
                if let Ok(line) = serde_json::to_string(&entry) {
                    let _ = writeln!(file, "{}", line);
                }
            }
            let _ = std::fs::rename(&temp_path, &self.path);
        }
    }

    /// Append a single entry to the NDJSON file (static, safe to call from any thread).
    fn append_to_file(path: &std::path::Path, key: &str, hash: &str) {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let entry = PinEntry {
                k: key.to_string(),
                h: hash.to_string(),
            };
            if let Ok(line) = serde_json::to_string(&entry) {
                let _ = writeln!(file, "{}", line);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn pin_path(dir: &TempDir) -> PathBuf {
        dir.path().join(".nora-pins.ndjson")
    }

    #[test]
    fn test_record_and_verify() {
        let dir = TempDir::new().unwrap();
        let store = HashPinStore::new(pin_path(&dir));

        store.record("maven/com/example/1.0/app.jar", b"jar-content");
        assert!(store.verify("maven/com/example/1.0/app.jar", b"jar-content"));
        assert!(!store.verify("maven/com/example/1.0/app.jar", b"tampered"));
    }

    #[test]
    fn test_verify_unknown_key_passes() {
        let dir = TempDir::new().unwrap();
        let store = HashPinStore::new(pin_path(&dir));

        // No pin exists — verification passes (open world)
        assert!(store.verify("unknown/key", b"anything"));
    }

    #[test]
    fn test_record_update_overwrites_pin() {
        let dir = TempDir::new().unwrap();
        let store = HashPinStore::new(pin_path(&dir));

        store.record("npm/meta/express", b"v1");
        assert!(store.verify("npm/meta/express", b"v1"));

        // Metadata update — pin is updated
        store.record("npm/meta/express", b"v2");
        assert!(store.verify("npm/meta/express", b"v2"));
        assert!(!store.verify("npm/meta/express", b"v1"));
    }

    #[test]
    fn test_remove_pin() {
        let dir = TempDir::new().unwrap();
        let store = HashPinStore::new(pin_path(&dir));

        store.record("key", b"data");
        assert_eq!(store.len(), 1);

        store.remove("key");
        assert_eq!(store.len(), 0);

        // After removal, any data passes verification (no pin)
        assert!(store.verify("key", b"whatever"));
    }

    #[test]
    fn test_persistence_and_reload() {
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);

        {
            let store = HashPinStore::new(&path);
            store.record("a", b"data-a");
            store.record("b", b"data-b");
            store.remove("b");
        }

        // Reload from disk
        let store = HashPinStore::new(&path);
        assert_eq!(store.len(), 1);
        assert!(store.verify("a", b"data-a"));
        assert!(store.verify("b", b"anything")); // removed, no pin
    }

    #[test]
    fn test_compact_removes_tombstones() {
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);

        {
            let store = HashPinStore::new(&path);
            store.record("keep", b"data");
            store.record("remove", b"data");
            store.remove("remove");
        }

        // After reload + compact, file should only have 1 entry
        let store = HashPinStore::new(&path);
        assert_eq!(store.len(), 1);

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("keep"));
    }

    #[test]
    fn test_idempotent_record() {
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);
        let store = HashPinStore::new(&path);

        // Same data twice — should not append duplicate
        store.record("key", b"data");
        store.record("key", b"data");

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1, "duplicate record should be idempotent");
    }

    #[test]
    fn test_empty_store_no_file() {
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);
        let store = HashPinStore::new(&path);

        assert_eq!(store.len(), 0);
        assert!(!path.exists(), "empty store should not create file");
    }

    #[test]
    fn test_sha256_correctness() {
        // Known test vector: SHA-256 of empty string
        let hash = HashPinStore::sha256_hex(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
