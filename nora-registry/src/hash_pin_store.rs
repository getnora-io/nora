// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Hash Pin Store — the local filesystem backend's record of the SHA-256 pin of
//! every artifact it stores.
//!
//! `LocalStorage` records a pin on every write and hands it back on every read;
//! the `Storage` wrapper is what compares it against the bytes. Together they
//! detect tampering at the storage layer (e.g. direct filesystem modification
//! bypassing NORA).
//!
//! Persistence: append-only NDJSON file (`.nora-pins.ndjson`) compacted on
//! startup. Each line: `{"k":"storage/key","h":"sha256hex"}`. An empty `h`
//! marks a deletion (tombstone).
//!
//! Durability: every pin write **propagates** its I/O result to the caller,
//! which fails closed (`StorageError::Io`) rather than report a `put()` success
//! the disk never accepted. A swallowed pin-write error would silently
//! downgrade a pinned key to open-world after a restart — the very integrity
//! bypass #582/#604 closed — because the in-memory pin is now updated only
//! *after* the durable append succeeds. (Crash-durability of the pin via
//! `fsync` is tracked separately: it must land together with the matching body
//! `fsync` on `put_from_path`, so the pin is never made *more* durable than the
//! bytes it pins.)

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
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

        // Replay NDJSON log — last entry per key wins.
        match std::fs::File::open(&path) {
            Ok(file) => {
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
            // First run / empty store — nothing to replay.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            // The pin file exists but cannot be read (permissions, EIO).
            // Loading an empty set would silently make every key open-world;
            // surface it loudly so the operator notices the integrity index did
            // not load rather than discovering it only on a missed tamper.
            Err(e) => {
                warn!(
                    error = %e,
                    path = %path.display(),
                    "hash-pin log present but unreadable; integrity index NOT loaded \
                     (keys verify open-world until this is fixed)"
                );
            }
        }

        let store = Self {
            pins: RwLock::new(pins),
            path,
        };

        // Compact on startup to remove tombstones and duplicates. Compaction is
        // an optimization, not an integrity-critical write: a failure leaves the
        // (correct, already-persisted) uncompacted log in place, so it is logged
        // and tolerated rather than fatal.
        if let Err(e) = store.compact() {
            warn!(
                error = %e,
                path = %store.path.display(),
                "hash-pin compaction on startup failed; continuing with uncompacted log"
            );
        }
        store
    }

    /// Record a pre-computed SHA-256 hash for a storage key.
    ///
    /// `hash` must be a lowercase hex-encoded SHA-256 (64 chars).
    ///
    /// Returns the I/O error if the pin append fails, so the caller can fail
    /// closed rather than serve an artifact it could not pin. The in-memory
    /// index is updated only *after* the append succeeds — memory must never
    /// claim a pin the disk does not hold, or a `get()` after a failed `put()`
    /// would verify against a RAM-only pin that vanishes on restart, and a
    /// retried `put()` would skip the (still-missing) append.
    pub fn record_hash(&self, key: &str, hash: &str) -> io::Result<()> {
        debug_assert!(
            hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()),
            "record_hash: expected 64-char hex SHA-256, got: {hash}"
        );

        // Atomic per key: hold the write lock across check → append → insert.
        // The disk append happens before the in-memory update (durability), and
        // no concurrent record_hash() for the same key can interleave its append
        // and insert with ours, so disk and memory cannot diverge. (An earlier
        // two-lock version — read-check, release, append, write-insert — had a
        // TOCTOU where two same-key writers' append and insert orders disagreed.)
        let mut pins = self.pins.write();
        if pins.get(key).is_none_or(|existing| *existing != hash) {
            Self::append_to_file(&self.path, key, hash)?;
            pins.insert(key.to_string(), hash.to_string());
        }
        Ok(())
    }

    /// Remove a pin entry. Called on `delete()`.
    ///
    /// Appends a tombstone before dropping the in-memory entry, returning any
    /// I/O error. A tombstone-write failure leaves the (now stale) pin in place;
    /// that is benign — `get()` on a deleted key fails at the inner backend
    /// before verification, and a later `put()` of the key overwrites the pin —
    /// so callers may treat a remove failure as non-fatal.
    pub fn remove(&self, key: &str) -> io::Result<()> {
        // Atomic tombstone: append + drop under one write lock (see record_hash()).
        let mut pins = self.pins.write();
        if pins.contains_key(key) {
            Self::append_to_file(&self.path, key, "")?;
            pins.remove(key);
        }
        Ok(())
    }

    /// Look up the stored SHA-256 hash for a key, if pinned.
    pub fn get(&self, key: &str) -> Option<String> {
        self.pins.read().get(key).cloned()
    }

    /// Compact the NDJSON file: rewrite with only live entries via a temp file
    /// and an atomic rename. Returns any I/O error; the caller decides whether a
    /// compaction failure is fatal (it is not — see [`HashPinStore::new`]).
    fn compact(&self) -> io::Result<()> {
        let pins = self.pins.read();
        if pins.is_empty() {
            // No live pins: remove the file if present; an absent file is fine.
            return match std::fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            };
        }

        let temp_path = self.path.with_extension("ndjson.tmp");
        let mut file = std::fs::File::create(&temp_path)?;
        for (key, hash) in pins.iter() {
            let entry = PinEntry {
                k: key.clone(),
                h: hash.clone(),
            };
            let line = serde_json::to_string(&entry).map_err(io::Error::other)?;
            writeln!(file, "{line}")?;
        }
        std::fs::rename(&temp_path, &self.path)?;
        Ok(())
    }

    /// Append a single entry to the NDJSON file (static, safe to call from any
    /// thread). Propagates any open/serialize/write error to the caller instead
    /// of swallowing it.
    fn append_to_file(path: &std::path::Path, key: &str, hash: &str) -> io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let entry = PinEntry {
            k: key.to_string(),
            h: hash.to_string(),
        };
        let line = serde_json::to_string(&entry).map_err(io::Error::other)?;
        writeln!(file, "{line}")?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    fn pin_path(dir: &TempDir) -> PathBuf {
        dir.path().join(".nora-pins.ndjson")
    }

    fn sha(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    #[test]
    fn test_record_and_get() {
        let dir = TempDir::new().unwrap();
        let store = HashPinStore::new(pin_path(&dir));
        let key = "maven/com/example/1.0/app.jar";

        store.record_hash(key, &sha(b"jar-content")).unwrap();
        assert_eq!(
            store.get(key).as_deref(),
            Some(sha(b"jar-content").as_str())
        );
        assert_eq!(store.get("unknown/key"), None);
    }

    #[test]
    fn test_record_update_overwrites_pin() {
        let dir = TempDir::new().unwrap();
        let store = HashPinStore::new(pin_path(&dir));
        let key = "npm/meta/express";

        store.record_hash(key, &sha(b"v1")).unwrap();
        // Metadata update — pin is updated
        store.record_hash(key, &sha(b"v2")).unwrap();
        assert_eq!(store.get(key).as_deref(), Some(sha(b"v2").as_str()));
    }

    #[test]
    fn test_remove_pin() {
        let dir = TempDir::new().unwrap();
        let store = HashPinStore::new(pin_path(&dir));

        store.record_hash("key", &sha(b"data")).unwrap();
        store.remove("key").unwrap();
        assert_eq!(store.get("key"), None);
    }

    #[test]
    fn test_persistence_and_reload() {
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);

        {
            let store = HashPinStore::new(&path);
            store.record_hash("a", &sha(b"data-a")).unwrap();
            store.record_hash("b", &sha(b"data-b")).unwrap();
            store.remove("b").unwrap();
        }

        // Reload from disk
        let store = HashPinStore::new(&path);
        assert_eq!(store.get("a").as_deref(), Some(sha(b"data-a").as_str()));
        assert_eq!(store.get("b"), None);
    }

    #[test]
    fn test_compact_removes_tombstones() {
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);

        {
            let store = HashPinStore::new(&path);
            store.record_hash("keep", &sha(b"data")).unwrap();
            store.record_hash("remove", &sha(b"data")).unwrap();
            store.remove("remove").unwrap();
        }

        // After reload + compact, file should only have 1 entry
        let store = HashPinStore::new(&path);
        assert!(store.get("keep").is_some());

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

        // Same hash twice — should not append duplicate
        store.record_hash("key", &sha(b"data")).unwrap();
        store.record_hash("key", &sha(b"data")).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1, "duplicate record_hash should be idempotent");
    }

    #[test]
    fn test_empty_store_no_file() {
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);
        let store = HashPinStore::new(&path);

        assert_eq!(store.get("anything"), None);
        assert!(!path.exists(), "empty store should not create file");
    }

    /// A pin write to an unwritable path must surface the I/O error, not swallow
    /// it — otherwise `put()` reports success while the pin never lands,
    /// silently downgrading the key to open-world on the next restart.
    ///
    /// The path is placed *under a regular file* so `open()` fails with
    /// `ENOTDIR` — a structural error the kernel returns even to root, unlike a
    /// `chmod`-based read-only directory which root (a common deployment for
    /// this code) bypasses via `DAC_OVERRIDE`.
    #[test]
    fn test_record_propagates_io_error() {
        let dir = TempDir::new().unwrap();
        let not_a_dir = dir.path().join("iamafile");
        std::fs::write(&not_a_dir, b"x").unwrap();
        let unwritable = not_a_dir.join(".nora-pins.ndjson");

        let store = HashPinStore::new(&unwritable);
        assert!(
            store.record_hash("k", &sha(b"data")).is_err(),
            "pin write to an unwritable path must return an error, not swallow it"
        );
        // The in-memory index must not claim a pin the disk never accepted.
        assert_eq!(
            store.get("k"),
            None,
            "failed pin write must not update memory"
        );
    }

    /// Regression for the disk-first TOCTOU: concurrent record_hash() calls for
    /// the SAME key with DIFFERENT hashes must leave the in-memory pin equal to
    /// what a fresh reload from disk sees — disk and memory cannot diverge.
    /// Holding the write lock across check → append → insert makes each call
    /// atomic per key; the earlier two-lock version could append in one order
    /// but insert in the other.
    #[test]
    fn test_concurrent_same_key_disk_memory_consistent() {
        use std::sync::Arc;
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);
        let store = Arc::new(HashPinStore::new(&path));
        let key = "concurrent/key";

        let handles: Vec<_> = (0..20)
            .map(|i| {
                let s = Arc::clone(&store);
                std::thread::spawn(move || {
                    let _ = s.record_hash(key, &sha(format!("data-{i}").as_bytes()));
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let in_memory = store.get(key);
        drop(store);
        // What survives a restart must equal what the live process holds.
        let reloaded = HashPinStore::new(&path);
        assert_eq!(
            in_memory,
            reloaded.get(key),
            "in-memory pin must match the durably-recorded pin (no TOCTOU divergence)"
        );
        assert!(in_memory.is_some(), "some writer must have recorded a pin");
    }
}
