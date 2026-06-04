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
use sha2::{Digest, Sha256};
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
    /// Returns the I/O error if the pin append fails, so the caller can fail
    /// closed rather than serve an artifact it could not pin. The in-memory
    /// index is updated only *after* the append succeeds — memory must never
    /// claim a pin the disk does not hold, or a `get()` after a failed `put()`
    /// would verify against a RAM-only pin that vanishes on restart, and a
    /// retried `put()` would skip the (still-missing) append.
    pub fn record(&self, key: &str, data: &[u8]) -> io::Result<()> {
        let hash = Self::sha256_hex(data);
        // Atomic per key: hold the write lock across check → append → insert.
        // The disk append happens before the in-memory update (durability), and
        // no concurrent record() for the same key can interleave its append and
        // insert with ours, so disk and memory cannot diverge. (An earlier
        // two-lock version — read-check, release, append, write-insert — had a
        // TOCTOU where two same-key writers' append and insert orders disagreed.)
        // The append is a ~100-byte line and record() runs on a blocking thread
        // (`spawn_blocking`), so holding the lock across it trades a little read
        // contention for correctness — the right call for a tamper-detection store.
        let mut pins = self.pins.write();
        if pins.get(key).is_none_or(|existing| *existing != hash) {
            Self::append_to_file(&self.path, key, &hash)?;
            pins.insert(key.to_string(), hash);
        }
        Ok(())
    }

    /// Record a pre-computed SHA-256 hash for a storage key.
    ///
    /// Used by streaming paths where the hash was already computed
    /// incrementally during download — avoids re-reading the file (#580).
    ///
    /// `hash` must be a lowercase hex-encoded SHA-256 (64 chars). Durability and
    /// ordering match [`HashPinStore::record`]: the pin is appended before the
    /// in-memory index is updated, and an I/O failure is returned to the caller.
    pub fn record_hash(&self, key: &str, hash: &str) -> io::Result<()> {
        debug_assert!(
            hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()),
            "record_hash: expected 64-char hex SHA-256, got: {hash}"
        );

        // Same atomic check → append → insert under one write lock as record().
        let mut pins = self.pins.write();
        if pins.get(key).is_none_or(|existing| *existing != hash) {
            Self::append_to_file(&self.path, key, hash)?;
            pins.insert(key.to_string(), hash.to_string());
        }
        Ok(())
    }

    /// Verify data integrity against pinned hash. Called on every `get()`.
    ///
    /// Returns `true` if the hash matches or no pin exists for this key.
    /// Returns `false` and logs a warning if tampering is detected.
    #[must_use = "ignoring verification result may allow tampered data"]
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
    /// Appends a tombstone before dropping the in-memory entry, returning any
    /// I/O error. A tombstone-write failure leaves the (now stale) pin in place;
    /// that is benign — `get()` on a deleted key fails at the inner backend
    /// before verification, and a later `put()` of the key overwrites the pin —
    /// so callers may treat a remove failure as non-fatal.
    pub fn remove(&self, key: &str) -> io::Result<()> {
        // Atomic tombstone: append + drop under one write lock (see record()).
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

    /// Number of pinned entries.
    pub fn len(&self) -> usize {
        self.pins.read().len()
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
    use tempfile::TempDir;

    fn pin_path(dir: &TempDir) -> PathBuf {
        dir.path().join(".nora-pins.ndjson")
    }

    #[test]
    fn test_record_and_verify() {
        let dir = TempDir::new().unwrap();
        let store = HashPinStore::new(pin_path(&dir));

        store
            .record("maven/com/example/1.0/app.jar", b"jar-content")
            .unwrap();
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

        store.record("npm/meta/express", b"v1").unwrap();
        assert!(store.verify("npm/meta/express", b"v1"));

        // Metadata update — pin is updated
        store.record("npm/meta/express", b"v2").unwrap();
        assert!(store.verify("npm/meta/express", b"v2"));
        assert!(!store.verify("npm/meta/express", b"v1"));
    }

    #[test]
    fn test_remove_pin() {
        let dir = TempDir::new().unwrap();
        let store = HashPinStore::new(pin_path(&dir));

        store.record("key", b"data").unwrap();
        assert_eq!(store.len(), 1);

        store.remove("key").unwrap();
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
            store.record("a", b"data-a").unwrap();
            store.record("b", b"data-b").unwrap();
            store.remove("b").unwrap();
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
            store.record("keep", b"data").unwrap();
            store.record("remove", b"data").unwrap();
            store.remove("remove").unwrap();
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
        store.record("key", b"data").unwrap();
        store.record("key", b"data").unwrap();

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
    fn test_record_hash_and_verify() {
        let dir = TempDir::new().unwrap();
        let store = HashPinStore::new(pin_path(&dir));

        // Pre-computed SHA-256 of b"streaming-data"
        let hash = HashPinStore::sha256_hex(b"streaming-data");
        store.record_hash("docker/blob/sha256:abc", &hash).unwrap();

        assert_eq!(store.len(), 1);
        assert!(store.verify("docker/blob/sha256:abc", b"streaming-data"));
        assert!(!store.verify("docker/blob/sha256:abc", b"tampered"));
    }

    #[test]
    fn test_record_hash_persists_on_reload() {
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);

        let hash = HashPinStore::sha256_hex(b"persistent");
        {
            let store = HashPinStore::new(&path);
            store.record_hash("key/hash", &hash).unwrap();
        }

        // Reload
        let store = HashPinStore::new(&path);
        assert_eq!(store.len(), 1);
        assert!(store.verify("key/hash", b"persistent"));
    }

    #[test]
    fn test_record_hash_idempotent() {
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);
        let store = HashPinStore::new(&path);

        let hash = HashPinStore::sha256_hex(b"data");
        store.record_hash("key", &hash).unwrap();
        store.record_hash("key", &hash).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1, "duplicate record_hash should be idempotent");
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
            store.record("k", b"data").is_err(),
            "pin write to an unwritable path must return an error, not swallow it"
        );
        // The in-memory index must not claim a pin the disk never accepted.
        assert_eq!(store.len(), 0, "failed pin write must not update memory");

        let hash = HashPinStore::sha256_hex(b"data");
        assert!(
            store.record_hash("k", &hash).is_err(),
            "record_hash must propagate the same I/O error"
        );
        assert_eq!(store.len(), 0, "failed record_hash must not update memory");
    }

    /// Regression for the disk-first TOCTOU: concurrent record() calls for the
    /// SAME key with DIFFERENT data must leave the in-memory pin equal to what a
    /// fresh reload from disk sees — disk and memory cannot diverge. Holding the
    /// write lock across check → append → insert makes each record() atomic per
    /// key; the earlier two-lock version could append in one order but insert in
    /// the other.
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
                    let _ = s.record(key, format!("data-{i}").as_bytes());
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
