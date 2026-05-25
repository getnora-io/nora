// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Digest quarantine — first-seen tracking for proxy-fetched artifacts.
//!
//! Tracks when a content digest was first seen by NORA's proxy layer.
//! New digests can be held in quarantine for a configurable duration,
//! providing a time-based supply chain defense for registries that lack
//! upstream publish dates (e.g. Docker/OCI).
//!
//! Persistence: append-only JSONL file, compacted on startup via atomic rewrite.
//! Fail-open: corrupt or missing JSONL → empty store, all pulls pass.

use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

/// Stale entry TTL: entries older than 90 days are pruned on startup.
const PRUNE_TTL_SECS: i64 = 90 * 24 * 3600;

// ============================================================================
// Quarantine Mode
// ============================================================================

/// Quarantine operating mode.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuarantineMode {
    /// Quarantine disabled (default).
    #[default]
    Off,
    /// Record + log, but don't block downloads.
    Observe,
    /// Block downloads for unknown/pending digests.
    Enforce,
}

impl QuarantineMode {
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "observe" => Self::Observe,
            "enforce" => Self::Enforce,
            _ => Self::Off,
        }
    }
}

// ============================================================================
// Digest Entry
// ============================================================================

/// A single quarantine record persisted in JSONL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestEntry {
    /// Registry type (e.g. "docker").
    pub registry: String,
    /// Content digest (e.g. "sha256:abc123...").
    pub digest: String,
    /// Unix timestamp (seconds) when first seen by NORA.
    pub first_seen: i64,
    /// Upstream that provided the content (e.g. "registry-1.docker.io").
    pub upstream: String,
}

// ============================================================================
// Quarantine Status
// ============================================================================

/// Result of checking a digest against the quarantine store.
#[derive(Debug, Clone, PartialEq)]
pub enum QuarantineStatus {
    /// Digest not seen before — just recorded.
    New,
    /// Digest known but still within quarantine window.
    Pending { remaining_secs: i64 },
    /// Digest has aged past the quarantine threshold.
    Mature,
}

impl QuarantineStatus {
    /// Value for the `X-Nora-Quarantine` response header.
    pub fn header_value(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Pending { .. } => "pending",
            Self::Mature => "mature",
        }
    }
}

// ============================================================================
// Digest Store
// ============================================================================

/// In-memory digest store backed by an append-only JSONL file.
///
/// Thread-safe via `parking_lot::RwLock`. Reads (check) take a shared lock,
/// writes (record) take an exclusive lock with double-check pattern.
pub struct DigestStore {
    entries: RwLock<HashMap<String, DigestEntry>>,
    path: PathBuf,
}

impl DigestStore {
    /// Load existing entries from JSONL, prune stale (>90d), compact file.
    ///
    /// Fail-open: corrupt lines are skipped, missing file → empty store.
    pub fn load(storage_path: &str) -> Self {
        let path = PathBuf::from(storage_path).join("quarantine.jsonl");
        let mut entries = HashMap::new();

        if path.exists() {
            match File::open(&path) {
                Ok(file) => {
                    let reader = BufReader::new(file);
                    let now = Utc::now().timestamp();
                    let cutoff = now - PRUNE_TTL_SECS;
                    let mut skipped = 0u32;

                    for line in reader.lines() {
                        let line = match line {
                            Ok(l) => l,
                            Err(e) => {
                                warn!(error = %e, "Skipping unreadable quarantine line");
                                skipped += 1;
                                continue;
                            }
                        };
                        if line.trim().is_empty() {
                            continue;
                        }
                        match serde_json::from_str::<DigestEntry>(&line) {
                            Ok(entry) => {
                                if entry.first_seen >= cutoff {
                                    let key = format!("{}:{}", entry.registry, entry.digest);
                                    entries.entry(key).or_insert(entry);
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "Skipping unparsable quarantine entry");
                                skipped += 1;
                            }
                        }
                    }

                    info!(
                        path = %path.display(),
                        entries = entries.len(),
                        skipped = skipped,
                        "Quarantine store loaded"
                    );
                }
                Err(e) => {
                    error!(
                        path = %path.display(),
                        error = %e,
                        "Failed to open quarantine file, starting empty (fail-open)"
                    );
                }
            }

            // Compact: atomic rewrite removes duplicates and pruned entries
            atomic_rewrite(&path, &entries);
        }

        Self {
            entries: RwLock::new(entries),
            path,
        }
    }

    /// Create an empty store (for tests or when quarantine is off).
    pub fn empty(storage_path: &str) -> Self {
        let path = PathBuf::from(storage_path).join("quarantine.jsonl");
        Self {
            entries: RwLock::new(HashMap::new()),
            path,
        }
    }

    /// Record a proxy-fetched digest. Returns the entry (existing or new).
    ///
    /// Idempotent: if the digest already exists, the original entry is returned.
    /// New entries are appended to JSONL asynchronously.
    pub fn record(&self, registry: &str, digest: &str, upstream: &str) -> DigestEntry {
        let key = format!("{}:{}", registry, digest);

        // Fast path: read lock
        {
            let entries = self.entries.read();
            if let Some(entry) = entries.get(&key) {
                return entry.clone();
            }
        }

        // Slow path: write lock
        let mut entries = self.entries.write();
        // Double-check after acquiring write lock
        if let Some(entry) = entries.get(&key) {
            return entry.clone();
        }

        let entry = DigestEntry {
            registry: registry.to_string(),
            digest: digest.to_string(),
            first_seen: Utc::now().timestamp(),
            upstream: upstream.to_string(),
        };

        entries.insert(key, entry.clone());
        append_jsonl(&self.path, &entry);
        entry
    }

    /// Record a locally-pushed digest as immediately mature.
    ///
    /// Sets `first_seen` to `now - quarantine_secs - 1` so the digest
    /// passes any quarantine check with threshold <= `quarantine_secs`.
    pub fn record_trusted(&self, registry: &str, digest: &str, quarantine_secs: i64) {
        let key = format!("{}:{}", registry, digest);
        let mut entries = self.entries.write();

        let entry = DigestEntry {
            registry: registry.to_string(),
            digest: digest.to_string(),
            first_seen: Utc::now().timestamp() - quarantine_secs - 1,
            upstream: "local".to_string(),
        };

        entries.insert(key, entry.clone());
        append_jsonl(&self.path, &entry);
    }

    /// Check quarantine status for a digest.
    #[must_use = "ignoring quarantine status may serve blocked artifacts"]
    pub fn check(&self, registry: &str, digest: &str, quarantine_secs: i64) -> QuarantineStatus {
        let key = format!("{}:{}", registry, digest);
        let entries = self.entries.read();

        match entries.get(&key) {
            None => QuarantineStatus::New,
            Some(entry) => {
                let age = Utc::now().timestamp() - entry.first_seen;
                if age >= quarantine_secs {
                    QuarantineStatus::Mature
                } else {
                    QuarantineStatus::Pending {
                        remaining_secs: quarantine_secs - age,
                    }
                }
            }
        }
    }

    /// Number of tracked digests.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }
}

// ============================================================================
// JSONL I/O helpers
// ============================================================================

/// Append a single entry to the JSONL file (async via spawn_blocking).
fn append_jsonl(path: &Path, entry: &DigestEntry) {
    let path = path.to_path_buf();
    let json = match serde_json::to_string(entry) {
        Ok(j) => j,
        Err(_) => return,
    };

    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    tokio::task::spawn_blocking(move || {
        match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(mut file) => {
                let _ = writeln!(file, "{}", json);
                let _ = file.flush();
            }
            Err(e) => {
                error!(
                    path = %path.display(),
                    error = %e,
                    "Failed to append quarantine entry (fail-open)"
                );
            }
        }
    });
}

/// Rewrite JSONL atomically: write temp file → fsync → rename.
///
/// Crash-safe: partial write leaves the old file intact.
fn atomic_rewrite(path: &Path, entries: &HashMap<String, DigestEntry>) {
    if entries.is_empty() {
        let _ = fs::remove_file(path);
        return;
    }

    let tmp_path = path.with_extension("jsonl.tmp");

    match File::create(&tmp_path) {
        Ok(mut file) => {
            for entry in entries.values() {
                if let Ok(json) = serde_json::to_string(entry) {
                    let _ = writeln!(file, "{}", json);
                }
            }
            if file.flush().is_ok() && file.sync_all().is_ok() {
                if let Err(e) = fs::rename(&tmp_path, path) {
                    error!(error = %e, "Failed to rename quarantine temp file");
                    let _ = fs::remove_file(&tmp_path);
                }
            } else {
                let _ = fs::remove_file(&tmp_path);
            }
        }
        Err(e) => {
            error!(error = %e, "Failed to create quarantine temp file");
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_quarantine_mode_from_str() {
        assert_eq!(QuarantineMode::from_str_lossy("off"), QuarantineMode::Off);
        assert_eq!(
            QuarantineMode::from_str_lossy("observe"),
            QuarantineMode::Observe
        );
        assert_eq!(
            QuarantineMode::from_str_lossy("enforce"),
            QuarantineMode::Enforce
        );
        assert_eq!(
            QuarantineMode::from_str_lossy("anything"),
            QuarantineMode::Off
        );
        assert_eq!(
            QuarantineMode::from_str_lossy("OBSERVE"),
            QuarantineMode::Observe
        );
        assert_eq!(
            QuarantineMode::from_str_lossy("ENFORCE"),
            QuarantineMode::Enforce
        );
    }

    #[test]
    fn test_quarantine_mode_default_is_off() {
        assert_eq!(QuarantineMode::default(), QuarantineMode::Off);
    }

    #[test]
    fn test_check_unknown_digest_is_new() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(tmp.path().to_str().unwrap());

        let status = store.check("docker", "sha256:abc123", 86400);
        assert_eq!(status, QuarantineStatus::New);
    }

    #[tokio::test]
    async fn test_record_then_check_pending() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(tmp.path().to_str().unwrap());

        store.record("docker", "sha256:abc123", "registry-1.docker.io");

        let status = store.check("docker", "sha256:abc123", 86400);
        match status {
            QuarantineStatus::Pending { remaining_secs } => {
                assert!(remaining_secs > 0);
                assert!(remaining_secs <= 86400);
            }
            other => panic!("Expected Pending, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_record_then_check_mature_zero_ttl() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(tmp.path().to_str().unwrap());

        store.record("docker", "sha256:abc123", "registry-1.docker.io");

        // TTL=0 → immediately mature
        let status = store.check("docker", "sha256:abc123", 0);
        assert_eq!(status, QuarantineStatus::Mature);
    }

    #[tokio::test]
    async fn test_record_trusted_immediately_mature() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(tmp.path().to_str().unwrap());

        store.record_trusted("docker", "sha256:local123", 86400);

        let status = store.check("docker", "sha256:local123", 86400);
        assert_eq!(status, QuarantineStatus::Mature);
    }

    #[tokio::test]
    async fn test_record_idempotent() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(tmp.path().to_str().unwrap());

        let entry1 = store.record("docker", "sha256:abc", "upstream1");
        let entry2 = store.record("docker", "sha256:abc", "upstream2");

        assert_eq!(entry1.first_seen, entry2.first_seen);
        assert_eq!(entry1.upstream, entry2.upstream);
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn test_registry_isolation() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(tmp.path().to_str().unwrap());

        store.record("docker", "sha256:abc", "docker-upstream");
        store.record("npm", "sha256:abc", "npmjs.org");

        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_persistence_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().to_str().unwrap();
        let jsonl_path = tmp.path().join("quarantine.jsonl");

        // Write JSONL directly (bypass async spawn_blocking in record())
        let now = Utc::now().timestamp();
        let entries = [
            DigestEntry {
                registry: "docker".into(),
                digest: "sha256:aaa".into(),
                first_seen: now,
                upstream: "upstream1".into(),
            },
            DigestEntry {
                registry: "docker".into(),
                digest: "sha256:bbb".into(),
                first_seen: now,
                upstream: "upstream2".into(),
            },
        ];
        {
            let mut file = std::fs::File::create(&jsonl_path).unwrap();
            for e in &entries {
                writeln!(file, "{}", serde_json::to_string(e).unwrap()).unwrap();
            }
            file.flush().unwrap();
        }

        let store = DigestStore::load(path);
        assert_eq!(store.len(), 2);

        let status = store.check("docker", "sha256:aaa", 86400);
        assert!(matches!(status, QuarantineStatus::Pending { .. }));
    }

    #[test]
    fn test_load_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::load(tmp.path().to_str().unwrap());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_load_corrupt_file_fail_open() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("quarantine.jsonl");

        let now = Utc::now().timestamp();
        let valid = serde_json::json!({
            "registry": "docker",
            "digest": "sha256:good",
            "first_seen": now,
            "upstream": "up"
        });
        std::fs::write(&path, format!("not json\n{}\ngarbage\n", valid)).unwrap();

        let store = DigestStore::load(tmp.path().to_str().unwrap());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_prune_stale_entries() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("quarantine.jsonl");

        let now = Utc::now().timestamp();
        let old_ts = now - (91 * 24 * 3600); // 91 days — stale
        let fresh_ts = now - (10 * 24 * 3600); // 10 days — kept

        let old = serde_json::json!({
            "registry": "docker", "digest": "sha256:old",
            "first_seen": old_ts, "upstream": "up"
        });
        let fresh = serde_json::json!({
            "registry": "docker", "digest": "sha256:fresh",
            "first_seen": fresh_ts, "upstream": "up"
        });
        std::fs::write(&path, format!("{}\n{}\n", old, fresh)).unwrap();

        let store = DigestStore::load(tmp.path().to_str().unwrap());
        assert_eq!(store.len(), 1);

        assert!(matches!(
            store.check("docker", "sha256:fresh", 86400),
            QuarantineStatus::Mature
        ));
        assert_eq!(
            store.check("docker", "sha256:old", 86400),
            QuarantineStatus::New
        );
    }

    #[test]
    fn test_quarantine_status_header_values() {
        assert_eq!(QuarantineStatus::New.header_value(), "new");
        assert_eq!(
            QuarantineStatus::Pending {
                remaining_secs: 100
            }
            .header_value(),
            "pending"
        );
        assert_eq!(QuarantineStatus::Mature.header_value(), "mature");
    }

    #[test]
    fn test_atomic_rewrite_compacts_duplicates() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("quarantine.jsonl");

        let now = Utc::now().timestamp();
        let entry = serde_json::json!({
            "registry": "docker", "digest": "sha256:dup",
            "first_seen": now, "upstream": "up"
        });
        std::fs::write(&path, format!("{}\n{}\n{}\n", entry, entry, entry)).unwrap();

        let store = DigestStore::load(tmp.path().to_str().unwrap());
        assert_eq!(store.len(), 1);

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 1);
    }

    #[test]
    fn test_empty_store_is_empty() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(tmp.path().to_str().unwrap());
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_digest_entry_serialization() {
        let entry = DigestEntry {
            registry: "docker".to_string(),
            digest: "sha256:abc".to_string(),
            first_seen: 1700000000,
            upstream: "registry-1.docker.io".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"registry\":\"docker\""));
        assert!(json.contains("\"first_seen\":1700000000"));

        let parsed: DigestEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.digest, "sha256:abc");
    }
}
