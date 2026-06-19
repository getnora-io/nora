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

use axum::http::{header, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};

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

impl std::fmt::Display for QuarantineMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Off => write!(f, "off"),
            Self::Observe => write!(f, "observe"),
            Self::Enforce => write!(f, "enforce"),
        }
    }
}

impl std::str::FromStr for QuarantineMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "observe" => Ok(Self::Observe),
            "enforce" => Ok(Self::Enforce),
            other => Err(format!(
                "unknown quarantine mode {:?} — valid values: off, observe, enforce",
                other
            )),
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

    // NOTE: the ledger records PROXY-fetched content only. Locally-pushed artifacts
    // are intentionally NOT recorded — the cooldown is a control on content arriving
    // from upstream, and the serve gate treats an unrecorded digest (`New`) as "serve".
    // A prior `record_trusted` matured local pushes here; it was removed because it
    // wrote the same key the proxy `check` reads, letting a local push set the
    // first-seen clock for a digest later fetched from upstream.

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
// Generic proxy quarantine gate
// ============================================================================
//
// Registry-agnostic generalization of the digest-quarantine wiring that
// previously lived only in the Docker handler. min-release-age cannot give a
// trustworthy release age on the proxy path (upstream dates are unsigned and
// spoofable, and several registries expose no date at all), so first-seen
// quarantine — keyed on the artifact's content digest and NORA's own clock — is
// the unspoofable supply-chain control that works for every proxy registry.

/// Resolve the effective quarantine `(mode, ttl_secs)` from the global curation
/// config. Returns `(Off, 0)` when disabled. Per-registry overrides can be
/// layered on top later; the proxy gate uses the global setting for now.
pub fn resolve_global(mode: Option<&QuarantineMode>, ttl: Option<&str>) -> (QuarantineMode, i64) {
    let mode = mode.cloned().unwrap_or(QuarantineMode::Off);
    if matches!(mode, QuarantineMode::Off) {
        return (QuarantineMode::Off, 0);
    }
    let secs = crate::curation::parse_duration(ttl.unwrap_or("14d")).unwrap_or(14 * 86400);
    (mode, secs)
}

/// Post-fetch / pre-serve quarantine gate for a proxy-fetched artifact.
///
/// Records the artifact's content digest as first-seen, then checks maturity.
/// Returns `Some(403)` to BLOCK (enforce mode, not yet mature), `None` to serve.
/// In observe mode it logs but never blocks. Idempotent: `record` preserves the
/// earliest `first_seen`, so calling this on every request (proxy fetch or cache
/// hit) is safe and the quarantine clock does not reset.
#[must_use = "the returned response blocks a quarantined artifact; dropping it serves the artifact"]
pub fn proxy_gate(
    store: &DigestStore,
    registry: &str,
    bytes: &[u8],
    mode: &QuarantineMode,
    quarantine_secs: i64,
    upstream: &str,
) -> Option<Response> {
    if matches!(mode, QuarantineMode::Off) {
        return None;
    }
    use sha2::Digest;
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)));
    store.record(registry, &digest, upstream);
    let status = store.check(registry, &digest, quarantine_secs);
    if matches!(status, QuarantineStatus::Mature) {
        return None;
    }
    warn!(
        registry = %registry,
        digest = %digest,
        status = %status.header_value(),
        mode = %mode,
        "quarantine: proxy artifact held (new to this mirror)"
    );
    if matches!(mode, QuarantineMode::Enforce) {
        Some(quarantine_forbidden(&digest, &status, quarantine_secs))
    } else {
        None
    }
}

/// Build a generic 403 for a quarantined proxy artifact (non-Docker shape).
fn quarantine_forbidden(digest: &str, status: &QuarantineStatus, quarantine_secs: i64) -> Response {
    let remaining = match status {
        QuarantineStatus::New => quarantine_secs,
        QuarantineStatus::Pending { remaining_secs } => *remaining_secs,
        QuarantineStatus::Mature => 0,
    };
    let quarantine_until = Utc::now().timestamp() + remaining;
    let body = serde_json::json!({
        "error": "quarantine",
        "message": "artifact held: new to this mirror",
        "detail": {
            "digest": digest,
            "quarantine_until": quarantine_until,
            "remaining_secs": remaining,
        }
    });
    (
        StatusCode::FORBIDDEN,
        [
            (
                HeaderName::from_static("x-nora-quarantine"),
                status.header_value(),
            ),
            (header::CONTENT_TYPE, "application/json"),
        ],
        body.to_string(),
    )
        .into_response()
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
        assert_eq!(
            "off".parse::<QuarantineMode>().unwrap(),
            QuarantineMode::Off
        );
        assert_eq!(
            "observe".parse::<QuarantineMode>().unwrap(),
            QuarantineMode::Observe
        );
        assert_eq!(
            "enforce".parse::<QuarantineMode>().unwrap(),
            QuarantineMode::Enforce
        );
        // Case insensitive
        assert_eq!(
            "OBSERVE".parse::<QuarantineMode>().unwrap(),
            QuarantineMode::Observe
        );
        assert_eq!(
            "ENFORCE".parse::<QuarantineMode>().unwrap(),
            QuarantineMode::Enforce
        );
        assert_eq!(
            "Off".parse::<QuarantineMode>().unwrap(),
            QuarantineMode::Off
        );
    }

    #[test]
    fn test_quarantine_mode_rejects_invalid() {
        assert!("anything".parse::<QuarantineMode>().is_err());
        assert!("eforce".parse::<QuarantineMode>().is_err());
        assert!("enabled".parse::<QuarantineMode>().is_err());
        assert!("on".parse::<QuarantineMode>().is_err());
        assert!("".parse::<QuarantineMode>().is_err());
        // Error message includes valid values
        let err = "typo".parse::<QuarantineMode>().unwrap_err();
        assert!(err.contains("off"), "error should list valid values: {err}");
        assert!(
            err.contains("observe"),
            "error should list valid values: {err}"
        );
        assert!(
            err.contains("enforce"),
            "error should list valid values: {err}"
        );
    }

    #[test]
    fn test_quarantine_mode_display_roundtrip() {
        for mode in [
            QuarantineMode::Off,
            QuarantineMode::Observe,
            QuarantineMode::Enforce,
        ] {
            let s = mode.to_string();
            let parsed: QuarantineMode = s.parse().unwrap();
            assert_eq!(mode, parsed);
        }
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
    async fn test_unrecorded_digest_is_new() {
        // The ledger tracks proxy-fetched content only. A digest that was never
        // proxy-recorded (e.g. a locally-pushed artifact, which is deliberately not
        // recorded) reads as `New`. The cache-serve gate treats `New` as "serve" and
        // blocks only `Pending`, so a local push is served and can never set the
        // first-seen clock for — or mature — a digest on the proxy path.
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(tmp.path().to_str().unwrap());

        let status = store.check("docker", "sha256:never_seen", 86400);
        assert_eq!(status, QuarantineStatus::New);
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
