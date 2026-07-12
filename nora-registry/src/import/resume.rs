//! Filesystem resume oracle — no DB (ADR-2, #599).
//!
//! Two authoritative on-disk structures under `<state_root>/.nora-import/<host>/`
//! (a `.nora-` prefix, filtered out of `list`/GC like `.nora-pins.ndjson`):
//!
//! - **`<repo>.done`** — written atomically (`tmp → fsync → rename → fsync dir`)
//!   only after a repo is fully walked. A `.done` repo is skipped whole on
//!   restart, without touching the journal (fast-path; no per-object S3 HEAD).
//! - **`<repo>.progress`** — an append-only NDJSON journal, one line per
//!   committed artifact. On resume it rebuilds an in-memory `HashSet` of
//!   committed keys (rebuildable-from-disk invariant). A torn last line from a
//!   crash mid-append is tolerated (skipped).
//!
//! This journal is the **authoritative** skip oracle (review R5); a
//! `storage.stat(key)` CAS check is only a fast-path the orchestrator may add on
//! the local backend. Strict ordering the orchestrator MUST keep (contract
//! `import-resume-journal-authoritative`): commit → journal line+fsync → advance
//! cursor; `.done` only after end-of-cursor AND the final journal fsync.
//!
//! Every source-controlled string is tainted: the host and repo are sanitized +
//! hashed into filenames so a `repo` of `../../etc` can never escape the control
//! directory (review R7) — these are NOT storage keys and bypass
//! `validate_storage_key`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use super::Result;

/// Per-source-host control directory: `<state_root>/.nora-import/<host-hash>/`.
pub struct ResumeStore {
    dir: PathBuf,
}

impl ResumeStore {
    /// Open (creating if needed) the control directory for `source_host`.
    pub async fn open(state_root: &Path, source_host: &str) -> Result<Self> {
        let dir = state_root
            .join(".nora-import")
            .join(hash_hex(source_host, 16));
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| format!("create resume dir {}: {e}", dir.display()))?;
        Ok(Self { dir })
    }

    fn done_path(&self, repo: &str) -> PathBuf {
        self.dir.join(format!("{}.done", repo_stem(repo)))
    }

    fn progress_path(&self, repo: &str) -> PathBuf {
        self.dir.join(format!("{}.progress", repo_stem(repo)))
    }

    /// Has this repo been fully imported in a prior run?
    pub fn is_repo_done(&self, repo: &str) -> bool {
        self.done_path(repo).exists()
    }

    /// Load (or start) the append journal for `repo`, rebuilding the set of
    /// already-committed keys from disk.
    pub async fn open_journal(&self, repo: &str) -> Result<RepoJournal> {
        let path = self.progress_path(repo);
        let mut seen = HashSet::new();
        if let Ok(contents) = tokio::fs::read_to_string(&path).await {
            for line in contents.lines() {
                // Tolerate a torn final line (crash mid-append): skip unparsable.
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    if let Some(k) = v.get("key").and_then(|k| k.as_str()) {
                        seen.insert(k.to_string());
                    }
                }
            }
        }
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .map_err(|e| format!("open journal {}: {e}", path.display()))?;
        Ok(RepoJournal {
            seen,
            file,
            path,
            since_sync: 0,
        })
    }

    /// Atomically publish the `.done` marker for `repo` (tmp → fsync → rename →
    /// fsync dir). MUST be called only after the repo's cursor is exhausted and
    /// the journal's final `sync()` has returned.
    pub async fn mark_repo_done(&self, repo: &str) -> Result<()> {
        let dest = self.done_path(repo);
        let tmp = dest.with_extension("done.tmp");
        {
            let mut f = tokio::fs::File::create(&tmp)
                .await
                .map_err(|e| format!("create done tmp: {e}"))?;
            f.write_all(b"done\n")
                .await
                .map_err(|e| format!("write done: {e}"))?;
            f.sync_all().await.map_err(|e| format!("fsync done: {e}"))?;
        }
        tokio::fs::rename(&tmp, &dest)
            .await
            .map_err(|e| format!("rename done: {e}"))?;
        sync_dir(&self.dir).await;
        Ok(())
    }
}

/// Append-only NDJSON journal of committed artifacts for one repo.
pub struct RepoJournal {
    seen: HashSet<String>,
    file: tokio::fs::File,
    path: PathBuf,
    since_sync: usize,
}

/// fsync the journal at least this often (a crash loses only the un-synced tail,
/// which re-imports idempotently — `put_from_path` is an atomic rename over
/// identical content, so a double-commit is a no-op).
const SYNC_EVERY: usize = 64;

impl RepoJournal {
    /// Append a committed artifact's key+digest. Call AFTER `put_from_path`
    /// succeeds and BEFORE advancing the source cursor (review R5, SRE #4).
    pub async fn record(&mut self, key: &str, sha256: &str) -> Result<()> {
        let line = format!("{}\n", serde_json::json!({ "key": key, "sha256": sha256 }));
        self.file
            .write_all(line.as_bytes())
            .await
            .map_err(|e| format!("append journal {}: {e}", self.path.display()))?;
        self.seen.insert(key.to_string());
        self.since_sync += 1;
        if self.since_sync >= SYNC_EVERY {
            self.sync().await?;
        }
        Ok(())
    }

    /// Flush + fsync the journal. MUST be awaited before `mark_repo_done`.
    pub async fn sync(&mut self) -> Result<()> {
        self.file
            .flush()
            .await
            .map_err(|e| format!("flush journal: {e}"))?;
        self.file
            .sync_all()
            .await
            .map_err(|e| format!("fsync journal: {e}"))?;
        self.since_sync = 0;
        Ok(())
    }

    /// A clone of the prior-run committed set, for read-only skip decisions in a
    /// concurrent section (so the append writer stays a single, uncontended owner).
    pub fn snapshot(&self) -> HashSet<String> {
        self.seen.clone()
    }
}

/// Sanitize a tainted source `repo` into a safe, collision-resistant filename
/// stem: an ASCII-safe truncation for human readability, plus a short content
/// hash so distinct repos that sanitize to the same string never share a file.
/// A `repo` of `../../etc` becomes `_.._.._etc__<hash>` — inside the dir, never a
/// path escape.
fn repo_stem(repo: &str) -> String {
    let safe: String = repo
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    // Strip leading/trailing dots, then collapse any interior `..` so the stem
    // can never be, contain, or be confused with a parent-dir reference.
    let safe = safe.trim_matches('.').replace("..", "_");
    let truncated: String = safe.chars().take(48).collect();
    format!("{truncated}__{}", hash_hex(repo, 8))
}

/// Lowercase hex of the first `bytes` bytes of `sha256(input)`.
fn hash_hex(input: &str, bytes: usize) -> String {
    let digest = Sha256::digest(input.as_bytes());
    hex::encode(&digest[..bytes.min(digest.len())])
}

/// Best-effort fsync of a directory so a just-renamed entry is crash-durable.
async fn sync_dir(dir: &Path) {
    if let Ok(f) = tokio::fs::File::open(dir).await {
        let _ = f.sync_all().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn journal_roundtrips_and_rebuilds_from_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ResumeStore::open(tmp.path(), "https://art.example.com")
            .await
            .unwrap();

        let mut j = store.open_journal("libs-release").await.unwrap();
        assert!(!j.snapshot().contains("maven/a/b.jar"));
        j.record("maven/a/b.jar", "abc").await.unwrap();
        j.record("maven/c/d.jar", "def").await.unwrap();
        j.sync().await.unwrap();
        assert!(j.snapshot().contains("maven/a/b.jar"));

        // Reopen: the set is rebuilt purely from disk (no RAM-only state).
        let j2 = store.open_journal("libs-release").await.unwrap();
        let seen = j2.snapshot();
        assert!(seen.contains("maven/a/b.jar"));
        assert!(seen.contains("maven/c/d.jar"));
        assert!(!seen.contains("maven/x/y.jar"));
        assert_eq!(seen.len(), 2);
    }

    #[tokio::test]
    async fn done_marker_is_persistent() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ResumeStore::open(tmp.path(), "nexus.local").await.unwrap();
        assert!(!store.is_repo_done("maven-releases"));
        store.mark_repo_done("maven-releases").await.unwrap();
        assert!(store.is_repo_done("maven-releases"));

        // A fresh store over the same root still sees it done.
        let store2 = ResumeStore::open(tmp.path(), "nexus.local").await.unwrap();
        assert!(store2.is_repo_done("maven-releases"));
    }

    #[tokio::test]
    async fn torn_last_line_is_tolerated() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ResumeStore::open(tmp.path(), "h").await.unwrap();
        let mut j = store.open_journal("r").await.unwrap();
        j.record("k1", "s1").await.unwrap();
        j.sync().await.unwrap();
        // Simulate a crash mid-append: a partial JSON line with no newline.
        let mut raw = tokio::fs::OpenOptions::new()
            .append(true)
            .open(store.progress_path("r"))
            .await
            .unwrap();
        raw.write_all(b"{\"key\": \"k2\", \"sha").await.unwrap();
        raw.sync_all().await.unwrap();
        drop(raw);

        let seen = store.open_journal("r").await.unwrap().snapshot();
        assert!(seen.contains("k1")); // valid line survives
        assert!(!seen.contains("k2")); // torn line ignored
    }

    #[test]
    fn repo_stem_sanitizes_traversal_and_is_distinct() {
        let a = repo_stem("../../etc");
        assert!(
            !a.contains('/'),
            "stem must not contain a path separator: {a}"
        );
        assert!(!a.contains(".."), "stem must not contain ..: {a}");
        // Distinct repos → distinct stems even if they sanitize alike.
        assert_ne!(repo_stem("a/b"), repo_stem("a_b"));
        assert_ne!(repo_stem("libs-release"), repo_stem("libs-snapshot"));
    }

    #[tokio::test]
    async fn record_triggers_periodic_fsync() {
        // Recording past SYNC_EVERY (64) triggers the in-loop sync(); all survive.
        let tmp = tempfile::tempdir().unwrap();
        let store = ResumeStore::open(tmp.path(), "h").await.unwrap();
        let mut j = store.open_journal("r").await.unwrap();
        for i in 0..70 {
            j.record(&format!("k{i}"), "sha").await.unwrap();
        }
        assert_eq!(j.snapshot().len(), 70);
        // Rebuilt from disk confirms the periodic fsync persisted them.
        assert_eq!(store.open_journal("r").await.unwrap().snapshot().len(), 70);
    }
}
