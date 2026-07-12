//! Per-artifact transfer pipeline (#599): stream → fsync → verify → curate →
//! commit. Templated on the PROXY handler path (streaming), NOT the mirror
//! consumer which `tokio::fs::read`s the whole file → OOM at TB-scale (review R5).
//!
//! Invariants baked in here:
//! - **verify-before-commit, fail-closed** (R8): a checksum mismatch, or an
//!   artifact we cannot verify from source, leaves *nothing* in storage (the
//!   storage backend is never called).
//! - **durable commit** (R4): the temp file is `sync_all()`'d (not just flushed)
//!   before the atomic rename — the same-fs rename branch of local
//!   `put_from_path` relies on the caller having fsync'd the source data.
//! - **curation not bypassed** (R1): the full `CurationEngine::evaluate` chain
//!   runs, honoring audit-mode (audit Block commits, matching the proxy).
//! - **at-rest integrity degrades on S3** (R6): the sha256 pin is recorded only
//!   on the local backend; the orchestrator emits the loud WARN, this path stays
//!   honest that verify-before-commit closes *transfer*, not *at-rest*, integrity.

use std::path::{Path, PathBuf};

use axum::body::Bytes;
use futures::stream::BoxStream;
use futures::StreamExt;
use sha2::Digest;

use super::{ArtifactRef, Result, SourceRegistry};
use crate::curation::{CurationEngine, Decision, FilterRequest};
use crate::registry_type::RegistryType;
use crate::storage::Storage;

/// RAII guard that deletes a temp file on drop unless disarmed. Import owns its
/// own copy rather than reaching into `registry::docker::TempFileGuard` (whose
/// `disarm` is module-private) so the import→registry boundary stays clean while
/// reusing the exact crash-safe delete-on-drop shape (#580, review R-Linus4).
struct TempFileGuard {
    path: Option<PathBuf>,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }
    /// Caller took ownership of cleanup (storage moved/deleted the file).
    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(ref p) = self.path {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Outcome of transferring one artifact. The orchestrator folds this into the
/// `total/imported/skipped/failed/bytes` tally.
#[derive(Debug)]
pub enum Outcome {
    /// Committed (or, in `--dry-run`, streamed+verified and *would* commit). The
    /// verified sha256 is carried so the orchestrator can journal it.
    Imported { bytes: u64, sha256: String },
    /// Intentionally not imported (curation enforce-Block, sha1-only without
    /// `--allow-sha1`, unsupported layout) — counts `skipped`.
    Skipped { reason: String },
    /// Verification/transfer failure (checksum mismatch, no checksum, IO,
    /// download error) — counts `failed`; nothing committed (fail-closed).
    Failed { reason: String },
}

/// Options threaded from the CLI into every transfer.
#[derive(Debug, Clone, Copy)]
pub struct TransferOpts {
    /// Stream + hash + verify + curate, but commit nothing (rehearsal).
    pub dry_run: bool,
    /// Permit committing sha1-only artifacts (marked weak provenance). SHA-1 is
    /// collision-broken, so this is opt-in (review R8).
    pub allow_sha1: bool,
}

/// Provenance strength derived from which source digest we can verify against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provenance {
    /// Source advertised a sha256 we verified — tamper-evident.
    Strong,
    /// Only a (collision-broken) sha1 was verified — transport integrity only.
    Weak,
}

/// R8 policy, applied BEFORE download so we never move bytes we can't verify.
enum VerifyPlan {
    Verify(Provenance),
    Skip(&'static str),
    Fail(&'static str),
}

fn plan_verification(a: &ArtifactRef, allow_sha1: bool) -> VerifyPlan {
    if a.sha256.is_some() {
        VerifyPlan::Verify(Provenance::Strong)
    } else if a.sha1.is_some() {
        if allow_sha1 {
            VerifyPlan::Verify(Provenance::Weak)
        } else {
            VerifyPlan::Skip(
                "sha1-only artifact; pass --allow-sha1 to import (SHA-1 is collision-broken)",
            )
        }
    } else {
        VerifyPlan::Fail(
            "no source checksum advertised; refusing to import an unverifiable artifact",
        )
    }
}

/// Stream one artifact to a temp file (incremental sha256+sha1), fsync it, verify
/// the source-advertised checksum, run curation, and — unless dry-run — commit it
/// atomically under `key`. `temp_dir` MUST be on the same filesystem as the local
/// storage root so the commit is an atomic rename.
#[allow(clippy::too_many_arguments)]
pub async fn transfer_artifact(
    source: &dyn SourceRegistry,
    artifact: &ArtifactRef,
    key: &str,
    rt: RegistryType,
    curation_name: &str,
    source_host: &str,
    storage: &Storage,
    curation: &CurationEngine,
    temp_dir: &Path,
    opts: TransferOpts,
) -> Outcome {
    // R8: decide verifiability up front — a no-checksum or ungated sha1-only
    // artifact never even gets downloaded.
    let provenance = match plan_verification(artifact, opts.allow_sha1) {
        VerifyPlan::Verify(p) => p,
        VerifyPlan::Skip(r) => {
            return Outcome::Skipped {
                reason: r.to_string(),
            }
        }
        VerifyPlan::Fail(r) => {
            return Outcome::Failed {
                reason: format!("{} ({})", r, artifact.path),
            }
        }
    };

    // 1. Stream → temp (peak RAM O(chunk)), hashing both digests incrementally.
    let stream = match source.download_stream(artifact).await {
        Ok(s) => s,
        Err(e) => {
            return Outcome::Failed {
                reason: format!("download {}: {e}", artifact.path),
            }
        }
    };
    let staged = match stage_to_temp(stream, temp_dir).await {
        Ok(s) => s,
        Err(e) => {
            return Outcome::Failed {
                reason: format!("stage {}: {e}", artifact.path),
            }
        }
    };
    let Staged {
        path: temp_path,
        mut guard,
        sha256,
        sha1,
        bytes,
    } = staged;

    // 2b. Truncation check: if the source advertised a size, a short/long body is
    // a corrupt transfer — fail-closed before hashing means anything.
    if let Some(expected) = artifact.size {
        if expected != bytes {
            return Outcome::Failed {
                reason: format!(
                    "size mismatch for {} ({}): source {expected} != downloaded {bytes}",
                    artifact.path, artifact.name
                ),
            };
        }
    }

    // 3. VERIFY advertised checksum vs local digest BEFORE commit (fail-closed).
    if let Err(reason) = verify_checksum(artifact, &sha256, &sha1, provenance) {
        return Outcome::Failed { reason }; // guard drops temp; storage untouched
    }

    // 4. CURATION — full engine chain, honoring audit-mode (review R1). The
    // integrity we pass is the digest of the bytes that actually arrived.
    let req = FilterRequest {
        registry: rt,
        upstream: Some(source_host.to_string()),
        name: curation_name.to_string(),
        // Best-effort: adapters can't always supply version/publish-date, so
        // date/version-keyed rules may no-op on some sources (Kelsey #4, an
        // accepted, documented asymmetry — not silent Allow-by-omission for the
        // integrity/namespace/blocklist rules, which DO run).
        version: None,
        integrity: Some(format!("sha256:{sha256}")),
        bypass: false,
        publish_date: None,
    };
    let result = curation.evaluate(&req);
    if !should_commit(&result.decision, result.audited) {
        return Outcome::Skipped {
            reason: format!(
                "curation blocked by {}",
                result.decided_by.as_deref().unwrap_or("policy")
            ),
        };
    }

    // 5. COMMIT (unless dry-run, which has already streamed+hashed+verified).
    if opts.dry_run {
        return Outcome::Imported { bytes, sha256 }; // rehearsal — guard drops temp
    }
    let _ = provenance; // (Weak provenance is surfaced by the orchestrator's report, not here.)
    match storage.put_from_path(key, &temp_path, Some(&sha256)).await {
        Ok(()) => {
            guard.disarm(); // storage moved the temp file into place
            Outcome::Imported { bytes, sha256 }
        }
        Err(e) => Outcome::Failed {
            reason: format!("commit {key}: {e}"),
        },
    }
}

/// A staged temp file plus its incrementally-computed digests.
struct Staged {
    path: PathBuf,
    guard: TempFileGuard,
    sha256: String,
    sha1: String,
    bytes: u64,
}

async fn stage_to_temp(
    mut stream: BoxStream<'static, Result<Bytes>>,
    temp_dir: &Path,
) -> Result<Staged> {
    tokio::fs::create_dir_all(temp_dir)
        .await
        .map_err(|e| format!("create temp dir: {e}"))?;
    let temp_path = temp_dir.join(format!("import-{}", uuid::Uuid::new_v4()));
    let guard = TempFileGuard::new(temp_path.clone());
    let mut file = tokio::fs::File::create(&temp_path)
        .await
        .map_err(|e| format!("create temp file: {e}"))?;

    let mut h256 = sha2::Sha256::new();
    // SAFETY(deprecated-hash-algo): SHA-1 is intentional and reviewed here — it is
    // NOT a security digest, only used to verify a source-advertised sha1 for
    // legacy sha1-only artifacts (old Artifactory/Nexus Maven), which are gated
    // behind --allow-sha1 and marked weak provenance (review R8). The commit pin
    // is always the sha256 above.
    let mut h1 = sha1::Sha1::new(); // nosemgrep: deprecated-hash-algo
    let mut bytes: u64 = 0;
    use tokio::io::AsyncWriteExt;
    while let Some(chunk) = stream.next().await {
        // A stalled body surfaces here as the client's read-timeout Err.
        let chunk = chunk?;
        h256.update(&chunk);
        h1.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|e| format!("write temp: {e}"))?;
        bytes += chunk.len() as u64;
    }

    // R4: sync_all (NOT just flush). flush() only hands bytes to the OS; the
    // same-fs rename branch of local put_from_path (storage/local.rs) fsyncs only
    // the parent dir and relies on the caller having fsync'd the src data. A
    // migration tool cannot leave a torn/zero artifact at a committed key that
    // the resume journal then marks done and never re-fetches.
    file.flush().await.map_err(|e| format!("flush temp: {e}"))?;
    file.sync_all()
        .await
        .map_err(|e| format!("fsync temp: {e}"))?;
    drop(file);

    let sha256 = hex::encode(h256.finalize());
    let sha1 = hex::encode(h1.finalize());
    Ok(Staged {
        path: temp_path,
        guard,
        sha256,
        sha1,
        bytes,
    })
}

/// Compare the source-advertised digest to the locally-computed one for the
/// planned provenance. Case-insensitive hex; fail-closed on mismatch.
fn verify_checksum(
    a: &ArtifactRef,
    sha256_local: &str,
    sha1_local: &str,
    provenance: Provenance,
) -> std::result::Result<(), String> {
    let (label, want, got) = match provenance {
        Provenance::Strong => ("sha256", a.sha256.as_deref().unwrap_or(""), sha256_local),
        Provenance::Weak => ("sha1", a.sha1.as_deref().unwrap_or(""), sha1_local),
    };
    if want.eq_ignore_ascii_case(got) {
        Ok(())
    } else {
        Err(format!(
            "{label} mismatch for {}: source {} != local {}",
            a.path,
            short(want),
            short(got)
        ))
    }
}

/// Whether an [`EvaluationResult`](crate::curation::EvaluationResult) permits a
/// commit. Allow/Skip commit; Block commits ONLY in audit mode (`audited=true`),
/// matching the proxy — in enforce mode Block skips. A namespace-isolation Block
/// is fail-closed even in Off mode (it comes back `audited=false`).
fn should_commit(decision: &Decision, audited: bool) -> bool {
    match decision {
        Decision::Allow | Decision::Skip => true,
        Decision::Block { .. } => audited,
    }
}

fn short(hex: &str) -> String {
    hex.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn art(sha256: Option<&str>, sha1: Option<&str>) -> ArtifactRef {
        ArtifactRef {
            repo: "r".into(),
            path: "a/b.jar".into(),
            name: "b.jar".into(),
            size: None,
            sha256: sha256.map(String::from),
            sha1: sha1.map(String::from),
        }
    }

    #[test]
    fn plan_verification_applies_r8_policy() {
        assert!(matches!(
            plan_verification(&art(Some("aa"), None), false),
            VerifyPlan::Verify(Provenance::Strong)
        ));
        assert!(matches!(
            plan_verification(&art(None, Some("bb")), true),
            VerifyPlan::Verify(Provenance::Weak)
        ));
        assert!(matches!(
            plan_verification(&art(None, Some("bb")), false),
            VerifyPlan::Skip(_)
        ));
        assert!(matches!(
            plan_verification(&art(None, None), true),
            VerifyPlan::Fail(_)
        ));
    }

    #[test]
    fn verify_checksum_is_case_insensitive_and_fail_closed() {
        let a = art(Some("ABCDEF"), None);
        assert!(verify_checksum(&a, "abcdef", "", Provenance::Strong).is_ok());
        assert!(verify_checksum(&a, "abcde0", "", Provenance::Strong).is_err());
        let a1 = art(None, Some("aa11"));
        assert!(verify_checksum(&a1, "ignored", "AA11", Provenance::Weak).is_ok());
        assert!(verify_checksum(&a1, "ignored", "bb22", Provenance::Weak).is_err());
    }

    #[test]
    fn should_commit_honors_audit_and_enforce() {
        assert!(should_commit(&Decision::Allow, false));
        assert!(should_commit(&Decision::Skip, false));
        // Enforce Block (audited=false) → skip.
        assert!(!should_commit(
            &Decision::Block {
                rule: "blocklist".into(),
                reason: "x".into()
            },
            false
        ));
        // Audit Block (audited=true) → commit (matches proxy).
        assert!(should_commit(
            &Decision::Block {
                rule: "blocklist".into(),
                reason: "x".into()
            },
            true
        ));
    }

    // ---- transfer_artifact orchestration: every outcome branch (in-process) ----

    use async_trait::async_trait;
    use futures::stream;

    /// In-process source: returns a canned body (or a download error) — enough to
    /// drive `transfer_artifact` through every branch without a live HTTP server.
    struct MockSource {
        body: Vec<u8>,
        fail_download: bool,
    }

    #[async_trait]
    impl SourceRegistry for MockSource {
        async fn list_repositories(&self) -> Result<Vec<crate::import::RepoRef>> {
            Ok(vec![])
        }
        fn artifacts<'a>(&'a self, _repo: &'a str) -> BoxStream<'a, Result<ArtifactRef>> {
            stream::empty().boxed()
        }
        async fn download_stream(
            &self,
            _artifact: &ArtifactRef,
        ) -> Result<BoxStream<'static, Result<Bytes>>> {
            if self.fail_download {
                return Err("mock download failure".to_string());
            }
            let body = self.body.clone();
            Ok(stream::once(async move { Ok(Bytes::from(body)) }).boxed())
        }
    }

    async fn harness() -> (Storage, CurationEngine, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(tmp.path().to_str().unwrap());
        let curation = CurationEngine::new(crate::config::CurationConfig::default());
        (storage, curation, tmp)
    }

    fn full_art(size: Option<u64>, sha256: Option<&str>, sha1: Option<&str>) -> ArtifactRef {
        ArtifactRef {
            repo: "r".into(),
            path: "com/x/1.0/x-1.0.jar".into(),
            name: "x-1.0.jar".into(),
            size,
            sha256: sha256.map(String::from),
            sha1: sha1.map(String::from),
        }
    }

    const KEY: &str = "maven/com/x/1.0/x-1.0.jar";

    async fn run_transfer(
        src: &MockSource,
        art: &ArtifactRef,
        storage: &Storage,
        curation: &CurationEngine,
        td: &std::path::Path,
        opts: TransferOpts,
    ) -> Outcome {
        transfer_artifact(
            src,
            art,
            KEY,
            RegistryType::Maven,
            "com/x",
            "src-host",
            storage,
            curation,
            td,
            opts,
        )
        .await
    }

    fn commit_opts() -> TransferOpts {
        TransferOpts {
            dry_run: false,
            allow_sha1: false,
        }
    }

    #[tokio::test]
    async fn transfer_no_checksum_is_failed_no_commit() {
        let (storage, curation, tmp) = harness().await;
        let td = tmp.path().join("t");
        let src = MockSource {
            body: b"x".to_vec(),
            fail_download: false,
        };
        let out = run_transfer(
            &src,
            &full_art(None, None, None),
            &storage,
            &curation,
            &td,
            commit_opts(),
        )
        .await;
        assert!(matches!(out, Outcome::Failed { .. }));
        assert!(storage.stat(KEY).await.is_none());
    }

    #[tokio::test]
    async fn transfer_sha1_only_without_flag_is_skipped() {
        let (storage, curation, tmp) = harness().await;
        let td = tmp.path().join("t");
        let src = MockSource {
            body: b"x".to_vec(),
            fail_download: false,
        };
        let out = run_transfer(
            &src,
            &full_art(None, None, Some("aa")),
            &storage,
            &curation,
            &td,
            commit_opts(),
        )
        .await;
        assert!(matches!(out, Outcome::Skipped { .. }));
    }

    #[tokio::test]
    async fn transfer_download_error_is_failed() {
        let (storage, curation, tmp) = harness().await;
        let td = tmp.path().join("t");
        let sha = hex::encode(sha2::Sha256::digest(b"x"));
        let src = MockSource {
            body: vec![],
            fail_download: true,
        };
        let out = run_transfer(
            &src,
            &full_art(None, Some(&sha), None),
            &storage,
            &curation,
            &td,
            commit_opts(),
        )
        .await;
        assert!(matches!(out, Outcome::Failed { .. }));
    }

    #[tokio::test]
    async fn transfer_size_mismatch_is_failed_no_commit() {
        let (storage, curation, tmp) = harness().await;
        let td = tmp.path().join("t");
        let body = b"hello";
        let sha = hex::encode(sha2::Sha256::digest(body));
        let src = MockSource {
            body: body.to_vec(),
            fail_download: false,
        };
        let out = run_transfer(
            &src,
            &full_art(Some(999), Some(&sha), None),
            &storage,
            &curation,
            &td,
            commit_opts(),
        )
        .await;
        assert!(matches!(out, Outcome::Failed { .. }));
        assert!(storage.stat(KEY).await.is_none());
    }

    #[tokio::test]
    async fn transfer_checksum_mismatch_fails_closed() {
        let (storage, curation, tmp) = harness().await;
        let td = tmp.path().join("t");
        let wrong = hex::encode(sha2::Sha256::digest(b"other"));
        let src = MockSource {
            body: b"real".to_vec(),
            fail_download: false,
        };
        let out = run_transfer(
            &src,
            &full_art(None, Some(&wrong), None),
            &storage,
            &curation,
            &td,
            commit_opts(),
        )
        .await;
        assert!(matches!(out, Outcome::Failed { .. }));
        assert!(storage.stat(KEY).await.is_none());
    }

    #[tokio::test]
    async fn transfer_happy_path_commits_and_pins() {
        let (storage, curation, tmp) = harness().await;
        let td = tmp.path().join("t");
        let body = b"hello world payload";
        let sha = hex::encode(sha2::Sha256::digest(body));
        let src = MockSource {
            body: body.to_vec(),
            fail_download: false,
        };
        let out = run_transfer(
            &src,
            &full_art(Some(body.len() as u64), Some(&sha), None),
            &storage,
            &curation,
            &td,
            commit_opts(),
        )
        .await;
        match out {
            Outcome::Imported { bytes, sha256 } => {
                assert_eq!(bytes as usize, body.len());
                assert_eq!(sha256, sha);
            }
            o => panic!("expected Imported, got {o:?}"),
        }
        assert_eq!(storage.get(KEY).await.unwrap().as_ref(), body);
        assert_eq!(storage.get_pin_hash(KEY).as_deref(), Some(sha.as_str()));
    }

    #[tokio::test]
    async fn transfer_dry_run_verifies_without_commit() {
        let (storage, curation, tmp) = harness().await;
        let td = tmp.path().join("t");
        let body = b"rehearsal";
        let sha = hex::encode(sha2::Sha256::digest(body));
        let src = MockSource {
            body: body.to_vec(),
            fail_download: false,
        };
        let out = run_transfer(
            &src,
            &full_art(Some(body.len() as u64), Some(&sha), None),
            &storage,
            &curation,
            &td,
            TransferOpts {
                dry_run: true,
                allow_sha1: false,
            },
        )
        .await;
        assert!(matches!(out, Outcome::Imported { .. }));
        assert!(storage.stat(KEY).await.is_none());
    }

    #[tokio::test]
    async fn transfer_sha1_verified_with_flag_commits() {
        let (storage, curation, tmp) = harness().await;
        let td = tmp.path().join("t");
        let body = b"legacy maven artifact";
        let sha1v = hex::encode(sha1::Sha1::digest(body));
        let src = MockSource {
            body: body.to_vec(),
            fail_download: false,
        };
        let out = run_transfer(
            &src,
            &full_art(None, None, Some(&sha1v)),
            &storage,
            &curation,
            &td,
            TransferOpts {
                dry_run: false,
                allow_sha1: true,
            },
        )
        .await;
        assert!(matches!(out, Outcome::Imported { .. }));
        assert!(storage.stat(KEY).await.is_some());
    }
}
