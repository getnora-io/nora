// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

mod local;
mod s3;

pub use local::LocalStorage;
pub use s3::S3Storage;

use crate::hash_pin_store::HashPinStore;
use crate::metrics::{STORAGE_GET_BYTES, STORAGE_OPERATIONS, STORAGE_VERIFY_DURATION_SECONDS};
use crate::validation::{validate_storage_key, ValidationError};
use async_trait::async_trait;
use axum::body::Bytes;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::AsyncRead;

/// File metadata
#[derive(Debug, Clone)]
pub struct FileMeta {
    pub size: u64,
    pub modified: u64, // Unix timestamp
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Network error: {0}")]
    Network(String),

    #[error("Object not found")]
    NotFound,

    #[error("IO error: {0}")]
    Io(String),

    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    /// Stored artifact failed hash-pin verification — tampering or on-disk
    /// corruption detected. Fail-closed: the tampered bytes are never served
    /// (handlers map this to 5xx). See #582.
    #[error("Integrity violation: artifact failed hash-pin verification")]
    IntegrityViolation,
}

pub type Result<T> = std::result::Result<T, StorageError>;

/// Registry prefix of a storage key, for metric labelling only
/// (`npm/lodash/metadata.json` → `npm`). Storage stays format-agnostic: this
/// reads the first path segment as an opaque label, with no registry-protocol
/// knowledge. Cardinality is bounded — an empty, oversized, or non-lowercase
/// first segment collapses to `other`, so a pathological key cannot explode the
/// label set.
fn registry_label(key: &str) -> &str {
    let segment = key.split('/').next().unwrap_or("");
    if !segment.is_empty() && segment.len() <= 16 && segment.bytes().all(|b| b.is_ascii_lowercase())
    {
        segment
    } else {
        "other"
    }
}

/// Outcome of [`Storage::repin`] — an operator integrity-recovery action (#601).
#[derive(Debug, PartialEq, Eq)]
pub enum RepinOutcome {
    /// The disk matched `expected` and the pin was updated from `old` to `new`.
    Updated { old: Option<String>, new: String },
    /// Dry run: the disk matched `expected` and the pin would change.
    WouldUpdate { old: Option<String>, new: String },
    /// The disk already matched `expected` and the pin already equalled it —
    /// nothing to do.
    AlreadyPinned { hash: String },
    /// Refused: the on-disk bytes hash to `disk`, not `expected`. The artifact
    /// is genuinely corrupt/tampered — re-pin cannot heal it; restore from
    /// backup. The pin is left unchanged.
    DiskMismatch { disk: String, expected: String },
    /// This backend has no pin store (S3) — there is nothing to re-pin.
    NoPinStore,
}

/// Storage backend trait
#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Bytes>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
    async fn stat(&self, key: &str) -> Option<FileMeta>;
    async fn health_check(&self) -> bool;
    /// Total size of all stored artifacts in bytes
    async fn total_size(&self) -> u64;
    fn backend_name(&self) -> &'static str;
    /// Refresh any cached size data. No-op for backends without caching.
    async fn refresh_total_size(&self) {}
    /// Move or copy a file from `src` into storage under `key`.
    ///
    /// Local backend: atomic `rename`, with streaming copy fallback on EXDEV.
    /// S3 backend: multipart upload from file.
    /// The caller is responsible for deleting `src` on error.
    async fn put_from_path(&self, key: &str, src: &Path) -> Result<()>;

    /// Open an artifact for streaming read without loading it into memory (#580).
    ///
    /// Returns `(size_bytes, reader)`. The caller converts the reader to a
    /// streaming HTTP response via `ReaderStream` + `Body::from_stream()`.
    ///
    /// Local backend: `tokio::fs::File::open` + metadata.
    /// S3 backend: `object_store::get` → byte-stream wrapped in `StreamReader`.
    async fn get_reader(&self, key: &str) -> Result<(u64, Pin<Box<dyn AsyncRead + Send + Unpin>>)>;

    /// Stream the inclusive byte range `[start, end]` of an object, returning the object's
    /// total size and a reader over exactly those bytes. The default reads from the start and
    /// discards the prefix; backends override with an efficient seek / ranged GET.
    async fn get_range(
        &self,
        key: &str,
        start: u64,
        end: u64,
    ) -> Result<(u64, Pin<Box<dyn AsyncRead + Send + Unpin>>)> {
        use tokio::io::AsyncReadExt;
        let (size, mut reader) = self.get_reader(key).await?;
        let mut to_skip = start;
        let mut buf = [0u8; 64 * 1024];
        while to_skip > 0 {
            let want = to_skip.min(buf.len() as u64) as usize;
            let n = reader
                .read(&mut buf[..want])
                .await
                .map_err(|e| StorageError::Io(e.to_string()))?;
            if n == 0 {
                break;
            }
            to_skip -= n as u64;
        }
        let len = end.saturating_sub(start) + 1;
        Ok((size, Box::pin(reader.take(len))))
    }
}

/// Storage wrapper for dynamic dispatch with integrity verification.
#[derive(Clone)]
pub struct Storage {
    inner: Arc<dyn StorageBackend>,
    pin_store: Option<Arc<HashPinStore>>,
}

impl Storage {
    pub fn new_local(path: &str) -> Self {
        let pin_path = PathBuf::from(path).join(".nora-pins.ndjson");
        Self {
            inner: Arc::new(LocalStorage::new(path)),
            pin_store: Some(Arc::new(HashPinStore::new(pin_path))),
        }
    }

    pub fn new_s3(
        s3_url: &str,
        bucket: &str,
        region: &str,
        access_key: Option<&str>,
        secret_key: Option<&str>,
    ) -> Self {
        tracing::warn!(
            "Hash pin store disabled for S3 backend — integrity verification unavailable"
        );
        Self {
            inner: Arc::new(S3Storage::new(
                s3_url, bucket, region, access_key, secret_key,
            )),
            pin_store: None,
        }
    }

    pub async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        validate_storage_key(key)?;
        match self.inner.put(key, data).await {
            Ok(()) => {
                STORAGE_OPERATIONS.with_label_values(&["put", "ok"]).inc();
                if let Some(ref pins) = self.pin_store {
                    let pins = Arc::clone(pins);
                    let key_owned = key.to_string();
                    let data_owned = data.to_vec();
                    // Await the pin record (SHA-256 + ndjson append, offloaded
                    // from the tokio worker) so `put()` does not return until the
                    // pin is durable. Previously this was fire-and-forget, which
                    // left a window where the artifact was readable but unpinned —
                    // a `get()` after a completed `put()` could serve it
                    // unverified (#604) — and silently dropped the pin if the task
                    // panicked. Fail-closed (mirroring `get()`): if integrity
                    // cannot be recorded, the write reports failure rather than
                    // leaving an unverifiable artifact.
                    //
                    // NOTE: a `get()` racing *during* an in-flight `put()` (between
                    // the inner write and this record) can still briefly observe
                    // the artifact unpinned. Fully closing that requires
                    // serializing get/put per key; it is benign (it serves NORA's
                    // own just-written bytes) and out of scope here.
                    // `record` now returns its I/O result: handle the inner
                    // failure (ENOSPC/EACCES/EIO/read-only FS) the same way as a
                    // panicked task — fail closed. Previously that error was
                    // swallowed inside `record`, so `put()` returned Ok while the
                    // pin never reached disk, silently downgrading the key to
                    // open-world after the next restart (the #582/#604 bypass).
                    //
                    // NOTE (immutable registries): `self.inner.put` already
                    // succeeded, so on an immutable registry the client's retry
                    // hits the immutability guard (409) and never re-runs this pin
                    // write — the orphaned body stays unpinned until an operator
                    // `repin`s it. That is still strictly better than the prior
                    // silent success and is the documented recovery path;
                    // auto-cleanup of the orphan body is a separate follow-up.
                    match tokio::task::spawn_blocking(move || pins.record(&key_owned, &data_owned))
                        .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            STORAGE_OPERATIONS
                                .with_label_values(&["put", "pin_error"])
                                .inc();
                            tracing::error!(error = %e, key = %key, "hash-pin record failed");
                            return Err(StorageError::Io(format!("hash-pin record failed: {e}")));
                        }
                        Err(e) => {
                            STORAGE_OPERATIONS
                                .with_label_values(&["put", "pin_error"])
                                .inc();
                            tracing::error!(error = %e, key = %key, "hash-pin record task panicked");
                            return Err(StorageError::Io(format!("hash-pin record failed: {e}")));
                        }
                    }
                }
                Ok(())
            }
            Err(e) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["put", "error"])
                    .inc();
                Err(e)
            }
        }
    }

    pub async fn get(&self, key: &str) -> Result<Bytes> {
        validate_storage_key(key)?;
        match self.inner.get(key).await {
            Ok(data) => {
                STORAGE_OPERATIONS.with_label_values(&["get", "ok"]).inc();
                let label = registry_label(key);
                STORAGE_GET_BYTES
                    .with_label_values(&[label])
                    .observe(data.len() as f64);
                if let Some(ref pins) = self.pin_store {
                    let pins = Arc::clone(pins);
                    let key_owned = key.to_string();
                    let data_ref = data.clone();
                    // SHA-256 verification — offloaded from the tokio worker.
                    // A buffered `get()` may hold a large artifact in memory;
                    // hashing it inline would stall the async worker for the
                    // hash duration, so we keep the blocking pool. The panic
                    // path is handled fail-closed below — see #582.
                    //
                    // INVARIANT (#582): a *positive* verify result is NEVER
                    // cached — the hash is recomputed on every read. Caching
                    // "verified" by mtime/size would re-open the bypass #582
                    // closed (bit-rot does not bump mtime; an on-disk tamperer
                    // can forge it via `utimes`). The recompute is the
                    // deliberate cost of fail-closed delivery; #602 instruments
                    // that cost via STORAGE_VERIFY_DURATION_SECONDS rather than
                    // weakening the guarantee.
                    let verify_start = std::time::Instant::now();
                    let outcome =
                        tokio::task::spawn_blocking(move || pins.verify(&key_owned, &data_ref))
                            .await;
                    STORAGE_VERIFY_DURATION_SECONDS
                        .with_label_values(&[label])
                        .observe(verify_start.elapsed().as_secs_f64());
                    match outcome {
                        // Genuine hash mismatch — tampering or on-disk corruption.
                        // Fail-closed: never serve the tampered bytes (#582).
                        Ok(false) => {
                            STORAGE_OPERATIONS
                                .with_label_values(&["get", "integrity_fail"])
                                .inc();
                            tracing::error!(
                                key = %key,
                                "integrity violation: refusing to serve tampered artifact"
                            );
                            return Err(StorageError::IntegrityViolation);
                        }
                        // Verification task itself panicked. We cannot prove the
                        // bytes are intact, so fail-closed too — a crashed
                        // verifier must not become an integrity bypass (#582).
                        Err(e) => {
                            STORAGE_OPERATIONS
                                .with_label_values(&["get", "verify_error"])
                                .inc();
                            tracing::error!(
                                error = %e,
                                key = %key,
                                "hash verification task failed: refusing to serve unverified artifact"
                            );
                            return Err(StorageError::IntegrityViolation);
                        }
                        // Hash matched, or no pin exists for this key (open-world).
                        Ok(true) => {}
                    }
                }
                Ok(data)
            }
            Err(e) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["get", "error"])
                    .inc();
                Err(e)
            }
        }
    }

    pub async fn delete(&self, key: &str) -> Result<()> {
        validate_storage_key(key)?;
        match self.inner.delete(key).await {
            Ok(()) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["delete", "ok"])
                    .inc();
                if let Some(ref pins) = self.pin_store {
                    let pins = Arc::clone(pins);
                    let key_owned = key.to_string();
                    // Await the tombstone write so a failure is observable rather
                    // than fire-and-forget. A lost tombstone is fail-safe (a stale
                    // pin at worst yields a future IntegrityViolation, healable via
                    // `repin`), so `delete()` still reports success — the
                    // authoritative action (byte removal) already succeeded.
                    match tokio::task::spawn_blocking(move || pins.remove(&key_owned)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            STORAGE_OPERATIONS
                                .with_label_values(&["delete", "pin_error"])
                                .inc();
                            tracing::warn!(
                                error = %e,
                                key = %key,
                                "hash-pin tombstone write failed; stale pin left (repin to heal)"
                            );
                        }
                        Err(e) => {
                            STORAGE_OPERATIONS
                                .with_label_values(&["delete", "pin_error"])
                                .inc();
                            tracing::warn!(error = %e, key = %key, "hash-pin tombstone task panicked");
                        }
                    }
                }
                Ok(())
            }
            Err(e) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["delete", "error"])
                    .inc();
                Err(e)
            }
        }
    }

    pub async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        // Empty prefix is valid for listing all
        if !prefix.is_empty() {
            validate_storage_key(prefix)?;
        }
        let keys = self.inner.list(prefix).await?;
        Ok(keys
            .into_iter()
            .filter(|k| !k.starts_with(".nora-"))
            .collect())
    }

    pub async fn stat(&self, key: &str) -> Option<FileMeta> {
        if validate_storage_key(key).is_err() {
            return None;
        }
        self.inner.stat(key).await
    }

    pub async fn health_check(&self) -> bool {
        self.inner.health_check().await
    }

    pub async fn total_size(&self) -> u64 {
        self.inner.total_size().await
    }

    pub fn backend_name(&self) -> &'static str {
        self.inner.backend_name()
    }

    /// Look up the pinned SHA-256 hash for a storage key (None if pin store is disabled or key is unknown).
    pub fn get_pin_hash(&self, key: &str) -> Option<String> {
        self.pin_store.as_ref().and_then(|p| p.get(key))
    }

    /// Operator recovery for an artifact whose hash pin no longer matches its
    /// stored bytes (#601). Reads the raw bytes *bypassing* verification — the
    /// whole point, since [`Storage::get`] fails closed on the very mismatch we
    /// are recovering from — and updates the pin to `expected` **only if the
    /// on-disk bytes already hash to `expected`**.
    ///
    /// `expected` is the SHA-256 the operator independently knows to be
    /// canonical for this key (from a CI manifest, upstream checksum, lockfile,
    /// …). Requiring it is the security guard that keeps this from becoming an
    /// integrity bypass: a plain "recompute the hash from disk" would let
    /// corrupted or tampered bytes silently re-bless themselves, re-opening the
    /// hole #582 closed. By demanding `disk == expected`, re-pin can only ever
    /// set the pin to a hash the disk *already* has **and** the operator has
    /// vouched for. If the disk is genuinely corrupt (`disk != expected`) it
    /// refuses — re-pin cannot heal corruption; the operator must restore from
    /// backup first.
    ///
    /// `apply == false` is a dry run (computes and compares, writes nothing).
    /// Local backend only — S3 has no pin store.
    pub async fn repin(&self, key: &str, expected: &str, apply: bool) -> Result<RepinOutcome> {
        validate_storage_key(key)?;
        let Some(ref pins) = self.pin_store else {
            return Ok(RepinOutcome::NoPinStore);
        };
        let expected = expected.to_ascii_lowercase();
        // Raw read — deliberately bypasses `Storage::get()`'s verification,
        // which would fail closed on the mismatch we are recovering from.
        let data = self.inner.get(key).await?;
        let disk = hex::encode(Sha256::digest(&data));
        if disk != expected {
            // The bytes on disk are not the ones the operator vouched for —
            // genuine corruption/tampering. Re-pin must NOT bless them.
            return Ok(RepinOutcome::DiskMismatch { disk, expected });
        }
        let old = pins.get(key);
        if old.as_deref() == Some(expected.as_str()) {
            return Ok(RepinOutcome::AlreadyPinned { hash: expected });
        }
        if !apply {
            return Ok(RepinOutcome::WouldUpdate { old, new: expected });
        }
        pins.record_hash(key, &expected)
            .map_err(|e| StorageError::Io(format!("hash-pin record failed: {e}")))?;
        Ok(RepinOutcome::Updated { old, new: expected })
    }

    /// Number of pinned hashes (0 if pin store is disabled).
    pub fn pinned_count(&self) -> usize {
        self.pin_store.as_ref().map_or(0, |p| p.len())
    }

    /// Refresh cached total_size. No-op for local storage, computes for S3.
    pub async fn refresh_total_size_cache(&self) {
        self.inner.refresh_total_size().await;
    }

    /// Move or copy a file from `src` into storage under `key`.
    ///
    /// When `sha256` is `Some`, the hash is recorded in the pin store without
    /// re-reading the file — used by streaming download paths where the hash
    /// was already computed incrementally (#580).
    ///
    /// When `sha256` is `None`, the pin store is not updated (legacy behavior
    /// for callers that have already verified integrity separately).
    pub async fn put_from_path(&self, key: &str, src: &Path, sha256: Option<&str>) -> Result<()> {
        validate_storage_key(key)?;
        match self.inner.put_from_path(key, src).await {
            Ok(()) => {
                STORAGE_OPERATIONS.with_label_values(&["put", "ok"]).inc();
                if let (Some(hash), Some(ref pins)) = (sha256, &self.pin_store) {
                    let pins = Arc::clone(pins);
                    let key_owned = key.to_string();
                    let hash = hash.to_string();
                    // Await the pin record so it is durable before this returns —
                    // the streaming write counterpart of the `put()` fix (#604).
                    // `record_hash` uses the pre-computed digest (no re-hash), so
                    // the await is near-free. Fail-closed on a panicking task.
                    match tokio::task::spawn_blocking(move || pins.record_hash(&key_owned, &hash))
                        .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            STORAGE_OPERATIONS
                                .with_label_values(&["put", "pin_error"])
                                .inc();
                            tracing::error!(error = %e, key = %key, "hash-pin record failed");
                            return Err(StorageError::Io(format!("hash-pin record failed: {e}")));
                        }
                        Err(e) => {
                            STORAGE_OPERATIONS
                                .with_label_values(&["put", "pin_error"])
                                .inc();
                            tracing::error!(error = %e, key = %key, "hash-pin record task panicked");
                            return Err(StorageError::Io(format!("hash-pin record failed: {e}")));
                        }
                    }
                }
                Ok(())
            }
            Err(e) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["put", "error"])
                    .inc();
                Err(e)
            }
        }
    }

    /// Open an artifact for streaming read without loading into memory (#580).
    ///
    /// Returns `(size_bytes, reader)`. Pin-store integrity is NOT checked here
    /// because streaming prevents full-data hashing. Callers that need integrity
    /// verification should use `verify_integrity_by_hash` with the content digest
    /// (available from the URL for Docker blobs).
    pub async fn get_reader(
        &self,
        key: &str,
    ) -> Result<(u64, Pin<Box<dyn AsyncRead + Send + Unpin>>)> {
        validate_storage_key(key)?;
        match self.inner.get_reader(key).await {
            Ok(reader) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["get_reader", "ok"])
                    .inc();
                Ok(reader)
            }
            Err(e) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["get_reader", "error"])
                    .inc();
                Err(e)
            }
        }
    }

    /// Stream the inclusive byte range `[start, end]` of an object (see the trait method).
    pub async fn get_range(
        &self,
        key: &str,
        start: u64,
        end: u64,
    ) -> Result<(u64, Pin<Box<dyn AsyncRead + Send + Unpin>>)> {
        validate_storage_key(key)?;
        match self.inner.get_range(key, start, end).await {
            Ok(r) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["get_range", "ok"])
                    .inc();
                Ok(r)
            }
            Err(e) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["get_range", "error"])
                    .inc();
                Err(e)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::TempDir;

    /// Wait until the pin record from `put()` is visible. Since #604 `put()`
    /// awaits the pin, so this returns on the first poll; kept for robustness.
    async fn await_pin(storage: &Storage, key: &str) {
        for _ in 0..200 {
            if storage.get_pin_hash(key).is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("pin for {key} was never recorded");
    }

    /// Regression for #604: `put()` must record the hash-pin BEFORE it returns,
    /// so there is no window where a completed put leaves the artifact readable
    /// but unpinned (which a later `get()` would serve unverified). Exercises
    /// the real call path `Storage::put()` → `get_pin_hash()` — the pin is
    /// observable synchronously, with no polling.
    #[tokio::test]
    async fn put_records_pin_before_returning() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());

        storage.put("raw/x/app.bin", b"payload").await.unwrap();

        assert!(
            storage.get_pin_hash("raw/x/app.bin").is_some(),
            "put() must record the hash-pin before returning (#604)"
        );
        // And the recorded pin must match the bytes (a subsequent get verifies).
        assert_eq!(&storage.get("raw/x/app.bin").await.unwrap()[..], b"payload");
    }

    #[test]
    fn registry_label_extracts_prefix_and_bounds_cardinality() {
        assert_eq!(registry_label("npm/lodash/metadata.json"), "npm");
        assert_eq!(
            registry_label("docker/library/nginx/blobs/sha256:ab"),
            "docker"
        );
        assert_eq!(registry_label("raw/x/app.bin"), "raw");
        // Defensive collapses to "other" — never an unbounded label.
        assert_eq!(registry_label(""), "other");
        assert_eq!(registry_label("/leading-slash"), "other");
        assert_eq!(registry_label("UPPER/x"), "other");
        assert_eq!(registry_label("averylongsegmentname/x"), "other"); // >16 chars
                                                                       // Filter is strictly [a-z] — digits/hyphens collapse to "other" so a
                                                                       // future "allow [a-z0-9]" change can't silently explode cardinality.
        assert_eq!(registry_label("v2/x"), "other");
        assert_eq!(registry_label("a-b/x"), "other");
        assert_eq!(registry_label("npm"), "npm"); // no slash, whole key is prefix
    }

    /// #602: a buffered `get()` of a pinned artifact records both the body-size
    /// and the verify-duration histograms (the data that decides whether the
    /// hash-on-read cost warrants a fix). Exercises the real `Storage::get()`.
    #[tokio::test]
    async fn get_observes_size_and_verify_duration_metrics() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        let key = "raw/metrics/app.bin";
        storage.put(key, b"observe-me").await.unwrap();

        let bytes_before = STORAGE_GET_BYTES
            .with_label_values(&["raw"])
            .get_sample_count();
        let verify_before = STORAGE_VERIFY_DURATION_SECONDS
            .with_label_values(&["raw"])
            .get_sample_count();

        let data = storage.get(key).await.unwrap();
        assert_eq!(&data[..], b"observe-me");

        // `>=` not `==`: these are global metrics and other tests share the
        // `raw` label under parallel execution; our get() contributes at least
        // one observation to each.
        assert!(
            STORAGE_GET_BYTES
                .with_label_values(&["raw"])
                .get_sample_count()
                >= bytes_before + 1,
            "get() must observe the body size"
        );
        assert!(
            STORAGE_VERIFY_DURATION_SECONDS
                .with_label_values(&["raw"])
                .get_sample_count()
                >= verify_before + 1,
            "get() of a pinned key must observe the verify duration"
        );
    }

    /// Regression for #604: the streaming write path `put_from_path()` must also
    /// record its pin BEFORE returning (same fire-and-forget gap as `put()`,
    /// on the path that handles Docker blobs). Exercises the real call path.
    #[tokio::test]
    async fn put_from_path_records_pin_before_returning() {
        use sha2::{Digest, Sha256};
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().join("store").to_str().unwrap());

        let src = dir.path().join("incoming.bin");
        std::fs::write(&src, b"streamed-bytes").unwrap();
        let sha = hex::encode(Sha256::digest(b"streamed-bytes"));

        let key = "docker/x/blobs/sha256:abc";
        storage.put_from_path(key, &src, Some(&sha)).await.unwrap();

        assert_eq!(
            storage.get_pin_hash(key).as_deref(),
            Some(sha.as_str()),
            "put_from_path must record the hash-pin before returning (#604)"
        );
    }

    /// Regression for #582: a pinned artifact corrupted on disk must NOT be
    /// served. Exercises the real call path `Storage::get()` — not `verify()`
    /// in isolation (PM-4). The bug was that `get()` computed the verification
    /// result and then returned `Ok(data)` regardless.
    #[tokio::test]
    async fn get_fails_closed_on_integrity_mismatch() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());

        let key = "raw/example/app.bin";
        storage.put(key, b"genuine-bytes").await.unwrap();
        await_pin(&storage, key).await;

        // Sanity: an untampered read returns the bytes.
        assert_eq!(&storage.get(key).await.unwrap()[..], b"genuine-bytes");

        // Tamper with the artifact directly on disk, bypassing NORA — exactly
        // the threat the pin store exists to catch.
        let before = STORAGE_OPERATIONS
            .with_label_values(&["get", "integrity_fail"])
            .get();
        std::fs::write(dir.path().join(key), b"TAMPERED").unwrap();

        // get() must refuse to serve the tampered bytes.
        let result = storage.get(key).await;
        assert!(
            matches!(result, Err(StorageError::IntegrityViolation)),
            "expected IntegrityViolation, got {result:?}"
        );

        // ...and the failure must be recorded (acceptance criterion).
        let after = STORAGE_OPERATIONS
            .with_label_values(&["get", "integrity_fail"])
            .get();
        assert!(after > before, "integrity_fail metric must increment");
    }

    /// The fix must not break legitimate reads: a matching hash still returns
    /// the bytes, and an unpinned key (open-world) passes through.
    #[tokio::test]
    async fn get_succeeds_for_matching_and_unpinned() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());

        // Pinned + matching → served.
        let key = "raw/ok/file.bin";
        storage.put(key, b"hello").await.unwrap();
        await_pin(&storage, key).await;
        assert_eq!(&storage.get(key).await.unwrap()[..], b"hello");

        // Unpinned key (written straight to disk, no pin) → open-world pass.
        let unpinned = "raw/ok/unpinned.bin";
        std::fs::write(dir.path().join(unpinned), b"no-pin").unwrap();
        assert_eq!(&storage.get(unpinned).await.unwrap()[..], b"no-pin");
    }

    fn sha_hex(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    /// #601 happy path: an artifact legitimately replaced out-of-band (disk now
    /// holds new canonical bytes, pin still references the old ones) fails
    /// closed, then `re-pin --expected <hash-of-new>` restores service because
    /// the disk already matches `expected`. Exercises the real `repin()` +
    /// `get()` call path (PM-4).
    #[tokio::test]
    async fn repin_fixes_stale_pin_when_disk_matches_expected() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        let key = "raw/app/release.bin";

        storage.put(key, b"v1-bytes").await.unwrap();
        await_pin(&storage, key).await;

        // Operator replaces the file out-of-band with new canonical bytes.
        std::fs::write(dir.path().join(key), b"v2-canonical").unwrap();
        // Now the pin (hash of v1) no longer matches the disk → fail-closed.
        assert!(matches!(
            storage.get(key).await,
            Err(StorageError::IntegrityViolation)
        ));

        let expected = sha_hex(b"v2-canonical");

        // Dry run reports the change without writing.
        assert_eq!(
            storage.repin(key, &expected, false).await.unwrap(),
            RepinOutcome::WouldUpdate {
                old: Some(sha_hex(b"v1-bytes")),
                new: expected.clone(),
            }
        );
        // ...and the pin is untouched, so it still fails closed.
        assert!(storage.get(key).await.is_err());

        // Apply: the disk matches `expected`, so the pin is updated.
        assert_eq!(
            storage.repin(key, &expected, true).await.unwrap(),
            RepinOutcome::Updated {
                old: Some(sha_hex(b"v1-bytes")),
                new: expected,
            }
        );
        // Service restored — the new canonical bytes are served.
        assert_eq!(&storage.get(key).await.unwrap()[..], b"v2-canonical");
    }

    /// #601 security guard: re-pin must NOT bless corrupt/tampered bytes. When
    /// the disk does not match `--expected`, it refuses and leaves the pin
    /// unchanged, so the artifact keeps failing closed (no integrity bypass).
    #[tokio::test]
    async fn repin_refuses_when_disk_does_not_match_expected() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        let key = "raw/app/payload.bin";

        storage.put(key, b"genuine").await.unwrap();
        await_pin(&storage, key).await;

        // Disk is tampered; operator (correctly) supplies the genuine hash.
        std::fs::write(dir.path().join(key), b"TAMPERED").unwrap();
        let genuine = sha_hex(b"genuine");

        // disk (hash of TAMPERED) != expected (hash of genuine) → refuse.
        assert_eq!(
            storage.repin(key, &genuine, true).await.unwrap(),
            RepinOutcome::DiskMismatch {
                disk: sha_hex(b"TAMPERED"),
                expected: genuine.clone(),
            }
        );
        // The pin was not changed to the tampered bytes — still fails closed.
        assert!(matches!(
            storage.get(key).await,
            Err(StorageError::IntegrityViolation)
        ));
        assert_eq!(storage.get_pin_hash(key).as_deref(), Some(genuine.as_str()));
    }

    /// Re-pinning a key whose pin already equals `expected` is a no-op.
    #[tokio::test]
    async fn repin_already_pinned_is_noop() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        let key = "raw/app/ok.bin";
        storage.put(key, b"stable").await.unwrap();
        await_pin(&storage, key).await;

        assert_eq!(
            storage.repin(key, &sha_hex(b"stable"), true).await.unwrap(),
            RepinOutcome::AlreadyPinned {
                hash: sha_hex(b"stable")
            }
        );
    }

    /// Documents the recovery contract for the immutable-publish unpin trap:
    /// when a `put()` body write succeeds but the pin write fails (now surfaced
    /// as `StorageError::Io` instead of swallowed), the artifact is left durably
    /// on disk *unpinned* (open-world). On an immutable registry the client
    /// cannot self-heal — its retry hits the 409 guard — so that orphaned state
    /// must be recoverable via operator `repin`. Models the orphaned state with
    /// `put_from_path(.., None)`, which stores the body without recording a pin.
    #[tokio::test]
    async fn orphaned_unpinned_body_is_repin_recoverable() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().join("store").to_str().unwrap());
        let key = "raw/app/orphan.bin";

        // Stage the post-failure state: body on disk, no pin recorded.
        let src = dir.path().join("incoming.bin");
        std::fs::write(&src, b"orphan-bytes").unwrap();
        storage.put_from_path(key, &src, None).await.unwrap();
        assert_eq!(
            storage.get_pin_hash(key),
            None,
            "precondition: the orphaned body must be stored without a pin"
        );

        // Operator re-pins with the independently-known canonical hash; the disk
        // already matches it, so the pin is set and service verifies again.
        let expected = sha_hex(b"orphan-bytes");
        assert_eq!(
            storage.repin(key, &expected, true).await.unwrap(),
            RepinOutcome::Updated {
                old: None,
                new: expected.clone(),
            }
        );
        assert_eq!(
            storage.get_pin_hash(key).as_deref(),
            Some(expected.as_str())
        );
        assert_eq!(&storage.get(key).await.unwrap()[..], b"orphan-bytes");
    }
}
