// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

mod local;
mod object;

pub use local::LocalStorage;
pub use object::ObjectStorage;

use crate::metrics::{STORAGE_GET_BYTES, STORAGE_OPERATIONS, STORAGE_VERIFY_DURATION_SECONDS};
use crate::validation::{validate_storage_key, ValidationError};
use async_trait::async_trait;
use axum::body::Bytes;
use sha2::{Digest, Sha256};
use std::path::Path;
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
    Io(#[from] std::io::Error),

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

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
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
}

/// Storage backend trait.
///
/// Every backend owns the SHA-256 integrity pin of the artifacts it stores and
/// keeps it beside the bytes — an NDJSON sidecar on the local filesystem,
/// user-defined object metadata on an object store. `sha256` arguments are
/// lowercase hex (64 chars).
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Store `data` under `key`, pinned to `sha256`. Fails closed: a body whose
    /// pin cannot be recorded is reported as a failed write (#582/#604).
    async fn put(&self, key: &str, data: &[u8], sha256: &str) -> Result<()>;
    /// Bytes plus the recorded pin, from ONE backend round-trip. `None` means
    /// the object carries no pin (open-world).
    async fn get(&self, key: &str) -> Result<(Bytes, Option<String>)>;
    /// The recorded pin for `key` without reading the bytes.
    async fn pin(&self, key: &str) -> Option<String>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
    async fn stat(&self, key: &str) -> Option<FileMeta>;
    /// List keys under `prefix` together with their size/mtime.
    ///
    /// Returns the metadata the listing already carries instead of forcing a
    /// per-key `stat()` — an extra HEAD per key on S3 (#738). The default impl
    /// falls back to `list()` + per-key `stat()`, so backends that do not
    /// override stay correct; Local and S3 override to reuse the metadata the
    /// listing itself produces.
    async fn list_with_meta(&self, prefix: &str) -> Result<Vec<(String, FileMeta)>> {
        let keys = self.list(prefix).await?;
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(meta) = self.stat(&key).await {
                out.push((key, meta));
            }
        }
        Ok(out)
    }
    async fn health_check(&self) -> bool;
    /// Total size of all stored artifacts in bytes
    async fn total_size(&self) -> u64;
    fn backend_name(&self) -> &'static str;
    /// Refresh any cached size data. No-op for backends without caching.
    async fn refresh_total_size(&self) {}
    /// Move or copy a file from `src` into storage under `key`, pinned to
    /// `sha256` when the caller computed one (streaming paths do; legacy
    /// callers that verified integrity separately pass `None`, leaving the
    /// object open-world).
    ///
    /// Local backend: atomic `rename`, with streaming copy fallback on EXDEV.
    /// Object store: multipart upload from file.
    /// The caller is responsible for deleting `src` on error.
    async fn put_from_path(&self, key: &str, src: &Path, sha256: Option<&str>) -> Result<()>;

    /// Server-side copy of `src` to `dst` inside the backend — the bytes never
    /// transit this process. `sha256` is the digest of the copied bytes when the
    /// caller knows it; otherwise `dst` inherits the pin of `src`.
    ///
    /// Returns [`StorageError::NotFound`] when `src` does not exist; an existing
    /// `dst` is overwritten.
    async fn copy(&self, src: &str, dst: &str, sha256: Option<&str>) -> Result<()>;

    /// Open an artifact for streaming read without loading it into memory (#580).
    ///
    /// Returns `(size_bytes, pin, reader)`. The caller converts the reader to a
    /// streaming HTTP response via `ReaderStream` + `Body::from_stream()`, and
    /// checks the pin as it streams.
    ///
    /// Local backend: `tokio::fs::File::open` + metadata.
    /// Object store: `object_store::get` → byte-stream wrapped in `StreamReader`.
    async fn get_reader(
        &self,
        key: &str,
    ) -> Result<(u64, Option<String>, Pin<Box<dyn AsyncRead + Send + Unpin>>)>;

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
        let (size, _, mut reader) = self.get_reader(key).await?;
        let mut to_skip = start;
        let mut buf = [0u8; 64 * 1024];
        while to_skip > 0 {
            let want = to_skip.min(buf.len() as u64) as usize;
            let n = reader.read(&mut buf[..want]).await?;
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
///
/// Owns key validation, metrics and the fail-closed verify gate; the pin itself
/// belongs to the backend, which stores it beside the bytes.
#[derive(Clone)]
pub struct Storage {
    inner: Arc<dyn StorageBackend>,
}

impl Storage {
    pub fn new_local(path: &str) -> Self {
        Self {
            inner: Arc::new(LocalStorage::new(path)),
        }
    }

    pub fn new_s3(
        s3_url: &str,
        bucket: &str,
        region: &str,
        access_key: Option<&str>,
        secret_key: Option<&str>,
        virtual_hosted: bool,
    ) -> Self {
        Self {
            inner: Arc::new(ObjectStorage::new(
                s3_url,
                bucket,
                region,
                access_key,
                secret_key,
                virtual_hosted,
            )),
        }
    }

    pub fn new_gcs(
        bucket: &str,
        service_account_path: Option<&str>,
        base_url: Option<&str>,
    ) -> Self {
        Self {
            inner: Arc::new(ObjectStorage::new_gcs(
                bucket,
                service_account_path,
                base_url,
            )),
        }
    }

    /// Test-only: wrap an arbitrary backend so unit tests can inject behaviour
    /// the real backends can't easily produce — e.g. a `stat`-failing backend
    /// driving GC's fail-closed "age unknown → keep and count" branch (#610).
    #[cfg(test)]
    pub(crate) fn from_backend(inner: Arc<dyn StorageBackend>) -> Self {
        Self { inner }
    }

    pub async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        validate_storage_key(key)?;
        // A buffered body can be large; hashing it inline would stall the tokio
        // worker for the hash duration, so the digest is computed on the
        // blocking pool. The backend records it together with the bytes, so a
        // completed `put()` is never readable-but-unpinned (#604).
        let buffered = data.to_vec();
        let hash = match tokio::task::spawn_blocking(move || sha256_hex(&buffered)).await {
            Ok(h) => h,
            Err(e) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["put", "error"])
                    .inc();
                tracing::error!(error = %e, key = %key, "hash task for put failed");
                return Err(StorageError::Io(std::io::Error::other(format!(
                    "hash task failed: {e}"
                ))));
            }
        };
        match self.inner.put(key, data, &hash).await {
            Ok(()) => {
                STORAGE_OPERATIONS.with_label_values(&["put", "ok"]).inc();
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

    /// Buffered read through the fail-closed integrity gate, returning the bytes
    /// and the pin they were checked against (`None` = open-world key).
    async fn get_pinned(&self, key: &str) -> Result<(Bytes, Option<String>)> {
        validate_storage_key(key)?;
        let (data, pin) = match self.inner.get(key).await {
            Ok(v) => v,
            Err(e) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["get", "error"])
                    .inc();
                return Err(e);
            }
        };
        STORAGE_OPERATIONS.with_label_values(&["get", "ok"]).inc();
        let label = registry_label(key);
        STORAGE_GET_BYTES
            .with_label_values(&[label])
            .observe(data.len() as f64);

        let Some(expected) = pin else {
            return Ok((data, None));
        };

        // SHA-256 verification — offloaded from the tokio worker for the same
        // reason as `put`. The panic path is handled fail-closed below (#582).
        //
        // INVARIANT (#582): a *positive* verify result is NEVER cached — the
        // hash is recomputed on every read. Caching "verified" by mtime/size
        // would re-open the bypass #582 closed (bit-rot does not bump mtime; an
        // at-rest tamperer can forge it via `utimes`). The recompute is the
        // deliberate cost of fail-closed delivery; #602 instruments that cost
        // via STORAGE_VERIFY_DURATION_SECONDS rather than weakening the
        // guarantee.
        let bytes = data.clone();
        let verify_start = std::time::Instant::now();
        let outcome = tokio::task::spawn_blocking(move || sha256_hex(&bytes)).await;
        STORAGE_VERIFY_DURATION_SECONDS
            .with_label_values(&[label])
            .observe(verify_start.elapsed().as_secs_f64());
        match outcome {
            Ok(actual) if actual == expected => Ok((data, Some(expected))),
            // Genuine hash mismatch — tampering or at-rest corruption.
            // Fail-closed: never serve the tampered bytes (#582).
            Ok(actual) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["get", "integrity_fail"])
                    .inc();
                tracing::error!(
                    key = %key,
                    expected = %expected,
                    actual = %actual,
                    "INTEGRITY VIOLATION: refusing to serve tampered artifact"
                );
                Err(StorageError::IntegrityViolation)
            }
            // Verification task itself panicked. We cannot prove the bytes are
            // intact, so fail closed too — a crashed verifier must not become an
            // integrity bypass (#582).
            Err(e) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["get", "verify_error"])
                    .inc();
                tracing::error!(
                    error = %e,
                    key = %key,
                    "hash verification task failed: refusing to serve unverified artifact"
                );
                Err(StorageError::IntegrityViolation)
            }
        }
    }

    pub async fn get(&self, key: &str) -> Result<Bytes> {
        // Validate locally as the first act, like every Storage wrapper method: a choke point
        // that does not depend on the transitive get_pinned() validation below surviving a future
        // refactor (trust-boundary invariant — mirrors get_verified).
        validate_storage_key(key)?;
        self.get_pinned(key).await.map(|(data, _)| data)
    }

    /// Buffered, integrity-gated read returning a compile-time integrity
    /// witness (typestate pilot — see [`crate::verified`]).
    ///
    /// Runs the same fail-closed gate as [`get`](Self::get): on tamper or a
    /// verify-task panic it returns [`StorageError::IntegrityViolation`] and
    /// yields no witness. It then reflects the outcome in the type:
    ///
    /// - a pin existed and the bytes matched it → [`GateOutcome::Verified`]
    ///   carrying a `Blob<Verified>` (a proof the bytes hash to the recorded
    ///   pin);
    /// - the object carries no pin (written before pins, or stored without a
    ///   digest) → [`GateOutcome::Unpinned`], so a caller cannot mistake the
    ///   open-world case for a verified read.
    ///
    /// [`GateOutcome::Verified`]: nora_registry::verified::GateOutcome::Verified
    /// [`GateOutcome::Unpinned`]: nora_registry::verified::GateOutcome::Unpinned
    ///
    /// The witness is minted by the sound smart-constructor
    /// [`Blob::<Verified>::verify`](nora_registry::verified::Blob::verify), which
    /// re-hashes the bytes — one extra SHA-256 over [`get`] on the pinned path.
    /// The pilot accepts that cost to keep the witness sound-by-construction
    /// without duplicating the security-critical gate; folding the witness into
    /// `get` so the hash runs once is the rollout step.
    pub async fn get_verified(&self, key: &str) -> Result<nora_registry::verified::GateOutcome> {
        // Validate locally as the first act, like every Storage wrapper method:
        // a choke point that does not depend on the transitive get() validation
        // below surviving a future refactor (trust-boundary invariant).
        validate_storage_key(key)?;
        use nora_registry::verified::{Blob, GateOutcome};
        // Reuse the fail-closed gate: it returns Ok only after a digest match or
        // on the open-world / no-pin branch.
        let (data, pin) = self.get_pinned(key).await?;
        match pin {
            Some(pin) => match Blob::verify(data, &pin) {
                Ok(blob) => Ok(GateOutcome::Verified(blob)),
                // The gate already verified these bytes against the same pin, so
                // a mismatch here is unreachable in practice; treat it as a
                // tamper signal and fail closed rather than downgrade.
                Err(_) => Err(StorageError::IntegrityViolation),
            },
            None => Ok(GateOutcome::Unpinned(Blob::raw(data))),
        }
    }

    pub async fn delete(&self, key: &str) -> Result<()> {
        validate_storage_key(key)?;
        match self.inner.delete(key).await {
            Ok(()) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["delete", "ok"])
                    .inc();
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

    /// List keys under `prefix` with their size/mtime, applying the same
    /// `.nora-` internal-file filter as [`list`]. Backends carry the metadata
    /// from the listing itself, avoiding a per-key `stat()` (#738).
    pub async fn list_with_meta(&self, prefix: &str) -> Result<Vec<(String, FileMeta)>> {
        if !prefix.is_empty() {
            validate_storage_key(prefix)?;
        }
        let entries = self.inner.list_with_meta(prefix).await?;
        Ok(entries
            .into_iter()
            .filter(|(k, _)| !k.starts_with(".nora-"))
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

    /// The recorded SHA-256 pin for a storage key, or `None` when the object
    /// carries no pin (written before pins, or stored without a digest).
    pub async fn pin(&self, key: &str) -> Option<String> {
        if validate_storage_key(key).is_err() {
            return None;
        }
        self.inner.pin(key).await
    }

    /// Operator recovery for an artifact whose hash pin no longer matches its
    /// stored bytes (#601). Reads the raw bytes *bypassing* verification — the
    /// whole point, since [`Storage::get`] fails closed on the very mismatch we
    /// are recovering from — and updates the pin to `expected` **only if the
    /// stored bytes already hash to `expected`**.
    ///
    /// `expected` is the SHA-256 the operator independently knows to be
    /// canonical for this key (from a CI manifest, upstream checksum, lockfile,
    /// …). Requiring it is the security guard that keeps this from becoming an
    /// integrity bypass: a plain "recompute the hash from disk" would let
    /// corrupted or tampered bytes silently re-bless themselves, re-opening the
    /// hole #582 closed. By demanding `disk == expected`, re-pin can only ever
    /// set the pin to a hash the stored bytes *already* have **and** the
    /// operator has vouched for. If the bytes are genuinely corrupt
    /// (`disk != expected`) it refuses — re-pin cannot heal corruption; the
    /// operator must restore from backup first.
    ///
    /// `apply == false` is a dry run (computes and compares, writes nothing).
    /// A pin travels with the bytes, and object metadata cannot be changed
    /// without re-writing the object, so applying a re-pin rewrites the
    /// artifact: the file and its sidecar entry on the local backend, the whole
    /// object on an object store.
    pub async fn repin(&self, key: &str, expected: &str, apply: bool) -> Result<RepinOutcome> {
        validate_storage_key(key)?;
        let expected = expected.to_ascii_lowercase();
        // Raw read — deliberately bypasses `Storage::get()`'s verification,
        // which would fail closed on the mismatch we are recovering from.
        let (data, old) = self.inner.get(key).await?;
        let disk = sha256_hex(&data);
        if disk != expected {
            // The stored bytes are not the ones the operator vouched for —
            // genuine corruption/tampering. Re-pin must NOT bless them.
            return Ok(RepinOutcome::DiskMismatch { disk, expected });
        }
        if old.as_deref() == Some(expected.as_str()) {
            return Ok(RepinOutcome::AlreadyPinned { hash: expected });
        }
        if !apply {
            return Ok(RepinOutcome::WouldUpdate { old, new: expected });
        }
        self.inner.put(key, &data, &expected).await?;
        Ok(RepinOutcome::Updated { old, new: expected })
    }

    /// Refresh cached total_size. No-op for local storage, computes for S3.
    pub async fn refresh_total_size_cache(&self) {
        self.inner.refresh_total_size().await;
    }

    /// Move or copy a file from `src` into storage under `key`.
    ///
    /// When `sha256` is `Some`, the backend pins the object to that digest
    /// without re-reading the file — used by streaming paths where the hash was
    /// computed incrementally (#580). When it is `None` the object is stored
    /// unpinned (legacy behaviour for callers that verified integrity
    /// separately).
    pub async fn put_from_path(&self, key: &str, src: &Path, sha256: Option<&str>) -> Result<()> {
        validate_storage_key(key)?;
        let sha256 = sha256.map(str::to_ascii_lowercase);
        match self.inner.put_from_path(key, src, sha256.as_deref()).await {
            Ok(()) => {
                STORAGE_OPERATIONS.with_label_values(&["put", "ok"]).inc();
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

    /// Server-side copy of `src` to `dst` (see [`StorageBackend::copy`]).
    ///
    /// `sha256` is the lowercase hex digest of the copied bytes; when present it
    /// pins `dst` without reading the object back. When it is `None`, `dst`
    /// inherits the pin of `src` if `src` carries one, and otherwise stays
    /// open-world — as [`put_from_path`](Self::put_from_path) does.
    pub async fn copy(&self, src: &str, dst: &str, sha256: Option<&str>) -> Result<()> {
        validate_storage_key(src)?;
        validate_storage_key(dst)?;
        let sha256 = sha256.map(str::to_ascii_lowercase);
        match self.inner.copy(src, dst, sha256.as_deref()).await {
            Ok(()) => {
                STORAGE_OPERATIONS.with_label_values(&["copy", "ok"]).inc();
                Ok(())
            }
            Err(e) => {
                STORAGE_OPERATIONS
                    .with_label_values(&["copy", "error"])
                    .inc();
                Err(e)
            }
        }
    }

    /// Open an artifact for streaming read without loading it into memory (#580).
    ///
    /// Returns `(size_bytes, pin, reader)`. The bytes are NOT verified here —
    /// streaming prevents a full-body hash before the first frame — so callers
    /// hash the stream and check it against `pin` at EOF (see raw's
    /// `verify_while_streaming`), or rely on a content-addressed digest.
    pub async fn get_reader(
        &self,
        key: &str,
    ) -> Result<(u64, Option<String>, Pin<Box<dyn AsyncRead + Send + Unpin>>)> {
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

    /// The GCS wrapper constructs without credentials or network.
    #[test]
    fn test_new_gcs_wrapper() {
        let storage = Storage::new_gcs("test-bucket", None, Some("http://localhost:4443"));
        assert_eq!(storage.backend_name(), "gcs");
    }

    /// Wait until the pin record from `put()` is visible. Since #604 `put()`
    /// awaits the pin, so this returns on the first poll; kept for robustness.
    async fn await_pin(storage: &Storage, key: &str) {
        for _ in 0..200 {
            if storage.pin(key).await.is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("pin for {key} was never recorded");
    }

    fn object_storage() -> (Arc<ObjectStorage>, Storage) {
        let backend = Arc::new(ObjectStorage::in_memory());
        let storage = Storage::from_backend(backend.clone());
        (backend, storage)
    }

    /// Regression for #604: `put()` must record the hash-pin BEFORE it returns,
    /// so there is no window where a completed put leaves the artifact readable
    /// but unpinned (which a later `get()` would serve unverified). Exercises
    /// the real call path `Storage::put()` → `pin()` — the pin is
    /// observable synchronously, with no polling.
    #[tokio::test]
    async fn put_records_pin_before_returning() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());

        storage.put("raw/x/app.bin", b"payload").await.unwrap();

        assert!(
            storage.pin("raw/x/app.bin").await.is_some(),
            "put() must record the hash-pin before returning (#604)"
        );
        // And the recorded pin must match the bytes (a subsequent get verifies).
        assert_eq!(&storage.get("raw/x/app.bin").await.unwrap()[..], b"payload");
    }

    /// A cross-repo copy must land the same bytes AND arrive pinned, so the
    /// destination is served verified rather than open-world.
    #[tokio::test]
    async fn copy_duplicates_bytes_and_pins_destination() {
        use nora_registry::verified::GateOutcome;

        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        let hash = hex::encode(Sha256::digest(b"layer"));

        storage.put("docker/src/blobs/x", b"layer").await.unwrap();
        storage
            .copy("docker/src/blobs/x", "docker/dst/blobs/x", Some(&hash))
            .await
            .unwrap();

        assert_eq!(
            &storage.get("docker/dst/blobs/x").await.unwrap()[..],
            b"layer"
        );
        assert_eq!(
            storage.pin("docker/dst/blobs/x").await.as_deref(),
            Some(hash.as_str())
        );
        assert!(matches!(
            storage.get_verified("docker/dst/blobs/x").await.unwrap(),
            GateOutcome::Verified(_)
        ));
    }

    #[tokio::test]
    async fn copy_missing_source_is_not_found() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());

        assert!(matches!(
            storage
                .copy("docker/src/blobs/gone", "docker/dst/blobs/gone", None)
                .await,
            Err(StorageError::NotFound)
        ));
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

    /// Regression for #604: the streaming write path `put_from_path()` — the one
    /// that handles Docker blobs — must record its pin BEFORE returning, so the
    /// pin is observable the moment the call completes. Exercises the real call
    /// path.
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
            storage.pin(key).await.as_deref(),
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

    /// `get_verified` reflects the gate outcome in the type: a pinned key yields
    /// `GateOutcome::Verified`, an unpinned (open-world) key yields `Unpinned`,
    /// and a tampered pinned artifact still fails closed — no witness is minted
    /// for bytes that fail the gate (the typestate cannot launder tampered data).
    #[tokio::test]
    async fn get_verified_reflects_pin_state_and_fails_closed() {
        use nora_registry::verified::GateOutcome;
        let dir = TempDir::new().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());

        // Pinned + matching → Verified, bytes intact.
        let key = "raw/v/app.bin";
        storage.put(key, b"verified-bytes").await.unwrap();
        match storage.get_verified(key).await.unwrap() {
            GateOutcome::Verified(blob) => assert_eq!(&blob.into_inner()[..], b"verified-bytes"),
            GateOutcome::Unpinned(_) => panic!("pinned key must yield Verified"),
        }

        // Unpinned key (written straight to disk, no pin) → Unpinned (open-world).
        let unpinned = "raw/v/unpinned.bin";
        std::fs::write(dir.path().join(unpinned), b"no-pin").unwrap();
        match storage.get_verified(unpinned).await.unwrap() {
            GateOutcome::Unpinned(blob) => assert_eq!(&blob.into_inner()[..], b"no-pin"),
            GateOutcome::Verified(_) => panic!("unpinned key must yield Unpinned"),
        }

        // Tamper the pinned artifact on disk → fail closed, no witness produced.
        std::fs::write(dir.path().join(key), b"TAMPERED").unwrap();
        assert!(matches!(
            storage.get_verified(key).await,
            Err(StorageError::IntegrityViolation)
        ));
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
        assert_eq!(storage.pin(key).await.as_deref(), Some(genuine.as_str()));
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
            storage.pin(key).await,
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
        assert_eq!(storage.pin(key).await.as_deref(), Some(expected.as_str()));
        assert_eq!(&storage.get(key).await.unwrap()[..], b"orphan-bytes");
    }

    // --- Object-store backend: the pin is user-defined object metadata ---

    /// A pinned object round-trips its pin through the store's metadata, so the
    /// gate verifies it exactly as it does on the local backend.
    #[tokio::test]
    async fn object_put_pins_and_verifies() {
        use nora_registry::verified::GateOutcome;
        let (_, storage) = object_storage();
        let key = "raw/obj/app.bin";

        storage.put(key, b"object-bytes").await.unwrap();

        assert_eq!(&storage.get(key).await.unwrap()[..], b"object-bytes");
        assert_eq!(
            storage.pin(key).await.as_deref(),
            Some(sha_hex(b"object-bytes").as_str())
        );
        assert!(matches!(
            storage.get_verified(key).await.unwrap(),
            GateOutcome::Verified(_)
        ));
    }

    /// The streaming write path pins when the caller computed a digest, and
    /// leaves the object open-world when it did not.
    #[tokio::test]
    async fn object_put_from_path_pins_only_with_a_digest() {
        use nora_registry::verified::GateOutcome;
        let (_, storage) = object_storage();
        let dir = TempDir::new().unwrap();

        let src = dir.path().join("pinned.bin");
        std::fs::write(&src, b"streamed").unwrap();
        let sha = sha_hex(b"streamed");
        storage
            .put_from_path("raw/obj/pinned.bin", &src, Some(&sha))
            .await
            .unwrap();
        assert_eq!(
            storage.pin("raw/obj/pinned.bin").await.as_deref(),
            Some(sha.as_str())
        );

        let src = dir.path().join("unpinned.bin");
        std::fs::write(&src, b"streamed").unwrap();
        storage
            .put_from_path("raw/obj/unpinned.bin", &src, None)
            .await
            .unwrap();
        assert_eq!(storage.pin("raw/obj/unpinned.bin").await, None);
        assert!(matches!(
            storage.get_verified("raw/obj/unpinned.bin").await.unwrap(),
            GateOutcome::Unpinned(_)
        ));
    }

    /// A store-side copy carries the source's user metadata, so the destination
    /// inherits the pin without the wrapper re-writing it.
    #[tokio::test]
    async fn object_copy_inherits_the_source_pin() {
        let (_, storage) = object_storage();
        storage.put("docker/src/blobs/x", b"layer").await.unwrap();

        storage
            .copy("docker/src/blobs/x", "docker/dst/blobs/x", None)
            .await
            .unwrap();

        assert_eq!(
            storage.pin("docker/dst/blobs/x").await.as_deref(),
            Some(sha_hex(b"layer").as_str())
        );
        assert_eq!(
            &storage.get("docker/dst/blobs/x").await.unwrap()[..],
            b"layer"
        );
    }

    /// Regression for #582 on an object store: bytes replaced under an unchanged
    /// pin must not be served. Writes through the backend directly, bypassing
    /// the wrapper — exactly the out-of-band tamper the pin exists to catch.
    #[tokio::test]
    async fn object_get_fails_closed_on_integrity_mismatch() {
        let (backend, storage) = object_storage();
        let key = "raw/obj/tampered.bin";

        storage.put(key, b"genuine-bytes").await.unwrap();
        backend
            .put(key, b"TAMPERED", &sha_hex(b"genuine-bytes"))
            .await
            .unwrap();

        assert!(matches!(
            storage.get(key).await,
            Err(StorageError::IntegrityViolation)
        ));
    }

    /// Objects written before pins existed carry no metadata: they stay
    /// readable and open-world, with no migration.
    #[tokio::test]
    async fn object_without_metadata_is_open_world() {
        use object_store::{ObjectStoreExt, PutPayload};
        let (backend, storage) = object_storage();
        let key = "raw/obj/legacy.bin";

        backend
            .store()
            .put(
                &object_store::path::Path::from(key),
                PutPayload::from_static(b"pre-existing"),
            )
            .await
            .unwrap();

        assert_eq!(&storage.get(key).await.unwrap()[..], b"pre-existing");
        assert_eq!(storage.pin(key).await, None);
    }

    /// #601 on an object store: re-pin still refuses bytes the operator did not
    /// vouch for, and applying it rewrites the object with the new pin.
    #[tokio::test]
    async fn object_repin_refuses_mismatch_and_pins_on_match() {
        let (_, storage) = object_storage();
        let dir = TempDir::new().unwrap();
        let key = "raw/obj/repin.bin";

        // An unpinned object (streamed in without a digest) is the recoverable
        // orphan case.
        let src = dir.path().join("orphan.bin");
        std::fs::write(&src, b"orphan-bytes").unwrap();
        storage.put_from_path(key, &src, None).await.unwrap();

        let wrong = sha_hex(b"something-else");
        assert_eq!(
            storage.repin(key, &wrong, true).await.unwrap(),
            RepinOutcome::DiskMismatch {
                disk: sha_hex(b"orphan-bytes"),
                expected: wrong,
            }
        );

        let expected = sha_hex(b"orphan-bytes");
        assert_eq!(
            storage.repin(key, &expected, true).await.unwrap(),
            RepinOutcome::Updated {
                old: None,
                new: expected.clone(),
            }
        );
        assert_eq!(storage.pin(key).await.as_deref(), Some(expected.as_str()));
        assert_eq!(&storage.get(key).await.unwrap()[..], b"orphan-bytes");
    }
}
