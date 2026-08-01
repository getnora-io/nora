// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use async_trait::async_trait;
use axum::body::Bytes;
use futures::TryStreamExt;
use object_store::aws::AmazonS3Builder;
use object_store::gcp::GoogleCloudStorageBuilder;
use object_store::path::Path;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutPayload, WriteMultipart};
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{FileMeta, Result, StorageBackend, StorageError};

/// Object-store backend (S3-compatible or Google Cloud Storage) using the
/// `object_store` crate. Everything past construction goes through the
/// [`ObjectStore`] trait, so both providers share one implementation.
pub struct ObjectStorage {
    store: Box<dyn ObjectStore>,
    /// "s3" or "gcs" — surfaced in /health.
    name: &'static str,
    /// Cached total size in bytes, refreshed by background task.
    cached_total_size: std::sync::atomic::AtomicU64,
    /// Whether cached_total_size has been initialized at least once.
    size_cache_initialized: std::sync::atomic::AtomicBool,
    /// Outcome of the last background refresh, served by `health_check()`.
    /// Starts `false` so readiness gates until the boot refresh confirms the
    /// store — a live probe here would list the whole bucket on every kubelet
    /// and LB health check, and slow listings under load mark the backend
    /// unhealthy exactly when it is busiest (#869).
    cached_reachable: std::sync::atomic::AtomicBool,
    /// Unix seconds of the last background refresh (`0` = never refreshed). Paired with
    /// `cached_reachable`, which is only ever written by the 60s maintenance loop: if that
    /// task stalls or dies, the stale flag would otherwise pin readiness forever. A refresh
    /// older than `HEALTH_MAX_STALE_SECS` is treated as unreachable (#872).
    last_refresh_unix: std::sync::atomic::AtomicU64,
}

/// Reachability older than this is treated as unknown → unreachable. 2.5× the 60s background
/// refresh cadence: tolerates one missed refresh + jitter without flapping, but a stalled or
/// dead maintenance loop un-readies the pod within the window instead of pinning a stale
/// `true` (#872).
const HEALTH_MAX_STALE_SECS: i64 = 150;

impl ObjectStorage {
    /// Create new S3 storage with optional credentials.
    ///
    /// `virtual_hosted` selects the request addressing style: `false` (default) appends
    /// the bucket to the endpoint path (`<endpoint>/<bucket>/<key>`); `true` uses the
    /// endpoint VERBATIM (`<endpoint>/<key>`), so the endpoint itself must include the
    /// bucket host (e.g. `https://<bucket>.oss-<region>.aliyuncs.com`). Needed for
    /// providers that reject signed path-style requests, e.g. Alibaba Cloud OSS.
    pub fn new(
        s3_url: &str,
        bucket: &str,
        region: &str,
        access_key: Option<&str>,
        secret_key: Option<&str>,
        virtual_hosted: bool,
    ) -> Self {
        let url = s3_url.trim_end_matches('/');
        let allow_http = url.starts_with("http://");

        let mut builder = AmazonS3Builder::new()
            .with_endpoint(url)
            .with_bucket_name(bucket)
            .with_region(region)
            .with_allow_http(allow_http)
            .with_virtual_hosted_style_request(virtual_hosted);

        match (access_key, secret_key) {
            (Some(ak), Some(sk)) => {
                builder = builder.with_access_key_id(ak).with_secret_access_key(sk);
            }
            _ => {
                builder = builder.with_skip_signature(true);
            }
        }

        let store = builder.build().expect("Failed to build S3 client");

        Self {
            store: Box::new(store),
            name: "s3",
            cached_total_size: std::sync::atomic::AtomicU64::new(0),
            size_cache_initialized: std::sync::atomic::AtomicBool::new(false),
            cached_reachable: std::sync::atomic::AtomicBool::new(false),
            last_refresh_unix: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create new Google Cloud Storage backend.
    ///
    /// Credentials resolve in order: explicit `service_account_path` (JSON key
    /// file), ambient `GOOGLE_*` environment (`GOOGLE_SERVICE_ACCOUNT`,
    /// `GOOGLE_APPLICATION_CREDENTIALS`, ...), then the instance metadata
    /// server — so GKE Workload Identity and GCE service accounts work with no
    /// key material at all. `base_url` overrides the endpoint for emulators
    /// (fake-gcs-server) or private access endpoints; an `http://` base_url
    /// also skips request signing (emulators don't verify signatures).
    pub fn new_gcs(
        bucket: &str,
        service_account_path: Option<&str>,
        base_url: Option<&str>,
    ) -> Self {
        let mut builder = GoogleCloudStorageBuilder::from_env().with_bucket_name(bucket);
        if let Some(path) = service_account_path {
            builder = builder.with_service_account_path(path);
        }
        if let Some(url) = base_url {
            let allow_http = url.starts_with("http://");
            builder = builder.with_base_url(url).with_client_options(
                object_store::ClientOptions::new().with_allow_http(allow_http),
            );
            if allow_http {
                builder = builder.with_skip_signature(true);
            }
        }
        let store = builder.build().expect("Failed to build GCS client");

        Self {
            store: Box::new(store),
            name: "gcs",
            cached_total_size: std::sync::atomic::AtomicU64::new(0),
            size_cache_initialized: std::sync::atomic::AtomicBool::new(false),
            cached_reachable: std::sync::atomic::AtomicBool::new(false),
            last_refresh_unix: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

/// Encode `@` in object keys to `%40` for SeaweedFS compatibility (shared by
/// every object-store backend so all providers use one key scheme).
///
/// SeaweedFS returns 500 on GET/PUT for keys containing `@`
/// (e.g. npm scoped packages like `npm/@babel/core/...`).
///
/// Uses `%40` (URL-encoding style) instead of `_at_` to avoid roundtrip
/// collisions with keys containing literal `_at_` (e.g. `look_at_this`) (#534).
fn encode_object_key(key: &str) -> String {
    key.replace('@', "%40")
}

/// Legacy encoding: `@` → `_at_` (used before #534).
/// Only needed for fallback reads of pre-migration data.
fn encode_object_key_legacy(key: &str) -> String {
    key.replace('@', "_at_")
}

/// Decode S3 keys back to original form.
///
/// `encode_object_key` maps `@` -> `%40`, but `object_store::path::Path` percent-
/// encodes the `%` we introduced (its INVALID set includes `%`, not `@`), so the
/// byte actually written — and returned by `list()`/`list_with_meta()` in
/// `meta.location` — is DOUBLE-encoded `%2540`, not `%40`. Reversing only `%40`
/// left the double form intact, so a follow-up `get()` on the listed key encoded a
/// third time (`%252540`) and 404'd. Net effect: scoped npm packages (`@scope/name`)
/// listed as if they had no versions, so scan-regenerate wrote an EMPTY packument on
/// every publish and `npm install` failed `ENOVERSIONS` (#878, S3/object_store only —
/// local FS has no `%` re-encoding). Reverse the double form FIRST, then the single
/// form (a backend that does not re-encode, e.g. an in-memory mock). Non-scoped keys
/// carry no `%` and are untouched by either replace.
///
/// Legacy `_at_` keys from pre-#534 data are still NOT decoded here — they are
/// handled by fallback reads in `get()`/`stat()`, avoiding the roundtrip collision
/// where a literal `_at_` (e.g. `cargo/look_at_this/`) would be wrongly decoded.
fn decode_object_key(key: &str) -> String {
    key.replace("%2540", "@").replace("%40", "@")
}

/// Map object_store errors to StorageError.
fn map_err(e: object_store::Error) -> StorageError {
    match e {
        object_store::Error::NotFound { .. } => StorageError::NotFound,
        object_store::Error::AlreadyExists { .. } => StorageError::AlreadyExists,
        other => StorageError::Network(other.to_string()),
    }
}

#[async_trait]
impl StorageBackend for ObjectStorage {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()> {
        let encoded = encode_object_key(key);
        let path = Path::from(encoded);
        let payload = PutPayload::from(data.to_vec());
        self.store.put(&path, payload).await.map_err(map_err)?;
        Ok(())
    }

    async fn put_if_absent(&self, key: &str, data: &[u8]) -> Result<()> {
        let encoded = encode_object_key(key);
        let path = Path::from(encoded);
        let payload = PutPayload::from(data.to_vec());
        self.store
            .put_opts(&path, payload, PutMode::Create.into())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let encoded = encode_object_key(key);
        let path = Path::from(encoded);
        match self.store.get(&path).await {
            Ok(result) => {
                let bytes = result.bytes().await.map_err(map_err)?;
                Ok(bytes)
            }
            Err(object_store::Error::NotFound { .. }) if key.contains('@') => {
                // Fallback: try legacy _at_ encoding for pre-#534 data.
                // Only needed when key contains @, since otherwise both schemes produce the same output.
                let legacy_path = Path::from(encode_object_key_legacy(key));
                let result = self.store.get(&legacy_path).await.map_err(map_err)?;
                let bytes = result.bytes().await.map_err(map_err)?;
                Ok(bytes)
            }
            Err(e) => Err(map_err(e)),
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let encoded = encode_object_key(key);
        let path = Path::from(encoded);
        self.store.delete(&path).await.map_err(map_err)?;
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let encoded = encode_object_key(prefix);
        let prefix_path = Path::from(encoded);
        let list_prefix = if prefix.is_empty() {
            None
        } else {
            Some(&prefix_path)
        };

        // Collect all objects from the listing stream.
        let objects: Vec<_> = self
            .store
            .list(list_prefix)
            .try_collect()
            .await
            .map_err(|e| StorageError::Network(e.to_string()))?;

        Ok(objects
            .into_iter()
            .map(|meta| decode_object_key(meta.location.as_ref()))
            .collect())
    }

    async fn list_with_meta(&self, prefix: &str) -> Result<Vec<(String, FileMeta)>> {
        let encoded = encode_object_key(prefix);
        let prefix_path = Path::from(encoded);
        let list_prefix = if prefix.is_empty() {
            None
        } else {
            Some(&prefix_path)
        };

        let objects: Vec<_> = self
            .store
            .list(list_prefix)
            .try_collect()
            .await
            .map_err(|e| StorageError::Network(e.to_string()))?;

        // The LIST response already carries size/last_modified — reuse it
        // instead of issuing a HEAD per key (#738).
        Ok(objects
            .into_iter()
            .map(|meta| {
                let modified = meta.last_modified.timestamp().try_into().unwrap_or(0u64);
                (
                    decode_object_key(meta.location.as_ref()),
                    FileMeta {
                        size: meta.size,
                        modified,
                    },
                )
            })
            .collect())
    }

    async fn stat(&self, key: &str) -> Option<FileMeta> {
        let encoded = encode_object_key(key);
        let path = Path::from(encoded);
        let meta = match self.store.head(&path).await {
            Ok(m) => m,
            Err(_) if key.contains('@') => {
                // Fallback: try legacy _at_ encoding for pre-#534 data
                let legacy_path = Path::from(encode_object_key_legacy(key));
                self.store.head(&legacy_path).await.ok()?
            }
            Err(_) => return None,
        };

        let modified = meta.last_modified.timestamp().try_into().unwrap_or(0u64);

        Some(FileMeta {
            size: meta.size,
            modified,
        })
    }

    async fn health_check(&self) -> bool {
        // Cached outcome of the last background refresh (#869) — probes must never hit the
        // store. False until the boot refresh succeeds, so readiness still gates a
        // misconfigured store at rollout. Self-expiring (#872): the flag is only written by
        // the 60s maintenance loop, so a stalled or dead loop lets the staleness window lapse
        // and un-readies the pod rather than pinning a stale `true` forever.
        self.cached_reachable
            .load(std::sync::atomic::Ordering::Relaxed)
            && crate::cache_ttl::is_within_ttl(
                self.last_refresh_unix
                    .load(std::sync::atomic::Ordering::Relaxed),
                HEALTH_MAX_STALE_SECS,
            )
    }

    async fn total_size(&self) -> u64 {
        self.cached_total_size
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn backend_name(&self) -> &'static str {
        self.name
    }

    async fn refresh_total_size(&self) {
        let result: std::result::Result<Vec<_>, _> = self.store.list(None).try_collect().await;

        self.cached_reachable
            .store(result.is_ok(), std::sync::atomic::Ordering::Relaxed);
        // Stamp every run (success or failure): this marks the maintenance loop as alive so
        // `health_check` can expire the cached verdict if the loop stops (#872).
        self.last_refresh_unix.store(
            crate::cache_ttl::now_unix(),
            std::sync::atomic::Ordering::Relaxed,
        );
        if let Ok(objects) = result {
            let total: u64 = objects.iter().map(|m| m.size).sum();
            self.cached_total_size
                .store(total, std::sync::atomic::Ordering::Relaxed);
            self.size_cache_initialized
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    async fn put_from_path(&self, key: &str, src: &std::path::Path) -> Result<()> {
        let encoded = encode_object_key(key);
        let s3_path = Path::from(encoded);

        // Streaming multipart upload: read file in 8 MiB chunks, feed to
        // WriteMultipart which buffers into 5 MiB parts and uploads in
        // parallel. Never loads the entire file into RAM (#580).
        let mut file = tokio::fs::File::open(src).await?;

        // CANCEL-SAFETY: if dropped between put_multipart and finish,
        // S3 does NOT automatically abort orphaned parts. Cleanup depends
        // on S3 lifecycle policy (AbortIncompleteMultipartUpload rule).
        // No partial objects are visible to readers (upload never completed).
        // finish() calls abort() on its own errors; cancellation (future
        // dropped) relies on lifecycle policy only.
        let upload = self.store.put_multipart(&s3_path).await.map_err(map_err)?;
        let mut writer = WriteMultipart::new(upload);

        let mut buf = vec![0u8; 8 * 1024 * 1024]; // 8 MiB read buffer
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            writer.write(&buf[..n]);
        }
        writer.finish().await.map_err(map_err)?;

        let _ = tokio::fs::remove_file(src).await;
        Ok(())
    }

    async fn get_reader(&self, key: &str) -> Result<(u64, Pin<Box<dyn AsyncRead + Send + Unpin>>)> {
        let encoded = encode_object_key(key);
        let path = Path::from(encoded);
        let result = match self.store.get(&path).await {
            Ok(r) => r,
            Err(object_store::Error::NotFound { .. }) if key.contains('@') => {
                let legacy_path = Path::from(encode_object_key_legacy(key));
                self.store.get(&legacy_path).await.map_err(map_err)?
            }
            Err(e) => return Err(map_err(e)),
        };
        let size = result.meta.size;
        let stream = result.into_stream().map_err(std::io::Error::other);
        let reader = tokio_util::io::StreamReader::new(stream);
        Ok((size as u64, Box::pin(reader)))
    }

    async fn get_range(
        &self,
        key: &str,
        start: u64,
        end: u64,
    ) -> Result<(u64, Pin<Box<dyn AsyncRead + Send + Unpin>>)> {
        let make_opts = || object_store::GetOptions {
            range: Some(object_store::GetRange::Bounded(start..(end + 1))),
            ..Default::default()
        };
        let path = Path::from(encode_object_key(key));
        let result = match self.store.get_opts(&path, make_opts()).await {
            Ok(r) => r,
            Err(object_store::Error::NotFound { .. }) if key.contains('@') => {
                let legacy_path = Path::from(encode_object_key_legacy(key));
                self.store
                    .get_opts(&legacy_path, make_opts())
                    .await
                    .map_err(map_err)?
            }
            Err(e) => return Err(map_err(e)),
        };
        let size = result.meta.size;
        let stream = result.into_stream().map_err(std::io::Error::other);
        let reader = tokio_util::io::StreamReader::new(stream);
        Ok((size as u64, Box::pin(reader)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_name() {
        let storage = ObjectStorage::new(
            "http://localhost:9000",
            "test-bucket",
            "us-east-1",
            Some("access"),
            Some("secret"),
            false,
        );
        assert_eq!(storage.backend_name(), "s3");
    }

    /// `health_check` is a cached signal (#869): false at construction (probes do no
    /// store I/O), and still false after a refresh against an unreachable endpoint.
    /// The true-path is the background refresh loop against a live store.
    #[tokio::test]
    async fn test_health_check_cached_not_live() {
        let storage = ObjectStorage::new("http://127.0.0.1:1", "b", "r", None, None, false);
        assert!(!storage.health_check().await);
        storage.refresh_total_size().await;
        assert!(!storage.health_check().await);
    }

    /// Cached reachability self-expires (#872): a `true` verdict whose last refresh is older
    /// than `HEALTH_MAX_STALE_SECS` (a stalled or dead maintenance loop) must NOT keep the pod
    /// ready. Only a recent refresh keeps `health_check` true.
    #[tokio::test]
    async fn test_health_check_expires_when_refresh_stalls() {
        use std::sync::atomic::Ordering::Relaxed;
        let storage = ObjectStorage::new("http://127.0.0.1:1", "b", "r", None, None, false);
        let now = crate::cache_ttl::now_unix();

        // A since-dead refresh loop: reachable was true, but the last refresh is ancient.
        storage.cached_reachable.store(true, Relaxed);
        storage
            .last_refresh_unix
            .store(now.saturating_sub(10_000), Relaxed);
        assert!(
            !storage.health_check().await,
            "stale reachability must not keep readiness up"
        );

        // A fresh refresh timestamp → reachable again.
        storage.last_refresh_unix.store(now, Relaxed);
        assert!(storage.health_check().await);
    }

    /// #878 unit guard: `decode_object_key` must reverse the DOUBLE-encoded `%2540`
    /// that `object_store::path::Path` produces from our `%40`, the single `%40`
    /// (a non-re-encoding backend), and must NOT touch a literal `_at_`.
    #[test]
    fn decode_reverses_double_encoded_at() {
        assert_eq!(
            decode_object_key("npm/%2540scope/pkg/metadata.json"),
            "npm/@scope/pkg/metadata.json"
        );
        assert_eq!(decode_object_key("npm/%40scope/x"), "npm/@scope/x");
        assert_eq!(
            decode_object_key("cargo/look_at_this/x"),
            "cargo/look_at_this/x"
        );
    }

    /// #878 regression through the REAL scan-regenerate call path (list -> get) against a
    /// live object_store. The `%`-re-encoding lives in `Path`, not the S3 backend, so the
    /// in-memory store reproduces the double-encoding faithfully — no MinIO needed. Before
    /// the `decode_object_key` fix, `list()` returned the `%2540` key, the follow-up `get()`
    /// re-encoded a third time and 404'd, and every scoped npm publish regenerated an empty
    /// packument (`npm install` -> ENOVERSIONS).
    #[tokio::test]
    async fn scoped_key_lists_and_gets_through_path_encoding() {
        let storage = ObjectStorage {
            store: Box::new(object_store::memory::InMemory::new()),
            name: "s3",
            cached_total_size: std::sync::atomic::AtomicU64::new(0),
            size_cache_initialized: std::sync::atomic::AtomicBool::new(false),
            cached_reachable: std::sync::atomic::AtomicBool::new(true),
            last_refresh_unix: std::sync::atomic::AtomicU64::new(0),
        };

        let key = "npm/@scope/pkg/versions/1.0.0.json";
        storage.put(key, br#"{"version":"1.0.0"}"#).await.unwrap();

        // Control: a non-scoped key (no `@`, no `%`) is unaffected.
        let plain = "npm/plainpkg/versions/1.0.0.json";
        storage.put(plain, br#"{"version":"1.0.0"}"#).await.unwrap();

        // list() must return the ORIGINAL logical key (with `@`), not the `%2540` form.
        let listed = storage.list("npm/@scope/pkg/versions/").await.unwrap();
        assert_eq!(
            listed,
            vec![key.to_string()],
            "list must decode %2540 back to @ so scan-regenerate can read it"
        );

        // The listed key must be directly get-able — the exact scan-regenerate step that
        // silently dropped scoped versions before the fix.
        let got = storage
            .get(&listed[0])
            .await
            .expect("get on the listed key must succeed");
        assert_eq!(&got[..], br#"{"version":"1.0.0"}"#);

        let listed_plain = storage.list("npm/plainpkg/versions/").await.unwrap();
        assert_eq!(listed_plain, vec![plain.to_string()]);
        assert!(storage.get(&listed_plain[0]).await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_put_if_absent_has_exactly_one_winner() {
        const CONTENDERS: usize = 16;
        let storage = std::sync::Arc::new(ObjectStorage {
            store: Box::new(object_store::memory::InMemory::new()),
            name: "s3",
            cached_total_size: std::sync::atomic::AtomicU64::new(0),
            size_cache_initialized: std::sync::atomic::AtomicBool::new(false),
            cached_reachable: std::sync::atomic::AtomicBool::new(true),
            last_refresh_unix: std::sync::atomic::AtomicU64::new(0),
        });
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(CONTENDERS));

        let mut handles = Vec::new();
        for i in 0..CONTENDERS {
            let storage = std::sync::Arc::clone(&storage);
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                let payload = vec![i as u8; 4096];
                barrier.wait().await;
                (i as u8, storage.put_if_absent("raw/shared", &payload).await)
            }));
        }

        let mut winner = None;
        let mut conflicts = 0;
        for handle in handles {
            let (candidate, result) = handle.await.expect("task panicked");
            match result {
                Ok(()) => assert!(
                    winner.replace(candidate).is_none(),
                    "more than one conditional object put succeeded"
                ),
                Err(StorageError::AlreadyExists) => conflicts += 1,
                Err(e) => panic!("unexpected conditional-put error: {e}"),
            }
        }

        let winner = winner.expect("one contender must create the object");
        assert_eq!(conflicts, CONTENDERS - 1);
        let stored = storage.get("raw/shared").await.unwrap();
        assert_eq!(stored.len(), 4096);
        assert!(stored.iter().all(|byte| *byte == winner));
    }

    #[test]
    fn test_s3_storage_creation_anonymous() {
        let storage = ObjectStorage::new(
            "http://localhost:9000",
            "test-bucket",
            "us-east-1",
            None,
            None,
            false,
        );
        assert_eq!(storage.backend_name(), "s3");
    }

    /// GCS construction with no credentials and an emulator base_url — the
    /// builder resolves credentials lazily (no build-time I/O), same contract
    /// as the anonymous S3 construction test above.
    #[test]
    fn test_gcs_storage_creation_emulator() {
        let storage = ObjectStorage::new_gcs("test-bucket", None, Some("http://localhost:4443"));
        assert_eq!(storage.backend_name(), "gcs");
    }

    /// GCS construction against the real endpoint (no base_url, no explicit
    /// service account) — the ambient-credential ladder must also be lazy.
    #[test]
    fn test_gcs_storage_creation_default_endpoint() {
        let storage = ObjectStorage::new_gcs("test-bucket", None, None);
        assert_eq!(storage.backend_name(), "gcs");
    }

    /// Empty ListObjectsV2 body so `refresh_total_size`'s `list(None)` succeeds against the mock.
    const EMPTY_LIST_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>test-bucket</Name><KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>"#;

    /// Run one `refresh_total_size` (a ListObjectsV2) against a mock server and return the
    /// request path the client actually used. Also covers the cached-reachability true
    /// path (#869): a successful refresh flips `health_check()` to true.
    async fn observed_list_path(virtual_hosted: bool) -> String {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_raw(EMPTY_LIST_XML, "application/xml"),
            )
            .mount(&server)
            .await;
        let storage = ObjectStorage::new(
            &server.uri(),
            "test-bucket",
            "us-east-1",
            Some("access"),
            Some("secret"),
            virtual_hosted,
        );
        assert!(!storage.health_check().await);
        storage.refresh_total_size().await;
        assert!(storage.health_check().await);
        let requests = server.received_requests().await.unwrap();
        requests[0].url.path().to_string()
    }

    /// Path-style (default): the bucket is addressed in the URL path.
    #[tokio::test]
    async fn test_path_style_addresses_bucket_in_path() {
        assert_eq!(observed_list_path(false).await, "/test-bucket");
    }

    /// Virtual-hosted: `object_store` uses the configured endpoint VERBATIM — the bucket is
    /// not injected into host or path, so the endpoint itself must carry the bucket host
    /// (e.g. `https://<bucket>.oss-<region>.aliyuncs.com`). This is the contract the docs
    /// describe; if `object_store` ever changes it, this test flags the doc drift.
    #[tokio::test]
    async fn test_virtual_hosted_uses_endpoint_verbatim() {
        assert_eq!(observed_list_path(true).await, "/");
    }

    #[test]
    fn test_s3_total_size_returns_zero_before_init() {
        let storage = ObjectStorage::new(
            "http://localhost:9000",
            "test-bucket",
            "us-east-1",
            Some("access"),
            Some("secret"),
            false,
        );
        assert!(!storage
            .size_cache_initialized
            .load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn test_error_mapping_not_found() {
        let err = object_store::Error::NotFound {
            path: "test/key".to_string(),
            source: "not found".into(),
        };
        match map_err(err) {
            StorageError::NotFound => {}
            other => panic!("Expected NotFound, got: {:?}", other),
        }
    }

    #[test]
    fn test_error_mapping_already_exists() {
        let err = object_store::Error::AlreadyExists {
            path: "test/key".to_string(),
            source: "exists".into(),
        };
        assert!(matches!(map_err(err), StorageError::AlreadyExists));
    }

    #[test]
    fn test_error_mapping_network() {
        let err = object_store::Error::Generic {
            store: "S3",
            source: "connection refused".into(),
        };
        match map_err(err) {
            StorageError::Network(msg) => {
                assert!(msg.contains("connection refused"));
            }
            other => panic!("Expected Network, got: {:?}", other),
        }
    }

    #[test]
    fn test_encode_object_key() {
        assert_eq!(encode_object_key("npm/@scope/pkg"), "npm/%40scope/pkg");
        assert_eq!(
            encode_object_key("npm/@babel/core/metadata.json"),
            "npm/%40babel/core/metadata.json"
        );
    }

    #[test]
    fn test_decode_object_key_new_encoding() {
        assert_eq!(decode_object_key("npm/%40scope/pkg"), "npm/@scope/pkg");
        assert_eq!(
            decode_object_key("npm/%40babel/core/metadata.json"),
            "npm/@babel/core/metadata.json"
        );
    }

    #[test]
    fn test_decode_object_key_legacy_not_decoded() {
        // Legacy _at_ keys are NOT decoded by decode_object_key (avoids #534 collision).
        // They are handled by fallback reads in get()/stat() instead.
        assert_eq!(decode_object_key("npm/_at_scope/pkg"), "npm/_at_scope/pkg");
        assert_eq!(
            decode_object_key("npm/_at_babel/core/metadata.json"),
            "npm/_at_babel/core/metadata.json"
        );
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let keys = [
            "npm/@scope/pkg",
            "npm/@babel/core/metadata.json",
            "simple/key/no-at",
            "raw/@org/file.txt",
            "cargo/look_at_this/1.0.crate", // #534: was broken with _at_ encoding
            "npm/some_at_pkg/metadata.json", // literal _at_ in name
        ];
        for key in keys {
            assert_eq!(
                decode_object_key(&encode_object_key(key)),
                key,
                "roundtrip failed for: {key}"
            );
        }
    }

    /// Regression test for #534: keys with literal `_at_` must not collide.
    #[test]
    fn test_no_roundtrip_collision_with_literal_at() {
        let key = "cargo/look_at_this/1.0.crate";
        let encoded = encode_object_key(key);
        // Must NOT contain _at_ substitution — key has no @
        assert_eq!(encoded, key);
        assert_eq!(decode_object_key(&encoded), key);
    }

    #[test]
    fn test_encode_no_at() {
        let key = "npm/chalk/metadata.json";
        assert_eq!(encode_object_key(key), key);
    }

    #[test]
    fn test_legacy_encode_for_fallback() {
        assert_eq!(
            encode_object_key_legacy("npm/@scope/pkg"),
            "npm/_at_scope/pkg"
        );
        // Key without @ is unchanged in both schemes
        assert_eq!(
            encode_object_key_legacy("npm/chalk/metadata.json"),
            "npm/chalk/metadata.json"
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// For any key containing @, _, or other ASCII chars, roundtrip must hold (#534).
        #[test]
        fn object_key_roundtrip(key in "[a-z0-9@_./-]{1,100}") {
            prop_assert_eq!(decode_object_key(&encode_object_key(&key)), key);
        }
    }
}
