// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Maven registry — Maven 2 repository layout with checksums, immutability,
//! and automatic `maven-metadata.xml` generation.
//!
//! Implements:
//!   GET  /maven2/{*path}  — download artifact, checksum, or metadata
//!   PUT  /maven2/{*path}  — upload artifact (with auto-checksum + metadata update)

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::registry::proxy_fetch;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, put},
    Router,
};
use sha2::Digest;
use std::collections::BTreeSet;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/maven2/{*path}", get(download))
        .route("/maven2/{*path}", put(upload))
}

// ============================================================================
// Path parsing
// ============================================================================

struct MavenCoordinates {
    group_path: String,
    artifact_id: String,
    version: String,
    filename: String,
}

enum MavenPathKind {
    VersionFile(MavenCoordinates),
    #[allow(dead_code)]
    ArtifactMeta {
        group_path: String,
        artifact_id: String,
        filename: String,
    },
    Opaque,
}

fn classify_path(path: &str) -> MavenPathKind {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if segments.len() < 2 {
        return MavenPathKind::Opaque;
    }

    let last = segments[segments.len() - 1];

    if (last == "maven-metadata.xml" || last.starts_with("maven-metadata.xml."))
        && segments.len() >= 2
    {
        return MavenPathKind::ArtifactMeta {
            group_path: segments[..segments.len() - 2].join("/"),
            artifact_id: segments[segments.len() - 2].to_string(),
            filename: last.to_string(),
        };
    }

    if segments.len() >= 4 {
        return MavenPathKind::VersionFile(MavenCoordinates {
            group_path: segments[..segments.len() - 3].join("/"),
            artifact_id: segments[segments.len() - 3].to_string(),
            version: segments[segments.len() - 2].to_string(),
            filename: last.to_string(),
        });
    }

    MavenPathKind::Opaque
}

fn is_checksum_file(filename: &str) -> bool {
    filename.ends_with(".md5")
        || filename.ends_with(".sha1")
        || filename.ends_with(".sha256")
        || filename.ends_with(".sha512")
}

fn is_snapshot(version: &str) -> bool {
    version.ends_with("-SNAPSHOT")
}

// ============================================================================
// Download
// ============================================================================

async fn download(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(path): Path<String>,
) -> Response {
    let key = format!("maven/{}", path);

    let artifact_name = path
        .split('/')
        .rev()
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("/");

    // Classify path for curation (used in both pre-download and integrity checks)
    let curation_coords = if let MavenPathKind::VersionFile(coords) = classify_path(&path) {
        let maven_name = format!(
            "{}:{}",
            coords.group_path.replace('/', "."),
            coords.artifact_id
        );
        Some((maven_name, coords.version))
    } else {
        None
    };

    // Curation check — only for versioned artifact files, not metadata
    if let Some((ref maven_name, ref maven_version)) = curation_coords {
        if let Some(response) = crate::curation::check_download(
            &state.curation,
            state.config.curation.bypass_token.as_deref(),
            &headers,
            crate::curation::RegistryType::Maven,
            maven_name,
            Some(maven_version),
            None,
        ) {
            return response;
        }
    }

    if let Ok(data) = state.storage.get(&key).await {
        // Curation integrity verification (issue #189)
        if let Some((ref maven_name, ref maven_version)) = curation_coords {
            if let Some(response) = crate::curation::verify_integrity(
                &state.curation,
                crate::curation::RegistryType::Maven,
                maven_name,
                Some(maven_version),
                &data,
            ) {
                return response;
            }
        }

        state.metrics.record_download("maven");
        state.metrics.record_cache_hit();
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            artifact_name,
            "maven",
            "CACHE",
        ));
        state
            .audit
            .log(AuditEntry::new("cache_hit", "api", "", "maven", ""));
        return with_content_type(&path, data).into_response();
    }

    for proxy in &state.config.maven.proxies {
        let url = format!("{}/{}", proxy.url().trim_end_matches('/'), path);

        match proxy_fetch(
            &state.http_client,
            &url,
            state.config.maven.proxy_timeout,
            proxy.auth(),
        )
        .await
        {
            Ok(data) => {
                state.metrics.record_download("maven");
                state.metrics.record_cache_miss();
                state.activity.push(ActivityEntry::new(
                    ActionType::ProxyFetch,
                    artifact_name,
                    "maven",
                    "PROXY",
                ));
                state
                    .audit
                    .log(AuditEntry::new("proxy_fetch", "api", "", "maven", ""));

                let storage = state.storage.clone();
                let key_clone = key.clone();
                let data_clone = data.clone();
                tokio::spawn(async move {
                    let _ = storage.put(&key_clone, &data_clone).await;
                });

                state.repo_index.invalidate("maven");

                return with_content_type(&path, data.into()).into_response();
            }
            Err(_) => continue,
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

// ============================================================================
// Upload
// ============================================================================

async fn upload(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    body: Bytes,
) -> Response {
    let key = format!("maven/{}", path);

    let artifact_name = path
        .split('/')
        .rev()
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("/");

    match classify_path(&path) {
        MavenPathKind::VersionFile(coords) if is_checksum_file(&coords.filename) => {
            // Client uploading a checksum — verify against our computed value
            if state.config.maven.checksum_verify {
                if let Ok(computed) = state.storage.get(&key).await {
                    let computed_str = String::from_utf8_lossy(&computed).trim().to_string();
                    let client_str = String::from_utf8_lossy(&body).trim().to_string();
                    if computed_str != client_str {
                        tracing::warn!(
                            path = %path,
                            expected = %computed_str,
                            received = %client_str,
                            "SECURITY: Maven checksum mismatch on upload"
                        );
                        return (StatusCode::BAD_REQUEST, "Checksum mismatch").into_response();
                    }
                }
            }
            match state.storage.put(&key, &body).await {
                Ok(()) => StatusCode::CREATED.into_response(),
                Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        }

        MavenPathKind::VersionFile(coords) => {
            // Primary artifact upload (jar, pom, war, etc.)
            let snap = is_snapshot(&coords.version);

            // Lock on metadata key to serialize all uploads for the same artifact.
            // This prevents TOCTOU races on both immutability checks and
            // maven-metadata.xml generation (read-list-generate-write cycle).
            let metadata_lock_key = format!(
                "maven/{}/{}/maven-metadata.xml",
                coords.group_path, coords.artifact_id
            );
            let lock = state.publish_lock(&metadata_lock_key);
            let _guard = lock.lock().await;

            if !snap
                && state.config.maven.immutable_releases
                && state.storage.stat(&key).await.is_some()
            {
                return (
                    StatusCode::CONFLICT,
                    format!(
                        "Version {}:{} is immutable (already deployed)",
                        coords.artifact_id, coords.version
                    ),
                )
                    .into_response();
            }

            if state.storage.put(&key, &body).await.is_err() {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }

            compute_and_store_checksums(&state.storage, &key, &body).await;

            update_artifact_metadata(&state, &coords.group_path, &coords.artifact_id).await;

            state.metrics.record_upload("maven");
            state.activity.push(ActivityEntry::new(
                ActionType::Push,
                artifact_name,
                "maven",
                "LOCAL",
            ));
            state
                .audit
                .log(AuditEntry::new("push", "api", "", "maven", ""));
            state.repo_index.invalidate("maven");

            StatusCode::CREATED.into_response()
        }

        MavenPathKind::ArtifactMeta { .. } => {
            // Client uploading maven-metadata.xml — accept silently.
            // We regenerate on primary artifact uploads anyway.
            match state.storage.put(&key, &body).await {
                Ok(()) => {
                    state.metrics.record_upload("maven");
                    StatusCode::CREATED.into_response()
                }
                Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        }

        MavenPathKind::Opaque => match state.storage.put(&key, &body).await {
            Ok(()) => {
                state.metrics.record_upload("maven");
                state.activity.push(ActivityEntry::new(
                    ActionType::Push,
                    artifact_name,
                    "maven",
                    "LOCAL",
                ));
                state
                    .audit
                    .log(AuditEntry::new("push", "api", "", "maven", ""));
                state.repo_index.invalidate("maven");
                StatusCode::CREATED.into_response()
            }
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
    }
}

// ============================================================================
// Checksum helpers
// ============================================================================

async fn compute_and_store_checksums(storage: &crate::storage::Storage, key: &str, data: &[u8]) {
    let md5_hex = hex::encode(md5::Md5::digest(data));
    let sha1_hex = hex::encode(sha1::Sha1::digest(data));
    let sha256_hex = hex::encode(sha2::Sha256::digest(data));
    let sha512_hex = hex::encode(sha2::Sha512::digest(data));

    let _ = storage
        .put(&format!("{}.md5", key), md5_hex.as_bytes())
        .await;
    let _ = storage
        .put(&format!("{}.sha1", key), sha1_hex.as_bytes())
        .await;
    let _ = storage
        .put(&format!("{}.sha256", key), sha256_hex.as_bytes())
        .await;
    let _ = storage
        .put(&format!("{}.sha512", key), sha512_hex.as_bytes())
        .await;
}

// ============================================================================
// Metadata generation
// ============================================================================

async fn update_artifact_metadata(state: &AppState, group_path: &str, artifact_id: &str) {
    let prefix = format!("maven/{}/{}/", group_path, artifact_id);
    let keys = state.storage.list(&prefix).await;

    let mut versions = BTreeSet::new();
    for key in &keys {
        let relative = match key.strip_prefix(&prefix) {
            Some(r) => r,
            None => continue,
        };
        if let Some(ver_segment) = relative.split('/').next() {
            if !ver_segment.is_empty() && !ver_segment.starts_with("maven-metadata") {
                versions.insert(ver_segment.to_string());
            }
        }
    }

    if versions.is_empty() {
        return;
    }

    let mut sorted: Vec<String> = versions.into_iter().collect();
    sort_maven_versions(&mut sorted);

    let group_id_dotted = group_path.replace('/', ".");
    let xml = generate_metadata_xml(&group_id_dotted, artifact_id, &sorted);

    let metadata_key = format!("{}maven-metadata.xml", prefix);
    if state
        .storage
        .put(&metadata_key, xml.as_bytes())
        .await
        .is_err()
    {
        tracing::error!(key = %metadata_key, "Failed to write maven-metadata.xml");
        return;
    }

    compute_and_store_checksums(&state.storage, &metadata_key, xml.as_bytes()).await;
}

fn sort_maven_versions(versions: &mut [String]) {
    versions.sort_by(|a, b| {
        let a_base = a.strip_suffix("-SNAPSHOT").unwrap_or(a);
        let b_base = b.strip_suffix("-SNAPSHOT").unwrap_or(b);
        match a_base.cmp(b_base) {
            std::cmp::Ordering::Equal => {
                let a_snap = a.ends_with("-SNAPSHOT");
                let b_snap = b.ends_with("-SNAPSHOT");
                a_snap.cmp(&b_snap)
            }
            other => other,
        }
    });
}

fn generate_metadata_xml(group_id: &str, artifact_id: &str, versions: &[String]) -> String {
    let latest = versions.last().map(|s| s.as_str()).unwrap_or("");
    let release = versions
        .iter()
        .rev()
        .find(|v| !v.ends_with("-SNAPSHOT"))
        .map(|s| s.as_str())
        .unwrap_or("");

    let now = chrono::Utc::now().format("%Y%m%d%H%M%S");

    let version_elements: String = versions
        .iter()
        .map(|v| format!("      <version>{}</version>", v))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>{}</groupId>
  <artifactId>{}</artifactId>
  <versioning>
    <latest>{}</latest>
    <release>{}</release>
    <versions>
{}
    </versions>
    <lastUpdated>{}</lastUpdated>
  </versioning>
</metadata>
"#,
        group_id, artifact_id, latest, release, version_elements, now
    )
}

// ============================================================================
// Content type
// ============================================================================

fn with_content_type(
    path: &str,
    data: Bytes,
) -> (StatusCode, [(header::HeaderName, &'static str); 1], Bytes) {
    let content_type = if path.ends_with(".pom") {
        "application/xml"
    } else if path.ends_with(".jar") {
        "application/java-archive"
    } else if path.ends_with(".xml") {
        "application/xml"
    } else if path.ends_with(".sha1")
        || path.ends_with(".md5")
        || path.ends_with(".sha256")
        || path.ends_with(".sha512")
    {
        "text/plain"
    } else {
        "application/octet-stream"
    };

    (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], data)
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_type_pom() {
        let (status, headers, _) =
            with_content_type("com/example/1.0/example-1.0.pom", Bytes::from("data"));
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[0].1, "application/xml");
    }

    #[test]
    fn test_content_type_jar() {
        let (_, headers, _) =
            with_content_type("com/example/1.0/example-1.0.jar", Bytes::from("data"));
        assert_eq!(headers[0].1, "application/java-archive");
    }

    #[test]
    fn test_content_type_xml() {
        let (_, headers, _) =
            with_content_type("com/example/maven-metadata.xml", Bytes::from("data"));
        assert_eq!(headers[0].1, "application/xml");
    }

    #[test]
    fn test_content_type_sha1() {
        let (_, headers, _) =
            with_content_type("com/example/1.0/example-1.0.jar.sha1", Bytes::from("data"));
        assert_eq!(headers[0].1, "text/plain");
    }

    #[test]
    fn test_content_type_md5() {
        let (_, headers, _) =
            with_content_type("com/example/1.0/example-1.0.jar.md5", Bytes::from("data"));
        assert_eq!(headers[0].1, "text/plain");
    }

    #[test]
    fn test_content_type_sha256() {
        let (_, headers, _) = with_content_type(
            "com/example/1.0/example-1.0.jar.sha256",
            Bytes::from("data"),
        );
        assert_eq!(headers[0].1, "text/plain");
    }

    #[test]
    fn test_content_type_unknown() {
        let (_, headers, _) = with_content_type("some/random/file.bin", Bytes::from("data"));
        assert_eq!(headers[0].1, "application/octet-stream");
    }

    #[test]
    fn test_content_type_preserves_body() {
        let body = Bytes::from("test-jar-content");
        let (_, _, data) = with_content_type("test.jar", body.clone());
        assert_eq!(data, body);
    }

    // ── Path classification ─────────────────────────────────────────────

    #[test]
    fn test_classify_version_file() {
        match classify_path("com/example/mylib/1.0.0/mylib-1.0.0.jar") {
            MavenPathKind::VersionFile(c) => {
                assert_eq!(c.group_path, "com/example");
                assert_eq!(c.artifact_id, "mylib");
                assert_eq!(c.version, "1.0.0");
                assert_eq!(c.filename, "mylib-1.0.0.jar");
            }
            _ => panic!("expected VersionFile"),
        }
    }

    #[test]
    fn test_classify_version_checksum() {
        match classify_path("com/example/mylib/1.0.0/mylib-1.0.0.jar.sha1") {
            MavenPathKind::VersionFile(c) => {
                assert!(is_checksum_file(&c.filename));
                assert_eq!(c.version, "1.0.0");
            }
            _ => panic!("expected VersionFile"),
        }
    }

    #[test]
    fn test_classify_artifact_metadata() {
        match classify_path("com/example/mylib/maven-metadata.xml") {
            MavenPathKind::ArtifactMeta {
                group_path,
                artifact_id,
                filename,
            } => {
                assert_eq!(group_path, "com/example");
                assert_eq!(artifact_id, "mylib");
                assert_eq!(filename, "maven-metadata.xml");
            }
            _ => panic!("expected ArtifactMeta"),
        }
    }

    #[test]
    fn test_classify_metadata_checksum() {
        match classify_path("com/example/mylib/maven-metadata.xml.sha256") {
            MavenPathKind::ArtifactMeta {
                artifact_id,
                filename,
                ..
            } => {
                assert_eq!(artifact_id, "mylib");
                assert_eq!(filename, "maven-metadata.xml.sha256");
            }
            _ => panic!("expected ArtifactMeta"),
        }
    }

    #[test]
    fn test_classify_deep_group() {
        match classify_path("org/apache/maven/plugins/maven-compiler-plugin/3.11.0/maven-compiler-plugin-3.11.0.jar") {
            MavenPathKind::VersionFile(c) => {
                assert_eq!(c.group_path, "org/apache/maven/plugins");
                assert_eq!(c.artifact_id, "maven-compiler-plugin");
                assert_eq!(c.version, "3.11.0");
            }
            _ => panic!("expected VersionFile"),
        }
    }

    #[test]
    fn test_classify_snapshot() {
        match classify_path("com/example/mylib/1.0-SNAPSHOT/mylib-1.0-SNAPSHOT.jar") {
            MavenPathKind::VersionFile(c) => {
                assert!(is_snapshot(&c.version));
            }
            _ => panic!("expected VersionFile"),
        }
    }

    #[test]
    fn test_classify_opaque_short_path() {
        assert!(matches!(classify_path("a"), MavenPathKind::Opaque));
    }

    // ── Checksum detection ──────────────────────────────────────────────

    #[test]
    fn test_is_checksum_file() {
        assert!(is_checksum_file("foo.md5"));
        assert!(is_checksum_file("foo.sha1"));
        assert!(is_checksum_file("foo.sha256"));
        assert!(is_checksum_file("foo.sha512"));
        assert!(!is_checksum_file("foo.jar"));
        assert!(!is_checksum_file("foo.pom"));
    }

    // ── Version sorting ─────────────────────────────────────────────────

    #[test]
    fn test_sort_versions_lexicographic() {
        let mut v = vec!["1.0.0".into(), "0.9.0".into(), "1.1.0".into()];
        sort_maven_versions(&mut v);
        assert_eq!(v, vec!["0.9.0", "1.0.0", "1.1.0"]);
    }

    #[test]
    fn test_sort_snapshot_after_release() {
        let mut v = vec!["1.0.0-SNAPSHOT".into(), "1.0.0".into(), "0.9.0".into()];
        sort_maven_versions(&mut v);
        assert_eq!(v, vec!["0.9.0", "1.0.0", "1.0.0-SNAPSHOT"]);
    }

    // ── Metadata XML generation ─────────────────────────────────────────

    #[test]
    fn test_generate_metadata_xml() {
        let xml = generate_metadata_xml("com.example", "mylib", &["0.9.0".into(), "1.0.0".into()]);
        assert!(xml.contains("<groupId>com.example</groupId>"));
        assert!(xml.contains("<artifactId>mylib</artifactId>"));
        assert!(xml.contains("<latest>1.0.0</latest>"));
        assert!(xml.contains("<release>1.0.0</release>"));
        assert!(xml.contains("<version>0.9.0</version>"));
        assert!(xml.contains("<version>1.0.0</version>"));
        assert!(xml.contains("<lastUpdated>"));
    }

    #[test]
    fn test_generate_metadata_snapshot_only() {
        let xml = generate_metadata_xml("com.example", "mylib", &["1.0.0-SNAPSHOT".into()]);
        assert!(xml.contains("<latest>1.0.0-SNAPSHOT</latest>"));
        assert!(xml.contains("<release></release>"));
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{body_bytes, create_test_context, send};
    use axum::body::Body;
    use axum::http::{header, Method, StatusCode};
    use sha2::Digest;

    #[tokio::test]
    async fn test_maven_put_get_roundtrip() {
        let ctx = create_test_context();
        let jar_data = b"fake-jar-content";

        let put = send(
            &ctx.app,
            Method::PUT,
            "/maven2/com/example/mylib/1.0/mylib-1.0.jar",
            Body::from(&jar_data[..]),
        )
        .await;
        assert_eq!(put.status(), StatusCode::CREATED);

        let get = send(
            &ctx.app,
            Method::GET,
            "/maven2/com/example/mylib/1.0/mylib-1.0.jar",
            "",
        )
        .await;
        assert_eq!(get.status(), StatusCode::OK);
        let body = body_bytes(get).await;
        assert_eq!(&body[..], jar_data);
    }

    #[tokio::test]
    async fn test_maven_not_found_no_proxy() {
        let ctx = create_test_context();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/maven2/missing/artifact/1.0/artifact-1.0.jar",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_maven_content_type_pom() {
        let ctx = create_test_context();
        send(
            &ctx.app,
            Method::PUT,
            "/maven2/com/ex/1.0/ex-1.0.pom",
            Body::from("<project/>"),
        )
        .await;

        let get = send(&ctx.app, Method::GET, "/maven2/com/ex/1.0/ex-1.0.pom", "").await;
        assert_eq!(get.status(), StatusCode::OK);
        assert_eq!(
            get.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/xml"
        );
    }

    #[tokio::test]
    async fn test_maven_content_type_jar() {
        let ctx = create_test_context();
        send(
            &ctx.app,
            Method::PUT,
            "/maven2/org/test/app/2.0/app-2.0.jar",
            Body::from("jar-data"),
        )
        .await;

        let get = send(
            &ctx.app,
            Method::GET,
            "/maven2/org/test/app/2.0/app-2.0.jar",
            "",
        )
        .await;
        assert_eq!(get.status(), StatusCode::OK);
        assert_eq!(
            get.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/java-archive"
        );
    }

    // ── Checksums ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_maven_auto_checksums() {
        let ctx = create_test_context();
        let data = b"test-jar-for-checksum";

        send(
            &ctx.app,
            Method::PUT,
            "/maven2/com/example/ck/1.0/ck-1.0.jar",
            Body::from(&data[..]),
        )
        .await;

        // SHA-256
        let resp = send(
            &ctx.app,
            Method::GET,
            "/maven2/com/example/ck/1.0/ck-1.0.jar.sha256",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let hash = body_bytes(resp).await;
        let expected = hex::encode(sha2::Sha256::digest(data));
        assert_eq!(String::from_utf8_lossy(&hash), expected);

        // SHA-1
        let resp = send(
            &ctx.app,
            Method::GET,
            "/maven2/com/example/ck/1.0/ck-1.0.jar.sha1",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // MD5
        let resp = send(
            &ctx.app,
            Method::GET,
            "/maven2/com/example/ck/1.0/ck-1.0.jar.md5",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_maven_checksum_verify_ok() {
        let ctx = create_test_context();
        let data = b"checksum-test-jar";

        send(
            &ctx.app,
            Method::PUT,
            "/maven2/com/example/cv/1.0/cv-1.0.jar",
            Body::from(&data[..]),
        )
        .await;

        let sha1 = hex::encode(sha1::Sha1::digest(data));
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/maven2/com/example/cv/1.0/cv-1.0.jar.sha1",
            Body::from(sha1),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_maven_checksum_verify_mismatch() {
        let ctx = create_test_context();
        let data = b"checksum-mismatch-test";

        send(
            &ctx.app,
            Method::PUT,
            "/maven2/com/example/cm/1.0/cm-1.0.jar",
            Body::from(&data[..]),
        )
        .await;

        let resp = send(
            &ctx.app,
            Method::PUT,
            "/maven2/com/example/cm/1.0/cm-1.0.jar.sha1",
            Body::from("0000000000000000000000000000000000000000"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── Immutability ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_maven_release_immutability() {
        let ctx = create_test_context();

        let r1 = send(
            &ctx.app,
            Method::PUT,
            "/maven2/com/example/imm/1.0.0/imm-1.0.0.jar",
            Body::from("v1"),
        )
        .await;
        assert_eq!(r1.status(), StatusCode::CREATED);

        let r2 = send(
            &ctx.app,
            Method::PUT,
            "/maven2/com/example/imm/1.0.0/imm-1.0.0.jar",
            Body::from("v2"),
        )
        .await;
        assert_eq!(r2.status(), StatusCode::CONFLICT);

        let get = send(
            &ctx.app,
            Method::GET,
            "/maven2/com/example/imm/1.0.0/imm-1.0.0.jar",
            "",
        )
        .await;
        let body = body_bytes(get).await;
        assert_eq!(&body[..], b"v1");
    }

    #[tokio::test]
    async fn test_maven_snapshot_overwrite() {
        let ctx = create_test_context();

        let r1 = send(
            &ctx.app,
            Method::PUT,
            "/maven2/com/example/snap/1.0-SNAPSHOT/snap-1.0-SNAPSHOT.jar",
            Body::from("snapshot-v1"),
        )
        .await;
        assert_eq!(r1.status(), StatusCode::CREATED);

        let r2 = send(
            &ctx.app,
            Method::PUT,
            "/maven2/com/example/snap/1.0-SNAPSHOT/snap-1.0-SNAPSHOT.jar",
            Body::from("snapshot-v2"),
        )
        .await;
        assert_eq!(r2.status(), StatusCode::CREATED);

        let get = send(
            &ctx.app,
            Method::GET,
            "/maven2/com/example/snap/1.0-SNAPSHOT/snap-1.0-SNAPSHOT.jar",
            "",
        )
        .await;
        let body = body_bytes(get).await;
        assert_eq!(&body[..], b"snapshot-v2");
    }

    // ── Metadata generation ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_maven_metadata_generated() {
        let ctx = create_test_context();

        send(
            &ctx.app,
            Method::PUT,
            "/maven2/com/example/meta/1.0.0/meta-1.0.0.jar",
            Body::from("v1"),
        )
        .await;

        send(
            &ctx.app,
            Method::PUT,
            "/maven2/com/example/meta/2.0.0/meta-2.0.0.jar",
            Body::from("v2"),
        )
        .await;

        let resp = send(
            &ctx.app,
            Method::GET,
            "/maven2/com/example/meta/maven-metadata.xml",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_bytes(resp).await;
        let xml = String::from_utf8_lossy(&body);
        assert!(xml.contains("<groupId>com.example</groupId>"));
        assert!(xml.contains("<artifactId>meta</artifactId>"));
        assert!(xml.contains("<version>1.0.0</version>"));
        assert!(xml.contains("<version>2.0.0</version>"));
        assert!(xml.contains("<latest>2.0.0</latest>"));
        assert!(xml.contains("<release>2.0.0</release>"));
    }

    #[tokio::test]
    async fn test_maven_metadata_checksums() {
        let ctx = create_test_context();

        send(
            &ctx.app,
            Method::PUT,
            "/maven2/com/example/mck/1.0.0/mck-1.0.0.jar",
            Body::from("data"),
        )
        .await;

        let resp = send(
            &ctx.app,
            Method::GET,
            "/maven2/com/example/mck/maven-metadata.xml.sha256",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let hash = body_bytes(resp).await;
        assert_eq!(hash.len(), 64);
    }

    #[tokio::test]
    async fn test_maven_different_versions_different_artifacts() {
        let ctx = create_test_context();

        send(
            &ctx.app,
            Method::PUT,
            "/maven2/com/example/multi/1.0.0/multi-1.0.0.jar",
            Body::from("v1-jar"),
        )
        .await;
        send(
            &ctx.app,
            Method::PUT,
            "/maven2/com/example/multi/1.0.0/multi-1.0.0.pom",
            Body::from("<pom/>"),
        )
        .await;
        send(
            &ctx.app,
            Method::PUT,
            "/maven2/com/example/multi/2.0.0/multi-2.0.0.jar",
            Body::from("v2-jar"),
        )
        .await;

        let r1 = send(
            &ctx.app,
            Method::GET,
            "/maven2/com/example/multi/1.0.0/multi-1.0.0.jar",
            "",
        )
        .await;
        assert_eq!(r1.status(), StatusCode::OK);

        let r2 = send(
            &ctx.app,
            Method::GET,
            "/maven2/com/example/multi/1.0.0/multi-1.0.0.pom",
            "",
        )
        .await;
        assert_eq!(r2.status(), StatusCode::OK);

        let r3 = send(
            &ctx.app,
            Method::GET,
            "/maven2/com/example/multi/2.0.0/multi-2.0.0.jar",
            "",
        )
        .await;
        assert_eq!(r3.status(), StatusCode::OK);
    }
}
