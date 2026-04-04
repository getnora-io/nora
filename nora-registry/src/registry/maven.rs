// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

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
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/maven2/{*path}", get(download))
        .route("/maven2/{*path}", put(upload))
}

async fn download(State(state): State<Arc<AppState>>, Path(path): Path<String>) -> Response {
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

    if let Ok(data) = state.storage.get(&key).await {
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

async fn upload(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    body: Bytes,
) -> StatusCode {
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

    match state.storage.put(&key, &body).await {
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
            StatusCode::CREATED
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

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
    } else if path.ends_with(".sha1") || path.ends_with(".md5") {
        "text/plain"
    } else {
        "application/octet-stream"
    };

    (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], data)
}

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
}
