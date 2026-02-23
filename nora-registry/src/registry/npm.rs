// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

use crate::activity_log::{ActionType, ActivityEntry};
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::sync::Arc;
use std::time::Duration;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/npm/{*path}", get(handle_request))
}

async fn handle_request(State(state): State<Arc<AppState>>, Path(path): Path<String>) -> Response {
    let is_tarball = path.contains("/-/");

    let key = if is_tarball {
        let parts: Vec<&str> = path.split("/-/").collect();
        if parts.len() == 2 {
            format!("npm/{}/tarballs/{}", parts[0], parts[1])
        } else {
            format!("npm/{}", path)
        }
    } else {
        format!("npm/{}/metadata.json", path)
    };

    let package_name = if is_tarball {
        path.split("/-/").next().unwrap_or(&path).to_string()
    } else {
        path.clone()
    };

    if let Ok(data) = state.storage.get(&key).await {
        if is_tarball {
            state.metrics.record_download("npm");
            state.metrics.record_cache_hit();
            state.activity.push(ActivityEntry::new(
                ActionType::CacheHit,
                package_name,
                "npm",
                "CACHE",
            ));
        }
        return with_content_type(is_tarball, data).into_response();
    }

    if let Some(proxy_url) = &state.config.npm.proxy {
        let url = format!("{}/{}", proxy_url.trim_end_matches('/'), path);

        if let Ok(data) = fetch_from_proxy(&state.http_client, &url, state.config.npm.proxy_timeout).await {
            if is_tarball {
                state.metrics.record_download("npm");
                state.metrics.record_cache_miss();
                state.activity.push(ActivityEntry::new(
                    ActionType::ProxyFetch,
                    package_name,
                    "npm",
                    "PROXY",
                ));
            }

            let storage = state.storage.clone();
            let key_clone = key.clone();
            let data_clone = data.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key_clone, &data_clone).await;
            });

            if is_tarball {
                state.repo_index.invalidate("npm");
            }

            return with_content_type(is_tarball, data.into()).into_response();
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

async fn fetch_from_proxy(client: &reqwest::Client, url: &str, timeout_secs: u64) -> Result<Vec<u8>, ()> {
    let response = client
        .get(url)
        .timeout(Duration::from_secs(timeout_secs))
        .send()
        .await
        .map_err(|_| ())?;

    if !response.status().is_success() {
        return Err(());
    }

    response.bytes().await.map(|b| b.to_vec()).map_err(|_| ())
}

fn with_content_type(
    is_tarball: bool,
    data: Bytes,
) -> (StatusCode, [(header::HeaderName, &'static str); 1], Bytes) {
    let content_type = if is_tarball {
        "application/octet-stream"
    } else {
        "application/json"
    };

    (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], data)
}
