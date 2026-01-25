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
    // Determine if this is a tarball request or metadata request
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

    // Try local storage first
    if let Ok(data) = state.storage.get(&key).await {
        return with_content_type(is_tarball, data).into_response();
    }

    // Try proxy if configured
    if let Some(proxy_url) = &state.config.npm.proxy {
        let url = if is_tarball {
            // Tarball URL: https://registry.npmjs.org/package/-/package-version.tgz
            format!("{}/{}", proxy_url.trim_end_matches('/'), path)
        } else {
            // Metadata URL: https://registry.npmjs.org/package
            format!("{}/{}", proxy_url.trim_end_matches('/'), path)
        };

        if let Ok(data) = fetch_from_proxy(&url, state.config.npm.proxy_timeout).await {
            // Cache in local storage (fire and forget)
            let storage = state.storage.clone();
            let key_clone = key.clone();
            let data_clone = data.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key_clone, &data_clone).await;
            });

            return with_content_type(is_tarball, data.into()).into_response();
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

async fn fetch_from_proxy(url: &str, timeout_secs: u64) -> Result<Vec<u8>, ()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|_| ())?;

    let response = client.get(url).send().await.map_err(|_| ())?;

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
