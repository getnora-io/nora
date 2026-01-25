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
use std::time::Duration;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/maven2/{*path}", get(download))
        .route("/maven2/{*path}", put(upload))
}

async fn download(State(state): State<Arc<AppState>>, Path(path): Path<String>) -> Response {
    let key = format!("maven/{}", path);

    // Try local storage first
    if let Ok(data) = state.storage.get(&key).await {
        return with_content_type(&path, data).into_response();
    }

    // Try proxy servers
    for proxy_url in &state.config.maven.proxies {
        let url = format!("{}/{}", proxy_url.trim_end_matches('/'), path);

        match fetch_from_proxy(&url, state.config.maven.proxy_timeout).await {
            Ok(data) => {
                // Cache in local storage (fire and forget)
                let storage = state.storage.clone();
                let key_clone = key.clone();
                let data_clone = data.clone();
                tokio::spawn(async move {
                    let _ = storage.put(&key_clone, &data_clone).await;
                });

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
    match state.storage.put(&key, &body).await {
        Ok(()) => StatusCode::CREATED,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
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
