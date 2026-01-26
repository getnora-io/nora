use crate::validation::{validate_digest, validate_docker_name, validate_docker_reference};
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderName, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, head, put},
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v2/", get(check))
        .route("/v2/{name}/blobs/{digest}", head(check_blob))
        .route("/v2/{name}/blobs/{digest}", get(download_blob))
        .route(
            "/v2/{name}/blobs/uploads/",
            axum::routing::post(start_upload),
        )
        .route("/v2/{name}/blobs/uploads/{uuid}", put(upload_blob))
        .route("/v2/{name}/manifests/{reference}", get(get_manifest))
        .route("/v2/{name}/manifests/{reference}", put(put_manifest))
        .route("/v2/{name}/tags/list", get(list_tags))
}

async fn check() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({})))
}

async fn check_blob(
    State(state): State<Arc<AppState>>,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_digest(&digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let key = format!("docker/{}/blobs/{}", name, digest);
    match state.storage.get(&key).await {
        Ok(data) => (
            StatusCode::OK,
            [(header::CONTENT_LENGTH, data.len().to_string())],
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn download_blob(
    State(state): State<Arc<AppState>>,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_digest(&digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let key = format!("docker/{}/blobs/{}", name, digest);
    match state.storage.get(&key).await {
        Ok(data) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            data,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn start_upload(Path(name): Path<String>) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let uuid = uuid::Uuid::new_v4().to_string();
    let location = format!("/v2/{}/blobs/uploads/{}", name, uuid);
    (
        StatusCode::ACCEPTED,
        [
            (header::LOCATION, location.clone()),
            (HeaderName::from_static("docker-upload-uuid"), uuid),
        ],
    )
        .into_response()
}

async fn upload_blob(
    State(state): State<Arc<AppState>>,
    Path((name, _uuid)): Path<(String, String)>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    body: Bytes,
) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let digest = match params.get("digest") {
        Some(d) => d,
        None => return (StatusCode::BAD_REQUEST, "Missing digest parameter").into_response(),
    };

    if let Err(e) = validate_digest(digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let key = format!("docker/{}/blobs/{}", name, digest);
    match state.storage.put(&key, &body).await {
        Ok(()) => {
            let location = format!("/v2/{}/blobs/{}", name, digest);
            (StatusCode::CREATED, [(header::LOCATION, location)]).into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn get_manifest(
    State(state): State<Arc<AppState>>,
    Path((name, reference)): Path<(String, String)>,
) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_docker_reference(&reference) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let key = format!("docker/{}/manifests/{}.json", name, reference);
    match state.storage.get(&key).await {
        Ok(data) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                "application/vnd.docker.distribution.manifest.v2+json",
            )],
            data,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn put_manifest(
    State(state): State<Arc<AppState>>,
    Path((name, reference)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_docker_reference(&reference) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let key = format!("docker/{}/manifests/{}.json", name, reference);
    match state.storage.put(&key, &body).await {
        Ok(()) => {
            use sha2::Digest;
            let digest = format!("sha256:{:x}", sha2::Sha256::digest(&body));
            let location = format!("/v2/{}/manifests/{}", name, reference);
            (
                StatusCode::CREATED,
                [
                    (header::LOCATION, location),
                    (HeaderName::from_static("docker-content-digest"), digest),
                ],
            )
                .into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn list_tags(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let prefix = format!("docker/{}/manifests/", name);
    let keys = state.storage.list(&prefix).await;
    let tags: Vec<String> = keys
        .iter()
        .filter_map(|k| {
            k.strip_prefix(&prefix)
                .and_then(|t| t.strip_suffix(".json"))
                .map(String::from)
        })
        .collect();
    (StatusCode::OK, Json(json!({"name": name, "tags": tags}))).into_response()
}
