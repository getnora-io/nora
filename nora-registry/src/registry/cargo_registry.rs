use crate::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/cargo/api/v1/crates/{crate_name}", get(get_metadata))
        .route(
            "/cargo/api/v1/crates/{crate_name}/{version}/download",
            get(download),
        )
}

async fn get_metadata(
    State(state): State<Arc<AppState>>,
    Path(crate_name): Path<String>,
) -> Response {
    let key = format!("cargo/{}/metadata.json", crate_name);
    match state.storage.get(&key).await {
        Ok(data) => (StatusCode::OK, data).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn download(
    State(state): State<Arc<AppState>>,
    Path((crate_name, version)): Path<(String, String)>,
) -> Response {
    let key = format!(
        "cargo/{}/{}/{}-{}.crate",
        crate_name, version, crate_name, version
    );
    match state.storage.get(&key).await {
        Ok(data) => (StatusCode::OK, data).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
