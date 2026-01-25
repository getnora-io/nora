use crate::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/simple/", get(list_packages))
}

async fn list_packages(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let keys = state.storage.list("pypi/").await;
    let mut packages = std::collections::HashSet::new();

    for key in keys {
        if let Some(pkg) = key.strip_prefix("pypi/").and_then(|k| k.split('/').next()) {
            packages.insert(pkg.to_string());
        }
    }

    let mut html = String::from("<html><body><h1>Simple Index</h1>");
    let mut pkg_list: Vec<_> = packages.into_iter().collect();
    pkg_list.sort();

    for pkg in pkg_list {
        html.push_str(&format!("<a href=\"/simple/{}/\">{}</a><br>", pkg, pkg));
    }
    html.push_str("</body></html>");

    (StatusCode::OK, Html(html))
}
