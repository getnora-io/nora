// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use axum::http::header;
use axum::response::IntoResponse;

/// Embedded Tailwind CSS (purged, minified)
const TAILWIND_CSS: &str = include_str!("static/tailwind.css");

/// Embedded htmx 1.9.10 (minified)
const HTMX_JS: &str = include_str!("static/htmx.min.js");

pub async fn serve_tailwind_css() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        TAILWIND_CSS,
    )
}

pub async fn serve_htmx_js() -> impl IntoResponse {
    (
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        HTMX_JS,
    )
}
