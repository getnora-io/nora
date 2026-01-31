// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

mod config;

use axum::extract::DefaultBodyLimit;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, put},
    Router,
};
use chrono::Utc;
use config::Config;
use quick_xml::se::to_string as to_xml;
use serde::Serialize;
use std::fs;
use std::sync::Arc;
use tracing::info;

pub struct AppState {
    pub config: Config,
}

#[derive(Serialize)]
#[serde(rename = "ListAllMyBucketsResult")]
struct ListBucketsResult {
    #[serde(rename = "Buckets")]
    buckets: Buckets,
}

#[derive(Serialize)]
struct Buckets {
    #[serde(rename = "Bucket")]
    bucket: Vec<BucketInfo>,
}

#[derive(Serialize)]
struct BucketInfo {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "CreationDate")]
    creation_date: String,
}

#[derive(Serialize)]
#[serde(rename = "ListBucketResult")]
struct ListObjectsResult {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Contents")]
    contents: Vec<ObjectInfo>,
}

#[derive(Serialize)]
struct ObjectInfo {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "Size")]
    size: u64,
    #[serde(rename = "LastModified")]
    last_modified: String,
}

#[derive(Serialize)]
#[serde(rename = "Error")]
struct S3Error {
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Message")]
    message: String,
}

fn xml_response<T: Serialize>(data: T) -> Response {
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        to_xml(&data).unwrap_or_default()
    );
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/xml")],
        xml,
    )
        .into_response()
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    let error = S3Error {
        code: code.to_string(),
        message: message.to_string(),
    };
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        to_xml(&error).unwrap_or_default()
    );
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/xml")],
        xml,
    )
        .into_response()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("nora_storage=info".parse().expect("valid directive")),
        )
        .init();

    let config = Config::load();
    fs::create_dir_all(&config.storage.data_dir).expect("Failed to create data directory");

    let state = Arc::new(AppState {
        config: config.clone(),
    });

    let app = Router::new()
        .route("/", get(list_buckets))
        .route("/{bucket}", get(list_objects))
        .route("/{bucket}", put(create_bucket))
        .route("/{bucket}", delete(delete_bucket))
        .route("/{bucket}/{*key}", put(put_object))
        .route("/{bucket}/{*key}", get(get_object))
        .route("/{bucket}/{*key}", delete(delete_object))
        .layer(DefaultBodyLimit::max(config.storage.max_body_size))
        .with_state(state);

    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind to address");

    info!("nora-storage (S3 compatible) running on http://{}", addr);
    axum::serve(listener, app).await.expect("Server error");
}

async fn list_buckets(State(state): State<Arc<AppState>>) -> Response {
    let data_dir = &state.config.storage.data_dir;
    let entries = match fs::read_dir(data_dir) {
        Ok(e) => e,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "Failed to read data",
            )
        }
    };

    let bucket_list: Vec<BucketInfo> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let modified = e.metadata().ok()?.modified().ok()?;
            let datetime: chrono::DateTime<Utc> = modified.into();
            Some(BucketInfo {
                name,
                creation_date: datetime.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            })
        })
        .collect();

    xml_response(ListBucketsResult {
        buckets: Buckets {
            bucket: bucket_list,
        },
    })
}

async fn list_objects(State(state): State<Arc<AppState>>, Path(bucket): Path<String>) -> Response {
    let bucket_path = format!("{}/{}", state.config.storage.data_dir, bucket);

    if !std::path::Path::new(&bucket_path).is_dir() {
        return error_response(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
        );
    }

    let objects = collect_files(std::path::Path::new(&bucket_path), "");
    xml_response(ListObjectsResult {
        name: bucket,
        contents: objects,
    })
}

fn collect_files(dir: &std::path::Path, prefix: &str) -> Vec<ObjectInfo> {
    let mut objects = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let name = entry.file_name().into_string().unwrap_or_default();
            let key = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", prefix, name)
            };

            if path.is_dir() {
                objects.extend(collect_files(&path, &key));
            } else if let Ok(metadata) = entry.metadata() {
                if let Ok(modified) = metadata.modified() {
                    let datetime: chrono::DateTime<Utc> = modified.into();
                    objects.push(ObjectInfo {
                        key,
                        size: metadata.len(),
                        last_modified: datetime.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    });
                }
            }
        }
    }
    objects
}

async fn create_bucket(State(state): State<Arc<AppState>>, Path(bucket): Path<String>) -> Response {
    let bucket_path = format!("{}/{}", state.config.storage.data_dir, bucket);
    match fs::create_dir(&bucket_path) {
        Ok(_) => (StatusCode::OK, "").into_response(),
        Err(_) => error_response(
            StatusCode::CONFLICT,
            "BucketAlreadyExists",
            "Bucket already exists",
        ),
    }
}

async fn put_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let file_path = format!("{}/{}/{}", state.config.storage.data_dir, bucket, key);

    if let Some(parent) = std::path::Path::new(&file_path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    match fs::write(&file_path, &body) {
        Ok(_) => {
            println!("PUT {}/{} ({} bytes)", bucket, key, body.len());
            (StatusCode::OK, "").into_response()
        }
        Err(e) => {
            println!("ERROR writing {}/{}: {}", bucket, key, e);
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "Failed to write object",
            )
        }
    }
}

async fn get_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    let file_path = format!("{}/{}/{}", state.config.storage.data_dir, bucket, key);

    match fs::read(&file_path) {
        Ok(data) => (StatusCode::OK, data).into_response(),
        Err(_) => error_response(
            StatusCode::NOT_FOUND,
            "NoSuchKey",
            "The specified key does not exist",
        ),
    }
}

async fn delete_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    let file_path = format!("{}/{}/{}", state.config.storage.data_dir, bucket, key);

    match fs::remove_file(&file_path) {
        Ok(_) => {
            println!("DELETE {}/{}", bucket, key);
            (StatusCode::NO_CONTENT, "").into_response()
        }
        Err(_) => error_response(
            StatusCode::NOT_FOUND,
            "NoSuchKey",
            "The specified key does not exist",
        ),
    }
}

async fn delete_bucket(State(state): State<Arc<AppState>>, Path(bucket): Path<String>) -> Response {
    let bucket_path = format!("{}/{}", state.config.storage.data_dir, bucket);

    match fs::remove_dir(&bucket_path) {
        Ok(_) => {
            println!("DELETE bucket {}", bucket);
            (StatusCode::NO_CONTENT, "").into_response()
        }
        Err(_) => error_response(
            StatusCode::CONFLICT,
            "BucketNotEmpty",
            "The bucket is not empty",
        ),
    }
}
