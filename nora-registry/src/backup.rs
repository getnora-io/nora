// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Backup and restore functionality for Nora
//!
//! Exports all artifacts to a tar.gz file and restores from backups.

use crate::storage::Storage;
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use tar::{Archive, Builder, Header};

/// Backup metadata stored in metadata.json
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub artifact_count: usize,
    pub total_bytes: u64,
    pub storage_backend: String,
}

/// Statistics returned after backup
#[derive(Debug)]
pub struct BackupStats {
    pub artifact_count: usize,
    pub total_bytes: u64,
    pub output_size: u64,
}

/// Statistics returned after restore
#[derive(Debug)]
pub struct RestoreStats {
    pub artifact_count: usize,
    pub total_bytes: u64,
}

/// Create a backup of all artifacts to a tar.gz file
pub async fn create_backup(storage: &Storage, output: &Path) -> Result<BackupStats, String> {
    println!("Creating backup to: {}", output.display());
    println!("Storage backend: {}", storage.backend_name());

    // List all keys
    println!("Scanning storage...");
    let keys = storage.list("").await;

    if keys.is_empty() {
        println!("No artifacts found in storage. Creating empty backup.");
    } else {
        println!("Found {} artifacts", keys.len());
    }

    // Create output file
    let file = File::create(output).map_err(|e| format!("Failed to create output file: {}", e))?;
    let encoder = GzEncoder::new(file, Compression::default());
    let mut archive = Builder::new(encoder);

    // Progress bar
    let pb = ProgressBar::new(keys.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .expect("Invalid progress template")
            .progress_chars("#>-"),
    );

    let mut total_bytes: u64 = 0;
    let mut artifact_count = 0;

    for key in &keys {
        // Get file data
        let data = match storage.get(key).await {
            Ok(data) => data,
            Err(e) => {
                pb.println(format!("Warning: Failed to read {}: {}", key, e));
                continue;
            }
        };

        // Create tar header
        let mut header = Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        header.set_cksum();

        // Add to archive
        archive
            .append_data(&mut header, key, &*data)
            .map_err(|e| format!("Failed to add {} to archive: {}", key, e))?;

        total_bytes += data.len() as u64;
        artifact_count += 1;
        pb.inc(1);
    }

    // Add metadata.json
    let metadata = BackupMetadata {
        version: env!("CARGO_PKG_VERSION").to_string(),
        created_at: Utc::now(),
        artifact_count,
        total_bytes,
        storage_backend: storage.backend_name().to_string(),
    };

    let metadata_json = serde_json::to_vec_pretty(&metadata)
        .map_err(|e| format!("Failed to serialize metadata: {}", e))?;

    let mut header = Header::new_gnu();
    header.set_size(metadata_json.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );
    header.set_cksum();

    archive
        .append_data(&mut header, "metadata.json", metadata_json.as_slice())
        .map_err(|e| format!("Failed to add metadata.json: {}", e))?;

    // Finish archive
    let encoder = archive
        .into_inner()
        .map_err(|e| format!("Failed to finish archive: {}", e))?;
    encoder
        .finish()
        .map_err(|e| format!("Failed to finish compression: {}", e))?;

    pb.finish_with_message("Backup complete");

    // Get output file size
    let output_size = std::fs::metadata(output).map(|m| m.len()).unwrap_or(0);

    let stats = BackupStats {
        artifact_count,
        total_bytes,
        output_size,
    };

    println!();
    println!("Backup complete:");
    println!("  Artifacts: {}", stats.artifact_count);
    println!("  Total data: {} bytes", stats.total_bytes);
    println!("  Backup file: {} bytes", stats.output_size);
    println!(
        "  Compression ratio: {:.1}%",
        if stats.total_bytes > 0 {
            (stats.output_size as f64 / stats.total_bytes as f64) * 100.0
        } else {
            100.0
        }
    );

    Ok(stats)
}

/// Restore artifacts from a backup file
pub async fn restore_backup(storage: &Storage, input: &Path) -> Result<RestoreStats, String> {
    println!("Restoring from: {}", input.display());
    println!("Storage backend: {}", storage.backend_name());

    // Open backup file
    let file = File::open(input).map_err(|e| format!("Failed to open backup file: {}", e))?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);

    // First pass: count entries and read metadata
    let file = File::open(input).map_err(|e| format!("Failed to open backup file: {}", e))?;
    let decoder = GzDecoder::new(file);
    let mut archive_count = Archive::new(decoder);

    let mut entry_count = 0;
    let mut metadata: Option<BackupMetadata> = None;

    for entry in archive_count
        .entries()
        .map_err(|e| format!("Failed to read archive: {}", e))?
    {
        let mut entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let path = entry
            .path()
            .map_err(|e| format!("Failed to read path: {}", e))?
            .to_string_lossy()
            .to_string();

        if path == "metadata.json" {
            let mut data = Vec::new();
            entry
                .read_to_end(&mut data)
                .map_err(|e| format!("Failed to read metadata: {}", e))?;
            metadata = serde_json::from_slice(&data).ok();
        } else {
            entry_count += 1;
        }
    }

    if let Some(ref meta) = metadata {
        println!("Backup info:");
        println!("  Version: {}", meta.version);
        println!("  Created: {}", meta.created_at);
        println!("  Artifacts: {}", meta.artifact_count);
        println!("  Original size: {} bytes", meta.total_bytes);
        println!();
    }

    // Progress bar
    let pb = ProgressBar::new(entry_count as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .expect("Invalid progress template")
            .progress_chars("#>-"),
    );

    let mut total_bytes: u64 = 0;
    let mut artifact_count = 0;

    // Second pass: restore files
    for entry in archive
        .entries()
        .map_err(|e| format!("Failed to read archive: {}", e))?
    {
        let mut entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let path = entry
            .path()
            .map_err(|e| format!("Failed to read path: {}", e))?
            .to_string_lossy()
            .to_string();

        // Skip metadata file
        if path == "metadata.json" {
            continue;
        }

        // Read data
        let mut data = Vec::new();
        entry
            .read_to_end(&mut data)
            .map_err(|e| format!("Failed to read {}: {}", path, e))?;

        // Put to storage
        storage
            .put(&path, &data)
            .await
            .map_err(|e| format!("Failed to store {}: {}", path, e))?;

        total_bytes += data.len() as u64;
        artifact_count += 1;
        pb.inc(1);
    }

    pb.finish_with_message("Restore complete");

    let stats = RestoreStats {
        artifact_count,
        total_bytes,
    };

    println!();
    println!("Restore complete:");
    println!("  Artifacts: {}", stats.artifact_count);
    println!("  Total data: {} bytes", stats.total_bytes);

    Ok(stats)
}

/// Format bytes for human-readable display
#[allow(dead_code)]
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn test_format_bytes_bytes() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn test_format_bytes_kilobytes() {
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(10240), "10.00 KB");
    }

    #[test]
    fn test_format_bytes_megabytes() {
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.00 MB");
    }

    #[test]
    fn test_format_bytes_gigabytes() {
        assert_eq!(format_bytes(1073741824), "1.00 GB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.00 GB");
    }

    #[test]
    fn test_backup_metadata_serialization() {
        let meta = BackupMetadata {
            version: "0.3.0".to_string(),
            created_at: chrono::Utc::now(),
            artifact_count: 42,
            total_bytes: 1024000,
            storage_backend: "local".to_string(),
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("\"version\":\"0.3.0\""));
        assert!(json.contains("\"artifact_count\":42"));
        assert!(json.contains("\"storage_backend\":\"local\""));
    }

    #[test]
    fn test_backup_metadata_deserialization() {
        let json = r#"{
            "version": "0.3.0",
            "created_at": "2026-01-01T00:00:00Z",
            "artifact_count": 10,
            "total_bytes": 5000,
            "storage_backend": "s3"
        }"#;
        let meta: BackupMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.version, "0.3.0");
        assert_eq!(meta.artifact_count, 10);
        assert_eq!(meta.total_bytes, 5000);
        assert_eq!(meta.storage_backend, "s3");
    }

    #[test]
    fn test_backup_metadata_roundtrip() {
        let meta = BackupMetadata {
            version: "1.0.0".to_string(),
            created_at: chrono::Utc::now(),
            artifact_count: 100,
            total_bytes: 999999,
            storage_backend: "local".to_string(),
        };
        let json = serde_json::to_value(&meta).unwrap();
        let restored: BackupMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(meta.version, restored.version);
        assert_eq!(meta.artifact_count, restored.artifact_count);
        assert_eq!(meta.total_bytes, restored.total_bytes);
    }

    #[tokio::test]
    async fn test_create_backup_empty_storage() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let output = dir.path().join("backup.tar.gz");

        let stats = create_backup(&storage, &output).await.unwrap();
        assert_eq!(stats.artifact_count, 0);
        assert_eq!(stats.total_bytes, 0);
        assert!(output.exists());
        assert!(stats.output_size > 0); // at least metadata.json
    }

    #[tokio::test]
    async fn test_backup_restore_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Put some test data
        storage
            .put("maven/com/example/1.0/test.jar", b"test-content")
            .await
            .unwrap();
        storage
            .put("docker/test/blobs/sha256:abc123", b"blob-data")
            .await
            .unwrap();

        // Create backup
        let backup_file = dir.path().join("backup.tar.gz");
        let backup_stats = create_backup(&storage, &backup_file).await.unwrap();
        assert_eq!(backup_stats.artifact_count, 2);

        // Restore to different storage
        let restore_storage = Storage::new_local(dir.path().join("restored").to_str().unwrap());
        let restore_stats = restore_backup(&restore_storage, &backup_file)
            .await
            .unwrap();
        assert_eq!(restore_stats.artifact_count, 2);

        // Verify data
        let data = restore_storage
            .get("maven/com/example/1.0/test.jar")
            .await
            .unwrap();
        assert_eq!(&data[..], b"test-content");
    }
}
