// Copyright (c) 2026 Volkov Pavel | DevITWay
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
