//! Migration between storage backends
//!
//! Supports migrating artifacts from one storage backend to another
//! (e.g., local filesystem to S3 or vice versa).

use crate::storage::Storage;
use indicatif::{ProgressBar, ProgressStyle};
use tracing::{info, warn};

/// Migration options
pub struct MigrateOptions {
    /// If true, show what would be migrated without copying
    pub dry_run: bool,
}

impl Default for MigrateOptions {
    fn default() -> Self {
        Self { dry_run: false }
    }
}

/// Migration statistics
#[derive(Debug, Default)]
pub struct MigrateStats {
    /// Total number of keys found
    pub total_keys: usize,
    /// Number of keys successfully migrated
    pub migrated: usize,
    /// Number of keys skipped (already exist in destination)
    pub skipped: usize,
    /// Number of keys that failed to migrate
    pub failed: usize,
    /// Total bytes transferred
    pub total_bytes: u64,
}

/// Migrate artifacts from source to destination storage
pub async fn migrate(
    from: &Storage,
    to: &Storage,
    options: MigrateOptions,
) -> Result<MigrateStats, String> {
    println!(
        "Migration: {} -> {}",
        from.backend_name(),
        to.backend_name()
    );

    if options.dry_run {
        println!("DRY RUN - no data will be copied");
    }

    // List all keys from source
    println!("Scanning source storage...");
    let keys = from.list("").await;

    if keys.is_empty() {
        println!("No artifacts found in source storage.");
        return Ok(MigrateStats::default());
    }

    println!("Found {} artifacts to migrate", keys.len());

    let pb = ProgressBar::new(keys.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .expect("Invalid progress bar template")
            .progress_chars("#>-"),
    );

    let mut stats = MigrateStats {
        total_keys: keys.len(),
        ..Default::default()
    };

    for key in &keys {
        // Check if already exists in destination
        if to.stat(key).await.is_some() {
            stats.skipped += 1;
            pb.inc(1);
            continue;
        }

        if options.dry_run {
            // Just count what would be migrated
            if let Some(meta) = from.stat(key).await {
                stats.total_bytes += meta.size;
            }
            stats.migrated += 1;
            pb.inc(1);
            continue;
        }

        // Fetch from source
        match from.get(key).await {
            Ok(data) => {
                // Write to destination
                match to.put(key, &data).await {
                    Ok(()) => {
                        stats.migrated += 1;
                        stats.total_bytes += data.len() as u64;
                    }
                    Err(e) => {
                        warn!("Failed to write {}: {}", key, e);
                        stats.failed += 1;
                    }
                }
            }
            Err(e) => {
                warn!("Failed to read {}: {}", key, e);
                stats.failed += 1;
            }
        }

        pb.inc(1);
    }

    pb.finish_with_message("Migration complete");

    println!();
    println!("Migration summary:");
    println!("  Total artifacts: {}", stats.total_keys);
    println!("  Migrated: {}", stats.migrated);
    println!("  Skipped (already exists): {}", stats.skipped);
    println!("  Failed: {}", stats.failed);
    println!("  Total bytes: {} KB", stats.total_bytes / 1024);

    if stats.failed > 0 {
        warn!("{} artifacts failed to migrate", stats.failed);
    }

    if options.dry_run {
        info!("Dry run complete. Re-run without --dry-run to perform actual migration.");
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_migrate_local_to_local() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        let src = Storage::new_local(src_dir.path().to_str().unwrap());
        let dst = Storage::new_local(dst_dir.path().to_str().unwrap());

        // Add test data to source
        src.put("test/file1", b"data1").await.unwrap();
        src.put("test/file2", b"data2").await.unwrap();

        let stats = migrate(&src, &dst, MigrateOptions::default())
            .await
            .unwrap();

        assert_eq!(stats.migrated, 2);
        assert_eq!(stats.failed, 0);
        assert_eq!(stats.skipped, 0);

        // Verify destination has the files
        assert!(dst.get("test/file1").await.is_ok());
        assert!(dst.get("test/file2").await.is_ok());
    }

    #[tokio::test]
    async fn test_migrate_skips_existing() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        let src = Storage::new_local(src_dir.path().to_str().unwrap());
        let dst = Storage::new_local(dst_dir.path().to_str().unwrap());

        // Add same file to both
        src.put("test/file", b"source").await.unwrap();
        dst.put("test/file", b"destination").await.unwrap();

        let stats = migrate(&src, &dst, MigrateOptions::default())
            .await
            .unwrap();

        assert_eq!(stats.migrated, 0);
        assert_eq!(stats.skipped, 1);

        // Destination should still have original content
        let data = dst.get("test/file").await.unwrap();
        assert_eq!(&*data, b"destination");
    }

    #[tokio::test]
    async fn test_migrate_dry_run() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        let src = Storage::new_local(src_dir.path().to_str().unwrap());
        let dst = Storage::new_local(dst_dir.path().to_str().unwrap());

        src.put("test/file", b"data").await.unwrap();

        let stats = migrate(
            &src,
            &dst,
            MigrateOptions {
                dry_run: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(stats.migrated, 1);

        // Destination should be empty (dry run)
        assert!(dst.get("test/file").await.is_err());
    }

    #[tokio::test]
    async fn test_migrate_empty_source() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        let src = Storage::new_local(src_dir.path().to_str().unwrap());
        let dst = Storage::new_local(dst_dir.path().to_str().unwrap());

        let stats = migrate(&src, &dst, MigrateOptions::default())
            .await
            .unwrap();

        assert_eq!(stats.total_keys, 0);
        assert_eq!(stats.migrated, 0);
    }
}
