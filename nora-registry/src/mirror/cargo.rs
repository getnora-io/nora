// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! `nora mirror cargo`: the sparse index entry of every crate a Cargo.lock names and every
//! `.crate` it locks, fetched through NORA so that its store serves an offline `cargo fetch`
//! (#1183).
//!
//! Cargo reads a crate's index entry before it downloads the crate, lockfile or not. NORA keeps
//! its copy of an upstream entry when it answers one, and serves that copy when the upstream is
//! out of reach; the mirror asks NORA for each entry once per crate name.

use super::{create_progress_bar, drain, fetch_ok, FetchError, MirrorResult, MirrorTarget};
use crate::registry::cargo_registry::{crate_index_prefix, is_valid_crate_name};
use futures::stream::{self, StreamExt};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

/// Why a locked crate is not usable offline.
#[derive(Debug, thiserror::Error)]
enum CargoMiss {
    #[error("not a crate name")]
    InvalidName,
    /// Shared by every locked version of the crate: the entry is fetched once per name.
    #[error("index entry: {0}")]
    Index(Arc<FetchError>),
    #[error("index entry does not list version {0}")]
    VersionNotListed(String),
    #[error("download: {0}")]
    Download(FetchError),
}

/// The versions each crate name's index entry lists, or why it could not be read.
type IndexEntries = HashMap<String, Result<BTreeSet<String>, Arc<FetchError>>>;

/// One line of a sparse index entry, as far as the mirror reads it.
#[derive(serde::Deserialize)]
struct IndexLine {
    vers: String,
}

/// Fetch, through NORA at `base`, the index entry of every crate name in `targets` and every
/// locked `.crate`; a locked crate is fetched when both its entry (listing its version) and its
/// archive are, and failed (with a warning naming why) otherwise.
pub(super) async fn mirror_crates(
    client: &reqwest::Client,
    base: &str,
    targets: &[MirrorTarget],
    concurrency: usize,
) -> MirrorResult {
    let concurrency = concurrency.max(1);
    let names: BTreeSet<String> = targets
        .iter()
        .filter(|t| is_valid_crate_name(&t.name))
        .map(|t| t.name.to_lowercase())
        .collect();
    let index: IndexEntries = stream::iter(names)
        .map(|name| async move {
            let url = format!("{base}/cargo/index/{}/{name}", crate_index_prefix(&name));
            let listed = index_versions(client, &url).await.map_err(Arc::new);
            (name, listed)
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    let pb = create_progress_bar(targets.len() as u64);
    let results: Vec<(&MirrorTarget, Result<u64, CargoMiss>)> = stream::iter(targets)
        .map(|target| {
            let index = &index;
            let pb = pb.clone();
            async move {
                let got = mirror_crate(client, base, target, index).await;
                pb.set_message(format!("{}@{}", target.name, target.version));
                pb.inc(1);
                (target, got)
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;
    pb.finish_with_message("done");

    let mut fetched = 0;
    let mut failed = 0;
    let mut bytes = 0u64;
    for (target, got) in results {
        match got {
            Ok(n) => {
                bytes += n;
                fetched += 1;
            }
            Err(miss) => {
                eprintln!("  WARN: {} {} -> {miss}", target.name, target.version);
                failed += 1;
            }
        }
    }
    MirrorResult {
        total: targets.len(),
        fetched,
        failed,
        bytes,
    }
}

/// One locked crate: its index entry must list its version, then its archive is fetched.
async fn mirror_crate(
    client: &reqwest::Client,
    base: &str,
    target: &MirrorTarget,
    index: &IndexEntries,
) -> Result<u64, CargoMiss> {
    // Every valid name has its entry's result in `index`.
    let listed = match index.get(&target.name.to_lowercase()) {
        Some(Ok(listed)) if is_valid_crate_name(&target.name) => listed,
        Some(Err(e)) => return Err(CargoMiss::Index(Arc::clone(e))),
        _ => return Err(CargoMiss::InvalidName),
    };
    if !listed.contains(&target.version) {
        return Err(CargoMiss::VersionNotListed(target.version.clone()));
    }
    // The name as locked: static.crates.io stores `Inflector` under its capitals.
    let url = format!(
        "{base}/cargo/api/v1/crates/{}/{}/download",
        target.name, target.version
    );
    let got = match fetch_ok(client, &url, None).await {
        Ok(resp) => drain(resp).await,
        Err(e) => Err(e),
    };
    got.map_err(CargoMiss::Download)
}

/// The versions a sparse index entry lists.
async fn index_versions(
    client: &reqwest::Client,
    url: &str,
) -> Result<BTreeSet<String>, FetchError> {
    let body = fetch_ok(client, url, None).await?.bytes().await?;
    let mut versions = BTreeSet::new();
    for line in body.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let line: IndexLine = serde_json::from_slice(line)?;
        versions.insert(line.vers);
    }
    Ok(versions)
}
