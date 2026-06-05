// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Unified cache TTL logic for all proxy registries.
//!
//! Semantics:
//! - `-1` — cache forever, never refetch from upstream
//! - `0`  — always refetch (disable cache for metadata)
//! - `>0` — TTL in seconds; refetch after this many seconds

/// Check if a cached entry is still fresh.
///
/// # Arguments
/// - `modified_unix` — file modification time (Unix epoch seconds)
/// - `ttl_secs` — TTL value from config (`-1` = forever, `0` = always stale, `>0` = seconds)
///
/// Returns `true` if the entry should be served from cache (fresh),
/// `false` if it should be refetched from upstream (stale).
pub fn is_within_ttl(modified_unix: u64, ttl_secs: i64) -> bool {
    match ttl_secs {
        // -1: cache forever — always fresh
        ..=-1 => true,
        // 0: always refetch — always stale
        0 => false,
        // >0: check age
        ttl => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now.saturating_sub(modified_unix) < ttl as u64
        }
    }
}

/// Whether a cached MUTABLE proxy resource (a cargo sparse index, a docker tag, a version
/// listing, …) may be served WITHOUT revalidating against upstream: only when there is no
/// upstream to revalidate against (the resource is locally authoritative) or it is still within
/// a POSITIVE `metadata_ttl` staleness window. A non-positive ttl revalidates every pull, so a
/// newly published version or yank appears.
pub fn mutable_ref_fresh(has_upstream: bool, metadata_ttl: i64, modified: Option<u64>) -> bool {
    if !has_upstream {
        return true;
    }
    metadata_ttl > 0
        && modified
            .map(|m| is_within_ttl(m, metadata_ttl))
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn ttl_minus_one_always_fresh() {
        // Even ancient entries are fresh with ttl=-1
        assert!(is_within_ttl(0, -1));
        assert!(is_within_ttl(1_000_000, -1));
    }

    #[test]
    fn ttl_zero_always_stale() {
        // Even just-modified entries are stale with ttl=0
        assert!(!is_within_ttl(now_secs(), 0));
        assert!(!is_within_ttl(now_secs() + 100, 0));
    }

    #[test]
    fn ttl_positive_fresh() {
        // Modified 10 seconds ago, TTL is 300 → fresh
        assert!(is_within_ttl(now_secs() - 10, 300));
    }

    #[test]
    fn ttl_positive_stale() {
        // Modified 600 seconds ago, TTL is 300 → stale
        assert!(!is_within_ttl(now_secs() - 600, 300));
    }

    #[test]
    fn ttl_positive_boundary() {
        // Modified exactly TTL seconds ago — stale (< not <=)
        let now = now_secs();
        assert!(!is_within_ttl(now - 300, 300));
        // One second less — still fresh
        assert!(is_within_ttl(now - 299, 300));
    }

    #[test]
    fn mutable_ref_fresh_hosted_and_proxied() {
        let now = now_secs();
        // Hosted (no upstream to revalidate against) → always fresh, regardless of ttl.
        assert!(mutable_ref_fresh(false, -1, Some(now)));
        assert!(mutable_ref_fresh(false, 0, None));
        // Proxied + non-positive ttl → revalidate every pull (not fresh) — the fix.
        assert!(!mutable_ref_fresh(true, -1, Some(now)));
        assert!(!mutable_ref_fresh(true, 0, Some(now)));
        // Proxied + positive ttl within the window → fresh (bounded staleness).
        assert!(mutable_ref_fresh(true, 300, Some(now - 10)));
        // Proxied + positive ttl beyond the window → revalidate.
        assert!(!mutable_ref_fresh(true, 300, Some(now - 600)));
        // Proxied + unknown mtime → revalidate.
        assert!(!mutable_ref_fresh(true, 300, None));
    }
}
