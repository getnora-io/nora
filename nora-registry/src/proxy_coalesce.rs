// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! In-memory single-flight coalescing for the proxy cache-miss path (#595).
//!
//! When `M` concurrent clients ask for the same expired or missing artifact,
//! the naive path sends `M` independent upstream fetches and `M` redundant
//! storage writes for one logical refresh — a classic thundering herd /
//! cache stampede. This module collapses that to **one** upstream fetch: the
//! first caller for a key ("leader") performs the fetch; concurrent callers
//! ("followers") wait for the leader's in-memory result and serve a clone of
//! it without touching the upstream or the cache.
//!
//! ## Why in-memory, not "followers re-read storage"
//!
//! NORA's registries cache proxied bytes with a fire-and-forget
//! `tokio::spawn(storage.put(..))` *after* the response is returned (e.g.
//! `registry/npm.rs`). A follower that polled storage would race that detached
//! task — the object may not be written yet. So the leader publishes its
//! finished serve-bytes into a shared [`Slot`] and followers read *that*; the
//! background cache write stays exactly as it was (leader does it once).
//!
//! ## Correctness & cancel-safety
//!
//! - Leader election is a single `Entry::Vacant`/`Occupied` decision under the
//!   map mutex (never `Arc::strong_count`, which races) — exactly one leader.
//! - The map mutex (`parking_lot`) is never held across an `.await`; its guard
//!   is `!Send`, so the compiler rejects accidental holds on the multi-thread
//!   runtime. `parking_lot` also does not poison, so a leader panic still runs
//!   the guard's `Drop`.
//! - [`FetchGuard`] removes the key (ABA-safe via `Arc::ptr_eq`) and wakes
//!   waiters **on `Drop`**, so a cancelled leader (client disconnect) frees the
//!   slot instead of poisoning the key. The slot is never left dangling.
//! - A follower registers its `Notified` *before* the fast-path result check,
//!   so it cannot miss a `notify_waiters()` that fires in the gap (tokio
//!   guarantees a `Notified` receives `notify_waiters` wakeups from the moment
//!   it is created, not first poll).
//! - State is purely in-memory and rebuildable — an empty map after restart is
//!   correct (matches the "in-memory indexes are rebuildable from disk"
//!   invariant). No storage-format change.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::Notify;

/// One in-flight key's shared state: the leader's published result plus a
/// notifier woken when the leader resolves (success, failure, or cancel).
struct Slot<T> {
    /// `Some` once the leader has a value to share; followers clone it.
    result: Mutex<Option<T>>,
    /// Notified when the leader finishes or its slot is released.
    ready: Notify,
}

impl<T> Slot<T> {
    fn new() -> Self {
        Slot {
            result: Mutex::new(None),
            ready: Notify::new(),
        }
    }
}

type SlotMap<T> = Arc<Mutex<HashMap<String, Arc<Slot<T>>>>>;

/// Per-key single-flight coordinator. Cheap to clone (shares one map).
///
/// `T` is the value followers receive — for the proxy path this is the
/// ready-to-serve response body (`axum::body::Bytes`, an `Arc`-backed buffer
/// whose clone is O(1)).
#[derive(Clone)]
pub struct InflightMap<T> {
    map: SlotMap<T>,
}

impl<T> Default for InflightMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> InflightMap<T> {
    /// Create an empty coordinator.
    pub fn new() -> Self {
        InflightMap {
            map: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

/// RAII slot lease held by the leader for the duration of its fetch.
///
/// On `Drop` — whether from a normal return, a panic unwind, or the future
/// being cancelled mid-fetch — it removes its own slot from the map and wakes
/// every waiter, then decrements the in-flight gauge. Removal is ABA-safe: if
/// the key was already reused by a newer leader, `Arc::ptr_eq` prevents this
/// guard from evicting that newer slot.
struct FetchGuard<T> {
    map: SlotMap<T>,
    key: String,
    slot: Arc<Slot<T>>,
    registry: &'static str,
}

impl<T> Drop for FetchGuard<T> {
    fn drop(&mut self) {
        {
            let mut map = self.map.lock();
            if let Entry::Occupied(occ) = map.entry(self.key.clone()) {
                // Only evict our own slot — a newer leader may have re-inserted
                // the same key after we removed/before this drop (ABA).
                if Arc::ptr_eq(occ.get(), &self.slot) {
                    occ.remove();
                }
            }
        } // map lock released before notifying
          // Wake followers. Those that already observed `result` ignore it; the
          // rest re-check `result` (None on leader failure/cancel) and fall
          // through to their own fetch.
        self.slot.ready.notify_waiters();
        crate::metrics::PROXY_INFLIGHT
            .with_label_values(&[self.registry])
            .dec();
    }
}

impl<T> InflightMap<T>
where
    T: Clone,
{
    /// Run `fetch` under single-flight for `key`.
    ///
    /// Exactly one concurrent caller per key (the leader) executes `fetch`;
    /// the rest (followers) wait up to `budget` for the leader's published
    /// value and return a clone of it, incrementing
    /// [`PROXY_COALESCED_TOTAL`](crate::metrics::PROXY_COALESCED_TOTAL). If the
    /// leader fails (`None`), is cancelled, or `budget` elapses, the follower
    /// falls through to its **own** `fetch` (fail-open — a request never hangs
    /// on a dead leader, and a transient leader failure never fails followers).
    ///
    /// `budget` should comfortably exceed the leader's worst-case wall-clock
    /// (upstream timeout + retry) so followers wake on the leader's
    /// notification rather than on the budget ceiling; the ceiling is only a
    /// safety net against a leader that never notifies.
    ///
    /// `registry` is the metric label for the in-flight gauge and coalesced
    /// counter.
    pub async fn coalesced<F, Fut>(
        &self,
        key: &str,
        registry: &'static str,
        budget: Duration,
        fetch: F,
    ) -> Option<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Option<T>>,
    {
        // --- PRECONDITIONS ---
        debug_assert!(!key.is_empty(), "coalesce key must not be empty");

        // Leader election: one decision under the lock, zero awaits.
        let role = {
            let mut map = self.map.lock();
            match map.entry(key.to_string()) {
                Entry::Vacant(v) => {
                    let slot = Arc::new(Slot::new());
                    v.insert(Arc::clone(&slot));
                    Role::Leader(slot)
                }
                Entry::Occupied(o) => Role::Follower(Arc::clone(o.get())),
            }
        }; // map lock dropped here — before any `.await`

        match role {
            Role::Leader(slot) => {
                crate::metrics::PROXY_INFLIGHT
                    .with_label_values(&[registry])
                    .inc();
                // Guard frees the slot + notifies waiters on every exit path,
                // including cancellation of `fetch().await` below.
                // CANCEL-SAFETY: slot release happens in `FetchGuard::drop`,
                // not after the await point.
                let _guard = FetchGuard {
                    map: Arc::clone(&self.map),
                    key: key.to_string(),
                    slot: Arc::clone(&slot),
                    registry,
                };
                let out = fetch().await;
                // Publish BEFORE the guard drops so a follower woken by the
                // guard's `notify_waiters()` always observes the final value.
                if let Some(ref value) = out {
                    *slot.result.lock() = Some(value.clone());
                }
                out
                // `_guard` drops here: removes key (ptr_eq) + notify_waiters.
            }
            Role::Follower(slot) => {
                // Register interest BEFORE checking `result`: a `Notified`
                // created now is guaranteed to receive a `notify_waiters()`
                // that fires before we await. If the leader already published,
                // the fast-path check below sees it regardless.
                let notified = slot.ready.notified();
                tokio::pin!(notified);

                if let Some(value) = slot.result.lock().clone() {
                    return Some(Self::record_follower(registry, value));
                }

                let reason = match tokio::time::timeout(budget, &mut notified).await {
                    Ok(()) => {
                        if let Some(value) = slot.result.lock().clone() {
                            return Some(Self::record_follower(registry, value));
                        }
                        // Leader resolved without a value (failure/cancel) —
                        // fall through to our own fetch.
                        "leader"
                    }
                    Err(_) => {
                        // Budget elapsed while the leader was still fetching —
                        // fall through. A rising `budget` rate means a slow
                        // upstream is re-stampeding past the coalescer.
                        "budget"
                    }
                };
                crate::metrics::PROXY_COALESCE_FALLTHROUGH_TOTAL
                    .with_label_values(&[registry, reason])
                    .inc();
                fetch().await
            }
        }
    }

    fn record_follower(registry: &'static str, value: T) -> T {
        crate::metrics::PROXY_COALESCED_TOTAL
            .with_label_values(&[registry])
            .inc();
        value
    }
}

enum Role<T> {
    Leader(Arc<Slot<T>>),
    Follower(Arc<Slot<T>>),
}

/// Follower wait budget for a registry whose upstream timeout is `proxy_timeout`
/// seconds. Sized above the leader's worst-case wall-clock with headroom: the
/// npm metadata path wired today uses the no-retry `proxy_fetch_conditional`
/// (leader ≈ `proxy_timeout`), but `proxy_fetch_core` (binary/tarball fetches)
/// retries once with a 1 s back-off (≈ `2 * proxy_timeout + 1 s`). We size for
/// the latter so the budget stays correct if coalescing is later wired onto a
/// retrying path. The leader notifies followers the instant it resolves, so
/// this is only a ceiling, not the expected wait — a follower that hits it is
/// counted under `PROXY_COALESCE_FALLTHROUGH_TOTAL{reason="budget"}`.
pub fn follower_budget(proxy_timeout_secs: u64) -> Duration {
    Duration::from_secs(2 * proxy_timeout_secs + 3)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::sync::Barrier;

    fn budget() -> Duration {
        Duration::from_secs(5)
    }

    /// M concurrent callers on the same key → `fetch` runs exactly once; the
    /// other M-1 receive the leader's value. (Acceptance: M→1 fetch.)
    #[tokio::test]
    async fn coalesces_concurrent_callers_to_single_fetch() {
        let map: InflightMap<u64> = InflightMap::new();
        let calls = Arc::new(AtomicUsize::new(0));
        const M: usize = 32;
        // Barrier ensures all tasks reach election before the leader finishes,
        // so they genuinely contend (otherwise a fast leader could complete
        // before followers arrive).
        let gate = Arc::new(Barrier::new(M));

        let mut handles = Vec::new();
        for _ in 0..M {
            let map = map.clone();
            let calls = Arc::clone(&calls);
            let gate = Arc::clone(&gate);
            handles.push(tokio::spawn(async move {
                gate.wait().await;
                map.coalesced("pkg", "test", budget(), || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    // Hold the slot so followers pile up behind the leader.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Some(7u64)
                })
                .await
            }));
        }

        let results: Vec<_> = futures::future::join_all(handles).await;
        for r in results {
            assert_eq!(r.unwrap(), Some(7u64), "every caller gets the value");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "exactly one upstream fetch for M concurrent callers"
        );
        assert!(
            map.map.lock().is_empty(),
            "slot is removed after the leader finishes"
        );
    }

    /// Distinct keys never block each other — two keys fetched concurrently
    /// each run their own fetch. (Acceptance: distinct keys independent.)
    #[tokio::test]
    async fn distinct_keys_do_not_block() {
        let map: InflightMap<u64> = InflightMap::new();
        let calls = Arc::new(AtomicUsize::new(0));

        let a = {
            let map = map.clone();
            let calls = Arc::clone(&calls);
            tokio::spawn(async move {
                map.coalesced("a", "test", budget(), || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Some(1u64)
                })
                .await
            })
        };
        let b = {
            let map = map.clone();
            let calls = Arc::clone(&calls);
            tokio::spawn(async move {
                map.coalesced("b", "test", budget(), || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Some(2u64)
                })
                .await
            })
        };

        assert_eq!(a.await.unwrap(), Some(1));
        assert_eq!(b.await.unwrap(), Some(2));
        assert_eq!(calls.load(Ordering::SeqCst), 2, "each distinct key fetched");
    }

    /// Leader failure (`None`) does not fail followers — they fall through to
    /// their own fetch. (Acceptance: leader failure doesn't fail followers.)
    #[tokio::test]
    async fn leader_failure_falls_through_to_followers() {
        let map: InflightMap<u64> = InflightMap::new();
        let calls = Arc::new(AtomicUsize::new(0));
        const M: usize = 8;
        let gate = Arc::new(Barrier::new(M));

        let mut handles = Vec::new();
        for _ in 0..M {
            let map = map.clone();
            let calls = Arc::clone(&calls);
            let gate = Arc::clone(&gate);
            handles.push(tokio::spawn(async move {
                gate.wait().await;
                map.coalesced("pkg", "test", budget(), || async {
                    let n = calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    // First caller (leader) "fails"; later callers succeed.
                    if n == 0 {
                        None
                    } else {
                        Some(99u64)
                    }
                })
                .await
            }));
        }

        let results: Vec<_> = futures::future::join_all(handles).await;
        let successes = results
            .iter()
            .filter(|r| r.as_ref().unwrap() == &Some(99))
            .count();
        assert!(
            successes >= 1,
            "followers fall through and fetch after the leader fails"
        );
        // Leader called fetch once; followers fell through and each fetched —
        // so more than one call, and no caller hung.
        assert!(
            calls.load(Ordering::SeqCst) >= 2,
            "leader failure forces followers to their own fetch"
        );
    }

    /// Leader cancellation (its future dropped mid-fetch) releases the key, so
    /// a subsequent request fetches cleanly with no permanent stall.
    /// (Acceptance: cancellation releases the key.)
    #[tokio::test]
    async fn leader_cancellation_releases_key() {
        let map: InflightMap<u64> = InflightMap::new();
        let calls = Arc::new(AtomicUsize::new(0));

        // Spawn a leader that sleeps long, then cancel it mid-fetch.
        let leader = {
            let map = map.clone();
            let calls = Arc::clone(&calls);
            tokio::spawn(async move {
                map.coalesced("pkg", "test", budget(), || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    Some(1u64)
                })
                .await
            })
        };

        // Let the leader register and start fetching, then cancel it.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!map.map.lock().is_empty(), "leader registered its slot");
        leader.abort();
        // Give the abort time to run the guard's Drop.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            map.map.lock().is_empty(),
            "cancelled leader's slot is released on drop"
        );

        // A fresh request becomes the new leader and fetches cleanly.
        let fresh = map
            .coalesced("pkg", "test", budget(), || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Some(2u64)
            })
            .await;
        assert_eq!(fresh, Some(2), "subsequent request fetches with no stall");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "cancelled leader + one clean refetch"
        );
    }

    #[test]
    fn budget_scales_with_timeout() {
        // 2 * timeout + 3s margin.
        assert_eq!(follower_budget(30), Duration::from_secs(63));
        assert_eq!(follower_budget(0), Duration::from_secs(3));
    }
}
