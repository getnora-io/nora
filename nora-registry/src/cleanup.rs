//! Unified periodic cleanup scheduler.
//!
//! Retention and GC used to run as two independent tasks with the same
//! default interval, sharing one `cleanup_lock`. Both ticked at the same
//! instant every cycle and the periodic path used `try_lock`: GC won the
//! race every time and retention logged "cleanup lock held ... skipping"
//! with no retry, so age-based retention never ran on a default schedule.
//!
//! One task removes that race by construction — every due pass runs in
//! order under a single lock acquisition, and the acquisition waits instead
//! of skipping. Retention runs before GC because retention deletes expired
//! versions, which creates the orphans GC then sweeps: one cycle now
//! reclaims what the split design needed two cycles for.

use futures::future::BoxFuture;
use futures::FutureExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::warn;

pub(crate) struct CleanupPass {
    pub name: &'static str,
    pub interval: Duration,
    /// Runs one pass. Owns its own start/done logging.
    pub run: Box<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync>,
}

pub(crate) fn spawn_cleanup_scheduler(
    passes: Vec<CleanupPass>,
    cleanup_lock: Arc<tokio::sync::Mutex<()>>,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Every pass is due at boot: a process restarting more often than its
        // interval must still clean.
        let mut due: Vec<Instant> = vec![Instant::now(); passes.len()];

        loop {
            let Some(next) = due.iter().min().copied() else {
                return;
            };

            // CANCEL-SAFETY: sleep_until and cancelled() hold no state between
            // polls, and pass work runs to completion inside one iteration.
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep_until(next) => {}
            }

            // Waiting on the lock cannot starve the cycle: this task is the
            // only periodic contender. Racing the wait against cancellation
            // keeps SIGTERM prompt when a manual cleanup holds the lock.
            let guard = tokio::select! {
                _ = cancel.cancelled() => return,
                g = cleanup_lock.lock() => g,
            };

            let now = Instant::now();
            for (i, pass) in passes.iter().enumerate() {
                if due[i] > now {
                    continue;
                }
                // Wake-time based, so same-interval passes stay phase-locked
                // and a pass overrunning its interval fires on the next loop.
                due[i] = now + pass.interval;
                if std::panic::AssertUnwindSafe((pass.run)())
                    .catch_unwind()
                    .await
                    .is_err()
                {
                    warn!(
                        pass = pass.name,
                        "cleanup pass panicked — continuing with remaining passes"
                    );
                }
            }

            drop(guard);
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    type Recorder = Arc<parking_lot::Mutex<Vec<&'static str>>>;

    fn recorder() -> Recorder {
        Arc::new(parking_lot::Mutex::new(Vec::new()))
    }

    fn recording_pass(name: &'static str, interval: Duration, rec: &Recorder) -> CleanupPass {
        let rec = rec.clone();
        CleanupPass {
            name,
            interval,
            run: Box::new(move || {
                let rec = rec.clone();
                async move {
                    rec.lock().push(name);
                }
                .boxed()
            }),
        }
    }

    fn panicking_pass(name: &'static str, interval: Duration, rec: &Recorder) -> CleanupPass {
        let rec = rec.clone();
        CleanupPass {
            name,
            interval,
            run: Box::new(move || {
                let rec = rec.clone();
                async move {
                    rec.lock().push(name);
                    panic!("pass exploded");
                }
                .boxed()
            }),
        }
    }

    async fn wait_for(rec: &Recorder, count: usize) -> Vec<&'static str> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let seen = rec.lock().clone();
            if seen.len() >= count {
                return seen;
            }
            assert!(Instant::now() < deadline, "only recorded {seen:?}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The first cycle runs at boot and chains retention → GC in order.
    #[tokio::test]
    async fn cycle_runs_passes_in_order_at_boot() {
        let rec = recorder();
        let interval = Duration::from_secs(10);
        let cancel = CancellationToken::new();
        let start = Instant::now();
        let handle = spawn_cleanup_scheduler(
            vec![
                recording_pass("retention", interval, &rec),
                recording_pass("gc", interval, &rec),
            ],
            Arc::new(tokio::sync::Mutex::new(())),
            cancel.clone(),
        );

        let seen = wait_for(&rec, 2).await;
        assert_eq!(&seen[..2], &["retention", "gc"]);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "boot cycle waited for the interval"
        );

        cancel.cancel();
        handle.await.unwrap();
    }

    /// A panicking pass must not skip the later passes of its own cycle, nor
    /// kill the scheduler.
    #[tokio::test]
    async fn pass_panic_does_not_prevent_later_passes() {
        let rec = recorder();
        let interval = Duration::from_millis(100);
        let cancel = CancellationToken::new();
        let handle = spawn_cleanup_scheduler(
            vec![
                panicking_pass("retention", interval, &rec),
                recording_pass("gc", interval, &rec),
            ],
            Arc::new(tokio::sync::Mutex::new(())),
            cancel.clone(),
        );

        let seen = wait_for(&rec, 4).await;
        assert_eq!(&seen[..4], &["retention", "gc", "retention", "gc"]);

        cancel.cancel();
        handle.await.unwrap();
    }

    /// The periodic cycle parks on a held cleanup lock instead of skipping —
    /// the starvation the split schedulers had is gone.
    #[tokio::test]
    async fn cycle_waits_for_cleanup_lock_instead_of_skipping() {
        let rec = recorder();
        let interval = Duration::from_millis(100);
        let cleanup_lock = Arc::new(tokio::sync::Mutex::new(()));
        let held = cleanup_lock.clone().lock_owned().await;

        let cancel = CancellationToken::new();
        let handle = spawn_cleanup_scheduler(
            vec![
                recording_pass("retention", interval, &rec),
                recording_pass("gc", interval, &rec),
            ],
            cleanup_lock,
            cancel.clone(),
        );

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(rec.lock().is_empty(), "ran while the lock was held");

        drop(held);
        let seen = wait_for(&rec, 2).await;
        assert_eq!(&seen[..2], &["retention", "gc"]);

        cancel.cancel();
        handle.await.unwrap();
    }

    /// A shutdown requested while the cycle is parked on the lock must break
    /// promptly, not wait out the holder.
    #[tokio::test]
    async fn cancel_while_parked_on_lock_stops_scheduler() {
        let rec = recorder();
        let cleanup_lock = Arc::new(tokio::sync::Mutex::new(()));
        let held = cleanup_lock.clone().lock_owned().await;

        let cancel = CancellationToken::new();
        let handle = spawn_cleanup_scheduler(
            vec![recording_pass(
                "retention",
                Duration::from_millis(100),
                &rec,
            )],
            cleanup_lock,
            cancel.clone(),
        );

        tokio::time::sleep(Duration::from_millis(300)).await;
        cancel.cancel();

        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("scheduler did not stop when cancelled while parked on the lock")
            .unwrap();

        assert!(rec.lock().is_empty());
        drop(held);
    }
}
