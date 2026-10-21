// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! The long-lived background tasks of the server, and what happens when one panics.
//!
//! The shipped build unwinds (C67), so a panic ends only the task it happened in. Left at
//! that, a dead task is silent: the process serves on while tokens stop being flushed or
//! the audit trail stops being written. Every long-lived task therefore runs here, and a
//! panic in one is always logged as an error naming the task and counted in
//! `nora_task_panics_total{task}`; then:
//! - an async task ([`Supervisor::spawn`]) runs again after a backoff. One that keeps
//!   panicking soon after each start fails `/health`, so an orchestrator restarts the
//!   process;
//! - a task on a blocking thread that NORA cannot run without ([`blocking`]: the audit
//!   writer) ends the process with [`EXIT_TASK_PANICKED`], since NORA without it would
//!   report what it does not do.
//!
//! A task may also have a [`Heartbeat`]: proof of progress, not only of life. The
//! maintenance loop beats after each completed tick, so one that hangs, or whose ticks keep
//! failing, fails `/health` too (R2-49). `/health` asks [`Supervisor::failing`] and nothing
//! else.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use futures::FutureExt;

/// Exit code of a process ended by a [`blocking`] task's panic: `EX_SOFTWARE`. The
/// packaged systemd units restart on it (they refuse only 78, a bad configuration).
pub const EXIT_TASK_PANICKED: i32 = 70;

/// Restart backoff and the crash-loop rule.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// The first wait before a restart; doubled after each panic up to `backoff_max`.
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    /// A run this long counts as recovered: the backoff and the panic count start over.
    pub stable_run: Duration,
    /// Panics in a row, each before `stable_run`, after which `/health` fails.
    pub crash_loop: u32,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            stable_run: Duration::from_secs(60),
            crash_loop: 5,
        }
    }
}

/// How a process is ended; replaced in tests.
pub type ExitHook = Arc<dyn Fn(i32) + Send + Sync>;

/// [`ExitHook`] of the real process.
pub fn process_exit() -> ExitHook {
    Arc::new(|code| std::process::exit(code))
}

/// When a task last showed progress. Stalled after `max_silence` without a beat.
pub struct Heartbeat {
    origin: tokio::time::Instant,
    /// Milliseconds from `origin` to the last beat.
    last_beat_ms: AtomicU64,
    max_silence: Duration,
}

impl Heartbeat {
    /// A heartbeat that counts as a beat now, and is stalled after `max_silence` without one.
    pub fn new(max_silence: Duration) -> Self {
        Self {
            origin: tokio::time::Instant::now(),
            last_beat_ms: AtomicU64::new(0),
            max_silence,
        }
    }

    /// Record progress.
    pub fn beat(&self) {
        let ms = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_beat_ms.store(ms, Ordering::Relaxed);
    }

    /// Time since the last beat.
    pub fn silent_for(&self) -> Duration {
        let now = self.origin.elapsed();
        now.saturating_sub(Duration::from_millis(
            self.last_beat_ms.load(Ordering::Relaxed),
        ))
    }

    /// Whether the task has been silent for longer than it may be.
    pub fn stalled(&self) -> bool {
        self.silent_for() > self.max_silence
    }
}

/// The supervisor of the process's long-lived tasks.
pub struct Supervisor {
    /// Tasks whose heartbeat `/health` reads.
    heartbeats: Vec<(&'static str, Arc<Heartbeat>)>,
    /// Tasks in a crash loop right now.
    crash_looping: ArcSwap<Vec<&'static str>>,
    timing: Timing,
}

impl Supervisor {
    /// A supervisor reading `heartbeats`, with the default timing.
    pub fn new(heartbeats: Vec<(&'static str, Arc<Heartbeat>)>) -> Self {
        Self::with(heartbeats, Timing::default())
    }

    /// A supervisor with its timing spelled out (tests).
    pub fn with(heartbeats: Vec<(&'static str, Arc<Heartbeat>)>, timing: Timing) -> Self {
        Self {
            heartbeats,
            crash_looping: ArcSwap::default(),
            timing,
        }
    }

    /// The task that fails `/health`, if one does: a stalled heartbeat or a crash loop.
    pub fn failing(&self) -> Option<&'static str> {
        self.heartbeats
            .iter()
            .find(|(_, heartbeat)| heartbeat.stalled())
            .map(|(name, _)| *name)
            .or_else(|| self.crash_looping.load().first().copied())
    }

    /// Spawn the task `run` makes, restarted after each panic; `run` is called again for each
    /// restart. The task ends when a run returns.
    pub fn spawn<F, Fut>(
        self: &Arc<Self>,
        name: &'static str,
        mut run: F,
    ) -> tokio::task::JoinHandle<()>
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let supervisor = Arc::clone(self);
        tokio::spawn(async move {
            let timing = supervisor.timing;
            let mut backoff = timing.backoff_min;
            let mut panics_in_a_row = 0u32;
            loop {
                #[cfg(feature = "fault-injection")]
                let task = crate::fault_injection::FaultPoint::new(name, run());
                #[cfg(not(feature = "fault-injection"))]
                let task = run();
                let task = AssertUnwindSafe(task).catch_unwind();
                tokio::pin!(task);
                // CANCEL-SAFETY: the task future stays pinned here and is awaited to its end
                // in both arms; the sleep only marks a run long enough to count as recovered.
                let ended = tokio::select! {
                    ended = &mut task => ended,
                    () = tokio::time::sleep(timing.stable_run) => {
                        panics_in_a_row = 0;
                        backoff = timing.backoff_min;
                        supervisor.recovered(name);
                        task.await
                    }
                };
                let Err(panic) = ended else {
                    return;
                };
                report_panic(name, &panic);
                panics_in_a_row += 1;
                if panics_in_a_row >= timing.crash_loop {
                    supervisor.crash_loop(name);
                }
                tracing::warn!(
                    task = name,
                    panics_in_a_row,
                    restart_in_ms = backoff.as_millis() as u64,
                    "restarting background task"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(timing.backoff_max);
            }
        })
    }

    fn crash_loop(&self, name: &'static str) {
        self.crash_looping.rcu(|tasks| {
            let mut tasks = Vec::clone(tasks);
            if !tasks.contains(&name) {
                tasks.push(name);
            }
            tasks
        });
    }

    fn recovered(&self, name: &'static str) {
        if self.crash_looping.load().contains(&name) {
            self.crash_looping.rcu(|tasks| {
                tasks
                    .iter()
                    .copied()
                    .filter(|task| *task != name)
                    .collect::<Vec<_>>()
            });
        }
    }
}

/// Run `work` on the current (blocking) thread as the task `name`, ending the process if it panics:
/// for a task that lives on a blocking thread, such as the audit writer.
pub fn blocking<F: FnOnce()>(name: &'static str, exit: &ExitHook, work: F) {
    if let Err(panic) = std::panic::catch_unwind(AssertUnwindSafe(work)) {
        report_panic(name, &panic);
        tracing::error!(
            task = name,
            "a task the server cannot run without died, exiting"
        );
        exit(EXIT_TASK_PANICKED);
    }
}

/// Every task panic: an error in the log naming the task, and the counter.
pub(crate) fn report_panic(name: &'static str, panic: &Box<dyn std::any::Any + Send>) {
    let message = panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload");
    tracing::error!(task = name, panic = message, "background task panicked");
    crate::metrics::TASK_PANICS_TOTAL
        .with_label_values(&[name])
        .inc();
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicI32;

    const TICK: Duration = Duration::from_millis(10);

    fn timing() -> Timing {
        Timing {
            backoff_min: TICK,
            backoff_max: TICK * 4,
            stable_run: TICK * 30,
            crash_loop: 3,
        }
    }

    fn supervisor() -> Arc<Supervisor> {
        Arc::new(Supervisor::with(Vec::new(), timing()))
    }

    fn panics(task: &str) -> u64 {
        crate::metrics::TASK_PANICS_TOTAL
            .with_label_values(&[task])
            .get()
    }

    /// Restart: the task runs again after a panic, the panic is counted, and one panic
    /// does not fail liveness.
    #[tokio::test]
    async fn a_task_that_panics_once_is_restarted() {
        let tasks = supervisor();
        let runs = Arc::new(AtomicU64::new(0));
        let r = Arc::clone(&runs);
        let task = tasks.spawn("test_restart", move || {
            let run = r.fetch_add(1, Ordering::SeqCst);
            async move {
                assert_ne!(run, 0, "a bug in the first run");
                std::future::pending::<()>().await;
            }
        });
        tokio::time::sleep(TICK * 10).await;
        assert_eq!(runs.load(Ordering::SeqCst), 2);
        assert_eq!(panics("test_restart"), 1);
        assert_eq!(tasks.failing(), None);
        assert!(!task.is_finished());
        task.abort();
    }

    /// Restart, crash loop: a task that keeps panicking soon after each start fails
    /// liveness by name, and clears it once a run lasts.
    #[tokio::test]
    async fn a_task_in_a_crash_loop_fails_liveness_until_it_recovers() {
        let tasks = supervisor();
        let runs = Arc::new(AtomicU64::new(0));
        let r = Arc::clone(&runs);
        let task = tasks.spawn("test_crash_loop", move || {
            let run = r.fetch_add(1, Ordering::SeqCst);
            async move {
                assert!(run >= 3, "a bug in the first three runs");
                std::future::pending::<()>().await;
            }
        });
        tokio::time::sleep(TICK * 15).await;
        assert_eq!(tasks.failing(), Some("test_crash_loop"));
        tokio::time::sleep(timing().stable_run + TICK * 5).await;
        assert_eq!(tasks.failing(), None, "a lasting run clears it");
        task.abort();
    }

    /// The blocking form, for the audit writer: a panic ends the process, a normal end
    /// does not.
    #[test]
    fn a_blocking_task_that_panics_ends_the_process() {
        let code = Arc::new(AtomicI32::new(0));
        let seen = Arc::clone(&code);
        let exit: ExitHook = Arc::new(move |c| seen.store(c, Ordering::SeqCst));
        blocking("test_blocking", &exit, || {});
        assert_eq!(code.load(Ordering::SeqCst), 0);
        blocking("test_blocking", &exit, || panic!("a bug"));
        assert_eq!(code.load(Ordering::SeqCst), EXIT_TASK_PANICKED);
        assert_eq!(panics("test_blocking"), 1);
    }

    /// A task that returns ends: shutdown is not a crash.
    #[tokio::test]
    async fn a_task_that_returns_is_not_restarted() {
        let tasks = supervisor();
        let runs = Arc::new(AtomicU64::new(0));
        let r = Arc::clone(&runs);
        let task = tasks.spawn("test_return", move || {
            r.fetch_add(1, Ordering::SeqCst);
            async {}
        });
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert_eq!(panics("test_return"), 0);
    }

    /// A stalled heartbeat names its task.
    #[tokio::test]
    async fn a_stalled_heartbeat_fails_liveness() {
        let heartbeat = Arc::new(Heartbeat::new(TICK * 3));
        let tasks = Supervisor::new(vec![("test_beat", Arc::clone(&heartbeat))]);
        assert_eq!(tasks.failing(), None);
        tokio::time::sleep(TICK * 6).await;
        assert_eq!(tasks.failing(), Some("test_beat"));
        heartbeat.beat();
        assert_eq!(tasks.failing(), None);
    }
}
