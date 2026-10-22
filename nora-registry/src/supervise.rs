// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! The long-lived background tasks of the server, and what happens when one panics.
//!
//! The shipped build unwinds, so a panic ends only the task it happened in. Left at
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
//! maintenance loop beats after each tick that completes or is cut at its deadline, so a
//! loop that starts no new tick, or whose ticks keep panicking, fails `/health` too; a tick
//! waiting on a store that does not answer does not (that is `/ready`'s business).
//! `/health` asks [`Supervisor::failing`] and nothing else.
//!
//! So that a task started under some other supervisor cannot go unseen, a shipped build has
//! one: [`of_process`] is the only way to one outside tests, and every call gets the same.
//! The work a task starts and does not wait for ([`Detached`]) comes from it too, one per
//! name, so a run still going is never joined by a second, however often the task restarts.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

/// [`ExitHook`] of the real process. In tests it records the exit code instead
/// ([`exits_requested`]), so a test can see that a task the process cannot run without ends
/// it, and the test runner lives on.
pub fn process_exit() -> ExitHook {
    #[cfg(test)]
    return Arc::new(exits::record);
    #[cfg(not(test))]
    Arc::new(|code| std::process::exit(code))
}

#[cfg(test)]
pub use exits::requested as exits_requested;

#[cfg(test)]
mod exits {
    static REQUESTED: std::sync::Mutex<Vec<i32>> = std::sync::Mutex::new(Vec::new());

    pub(super) fn record(code: i32) {
        REQUESTED.lock().unwrap().push(code);
    }

    /// The exit codes [`super::process_exit`] has been asked for in this test process.
    pub fn requested() -> Vec<i32> {
        REQUESTED.lock().unwrap().clone()
    }
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

    /// How long the task may be silent.
    pub fn max_silence(&self) -> Duration {
        self.max_silence
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
    /// Whether a run of the detached work of each name is going.
    detached: ArcSwap<Vec<(&'static str, Arc<AtomicBool>)>>,
    timing: Timing,
}

/// The supervisor of the process, and the maintenance loop's heartbeat it reads, stalled after
/// `max_silence` without a beat. The first call builds them; every later one gets the same,
/// whatever it asks, so code that starts a task cannot hold a supervisor `/health` does not
/// read. In tests each call builds its own: a test process runs many servers.
pub fn of_process(max_silence: Duration) -> (Arc<Supervisor>, Arc<Heartbeat>) {
    #[cfg(test)]
    return maintained(max_silence);
    #[cfg(not(test))]
    {
        static PROCESS: std::sync::OnceLock<(Arc<Supervisor>, Arc<Heartbeat>)> =
            std::sync::OnceLock::new();
        once(&PROCESS, max_silence)
    }
}

/// What `cell` holds, built by [`maintained`] if it holds nothing yet.
fn once(
    cell: &std::sync::OnceLock<(Arc<Supervisor>, Arc<Heartbeat>)>,
    max_silence: Duration,
) -> (Arc<Supervisor>, Arc<Heartbeat>) {
    let (tasks, heartbeat) = cell.get_or_init(|| maintained(max_silence));
    (Arc::clone(tasks), Arc::clone(heartbeat))
}

/// A supervisor with the default timing reading the maintenance loop's heartbeat.
fn maintained(max_silence: Duration) -> (Arc<Supervisor>, Arc<Heartbeat>) {
    let heartbeat = Arc::new(Heartbeat::new(max_silence));
    let tasks = Supervisor::build(
        vec![("maintenance", Arc::clone(&heartbeat))],
        Timing::default(),
    );
    (Arc::new(tasks), heartbeat)
}

impl Supervisor {
    fn build(heartbeats: Vec<(&'static str, Arc<Heartbeat>)>, timing: Timing) -> Self {
        Self {
            heartbeats,
            crash_looping: ArcSwap::default(),
            detached: ArcSwap::default(),
            timing,
        }
    }

    /// A supervisor of its own reading `heartbeats`, with the default timing (tests).
    #[cfg(test)]
    pub fn new(heartbeats: Vec<(&'static str, Arc<Heartbeat>)>) -> Self {
        Self::build(heartbeats, Timing::default())
    }

    /// A supervisor of its own with its timing spelled out (tests).
    #[cfg(test)]
    pub fn with(heartbeats: Vec<(&'static str, Arc<Heartbeat>)>, timing: Timing) -> Self {
        Self::build(heartbeats, timing)
    }

    /// The detached work reported as the task `name`: every call for one name shares its
    /// runs, so one starts only while none of that name is going.
    pub fn detached(&self, name: &'static str) -> Detached {
        let of = |runs: &[(&'static str, Arc<AtomicBool>)]| {
            runs.iter()
                .find(|(run, _)| *run == name)
                .map(|(_, running)| Arc::clone(running))
        };
        if of(&self.detached.load()).is_none() {
            self.detached.rcu(|runs| {
                let mut runs = Vec::clone(runs);
                if of(&runs).is_none() {
                    runs.push((name, Arc::new(AtomicBool::new(false))));
                }
                runs
            });
        }
        Detached {
            name,
            running: of(&self.detached.load()).unwrap_or_default(),
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

/// Work a periodic task starts and does not wait for, such as counting the store's size:
/// it runs in a task of its own, at most one run at a time, so a slow run is never joined by
/// a second. Only [`Supervisor::detached`] makes one, and every one of a name shares its runs. A panic in a run is reported under `name` (log and counter) and ends only that
/// run; the next start runs again.
pub struct Detached {
    name: &'static str,
    running: Arc<AtomicBool>,
}

/// Marks a [`Detached`] run finished however it ends, a panic included.
struct Finished(Arc<AtomicBool>);

impl Drop for Finished {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Detached {
    /// Start `work` unless the previous run is still going. Returns the run's handle, or
    /// `None` when nothing was started; dropping the handle does not stop the run.
    pub fn start<F>(&self, work: F) -> Option<tokio::task::JoinHandle<()>>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if self.running.swap(true, Ordering::AcqRel) {
            return None;
        }
        let finished = Finished(Arc::clone(&self.running));
        let name = self.name;
        let run = tokio::spawn(async move {
            let _finished = finished;
            if let Err(panic) = AssertUnwindSafe(work).catch_unwind().await {
                report_panic(name, &panic);
            }
        });
        Some(run)
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

/// Panics of the task `name` counted so far in this test process.
#[cfg(test)]
pub(crate) fn panics_counted(name: &str) -> u64 {
    crate::metrics::TASK_PANICS_TOTAL
        .with_label_values(&[name])
        .get()
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

    /// The supervisor a shipped build has is built once: every later call, the server's
    /// own or any other, gets the same one, and the heartbeat it reads.
    #[test]
    fn a_process_has_one_supervisor() {
        let cell = std::sync::OnceLock::new();
        let (tasks, heartbeat) = once(&cell, Duration::from_secs(300));
        let (again, beats) = once(&cell, Duration::from_secs(90));
        assert!(Arc::ptr_eq(&tasks, &again));
        assert!(Arc::ptr_eq(&heartbeat, &beats));
        assert_eq!(beats.max_silence(), Duration::from_secs(300));
        assert!(tasks
            .heartbeats
            .iter()
            .any(|(name, beat)| *name == "maintenance" && Arc::ptr_eq(beat, &heartbeat)));
    }

    /// Detached work of one name asked for twice, as a restarted task asks for it again, is
    /// one: a second run does not start beside a run still going. Another name runs apart.
    #[tokio::test]
    async fn detached_work_of_one_name_runs_one_at_a_time_however_often_it_is_asked_for() {
        let tasks = supervisor();
        let first = tasks.detached("size");
        let again = tasks.detached("size");
        let other = tasks.detached("flush");
        let (done, finish) = tokio::sync::oneshot::channel::<()>();
        let run = first.start(async move {
            let _ = finish.await;
        });
        assert!(run.is_some());
        assert!(
            again.start(async {}).is_none(),
            "a second run beside the first"
        );
        assert!(other.start(async {}).is_some(), "another name runs apart");
        done.send(()).unwrap();
        run.unwrap().await.unwrap();
        assert!(
            again.start(async {}).is_some(),
            "the next run once the first ended"
        );
    }

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

    /// Restart backoff: each restart waits out the backoff, doubled after each panic up to
    /// its cap, so a task that panics at every start is not restarted in a hot loop.
    #[tokio::test(start_paused = true)]
    async fn restarts_wait_out_a_doubling_backoff() {
        let tasks = Arc::new(Supervisor::with(
            Vec::new(),
            Timing {
                backoff_min: Duration::from_secs(1),
                backoff_max: Duration::from_secs(4),
                stable_run: Duration::from_secs(1000),
                crash_loop: 1000,
            },
        ));
        let origin = tokio::time::Instant::now();
        let starts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let s = Arc::clone(&starts);
        let task = tasks.spawn("test_backoff", move || {
            let mut starts = s.lock().unwrap();
            starts.push(origin.elapsed());
            // Past twenty runs, a restart without a pause would spin and stop the paused
            // clock: the run then waits, so the test fails on the gaps instead of hanging.
            let spinning = starts.len() > 20;
            async move {
                if spinning {
                    std::future::pending::<()>().await;
                }
                panic!("a bug in every run")
            }
        });
        tokio::time::sleep(Duration::from_millis(20_500)).await;
        task.abort();
        let starts = starts.lock().unwrap();
        let gaps: Vec<u128> = starts
            .windows(2)
            .map(|w| (w[1] - w[0]).as_millis())
            .collect();
        assert_eq!(gaps, [1000, 2000, 4000, 4000, 4000, 4000], "{starts:?}");
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

    /// Detached work runs one at a time: while a run is going no second one starts, and the
    /// next start after it ends runs.
    #[tokio::test]
    async fn detached_work_runs_one_at_a_time() {
        let work = supervisor().detached("test_detached_one");
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let first = work
            .start(async move {
                let _ = wait.await;
            })
            .unwrap();
        assert!(
            work.start(async {}).is_none(),
            "a second run while one goes"
        );
        release.send(()).unwrap();
        first.await.unwrap();
        let next = work
            .start(async {})
            .expect("the next start after the run ended");
        next.await.unwrap();
    }

    /// A detached run that panics late is logged and counted under its name, and does not
    /// keep the next start from running.
    #[tokio::test]
    async fn a_detached_run_that_panics_is_reported_and_the_next_runs() {
        let work = supervisor().detached("test_detached_panic");
        let run = work
            .start(async {
                tokio::time::sleep(TICK).await;
                panic!("a bug that shows after a while");
            })
            .unwrap();
        run.await.expect("the panic is caught in the run");
        assert_eq!(panics("test_detached_panic"), 1);
        let ran = Arc::new(AtomicU64::new(0));
        let r = Arc::clone(&ran);
        work.start(async move {
            r.fetch_add(1, Ordering::SeqCst);
        })
        .expect("the next start after a panic")
        .await
        .unwrap();
        assert_eq!(ran.load(Ordering::SeqCst), 1);
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
