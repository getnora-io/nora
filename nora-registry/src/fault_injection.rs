// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Fault injection for the release-binary panic check (`scripts/release-panic-check.sh`).
//!
//! Tests always build with unwind, so only a release binary shows what a panic does to
//! the process that ships. This module exists only in a build with the
//! `fault-injection` feature, which no shipped build enables; it adds routes that make a
//! handler, a background task or the maintenance loop panic or hang.

use axum::{routing::get, Router};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use crate::AppState;

/// What the next maintenance ticks do: run normally, panic once, panic every time, or hang.
static MAINTENANCE_FAULT: AtomicU8 = AtomicU8::new(NONE);
const NONE: u8 = 0;
const PANIC: u8 = 1;
const HANG: u8 = 2;
const PANIC_ONCE: u8 = 3;

/// The fault-injection routes, all under `/__fi/`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/__fi/panic", get(handler_panic))
        .route("/__fi/panic-bg", get(background_panic))
        .route("/__fi/panic-maint", get(|| arm(PANIC)))
        .route("/__fi/panic-maint-once", get(|| arm(PANIC_ONCE)))
        .route("/__fi/hang-maint", get(|| arm(HANG)))
        .route("/__fi/panic-task/{task}", get(arm_task))
}

/// The supervised tasks a panic can be injected into, by the names they run under.
const TASKS: [&str; 5] = ["maintenance", "pull_stats", "cleanup", "sighup", "audit"];

/// Per task in [`TASKS`]: 0 = run normally, 1 = panic once, 2 = panic on every poll.
static TASK_FAULTS: [AtomicU8; 5] = [const { AtomicU8::new(NONE) }; 5];

#[derive(serde::Deserialize)]
struct ArmTask {
    /// Panic again on every restart, not once.
    #[serde(default)]
    every: bool,
}

/// `GET /__fi/panic-task/{task}[?every=true]`: the named supervised task panics the next
/// time it is polled (its FI wrapper wakes it within 200 ms). For `audit`, an audit entry
/// is logged so the writer thread meets the fault.
async fn arm_task(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Path(task): axum::extract::Path<String>,
    axum::extract::Query(arm): axum::extract::Query<ArmTask>,
) -> (axum::http::StatusCode, &'static str) {
    let Some(index) = TASKS.iter().position(|name| *name == task) else {
        return (axum::http::StatusCode::NOT_FOUND, "no such task");
    };
    TASK_FAULTS[index].store(if arm.every { 2 } else { 1 }, Ordering::SeqCst);
    if task == "audit" {
        state.audit.log(crate::audit::AuditEntry::new(
            "fault_injection",
            "fault-injection",
            "-",
            "-",
            "make the audit writer panic",
        ));
    }
    (axum::http::StatusCode::OK, "armed")
}

/// Whether the task `name` is to panic now (a one-shot fault is used up by this).
pub fn task_fault(name: &str) -> bool {
    let Some(index) = TASKS.iter().position(|task| *task == name) else {
        return false;
    };
    match TASK_FAULTS[index].load(Ordering::SeqCst) {
        1 => TASK_FAULTS[index]
            .compare_exchange(1, NONE, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok(),
        2 => true,
        _ => false,
    }
}

/// A supervised task's future in a fault-injection build: panics inside the running task
/// once [`task_fault`] says so, and wakes every 200 ms to look, so a task asleep for hours
/// (the cleanup scheduler) meets its fault too.
pub struct FaultPoint<F> {
    name: &'static str,
    task: std::pin::Pin<Box<F>>,
    look: tokio::time::Interval,
}

impl<F: std::future::Future<Output = ()>> FaultPoint<F> {
    pub fn new(name: &'static str, task: F) -> Self {
        Self {
            name,
            task: Box::pin(task),
            look: tokio::time::interval(Duration::from_millis(200)),
        }
    }
}

impl<F: std::future::Future<Output = ()>> std::future::Future for FaultPoint<F> {
    type Output = ();

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        if task_fault(self.name) {
            panic!("fault injection: {} task panic", self.name);
        }
        while self.look.poll_tick(cx).is_ready() {}
        self.task.as_mut().poll(cx)
    }
}

async fn handler_panic() -> &'static str {
    panic!("fault injection: handler panic");
}

/// A spawned task with no guard of its own panics; the handler waits for it to end and
/// reports how it ended.
async fn background_panic() -> &'static str {
    let ended = tokio::spawn(async {
        panic!("fault injection: background task panic");
    })
    .await;
    match ended {
        Err(e) if e.is_panic() => "background task panicked",
        _ => "background task did not panic",
    }
}

async fn arm(fault: u8) -> &'static str {
    MAINTENANCE_FAULT.store(fault, Ordering::SeqCst);
    "armed"
}

/// Called at the start of every maintenance tick: panics or never returns once armed.
pub async fn maintenance_fault() {
    match MAINTENANCE_FAULT.load(Ordering::SeqCst) {
        PANIC => panic!("fault injection: maintenance tick panic"),
        PANIC_ONCE => {
            MAINTENANCE_FAULT.store(NONE, Ordering::SeqCst);
            panic!("fault injection: maintenance tick panic");
        }
        HANG => std::future::pending::<()>().await,
        _ => {}
    }
}

/// `NORA_FI_MAINTENANCE_MAX_SILENCE_SECS`, so the check sees a stalled loop fail `/health`
/// in seconds instead of minutes.
pub fn maintenance_max_silence() -> Option<Duration> {
    std::env::var("NORA_FI_MAINTENANCE_MAX_SILENCE_SECS")
        .ok()?
        .parse()
        .ok()
        .map(Duration::from_secs)
}
