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
