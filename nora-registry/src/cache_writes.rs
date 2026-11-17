// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Cache writes that run after their response, counted so a graceful stop waits for them.
//!
//! A proxied artifact is answered first and stored afterwards, in a task of its own, so the
//! client does not wait for storage. A stop right after the answer used to drop that task:
//! the artifact was served and not kept, and after a restart with the upstream down it could
//! not be served at all. Every such write runs through [`CacheWrites::spawn`], and the stop
//! waits for them ([`CacheWrites::finish`]) before the audit log is flushed.

use futures::FutureExt;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::time::Duration;
use tokio_util::task::TaskTracker;

/// The cache writes in flight. Cloning shares the count.
#[derive(Clone, Default)]
pub(crate) struct CacheWrites(TaskTracker);

impl CacheWrites {
    /// Run `write` in a task of its own, counted until it ends. A panic in it is logged and
    /// ends that task only, as in every other detached task of the server.
    pub(crate) fn spawn<F>(&self, registry: &'static str, write: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.0
            .spawn(AssertUnwindSafe(write).catch_unwind().map(move |done| {
                if let Err(panic) = done {
                    tracing::error!(registry, panic = ?panic, "background cache write panicked");
                }
            }));
    }

    /// Take no more writes, and wait for those in flight for at most `within`. The number of
    /// writes still running when it passed; they are dropped with the process.
    pub(crate) async fn finish(&self, within: Duration) -> usize {
        self.0.close();
        // CANCEL-SAFETY: `wait` only observes the tracker; dropping it on timeout leaves the
        // writes running, and the count read after it is what the caller reports.
        match tokio::time::timeout(within, self.0.wait()).await {
            Ok(()) => 0,
            Err(_) => self.0.len(),
        }
    }

    /// Writes in flight.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// A write that is still running when the stop begins is waited for.
    #[tokio::test]
    async fn a_write_in_flight_is_waited_for() {
        let writes = CacheWrites::default();
        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        writes.spawn("npm", async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            flag.store(true, Ordering::SeqCst);
        });
        let started = std::time::Instant::now();
        assert_eq!(writes.finish(Duration::from_secs(5)).await, 0);
        assert!(done.load(Ordering::SeqCst));
        // Done when the writes are, not at the ceiling.
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    /// A write slower than the ceiling does not hold the stop: it ends at the ceiling and
    /// says how many writes are still running.
    #[tokio::test(start_paused = true)]
    async fn a_write_slower_than_the_ceiling_does_not_hold_the_stop() {
        let writes = CacheWrites::default();
        writes.spawn("npm", tokio::time::sleep(Duration::from_secs(3600)));
        writes.spawn("npm", async {});
        let started = tokio::time::Instant::now();
        assert_eq!(writes.finish(Duration::from_secs(10)).await, 1);
        assert_eq!(started.elapsed(), Duration::from_secs(10));
    }

    /// A panic in a write ends that write, and the stop still finishes.
    #[tokio::test]
    async fn a_panicking_write_is_counted_out() {
        let writes = CacheWrites::default();
        writes.spawn("npm", async { panic!("injected") });
        assert_eq!(writes.finish(Duration::from_secs(5)).await, 0);
        assert_eq!(writes.len(), 0);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod every_write_is_counted_tests {
    /// Where a registry handler may start a task that is not a counted cache write: (file,
    /// function, why). Empty: every task a handler starts after its response writes or
    /// deletes cache, and goes through [`super::CacheWrites`] so a stop waits for it.
    const ALLOWED: &[(&str, &str, &str)] = &[];

    const STARTS: &[&str] = &["tokio::spawn(", "tokio::task::spawn("];

    /// (file, function) of every task start in `text` outside `#[cfg(test)]` modules and
    /// comments.
    fn starts_in(file: &str, text: &str) -> Vec<(String, String)> {
        let lines: Vec<&str> = text.lines().collect();
        let mut found = Vec::new();
        let mut function = String::from("-");
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            if line.trim() == "#[cfg(test)]" {
                if let Some(next) = lines[i + 1..].iter().find(|l| !l.trim().starts_with("#[")) {
                    let body = next.trim_start();
                    if body.starts_with("mod ")
                        || body.starts_with("pub mod ")
                        || body.starts_with("pub(crate) mod ")
                    {
                        let indent = &next[..next.len() - body.len()];
                        let close = format!("{indent}}}");
                        while i < lines.len() && lines[i] != close {
                            i += 1;
                        }
                        i += 1;
                        continue;
                    }
                }
            }
            let code = line.split("//").next().unwrap_or("");
            if let Some(at) = code.find("fn ") {
                let name: String = code[at + 3..]
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    function = name;
                }
            }
            if STARTS.iter().any(|start| code.contains(start)) {
                found.push((file.to_string(), function.clone()));
            }
            i += 1;
        }
        found
    }

    /// A task a registry handler starts is a counted cache write, or is listed with why.
    #[test]
    fn a_registry_handler_starts_no_uncounted_task() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/registry");
        let mut found = Vec::new();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "rs") {
                let name = path.file_name().unwrap().to_string_lossy().to_string();
                found.extend(starts_in(&name, &std::fs::read_to_string(&path).unwrap()));
            }
        }
        found.sort();
        found.dedup();
        let listed: Vec<(String, String)> = ALLOWED
            .iter()
            .map(|(f, n, _)| (f.to_string(), n.to_string()))
            .collect();
        let new: Vec<_> = found.iter().filter(|f| !listed.contains(f)).collect();
        let gone: Vec<_> = listed.iter().filter(|l| !found.contains(l)).collect();
        assert!(
            new.is_empty() && gone.is_empty(),
            "tasks started by a registry handler outside CacheWrites, not listed: {new:?}; \
             listed, gone: {gone:?}. Start it through state.cache_writes (or spawn_cache), or \
             list it with why a stop need not wait for it"
        );
    }

    /// The check sees a start in a function and skips one in a test module or a comment.
    #[test]
    fn the_check_sees_a_start_and_skips_tests() {
        let text = "fn serve() {\n    tokio::spawn(async {});\n}\n\
                    // tokio::spawn(in a comment)\n\
                    #[cfg(test)]\nmod tests {\n    fn t() { tokio::spawn(async {}); }\n}\n\
                    fn after() { tokio::task::spawn(async {}); }\n";
        assert_eq!(
            starts_in("x.rs", text),
            vec![
                ("x.rs".to_string(), "serve".to_string()),
                ("x.rs".to_string(), "after".to_string()),
            ]
        );
    }
}
