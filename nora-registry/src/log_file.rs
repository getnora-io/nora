// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! `NORA_LOG_FILE`: a thread writes the log lines to the file, so no request waits on the disk,
//! and the process ends with the lines it logged in the file.
//!
//! A line goes to a bounded queue, and is dropped when the queue is full: a file that falls
//! [`QUEUE_LINES`] lines behind does not stall the server. No thread that logs ever writes to the
//! file itself, so a file that takes no writes (a full pipe, a disk that does not answer) holds up
//! no request, no task and no shutdown. Before the process ends ([`LogFile::exit_after_logs`]),
//! when `main` returns, and when it unwinds from a panic ([`LogFile::drain_on_drop`]), the queue is
//! given [`DRAIN_WAIT`] to reach the file, lines logged meanwhile included. Nothing waits longer,
//! and nothing is printed on the way out.

use std::fs::File;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Lines the queue holds before a new one is dropped (tracing-appender's default, used before).
const QUEUE_LINES: usize = 128_000;

/// How long an ending process waits for the queue to reach the file.
const DRAIN_WAIT: Duration = Duration::from_secs(1);

/// `NORA_LOG_FILE`, or no file. Cloned to whatever may end the process: every clone drains the
/// same queue.
#[derive(Clone, Default)]
pub(crate) struct LogFile(Option<FileLines>);

/// The writer of `NORA_LOG_FILE` the log layer writes through.
#[derive(Clone)]
pub(crate) struct FileLines(Arc<Lines>);

struct Lines {
    queue: SyncSender<Vec<u8>>,
    shared: Arc<Shared>,
}

/// What the writing thread and the threads that log share.
struct Shared {
    file: File,
    /// Lines handed to the queue and not dropped: counted before they go in, so a drain counts
    /// every line it must wait for. A line no thread can write stays counted.
    queued: AtomicU64,
    /// Lines the writing thread has written, counted once its write has returned.
    written: AtomicU64,
}

impl LogFile {
    /// `file`, written by a thread through a queue of [`QUEUE_LINES`] lines. No file at all when
    /// the thread cannot be started: no thread that logs is left to write it.
    pub(crate) fn new(file: File) -> Self {
        Self::with_queue(file, QUEUE_LINES)
    }

    fn with_queue(file: File, queue_lines: usize) -> Self {
        let (queue, lines) = sync_channel(queue_lines);
        let shared = Arc::new(Shared {
            file,
            queued: AtomicU64::new(0),
            written: AtomicU64::new(0),
        });
        let worker = Arc::clone(&shared);
        let spawned = std::thread::Builder::new()
            .name("nora-log-file".to_string())
            .spawn(move || write_queue(&worker, lines));
        if let Err(e) = spawned {
            eprintln!("WARNING: NORA_LOG_FILE is not written: its thread did not start: {e}");
            return Self::default();
        }
        Self(Some(FileLines(Arc::new(Lines { queue, shared }))))
    }

    /// A file whose queue no thread writes, as when the writing thread is stuck on the disk: the
    /// receiving end is returned, so the queue stays open until the test drops it.
    #[cfg(test)]
    fn with_stuck_thread(file: File) -> (Self, Receiver<Vec<u8>>) {
        let (queue, lines) = sync_channel(QUEUE_LINES);
        let shared = Arc::new(Shared {
            file,
            queued: AtomicU64::new(0),
            written: AtomicU64::new(0),
        });
        (
            Self(Some(FileLines(Arc::new(Lines { queue, shared })))),
            lines,
        )
    }

    /// The writer for the log layer, when there is a file.
    pub(crate) fn lines(&self) -> Option<FileLines> {
        self.0.clone()
    }

    /// Waits up to [`DRAIN_WAIT`] for every line logged so far, and every line logged meanwhile,
    /// to be written. Returns whether they were. Blocks the calling thread, never a thread that
    /// logs: called once the process is ending.
    pub(crate) fn drain(&self) -> bool {
        self.0
            .as_ref()
            .is_none_or(|lines| lines.0.shared.drain(DRAIN_WAIT))
    }

    /// Drains the file when dropped: held by `main`, so a return and the unwinding of a panic
    /// both drain it.
    pub(crate) fn drain_on_drop(&self) -> DrainOnDrop {
        DrainOnDrop(self.clone())
    }

    /// Ends the process with `code` once the lines logged so far are in `NORA_LOG_FILE` (or
    /// [`DRAIN_WAIT`] has passed): `std::process::exit` alone stops the writing thread with the last
    /// lines, the error the process ends on among them, still queued. Every exit of the binary
    /// goes through here.
    pub(crate) fn exit_after_logs(&self, code: i32) -> ! {
        self.drain();
        std::process::exit(code)
    }

    /// The exit hook of a task the process cannot run without ([`crate::supervise::blocking`]):
    /// it ends the process from that task's own thread, whatever the main task is doing.
    pub(crate) fn exit_hook(&self) -> crate::supervise::ExitHook {
        let log_file = self.clone();
        Arc::new(move |code| log_file.exit_after_logs(code))
    }
}

/// [`LogFile::drain_on_drop`].
#[must_use = "dropped at once, it drains the file before anything is logged"]
pub(crate) struct DrainOnDrop(LogFile);

impl Drop for DrainOnDrop {
    fn drop(&mut self) {
        self.0.drain();
    }
}

impl Shared {
    fn drain(&self, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        loop {
            if self.written.load(SeqCst) >= self.queued.load(SeqCst) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// The writing thread: each line in order, for as long as the queue is open. A failed or
/// panicking write is not retried, as before: the line counts as handled and the thread goes on.
fn write_queue(shared: &Shared, lines: Receiver<Vec<u8>>) {
    for line in lines.iter() {
        let write = std::panic::AssertUnwindSafe(|| (&shared.file).write_all(&line));
        let _ = std::panic::catch_unwind(write);
        shared.written.fetch_add(1, SeqCst);
    }
}

/// One log event's writer: hands the line to the queue and returns.
pub(crate) struct LineWriter<'a>(&'a Lines);

impl Write for LineWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let lines = self.0;
        let shared = &lines.shared;
        shared.queued.fetch_add(1, SeqCst);
        match lines.queue.try_send(buf.to_vec()) {
            Ok(()) => {}
            // Dropped, as before: the file is a queue full behind.
            Err(TrySendError::Full(_)) => {
                shared.queued.fetch_sub(1, SeqCst);
            }
            // No thread will write it: it stays counted, so no drain reports it written.
            Err(TrySendError::Disconnected(_)) => {}
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for FileLines {
    type Writer = LineWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        LineWriter(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tracing_subscriber::fmt::MakeWriter;

    fn log(lines: &FileLines, line: &str) {
        lines.make_writer().write_all(line.as_bytes()).unwrap();
    }

    /// Lines reach the file in the order logged, through the thread, and a drain waits for them.
    #[test]
    fn lines_reach_the_file_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nora.log");
        let log_file = LogFile::new(File::create(&path).unwrap());
        let lines = log_file.lines().unwrap();
        for i in 0..1000 {
            log(&lines, &format!("line {i}\n"));
        }
        assert!(log_file.drain());
        let text = std::fs::read_to_string(&path).unwrap();
        let want: String = (0..1000).map(|i| format!("line {i}\n")).collect();
        assert_eq!(text, want);
        log(&lines, "after\n");
        assert!(log_file.drain());
        assert!(
            std::fs::read_to_string(&path).unwrap().ends_with("after\n"),
            "a line after a drain still reaches the file"
        );
    }

    /// Threads logging while the file drains lose no line: each is counted before it is queued, so
    /// the drain waits for it, or it goes after the drain through the same thread.
    #[test]
    fn no_line_is_lost_to_a_drain_racing_the_threads_that_log() {
        for round in 0..20 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("nora.log");
            let log_file = LogFile::new(File::create(&path).unwrap());
            let threads: Vec<_> = (0..4)
                .map(|t| {
                    let lines = log_file.lines().unwrap();
                    std::thread::spawn(move || {
                        for i in 0..500 {
                            log(&lines, &format!("{t}:{i}\n"));
                        }
                    })
                })
                .collect();
            std::thread::sleep(Duration::from_micros(200 * round));
            let drained = log_file.drain();
            for t in threads {
                t.join().unwrap();
            }
            assert!(drained, "round {round}: the queue did not reach the file");
            // Lines logged after the drain returned go through the thread too.
            assert!(
                log_file.drain(),
                "round {round}: the rest did not reach the file"
            );
            let text = std::fs::read_to_string(&path).unwrap();
            for t in 0..4 {
                for i in 0..500 {
                    assert!(
                        text.contains(&format!("{t}:{i}\n")),
                        "round {round}: {t}:{i} lost"
                    );
                }
            }
        }
    }

    /// A full queue drops the line rather than block the thread that logs it.
    #[test]
    fn a_full_queue_drops_rather_than_blocks() {
        // The FIFO stays full, its read end held, until the test ends.
        let (_dir, _pipe, _filled, fifo) = full_fifo();
        let log_file = LogFile::with_queue(fifo_writer(&fifo), 1);
        let lines = log_file.lines().unwrap();
        let start = Instant::now();
        for i in 0..100 {
            log(&lines, &format!("line {i}\n"));
        }
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "a full queue blocked"
        );
    }

    /// A line logged while an ending process drains the queue reaches the file: the drain waits for
    /// lines logged meanwhile too.
    #[test]
    fn a_line_logged_while_the_file_drains_is_written() {
        let (_dir, mut pipe, filled, fifo) = full_fifo();
        let log_file = LogFile::new(fifo_writer(&fifo));
        let lines = log_file.lines().unwrap();
        log(&lines, "before\n");
        let ending = log_file.clone();
        let drain = std::thread::spawn(move || ending.drain());
        std::thread::sleep(Duration::from_millis(50));
        let during = std::thread::spawn(move || log(&lines, "during\n"));
        std::thread::sleep(Duration::from_millis(250));
        let text = read_until(&mut pipe, filled, &["before\n", "during\n"]);
        assert!(
            drain.join().unwrap(),
            "the drain did not finish once the file took writes"
        );
        during.join().unwrap();
        assert!(text.contains("before\n"), "{text:?}");
        assert!(
            text.contains("during\n"),
            "the line logged during the drain is lost: {text:?}"
        );
    }

    /// On a file that takes no writes, a drain gives up after about [`DRAIN_WAIT`], and says so.
    #[test]
    fn a_drain_on_a_file_that_takes_no_writes_is_bounded() {
        let (_dir, _pipe, _filled, fifo) = full_fifo();
        let log_file = LogFile::new(fifo_writer(&fifo));
        log(&log_file.lines().unwrap(), "stuck\n");
        let start = Instant::now();
        assert!(!log_file.drain());
        let took = start.elapsed();
        assert!(took >= DRAIN_WAIT, "returned before the wait: {took:?}");
        assert!(took < DRAIN_WAIT * 3, "waited past the bound: {took:?}");
    }

    /// A line handed to a stuck writing thread is not reported as written, and a line after the
    /// drain is not written by the thread that logs it either: the file is the writing thread's
    /// alone.
    #[test]
    fn a_stuck_thread_leaves_the_lines_unwritten_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nora.log");
        let (log_file, _queue) = LogFile::with_stuck_thread(File::create(&path).unwrap());
        let lines = log_file.lines().unwrap();
        log(&lines, "queued\n");
        assert!(!log_file.drain(), "a stuck queue counts as drained");
        log(&lines, "after\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
    }

    /// A file that takes no writes never holds up a thread that logs: not while the file drains,
    /// not after. A thread stuck in a write is a runtime that cannot shut down.
    #[test]
    fn no_log_call_waits_on_a_file_that_takes_no_writes() {
        let (_dir, _pipe, _filled, fifo) = full_fifo();
        let log_file = LogFile::new(fifo_writer(&fifo));
        let lines = log_file.lines().unwrap();
        log(&lines, "first\n");
        let ending = log_file.clone();
        let drain = std::thread::spawn(move || ending.drain());
        std::thread::sleep(Duration::from_millis(50));
        let loggers: Vec<_> = (0..8)
            .map(|t| {
                let lines = lines.clone();
                std::thread::spawn(move || {
                    for i in 0..10 {
                        log(&lines, &format!("{t}:{i}\n"));
                    }
                })
            })
            .collect();
        let deadline = Instant::now() + Duration::from_secs(3);
        while loggers.iter().any(|l| !l.is_finished()) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let stuck = loggers.iter().filter(|l| !l.is_finished()).count();
        assert_eq!(stuck, 0, "{stuck} of 8 threads are stuck in a log call");
        assert!(
            !drain.join().unwrap(),
            "a file that takes no writes counts as drained"
        );
        log(&lines, "after\n");
    }

    /// A drain that reports success has every line logged before it in the file: a write that has
    /// started and not finished, or a line no thread can write, is not counted as written. Checked
    /// the moment the drain returns, nothing read from the file yet, as an exit would see it.
    #[test]
    fn a_drain_reports_success_only_with_every_line_in_the_file() {
        let (_dir, mut pipe, filled, fifo) = full_fifo();
        let (log_file, queue) = LogFile::with_stuck_thread(fifo_writer(&fifo));
        drop(queue);
        let lines = log_file.lines().unwrap();
        let logger = std::thread::spawn(move || log(&lines, "late\n"));
        std::thread::sleep(Duration::from_millis(50));
        let drained = log_file.drain();
        let finished = logger.is_finished();
        assert!(
            !drained || finished,
            "the drain reported success while the line was still being written"
        );
        if drained {
            let text = read_until(&mut pipe, filled, &["late\n"]);
            assert!(
                text.contains("late\n"),
                "the drain reported success, the line is not in the file: {text:?}"
            );
        }
    }

    /// No file: draining is done at once.
    #[test]
    fn no_file_drains_at_once() {
        assert!(LogFile::default().drain());
        assert!(LogFile::default().lines().is_none());
    }

    /// A FIFO the test holds full, so a writer to it waits until the test reads: its directory, the
    /// test's read end, the filler bytes in front, and its path.
    fn full_fifo() -> (tempfile::TempDir, File, usize, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("nora.log");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .unwrap();
        let mut pipe = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo)
            .unwrap();
        let flags = rustix::fs::fcntl_getfl(&pipe).unwrap();
        rustix::fs::fcntl_setfl(&pipe, flags | rustix::fs::OFlags::NONBLOCK).unwrap();
        let mut filled = 0;
        for chunk in [4096, 1] {
            let filler = vec![b'#'; chunk];
            while let Ok(n) = pipe.write(&filler) {
                filled += n;
            }
        }
        (dir, pipe, filled, fifo)
    }

    fn fifo_writer(fifo: &std::path::Path) -> File {
        std::fs::OpenOptions::new().append(true).open(fifo).unwrap()
    }

    /// Reads the FIFO until it holds every one of `want` after the filler, or 5 s pass.
    fn read_until(pipe: &mut File, filled: usize, want: &[&str]) -> String {
        let mut out = Vec::new();
        let mut buf = vec![0; 1 << 16];
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(n) = pipe.read(&mut buf) {
                out.extend_from_slice(&buf[..n]);
            }
            let text = String::from_utf8_lossy(&out[filled.min(out.len())..]).into_owned();
            if want.iter().all(|w| text.contains(w)) || Instant::now() > deadline {
                return text;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
