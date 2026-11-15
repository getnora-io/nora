//! `nora serve` run as a process, for the tests that need the real binary: its exit code, its
//! log, and the signals a service manager sends it.
//!
//! The port is chosen by binding port 0 and letting it go, so another process can take it before
//! NORA binds. A port answering a connection therefore says nothing about NORA: the process is
//! serving when its own log says it bound ("Nora started"), and a start that lost the port to
//! another process is retried on a fresh one.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How long a start, a reload or a request may take before a test gives up on it.
pub const DEADLINE: Duration = Duration::from_secs(30);

/// What NORA logs once its listener is bound.
const STARTED: &str = "Nora started";

/// What the process says when the port was taken between the test choosing it and NORA binding.
const PORT_TAKEN: [&str; 2] = ["Failed to bind", "AddrInUse"];

/// A running `nora serve`.
pub struct Nora {
    child: Child,
    pub port: u16,
    stdout: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
    readers: Vec<JoinHandle<()>>,
}

/// How a start ended.
pub enum Started {
    /// The process logged that it bound its port.
    Serving(Nora),
    /// The process exited: its code (`None` when a signal ended it) and its stderr.
    Exited(Option<i32>, String),
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn collect(from: impl Read + Send + 'static, into: Arc<Mutex<String>>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        for line in BufReader::new(from).lines() {
            let Ok(line) = line else { break };
            let mut text = into.lock().unwrap();
            text.push_str(&line);
            text.push('\n');
        }
    })
}

/// `nora serve` in `dir` with the settings in `envs`, until it either logs that it bound its
/// port or exits. `NORA_HOST` and `NORA_PORT` are set here, `NORA_CONFIG_PATH` only by `envs`.
/// A start that lost its port to another process is retried on a fresh one.
pub fn start(dir: &std::path::Path, envs: &[(&str, &str)]) -> Started {
    for _ in 0..5 {
        match start_on(dir, envs, free_port()) {
            Started::Exited(_, stderr) if PORT_TAKEN.iter().all(|says| stderr.contains(says)) => {
                continue
            }
            started => return started,
        }
    }
    panic!("five ports in a row were taken before nora bound them");
}

/// [`start`] on `port`, once.
pub fn start_on(dir: &std::path::Path, envs: &[(&str, &str)], port: u16) -> Started {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nora"));
    command
        .arg("serve")
        .current_dir(dir)
        .env_remove("NORA_CONFIG_PATH")
        .env("NORA_HOST", "127.0.0.1")
        .env("NORA_PORT", port.to_string());
    for (key, value) in envs {
        command.env(key, value);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (stdout, stderr) = (Arc::default(), Arc::default());
    let readers = vec![
        collect(child.stdout.take().unwrap(), Arc::clone(&stdout)),
        collect(child.stderr.take().unwrap(), Arc::clone(&stderr)),
    ];
    let mut nora = Nora {
        child,
        port,
        stdout,
        stderr,
        readers,
    };
    match nora.until(|log| log.contains(STARTED)) {
        Some(_) => Started::Serving(nora),
        None => {
            let (code, stderr) = nora.exited();
            Started::Exited(code, stderr)
        }
    }
}

impl Nora {
    /// Waits until `holds` is true of the log (stdout and stderr), or the process exits:
    /// `Some` with the log in the first case, `None` in the second. Panics past [`DEADLINE`].
    pub fn until(&mut self, holds: impl Fn(&str) -> bool) -> Option<String> {
        let deadline = Instant::now() + DEADLINE;
        loop {
            let log = self.log();
            if holds(&log) {
                return Some(log);
            }
            if self.child.try_wait().unwrap().is_some() {
                // What the process wrote last is still in the pipes until the readers end.
                return holds(&self.drained()).then(|| self.log());
            }
            assert!(
                Instant::now() < deadline,
                "nora: nothing after {DEADLINE:?}:\n{log}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Everything the process wrote so far, stdout then stderr.
    pub fn log(&self) -> String {
        format!(
            "{}{}",
            self.stdout.lock().unwrap(),
            self.stderr.lock().unwrap()
        )
    }

    /// Sends `signal` (a name `kill` takes, such as `HUP`) to the process.
    pub fn signal(&self, signal: &str) {
        let sent = Command::new("kill")
            .arg(format!("-{signal}"))
            .arg(self.child.id().to_string())
            .status()
            .unwrap();
        assert!(sent.success(), "kill -{signal} failed");
    }

    /// The URL of `path` on this server.
    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn drained(&mut self) -> String {
        for reader in self.readers.drain(..) {
            reader.join().unwrap();
        }
        self.log()
    }

    /// The exit code and stderr of a process that has exited.
    fn exited(&mut self) -> (Option<i32>, String) {
        let status: ExitStatus = self.child.wait().unwrap();
        self.drained();
        (status.code(), self.stderr.lock().unwrap().clone())
    }
}

impl Drop for Nora {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
