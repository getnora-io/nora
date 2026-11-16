//! A command writes the line it logged last to `NORA_LOG_FILE`, whether it ends the process on
//! an error or returns. The file writer hands each line to a background thread; ending the
//! process without waiting for that thread loses the lines it has not written yet, so the
//! error that made the command exit was missing from the file once in a few hundred runs.
//!
//! Here the log file is a FIFO whose buffer the test fills before the command starts: the
//! writer thread stays on its first line, and every later line waits in its queue until the
//! test reads the FIFO, a quarter of a second after the command logged its line. A process
//! that ends without waiting for the writer is gone by then and its line with it, every run;
//! one that waits writes the line once the test reads.
//!
//! The two parts below: [`exit_paths_write_their_last_line`] runs each kind of exit, and
//! [`every_exit_waits_for_the_log_file`] keeps every `process::exit` of the binary behind the
//! one function that waits for the writer first.

use std::path::{Path, PathBuf};

/// What a run of `nora` left behind.
#[cfg(target_os = "linux")]
struct Run {
    code: Option<i32>,
    /// What the process wrote to `NORA_LOG_FILE`.
    file: String,
    stdout: String,
}

/// Runs `nora args` in `dir` with `envs` and `NORA_LOG_FILE` on a FIFO the test holds full,
/// until the process exits. `line` is the line the command logs last: once stdout has it, the
/// test waits a quarter of a second and reads the FIFO.
#[cfg(target_os = "linux")]
fn run_with_held_log_file(dir: &Path, args: &[&str], envs: &[(&str, &str)], line: &str) -> Run {
    use std::io::{ErrorKind, Read, Write};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let fifo = dir.join("nora-file.log");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
    )
    .unwrap();
    // Read and write end in one descriptor: the open does not wait for a peer, and a read
    // never reports end of file while the test holds it.
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
        loop {
            match pipe.write(&filler) {
                Ok(n) => filled += n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => panic!("filling the FIFO: {e}"),
            }
        }
    }
    assert!(filled > 0, "the FIFO took no filler");

    let stdout = dir.join("stdout.log");
    let mut child = Command::new(env!("CARGO_BIN_EXE_nora"))
        .args(args)
        .current_dir(dir)
        .env_remove("NORA_CONFIG_PATH")
        .env("NORA_STORAGE_PATH", dir.join("data"))
        .env("NORA_LOG_FILE", "nora-file.log")
        .envs(envs.iter().copied())
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&stdout).unwrap())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let read_stdout = || std::fs::read_to_string(&stdout).unwrap_or_default();

    // stdout is written before the process can exit, so once it has the line, or the process
    // is gone, the line has been logged.
    let deadline = Instant::now() + Duration::from_secs(60);
    while !read_stdout().contains(line)
        && child.try_wait().unwrap().is_none()
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    // A process that does not wait for the writer has exited by now; one that waits is held
    // until the FIFO is read (the writer is given about a second).
    std::thread::sleep(Duration::from_millis(250));

    let mut written = Vec::new();
    let mut buf = vec![0; 1 << 16];
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        let exited = child.try_wait().unwrap();
        loop {
            match pipe.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => written.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => panic!("reading the FIFO: {e}"),
            }
        }
        if let Some(status) = exited {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("nora {args:?} did not exit");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(written.len() >= filled, "the FIFO lost its filler");
    Run {
        code: status.code(),
        file: String::from_utf8_lossy(&written[filled..]).into_owned(),
        stdout: read_stdout(),
    }
}

/// A port nothing listens on.
#[cfg(target_os = "linux")]
fn closed_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Each kind of exit: an error in a command (`mirror`, `re-pin` with its own exit code), a
/// configuration `serve` cannot start with (78), and a command that succeeds and returns. The
/// exit code is the one each path had, and the file has the line logged last.
#[cfg(target_os = "linux")]
#[test]
fn exit_paths_write_their_last_line() {
    let port = closed_port().to_string();
    let registry = format!("http://127.0.0.1:{port}");
    let mut wrong = Vec::new();
    let mut check = |name: &str, run: Run, line: &str, code: i32| {
        if !run.stdout.contains(line) {
            wrong.push(format!("{name}: stdout has no {line:?}: {}", run.stdout));
        }
        if run.code != Some(code) {
            wrong.push(format!("{name}: exited with {:?}, not {code}", run.code));
        }
        if !run.file.contains(line) {
            wrong.push(format!(
                "{name}: NORA_LOG_FILE has no {line:?}, logged before exit {:?}: {:?}",
                run.code, run.file
            ));
        }
    };

    let dir = tempfile::tempdir().unwrap();
    let args = [
        "mirror",
        "--registry",
        &registry,
        "npm",
        "--packages",
        "left-pad",
    ];
    let run = run_with_held_log_file(dir.path(), &args, &[], "Mirror failed");
    check("mirror", run, "Mirror failed", 1);

    let dir = tempfile::tempdir().unwrap();
    let line = "--expected must be a 64-character hex SHA-256";
    let args = ["re-pin", "raw/a.bin", "--expected", "zz"];
    let run = run_with_held_log_file(dir.path(), &args, &[], line);
    check("re-pin", run, line, 2);

    let dir = tempfile::tempdir().unwrap();
    let blocklist = dir.path().join("blocklist.json");
    std::fs::write(
        &blocklist,
        r#"{"version": 1, "rules": [{"registry": "pyip", "name": "six", "version": "*", "reason": "r"}]}"#,
    )
    .unwrap();
    let envs = [
        ("NORA_HOST", "127.0.0.1"),
        ("NORA_PORT", port.as_str()),
        ("NORA_CURATION_MODE", "enforce"),
        ("NORA_CURATION_BLOCKLIST_PATH", blocklist.to_str().unwrap()),
    ];
    let line = "Cannot start in enforce mode";
    let run = run_with_held_log_file(dir.path(), &["serve"], &envs, line);
    check("serve", run, line, 78);

    // Success: the warning is the last line, then `main` returns.
    let dir = tempfile::tempdir().unwrap();
    let artifact = dir.path().join("data/raw/a.bin");
    std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
    std::fs::write(&artifact, "hello").unwrap();
    let sha = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    let args = ["re-pin", "raw/a.bin", "--expected", sha, "--yes"];
    let line = "INTEGRITY RE-PIN";
    let run = run_with_held_log_file(dir.path(), &args, &[], line);
    check("re-pin --yes", run, line, 0);

    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// A server stops in bounded time while its log file takes no writes, with tasks logging
/// through the stop: a FIFO nobody reads, SIGHUP after SIGHUP (each reload logs) around the
/// SIGTERM. A task stuck writing to the file is a runtime that never finishes shutting down.
#[cfg(target_os = "linux")]
#[test]
fn a_server_stops_while_its_log_file_takes_no_writes() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("nora-file.log");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
    )
    .unwrap();
    // The read end, held and never read, and the FIFO filled through it: it takes no writes.
    let mut pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fifo)
        .unwrap();
    let flags = rustix::fs::fcntl_getfl(&pipe).unwrap();
    rustix::fs::fcntl_setfl(&pipe, flags | rustix::fs::OFlags::NONBLOCK).unwrap();
    for chunk in [4096, 1] {
        let filler = vec![b'#'; chunk];
        while std::io::Write::write(&mut pipe, &filler).is_ok() {}
    }
    let stdout = dir.path().join("stdout.log");
    let port = closed_port().to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nora"))
        .arg("serve")
        .current_dir(dir.path())
        .env_remove("NORA_CONFIG_PATH")
        .env("NORA_STORAGE_PATH", dir.path().join("data"))
        .env("NORA_HOST", "127.0.0.1")
        .env("NORA_PORT", &port)
        .env("NORA_LOG_FILE", &fifo)
        .env("RUST_LOG", "debug")
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&stdout).unwrap())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id().to_string();
    let signal = |name: &str| {
        let _ = Command::new("kill")
            .arg(format!("-{name}"))
            .arg(&pid)
            .status();
    };
    let mut wait_for = |line: &str| {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !std::fs::read_to_string(&stdout)
            .unwrap_or_default()
            .contains(line)
        {
            assert!(
                Instant::now() < deadline,
                "the server never logged {line:?}"
            );
            assert!(
                child.try_wait().unwrap().is_none(),
                "the server exited before logging {line:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    // The SIGHUP handler is installed by a task started after "Nora started": one reload answered
    // shows it is in place, so no SIGHUP below meets the default action and ends the process.
    wait_for("Connection limits");
    std::thread::sleep(Duration::from_millis(500));
    signal("HUP");
    wait_for("Curation policy reloaded successfully");
    for _ in 0..10 {
        signal("HUP");
        std::thread::sleep(Duration::from_millis(20));
    }
    signal("TERM");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        signal("HUP");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        status.is_some(),
        "the server did not stop within 30 s of SIGTERM while its log file took no writes"
    );
}

/// A panic still writes the lines logged before it: `serve` on a port another socket holds
/// panics at the bind ("Failed to bind", 101), after its startup lines.
#[cfg(target_os = "linux")]
#[test]
fn a_panic_still_writes_the_lines_logged_before_it() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port().to_string();
    let dir = tempfile::tempdir().unwrap();
    let line = "cargo name records checked";
    let envs = [("NORA_HOST", "127.0.0.1"), ("NORA_PORT", port.as_str())];
    let run = run_with_held_log_file(dir.path(), &["serve"], &envs, line);
    assert!(
        run.stdout.contains(line),
        "stdout has no {line:?}: {}",
        run.stdout
    );
    assert_eq!(run.code, Some(101), "not the panic at the bind");
    assert!(
        run.file.contains(line),
        "NORA_LOG_FILE has no {line:?}, logged before the panic: {:?}",
        run.file
    );
    drop(taken);
}

/// The one function the binary ends the process through.
const EXIT_FN: &str = "exit_after_logs";

fn is_test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("cfg")
            && a.parse_args::<syn::Meta>()
                .map(|m| m.path().is_ident("test"))
                .unwrap_or(false)
    })
}

/// Every reach of `std::process::exit` outside test code, with the function it is in: a path
/// naming it (called or passed as a value), through `std::process`, an alias of that module, or
/// a `use` of `exit` itself (renamed or by glob).
#[derive(Default)]
struct ExitReaches {
    file: PathBuf,
    /// Names `std::process` goes by in the file: `process`, and every `use std::process as x`.
    process_aliases: Vec<String>,
    fns: Vec<String>,
    found: Vec<(String, String)>,
}

/// `prefix::ident` as a `use` names it: `self` is the prefix itself.
fn joined(prefix: &[String], ident: &syn::Ident) -> Vec<String> {
    let mut full = prefix.to_vec();
    if ident != "self" {
        full.push(ident.to_string());
    }
    full
}

/// Whether a macro's tokens name `process::exit` (or `<alias>::exit`): syn does not parse the
/// body of a macro call, so an exit inside `tokio::select!` is found here, in the tokens as
/// they print (`std :: process :: exit (1)`).
fn tokens_name_exit(tokens: &str, aliases: &[String]) -> bool {
    let tokens: Vec<&str> = tokens.split_whitespace().collect();
    tokens.windows(3).any(|w| {
        (w[0] == "process" || aliases.iter().any(|a| a == w[0])) && w[1] == "::" && w[2] == "exit"
    })
}

impl ExitReaches {
    fn record(&mut self, what: String) {
        let at = self.fns.last().cloned().unwrap_or_default();
        self.found
            .push((at, format!("{}: {what}", self.file.display())));
    }

    /// `use` trees under `prefix`: an alias of `std::process`, or `exit` taken from it.
    fn use_tree(&mut self, tree: &syn::UseTree, prefix: &mut Vec<String>) {
        let is_process = |p: &[String]| p.len() >= 2 && p[p.len() - 2..] == ["std", "process"];
        match tree {
            syn::UseTree::Path(p) => {
                prefix.push(p.ident.to_string());
                self.use_tree(&p.tree, prefix);
                prefix.pop();
            }
            syn::UseTree::Name(n) => {
                let full = joined(prefix, &n.ident);
                if is_process(&full) {
                    self.process_aliases.push("process".into());
                } else if is_process(prefix) && n.ident == "exit" {
                    self.record(format!("use {}", full.join("::")));
                }
            }
            syn::UseTree::Rename(r) => {
                let full = joined(prefix, &r.ident);
                if is_process(&full) {
                    self.process_aliases.push(r.rename.to_string());
                } else if is_process(prefix) && r.ident == "exit" {
                    self.record(format!("use {} as {}", full.join("::"), r.rename));
                }
            }
            syn::UseTree::Glob(_) => {
                if is_process(prefix) {
                    self.record(format!("use {}::*", prefix.join("::")));
                }
            }
            syn::UseTree::Group(g) => {
                for t in &g.items {
                    self.use_tree(t, prefix);
                }
            }
        }
    }
}

impl<'ast> syn::visit::Visit<'ast> for ExitReaches {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if is_test_only(&f.attrs) {
            return;
        }
        self.fns.push(f.sig.ident.to_string());
        syn::visit::visit_item_fn(self, f);
        self.fns.pop();
    }
    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        if is_test_only(&f.attrs) {
            return;
        }
        self.fns.push(f.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, f);
        self.fns.pop();
    }
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        if !is_test_only(&m.attrs) {
            syn::visit::visit_item_mod(self, m);
        }
    }
    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        if !is_test_only(&i.attrs) {
            syn::visit::visit_item_impl(self, i);
        }
    }
    fn visit_stmt(&mut self, s: &'ast syn::Stmt) {
        let attrs = match s {
            syn::Stmt::Local(l) => &l.attrs,
            syn::Stmt::Expr(syn::Expr::Return(r), _) => &r.attrs,
            syn::Stmt::Expr(syn::Expr::Call(c), _) => &c.attrs,
            syn::Stmt::Macro(m) => &m.attrs,
            _ => return syn::visit::visit_stmt(self, s),
        };
        if !is_test_only(attrs) {
            syn::visit::visit_stmt(self, s);
        }
    }
    fn visit_item_use(&mut self, u: &'ast syn::ItemUse) {
        if !is_test_only(&u.attrs) {
            self.use_tree(&u.tree, &mut Vec::new());
        }
    }
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        if tokens_name_exit(&m.tokens.to_string(), &self.process_aliases) {
            let name: Vec<String> = m
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            self.record(format!("process::exit inside {}!", name.join("::")));
        }
        syn::visit::visit_macro(self, m);
    }
    fn visit_path(&mut self, p: &'ast syn::Path) {
        let names: Vec<String> = p.segments.iter().map(|s| s.ident.to_string()).collect();
        if let [.., module, last] = names.as_slice() {
            if last == "exit"
                && (module == "process" || self.process_aliases.iter().any(|a| a == module))
            {
                self.record(names.join("::"));
            }
        }
        syn::visit::visit_path(self, p);
    }
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every `process::exit` of the binary outside its tests is the one in [`EXIT_FN`], which waits
/// for the log file writer first: an exit added anywhere else, or reached through an alias, a
/// renamed `use` or a glob, is named here. The one in `EXIT_FN` must be found, or the walk saw
/// nothing.
#[test]
fn every_exit_waits_for_the_log_file() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files.sort();
    let mut found = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        let ast = syn::parse_file(&text).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        let mut reaches = ExitReaches {
            file: file.strip_prefix(&src).unwrap().to_path_buf(),
            ..Default::default()
        };
        // Aliases first: a `use` may follow the code that relies on it.
        for item in &ast.items {
            if let syn::Item::Use(u) = item {
                syn::visit::Visit::visit_item_use(&mut reaches, u);
            }
        }
        reaches.found.clear();
        syn::visit::Visit::visit_file(&mut reaches, &ast);
        found.extend(reaches.found);
    }
    let (inside, outside): (Vec<_>, Vec<_>) = found.into_iter().partition(|(f, _)| f == EXIT_FN);
    let outside: Vec<String> = outside
        .into_iter()
        .map(|(f, at)| format!("{at} (in fn {f})"))
        .collect();
    assert!(
        outside.is_empty(),
        "process::exit outside {EXIT_FN}, the exit that waits for NORA_LOG_FILE: {outside:#?}"
    );
    assert_eq!(
        inside.len(),
        1,
        "expected the one process::exit in {EXIT_FN}: {inside:?}"
    );
}
