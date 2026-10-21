//! An enabled OIDC provider without an audience would accept a token its issuer minted for any
//! other service — on GitHub Actions, any repository on the host. The config tests in
//! `config/mod.rs` judge the validation; this runs the binary, so the exit code and what the
//! operator reads at start are covered as well.

use std::fs::File;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// `[auth.oidc]` with one provider `gh` carrying `keys`.
fn oidc_config(keys: &str) -> String {
    format!(
        "[auth]\nenabled = true\n[auth.oidc]\nenabled = true\n[[auth.oidc.providers]]\n\
         name = \"gh\"\nissuer = \"https://token.actions.githubusercontent.com\"\n{keys}\n\
         [[auth.oidc.providers.role_rules]]\npattern = \"repo:myorg/*\"\nrole = \"write\"\n"
    )
}

/// `nora serve` with `config` in `dir`; stdout and stderr go to `dir/out` and `dir/err`.
fn spawn(dir: &Path, config: &str) -> (Child, u16) {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let path = dir.join("config.toml");
    std::fs::write(&path, config).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_nora"))
        .arg("serve")
        .current_dir(dir)
        .env("NORA_CONFIG_PATH", &path)
        .env_remove("NORA_CONFIG_STRICT")
        .env_remove("NORA_AUTH_OIDC_ENABLED")
        .env("NORA_HOST", "127.0.0.1")
        .env("NORA_PORT", port.to_string())
        .env("NORA_STORAGE_PATH", dir.join("data"))
        .env("NORA_AUTH_TOKEN_STORAGE", dir.join("tokens"))
        .env("NORA_AUTH_HTPASSWD_FILE", dir.join("no-htpasswd"))
        .stdin(Stdio::null())
        .stdout(File::create(dir.join("out")).unwrap())
        .stderr(File::create(dir.join("err")).unwrap())
        .spawn()
        .unwrap();
    (child, port)
}

/// Waits for the process to exit, or for its port to accept a connection (`None`).
fn exit_or_listen(child: &mut Child, port: u16) -> Option<ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return None;
        }
        assert!(
            Instant::now() < deadline,
            "nora serve neither exited nor came up"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn output(dir: &Path) -> String {
    let out = std::fs::read_to_string(dir.join("out")).unwrap();
    let err = std::fs::read_to_string(dir.join("err")).unwrap();
    format!("{out}{err}")
}

#[test]
fn a_provider_without_audience_stops_the_start() {
    let dir = tempfile::tempdir().unwrap();
    let (mut child, port) = spawn(dir.path(), &oidc_config(""));
    let status = exit_or_listen(&mut child, port);
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let output = output(dir.path());
    // EX_CONFIG: the packaged units do not restart into a configuration error.
    assert_eq!(status.and_then(|s| s.code()), Some(78), "{output}");
    assert!(output.contains("\"gh\""), "{output}");
    assert!(output.contains("any_audience = true"), "{output}");
}

#[test]
fn any_audience_starts_and_warns() {
    let dir = tempfile::tempdir().unwrap();
    let (mut child, port) = spawn(dir.path(), &oidc_config("any_audience = true"));
    let status = exit_or_listen(&mut child, port);
    let _ = child.kill();
    let _ = child.wait();
    let output = output(dir.path());
    assert!(status.is_none(), "nora serve exited: {output}");
    let warning = output
        .lines()
        .find(|l| l.contains("WARN") && l.contains("any_audience"))
        .unwrap_or_else(|| panic!("no warning about any_audience: {output}"));
    assert!(warning.contains("gh"), "{warning}");
}

#[test]
fn an_audience_starts_without_a_warning_about_it() {
    let dir = tempfile::tempdir().unwrap();
    let (mut child, port) = spawn(dir.path(), &oidc_config("audience = \"nora\""));
    let status = exit_or_listen(&mut child, port);
    let _ = child.kill();
    let _ = child.wait();
    let output = output(dir.path());
    assert!(status.is_none(), "nora serve exited: {output}");
    assert!(
        !output
            .lines()
            .any(|l| l.contains("WARN") && l.contains("audience")),
        "{output}"
    );
}
