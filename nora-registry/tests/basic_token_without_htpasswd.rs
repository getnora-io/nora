//! #1094: with auth enabled and no htpasswd file (the OIDC-only setup, #996), an API token sent
//! as the Basic password authenticates — Docker, twine and Maven send nothing else. The router
//! tests in `auth/mod.rs` build their own state; this runs the binary, so the wiring in `main.rs`
//! (a token store whenever auth is enabled, htpasswd or not) is covered as well.

use base64::{engine::general_purpose::STANDARD, Engine};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A running `nora serve`, stopped on drop.
struct Server {
    child: Child,
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `nora serve` with auth enabled, the token store and storage in `dir`, plus `env`.
fn serve(dir: &Path, env: &[(&str, &Path)]) -> Server {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut command = Command::new(env!("CARGO_BIN_EXE_nora"));
    command
        .arg("serve")
        .current_dir(dir)
        .env_remove("NORA_CONFIG_PATH")
        .env("NORA_HOST", "127.0.0.1")
        .env("NORA_PORT", port.to_string())
        .env("NORA_STORAGE_PATH", dir.join("data"))
        .env("NORA_AUTH_ENABLED", "true")
        .env("NORA_AUTH_TOKEN_STORAGE", dir.join("tokens"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, value) in env {
        command.env(key, value);
    }
    let mut server = Server {
        child: command.spawn().unwrap(),
        port,
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    while request(port, "GET", "/health", None, "").is_none() {
        assert!(
            server.child.try_wait().unwrap().is_none(),
            "nora serve exited"
        );
        assert!(Instant::now() < deadline, "nora serve did not come up");
        std::thread::sleep(Duration::from_millis(50));
    }
    server
}

/// One HTTP/1.1 request; the status code and body, `None` when the connection fails.
fn request(
    port: u16,
    method: &str,
    path: &str,
    authorization: Option<&str>,
    json: &str,
) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    if let Some(value) = authorization {
        head.push_str(&format!("Authorization: {value}\r\n"));
    }
    if !json.is_empty() {
        head.push_str("Content-Type: application/json\r\n");
    }
    head.push_str(&format!("Content-Length: {}\r\n\r\n{json}", json.len()));
    stream.write_all(head.as_bytes()).ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let status = response.split(' ').nth(1)?.parse().ok()?;
    let body = response.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    Some((status, body.to_string()))
}

fn basic(password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("ci:{password}")))
}

/// Mint an API token through `POST /api/tokens`, which checks the htpasswd user.
fn mint(port: u16, role: &str) -> String {
    let json =
        format!(r#"{{"username":"admin","password":"secret","ttl_days":1,"role":"{role}"}}"#);
    let (status, body) = request(port, "POST", "/api/tokens", None, &json).unwrap();
    assert_eq!(status, 200, "{body}");
    let token = serde_json::from_str::<serde_json::Value>(&body).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(token.starts_with("nra_"), "{body}");
    token
}

/// The API tokens work on a server without htpasswd: over Basic (as Docker, twine and Maven send
/// them) and over Bearer, with the read token gated to reads.
fn assert_tokens_work(port: u16, write: &str, read: &str) {
    let call = |method, path, authorization: String| {
        request(port, method, path, Some(&authorization), "").unwrap()
    };
    let status = |method, path, password: &str| call(method, path, basic(password)).0;

    // `docker login`: the /v2/ ping with the token as the Basic password.
    assert_eq!(status("GET", "/v2/", write), 200);
    assert_eq!(status("GET", "/v2/", read), 200);
    // `docker pull` starts with HEAD: a read, which the read token may do.
    assert_eq!(status("HEAD", "/v2/", read), 200);
    // A push starts with a blob upload: the write token may, the read token may not.
    assert_eq!(status("POST", "/v2/app/blobs/uploads/", write), 202);
    assert_eq!(status("POST", "/v2/app/blobs/uploads/", read), 403);
    // The same tokens over Bearer.
    assert_eq!(call("GET", "/v2/", format!("Bearer {write}")).0, 200);
    assert_eq!(call("GET", "/v2/", format!("Bearer {read}")).0, 200);
    // A wrong token is still refused — as a wrong credential, not as an unconfigured Basic.
    let (code, body) = call("GET", "/v2/", basic("nra_00000000000000000000000000000000"));
    assert_eq!(code, 401);
    assert!(body.contains("Invalid username or password"), "{body}");
}

#[test]
fn an_api_token_as_the_basic_password_works_without_htpasswd() {
    let dir = tempfile::tempdir().unwrap();
    let htpasswd = dir.path().join("htpasswd");
    let hash = bcrypt::hash("secret", 4).unwrap();
    std::fs::write(&htpasswd, format!("admin:{hash}\n")).unwrap();
    let oidc = dir.path().join("oidc.toml");
    std::fs::write(
        &oidc,
        "[auth.oidc]\nenabled = true\n[[auth.oidc.providers]]\nname = \"ci\"\n\
         issuer = \"https://issuer.invalid\"\naudience = \"nora\"\n",
    )
    .unwrap();

    // Tokens are minted while htpasswd exists; the store outlives it.
    let (write, read) = {
        let server = serve(dir.path(), &[("NORA_AUTH_HTPASSWD_FILE", &htpasswd)]);
        (mint(server.port, "write"), mint(server.port, "read"))
    };

    // OIDC-only (#996), the setup #1094 was reported on.
    let missing = dir.path().join("no-such-htpasswd");
    {
        let server = serve(
            dir.path(),
            &[
                ("NORA_AUTH_HTPASSWD_FILE", &missing),
                ("NORA_CONFIG_PATH", &oidc),
            ],
        );
        assert_tokens_work(server.port, &write, &read);
    }

    // Neither htpasswd nor OIDC: the token store is still created, so the tokens still work.
    let server = serve(dir.path(), &[("NORA_AUTH_HTPASSWD_FILE", &missing)]);
    assert_tokens_work(server.port, &write, &read);
}
