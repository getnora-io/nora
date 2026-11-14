// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! The Docker token service (#1226) of the server as it ships. The router tests in
//! `auth/docker_token.rs` build their own state; this runs `nora serve`, so the wiring in
//! `main.rs` is covered too: under `docker_anon_pull` the server has the token key, the ping
//! sends a client to the token service, a revoked API token ends the Docker token issued on
//! it, and a token request body is read only up to its own small limit.

mod common;

use base64::{engine::general_purpose::STANDARD, Engine};
use std::io::{Read, Write};
use std::net::TcpStream;

/// One HTTP/1.1 request: the status, the headers and the body of the answer.
fn request(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, String, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(common::DEADLINE)).unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    stream.write_all(head.as_bytes()).unwrap();
    // A server refusing the body may answer and close before it is all sent.
    let _ = stream.write_all(body);
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer);
    let answer = String::from_utf8_lossy(&answer).into_owned();
    let (head, body) = answer.split_once("\r\n\r\n").unwrap_or((&answer, ""));
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, head.to_string(), body.to_string())
}

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"))
}

/// A Docker token from the token service for these headers.
fn docker_token(port: u16, headers: &[(&str, &str)]) -> String {
    let (status, _, body) = request(port, "GET", "/api/docker/token", headers, b"");
    assert_eq!(status, 200, "{body}");
    let token = json(&body)["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("nrd_"), "{body}");
    token
}

/// The status of a blob upload start, the first write of a push, with this Docker token.
fn upload(port: u16, token: &str) -> u16 {
    let bearer = format!("Bearer {token}");
    let headers = [("Authorization", bearer.as_str())];
    request(port, "POST", "/v2/app/blobs/uploads/", &headers, b"").0
}

#[test]
fn the_shipped_server_runs_the_docker_token_service() {
    let dir = tempfile::tempdir().unwrap();
    let htpasswd = dir.path().join("htpasswd");
    let hash = bcrypt::hash("secret", 4).unwrap();
    std::fs::write(&htpasswd, format!("admin:{hash}\n")).unwrap();
    let path = |p: &std::path::Path| p.to_str().unwrap().to_string();
    let envs = [
        ("NORA_STORAGE_PATH", path(&dir.path().join("data"))),
        ("NORA_AUTH_ENABLED", "true".into()),
        ("NORA_AUTH_DOCKER_ANON_PULL", "true".into()),
        ("NORA_AUTH_HTPASSWD_FILE", path(&htpasswd)),
        ("NORA_AUTH_TOKEN_STORAGE", path(&dir.path().join("tokens"))),
    ];
    let envs: Vec<(&str, &str)> = envs.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let nora = match common::start(dir.path(), &envs) {
        common::Started::Serving(nora) => nora,
        common::Started::Exited(code, stderr) => panic!("nora exited {code:?}: {stderr}"),
    };
    let port = nora.port;

    // The ping sends the client to the token service.
    let (status, head, _) = request(port, "GET", "/v2/", &[], b"");
    assert_eq!(status, 401, "{head}");
    assert!(
        head.contains("Bearer realm=") && head.contains("/api/docker/token\""),
        "{head}"
    );

    // No credentials: a token that pulls and does not push.
    let anonymous = docker_token(port, &[]);
    assert_eq!(upload(port, &anonymous), 401);

    // The htpasswd user: a token that pushes.
    let basic = format!("Basic {}", STANDARD.encode("admin:secret"));
    let admin = docker_token(port, &[("Authorization", &basic)]);
    assert_eq!(upload(port, &admin), 202);

    // An API token as the password: a token that pushes until the API token is revoked.
    let login = r#""username":"admin","password":"secret""#;
    let create = format!(r#"{{{login},"ttl_days":1,"role":"write"}}"#);
    let content_type = [("Content-Type", "application/json")];
    let (status, _, body) = request(
        port,
        "POST",
        "/api/tokens",
        &content_type,
        create.as_bytes(),
    );
    assert_eq!(status, 200, "{body}");
    let api_token = json(&body)["token"].as_str().unwrap().to_string();
    let basic = format!("Basic {}", STANDARD.encode(format!("ci:{api_token}")));
    let issued = docker_token(port, &[("Authorization", &basic)]);
    assert_eq!(upload(port, &issued), 202);
    let list = format!("{{{login}}}");
    let (_, _, body) = request(
        port,
        "POST",
        "/api/tokens/list",
        &content_type,
        list.as_bytes(),
    );
    let hash_prefix = json(&body)["tokens"][0]["hash_prefix"]
        .as_str()
        .unwrap()
        .to_string();
    let revoke = format!(r#"{{{login},"hash_prefix":"{hash_prefix}"}}"#);
    let (status, _, body) = request(
        port,
        "POST",
        "/api/tokens/revoke",
        &content_type,
        revoke.as_bytes(),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(upload(port, &issued), 401, "revoked, still pushing");
    assert_eq!(
        upload(port, &admin),
        202,
        "the htpasswd token is not affected"
    );

    // A token request body past its limit is refused before it is read, whatever
    // `server.body_limit_mb` allows an upload.
    let form = [("Content-Type", "application/x-www-form-urlencoded")];
    let big = vec![b'x'; 256 * 1024];
    let (status, _, _) = request(port, "POST", "/api/docker/token", &form, &big);
    assert_eq!(status, 413);
    drop(nora);
}
