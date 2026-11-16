// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! `[tls] ca_cert` on the S3 store of the server as it ships (#1186): `nora serve` runs as a
//! process against an S3 store over TLS whose certificate a private CA signed, and `/ready` is
//! asked over a socket. The store answers a listing with an empty bucket and anything else with
//! "no such key", which is all a readiness verdict needs.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const STORE_CA: &str = include_str!("fixtures/storage-ca/ca.pem");
const OTHER_CA: &str = include_str!("fixtures/storage-ca/other-ca.pem");
const STORE_CERT: &str = include_str!("fixtures/storage-ca/store.pem");
const STORE_KEY: &str = include_str!("fixtures/storage-ca/store-key.pem");

/// How long a store that is never trusted is watched not becoming ready: several times what a
/// trusted one takes here.
const NOT_READY_FOR: Duration = Duration::from_secs(8);

/// Requests the store answered after a handshake.
type Answered = Arc<AtomicUsize>;

/// The S3 store over TLS with [`STORE_CERT`]; its `https://` address.
fn private_ca_store() -> (String, Answered) {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from_pem_slice(STORE_CERT.as_bytes()).unwrap()],
        PrivateKeyDer::from_pem_slice(STORE_KEY.as_bytes()).unwrap(),
    )
    .unwrap();
    let config = Arc::new(config);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    let answered = Answered::default();
    let count = answered.clone();
    std::thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(tcp) = tcp else { continue };
            let (config, count) = (config.clone(), count.clone());
            std::thread::spawn(move || {
                let connection = rustls::ServerConnection::new(config).unwrap();
                let mut tls = rustls::StreamOwned::new(connection, tcp);
                loop {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        match tls.read(&mut byte) {
                            Ok(1) => head.push(byte[0]),
                            _ => return,
                        }
                    }
                    count.fetch_add(1, Ordering::SeqCst);
                    let line = String::from_utf8_lossy(&head);
                    let (status, body) = if line.contains("list-type=2") {
                        (
                            "200 OK",
                            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult><Name>b</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>",
                        )
                    } else {
                        (
                            "404 Not Found",
                            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>NoSuchKey</Code><Message>none</Message></Error>",
                        )
                    };
                    let answer = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    if tls
                        .write_all(answer.as_bytes())
                        .and_then(|()| tls.flush())
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    (address, answered)
}

/// The status of `GET /ready`.
fn ready(port: u16) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(common::DEADLINE)).unwrap();
    write!(
        stream,
        "GET /ready HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    answer[9..12].parse().unwrap()
}

/// `nora serve` on the S3 store at `address`, with `envs` on top.
fn serve(dir: &std::path::Path, address: &str, envs: &[(&str, &str)]) -> common::Nora {
    let mut all = vec![
        ("NORA_STORAGE_MODE", "s3"),
        ("NORA_STORAGE_S3_URL", address),
        ("NORA_STORAGE_BUCKET", "b"),
        ("NORA_STORAGE_PATH", "data"),
    ];
    all.extend_from_slice(envs);
    match common::start(dir, &all) {
        common::Started::Serving(nora) => nora,
        common::Started::Exited(code, stderr) => panic!("nora exited {code:?}: {stderr}"),
    }
}

/// Whether `/ready` answers 200 within `within`.
fn becomes_ready(nora: &common::Nora, within: Duration) -> bool {
    let until = Instant::now() + within;
    while Instant::now() < until {
        if ready(nora.port) == 200 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn bundle(dir: &std::path::Path, name: &str, pems: &[&str]) -> String {
    let path = dir.join(name);
    std::fs::write(&path, pems.join("\n")).unwrap();
    path.to_str().unwrap().to_string()
}

/// With the store's CA in `ca_cert` (second in the bundle) the server becomes ready and its
/// requests reach the store. Without it, or with a bundle of another CA, it never does and the
/// store answers nothing: the client does not trust it.
#[test]
fn the_shipped_server_trusts_an_s3_store_through_ca_cert() {
    let dir = tempfile::tempdir().unwrap();
    let trusted = bundle(dir.path(), "trusted.pem", &[OTHER_CA, STORE_CA]);
    let other = bundle(dir.path(), "other.pem", &[OTHER_CA]);

    let (address, answered) = private_ca_store();
    let nora = serve(dir.path(), &address, &[("NORA_TLS_CA_CERT", &trusted)]);
    assert!(
        becomes_ready(&nora, common::DEADLINE),
        "not ready with the CA:\n{}",
        nora.log()
    );
    assert!(answered.load(Ordering::SeqCst) >= 1);
    drop(nora);

    for envs in [vec![], vec![("NORA_TLS_CA_CERT", other.as_str())]] {
        let (address, answered) = private_ca_store();
        let nora = serve(dir.path(), &address, &envs);
        assert!(
            !becomes_ready(&nora, NOT_READY_FOR),
            "ready without the store's CA ({envs:?}):\n{}",
            nora.log()
        );
        assert_eq!(answered.load(Ordering::SeqCst), 0, "{envs:?}");
    }
}

/// GCS with its address from the environment (`GOOGLE_BASE_URL`), not from NORA's
/// `gcs_base_url`: the client options come from the environment there, and adding the CA must
/// keep the address and the rest of what the environment set. Same verdicts as on S3.
#[test]
fn the_shipped_server_trusts_a_gcs_store_addressed_by_the_environment_through_ca_cert() {
    let dir = tempfile::tempdir().unwrap();
    let trusted = bundle(dir.path(), "trusted.pem", &[STORE_CA]);
    // The store takes no token; the fields must be there though nothing reads them.
    let key = dir.path().join("key.json");
    std::fs::write(
        &key,
        r#"{"disable_oauth": true, "private_key": "unused", "private_key_id": "unused", "client_email": "nora@test"}"#,
    )
    .unwrap();
    let key = key.to_str().unwrap();
    for (ca_cert, trusts) in [(Some(trusted.as_str()), true), (None, false)] {
        let (address, answered) = private_ca_store();
        let mut envs = vec![
            ("NORA_STORAGE_MODE", "gcs"),
            ("NORA_STORAGE_BUCKET", "b"),
            ("NORA_STORAGE_GCS_SERVICE_ACCOUNT_PATH", key),
            ("NORA_STORAGE_PATH", "data"),
            ("GOOGLE_BASE_URL", address.as_str()),
        ];
        if let Some(ca_cert) = ca_cert {
            envs.push(("NORA_TLS_CA_CERT", ca_cert));
        }
        let nora = match common::start(dir.path(), &envs) {
            common::Started::Serving(nora) => nora,
            common::Started::Exited(code, stderr) => panic!("nora exited {code:?}: {stderr}"),
        };
        let within = if trusts {
            common::DEADLINE
        } else {
            NOT_READY_FOR
        };
        assert_eq!(
            becomes_ready(&nora, within),
            trusts,
            "ca_cert {ca_cert:?}:\n{}",
            nora.log()
        );
        assert_eq!(
            answered.load(Ordering::SeqCst) >= 1,
            trusts,
            "ca_cert {ca_cert:?}"
        );
    }
}

/// A `ca_cert` that cannot be trusted stops the start of a server on S3 with its path, as any
/// other configuration error, instead of failing every request later.
#[test]
fn a_ca_cert_that_cannot_be_trusted_stops_the_start_on_s3() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.pem");
    let missing = missing.to_str().unwrap();
    let broken = bundle(dir.path(), "broken.pem", &["not a certificate"]);
    let (address, _) = private_ca_store();
    for ca_cert in [missing, broken.as_str()] {
        let all = [
            ("NORA_STORAGE_MODE", "s3"),
            ("NORA_STORAGE_S3_URL", address.as_str()),
            ("NORA_STORAGE_BUCKET", "b"),
            ("NORA_TLS_CA_CERT", ca_cert),
        ];
        match common::start(dir.path(), &all) {
            common::Started::Exited(code, stderr) => {
                assert_eq!(code, Some(78), "{stderr}");
                assert!(stderr.contains(ca_cert), "{stderr}");
            }
            common::Started::Serving(nora) => panic!("served with {ca_cert}:\n{}", nora.log()),
        }
    }
}
