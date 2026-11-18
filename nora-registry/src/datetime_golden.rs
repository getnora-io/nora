// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Golden values for every date NORA writes and reads (#1282).
//!
//! Every expected value below was produced by NORA 1.4.5's own date code (chrono 0.4.45) and
//! is checked against the current one. They are the bytes clients and stores already hold: a
//! change that needs one of them edited changes what NORA writes or how it reads what it wrote.

#![allow(clippy::unwrap_used)]

use super::*;

/// (seconds, nanoseconds, JSON/`rfc3339`, `rfc3339_secs`, `http_date`, `apt_release_date`,
/// `maven_last_updated`, `composer_time`, `Display`).
type Spelling = (
    i64,
    u32,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

#[rustfmt::skip]
const SPELLINGS: &[Spelling] = &[
    (0, 0, "1970-01-01T00:00:00Z", "1970-01-01T00:00:00Z", "Thu, 01 Jan 1970 00:00:00 GMT", "Thu, 01 Jan 1970 00:00:00 UTC", "19700101000000", "1970-01-01T00:00:00+00:00", "1970-01-01 00:00:00 UTC"),
    (1, 1, "1970-01-01T00:00:01.000000001Z", "1970-01-01T00:00:01Z", "Thu, 01 Jan 1970 00:00:01 GMT", "Thu, 01 Jan 1970 00:00:01 UTC", "19700101000001", "1970-01-01T00:00:01+00:00", "1970-01-01 00:00:01.000000001 UTC"),
    (-1, 0, "1969-12-31T23:59:59Z", "1969-12-31T23:59:59Z", "Wed, 31 Dec 1969 23:59:59 GMT", "Wed, 31 Dec 1969 23:59:59 UTC", "19691231235959", "1969-12-31T23:59:59+00:00", "1969-12-31 23:59:59 UTC"),
    (-1, 999999999, "1969-12-31T23:59:59.999999999Z", "1969-12-31T23:59:59Z", "Wed, 31 Dec 1969 23:59:59 GMT", "Wed, 31 Dec 1969 23:59:59 UTC", "19691231235959", "1969-12-31T23:59:59+00:00", "1969-12-31 23:59:59.999999999 UTC"),
    (1700000000, 0, "2023-11-14T22:13:20Z", "2023-11-14T22:13:20Z", "Tue, 14 Nov 2023 22:13:20 GMT", "Tue, 14 Nov 2023 22:13:20 UTC", "20231114221320", "2023-11-14T22:13:20+00:00", "2023-11-14 22:13:20 UTC"),
    (1700000000, 100000000, "2023-11-14T22:13:20.100Z", "2023-11-14T22:13:20Z", "Tue, 14 Nov 2023 22:13:20 GMT", "Tue, 14 Nov 2023 22:13:20 UTC", "20231114221320", "2023-11-14T22:13:20+00:00", "2023-11-14 22:13:20.100 UTC"),
    (1700000000, 120000000, "2023-11-14T22:13:20.120Z", "2023-11-14T22:13:20Z", "Tue, 14 Nov 2023 22:13:20 GMT", "Tue, 14 Nov 2023 22:13:20 UTC", "20231114221320", "2023-11-14T22:13:20+00:00", "2023-11-14 22:13:20.120 UTC"),
    (1700000000, 123000000, "2023-11-14T22:13:20.123Z", "2023-11-14T22:13:20Z", "Tue, 14 Nov 2023 22:13:20 GMT", "Tue, 14 Nov 2023 22:13:20 UTC", "20231114221320", "2023-11-14T22:13:20+00:00", "2023-11-14 22:13:20.123 UTC"),
    (1700000000, 123400000, "2023-11-14T22:13:20.123400Z", "2023-11-14T22:13:20Z", "Tue, 14 Nov 2023 22:13:20 GMT", "Tue, 14 Nov 2023 22:13:20 UTC", "20231114221320", "2023-11-14T22:13:20+00:00", "2023-11-14 22:13:20.123400 UTC"),
    (1700000000, 123456000, "2023-11-14T22:13:20.123456Z", "2023-11-14T22:13:20Z", "Tue, 14 Nov 2023 22:13:20 GMT", "Tue, 14 Nov 2023 22:13:20 UTC", "20231114221320", "2023-11-14T22:13:20+00:00", "2023-11-14 22:13:20.123456 UTC"),
    (1700000000, 123456700, "2023-11-14T22:13:20.123456700Z", "2023-11-14T22:13:20Z", "Tue, 14 Nov 2023 22:13:20 GMT", "Tue, 14 Nov 2023 22:13:20 UTC", "20231114221320", "2023-11-14T22:13:20+00:00", "2023-11-14 22:13:20.123456700 UTC"),
    (1700000000, 123456789, "2023-11-14T22:13:20.123456789Z", "2023-11-14T22:13:20Z", "Tue, 14 Nov 2023 22:13:20 GMT", "Tue, 14 Nov 2023 22:13:20 UTC", "20231114221320", "2023-11-14T22:13:20+00:00", "2023-11-14 22:13:20.123456789 UTC"),
    (1700000000, 1000, "2023-11-14T22:13:20.000001Z", "2023-11-14T22:13:20Z", "Tue, 14 Nov 2023 22:13:20 GMT", "Tue, 14 Nov 2023 22:13:20 UTC", "20231114221320", "2023-11-14T22:13:20+00:00", "2023-11-14 22:13:20.000001 UTC"),
    (1700000000, 1, "2023-11-14T22:13:20.000000001Z", "2023-11-14T22:13:20Z", "Tue, 14 Nov 2023 22:13:20 GMT", "Tue, 14 Nov 2023 22:13:20 UTC", "20231114221320", "2023-11-14T22:13:20+00:00", "2023-11-14 22:13:20.000000001 UTC"),
    (1700000000, 999999999, "2023-11-14T22:13:20.999999999Z", "2023-11-14T22:13:20Z", "Tue, 14 Nov 2023 22:13:20 GMT", "Tue, 14 Nov 2023 22:13:20 UTC", "20231114221320", "2023-11-14T22:13:20+00:00", "2023-11-14 22:13:20.999999999 UTC"),
    (1709164799, 0, "2024-02-28T23:59:59Z", "2024-02-28T23:59:59Z", "Wed, 28 Feb 2024 23:59:59 GMT", "Wed, 28 Feb 2024 23:59:59 UTC", "20240228235959", "2024-02-28T23:59:59+00:00", "2024-02-28 23:59:59 UTC"),
    (1709164800, 5000000, "2024-02-29T00:00:00.005Z", "2024-02-29T00:00:00Z", "Thu, 29 Feb 2024 00:00:00 GMT", "Thu, 29 Feb 2024 00:00:00 UTC", "20240229000000", "2024-02-29T00:00:00+00:00", "2024-02-29 00:00:00.005 UTC"),
    (1798761599, 0, "2026-12-31T23:59:59Z", "2026-12-31T23:59:59Z", "Thu, 31 Dec 2026 23:59:59 GMT", "Thu, 31 Dec 2026 23:59:59 UTC", "20261231235959", "2026-12-31T23:59:59+00:00", "2026-12-31 23:59:59 UTC"),
    (1798761600, 0, "2027-01-01T00:00:00Z", "2027-01-01T00:00:00Z", "Fri, 01 Jan 2027 00:00:00 GMT", "Fri, 01 Jan 2027 00:00:00 UTC", "20270101000000", "2027-01-01T00:00:00+00:00", "2027-01-01 00:00:00 UTC"),
    (1763337600, 0, "2025-11-17T00:00:00Z", "2025-11-17T00:00:00Z", "Mon, 17 Nov 2025 00:00:00 GMT", "Mon, 17 Nov 2025 00:00:00 UTC", "20251117000000", "2025-11-17T00:00:00+00:00", "2025-11-17 00:00:00 UTC"),
    (1763424000, 0, "2025-11-18T00:00:00Z", "2025-11-18T00:00:00Z", "Tue, 18 Nov 2025 00:00:00 GMT", "Tue, 18 Nov 2025 00:00:00 UTC", "20251118000000", "2025-11-18T00:00:00+00:00", "2025-11-18 00:00:00 UTC"),
    (1763510400, 0, "2025-11-19T00:00:00Z", "2025-11-19T00:00:00Z", "Wed, 19 Nov 2025 00:00:00 GMT", "Wed, 19 Nov 2025 00:00:00 UTC", "20251119000000", "2025-11-19T00:00:00+00:00", "2025-11-19 00:00:00 UTC"),
    (1763596800, 0, "2025-11-20T00:00:00Z", "2025-11-20T00:00:00Z", "Thu, 20 Nov 2025 00:00:00 GMT", "Thu, 20 Nov 2025 00:00:00 UTC", "20251120000000", "2025-11-20T00:00:00+00:00", "2025-11-20 00:00:00 UTC"),
    (1763683200, 0, "2025-11-21T00:00:00Z", "2025-11-21T00:00:00Z", "Fri, 21 Nov 2025 00:00:00 GMT", "Fri, 21 Nov 2025 00:00:00 UTC", "20251121000000", "2025-11-21T00:00:00+00:00", "2025-11-21 00:00:00 UTC"),
    (1763769600, 0, "2025-11-22T00:00:00Z", "2025-11-22T00:00:00Z", "Sat, 22 Nov 2025 00:00:00 GMT", "Sat, 22 Nov 2025 00:00:00 UTC", "20251122000000", "2025-11-22T00:00:00+00:00", "2025-11-22 00:00:00 UTC"),
    (1763856000, 0, "2025-11-23T00:00:00Z", "2025-11-23T00:00:00Z", "Sun, 23 Nov 2025 00:00:00 GMT", "Sun, 23 Nov 2025 00:00:00 UTC", "20251123000000", "2025-11-23T00:00:00+00:00", "2025-11-23 00:00:00 UTC"),
    (951782400, 0, "2000-02-29T00:00:00Z", "2000-02-29T00:00:00Z", "Tue, 29 Feb 2000 00:00:00 GMT", "Tue, 29 Feb 2000 00:00:00 UTC", "20000229000000", "2000-02-29T00:00:00+00:00", "2000-02-29 00:00:00 UTC"),
    (4107542400, 0, "2100-03-01T00:00:00Z", "2100-03-01T00:00:00Z", "Mon, 01 Mar 2100 00:00:00 GMT", "Mon, 01 Mar 2100 00:00:00 UTC", "21000301000000", "2100-03-01T00:00:00+00:00", "2100-03-01 00:00:00 UTC"),
    (-2208988800, 0, "1900-01-01T00:00:00Z", "1900-01-01T00:00:00Z", "Mon, 01 Jan 1900 00:00:00 GMT", "Mon, 01 Jan 1900 00:00:00 UTC", "19000101000000", "1900-01-01T00:00:00+00:00", "1900-01-01 00:00:00 UTC"),
    (-62135596800, 0, "0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z", "Mon, 01 Jan 0001 00:00:00 GMT", "Mon, 01 Jan 0001 00:00:00 UTC", "00010101000000", "0001-01-01T00:00:00+00:00", "0001-01-01 00:00:00 UTC"),
    (-62135596801, 0, "0000-12-31T23:59:59Z", "0000-12-31T23:59:59Z", "Sun, 31 Dec 0000 23:59:59 GMT", "Sun, 31 Dec 0000 23:59:59 UTC", "00001231235959", "0000-12-31T23:59:59+00:00", "0000-12-31 23:59:59 UTC"),
    (-62167219200, 0, "0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z", "Sat, 01 Jan 0000 00:00:00 GMT", "Sat, 01 Jan 0000 00:00:00 UTC", "00000101000000", "0000-01-01T00:00:00+00:00", "0000-01-01 00:00:00 UTC"),
    (-62198755200, 0, "-0001-01-01T00:00:00Z", "-0001-01-01T00:00:00Z", "Fri, 01 Jan -0001 00:00:00 GMT", "Fri, 01 Jan -0001 00:00:00 UTC", "-00010101000000", "-0001-01-01T00:00:00+00:00", "-0001-01-01 00:00:00 UTC"),
    (253402300799, 999999999, "9999-12-31T23:59:59.999999999Z", "9999-12-31T23:59:59Z", "Fri, 31 Dec 9999 23:59:59 GMT", "Fri, 31 Dec 9999 23:59:59 UTC", "99991231235959", "9999-12-31T23:59:59+00:00", "9999-12-31 23:59:59.999999999 UTC"),
    (253402300800, 0, "+10000-01-01T00:00:00Z", "+10000-01-01T00:00:00Z", "Sat, 01 Jan +10000 00:00:00 GMT", "Sat, 01 Jan +10000 00:00:00 UTC", "+100000101000000", "+10000-01-01T00:00:00+00:00", "+10000-01-01 00:00:00 UTC"),
    (8210266876799, 999999999, "+262142-12-31T23:59:59.999999999Z", "+262142-12-31T23:59:59Z", "Mon, 31 Dec +262142 23:59:59 GMT", "Mon, 31 Dec +262142 23:59:59 UTC", "+2621421231235959", "+262142-12-31T23:59:59+00:00", "+262142-12-31 23:59:59.999999999 UTC"),
    (-8334601228800, 0, "-262143-01-01T00:00:00Z", "-262143-01-01T00:00:00Z", "Thu, 01 Jan -262143 00:00:00 GMT", "Thu, 01 Jan -262143 00:00:00 UTC", "-2621430101000000", "-262143-01-01T00:00:00+00:00", "-262143-01-01 00:00:00 UTC"),
];

#[test]
fn every_instant_is_spelled_as_nora_spelled_it() {
    for &(secs, nanos, json, secs_z, http, apt, maven, composer, display) in SPELLINGS {
        let t = UtcTime::from_unix(secs, nanos).unwrap();
        let at = format!("{secs}.{nanos:09}");
        assert_eq!(t.rfc3339(), json, "rfc3339 of {at}");
        assert_eq!(t.rfc3339_secs(), secs_z, "rfc3339_secs of {at}");
        assert_eq!(t.http_date(), http, "http_date of {at}");
        assert_eq!(t.apt_release_date(), apt, "apt_release_date of {at}");
        assert_eq!(t.maven_last_updated(), maven, "maven_last_updated of {at}");
        assert_eq!(t.composer_time(), composer, "composer_time of {at}");
        assert_eq!(t.to_string(), display, "Display of {at}");
        assert_eq!(
            serde_json::to_string(&t).unwrap(),
            format!("\"{json}\""),
            "JSON of {at}"
        );
        assert_eq!(
            (t.unix(), t.subsec_nanos()),
            (secs, nanos),
            "{at} round trip"
        );
    }
}

#[test]
fn an_instant_outside_the_calendar_does_not_exist() {
    for (secs, nanos) in [
        (-8_334_601_228_801, 0),
        (8_210_266_876_800, 0),
        (i64::MIN, 0),
        (i64::MAX, 0),
        (0, 1_000_000_000),
        (0, u32::MAX),
    ] {
        assert_eq!(UtcTime::from_unix(secs, nanos), None, "{secs}.{nanos}");
    }
    assert!(UtcTime::from_unix(-8_334_601_228_800, 0).is_some());
    assert!(UtcTime::from_unix(8_210_266_876_799, 999_999_999).is_some());
    assert_eq!(UtcTime::EPOCH, UtcTime::from_unix(0, 0).unwrap());
}

#[test]
fn seconds_between_two_instants_are_counted_toward_zero() {
    let t = |s, n| UtcTime::from_unix(s, n).unwrap();
    for (a, b, expected) in [
        (t(0, 0), t(0, 0), 0),
        (t(0, 0), t(59, 999_999_999), 59),
        (t(0, 0), t(60, 0), 60),
        (t(0, 500_000_000), t(1, 0), 0),
        (t(1, 0), t(0, 500_000_000), 0),
        (t(2, 0), t(0, 500_000_000), -1),
        (t(100, 0), t(0, 0), -100),
        (t(0, 999_999_999), t(86_400, 0), 86_399),
    ] {
        assert_eq!(a.seconds_until(b), expected, "{a} .. {b}");
    }
}

#[test]
fn the_documented_spellings_are_read() {
    for (s, expected) in [
        ("2024-01-15T10:30:00Z", Some(1_705_314_600)),
        ("2024-01-15T10:30:00.123Z", Some(1_705_314_600)),
        ("2024-01-15T10:30:00+00:00", Some(1_705_314_600)),
        ("2024-01-15T10:30:00.000+0000", Some(1_705_314_600)),
        ("2024-01-15T10:30:00", Some(1_705_314_600)),
        ("2024-01-15T10:30:00+05:30", Some(1_705_294_800)),
        ("2024-01-15", None),
        ("", None),
    ] {
        assert_eq!(parse_iso8601_to_unix(s), expected, "{s:?}");
    }
    assert_eq!(
        parse_rfc2822_to_unix("Sun, 06 Nov 1994 08:49:37 GMT"),
        Some(784_111_777)
    );
    assert_eq!(
        parse_rfc3339_relaxed("2026-11-17T08:15:00.120Z"),
        UtcTime::from_unix(1_794_903_300, 120_000_000)
    );
}

/// Each line of the corpus: an input, then what NORA 1.4.5 made of it as an upstream date
/// (`parse_iso8601_to_unix`), as an RFC 2822 `Last-Modified`, and as a serialized time read
/// back (`[seconds, nanoseconds]`); `null` where it refused it. Seeds are spellings registries
/// and earlier releases wrote, and the edges of each grammar; the rest are deterministic one-
/// character mutations of them.
#[test]
fn the_parse_corpus_is_read_as_nora_read_it() {
    let corpus = include_str!("../testdata/datetime/parse-corpus.jsonl");
    let mut wrong = Vec::new();
    let mut lines = 0;
    for line in corpus.lines() {
        lines += 1;
        let (input, iso, rfc2822, relaxed): (String, Option<i64>, Option<i64>, Option<(i64, u32)>) =
            serde_json::from_str(line).unwrap();
        let got = (
            parse_iso8601_to_unix(&input),
            parse_rfc2822_to_unix(&input),
            parse_rfc3339_relaxed(&input).map(|t| (t.unix(), t.subsec_nanos())),
        );
        if got != (iso, rfc2822, relaxed) {
            wrong.push(format!(
                "{input:?}: expected {:?}, got {got:?}",
                (iso, rfc2822, relaxed)
            ));
        }
    }
    assert!(lines > 4000, "the corpus is all there ({lines} lines)");
    assert!(
        wrong.is_empty(),
        "{} of {lines} read differently:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn the_logs_and_metadata_nora_writes_keep_their_json() {
    let t = UtcTime::from_unix(1_700_000_000, 123_456_789).unwrap();
    let mut audit = crate::audit::AuditEntry::new("push", "alice", "app:1.0", "docker", "ok");
    audit.ts = t;
    assert_eq!(
        serde_json::to_string(&audit).unwrap(),
        r#"{"ts":"2023-11-14T22:13:20.123456789Z","action":"push","actor":"alice","artifact":"app:1.0","registry":"docker","detail":"ok"}"#
    );
    // The activity feed's JSON: `activity_log::tests::an_entry_keeps_its_json`.
    let backup = crate::backup::BackupMetadata {
        version: "1.4.5".to_string(),
        created_at: UtcTime::from_unix(1_700_000_000, 0).unwrap(),
        artifact_count: 2,
        total_bytes: 10,
        storage_backend: "local".to_string(),
    };
    assert_eq!(
        serde_json::to_string(&backup).unwrap(),
        r#"{"version":"1.4.5","created_at":"2023-11-14T22:13:20Z","artifact_count":2,"total_bytes":10,"storage_backend":"local"}"#
    );
}

#[test]
fn a_backup_written_by_an_earlier_release_is_read_back() {
    for (created_at, secs, nanos, printed) in [
        (
            "2026-01-01T00:00:00Z",
            1_767_225_600,
            0,
            "2026-01-01 00:00:00 UTC",
        ),
        (
            "2023-11-14T22:13:20.123456789Z",
            1_700_000_000,
            123_456_789,
            "2023-11-14 22:13:20.123456789 UTC",
        ),
        (
            "2023-11-14T23:13:20.5+01:00",
            1_700_000_000,
            500_000_000,
            "2023-11-14 22:13:20.500 UTC",
        ),
        (
            "2023-11-14 22:13:20 UTC",
            1_700_000_000,
            0,
            "2023-11-14 22:13:20 UTC",
        ),
    ] {
        let json = format!(
            r#"{{"version":"0.3.0","created_at":"{created_at}","artifact_count":1,"total_bytes":1,"storage_backend":"s3"}}"#
        );
        let meta: crate::backup::BackupMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(
            (meta.created_at.unix(), meta.created_at.subsec_nanos()),
            (secs, nanos),
            "{created_at}"
        );
        assert_eq!(meta.created_at.to_string(), printed, "{created_at}");
    }
    let refused = r#"{"version":"0.3.0","created_at":"yesterday","artifact_count":1,"total_bytes":1,"storage_backend":"s3"}"#;
    assert!(serde_json::from_str::<crate::backup::BackupMetadata>(refused).is_err());
}

#[test]
fn the_openapi_document_is_unchanged() {
    use sha2::Digest;
    use utoipa::OpenApi;
    let doc = serde_json::to_value(crate::openapi::ApiDoc::openapi()).unwrap();
    assert_eq!(
        doc["components"]["schemas"]["ActivityEntry"]["properties"]["timestamp"].to_string(),
        r#"{"format":"date-time","type":"string"}"#
    );
    // The whole served document, less the release number a release bumps.
    let mut api = crate::openapi::ApiDoc::openapi();
    api.info.version = String::new();
    let json = api.to_json().unwrap();
    assert_eq!(
        hex::encode(sha2::Sha256::digest(json.as_bytes())),
        "9764d2111ef2fa77b63ee0a688395d007e0da1cbc76c5fb24c45f1cd307701c0",
        "the served /api-docs/openapi.json changed"
    );
}

/// RUSTSEC-2026-0543: chrono is unmaintained. NORA's own dates do not depend on it; it may stay
/// in the tree only through a dependency (object_store), which `deny.toml` names.
///
/// Judged on the resolved graph: `Cargo.lock` names the packages `nora-registry` depends on by
/// their real name, whatever the manifest calls them and whichever `[target.*]` table they are
/// in. The manifest is still read for a dependency built with its own `chrono` feature.
#[test]
fn nora_does_not_depend_on_chrono_itself() {
    let lock: toml::Table = include_str!("../../Cargo.lock").parse().unwrap();
    let nora = lock["package"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"].as_str() == Some("nora-registry"))
        .expect("nora-registry in Cargo.lock");
    let deps = nora["dependencies"].as_array().unwrap();
    assert!(
        deps.len() > 20,
        "the dependencies are all there ({})",
        deps.len()
    );
    for dep in deps {
        let name = dep.as_str().unwrap().split(' ').next().unwrap();
        assert_ne!(
            name, "chrono",
            "nora-registry depends on chrono in Cargo.lock"
        );
    }

    let manifest: toml::Table = include_str!("../Cargo.toml").parse().unwrap();
    let sections = |prefix: &str, t: &toml::Table| -> Vec<(String, toml::Table)> {
        ["dependencies", "dev-dependencies", "build-dependencies"]
            .iter()
            .filter_map(|s| Some((format!("{prefix}{s}"), t.get(*s)?.as_table()?.clone())))
            .collect()
    };
    let mut tables = sections("", &manifest);
    if let Some(targets) = manifest.get("target").and_then(|t| t.as_table()) {
        for (cfg, t) in targets {
            tables.extend(sections(&format!("target.{cfg}."), t.as_table().unwrap()));
        }
    }
    assert!(
        tables.len() >= 3,
        "dependency tables read: {}",
        tables.len()
    );
    for (section, deps) in tables {
        for (name, spec) in &deps {
            let package = spec.get("package").and_then(|p| p.as_str()).unwrap_or(name);
            assert_ne!(package, "chrono", "chrono in [{section}] as {name}");
            let features = spec.get("features").and_then(|f| f.as_array());
            assert!(
                !features.is_some_and(|f| f.iter().any(|f| f.as_str() == Some("chrono"))),
                "{name} in [{section}] built with its chrono feature"
            );
        }
    }
}
/// A leap second exists only as read (`23:59:60` in a backup's `created_at`), and is written
/// back as such.
#[test]
fn a_leap_second_is_kept_as_read() {
    for (input, secs, nanos, json, secs_z, http, maven, display) in [
        (
            "2016-12-31T23:59:60.5Z",
            1_483_228_799,
            1_500_000_000,
            "2016-12-31T23:59:60.500Z",
            "2016-12-31T23:59:60Z",
            "Sat, 31 Dec 2016 23:59:60 GMT",
            "20161231235960",
            "2016-12-31 23:59:60.500 UTC",
        ),
        (
            "2024-01-15T10:30:60Z",
            1_705_314_659,
            1_000_000_000,
            "2024-01-15T10:30:60Z",
            "2024-01-15T10:30:60Z",
            "Mon, 15 Jan 2024 10:30:60 GMT",
            "20240115103060",
            "2024-01-15 10:30:60 UTC",
        ),
        (
            "1990-12-31T15:59:60-08:00",
            662_687_999,
            1_000_000_000,
            "1990-12-31T23:59:60Z",
            "1990-12-31T23:59:60Z",
            "Mon, 31 Dec 1990 23:59:60 GMT",
            "19901231235960",
            "1990-12-31 23:59:60 UTC",
        ),
        (
            "2016-12-31T23:59:60.123456Z",
            1_483_228_799,
            1_123_456_000,
            "2016-12-31T23:59:60.123456Z",
            "2016-12-31T23:59:60Z",
            "Sat, 31 Dec 2016 23:59:60 GMT",
            "20161231235960",
            "2016-12-31 23:59:60.123456 UTC",
        ),
    ] {
        let t = parse_rfc3339_relaxed(input).unwrap();
        assert_eq!((t.unix(), t.subsec_nanos()), (secs, nanos), "{input}");
        assert_eq!(t.rfc3339(), json, "{input}");
        assert_eq!(t.rfc3339_secs(), secs_z, "{input}");
        assert_eq!(t.http_date(), http, "{input}");
        assert_eq!(t.maven_last_updated(), maven, "{input}");
        assert_eq!(t.to_string(), display, "{input}");
        assert_eq!(UtcTime::from_unix(secs, nanos), Some(t), "{input}");
    }
    let leap = |s: &str| parse_rfc3339_relaxed(s).unwrap();
    let at = |s| UtcTime::from_unix(s, 0).unwrap();
    assert_eq!(
        leap("2016-12-31T23:59:60.5Z").seconds_until(at(1_483_228_800)),
        0
    );
    assert_eq!(
        leap("2024-01-15T10:30:60Z").seconds_until(at(1_705_314_660)),
        1
    );
    assert_eq!(
        leap("1990-12-31T15:59:60-08:00").seconds_until(at(662_688_000)),
        0
    );
    assert_eq!(
        at(1_705_314_659).seconds_until(leap("2024-01-15T10:30:60Z")),
        1
    );
    assert_eq!(
        at(1_705_314_660).seconds_until(leap("2024-01-15T10:30:60.25Z")),
        0
    );
    assert_eq!(
        leap("2024-01-15T10:30:60.25Z").seconds_until(at(1_705_314_600)),
        -60
    );
    assert_eq!(
        at(1_705_314_600).seconds_until(leap("2024-01-15T10:30:60.25Z")),
        60
    );
    assert_eq!(UtcTime::from_unix(58, 1_000_000_000), None);
    assert_eq!(UtcTime::from_unix(59, 2_000_000_000), None);
    assert_eq!(
        UtcTime::from_unix(59, 1_999_999_999).unwrap().to_string(),
        "1970-01-01 00:00:60.999999999 UTC"
    );
}
