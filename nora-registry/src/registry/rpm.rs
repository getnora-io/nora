// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! RPM registry — hosted yum/dnf repositories with server-generated repodata.
//!
//! Implements:
//!   PUT    /rpm/{repo}/{*path}  — upload a .rpm (parses the header, regenerates repodata)
//!   GET    /rpm/{repo}/{*path}  — download a package or repodata file
//!   HEAD   /rpm/{repo}/{*path}  — existence/size check
//!   DELETE /rpm/{repo}/{*path}  — remove a package (regenerates repodata)
//!
//! Each `{repo}` is an independent repository: `repodata/repomd.xml` plus
//! sha256-named primary/filelists/other.xml.gz are regenerated on every
//! publish/delete from per-package metadata sidecars (parsed once at upload,
//! cargo-index style), so a rebuild never re-reads package payloads. Metadata
//! is unsigned — clients use `gpgcheck=0 repo_gpgcheck=0` (GPG signing is a
//! separate roadmap item, #128).

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::auth::{enforce_namespace_scope, NamespaceAuthority};
use crate::registry::{method_not_allowed, proxied_repo_conflict};
use crate::validation::validate_storage_key;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Router,
};
use flate2::write::GzEncoder;
use rpm::PackageMetadata;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::io::Write;

/// Dashboard index: group stored .rpm files by repository name.
pub const INDEX_PATTERN: (&str, &str) = ("rpm/", ".rpm");

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/rpm/{repo}/-/reindex", axum::routing::post(reindex))
        .route(
            "/rpm/{repo}/{*path}",
            get(download)
                .head(check_exists)
                .put(upload)
                .delete(delete_package)
                .fallback(|| async { method_not_allowed("GET, HEAD, PUT, DELETE") }),
        )
}

/// Sidecar prefix inside a repo. Not a valid RPM path component for clients
/// (uploads to it are rejected), so it can never collide with package files.
const META_DIR: &str = ".nora-meta";
const REPODATA: &str = "repodata";

fn package_key(repo: &str, path: &str) -> String {
    format!("rpm/{repo}/{path}")
}

fn sidecar_key(repo: &str, path: &str) -> String {
    format!("rpm/{repo}/{META_DIR}/{path}.json")
}

fn repomd_key(repo: &str) -> String {
    format!("rpm/{repo}/{REPODATA}/repomd.xml")
}

/// Validate the `{repo}` segment and the tail path of a package operation.
/// The storage-key wrapper re-validates centrally; this is edge defence with
/// format-specific rules (single-segment repo, `.rpm` suffix, reserved dirs).
fn validate_package_path(repo: &str, path: &str) -> Result<(), &'static str> {
    if repo.is_empty() || !repo.is_ascii() || repo.contains('/') || repo.starts_with('.') {
        return Err("Invalid repository name");
    }
    if !path.is_ascii() || path.contains("..") || path.contains('\0') || path.starts_with('/') {
        return Err("Invalid path");
    }
    let lower = path.to_ascii_lowercase();
    if !lower.ends_with(".rpm") {
        return Err("Only .rpm files can be published");
    }
    if path
        .split('/')
        .any(|seg| seg.is_empty() || seg.starts_with('.'))
    {
        return Err("Invalid path");
    }
    if path.starts_with(&format!("{REPODATA}/")) {
        return Err("repodata/ is server-generated");
    }
    Ok(())
}

// ============================================================================
// Package metadata sidecar (parsed once at upload, read back on regeneration)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DepRecord {
    name: String,
    /// createrepo_c flags string (EQ/LT/GT/LE/GE); `None` = unversioned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    flags: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    epoch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rel: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pre: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileRecord {
    path: String,
    /// "" = regular file, "dir", or "ghost" (matches repodata `type` attr).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChangelogRecord {
    author: String,
    date: u64,
    text: String,
}

/// Everything primary/filelists/other.xml need for one package. Written at
/// upload; a repodata rebuild only lists and reads these JSON sidecars.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PkgRecord {
    name: String,
    epoch: u32,
    version: String,
    release: String,
    arch: String,
    summary: String,
    description: String,
    packager: String,
    url: String,
    license: String,
    vendor: String,
    group: String,
    buildhost: String,
    sourcerpm: String,
    build_time: u64,
    file_time: u64,
    size_package: u64,
    size_installed: u64,
    header_start: u64,
    header_end: u64,
    /// Location href relative to the repo root (= the upload path).
    href: String,
    /// sha256 of the whole .rpm file (the repodata pkgid).
    pkgid: String,
    provides: Vec<DepRecord>,
    requires: Vec<DepRecord>,
    conflicts: Vec<DepRecord>,
    obsoletes: Vec<DepRecord>,
    files: Vec<FileRecord>,
    changelogs: Vec<ChangelogRecord>,
}

fn dep_records(deps: Vec<rpm::Dependency>, drop_rpmlib: bool) -> Vec<DepRecord> {
    let mut out: Vec<DepRecord> = Vec::new();
    for d in deps {
        if drop_rpmlib && d.name.starts_with("rpmlib(") {
            continue; // internal rpm capabilities; createrepo_c omits them too
        }
        let flags = flags_str(d.flags);
        let (epoch, ver, rel) = if flags.is_some() {
            let (e, v, r) = parse_evr(&d.version);
            (Some(e), Some(v), r)
        } else {
            (None, None, None)
        };
        let pre = d.flags.intersects(
            rpm::DependencyFlags::PREREQ
                | rpm::DependencyFlags::SCRIPT_PRE
                | rpm::DependencyFlags::SCRIPT_POST,
        );
        let rec = DepRecord {
            name: d.name,
            flags,
            epoch,
            ver,
            rel,
            pre,
        };
        // Exact duplicates are common (e.g. config(x) in provides twice).
        if !out.iter().any(|o| {
            o.name == rec.name && o.flags == rec.flags && o.ver == rec.ver && o.rel == rec.rel
        }) {
            out.push(rec);
        }
    }
    out
}

fn flags_str(flags: rpm::DependencyFlags) -> Option<String> {
    let cmp = flags
        & (rpm::DependencyFlags::LESS
            | rpm::DependencyFlags::GREATER
            | rpm::DependencyFlags::EQUAL);
    let s = if cmp == rpm::DependencyFlags::EQUAL {
        "EQ"
    } else if cmp == rpm::DependencyFlags::LESS {
        "LT"
    } else if cmp == rpm::DependencyFlags::GREATER {
        "GT"
    } else if cmp == rpm::DependencyFlags::LESS | rpm::DependencyFlags::EQUAL {
        "LE"
    } else if cmp == rpm::DependencyFlags::GREATER | rpm::DependencyFlags::EQUAL {
        "GE"
    } else {
        return None;
    };
    Some(s.to_string())
}

/// Split an EVR string (`[epoch:]version[-release]`) into its parts.
/// Epoch defaults to "0" per repodata convention.
fn parse_evr(evr: &str) -> (String, String, Option<String>) {
    let (epoch, rest) = match evr.split_once(':') {
        Some((e, r)) if e.chars().all(|c| c.is_ascii_digit()) && !e.is_empty() => {
            (e.to_string(), r)
        }
        _ => ("0".to_string(), evr),
    };
    match rest.rsplit_once('-') {
        Some((v, r)) => (epoch, v.to_string(), Some(r.to_string())),
        None => (epoch, rest.to_string(), None),
    }
}

/// A file belongs in primary.xml if dnf may need it for dependency solving
/// without fetching filelists (createrepo_c's `is_primary` rule).
fn is_primary_file(path: &str) -> bool {
    path.starts_with("/etc/") || path == "/usr/lib/sendmail" || path.contains("bin/")
}

fn extract_record(
    md: &PackageMetadata,
    body: &[u8],
    href: &str,
    file_time: u64,
    changelog_limit: usize,
) -> Result<PkgRecord, rpm::Error> {
    let offsets = md.get_package_segment_offsets();
    let files = md
        .get_file_entries()?
        .iter()
        .map(|f| {
            let kind = if f.flags().contains(rpm::FileFlags::GHOST) {
                "ghost"
            } else if f.file_type() == rpm::FileType::Dir {
                "dir"
            } else {
                ""
            };
            FileRecord {
                path: f.path().to_string_lossy().into_owned(),
                kind: kind.to_string(),
            }
        })
        .collect();

    // Newest-first in the header; keep the most recent N like createrepo_c.
    let mut changelogs: Vec<ChangelogRecord> = md
        .get_changelog_entries()
        .unwrap_or_default()
        .into_iter()
        .map(|c| ChangelogRecord {
            author: c.name,
            date: c.timestamp,
            text: c.description,
        })
        .collect();
    changelogs.sort_by_key(|c| c.date);
    if changelogs.len() > changelog_limit {
        changelogs.drain(..changelogs.len() - changelog_limit);
    }

    Ok(PkgRecord {
        name: md.get_name()?.to_string(),
        epoch: md.get_epoch().unwrap_or(0),
        version: md.get_version()?.to_string(),
        release: md.get_release()?.to_string(),
        arch: md.get_arch().unwrap_or("noarch").to_string(),
        summary: md.get_summary().unwrap_or_default().to_string(),
        description: md.get_description().unwrap_or_default().to_string(),
        packager: md.get_packager().unwrap_or_default().to_string(),
        url: md.get_url().unwrap_or_default().to_string(),
        license: md.get_license().unwrap_or_default().to_string(),
        vendor: md.get_vendor().unwrap_or_default().to_string(),
        group: md.get_group().unwrap_or_default().to_string(),
        buildhost: md.get_build_host().unwrap_or_default().to_string(),
        sourcerpm: md.get_source_rpm().unwrap_or_default().to_string(),
        build_time: md.get_build_time().unwrap_or(0),
        file_time,
        size_package: body.len() as u64,
        size_installed: md.get_installed_size().unwrap_or(0),
        header_start: offsets.header,
        header_end: offsets.payload,
        href: href.to_string(),
        pkgid: hex::encode(sha2::Sha256::digest(body)),
        provides: dep_records(md.get_provides().unwrap_or_default(), false),
        requires: dep_records(md.get_requires().unwrap_or_default(), true),
        conflicts: dep_records(md.get_conflicts().unwrap_or_default(), false),
        obsoletes: dep_records(md.get_obsoletes().unwrap_or_default(), false),
        files,
        changelogs,
    })
}

// ============================================================================
// Repodata XML generation
// ============================================================================

/// Escape XML entities and drop characters outside the XML 1.0 `Char`
/// production (C0 controls except \t \n \r, and U+FFFE/U+FFFF). Those are
/// forbidden even as character references — libxml2 (what dnf uses) rejects
/// the whole document if one appears, so an RPM with a stray control byte in
/// a header string would brick its repo's metadata (#826).
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\t'
            | '\n'
            | '\r'
            | '\u{20}'..='\u{D7FF}'
            | '\u{E000}'..='\u{FFFD}'
            | '\u{10000}'..='\u{10FFFF}' => out.push(c),
            _ => {} // XML-illegal — dropped
        }
    }
    out
}

fn dep_entry_xml(out: &mut String, tag: &str, deps: &[DepRecord]) {
    if deps.is_empty() {
        return;
    }
    out.push_str(&format!("    <rpm:{tag}>\n"));
    for d in deps {
        out.push_str(&format!(
            "      <rpm:entry name=\"{}\"",
            xml_escape(&d.name)
        ));
        if let Some(ref f) = d.flags {
            out.push_str(&format!(" flags=\"{f}\""));
            out.push_str(&format!(
                " epoch=\"{}\"",
                xml_escape(d.epoch.as_deref().unwrap_or("0"))
            ));
            if let Some(ref v) = d.ver {
                out.push_str(&format!(" ver=\"{}\"", xml_escape(v)));
            }
            if let Some(ref r) = d.rel {
                out.push_str(&format!(" rel=\"{}\"", xml_escape(r)));
            }
        }
        if d.pre {
            out.push_str(" pre=\"1\"");
        }
        out.push_str("/>\n");
    }
    out.push_str(&format!("    </rpm:{tag}>\n"));
}

fn generate_primary_xml(pkgs: &[PkgRecord]) -> String {
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata xmlns=\"http://linux.duke.edu/metadata/common\" xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\" packages=\"{}\">\n",
        pkgs.len()
    );
    for p in pkgs {
        out.push_str("<package type=\"rpm\">\n");
        out.push_str(&format!("  <name>{}</name>\n", xml_escape(&p.name)));
        out.push_str(&format!("  <arch>{}</arch>\n", xml_escape(&p.arch)));
        out.push_str(&format!(
            "  <version epoch=\"{}\" ver=\"{}\" rel=\"{}\"/>\n",
            p.epoch,
            xml_escape(&p.version),
            xml_escape(&p.release)
        ));
        out.push_str(&format!(
            "  <checksum type=\"sha256\" pkgid=\"YES\">{}</checksum>\n",
            p.pkgid
        ));
        out.push_str(&format!(
            "  <summary>{}</summary>\n",
            xml_escape(&p.summary)
        ));
        out.push_str(&format!(
            "  <description>{}</description>\n",
            xml_escape(&p.description)
        ));
        out.push_str(&format!(
            "  <packager>{}</packager>\n",
            xml_escape(&p.packager)
        ));
        out.push_str(&format!("  <url>{}</url>\n", xml_escape(&p.url)));
        out.push_str(&format!(
            "  <time file=\"{}\" build=\"{}\"/>\n",
            p.file_time, p.build_time
        ));
        out.push_str(&format!(
            "  <size package=\"{}\" installed=\"{}\" archive=\"{}\"/>\n",
            p.size_package, p.size_installed, p.size_installed
        ));
        out.push_str(&format!("  <location href=\"{}\"/>\n", xml_escape(&p.href)));
        out.push_str("  <format>\n");
        out.push_str(&format!(
            "    <rpm:license>{}</rpm:license>\n",
            xml_escape(&p.license)
        ));
        out.push_str(&format!(
            "    <rpm:vendor>{}</rpm:vendor>\n",
            xml_escape(&p.vendor)
        ));
        out.push_str(&format!(
            "    <rpm:group>{}</rpm:group>\n",
            xml_escape(&p.group)
        ));
        out.push_str(&format!(
            "    <rpm:buildhost>{}</rpm:buildhost>\n",
            xml_escape(&p.buildhost)
        ));
        out.push_str(&format!(
            "    <rpm:sourcerpm>{}</rpm:sourcerpm>\n",
            xml_escape(&p.sourcerpm)
        ));
        out.push_str(&format!(
            "    <rpm:header-range start=\"{}\" end=\"{}\"/>\n",
            p.header_start, p.header_end
        ));
        dep_entry_xml(&mut out, "provides", &p.provides);
        dep_entry_xml(&mut out, "requires", &p.requires);
        dep_entry_xml(&mut out, "conflicts", &p.conflicts);
        dep_entry_xml(&mut out, "obsoletes", &p.obsoletes);
        for f in p.files.iter().filter(|f| is_primary_file(&f.path)) {
            if f.kind.is_empty() {
                out.push_str(&format!("    <file>{}</file>\n", xml_escape(&f.path)));
            } else {
                out.push_str(&format!(
                    "    <file type=\"{}\">{}</file>\n",
                    f.kind,
                    xml_escape(&f.path)
                ));
            }
        }
        out.push_str("  </format>\n</package>\n");
    }
    out.push_str("</metadata>\n");
    out
}

fn generate_filelists_xml(pkgs: &[PkgRecord]) -> String {
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<filelists xmlns=\"http://linux.duke.edu/metadata/filelists\" packages=\"{}\">\n",
        pkgs.len()
    );
    for p in pkgs {
        out.push_str(&format!(
            "<package pkgid=\"{}\" name=\"{}\" arch=\"{}\">\n  <version epoch=\"{}\" ver=\"{}\" rel=\"{}\"/>\n",
            p.pkgid,
            xml_escape(&p.name),
            xml_escape(&p.arch),
            p.epoch,
            xml_escape(&p.version),
            xml_escape(&p.release)
        ));
        for f in &p.files {
            if f.kind.is_empty() {
                out.push_str(&format!("  <file>{}</file>\n", xml_escape(&f.path)));
            } else {
                out.push_str(&format!(
                    "  <file type=\"{}\">{}</file>\n",
                    f.kind,
                    xml_escape(&f.path)
                ));
            }
        }
        out.push_str("</package>\n");
    }
    out.push_str("</filelists>\n");
    out
}

fn generate_other_xml(pkgs: &[PkgRecord]) -> String {
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<otherdata xmlns=\"http://linux.duke.edu/metadata/other\" packages=\"{}\">\n",
        pkgs.len()
    );
    for p in pkgs {
        out.push_str(&format!(
            "<package pkgid=\"{}\" name=\"{}\" arch=\"{}\">\n  <version epoch=\"{}\" ver=\"{}\" rel=\"{}\"/>\n",
            p.pkgid,
            xml_escape(&p.name),
            xml_escape(&p.arch),
            p.epoch,
            xml_escape(&p.version),
            xml_escape(&p.release)
        ));
        for c in &p.changelogs {
            out.push_str(&format!(
                "  <changelog author=\"{}\" date=\"{}\">{}</changelog>\n",
                xml_escape(&c.author),
                c.date,
                xml_escape(&c.text)
            ));
        }
        out.push_str("</package>\n");
    }
    out.push_str("</otherdata>\n");
    out
}

struct RepodataFile {
    kind: &'static str,
    href: String,
    checksum: String,
    open_checksum: String,
    size: usize,
    open_size: usize,
    gz: Vec<u8>,
}

fn build_repodata_file(kind: &'static str, xml: &str) -> Result<RepodataFile, std::io::Error> {
    let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(xml.as_bytes())?;
    let gz = enc.finish()?;
    let checksum = hex::encode(sha2::Sha256::digest(&gz));
    Ok(RepodataFile {
        kind,
        href: format!("{REPODATA}/{checksum}-{kind}.xml.gz"),
        checksum,
        open_checksum: hex::encode(sha2::Sha256::digest(xml.as_bytes())),
        size: gz.len(),
        open_size: xml.len(),
        gz,
    })
}

fn generate_repomd_xml(files: &[RepodataFile], revision: u64) -> String {
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<repomd xmlns=\"http://linux.duke.edu/metadata/repo\" xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\">\n  <revision>{revision}</revision>\n"
    );
    for f in files {
        out.push_str(&format!(
            r#"  <data type="{kind}">
    <checksum type="sha256">{checksum}</checksum>
    <open-checksum type="sha256">{open_checksum}</open-checksum>
    <location href="{href}"/>
    <timestamp>{revision}</timestamp>
    <size>{size}</size>
    <open-size>{open_size}</open-size>
  </data>
"#,
            kind = f.kind,
            checksum = f.checksum,
            open_checksum = f.open_checksum,
            href = f.href,
            size = f.size,
            open_size = f.open_size,
        ));
    }
    out.push_str("</repomd>\n");
    out
}

/// Rebuild the full repodata for `repo` from metadata sidecars. Caller must
/// hold the repo's publish lock. Fail-closed: any error aborts the rebuild
/// (and the surrounding publish) rather than writing a truncated repo —
/// same contract as the cargo index (`regenerate_cargo_index`).
/// AppState-free so callers outside the request path (reindex, and later
/// retention / key-rotation sweeps) can rebuild a repo with just storage and
/// the signer.
pub(crate) async fn regenerate_repodata(
    storage: &crate::Storage,
    signer: Option<&crate::signing::RepoSigner>,
    repo: &str,
) -> Result<(), String> {
    let meta_prefix = format!("rpm/{repo}/{META_DIR}/");
    let keys = storage
        .list(&meta_prefix)
        .await
        .map_err(|e| format!("list sidecars: {e}"))?;

    let mut pkgs = Vec::with_capacity(keys.len());
    for key in &keys {
        let data = storage
            .get(key)
            .await
            .map_err(|e| format!("read sidecar {key}: {e}"))?;
        let rec: PkgRecord =
            serde_json::from_slice(&data).map_err(|e| format!("parse sidecar {key}: {e}"))?;
        pkgs.push(rec);
    }
    // Deterministic output: same package set → byte-identical repodata.
    pkgs.sort_by(|a, b| {
        (&a.name, a.epoch, &a.version, &a.release, &a.arch)
            .cmp(&(&b.name, b.epoch, &b.version, &b.release, &b.arch))
    });

    let files = [
        build_repodata_file("primary", &generate_primary_xml(&pkgs)),
        build_repodata_file("filelists", &generate_filelists_xml(&pkgs)),
        build_repodata_file("other", &generate_other_xml(&pkgs)),
    ];
    let mut built = Vec::with_capacity(3);
    for f in files {
        built.push(f.map_err(|e| format!("gzip repodata: {e}"))?);
    }

    let revision = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    for f in &built {
        storage
            .put(&format!("rpm/{repo}/{}", f.href), &f.gz)
            .await
            .map_err(|e| format!("write {}: {e}", f.href))?;
    }
    // repomd.xml last — it references the files above, so a reader never sees
    // a repomd pointing at data that has not been written yet.
    let repomd = generate_repomd_xml(&built, revision);
    storage
        .put(&repomd_key(repo), repomd.as_bytes())
        .await
        .map_err(|e| format!("write repomd.xml: {e}"))?;

    // Signature written AFTER repomd.xml so a reader never sees a signature
    // for bytes that are not there yet. The converse window exists — a reader
    // between the two puts sees new repomd with the previous signature — and
    // resolves on client retry, same transient class as the hashed-blob
    // window above. Fail-closed like the rest of the rebuild: a repo that
    // claims to be signed must never publish an unsigned or stale-signed
    // repomd (#128).
    let asc_key = format!("{}.asc", repomd_key(repo));
    match signer {
        Some(signer) => {
            let asc = signer.sign_detached(repomd.as_bytes())?;
            storage
                .put(&asc_key, asc.as_bytes())
                .await
                .map_err(|e| format!("write repomd.xml.asc: {e}"))?;
        }
        None => {
            // Signing turned off after having been on: a stale signature that
            // no longer matches repomd.xml would hard-fail repo_gpgcheck.
            if storage.stat(&asc_key).await.is_some() {
                storage
                    .delete(&asc_key)
                    .await
                    .map_err(|e| format!("delete stale repomd.xml.asc: {e}"))?;
            }
        }
    }

    // Drop repodata generations no longer referenced by repomd.xml. A client
    // that fetched the old repomd in the regeneration window gets a 404 on the
    // old blobs and re-fetches repomd — dnf handles this (same behaviour as
    // createrepo_c without --retain-old-md).
    let current: std::collections::HashSet<String> = built
        .iter()
        .map(|f| format!("rpm/{repo}/{}", f.href))
        .collect();
    if let Ok(existing) = storage.list(&format!("rpm/{repo}/{REPODATA}/")).await {
        for key in existing {
            if key.ends_with("repomd.xml")
                || key.ends_with("repomd.xml.asc")
                || current.contains(&key)
            {
                continue;
            }
            if let Err(e) = storage.delete(&key).await {
                tracing::warn!(key = %key, error = %e, "rpm: failed to prune stale repodata");
            }
        }
    }
    Ok(())
}

// ============================================================================
// Handlers
// ============================================================================

async fn upload(
    State(state): State<AppState>,
    Path((repo, path)): Path<(String, String)>,
    Extension(authority): Extension<NamespaceAuthority>,
    body: Bytes,
) -> Response {
    if !state.config.rpm.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if state.config.rpm.proxies.contains_key(&repo) {
        return proxied_repo_conflict();
    }
    if let Err(msg) = validate_package_path(&repo, &path) {
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }
    // Enforce OIDC namespace_scope on the repository name (#583).
    if enforce_namespace_scope(&authority, &repo).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    if body.len() as u64 > state.config.rpm.max_file_size {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "File too large. Max size: {} bytes",
                state.config.rpm.max_file_size
            ),
        )
            .into_response();
    }

    let md = match PackageMetadata::parse(&mut &body[..]) {
        Ok(md) => md,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("Not a valid RPM: {e}")).into_response()
        }
    };
    let file_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let record = match extract_record(
        &md,
        &body,
        &path,
        file_time,
        state.config.rpm.changelog_limit,
    ) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("RPM header missing required tags: {e}"),
            )
                .into_response()
        }
    };
    let sidecar = match serde_json::to_vec(&record) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(error = %e, "rpm: failed to serialize package record");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let key = package_key(&repo, &path);
    if validate_storage_key(&key).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Serialize publishes/deletes per repo: the repodata rebuild is a
    // list-read-generate-write cycle over the whole repo (same TOCTOU
    // rationale as the maven-metadata.xml lock).
    let lock = state.publish_lock(&repomd_key(&repo));
    let _guard = lock.lock().await;

    if let Err(e) = state.storage.put(&key, &body).await {
        tracing::error!(error = %e, key = %key, "rpm: failed to store package");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if let Err(e) = state
        .storage
        .put(&sidecar_key(&repo, &path), &sidecar)
        .await
    {
        tracing::error!(error = %e, key = %key, "rpm: failed to store metadata sidecar");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if let Err(e) = regenerate_repodata(&state.storage, state.signer.as_deref(), &repo).await {
        tracing::error!(repo = %repo, error = %e, "rpm: repodata regeneration failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Package stored but repodata regeneration failed",
        )
            .into_response();
    }

    let nevra = format!(
        "{}-{}-{}.{}",
        record.name, record.version, record.release, record.arch
    );
    state.metrics.record_upload("rpm");
    state
        .audit
        .log(AuditEntry::new("push", "api", &nevra, "rpm", ""));
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        format!("{repo}/{nevra}"),
        crate::registry_type::RegistryType::Rpm,
        "LOCAL",
    ));
    state.repo_index.invalidate("rpm");

    StatusCode::CREATED.into_response()
}

async fn download(
    State(state): State<AppState>,
    Path((repo, path)): Path<(String, String)>,
) -> Response {
    if !state.config.rpm.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    // Pull-through repo: every path (including repodata/ and repomd.xml.key,
    // which are server-generated only for hosted repos) proxies to the
    // configured upstream. Packages are immutable; metadata is TTL-bounded.
    if let Some(entry) = state.config.rpm.proxies.get(&repo) {
        let key = package_key(&repo, &path);
        if validate_storage_key(&key).is_err() || path.starts_with(META_DIR) {
            return StatusCode::BAD_REQUEST.into_response();
        }
        let lower = path.to_ascii_lowercase();
        let immutable = lower.ends_with(".rpm") || lower.ends_with(".drpm");
        let url = format!("{}/{}", entry.url().trim_end_matches('/'), path);
        return crate::registry::repo_proxy_download(
            &state,
            "rpm",
            crate::registry_type::RegistryType::Rpm,
            format!("{repo}/{path}"),
            key,
            url,
            entry.auth(),
            state.config.rpm.proxy_timeout,
            state.config.rpm.metadata_ttl,
            immutable,
            content_type(&path),
        )
        .await;
    }
    if path == format!("{REPODATA}/repomd.xml.key") {
        return match &state.signer {
            Some(signer) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/pgp-keys")],
                signer.public_key_armored().to_string(),
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    let key = package_key(&repo, &path);
    if validate_storage_key(&key).is_err() || path.starts_with(META_DIR) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    match state.storage.get_verified(&key).await {
        Ok(outcome) => {
            state.metrics.record_download("rpm");
            state.activity.push(ActivityEntry::new(
                ActionType::Pull,
                format!("{repo}/{path}"),
                crate::registry_type::RegistryType::Rpm,
                "LOCAL",
            ));
            use nora_registry::verified::{verified_body, GateOutcome};
            let data = match outcome {
                GateOutcome::Verified(blob) => verified_body(blob),
                GateOutcome::Unpinned(blob) => blob.into_inner(),
            };
            let mut builder = axum::http::Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, content_type(&path));
            // repomd.xml is rewritten in place on every publish — clients must
            // revalidate it. Hashed repodata blobs and .rpm files are immutable.
            if path == format!("{REPODATA}/repomd.xml") {
                builder = builder.header(header::CACHE_CONTROL, "no-cache");
            }
            builder
                .body(axum::body::Body::from(data))
                .expect("valid response")
                .into_response()
        }
        Err(crate::storage::StorageError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(error = %e, key = %key, "rpm: failed to read artifact");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn check_exists(
    State(state): State<AppState>,
    Path((repo, path)): Path<(String, String)>,
) -> Response {
    if !state.config.rpm.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let key = package_key(&repo, &path);
    if validate_storage_key(&key).is_err() || path.starts_with(META_DIR) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match state.storage.stat(&key).await {
        Some(meta) => (
            StatusCode::OK,
            [
                (header::CONTENT_LENGTH, meta.size.to_string()),
                (header::CONTENT_TYPE, content_type(&path).to_string()),
            ],
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn delete_package(
    State(state): State<AppState>,
    Path((repo, path)): Path<(String, String)>,
    Extension(authority): Extension<NamespaceAuthority>,
) -> Response {
    if !state.config.rpm.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if state.config.rpm.proxies.contains_key(&repo) {
        return proxied_repo_conflict();
    }
    if let Err(msg) = validate_package_path(&repo, &path) {
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }
    if enforce_namespace_scope(&authority, &repo).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let key = package_key(&repo, &path);
    if validate_storage_key(&key).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let lock = state.publish_lock(&repomd_key(&repo));
    let _guard = lock.lock().await;

    match state.storage.delete(&key).await {
        Ok(()) => {}
        Err(crate::storage::StorageError::NotFound) => {
            return StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, key = %key, "rpm: failed to delete package");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    if let Err(e) = state.storage.delete(&sidecar_key(&repo, &path)).await {
        tracing::warn!(error = %e, key = %key, "rpm: failed to delete metadata sidecar");
    }
    if let Err(e) = regenerate_repodata(&state.storage, state.signer.as_deref(), &repo).await {
        tracing::error!(repo = %repo, error = %e, "rpm: repodata regeneration failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Package deleted but repodata regeneration failed",
        )
            .into_response();
    }

    state
        .audit
        .log(AuditEntry::new("delete", "api", &path, "rpm", ""));
    state.repo_index.invalidate("rpm");
    StatusCode::NO_CONTENT.into_response()
}

/// Reconcile a repository with what is actually in storage, then rebuild
/// (and re-sign) its repodata. Heals out-of-band changes the publish path
/// never saw: packages deleted directly from storage (their stale sidecars
/// are dropped) and packages added directly to storage (parsed, sidecar
/// created). Also the re-sign hook after a signing-key change. Runs under
/// the repo publish lock, like every rebuild.
async fn reindex(
    State(state): State<AppState>,
    Path(repo): Path<String>,
    Extension(authority): Extension<NamespaceAuthority>,
) -> Response {
    if !state.config.rpm.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if repo.is_empty() || !repo.is_ascii() || repo.contains('/') || repo.starts_with('.') {
        return (StatusCode::BAD_REQUEST, "Invalid repository name").into_response();
    }
    if state.config.rpm.proxies.contains_key(&repo) {
        return proxied_repo_conflict();
    }
    if enforce_namespace_scope(&authority, &repo).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }

    let lock = state.publish_lock(&repomd_key(&repo));
    let _guard = lock.lock().await;

    let prefix = format!("rpm/{repo}/");
    let keys = match state.storage.list(&prefix).await {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, repo = %repo, "rpm reindex: list failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if keys.is_empty() {
        return (StatusCode::NOT_FOUND, "No such repository").into_response();
    }

    let meta_prefix = format!("rpm/{repo}/{META_DIR}/");
    let mut packages: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut sidecars: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for key in &keys {
        if let Some(rest) = key.strip_prefix(&meta_prefix) {
            if let Some(pkg) = rest.strip_suffix(".json") {
                sidecars.insert(pkg.to_string());
            }
        } else if let Some(rest) = key.strip_prefix(&prefix) {
            if rest.to_ascii_lowercase().ends_with(".rpm") && !rest.starts_with(REPODATA) {
                packages.insert(rest.to_string());
            }
        }
    }

    // Drop sidecars whose package is gone (deleted out-of-band).
    let mut orphans_removed = 0usize;
    for stale in sidecars.difference(&packages) {
        match state.storage.delete(&sidecar_key(&repo, stale)).await {
            Ok(()) => orphans_removed += 1,
            Err(e) => {
                tracing::error!(error = %e, repo = %repo, pkg = %stale, "rpm reindex: orphan sidecar delete failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }

    // Parse packages that have no sidecar (added out-of-band). The package is
    // read fully once — header for the fields, whole body for the pkgid.
    let mut sidecars_created = 0usize;
    for missing in packages.difference(&sidecars) {
        let body = match state.storage.get(&package_key(&repo, missing)).await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, repo = %repo, pkg = %missing, "rpm reindex: package read failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        let md = match PackageMetadata::parse(&mut &body[..]) {
            Ok(md) => md,
            Err(e) => {
                tracing::error!(error = %e, repo = %repo, pkg = %missing, "rpm reindex: not a valid RPM — refusing to index");
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("{missing} is not a valid RPM: {e}"),
                )
                    .into_response();
            }
        };
        let file_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let record = match extract_record(
            &md,
            &body,
            missing,
            file_time,
            state.config.rpm.changelog_limit,
        ) {
            Ok(r) => r,
            Err(e) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("{missing}: RPM header missing required tags: {e}"),
                )
                    .into_response()
            }
        };
        let json = match serde_json::to_vec(&record) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(error = %e, "rpm reindex: sidecar serialize failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        if let Err(e) = state.storage.put(&sidecar_key(&repo, missing), &json).await {
            tracing::error!(error = %e, repo = %repo, pkg = %missing, "rpm reindex: sidecar write failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        sidecars_created += 1;
    }

    if let Err(e) = regenerate_repodata(&state.storage, state.signer.as_deref(), &repo).await {
        tracing::error!(repo = %repo, error = %e, "rpm reindex: repodata regeneration failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    state
        .audit
        .log(AuditEntry::new("reindex", "api", &repo, "rpm", ""));
    state.repo_index.invalidate("rpm");

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "packages": packages.len(),
            "sidecars_created": sidecars_created,
            "orphans_removed": orphans_removed,
            "signed": state.signer.is_some(),
        })),
    )
        .into_response()
}

fn content_type(path: &str) -> &'static str {
    if path.ends_with(".rpm") {
        "application/x-rpm"
    } else if path.ends_with(".xml") {
        "application/xml"
    } else if path.ends_with(".xml.gz") {
        "application/gzip"
    } else {
        "application/octet-stream"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_evr() {
        assert_eq!(
            parse_evr("1:2.3-4.el9"),
            ("1".into(), "2.3".into(), Some("4.el9".into()))
        );
        assert_eq!(
            parse_evr("2.3-4"),
            ("0".into(), "2.3".into(), Some("4".into()))
        );
        assert_eq!(parse_evr("2.3"), ("0".into(), "2.3".into(), None));
        // A non-numeric prefix before ':' is part of the version, not an epoch.
        assert_eq!(parse_evr("a:b"), ("0".into(), "a:b".into(), None));
    }

    #[test]
    fn test_flags_str() {
        use rpm::DependencyFlags as F;
        assert_eq!(flags_str(F::EQUAL).as_deref(), Some("EQ"));
        assert_eq!(flags_str(F::LESS).as_deref(), Some("LT"));
        assert_eq!(flags_str(F::GREATER).as_deref(), Some("GT"));
        assert_eq!(flags_str(F::LESS | F::EQUAL).as_deref(), Some("LE"));
        assert_eq!(flags_str(F::GREATER | F::EQUAL).as_deref(), Some("GE"));
        assert_eq!(flags_str(F::ANY), None);
        // Comparison bits survive alongside unrelated flag bits.
        assert_eq!(
            flags_str(F::GREATER | F::EQUAL | F::PREREQ).as_deref(),
            Some("GE")
        );
    }

    #[test]
    fn test_is_primary_file() {
        assert!(is_primary_file("/etc/foo.conf"));
        assert!(is_primary_file("/usr/bin/foo"));
        assert!(is_primary_file("/usr/sbin/foo"));
        assert!(is_primary_file("/usr/lib/sendmail"));
        assert!(!is_primary_file("/usr/share/doc/foo/README"));
        assert!(!is_primary_file("/var/lib/foo/state"));
    }

    #[test]
    fn test_validate_package_path() {
        assert!(validate_package_path("myrepo", "Packages/foo-1.0-1.x86_64.rpm").is_ok());
        assert!(validate_package_path("myrepo", "foo.rpm").is_ok());
        assert!(validate_package_path("a/b", "foo.rpm").is_err()); // multi-segment repo
        assert!(validate_package_path("", "foo.rpm").is_err());
        assert!(validate_package_path(".hidden", "foo.rpm").is_err());
        assert!(validate_package_path("myrepo", "foo.txt").is_err()); // not .rpm
        assert!(validate_package_path("myrepo", "repodata/foo.rpm").is_err()); // reserved
        assert!(validate_package_path("myrepo", ".nora-meta/foo.rpm").is_err()); // dot segment
        assert!(validate_package_path("myrepo", "a/../b.rpm").is_err()); // traversal
        assert!(validate_package_path("myrepo", "/abs.rpm").is_err());
    }

    #[test]
    fn test_xml_escape() {
        assert_eq!(xml_escape("a<b>&\"c"), "a&lt;b&gt;&amp;&quot;c");
    }

    /// XML 1.0 forbids most C0 controls even as character references; a single
    /// one makes libxml2 (dnf) reject the whole repodata file (#826).
    #[test]
    fn test_xml_escape_drops_illegal_chars() {
        assert_eq!(xml_escape("a\u{01}b"), "ab");
        assert_eq!(xml_escape("a\u{08}\u{0b}\u{0c}\u{0e}\u{1f}b"), "ab");
        assert_eq!(xml_escape("a\u{fffe}\u{ffff}b"), "ab");
        // Legal whitespace controls survive.
        assert_eq!(xml_escape("a\tb\nc\rd"), "a\tb\nc\rd");
        // Legal non-ASCII survives.
        assert_eq!(xml_escape("héllo — 包"), "héllo — 包");
    }

    /// End-to-end: a package record laced with control bytes must yield XML in
    /// which every character satisfies the XML 1.0 `Char` production (#826).
    #[test]
    fn test_generated_xml_contains_no_illegal_chars() {
        let hostile = "x\u{01}\u{02}\u{1f}y";
        let pkg = PkgRecord {
            name: hostile.into(),
            epoch: 0,
            version: "1.0".into(),
            release: "1".into(),
            arch: "x86_64".into(),
            summary: hostile.into(),
            description: format!("desc {hostile}"),
            packager: hostile.into(),
            url: hostile.into(),
            license: hostile.into(),
            vendor: hostile.into(),
            group: hostile.into(),
            buildhost: hostile.into(),
            sourcerpm: hostile.into(),
            build_time: 0,
            file_time: 0,
            size_package: 1,
            size_installed: 1,
            header_start: 0,
            header_end: 1,
            href: "Packages/x.rpm".into(),
            pkgid: "deadbeef".into(),
            provides: vec![DepRecord {
                name: hostile.into(),
                flags: Some("EQ".into()),
                epoch: Some("0".into()),
                ver: Some(hostile.into()),
                rel: None,
                pre: false,
            }],
            requires: vec![],
            conflicts: vec![],
            obsoletes: vec![],
            files: vec![FileRecord {
                path: format!("/usr/bin/{hostile}"),
                kind: String::new(),
            }],
            changelogs: vec![ChangelogRecord {
                author: hostile.into(),
                date: 1,
                text: hostile.into(),
            }],
        };
        let pkgs = [pkg];
        for xml in [
            generate_primary_xml(&pkgs),
            generate_filelists_xml(&pkgs),
            generate_other_xml(&pkgs),
        ] {
            let bad = xml.chars().find(|&c| {
                !matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
            });
            assert_eq!(bad, None, "illegal char {bad:?} in generated XML");
            assert!(xml.contains("xy"), "escaped fields must keep legal chars");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use super::REPODATA;
    use crate::test_helpers::{body_bytes, create_test_context, send};
    use axum::http::{Method, StatusCode};
    use std::io::Read;

    /// Build a real .rpm in memory with a known dependency, config file,
    /// binary, and changelog — exercises the same parse path dnf publishes hit.
    fn build_test_rpm(name: &str, version: &str) -> Vec<u8> {
        let pkg = rpm::PackageBuilder::new(name, version, "MIT", "x86_64", "A test package")
            .release("1")
            .description("Test package for the NORA rpm registry")
            .requires(rpm::Dependency::greater_eq("bash", "4.0"))
            .add_changelog_entry(
                "Test Author <test@example.com> - 1.0-1",
                "- initial release",
                1_700_000_000u32,
            )
            .with_file_contents(
                b"#!/bin/sh\necho hi\n".to_vec(),
                rpm::FileOptions::new(format!("/usr/bin/{name}")),
            )
            .unwrap()
            .with_file_contents(
                b"key=value\n".to_vec(),
                rpm::FileOptions::new(format!("/etc/{name}.conf")).config(),
            )
            .unwrap()
            .build()
            .unwrap();
        let mut buf = Vec::new();
        pkg.write(&mut buf).unwrap();
        buf
    }

    fn gunzip(data: &[u8]) -> String {
        let mut out = String::new();
        flate2::read::GzDecoder::new(data)
            .read_to_string(&mut out)
            .unwrap();
        out
    }

    /// Extract the `href` of a repomd `<data type="{kind}">` entry.
    fn repomd_href(repomd: &str, kind: &str) -> String {
        let start = repomd
            .find(&format!("<data type=\"{kind}\">"))
            .unwrap_or_else(|| panic!("repomd missing data type {kind}: {repomd}"));
        let rest = &repomd[start..];
        let href_start = rest.find("href=\"").unwrap() + 6;
        let href_end = rest[href_start..].find('"').unwrap() + href_start;
        rest[href_start..href_end].to_string()
    }

    #[tokio::test]
    async fn test_rpm_upload_generates_repodata() {
        let ctx = create_test_context();
        let body = build_test_rpm("hello", "1.0");

        let resp = send(
            &ctx.app,
            Method::PUT,
            "/rpm/myrepo/Packages/hello-1.0-1.x86_64.rpm",
            body.clone(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = send(&ctx.app, Method::GET, "/rpm/myrepo/repodata/repomd.xml", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .unwrap()
                .to_str()
                .unwrap(),
            "no-cache"
        );
        let repomd = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();

        // primary.xml: identity, dependency flags, location, primary-file subset.
        let primary_href = repomd_href(&repomd, "primary");
        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/rpm/myrepo/{primary_href}"),
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let primary = gunzip(&body_bytes(resp).await);
        assert!(primary.contains("packages=\"1\""), "{primary}");
        assert!(primary.contains("<name>hello</name>"));
        assert!(primary.contains("ver=\"1.0\" rel=\"1\""));
        assert!(primary.contains("<location href=\"Packages/hello-1.0-1.x86_64.rpm\"/>"));
        assert!(
            primary.contains("<rpm:entry name=\"bash\" flags=\"GE\" epoch=\"0\" ver=\"4.0\"/>"),
            "{primary}"
        );
        assert!(primary.contains("<file>/etc/hello.conf</file>"));
        assert!(primary.contains("<file>/usr/bin/hello</file>"));
        assert!(
            !primary.contains("rpmlib("),
            "rpmlib deps must be dropped: {primary}"
        );
        // pkgid = sha256 of the uploaded bytes.
        let pkgid = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&body));
        assert!(primary.contains(&pkgid));

        // filelists.xml: every file listed.
        let filelists_href = repomd_href(&repomd, "filelists");
        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/rpm/myrepo/{filelists_href}"),
            "",
        )
        .await;
        let filelists = gunzip(&body_bytes(resp).await);
        assert!(filelists.contains("<file>/usr/bin/hello</file>"));
        assert!(filelists.contains("<file>/etc/hello.conf</file>"));

        // other.xml: changelog present.
        let other_href = repomd_href(&repomd, "other");
        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/rpm/myrepo/{other_href}"),
            "",
        )
        .await;
        let other = gunzip(&body_bytes(resp).await);
        assert!(other.contains("Test Author"), "{other}");
        assert!(other.contains("initial release"));

        // Package downloads back byte-identical.
        let resp = send(
            &ctx.app,
            Method::GET,
            "/rpm/myrepo/Packages/hello-1.0-1.x86_64.rpm",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            "application/x-rpm"
        );
        assert_eq!(&body_bytes(resp).await[..], &body[..]);
    }

    #[tokio::test]
    async fn test_rpm_delete_regenerates_empty_repodata() {
        let ctx = create_test_context();
        let body = build_test_rpm("hello", "1.0");
        send(&ctx.app, Method::PUT, "/rpm/myrepo/hello.rpm", body).await;

        let resp = send(&ctx.app, Method::DELETE, "/rpm/myrepo/hello.rpm", "").await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let resp = send(&ctx.app, Method::GET, "/rpm/myrepo/hello.rpm", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // Repo remains valid, just empty.
        let resp = send(&ctx.app, Method::GET, "/rpm/myrepo/repodata/repomd.xml", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let repomd = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
        let primary_href = repomd_href(&repomd, "primary");
        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/rpm/myrepo/{primary_href}"),
            "",
        )
        .await;
        let primary = gunzip(&body_bytes(resp).await);
        assert!(primary.contains("packages=\"0\""), "{primary}");

        let resp = send(&ctx.app, Method::DELETE, "/rpm/myrepo/hello.rpm", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_rpm_stale_repodata_pruned_on_republish() {
        let ctx = create_test_context();
        send(
            &ctx.app,
            Method::PUT,
            "/rpm/myrepo/a.rpm",
            build_test_rpm("aaa", "1.0"),
        )
        .await;
        let resp = send(&ctx.app, Method::GET, "/rpm/myrepo/repodata/repomd.xml", "").await;
        let repomd_v1 = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
        let primary_v1 = repomd_href(&repomd_v1, "primary");

        send(
            &ctx.app,
            Method::PUT,
            "/rpm/myrepo/b.rpm",
            build_test_rpm("bbb", "2.0"),
        )
        .await;

        // Old generation is gone; exactly repomd.xml + 3 current files remain.
        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/rpm/myrepo/{primary_v1}"),
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let keys = ctx
            .state
            .storage
            .list(&format!("rpm/myrepo/{REPODATA}/"))
            .await
            .unwrap();
        // repomd.xml + .asc + 3 current hashed files.
        assert_eq!(keys.len(), 5, "stale repodata not pruned: {keys:?}");

        // New primary covers both packages, sorted by name.
        let resp = send(&ctx.app, Method::GET, "/rpm/myrepo/repodata/repomd.xml", "").await;
        let repomd_v2 = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
        let primary_v2 = repomd_href(&repomd_v2, "primary");
        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/rpm/myrepo/{primary_v2}"),
            "",
        )
        .await;
        let primary = gunzip(&body_bytes(resp).await);
        assert!(primary.contains("packages=\"2\""));
        let a = primary.find("<name>aaa</name>").unwrap();
        let b = primary.find("<name>bbb</name>").unwrap();
        assert!(a < b, "packages must be sorted by name");
    }

    #[tokio::test]
    async fn test_rpm_upload_rejects_invalid() {
        let ctx = create_test_context();

        // Garbage body.
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/rpm/myrepo/x.rpm",
            b"not an rpm".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Wrong suffix.
        let resp = send(&ctx.app, Method::PUT, "/rpm/myrepo/x.txt", b"data".to_vec()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Server-generated directory.
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/rpm/myrepo/repodata/evil.rpm",
            build_test_rpm("evil", "1.0"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Nothing was stored.
        let keys = ctx.state.storage.list("rpm/").await.unwrap();
        assert!(keys.is_empty(), "rejected uploads must not write: {keys:?}");
    }

    #[tokio::test]
    async fn test_rpm_max_file_size_enforced() {
        let ctx =
            crate::test_helpers::create_test_context_with_config(|c| c.rpm.max_file_size = 16);
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/rpm/myrepo/big.rpm",
            build_test_rpm("big", "1.0"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_rpm_namespace_scope_enforced() {
        use crate::config::ScopeEnforcement;

        let ctx = create_test_context();
        let scoped = |mode| {
            crate::auth::NamespaceAuthority::from_oidc_scope("ci", &["myrepo".to_string()], mode)
        };

        // Out of scope -> 403, nothing written.
        let resp = super::upload(
            axum::extract::State(ctx.state.clone()),
            axum::extract::Path(("otherrepo".to_string(), "x.rpm".to_string())),
            axum::Extension(scoped(ScopeEnforcement::Enforce)),
            axum::body::Bytes::from(build_test_rpm("x", "1.0")),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(ctx.state.storage.list("rpm/").await.unwrap().is_empty());

        // In scope -> created.
        let resp = super::upload(
            axum::extract::State(ctx.state.clone()),
            axum::extract::Path(("myrepo".to_string(), "x.rpm".to_string())),
            axum::Extension(scoped(ScopeEnforcement::Enforce)),
            axum::body::Bytes::from(build_test_rpm("x", "1.0")),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        // DELETE out of scope -> 403.
        let resp = super::delete_package(
            axum::extract::State(ctx.state.clone()),
            axum::extract::Path(("otherrepo".to_string(), "x.rpm".to_string())),
            axum::Extension(scoped(ScopeEnforcement::Enforce)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_rpm_head_and_sidecars_not_served() {
        let ctx = create_test_context();
        let body = build_test_rpm("hello", "1.0");
        let len = body.len();
        send(&ctx.app, Method::PUT, "/rpm/myrepo/hello.rpm", body).await;

        let resp = send(&ctx.app, Method::HEAD, "/rpm/myrepo/hello.rpm", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("content-length")
                .unwrap()
                .to_str()
                .unwrap(),
            len.to_string()
        );

        // The metadata sidecar directory is internal.
        let resp = send(
            &ctx.app,
            Method::GET,
            "/rpm/myrepo/.nora-meta/hello.rpm.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_rpm_disabled_returns_404() {
        let ctx = crate::test_helpers::create_test_context_with_config(|c| c.rpm.enabled = false);
        let resp = send(&ctx.app, Method::GET, "/rpm/myrepo/repodata/repomd.xml", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let resp = send(&ctx.app, Method::PUT, "/rpm/myrepo/x.rpm", b"x".to_vec()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod signing_tests {
    use crate::test_helpers::{
        body_bytes, create_test_context, create_test_context_with_config, send,
    };
    use axum::http::{Method, StatusCode};
    use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};

    fn build_rpm() -> Vec<u8> {
        let pkg = rpm::PackageBuilder::new("sig", "1.0", "MIT", "x86_64", "sig test")
            .release("1")
            .build()
            .unwrap();
        let mut buf = Vec::new();
        pkg.write(&mut buf).unwrap();
        buf
    }

    /// repomd.xml.asc must cryptographically verify against the served
    /// public key over the served repomd.xml bytes (#128).
    #[tokio::test]
    async fn test_rpm_repomd_signature_verifies() {
        let ctx = create_test_context();
        send(&ctx.app, Method::PUT, "/rpm/myrepo/sig.rpm", build_rpm()).await;

        let repomd =
            body_bytes(send(&ctx.app, Method::GET, "/rpm/myrepo/repodata/repomd.xml", "").await)
                .await;

        let resp = send(
            &ctx.app,
            Method::GET,
            "/rpm/myrepo/repodata/repomd.xml.asc",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let asc = body_bytes(resp).await;

        let resp = send(
            &ctx.app,
            Method::GET,
            "/rpm/myrepo/repodata/repomd.xml.key",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            "application/pgp-keys"
        );
        let key = body_bytes(resp).await;

        let (public, _) =
            SignedPublicKey::from_armor_single(std::io::Cursor::new(&key[..])).unwrap();
        let (sig, _) =
            DetachedSignature::from_armor_single(std::io::Cursor::new(&asc[..])).unwrap();
        sig.verify(&public, &repomd[..]).unwrap();
    }

    /// Signature stays consistent across regenerations: after a second
    /// publish the new .asc verifies the new repomd (never the old one).
    #[tokio::test]
    async fn test_rpm_signature_tracks_regeneration() {
        let ctx = create_test_context();
        send(&ctx.app, Method::PUT, "/rpm/myrepo/a.rpm", build_rpm()).await;
        let asc_v1 = body_bytes(
            send(
                &ctx.app,
                Method::GET,
                "/rpm/myrepo/repodata/repomd.xml.asc",
                "",
            )
            .await,
        )
        .await;

        send(&ctx.app, Method::PUT, "/rpm/myrepo/b.rpm", build_rpm()).await;
        let repomd =
            body_bytes(send(&ctx.app, Method::GET, "/rpm/myrepo/repodata/repomd.xml", "").await)
                .await;
        let asc_v2 = body_bytes(
            send(
                &ctx.app,
                Method::GET,
                "/rpm/myrepo/repodata/repomd.xml.asc",
                "",
            )
            .await,
        )
        .await;
        assert_ne!(asc_v1, asc_v2);

        let key = body_bytes(
            send(
                &ctx.app,
                Method::GET,
                "/rpm/myrepo/repodata/repomd.xml.key",
                "",
            )
            .await,
        )
        .await;
        let (public, _) =
            SignedPublicKey::from_armor_single(std::io::Cursor::new(&key[..])).unwrap();
        let (sig, _) =
            DetachedSignature::from_armor_single(std::io::Cursor::new(&asc_v2[..])).unwrap();
        sig.verify(&public, &repomd[..]).unwrap();
    }

    /// Unsigned mode: no signature or key endpoints, and a stale .asc left
    /// over from a previously-signed deployment is removed on regeneration.
    #[tokio::test]
    async fn test_rpm_unsigned_mode_removes_stale_signature() {
        let ctx = create_test_context_with_config(|c| c.signing.enabled = false);
        ctx.state
            .storage
            .put("rpm/myrepo/repodata/repomd.xml.asc", b"stale signature")
            .await
            .unwrap();

        send(&ctx.app, Method::PUT, "/rpm/myrepo/sig.rpm", build_rpm()).await;

        let resp = send(
            &ctx.app,
            Method::GET,
            "/rpm/myrepo/repodata/repomd.xml.asc",
            "",
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "stale .asc must be pruned"
        );
        let resp = send(
            &ctx.app,
            Method::GET,
            "/rpm/myrepo/repodata/repomd.xml.key",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod reindex_tests {
    use crate::test_helpers::{body_bytes, create_test_context, send};
    use axum::http::{Method, StatusCode};

    fn build_rpm(name: &str) -> Vec<u8> {
        let pkg = rpm::PackageBuilder::new(name, "1.0", "MIT", "x86_64", "t")
            .release("1")
            .build()
            .unwrap();
        let mut buf = Vec::new();
        pkg.write(&mut buf).unwrap();
        buf
    }

    async fn primary(ctx: &crate::test_helpers::TestContext) -> String {
        let repomd = String::from_utf8(
            body_bytes(send(&ctx.app, Method::GET, "/rpm/myrepo/repodata/repomd.xml", "").await)
                .await
                .to_vec(),
        )
        .unwrap();
        let start = repomd.find("href=\"").unwrap() + 6;
        let end = repomd[start..].find('"').unwrap() + start;
        let href = &repomd[start..end];
        let resp = send(&ctx.app, Method::GET, &format!("/rpm/myrepo/{href}"), "").await;
        let gz = body_bytes(resp).await;
        let mut out = String::new();
        std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&gz[..]), &mut out)
            .unwrap();
        out
    }

    /// Out-of-band deletion: the package vanishes from storage behind the
    /// API's back; reindex drops the orphan sidecar and the rebuilt (and
    /// re-signed) repodata stops advertising it.
    #[tokio::test]
    async fn test_reindex_heals_out_of_band_delete() {
        let ctx = create_test_context();
        send(
            &ctx.app,
            Method::PUT,
            "/rpm/myrepo/aaa.rpm",
            build_rpm("aaa"),
        )
        .await;
        send(
            &ctx.app,
            Method::PUT,
            "/rpm/myrepo/bbb.rpm",
            build_rpm("bbb"),
        )
        .await;

        // Delete one package directly in storage — the manual-deletion gap.
        ctx.state
            .storage
            .delete("rpm/myrepo/aaa.rpm")
            .await
            .unwrap();
        assert!(
            primary(&ctx).await.contains("<name>aaa</name>"),
            "stale before reindex"
        );

        let resp = send(&ctx.app, Method::POST, "/rpm/myrepo/-/reindex", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert_eq!(body["packages"], 1);
        assert_eq!(body["orphans_removed"], 1);
        assert_eq!(body["signed"], true);

        let p = primary(&ctx).await;
        assert!(
            !p.contains("<name>aaa</name>"),
            "reindex must drop the deleted package"
        );
        assert!(p.contains("<name>bbb</name>"));
        // Signature regenerated alongside.
        let asc = send(
            &ctx.app,
            Method::GET,
            "/rpm/myrepo/repodata/repomd.xml.asc",
            "",
        )
        .await;
        assert_eq!(asc.status(), StatusCode::OK);
    }

    /// Out-of-band addition: a package dropped straight into storage gets
    /// parsed, sidecar'd, and served after reindex.
    #[tokio::test]
    async fn test_reindex_adopts_out_of_band_add() {
        let ctx = create_test_context();
        send(
            &ctx.app,
            Method::PUT,
            "/rpm/myrepo/aaa.rpm",
            build_rpm("aaa"),
        )
        .await;
        ctx.state
            .storage
            .put("rpm/myrepo/ccc.rpm", &build_rpm("ccc"))
            .await
            .unwrap();

        let resp = send(&ctx.app, Method::POST, "/rpm/myrepo/-/reindex", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert_eq!(body["packages"], 2);
        assert_eq!(body["sidecars_created"], 1);

        let p = primary(&ctx).await;
        assert!(
            p.contains("<name>ccc</name>"),
            "adopted package must be served"
        );
    }

    /// Garbage dropped into storage must fail the reindex loudly, not get
    /// silently skipped into a repo that lies about its contents.
    #[tokio::test]
    async fn test_reindex_rejects_invalid_out_of_band_package() {
        let ctx = create_test_context();
        send(
            &ctx.app,
            Method::PUT,
            "/rpm/myrepo/aaa.rpm",
            build_rpm("aaa"),
        )
        .await;
        ctx.state
            .storage
            .put("rpm/myrepo/junk.rpm", b"not an rpm")
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::POST, "/rpm/myrepo/-/reindex", "").await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_reindex_unknown_repo_404s_and_scope_enforced() {
        let ctx = create_test_context();
        let resp = send(&ctx.app, Method::POST, "/rpm/nosuch/-/reindex", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        use crate::config::ScopeEnforcement;
        let scoped = crate::auth::NamespaceAuthority::from_oidc_scope(
            "ci",
            &["otherrepo".to_string()],
            ScopeEnforcement::Enforce,
        );
        let resp = super::reindex(
            axum::extract::State(ctx.state.clone()),
            axum::extract::Path("myrepo".to_string()),
            axum::Extension(scoped),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod proxy_tests {
    use crate::config::registry::RepoProxyEntry;
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Wait for the background `spawn_cache` write to land.
    async fn await_cached(state: &crate::AppState, key: &str) {
        for _ in 0..100 {
            if state.storage.stat(key).await.is_some() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("cache write for {key} never landed");
    }

    #[tokio::test]
    async fn test_rpm_proxy_fetches_caches_then_serves_from_cache() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/Packages/foo-1.0-1.x86_64.rpm"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"rpmbytes".to_vec()))
            .expect(1) // second GET must come from the cache
            .mount(&upstream)
            .await;

        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.rpm.enabled = true;
            cfg.rpm
                .proxies
                .insert("fedora".to_string(), RepoProxyEntry::Simple(uri));
        });

        let resp = send(
            &ctx.app,
            Method::GET,
            "/rpm/fedora/Packages/foo-1.0-1.x86_64.rpm",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"rpmbytes");

        await_cached(&ctx.state, "rpm/fedora/Packages/foo-1.0-1.x86_64.rpm").await;
        let resp = send(
            &ctx.app,
            Method::GET,
            "/rpm/fedora/Packages/foo-1.0-1.x86_64.rpm",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"rpmbytes");
    }

    #[tokio::test]
    async fn test_rpm_proxy_metadata_revalidates_when_ttl_zero() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repodata/repomd.xml"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<repomd/>"))
            .expect(2) // ttl=0 → every GET revalidates upstream
            .mount(&upstream)
            .await;

        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.rpm.enabled = true;
            cfg.rpm.metadata_ttl = 0;
            cfg.rpm
                .proxies
                .insert("fedora".to_string(), RepoProxyEntry::Simple(uri));
        });

        for _ in 0..2 {
            let resp = send(&ctx.app, Method::GET, "/rpm/fedora/repodata/repomd.xml", "").await;
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                resp.headers()
                    .get(axum::http::header::CACHE_CONTROL)
                    .and_then(|v| v.to_str().ok()),
                Some("no-cache"),
                "mutable metadata must not be client-cached"
            );
        }
    }

    #[tokio::test]
    async fn test_rpm_proxy_serves_stale_metadata_when_upstream_down() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&upstream)
            .await;

        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.rpm.enabled = true;
            cfg.rpm.metadata_ttl = 0; // force revalidation so the fetch fails
            cfg.rpm
                .proxies
                .insert("fedora".to_string(), RepoProxyEntry::Simple(uri));
        });
        ctx.state
            .storage
            .put("rpm/fedora/repodata/repomd.xml", b"<repomd-cached/>")
            .await
            .unwrap();

        let resp = send(&ctx.app, Method::GET, "/rpm/fedora/repodata/repomd.xml", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("x-nora-stale")
                .and_then(|v| v.to_str().ok()),
            Some("true")
        );
        assert_eq!(&body_bytes(resp).await[..], b"<repomd-cached/>");
    }

    #[tokio::test]
    async fn test_rpm_proxy_quarantine_enforce_holds_new_package() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"heldrpm".to_vec()))
            .mount(&upstream)
            .await;

        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.rpm.enabled = true;
            cfg.rpm
                .proxies
                .insert("fedora".to_string(), RepoProxyEntry::Simple(uri));
            cfg.curation.rpm.quarantine = Some(crate::digest_quarantine::QuarantineMode::Enforce);
        });

        let resp = send(
            &ctx.app,
            Method::GET,
            "/rpm/fedora/Packages/held-1.0-1.x86_64.rpm",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Metadata is never quarantined — repodata must still flow.
        let resp = send(&ctx.app, Method::GET, "/rpm/fedora/repodata/repomd.xml", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_rpm_proxied_repo_rejects_writes() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.rpm.enabled = true;
            cfg.rpm.proxies.insert(
                "fedora".to_string(),
                RepoProxyEntry::Simple("http://upstream.invalid".to_string()),
            );
        });

        let resp = send(
            &ctx.app,
            Method::PUT,
            "/rpm/fedora/foo-1.0-1.x86_64.rpm",
            "x",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let resp = send(
            &ctx.app,
            Method::DELETE,
            "/rpm/fedora/foo-1.0-1.x86_64.rpm",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let resp = send(&ctx.app, Method::POST, "/rpm/fedora/-/reindex", "").await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        // A hosted repo (not in the proxies map) is untouched by the guard.
        let resp = send(&ctx.app, Method::PUT, "/rpm/hosted/not-an-rpm.txt", "x").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
