// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! `nora mirror go` — fill NORA's Go module proxy with what `go mod download` reads offline.
//!
//! The module versions come from go.mod and go.sum, and each is fetched through NORA's
//! `/go/` proxy, so NORA stores it under the key it serves it from and its curation and
//! quarantine judge it as they judge a `go` client's request. Which files a version needs was
//! measured with the go command (1.22.5) through NORA:
//!
//! - a module that go.mod requires (after its `replace` directives): `.info`, `.mod`, `.zip` —
//!   `go mod download` reads all three;
//! - a version that go.sum lists with a module hash (`<path> <version> h1:…`): the same three —
//!   `go build`, `go test` and `go list -deps -test all` read them;
//! - a version that go.sum lists only with a go.mod hash (`<path> <version>/go.mod h1:…`): the
//!   `.mod` — the go command reads that go.mod to build the module graph, never the code —
//!   unless go.mod's `go` line is older than 1.17 or missing: then `go mod download` downloads
//!   the whole build list (`cmd/go/internal/modcmd/download.go`), and every go.sum version is
//!   fetched in full (measured with go 1.22.5 and 1.26.3);
//! - a requirement on a query rather than a version (`vnext`, `master`): its `.info`, which
//!   names the version, then that version's `.info`, `.mod` and `.zip` — the go command asks
//!   for nothing else, and writes that version into go.mod.
//!
//! Paths and versions are escaped as the go command escapes them (`!` before a lowercase letter
//! for each capital), so the stored key is the one an offline client asks for.

use super::{create_progress_bar, MirrorResult};
use futures::stream::{self, StreamExt};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Which files of a module version the go command reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Need {
    /// Only `.mod`: a version in the module graph whose code is never built.
    GoMod,
    /// `.info`, `.mod` and `.zip`: a version whose code is downloaded.
    Full,
}

impl Need {
    /// The files, in the order the go command asks for them (`.info` first: NORA's curation
    /// reads a release date from it when it judges the `.zip`).
    fn files(self) -> &'static [&'static str] {
        match self {
            Need::GoMod => &["mod"],
            Need::Full => &["info", "mod", "zip"],
        }
    }
}

/// Why go.mod or go.sum cannot be read into a list of module versions.
#[derive(Debug, thiserror::Error)]
pub(super) enum GoListError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}:{line}: {why}")]
    Line {
        path: String,
        line: usize,
        why: LineError,
    },
}

/// What is wrong with one line of go.mod or go.sum.
#[derive(Debug, thiserror::Error)]
pub(super) enum LineError {
    #[error("a requirement is `<module path> <version>`, not `{0}`")]
    Require(String),
    #[error(
        "a replacement is `<module path> [<version>] => <module path> <version>` or \
         `<module path> [<version>] => <directory>`, not `{0}`"
    )]
    Replace(String),
    #[error("a go.sum line is `<module path> <version>[/go.mod] <hash>`, not `{0}`")]
    Sum(String),
    #[error("`{0}` is not a module path")]
    ModulePath(String),
    #[error("`{0}` is not a module version")]
    Version(String),
    #[error("`{0}` is not a module version or a query (a branch, tag or revision)")]
    Query(String),
    #[error(
        "{0} {1}: the go command resolves `{1}` from the module's version list; \
         run `go mod tidy` to write the version it picks into go.mod"
    )]
    ListQuery(String, String),
    #[error("a quoted string is not closed, or has an escape Go does not allow: `{0}`")]
    Quoted(String),
    #[error("the block opened here with `(` is not closed")]
    Unclosed,
}

/// Why one file of a module version did not come back from NORA.
#[derive(Debug, thiserror::Error)]
enum FetchError {
    #[error("{0}")]
    Http(#[from] reqwest::Error),
    #[error("HTTP {0}")]
    Status(reqwest::StatusCode),
    #[error("the .info names no module version: {0}")]
    Info(String),
    #[error("the .info is not JSON with a Version: {0}")]
    InfoJson(#[source] serde_json::Error),
}

/// Where a `replace` directive sends a module.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Replacement {
    /// Another module version, fetched from the proxy instead.
    Module { path: String, version: String },
    /// A directory on disk: nothing to fetch.
    Directory,
}

/// A `replace` directive: for every version of `path`, or only for `version`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Replace {
    path: String,
    version: Option<String>,
    to: Replacement,
}

/// The requirements and replacements of a go.mod.
#[derive(Debug, Default, PartialEq, Eq)]
struct GoMod {
    /// The version on the `go` line, if there is one.
    go: Option<String>,
    requires: Vec<(String, String)>,
    replaces: Vec<Replace>,
}

impl GoMod {
    /// Whether `go mod download` downloads the whole build list rather than the required modules
    /// only: the `go` line is missing or older than 1.17 (`download.go`: `modFile.Go == nil ||
    /// gover.Compare(modFile.Go.Version, "1.17") < 0`). In `gover` order no `1.17…` is below
    /// 1.17, so the major and minor numbers decide; a line they cannot be read from counts as
    /// old, which fetches more, never less.
    fn downloads_build_list(&self) -> bool {
        let Some(go) = &self.go else {
            return true;
        };
        let number = |s: Option<&str>| {
            let s = s.unwrap_or("");
            let digits = s.bytes().take_while(u8::is_ascii_digit).count();
            s[..digits].parse::<u64>().ok()
        };
        let mut parts = go.splitn(3, '.');
        match (number(parts.next()), number(parts.next())) {
            (Some(1), Some(minor)) => minor < 17,
            (Some(major), _) => major < 1,
            (None, _) => true,
        }
    }

    /// The module versions the go command fetches for the requirements: each one replaced as
    /// a `replace` directive says (one naming the version wins over one for every version),
    /// none for a module replaced by a directory.
    fn fetched(&self) -> Vec<(String, String)> {
        self.requires
            .iter()
            .filter_map(|(path, version)| {
                let replace = self
                    .replaces
                    .iter()
                    .find(|r| r.path == *path && r.version.as_deref() == Some(version.as_str()))
                    .or_else(|| {
                        self.replaces
                            .iter()
                            .find(|r| r.path == *path && r.version.is_none())
                    });
                match replace.map(|r| &r.to) {
                    None => Some((path.clone(), version.clone())),
                    Some(Replacement::Module { path, version }) => {
                        Some((path.clone(), version.clone()))
                    }
                    Some(Replacement::Directory) => None,
                }
            })
            .collect()
    }
}

/// A module path the go command accepts, as far as a URL needs: non-empty elements of ASCII
/// letters, digits, `-`, `.`, `_` and `~`, none of them `.` or `..`.
fn is_module_path(path: &str) -> bool {
    !path.is_empty()
        && path.split('/').all(|e| {
            !e.is_empty()
                && e != "."
                && e != ".."
                && e.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
        })
}

/// A module version as go.mod and go.sum write it: `v` and then semantic-version characters
/// (a pseudo-version and `+incompatible` included).
fn is_version(version: &str) -> bool {
    version.len() > 1
        && version.starts_with('v')
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+'))
}

/// What a requirement may name instead of a version, as far as a URL needs: a branch, tag or
/// revision of letters, digits, `-`, `.`, `_`, `~` and `+`, starting with a letter or digit.
/// The go command resolves it through `@v/<query>.info`.
fn is_query(query: &str) -> bool {
    query
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && query
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+'))
}

/// A query the go command resolves from the module's version list (`@v/list`, `@latest`)
/// rather than from `@v/<query>.info` (`modload/query.go`, `newQueryMatcher`): `latest`,
/// `upgrade`, `patch` and a semantic-version prefix (`v1`, `v1.2`). Every other query that is not
/// a version is a revision query (a branch, tag or commit), resolved through its `.info`.
fn is_list_query(query: &str) -> bool {
    let numeric = |s: &str| {
        !s.is_empty()
            && s.bytes().all(|b| b.is_ascii_digit())
            && (s.len() == 1 || !s.starts_with('0'))
    };
    matches!(query, "latest" | "upgrade" | "patch")
        || query.strip_prefix('v').is_some_and(|rest| {
            let parts: Vec<&str> = rest.split('.').collect();
            parts.len() <= 2 && parts.iter().all(|p| numeric(p))
        })
}

/// A replacement target without a version, which go.mod allows only for a directory: the go
/// command's `modfile.IsDirectoryPath`, Unix and Windows forms both.
fn is_directory(target: &str) -> bool {
    let b = target.as_bytes();
    matches!(target, "." | "..")
        || ["./", ".\\", "../", "..\\"]
            .iter()
            .any(|p| target.starts_with(p))
        || target.starts_with('/')
        || target.starts_with('\\')
        || (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
}

/// Escape a module path or version as the go command does in a proxy URL: each capital becomes
/// `!` and its lowercase letter (`github.com/BurntSushi` → `github.com/!burnt!sushi`).
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// One token of a go.mod line, as the go command's lexer (`modfile/read.go`) splits it: a word,
/// a punctuation mark or a quoted string, with its quotes taken off and its escapes read.
#[derive(Debug, PartialEq, Eq)]
struct Token {
    text: String,
    quoted: bool,
}

impl Token {
    /// Whether this is the punctuation mark `mark`, not a string that holds it.
    fn is(&self, mark: &str) -> bool {
        !self.quoted && self.text == mark
    }
}

/// Punctuation the go.mod lexer makes a token of its own.
fn is_punctuation(c: char) -> bool {
    matches!(c, '(' | ')' | '[' | ']' | '{' | '}' | ',')
}

/// The escapes of a `"…"` string, read as Go's `strconv.Unquote` reads them; `None` for one it
/// refuses. A byte escape above ASCII becomes the character of that code, which no module path
/// or directory prefix holds.
fn unescape(body: &str) -> Option<String> {
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    // The character of the next `n` digits in `radix`.
    fn code(chars: &mut std::str::Chars, n: usize, radix: u32) -> Option<char> {
        let digits: String = chars.by_ref().take(n).collect();
        if digits.chars().count() != n {
            return None;
        }
        u32::from_str_radix(&digits, radix)
            .ok()
            .and_then(char::from_u32)
    }
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let e = chars.next()?;
        out.push(match e {
            'a' => '\u{7}',
            'b' => '\u{8}',
            'f' => '\u{c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'v' => '\u{b}',
            '\\' => '\\',
            '"' => '"',
            'x' => code(&mut chars, 2, 16)?,
            'u' => code(&mut chars, 4, 16)?,
            'U' => code(&mut chars, 8, 16)?,
            '0'..='7' => {
                let rest = u32::from(code(&mut chars, 2, 8)?);
                let value = e.to_digit(8)? * 64 + rest;
                if value > 0xff {
                    return None;
                }
                char::from_u32(value)?
            }
            _ => return None,
        });
    }
    Some(out)
}

/// Split one go.mod line into tokens: `//` outside a string starts a comment, a `"…"` or
/// `` `…` `` string is one token whatever it holds (a space or `//` included) and ends on the
/// same line.
fn lex(line: &str) -> Result<Vec<Token>, LineError> {
    let quoted = || LineError::Quoted(line.trim().to_string());
    let mut tokens = Vec::new();
    let mut rest = line;
    loop {
        rest = rest.trim_start_matches([' ', '\t', '\r']);
        let Some(c) = rest.chars().next() else {
            return Ok(tokens);
        };
        if rest.starts_with("//") {
            return Ok(tokens);
        }
        if is_punctuation(c) {
            tokens.push(Token {
                text: c.to_string(),
                quoted: false,
            });
            rest = &rest[1..];
        } else if c == '"' || c == '`' {
            // The closing quote: the first one not escaped (a raw string has no escapes).
            let body = &rest[1..];
            let mut end = None;
            let mut escaped = false;
            for (i, d) in body.char_indices() {
                if escaped {
                    escaped = false;
                } else if d == '\\' && c == '"' {
                    escaped = true;
                } else if d == c {
                    end = Some(i);
                    break;
                }
            }
            let end = end.ok_or_else(quoted)?;
            let text = if c == '"' {
                unescape(&body[..end]).ok_or_else(quoted)?
            } else {
                body[..end].to_string()
            };
            tokens.push(Token { text, quoted: true });
            rest = &body[end + 1..];
        } else {
            let end = rest
                .char_indices()
                .find(|&(i, d)| {
                    d.is_whitespace() || is_punctuation(d) || rest[i..].starts_with("//")
                })
                .map_or(rest.len(), |(i, _)| i);
            tokens.push(Token {
                text: rest[..end].to_string(),
                quoted: false,
            });
            rest = &rest[end..];
        }
    }
}

/// A module path and a version or query read from a requirement or a replacement target, both
/// checked; the go command resolves a query (`vnext`, `master`) to a version.
fn module_query(path: &str, query: &str) -> Result<(String, String), LineError> {
    if !is_module_path(path) {
        return Err(LineError::ModulePath(path.to_string()));
    }
    if !is_query(query) {
        return Err(LineError::Query(query.to_string()));
    }
    if is_list_query(query) {
        return Err(LineError::ListQuery(path.to_string(), query.to_string()));
    }
    Ok((path.to_string(), query.to_string()))
}

/// A module path and version read from go.sum, both checked.
fn module_version(path: &str, version: &str) -> Result<(String, String), LineError> {
    if !is_module_path(path) {
        return Err(LineError::ModulePath(path.to_string()));
    }
    if !is_version(version) {
        return Err(LineError::Version(version.to_string()));
    }
    Ok((path.to_string(), version.to_string()))
}

/// One requirement: `<module path> <version>`.
fn parse_require(tokens: &[Token], line: &str) -> Result<(String, String), LineError> {
    match tokens {
        [path, version] => module_query(&path.text, &version.text),
        _ => Err(LineError::Require(line.to_string())),
    }
}

/// One replacement: `<path> [<version>] => <path> <version>` or `… => <directory>`.
fn parse_replace(tokens: &[Token], line: &str) -> Result<Replace, LineError> {
    let bad = || LineError::Replace(line.to_string());
    let arrow = tokens.iter().position(|t| t.is("=>")).ok_or_else(bad)?;
    let (from, to) = (&tokens[..arrow], &tokens[arrow + 1..]);
    let (path, version) = match from {
        [path] => (path.text.as_str(), None),
        [path, version] => (path.text.as_str(), Some(version.text.as_str())),
        _ => return Err(bad()),
    };
    if !is_module_path(path) {
        return Err(LineError::ModulePath(path.to_string()));
    }
    if let Some(v) = version {
        if !is_version(v) {
            return Err(LineError::Version(v.to_string()));
        }
    }
    let to = match to {
        [target, version] => {
            let (path, version) = module_query(&target.text, &version.text)?;
            Replacement::Module { path, version }
        }
        [target] if is_directory(&target.text) => Replacement::Directory,
        _ => return Err(bad()),
    };
    Ok(Replace {
        path: path.to_string(),
        version: version.map(str::to_string),
        to,
    })
}

/// Read the `go`, `require` and `replace` directives of a go.mod, single-line and in blocks;
/// every other directive is ignored. A directive that cannot be read fails with its line number:
/// skipping it would leave a module out of the store and still report success.
fn parse_go_mod(content: &str) -> Result<GoMod, (usize, LineError)> {
    let mut go_mod = GoMod::default();
    // The verb of the open block and the line that opened it.
    let mut block: Option<(String, usize)> = None;
    for (i, raw) in content.lines().enumerate() {
        let n = i + 1;
        let tokens = lex(raw).map_err(|e| (n, e))?;
        let Some(first) = tokens.first() else {
            continue;
        };
        let line = raw.trim();
        let (verb, args): (String, &[Token]) = match &block {
            Some(_) if tokens.len() == 1 && first.is(")") => {
                block = None;
                continue;
            }
            Some((verb, _)) => (verb.clone(), &tokens[..]),
            None => {
                // `require (` and `require(` both open a block.
                if tokens.get(1).is_some_and(|t| t.is("(")) {
                    block = Some((first.text.clone(), n));
                    continue;
                }
                (first.text.clone(), &tokens[1..])
            }
        };
        match verb.as_str() {
            "go" => go_mod.go = args.first().map(|t| t.text.clone()),
            "require" => go_mod
                .requires
                .push(parse_require(args, line).map_err(|e| (n, e))?),
            "replace" => go_mod
                .replaces
                .push(parse_replace(args, line).map_err(|e| (n, e))?),
            _ => {}
        }
    }
    if let Some((_, opened)) = block {
        return Err((opened, LineError::Unclosed));
    }
    Ok(go_mod)
}

/// Read a go.sum: each line names a module version with a module hash (its code is needed) or
/// a go.mod hash (`<version>/go.mod`: only its go.mod is).
fn parse_go_sum(content: &str) -> Result<Vec<(String, String, Need)>, (usize, LineError)> {
    let mut out = Vec::new();
    for (i, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let [path, version, _hash] = tokens[..] else {
            return Err((i + 1, LineError::Sum(line.to_string())));
        };
        let (version, need) = match version.strip_suffix("/go.mod") {
            Some(v) => (v, Need::GoMod),
            None => (version, Need::Full),
        };
        let (path, version) = module_version(path, version).map_err(|e| (i + 1, e))?;
        out.push((path, version, need));
    }
    Ok(out)
}

fn read(path: &Path) -> Result<String, GoListError> {
    std::fs::read_to_string(path).map_err(|source| GoListError::Read {
        path: path.display().to_string(),
        source,
    })
}

/// Every module version to fetch and the files it needs: go.mod's requirements in full, and
/// what go.sum lists — in full too when go.mod's `go` line makes `go mod download` download the
/// whole build list — deduplicated (a version needed in full and for its go.mod is fetched in
/// full), in a stable order.
fn module_versions(
    modfile: &Path,
    sumfile: Option<&Path>,
) -> Result<BTreeMap<(String, String), Need>, GoListError> {
    let at = |path: &Path| {
        let path = path.display().to_string();
        move |(line, why)| GoListError::Line { path, line, why }
    };
    let go_mod = parse_go_mod(&read(modfile)?).map_err(at(modfile))?;
    let mut versions = BTreeMap::new();
    for key in go_mod.fetched() {
        versions.insert(key, Need::Full);
    }
    let build_list = go_mod.downloads_build_list();
    if let Some(sumfile) = sumfile {
        for (path, version, need) in parse_go_sum(&read(sumfile)?).map_err(at(sumfile))? {
            let need = if build_list { Need::Full } else { need };
            let entry = versions.entry((path, version)).or_insert(need);
            *entry = (*entry).max(need);
        }
    }
    Ok(versions)
}

/// GET `url` through NORA and read the body to its end, counting its bytes without holding
/// them (a module zip can be up to NORA's size limit).
async fn fetch(client: &reqwest::Client, url: &str) -> Result<u64, FetchError> {
    let mut resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        return Err(FetchError::Status(resp.status()));
    }
    let mut n = 0u64;
    while let Some(chunk) = resp.chunk().await? {
        n += chunk.len() as u64;
    }
    Ok(n)
}

/// The most of a `.info` read: it is a line of JSON.
const INFO_LIMIT: usize = 64 * 1024;

/// GET the `.info` of a query (`vnext`, `master`) through NORA and read the version it names,
/// which is what the go command asks for next. The version must be canonical: it is what the go
/// command writes into go.mod.
async fn resolve(client: &reqwest::Client, url: &str) -> Result<(u64, String), FetchError> {
    #[derive(serde::Deserialize)]
    struct Info {
        #[serde(rename = "Version")]
        version: String,
    }
    let mut resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        return Err(FetchError::Status(resp.status()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        body.extend_from_slice(&chunk);
        if body.len() > INFO_LIMIT {
            return Err(FetchError::Info(format!("over {INFO_LIMIT} bytes")));
        }
    }
    let info: Info = serde_json::from_slice(&body).map_err(FetchError::InfoJson)?;
    if !crate::registry::is_canonical_go_version(&info.version) {
        return Err(FetchError::Info(format!("`{}`", info.version)));
    }
    Ok((body.len() as u64, info.version))
}

/// Fetch the files of one module version, in order. A requirement on a query is first resolved
/// through its `.info` (kept in the store: an offline `go mod download` asks for it) and then the
/// files of the version it names are fetched, as the go command fetches them. Every file is
/// asked for even after one fails, so the store holds as much as NORA can serve; the version
/// counts as failed if any did.
async fn fetch_version(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    version: &str,
    need: Need,
) -> (u64, Vec<(String, FetchError)>) {
    let path_e = escape(path);
    let url = |version: &str, ext: &str| format!("{base}/go/{path_e}/@v/{}.{ext}", escape(version));
    let mut bytes = 0;
    let mut misses = Vec::new();
    let mut version = version.to_string();
    if need == Need::Full && !crate::registry::is_canonical_go_version(&version) {
        match resolve(client, &url(&version, "info")).await {
            Ok((n, resolved)) => {
                bytes += n;
                version = resolved;
            }
            Err(e) => {
                misses.push((format!("{version}.info"), e));
                return (bytes, misses);
            }
        }
    }
    for ext in need.files() {
        match fetch(client, &url(&version, ext)).await {
            Ok(n) => bytes += n,
            Err(e) => misses.push((format!("{version}.{ext}"), e)),
        }
    }
    (bytes, misses)
}

/// `nora mirror go`: fetch through NORA every module version that `go.mod` requires and that
/// `go.sum` lists — `sumfile`, or the go.sum beside go.mod when there is one — so that the go
/// command, with `GOPROXY` set to NORA, downloads the module offline.
pub(super) async fn run_go_mirror(
    client: &reqwest::Client,
    registry: &str,
    modfile: &Path,
    sumfile: Option<PathBuf>,
    concurrency: usize,
) -> Result<MirrorResult, GoListError> {
    let sumfile = match sumfile {
        Some(path) => Some(path),
        None => {
            let beside = modfile.with_file_name("go.sum");
            if beside.is_file() {
                Some(beside)
            } else {
                eprintln!(
                    "  NOTE: no go.sum beside {}: only the modules go.mod requires are fetched. \
                     `go mod download` also reads the go.mod of the versions go.sum lists; \
                     pass --sumfile, or run `go mod tidy` first.",
                    modfile.display()
                );
                None
            }
        }
    };
    let versions = module_versions(modfile, sumfile.as_deref())?;
    if versions.is_empty() {
        println!("No modules found in {}", modfile.display());
        return Ok(MirrorResult {
            total: 0,
            fetched: 0,
            failed: 0,
            bytes: 0,
        });
    }
    println!(
        "Mirroring {} Go module versions via {}...",
        versions.len(),
        registry
    );

    let base = registry.trim_end_matches('/');
    let pb = create_progress_bar(versions.len() as u64);
    let mut done = stream::iter(versions.iter())
        .map(|((path, version), need)| async move {
            let (bytes, misses) = fetch_version(client, base, path, version, *need).await;
            (path, version, bytes, misses)
        })
        .buffer_unordered(concurrency.max(1));

    let (mut fetched, mut failed, mut bytes) = (0, 0, 0u64);
    while let Some((path, version, n, misses)) = done.next().await {
        bytes += n;
        if misses.is_empty() {
            fetched += 1;
        } else {
            failed += 1;
            for (file, e) in &misses {
                pb.suspend(|| eprintln!("  WARN: {path}@{version}: {file} -> {e}"));
            }
        }
        pb.set_message(format!("{path}@{version}"));
        pb.inc(1);
    }
    pb.finish_with_message("done");

    Ok(MirrorResult {
        total: versions.len(),
        fetched,
        failed,
        bytes,
    })
}

/// #1185: what `nora mirror go` leaves in the store must serve an offline `go` client. Each test
/// runs the command as the CLI parses it (`nora mirror go --modfile …`) against a NORA served
/// over a socket, with a fake Go module proxy as its upstream; then a second NORA over the same
/// store and with no upstream answers what the client asks. The files the client asks for were
/// measured with go 1.22.5 through NORA: `go mod download` reads the `.info`, `.mod` and `.zip`
/// of every module that go.mod requires and only the `.mod` of every version that go.sum lists
/// with a `/go.mod` hash; `go list -deps -test all` also reads the `.info` and `.zip` of every
/// version that go.sum lists with a module hash.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod offline_seed_tests {
    use super::super::{run_mirror, MirrorFormat};
    use crate::test_helpers::{
        body_bytes, create_test_context_in_memory, create_test_context_with_storage_and_config,
        send, TestContext,
    };
    use axum::http::{Method, StatusCode};
    use clap::Parser;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// `nora mirror <format>`, parsed as the CLI parses it.
    #[derive(Parser)]
    struct MirrorCli {
        #[command(subcommand)]
        format: MirrorFormat,
    }

    /// Run `nora mirror <args…>` against the NORA at `url`: `None` when it succeeds, the error
    /// it ends with otherwise (an argument clap refuses included).
    async fn mirror(url: &str, args: &[&str]) -> Option<String> {
        let cli = match MirrorCli::try_parse_from(
            std::iter::once("mirror").chain(args.iter().copied()),
        ) {
            Ok(cli) => cli,
            Err(e) => return Some(e.to_string()),
        };
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        run_mirror(cli.format, url, 4, false, &client).await.err()
    }

    /// NORA over a socket, as the mirror (an HTTP client of a running NORA) reaches it. The
    /// server stops when this drops.
    struct Served {
        url: String,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Served {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn serve(ctx: &TestContext) -> Served {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = ctx.app.clone();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Served {
            url: format!("http://{addr}"),
            task,
        }
    }

    /// NORA proxying Go modules from `upstream`, over a store in memory.
    fn online(upstream: &MockServer) -> TestContext {
        let uri = upstream.uri();
        create_test_context_in_memory(|cfg| cfg.go.proxy = Some(uri))
    }

    /// NORA restarted on the same store without an upstream: what an offline client gets is only
    /// what the store holds.
    fn offline(ctx: &TestContext) -> TestContext {
        create_test_context_with_storage_and_config(ctx.state.storage.clone(), |cfg| {
            cfg.go.proxy = None;
        })
    }

    async fn get(ctx: &TestContext, uri: &str) -> (StatusCode, Vec<u8>) {
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        let status = resp.status();
        (status, body_bytes(resp).await.to_vec())
    }

    /// Ask `uri` until it answers 200, up to a deadline: what the mirror fetched is written by
    /// NORA's cache task after NORA answers (on a store in memory, at its first yield).
    async fn get_ok(ctx: &TestContext, uri: &str) -> Vec<u8> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let (status, body) = get(ctx, uri).await;
            if status == StatusCode::OK {
                return body;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{uri} offline: {status}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    fn write(dir: &std::path::Path, name: &str, content: &str) -> String {
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        p.to_str().unwrap().to_string()
    }

    /// The bytes the fake upstream serves for one file: distinct per file, so a file served from
    /// the wrong key does not pass.
    fn body_of(escaped_module: &str, escaped_version: &str, ext: &str) -> Vec<u8> {
        match ext {
            "info" => format!(
                "{{\"Version\":\"{escaped_version}\",\"Time\":\"2024-01-02T03:04:05Z\",\"For\":\"{escaped_module}\"}}"
            )
            .into_bytes(),
            "mod" => format!("module {escaped_module} // {escaped_version}\n").into_bytes(),
            _ => format!("PK zip of {escaped_module}@{escaped_version}").into_bytes(),
        }
    }

    /// Mount the file `<module>/@v/<version>.<ext>` (escaped as the go client escapes it) on the
    /// fake upstream, expecting it to be asked for `times` times.
    async fn upstream_file(
        upstream: &MockServer,
        escaped_module: &str,
        escaped_version: &str,
        ext: &str,
        times: u64,
    ) {
        Mock::given(method("GET"))
            .and(path(format!(
                "/{escaped_module}/@v/{escaped_version}.{ext}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body_of(
                escaped_module,
                escaped_version,
                ext,
            )))
            .expect(times)
            .mount(upstream)
            .await;
    }

    /// Offline, NORA serves `<module>/@v/<version>.<ext>` with the upstream's bytes.
    async fn assert_offline(
        ctx: &TestContext,
        escaped_module: &str,
        escaped_version: &str,
        ext: &str,
    ) {
        let got = get_ok(
            ctx,
            &format!("/go/{escaped_module}/@v/{escaped_version}.{ext}"),
        )
        .await;
        assert_eq!(
            got,
            body_of(escaped_module, escaped_version, ext),
            "{escaped_module}@{escaped_version}.{ext}"
        );
    }

    /// Paths the fake upstream was asked for.
    async fn asked(upstream: &MockServer) -> Vec<String> {
        upstream
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }

    const GO_MOD: &str = "\
module example.com/app

go 1.21

require (
\tgithub.com/Upper/Mod v1.2.0
\texample.com/incompat v3.0.0+incompatible
\texample.com/rc v1.0.0-RC1 // a prerelease with capitals
)

require example.com/indirect v0.3.0 // indirect
";

    const GO_SUM: &str = "\
example.com/incompat v3.0.0+incompatible h1:AAAA=
example.com/incompat v3.0.0+incompatible/go.mod h1:BBBB=
example.com/indirect v0.3.0 h1:CCCC=
example.com/indirect v0.3.0/go.mod h1:DDDD=
example.com/old v0.1.0/go.mod h1:EEEE=
example.com/rc v1.0.0-RC1 h1:FFFF=
example.com/rc v1.0.0-RC1/go.mod h1:GGGG=
example.com/testonly v0.2.0 h1:HHHH=
example.com/testonly v0.2.0/go.mod h1:IIII=
github.com/Upper/Mod v1.2.0 h1:JJJJ=
github.com/Upper/Mod v1.2.0/go.mod h1:KKKK=
";

    /// The module versions that `go mod download` reads in full (`.info`, `.mod`, `.zip`), as
    /// the go client escapes them.
    const FULL: &[(&str, &str)] = &[
        ("github.com/!upper/!mod", "v1.2.0"),
        ("example.com/incompat", "v3.0.0+incompatible"),
        ("example.com/rc", "v1.0.0-!r!c1"),
        ("example.com/indirect", "v0.3.0"),
        ("example.com/testonly", "v0.2.0"),
    ];

    #[tokio::test]
    async fn go_mirror_leaves_what_go_mod_download_reads_offline() {
        let upstream = MockServer::start().await;
        for (m, v) in FULL {
            for ext in ["info", "mod", "zip"] {
                upstream_file(&upstream, m, v, ext, 1).await;
            }
        }
        // A version go.sum lists only with a `/go.mod` hash: the client reads its go.mod for the
        // module graph, never its code.
        upstream_file(&upstream, "example.com/old", "v0.1.0", "mod", 1).await;
        upstream_file(&upstream, "example.com/old", "v0.1.0", "info", 0).await;
        upstream_file(&upstream, "example.com/old", "v0.1.0", "zip", 0).await;

        let dir = tempfile::tempdir().unwrap();
        let modfile = write(dir.path(), "go.mod", GO_MOD);
        // go.sum beside go.mod is read without being named.
        write(dir.path(), "go.sum", GO_SUM);

        let ctx = online(&upstream);
        let nora = serve(&ctx).await;
        let failure = mirror(&nora.url, &["go", "--modfile", &modfile]).await;
        assert!(failure.is_none(), "mirror: {failure:?}");

        let off = offline(&ctx);
        for (m, v) in FULL {
            for ext in ["info", "mod", "zip"] {
                assert_offline(&off, m, v, ext).await;
            }
        }
        assert_offline(&off, "example.com/old", "v0.1.0", "mod").await;
        // Each file once, even when go.mod and go.sum both name its version; nothing more.
        upstream.verify().await;
    }

    #[tokio::test]
    async fn go_mirror_follows_replace_and_skips_a_local_one() {
        let upstream = MockServer::start().await;
        for ext in ["info", "mod", "zip"] {
            upstream_file(&upstream, "example.com/fork", "v1.0.1", ext, 1).await;
            upstream_file(&upstream, "example.com/!fork!two", "v2.0.0", ext, 1).await;
        }

        let dir = tempfile::tempdir().unwrap();
        let modfile = write(
            dir.path(),
            "go.mod",
            "module example.com/app\n\ngo 1.21\n\nrequire (\n\
             \texample.com/orig v1.0.0\n\
             \texample.com/other v0.5.0\n\
             \texample.com/local v0.0.0-00010101000000-000000000000\n\
             \texample.com/spaced v0.0.0-00010101000000-000000000000\n\
             )\n\n\
             replace (\n\
             \texample.com/orig v1.0.0 => example.com/fork v1.0.1\n\
             \texample.com/local => ../local\n\
             )\n\n\
             replace example.com/spaced => \"../local module\" // a directory with a space\n\
             replace example.com/other => example.com/ForkTwo v2.0.0\n",
        );
        // go.sum elsewhere, named on the command line; go writes it for the replacements only.
        let sums = tempfile::tempdir().unwrap();
        let sumfile = write(
            sums.path(),
            "go.sum",
            "example.com/ForkTwo v2.0.0 h1:AAAA=\n\
             example.com/ForkTwo v2.0.0/go.mod h1:BBBB=\n\
             example.com/fork v1.0.1 h1:CCCC=\n\
             example.com/fork v1.0.1/go.mod h1:DDDD=\n",
        );

        let ctx = online(&upstream);
        let nora = serve(&ctx).await;
        let failure = mirror(
            &nora.url,
            &["go", "--modfile", &modfile, "--sumfile", &sumfile],
        )
        .await;
        assert!(failure.is_none(), "mirror: {failure:?}");

        let off = offline(&ctx);
        for ext in ["info", "mod", "zip"] {
            assert_offline(&off, "example.com/fork", "v1.0.1", ext).await;
            assert_offline(&off, "example.com/!fork!two", "v2.0.0", ext).await;
        }
        let paths = asked(&upstream).await;
        for replaced in [
            "/example.com/orig/",
            "/example.com/other/",
            "/example.com/local/",
            "/example.com/spaced/",
        ] {
            assert!(
                !paths.iter().any(|p| p.starts_with(replaced)),
                "a replaced module was fetched: {paths:?}"
            );
        }
        upstream.verify().await;
    }

    /// go 1.22.5 and 1.26.3, measured against a logging fake proxy: for `require <module> vnext`
    /// (or `master`) `go mod download` asks `@v/vnext.info`, then the `.mod` and `.zip` of the
    /// version that `.info` names, and writes that version into go.mod; `go build` then asks its
    /// `.info`. It never asks for `vnext.mod` or `vnext.zip`.
    #[tokio::test]
    async fn go_mirror_resolves_a_branch_requirement_through_its_info() {
        let upstream = MockServer::start().await;
        for (m, query, version) in [
            (
                "example.com/c",
                "vnext",
                "v0.0.0-20240102030405-abcdefabcdef",
            ),
            ("example.com/d", "master", "v1.2.3"),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/{m}/@v/{query}.info")))
                .respond_with(
                    ResponseTemplate::new(200).set_body_bytes(body_of(m, version, "info")),
                )
                .expect(1)
                .mount(&upstream)
                .await;
            for ext in ["info", "mod", "zip"] {
                upstream_file(&upstream, m, version, ext, 1).await;
            }
            for ext in ["mod", "zip"] {
                upstream_file(&upstream, m, query, ext, 0).await;
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let modfile = write(
            dir.path(),
            "go.mod",
            "module example.com/app\n\ngo 1.21\n\n\
             require (\n\texample.com/c vnext\n\texample.com/d master\n)\n",
        );
        let ctx = online(&upstream);
        let nora = serve(&ctx).await;
        let failure = mirror(&nora.url, &["go", "--modfile", &modfile]).await;
        assert!(failure.is_none(), "mirror: {failure:?}");

        let off = offline(&ctx);
        for (m, query, version) in [
            (
                "example.com/c",
                "vnext",
                "v0.0.0-20240102030405-abcdefabcdef",
            ),
            ("example.com/d", "master", "v1.2.3"),
        ] {
            // The query answers offline with the version it named.
            let got = get_ok(&off, &format!("/go/{m}/@v/{query}.info")).await;
            assert_eq!(got, body_of(m, version, "info"), "{m}@{query}.info");
            for ext in ["info", "mod", "zip"] {
                assert_offline(&off, m, version, ext).await;
            }
        }
        upstream.verify().await;
    }

    #[tokio::test]
    async fn go_mirror_fails_when_a_file_is_not_fetched() {
        let upstream = MockServer::start().await;
        for ext in ["info", "mod", "zip"] {
            upstream_file(&upstream, "example.com/good", "v1.0.0", ext, 1).await;
        }
        for ext in ["info", "mod"] {
            upstream_file(&upstream, "example.com/broken", "v1.0.0", ext, 1).await;
        }
        Mock::given(method("GET"))
            .and(path("/example.com/broken/@v/v1.0.0.zip"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&upstream)
            .await;
        // `example.com/gone v0.1.0/go.mod` is listed in go.sum, and the upstream has no such file.

        let dir = tempfile::tempdir().unwrap();
        let modfile = write(
            dir.path(),
            "go.mod",
            "module example.com/app\n\ngo 1.21\n\n\
             require (\n\texample.com/good v1.0.0\n\texample.com/broken v1.0.0\n)\n",
        );
        write(
            dir.path(),
            "go.sum",
            "example.com/broken v1.0.0 h1:AAAA=\n\
             example.com/broken v1.0.0/go.mod h1:BBBB=\n\
             example.com/gone v0.1.0/go.mod h1:CCCC=\n\
             example.com/good v1.0.0 h1:DDDD=\n\
             example.com/good v1.0.0/go.mod h1:EEEE=\n",
        );

        let ctx = online(&upstream);
        let nora = serve(&ctx).await;
        let err = mirror(&nora.url, &["go", "--modfile", &modfile])
            .await
            .expect("a module whose zip or go.mod NORA cannot serve fails the mirror");
        assert!(err.starts_with("2 "), "two module versions failed: {err}");

        let off = offline(&ctx);
        for ext in ["info", "mod", "zip"] {
            assert_offline(&off, "example.com/good", "v1.0.0", ext).await;
        }
    }

    #[tokio::test]
    async fn go_mirror_refuses_a_go_mod_it_cannot_read() {
        let upstream = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        // A requirement without a version names no files: reading past it would leave a module
        // out of the store and report success.
        let modfile = write(
            dir.path(),
            "go.mod",
            "module example.com/app\n\ngo 1.21\n\nrequire (\n\texample.com/a v1.0.0\n\texample.com/b\n)\n",
        );
        let ctx = online(&upstream);
        let nora = serve(&ctx).await;
        let err = mirror(&nora.url, &["go", "--modfile", &modfile])
            .await
            .expect("an unreadable go.mod fails before anything is fetched");
        assert!(
            err.contains("go.mod") && err.contains(":7"),
            "names the line: {err}"
        );
        assert!(asked(&upstream).await.is_empty(), "nothing is fetched");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// go.mod and go.sum of a small real project, as `go mod tidy` (go 1.22.5) wrote them.
    const MEASURED_GO_MOD: &str = "\
module example.com/offline

go 1.21

require (
\tgithub.com/BurntSushi/toml v1.3.2
\tgithub.com/golang-jwt/jwt v3.2.2+incompatible
\tgithub.com/google/uuid v1.6.0
\tgithub.com/sirupsen/logrus v1.9.3
\tgithub.com/stretchr/testify v1.8.4
\tgolang.org/x/sync v0.6.0
\tgopkg.in/yaml.v3 v3.0.1
)

require (
\tgithub.com/davecgh/go-spew v1.1.1 // indirect
\tgithub.com/pmezard/go-difflib v1.0.0 // indirect
\tgolang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 // indirect
)
";

    const MEASURED_GO_SUM: &str = "\
github.com/BurntSushi/toml v1.3.2 h1:o7IhLm0Msx3BaB+n3Ag7L8EVlByGnpq14C4YWiu/gL8=
github.com/BurntSushi/toml v1.3.2/go.mod h1:CxXYINrC8qIiEnFrOxCa7Jy5BFHlXnUU2pbicEuybxQ=
github.com/davecgh/go-spew v1.1.0/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/davecgh/go-spew v1.1.1 h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=
github.com/davecgh/go-spew v1.1.1/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/golang-jwt/jwt v3.2.2+incompatible h1:IfV12K8xAKAnZqdXVzCZ+TOjboZ2keLg81eXfW3O+oY=
github.com/golang-jwt/jwt v3.2.2+incompatible/go.mod h1:8pz2t5EyA70fFQQSrl6XZXzqecmYZeUEB8OUGHkxJ+I=
github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=
github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
github.com/pmezard/go-difflib v1.0.0 h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=
github.com/pmezard/go-difflib v1.0.0/go.mod h1:iKH77koFhYxTK1pcRnkKkqfTogsbg7gZNVY4sRDYZ/4=
github.com/sirupsen/logrus v1.9.3 h1:dueUQJ1C2q9oE3F7wvmSGAaVtTmUizReu6fjN8uqzbQ=
github.com/sirupsen/logrus v1.9.3/go.mod h1:naHLuLoDiP4jHNo9R0sCBMtWGeIprob74mVsIT4qYEQ=
github.com/stretchr/objx v0.1.0/go.mod h1:HFkY916IF+rwdDfMAkV7OtwuqBVzrE8GR6GFx+wExME=
github.com/stretchr/testify v1.7.0/go.mod h1:6Fq8oRcR53rry900zMqJjRRixrwX3KX962/h/Wwjteg=
github.com/stretchr/testify v1.8.4 h1:CcVxjf3Q8PM0mHUKJCdn+eZZtm5yQwehR5yeSVQQcUk=
github.com/stretchr/testify v1.8.4/go.mod h1:sz/lmYIOXD/1dqDmKjjqLyZ2RngseejIcXlSw2iwfAo=
golang.org/x/sync v0.6.0 h1:5BMeUDZ7vkXGfEr1x9B4bRcTH4lpkTkpdh0T/J+qjbQ=
golang.org/x/sync v0.6.0/go.mod h1:Czt+wKu1gCyEFDUtn0jG5QVvpJ6rzVqr5aXyt9drQfk=
golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 h1:0A+M6Uqn+Eje4kHMK80dtF3JCXC4ykBgQG4Fe06QRhQ=
golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405 h1:yhCVgyC4o1eVCa2tZl7eS0r+SDo693bJlVdllGtEeKM=
gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405/go.mod h1:Co6ibVJAznAaIkqp8huTwlJQCZ016jof/cbN4VW5Yz0=
gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
gopkg.in/yaml.v3 v3.0.1 h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=
gopkg.in/yaml.v3 v3.0.1/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
";

    /// The files go 1.22.5 asked NORA for (`GOPROXY` set to NORA, empty module cache) when
    /// `go mod download`, `go build`, `go mod verify` and `go list -deps -test all` ran on that
    /// project, as NORA stored them.
    const MEASURED_FILES: &[&str] = &[
        "github.com/!burnt!sushi/toml/@v/v1.3.2.info",
        "github.com/!burnt!sushi/toml/@v/v1.3.2.mod",
        "github.com/!burnt!sushi/toml/@v/v1.3.2.zip",
        "github.com/davecgh/go-spew/@v/v1.1.0.mod",
        "github.com/davecgh/go-spew/@v/v1.1.1.info",
        "github.com/davecgh/go-spew/@v/v1.1.1.mod",
        "github.com/davecgh/go-spew/@v/v1.1.1.zip",
        "github.com/golang-jwt/jwt/@v/v3.2.2+incompatible.info",
        "github.com/golang-jwt/jwt/@v/v3.2.2+incompatible.mod",
        "github.com/golang-jwt/jwt/@v/v3.2.2+incompatible.zip",
        "github.com/google/uuid/@v/v1.6.0.info",
        "github.com/google/uuid/@v/v1.6.0.mod",
        "github.com/google/uuid/@v/v1.6.0.zip",
        "github.com/pmezard/go-difflib/@v/v1.0.0.info",
        "github.com/pmezard/go-difflib/@v/v1.0.0.mod",
        "github.com/pmezard/go-difflib/@v/v1.0.0.zip",
        "github.com/sirupsen/logrus/@v/v1.9.3.info",
        "github.com/sirupsen/logrus/@v/v1.9.3.mod",
        "github.com/sirupsen/logrus/@v/v1.9.3.zip",
        "github.com/stretchr/objx/@v/v0.1.0.mod",
        "github.com/stretchr/testify/@v/v1.7.0.mod",
        "github.com/stretchr/testify/@v/v1.8.4.info",
        "github.com/stretchr/testify/@v/v1.8.4.mod",
        "github.com/stretchr/testify/@v/v1.8.4.zip",
        "golang.org/x/sync/@v/v0.6.0.info",
        "golang.org/x/sync/@v/v0.6.0.mod",
        "golang.org/x/sync/@v/v0.6.0.zip",
        "golang.org/x/sys/@v/v0.0.0-20220715151400-c0bba94af5f8.info",
        "golang.org/x/sys/@v/v0.0.0-20220715151400-c0bba94af5f8.mod",
        "golang.org/x/sys/@v/v0.0.0-20220715151400-c0bba94af5f8.zip",
        "gopkg.in/check.v1/@v/v0.0.0-20161208181325-20d25e280405.info",
        "gopkg.in/check.v1/@v/v0.0.0-20161208181325-20d25e280405.mod",
        "gopkg.in/check.v1/@v/v0.0.0-20161208181325-20d25e280405.zip",
        "gopkg.in/yaml.v3/@v/v3.0.0-20200313102051-9f266ea9e77c.mod",
        "gopkg.in/yaml.v3/@v/v3.0.1.info",
        "gopkg.in/yaml.v3/@v/v3.0.1.mod",
        "gopkg.in/yaml.v3/@v/v3.0.1.zip",
    ];

    /// The proxy files planned for go.mod and go.sum, as `<escaped path>/@v/<escaped version>.<ext>`.
    fn planned(go_mod: &str, go_sum: &str) -> Vec<String> {
        let dir = tempfile::tempdir().unwrap();
        let (m, s) = (dir.path().join("go.mod"), dir.path().join("go.sum"));
        std::fs::write(&m, go_mod).unwrap();
        std::fs::write(&s, go_sum).unwrap();
        let mut files: Vec<String> = module_versions(&m, Some(&s))
            .unwrap()
            .iter()
            .flat_map(|((path, version), need)| {
                need.files()
                    .iter()
                    .map(move |ext| format!("{}/@v/{}.{ext}", escape(path), escape(version)))
            })
            .collect();
        files.sort();
        files
    }

    #[test]
    fn plans_exactly_the_files_the_go_command_was_measured_to_read() {
        let mut measured: Vec<String> = MEASURED_FILES.iter().map(|f| f.to_string()).collect();
        measured.sort();
        assert_eq!(planned(MEASURED_GO_MOD, MEASURED_GO_SUM), measured);
    }

    /// The project go 1.22.5 and 1.26.3 were measured on: a main module that requires A, whose
    /// go.mod requires B; no package imports B, so `go mod tidy` leaves only B's go.mod hash.
    const OLD_GO_SUM: &str = "\
example.com/a v1.0.0 h1:9aAWzYdrnCCuhn6lIn0dr5KoazV3CRN2tMk1gWbwACk=
example.com/a v1.0.0/go.mod h1:W/a93JNhRNWPjLZJn8IC+dq18BuLzHUOS8BW9vG2fas=
example.com/b v1.0.0/go.mod h1:dFYOyd6FjirzV0EpGfCRpL1g8tqPwL+WQHAY5bcfsoA=
";

    /// With `go 1.16` (or no `go` line: `go mod download` then adds `require B // indirect` and
    /// the next download asks for B in full) `go mod download` downloads the whole build list,
    /// B's `.info` and `.zip` included; from `go 1.17` on only B's `.mod`.
    #[test]
    fn a_main_module_before_go_1_17_needs_every_go_sum_version_in_full() {
        let a = [
            "example.com/a/@v/v1.0.0.info",
            "example.com/a/@v/v1.0.0.mod",
            "example.com/a/@v/v1.0.0.zip",
        ];
        let b_full = [
            "example.com/b/@v/v1.0.0.info",
            "example.com/b/@v/v1.0.0.mod",
            "example.com/b/@v/v1.0.0.zip",
        ];
        let old: Vec<String> = a.iter().chain(&b_full).map(|f| f.to_string()).collect();
        let new: Vec<String> = a
            .iter()
            .chain(&["example.com/b/@v/v1.0.0.mod"])
            .map(|f| f.to_string())
            .collect();
        let require = "require example.com/a v1.0.0\n";
        for (go_line, want) in [
            ("go 1.16\n", &old),
            ("", &old),
            ("go 1.12\n", &old),
            ("go 1.17\n", &new),
            ("go 1.21\n", &new),
            ("go 1.22.5\n", &new),
            ("go 1.17rc1\n", &new),
            ("go 1.100\n", &new),
        ] {
            let go_mod = format!("module example.com/app\n\n{go_line}\n{require}");
            assert_eq!(&planned(&go_mod, OLD_GO_SUM), want, "{go_line:?}");
        }
    }

    #[test]
    fn a_quoted_token_is_one_argument_whatever_it_holds() {
        let go_mod = "module m\n\nrequire (\n\texample.com/a v1.0.0\n\texample.com/b v1.0.0\n\
                      \texample.com/c v1.0.0\n\texample.com/d v1.0.0\n\texample.com/e v1.0.0\n)\n\
                      replace example.com/a => \"../local module\"\n\
                      replace example.com/b => \"./a//b\" // the `//` inside the quotes is not a comment\n\
                      replace example.com/c v1.0.0 => \"..\\\\win dir\\\\c\"\n\
                      replace (\n\t\"example.com/d\" => \"example.com/\\x64fork\" \"v1.0.1\"\n)\n";
        let fetched = parse_go_mod(go_mod).unwrap().fetched();
        assert_eq!(
            fetched,
            vec![
                ("example.com/dfork".to_string(), "v1.0.1".to_string()),
                ("example.com/e".to_string(), "v1.0.0".to_string()),
            ]
        );
        for (bad, why) in [
            ("module m\nreplace example.com/a => \"../open\n", "quoted"),
            ("module m\nreplace example.com/a => \"../\\q\"\n", "quoted"),
            (
                "module m\nreplace example.com/a => .hidden\n",
                "replacement",
            ),
        ] {
            let (n, e) = parse_go_mod(bad).expect_err(bad);
            assert_eq!(n, 2, "{bad}");
            assert!(e.to_string().contains(why), "{bad}: {e}");
        }
    }

    #[test]
    fn a_version_needed_in_full_is_fetched_in_full_whichever_line_comes_first() {
        let go_mod = "module m\n\nrequire example.com/a v1.0.0\n";
        let go_sum = "example.com/a v1.0.0/go.mod h1:X=\nexample.com/b v1.0.0/go.mod h1:X=\nexample.com/b v1.0.0 h1:X=\n";
        assert_eq!(
            planned(go_mod, go_sum),
            vec![
                "example.com/a/@v/v1.0.0.info",
                "example.com/a/@v/v1.0.0.mod",
                "example.com/a/@v/v1.0.0.zip",
                "example.com/b/@v/v1.0.0.info",
                "example.com/b/@v/v1.0.0.mod",
                "example.com/b/@v/v1.0.0.zip",
            ]
        );
    }

    #[test]
    fn escapes_capitals_as_the_go_command_does() {
        assert_eq!(
            escape("github.com/BurntSushi/toml"),
            "github.com/!burnt!sushi/toml"
        );
        assert_eq!(escape("v1.0.0-RC1"), "v1.0.0-!r!c1");
        assert_eq!(escape("golang.org/x/text"), "golang.org/x/text");
    }

    #[test]
    fn reads_requirements_single_line_in_blocks_quoted_and_after_comments() {
        let go_mod = "// header comment\nmodule example.com/app // trailing\n\ngo 1.22\ntoolchain go1.22.5\n\n\
                      require example.com/one v1.0.0\nrequire(\n\t\"example.com/two\" v2.0.0+incompatible // indirect\n\n\
                      \t// a comment line\n)\nrequire (\n\t`example.com/three` v0.0.0-20240101000000-abcdefabcdef\n)\n\
                      exclude example.com/one v0.9.0\nretract (\n\tv1.0.1 // published by mistake\n\t[v1.1.0, v1.1.9]\n)\n\
                      godebug default=go1.21\n";
        let parsed = parse_go_mod(go_mod).unwrap();
        assert_eq!(
            parsed.requires,
            vec![
                ("example.com/one".to_string(), "v1.0.0".to_string()),
                (
                    "example.com/two".to_string(),
                    "v2.0.0+incompatible".to_string()
                ),
                (
                    "example.com/three".to_string(),
                    "v0.0.0-20240101000000-abcdefabcdef".to_string()
                ),
            ]
        );
        assert!(parsed.replaces.is_empty());
    }

    #[test]
    fn a_replacement_for_one_version_wins_over_one_for_every_version() {
        let go_mod = "module m\n\nrequire (\n\texample.com/a v1.0.0\n\texample.com/b v1.0.0\n\texample.com/c v1.0.0\n\
                      \texample.com/d v1.0.0\n\texample.com/e v1.0.0\n)\n\
                      replace example.com/a => example.com/all v9.0.0\n\
                      replace example.com/a v1.0.0 => example.com/one v1.0.1\n\
                      replace example.com/b v0.5.0 => example.com/other v1.0.0\n\
                      replace (\n\texample.com/c => ./c\n\texample.com/d => /abs/d\n\texample.com/e => C:\\src\\e\n)\n";
        let fetched = parse_go_mod(go_mod).unwrap().fetched();
        assert_eq!(
            fetched,
            vec![
                ("example.com/one".to_string(), "v1.0.1".to_string()),
                ("example.com/b".to_string(), "v1.0.0".to_string()),
            ]
        );
    }

    #[test]
    fn a_line_it_cannot_read_fails_with_its_number() {
        let cases: &[(&str, usize, &str)] = &[
            ("module m\nrequire example.com/a\n", 2, "requirement"),
            (
                "module m\nrequire (\n\texample.com/a v1 extra\n)\n",
                3,
                "requirement",
            ),
            (
                "module m\nrequire example.com/../a v1.0.0\n",
                2,
                "module path",
            ),
            (
                "module m\nrequire example.com/a?x=1 v1.0.0\n",
                2,
                "module path",
            ),
            (
                "module m\nrequire example.com/a -1.0.0\n",
                2,
                "module version",
            ),
            (
                "module m\nrequire example.com/a v1.2\n",
                2,
                "example.com/a v1.2: the go command resolves `v1.2` from the module's version list",
            ),
            (
                "module m\nrequire (\n\texample.com/a latest\n)\n",
                3,
                "go mod tidy",
            ),
            (
                "module m\nreplace example.com/a => example.com/b v1\n",
                2,
                "version list",
            ),
            (
                "module m\nrequire example.com/a v1.0.0#frag\n",
                2,
                "module version",
            ),
            ("module m\nreplace example.com/a v1.0.0\n", 2, "replacement"),
            (
                "module m\nreplace example.com/a => example.com/b\n",
                2,
                "replacement",
            ),
            (
                "module m\n\nrequire (\n\texample.com/a v1.0.0\n",
                3,
                "not closed",
            ),
        ];
        for (go_mod, line, what) in cases {
            let (n, why) = parse_go_mod(go_mod).expect_err(go_mod);
            assert_eq!(n, *line, "{go_mod}");
            assert!(why.to_string().contains(what), "{go_mod}: {why}");
        }
        let (n, why) =
            parse_go_sum("example.com/a v1.0.0 h1:X=\nexample.com/b v1.0.0\n").unwrap_err();
        assert_eq!(n, 2);
        assert!(why.to_string().contains("go.sum line"), "{why}");
    }

    #[test]
    fn a_go_mod_error_names_the_file_and_line() {
        let dir = tempfile::tempdir().unwrap();
        let m = dir.path().join("go.mod");
        std::fs::write(&m, "module m\n\nrequire example.com/a\n").unwrap();
        let err = module_versions(&m, None).unwrap_err().to_string();
        assert!(err.starts_with(&format!("{}:3: ", m.display())), "{err}");
        let missing = dir.path().join("absent.sum");
        std::fs::write(&m, "module m\n").unwrap();
        let err = module_versions(&m, Some(&missing)).unwrap_err().to_string();
        assert!(
            err.starts_with("cannot read ") && err.contains("absent.sum"),
            "{err}"
        );
    }
}
