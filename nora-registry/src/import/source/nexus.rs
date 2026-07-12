//! Nexus source adapter (#599).
//!
//! Repos: `GET /service/rest/v1/repositories` (hosted only — proxy/group are not
//! migratable artifacts). Artifacts: paginated
//! `GET /service/rest/v1/components?repository=…&continuationToken=…` with an
//! **opaque** token (no offset), flattening the components→assets model. The
//! forward cursor threads the token internally so resume never re-walks pages.
//! Download: `{base}/repository/{repo}/{path}`. Nexus exposes **no** permission
//! API, so `--with-permissions` is a hard error in `run` before any bytes move
//! (`permissions::ensure_supported`), with an informational NOTE in `assess`
//! (review R3).

use async_trait::async_trait;
use axum::body::Bytes;
use futures::stream::{self, BoxStream, StreamExt};
use serde_json::Value;
use std::collections::VecDeque;

use super::super::{ArtifactRef, RepoRef, Result, SourceRegistry};
use super::SourceHttp;

/// Safety cap on component pages per repo (opaque cursor → guard against a token
/// that never terminates).
const MAX_PAGES: usize = 1_000_000;

pub(crate) struct Nexus {
    http: SourceHttp,
}

impl Nexus {
    pub(crate) fn new(http: SourceHttp) -> Self {
        Self { http }
    }

    /// Fetch one components page. Returns `(flattened assets, next token)`.
    async fn fetch_page(
        &self,
        repo: &str,
        token: Option<&str>,
    ) -> Result<(Vec<ArtifactRef>, Option<String>)> {
        let path = match token {
            Some(t) => format!(
                "/service/rest/v1/components?repository={}&continuationToken={}",
                urlencode(repo),
                urlencode(t)
            ),
            None => format!("/service/rest/v1/components?repository={}", urlencode(repo)),
        };
        let resp = self.http.get(&path).await?;
        if !resp.status().is_success() {
            return Err(format!(
                "Nexus components for repo {repo:?}: HTTP {}",
                resp.status().as_u16()
            ));
        }
        let json: Value = resp.json().await.map_err(|e| {
            format!(
                "Nexus components: invalid JSON (timeout={})",
                e.is_timeout()
            )
        })?;
        let items = json
            .get("items")
            .and_then(Value::as_array)
            .ok_or_else(|| "Nexus components: missing 'items' array".to_string())?;

        let mut out = Vec::new();
        for component in items {
            let Some(assets) = component.get("assets").and_then(Value::as_array) else {
                continue;
            };
            for asset in assets {
                if let Some(a) = parse_asset(repo, asset) {
                    out.push(a);
                }
            }
        }
        let next = json
            .get("continuationToken")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        Ok((out, next))
    }
}

#[async_trait]
impl SourceRegistry for Nexus {
    async fn list_repositories(&self) -> Result<Vec<RepoRef>> {
        let resp = self.http.get("/service/rest/v1/repositories").await?;
        if !resp.status().is_success() {
            return Err(format!(
                "Nexus /service/rest/v1/repositories: HTTP {}",
                resp.status().as_u16()
            ));
        }
        let json: Value = resp.json().await.map_err(|e| {
            format!(
                "Nexus repositories: invalid JSON (timeout={})",
                e.is_timeout()
            )
        })?;
        let arr = json
            .as_array()
            .ok_or_else(|| "Nexus repositories: expected JSON array".to_string())?;
        let mut repos = Vec::new();
        for r in arr {
            // Only hosted repos hold migratable artifacts; skip proxy/group.
            let rtype = r.get("type").and_then(Value::as_str).unwrap_or("");
            if !rtype.eq_ignore_ascii_case("hosted") {
                continue;
            }
            let Some(name) = r.get("name").and_then(Value::as_str) else {
                continue;
            };
            let format = r
                .get("format")
                .and_then(Value::as_str)
                .unwrap_or("generic")
                .to_ascii_lowercase();
            repos.push(RepoRef {
                name: name.to_string(),
                format,
            });
        }
        Ok(repos)
    }

    fn artifacts<'a>(&'a self, repo: &'a str) -> BoxStream<'a, Result<ArtifactRef>> {
        let init = Cursor {
            token: None,
            first: true,
            buf: VecDeque::new(),
            done: false,
            pages: 0,
        };
        stream::unfold(init, move |mut st| async move {
            loop {
                if let Some(art) = st.buf.pop_front() {
                    return Some((Ok(art), st));
                }
                if st.done {
                    return None;
                }
                if st.pages >= MAX_PAGES {
                    tracing::warn!(
                        repo,
                        pages = st.pages,
                        "Nexus: max-pages cap hit; stopping repo walk"
                    );
                    return None;
                }
                // Only the first request is allowed to have no token; thereafter a
                // `None` token means the cursor is exhausted.
                if !st.first && st.token.is_none() {
                    return None;
                }
                st.first = false;
                match self.fetch_page(repo, st.token.as_deref()).await {
                    Ok((rows, next)) => {
                        st.pages += 1;
                        st.token = next;
                        if st.token.is_none() {
                            st.done = true;
                        }
                        if rows.is_empty() {
                            // Empty page: only continue if the cursor advances,
                            // else we'd spin forever on a stuck token.
                            if st.done {
                                return None;
                            }
                            continue;
                        }
                        st.buf.extend(rows);
                    }
                    Err(e) => {
                        st.done = true;
                        return Some((Err(e), st));
                    }
                }
            }
        })
        .boxed()
    }

    async fn download_stream(
        &self,
        artifact: &ArtifactRef,
    ) -> Result<BoxStream<'static, Result<Bytes>>> {
        let url = self
            .http
            .url(&format!("/repository/{}/{}", artifact.repo, artifact.path));
        let resp = self.http.get_absolute(&url).await?;
        if !resp.status().is_success() {
            return Err(format!(
                "Nexus download {}: HTTP {}",
                artifact.path,
                resp.status().as_u16()
            ));
        }
        Ok(resp
            .bytes_stream()
            .map(|r| r.map_err(|e| format!("download chunk (timeout={})", e.is_timeout())))
            .boxed())
    }
}

/// Forward cursor state for the components walk.
struct Cursor {
    token: Option<String>,
    first: bool,
    buf: VecDeque<ArtifactRef>,
    done: bool,
    pages: usize,
}

/// Parse one Nexus asset into an [`ArtifactRef`]. Absent checksums (Nexus omits
/// the field rather than sending an empty string) become `None` so R8's
/// fail-closed logic sees "no checksum".
fn parse_asset(repo: &str, asset: &Value) -> Option<ArtifactRef> {
    let path = asset
        .get("path")
        .and_then(Value::as_str)?
        .trim_start_matches('/');
    if path.is_empty() {
        return None;
    }
    let checksum = asset.get("checksum");
    let sha256 = checksum
        .and_then(|c| c.get("sha256"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let sha1 = checksum
        .and_then(|c| c.get("sha1"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let size = asset.get("fileSize").and_then(Value::as_u64);
    let name = path.rsplit('/').next().unwrap_or(path).to_string();
    Some(ArtifactRef {
        repo: repo.to_string(),
        path: path.to_string(),
        name,
        size,
        sha256,
        sha1,
    })
}

/// Minimal percent-encoding for query-parameter values (repo names, opaque
/// continuation tokens). Encodes everything outside the unreserved set so a repo
/// name with `/`, `&`, `=`, or `+` cannot break out of the query parameter.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_asset_reads_path_checksums_and_basename() {
        let asset = serde_json::json!({
            "path": "com/example/foo/1.0/foo-1.0.jar",
            "checksum": { "sha1": "aa", "sha256": "bb" },
            "fileSize": 999
        });
        let a = parse_asset("maven-releases", &asset).unwrap();
        assert_eq!(a.repo, "maven-releases");
        assert_eq!(a.path, "com/example/foo/1.0/foo-1.0.jar");
        assert_eq!(a.name, "foo-1.0.jar");
        assert_eq!(a.sha256.as_deref(), Some("bb"));
        assert_eq!(a.sha1.as_deref(), Some("aa"));
        assert_eq!(a.size, Some(999));
    }

    #[test]
    fn parse_asset_missing_checksums_is_none() {
        let asset = serde_json::json!({ "path": "a/b.txt" });
        let a = parse_asset("raw-hosted", &asset).unwrap();
        assert_eq!(a.name, "b.txt");
        assert_eq!(a.sha256, None);
        assert_eq!(a.sha1, None);
    }

    #[test]
    fn urlencode_escapes_separators() {
        assert_eq!(urlencode("a/b&c=d+e"), "a%2Fb%26c%3Dd%2Be");
        assert_eq!(urlencode("simple-repo_1.0"), "simple-repo_1.0");
    }
}
