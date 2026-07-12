//! Artifactory source adapter (#599).
//!
//! Repos: `GET /api/repositories` (local/federated only — remote/virtual are
//! proxies/aggregates, not artifacts to migrate). Artifacts: AQL
//! `POST /api/search/aql`, forward-only via `offset`/`limit`. The load-bearing
//! gotcha (baked in below): AQL `range.total` is the **per-page** row count, not
//! the result-set total — so termination is by page *shape* (a short page ends
//! the walk) with a no-progress guard and a max-pages cap, never by `total`.
//! Download: `GET {base}/{repo}/{path}`, and on 404 read storage-info and retry
//! the returned `downloadUri` (large/virtual-backed artifacts).

use async_trait::async_trait;
use axum::body::Bytes;
use futures::stream::{self, BoxStream, StreamExt};
use serde_json::Value;
use std::collections::VecDeque;

use super::super::{ArtifactRef, RepoRef, Result, SourceRegistry};
use super::{join_path, SourceHttp};

/// AQL page size. Large enough to amortize round-trips, small enough to bound
/// the buffered `VecDeque` and per-page latency.
const PAGE_LIMIT: usize = 1000;
/// Safety cap on pages walked per repo (PAGE_LIMIT × this = max artifacts/repo).
const MAX_PAGES: usize = 1_000_000;

pub(crate) struct Artifactory {
    http: SourceHttp,
}

/// Forward cursor state for the AQL offset walk.
struct Cursor {
    offset: usize,
    buf: VecDeque<ArtifactRef>,
    done: bool,
    pages: usize,
}

impl Artifactory {
    pub(crate) fn new(http: SourceHttp) -> Self {
        Self { http }
    }

    /// Fetch one AQL page at `offset`. Returns the parsed artifacts (empty = no
    /// more rows). AQL-injects nothing: `repo` is escaped through `serde_json`.
    async fn fetch_page(&self, repo: &str, offset: usize) -> Result<Vec<ArtifactRef>> {
        let criteria = serde_json::json!({ "repo": repo, "type": "file" });
        let body = format!(
            "items.find({criteria}).include(\"repo\",\"path\",\"name\",\"size\",\"sha256\",\"actual_sha1\").sort({{\"$asc\":[\"path\",\"name\"]}}).offset({offset}).limit({PAGE_LIMIT})"
        );
        let resp = self.http.post_text("/api/search/aql", body).await?;
        if !resp.status().is_success() {
            return Err(format!(
                "Artifactory AQL for repo {repo:?}: HTTP {}",
                resp.status().as_u16()
            ));
        }
        let json: Value = resp
            .json()
            .await
            .map_err(|e| format!("Artifactory AQL: invalid JSON (timeout={})", e.is_timeout()))?;
        let results = json
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| "Artifactory AQL: missing 'results' array".to_string())?;
        Ok(results.iter().filter_map(parse_item).collect())
    }
}

#[async_trait]
impl SourceRegistry for Artifactory {
    async fn list_repositories(&self) -> Result<Vec<RepoRef>> {
        let resp = self.http.get("/api/repositories").await?;
        if !resp.status().is_success() {
            return Err(format!(
                "Artifactory /api/repositories: HTTP {}",
                resp.status().as_u16()
            ));
        }
        let json: Value = resp.json().await.map_err(|e| {
            format!(
                "Artifactory /api/repositories: invalid JSON (timeout={})",
                e.is_timeout()
            )
        })?;
        let arr = json
            .as_array()
            .ok_or_else(|| "Artifactory /api/repositories: expected JSON array".to_string())?;
        let mut repos = Vec::new();
        for r in arr {
            // Only hosted repos carry migratable artifacts; skip remote/virtual.
            let rtype = r.get("type").and_then(Value::as_str).unwrap_or("");
            if !matches!(rtype.to_ascii_uppercase().as_str(), "LOCAL" | "FEDERATED") {
                continue;
            }
            let Some(name) = r.get("key").and_then(Value::as_str) else {
                continue;
            };
            let format = r
                .get("packageType")
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
            offset: 0,
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
                        "Artifactory: max-pages cap hit; stopping repo walk"
                    );
                    return None;
                }
                match self.fetch_page(repo, st.offset).await {
                    Ok(rows) => {
                        let n = rows.len();
                        st.pages += 1;
                        // Page-shape termination: a short page is the last page.
                        if n < PAGE_LIMIT {
                            st.done = true;
                        }
                        // No-progress guard: an empty page ends the walk even if
                        // the server misreports and never shrinks the page.
                        if n == 0 {
                            return None;
                        }
                        st.offset += n;
                        st.buf.extend(rows);
                        // loop back to pop the first buffered item
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
        // artifact.path is the repo-relative path incl. filename (join of AQL
        // path+name). Primary: direct download.
        let direct = self
            .http
            .url(&format!("/{}/{}", artifact.repo, artifact.path));
        let resp = self.http.get_absolute(&direct).await?;
        let resp = if resp.status() == reqwest::StatusCode::NOT_FOUND {
            // 404 fallback: storage-info exposes a resolvable downloadUri.
            let info_url = self
                .http
                .url(&format!("/api/storage/{}/{}", artifact.repo, artifact.path));
            let info = self.http.get_absolute(&info_url).await?;
            if !info.status().is_success() {
                return Err(format!(
                    "Artifactory download {}: HTTP 404 and storage-info HTTP {}",
                    artifact.path,
                    info.status().as_u16()
                ));
            }
            let meta: Value = info
                .json()
                .await
                .map_err(|_| "Artifactory storage-info: invalid JSON".to_string())?;
            let uri = meta
                .get("downloadUri")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "Artifactory storage-info for {}: no downloadUri",
                        artifact.path
                    )
                })?;
            self.http.get_absolute(uri).await?
        } else {
            resp
        };
        if !resp.status().is_success() {
            return Err(format!(
                "Artifactory download {}: HTTP {}",
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

/// Parse one AQL result row into an [`ArtifactRef`], tolerating Artifactory's
/// quirks: `size` may be a number or a string, and absent checksums come back as
/// empty strings (treated as `None`, so R8 fail-closed logic sees "no checksum",
/// not a bogus empty digest).
fn parse_item(v: &Value) -> Option<ArtifactRef> {
    let repo = v.get("repo")?.as_str()?.to_string();
    let dir = v.get("path")?.as_str()?;
    let name = v.get("name")?.as_str()?.to_string();
    let full = join_path(dir, &name);
    Some(ArtifactRef {
        repo,
        path: full,
        name,
        size: v.get("size").and_then(val_to_u64),
        sha256: v.get("sha256").and_then(non_empty_str),
        sha1: v.get("actual_sha1").and_then(non_empty_str),
    })
}

fn val_to_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn non_empty_str(v: &Value) -> Option<String> {
    match v.as_str() {
        Some(s) if !s.is_empty() => Some(s.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_item_joins_path_and_reads_checksums() {
        let v = serde_json::json!({
            "repo": "libs-release-local",
            "path": "com/example/foo/1.0",
            "name": "foo-1.0.jar",
            "size": 1234,
            "sha256": "abc123",
            "actual_sha1": "def456"
        });
        let a = parse_item(&v).unwrap();
        assert_eq!(a.path, "com/example/foo/1.0/foo-1.0.jar");
        assert_eq!(a.name, "foo-1.0.jar");
        assert_eq!(a.size, Some(1234));
        assert_eq!(a.sha256.as_deref(), Some("abc123"));
        assert_eq!(a.sha1.as_deref(), Some("def456"));
    }

    #[test]
    fn parse_item_treats_empty_checksums_and_string_size() {
        let v = serde_json::json!({
            "repo": "r", "path": ".", "name": "root.txt",
            "size": "42", "sha256": "", "actual_sha1": ""
        });
        let a = parse_item(&v).unwrap();
        assert_eq!(a.path, "root.txt"); // path "." collapses
        assert_eq!(a.size, Some(42)); // string size parsed
        assert_eq!(a.sha256, None); // empty → None (R8 sees "no checksum")
        assert_eq!(a.sha1, None);
    }
}
