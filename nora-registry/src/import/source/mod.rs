//! Migration source adapters (#599). Each implements [`super::SourceRegistry`]
//! as a forward-only cursor so a source's native pagination never leaks and
//! resume never re-walks completed pages.
//!
//! Shared here: the SSRF-guarded HTTP plumbing ([`SourceHttp`]) and a retry
//! helper with capped exponential backoff that honors `Retry-After` (review R9)
//! — a long TB-scale import must survive a rate-limited/5xx source without
//! aborting a repo, and must never retry into an SSRF redirect target.

pub mod artifactory;
pub mod nexus;

use super::{Result, SourceKind, SourceRegistry};
use std::time::Duration;

/// Max send attempts per request before giving up (review R9).
const MAX_ATTEMPTS: u32 = 5;
/// Cap on any single backoff/`Retry-After` sleep — a hostile `Retry-After: 86400`
/// must not park the import for a day.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Build a source adapter for `kind` at base `url`.
///
/// `client` MUST be the SSRF-guarded client from [`super::http::build_import_client`]
/// (never `build_http_client`, which has no redirect/DNS guard — review R2).
/// `auth` is optional `user:pass` basic-auth credentials read from the
/// `NORA_IMPORT_AUTH` env var (never a CLI flag); held as a plain `String` for
/// the process lifetime, attached only at the reqwest call site, and never logged
/// (error text is built from a redacted URL). `allow_private` mirrors
/// `--allow-private-cidrs`.
pub fn build_source(
    kind: SourceKind,
    url: &str,
    client: reqwest::Client,
    auth: Option<String>,
    allow_private: bool,
) -> Result<Box<dyn SourceRegistry>> {
    let base = url.trim_end_matches('/').to_string();
    if base.is_empty() {
        return Err("--url must not be empty".to_string());
    }
    let http = SourceHttp {
        client,
        base,
        auth,
        allow_private,
    };
    match kind {
        SourceKind::Artifactory => Ok(Box::new(artifactory::Artifactory::new(http))),
        SourceKind::Nexus => Ok(Box::new(nexus::Nexus::new(http))),
    }
}

/// SSRF-guarded HTTP plumbing shared by the adapters: base URL, optional
/// credentials, and retry/backoff. The credential is attached per request and
/// never appears in a log line (error messages are built from a redacted URL,
/// not `reqwest::Error`'s Display — review Security #6).
pub(crate) struct SourceHttp {
    pub(crate) client: reqwest::Client,
    /// Base URL with any trailing slash trimmed; `path` args start with `/`.
    pub(crate) base: String,
    pub(crate) auth: Option<String>,
    /// `--allow-private-cidrs`: opt out of the IP-literal deny-check on
    /// source-supplied absolute URLs (`downloadUri`/`downloadUrl`).
    pub(crate) allow_private: bool,
}

impl SourceHttp {
    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    fn authed(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            Some(creds) => rb.header(
                reqwest::header::AUTHORIZATION,
                crate::config::basic_auth_header(creds),
            ),
            None => rb,
        }
    }

    /// Like [`authed`], but attaches the credential ONLY when `url` is on the
    /// source's own origin (scheme+host+port). A source-supplied absolute URL
    /// (`downloadUri`) may name a *different* host; sending the basic-auth there
    /// would exfiltrate the operator's source credentials to an attacker-chosen
    /// host (reqwest strips auth on cross-host *redirects*, but this is a fresh
    /// request we issue — no stripping). Review: credential exfil via downloadUri.
    fn authed_same_origin(
        &self,
        url: &str,
        rb: reqwest::RequestBuilder,
    ) -> reqwest::RequestBuilder {
        if same_origin(&self.base, url) {
            self.authed(rb)
        } else {
            rb
        }
    }

    /// `GET {base}{path}` with retry. Returns the [`reqwest::Response`] on a
    /// non-retryable status (caller inspects it); errors only after exhausting
    /// retries or on a non-transient failure.
    pub(crate) async fn get(&self, path: &str) -> Result<reqwest::Response> {
        let full = self.url(path);
        self.send_with_retry(&full, "GET", || self.authed(self.client.get(&full)))
            .await
    }

    /// `GET` a **source-supplied absolute URL** (Artifactory `downloadUri`, Nexus
    /// `downloadUrl`). Because this URL is attacker-influenced, it gets defences
    /// the base-relative paths don't need: (1) an IP-literal deny-check — the DNS
    /// resolver never fires for a literal and the redirect policy only covers
    /// hops, so an unchecked `downloadUri` of `http://169.254.169.254/…` would
    /// reach connect() — and (2) credentials only if the URL is on the source's
    /// own origin (no cross-host credential leak). Hostname hosts are still
    /// DNS-pinned by the guarded client at connect.
    pub(crate) async fn get_absolute(&self, url: &str) -> Result<reqwest::Response> {
        if super::http::is_blocked_url_host(url, self.allow_private) {
            return Err(format!(
                "SSRF guard: source-supplied URL {} resolves to a blocked (loopback/private/metadata) IP literal",
                super::http::redact_url(url)
            ));
        }
        self.send_with_retry(url, "GET", || {
            self.authed_same_origin(url, self.client.get(url))
        })
        .await
    }

    /// `POST {base}{path}` with a text/plain body (Artifactory AQL).
    pub(crate) async fn post_text(&self, path: &str, body: String) -> Result<reqwest::Response> {
        let full = self.url(path);
        self.send_with_retry(&full, "POST", || {
            self.authed(
                self.client
                    .post(&full)
                    .header(reqwest::header::CONTENT_TYPE, "text/plain")
                    .body(body.clone()),
            )
        })
        .await
    }

    /// Capped exponential backoff honoring `Retry-After` on 429/5xx and transient
    /// transport errors. Never retries a redirect-policy rejection (an SSRF hop),
    /// and builds error text from a *redacted* URL, never `e.to_string()`.
    async fn send_with_retry<F>(
        &self,
        url: &str,
        method: &str,
        make: F,
    ) -> Result<reqwest::Response>
    where
        F: Fn() -> reqwest::RequestBuilder,
    {
        let safe = super::http::redact_url(url);
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match make().send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let retryable = status == reqwest::StatusCode::TOO_MANY_REQUESTS
                        || status.is_server_error();
                    if retryable && attempt < MAX_ATTEMPTS {
                        let delay = retry_after(&resp).unwrap_or_else(|| backoff(attempt));
                        tracing::warn!(url = %safe, status = status.as_u16(), attempt, delay_ms = delay.as_millis() as u64, "import source retry");
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    // A redirect-policy rejection is an SSRF stop — do NOT retry
                    // it (Security #6). Only transport-transient errors retry.
                    let transient =
                        !e.is_redirect() && (e.is_timeout() || e.is_connect() || e.is_request());
                    if transient && attempt < MAX_ATTEMPTS {
                        let delay = backoff(attempt);
                        tracing::warn!(url = %safe, attempt, delay_ms = delay.as_millis() as u64, "import source transport retry");
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    return Err(format!(
                        "{method} {safe} failed (timeout={}, connect={}, redirect={})",
                        e.is_timeout(),
                        e.is_connect(),
                        e.is_redirect()
                    ));
                }
            }
        }
    }
}

/// Parse a `Retry-After` header (delta-seconds form) into a capped delay. HTTP-date
/// form and unparsable values fall back to exponential backoff at the call site.
fn retry_after(resp: &reqwest::Response) -> Option<Duration> {
    let raw = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .to_string();
    match raw.parse::<u64>() {
        Ok(secs) => Some(Duration::from_secs(secs).min(MAX_BACKOFF)),
        // HTTP-date form (RFC 7231, common on gateways/CDNs): we don't parse the
        // date, but a present Retry-After means the server asked us to wait —
        // honor it with the capped max pause rather than a shorter exp backoff.
        Err(_) => Some(MAX_BACKOFF),
    }
}

/// Capped exponential backoff: 200ms, 400ms, 800ms, ... up to [`MAX_BACKOFF`].
fn backoff(attempt: u32) -> Duration {
    let ms = 200u64.saturating_mul(1u64 << attempt.min(8).saturating_sub(1));
    Duration::from_millis(ms).min(MAX_BACKOFF)
}

/// Do `base` and `url` share the same origin (scheme + host + port)? Used to
/// decide whether the source credential may travel to a source-supplied absolute
/// URL. Unparsable `url` → `false` (fail-closed: no credential).
fn same_origin(base: &str, url: &str) -> bool {
    let origin = |s: &str| {
        reqwest::Url::parse(s).ok().map(|u| {
            (
                u.scheme().to_string(),
                u.host_str().map(str::to_string),
                u.port_or_known_default(),
            )
        })
    };
    match (origin(base), origin(url)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// Split a repo-relative directory `path` and file `name` into one repo-relative
/// path. Artifactory AQL returns them separately (`path` may be `.` for root);
/// Nexus already gives a joined asset path.
pub(crate) fn join_path(path: &str, name: &str) -> String {
    let path = path.trim_matches('/');
    if path.is_empty() || path == "." {
        name.to_string()
    } else {
        format!("{path}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_capped_and_monotonic() {
        assert_eq!(backoff(1), Duration::from_millis(200));
        assert_eq!(backoff(2), Duration::from_millis(400));
        assert_eq!(backoff(3), Duration::from_millis(800));
        assert!(backoff(20) <= MAX_BACKOFF);
    }

    #[test]
    fn join_path_handles_root_and_nested() {
        assert_eq!(join_path(".", "foo-1.0.jar"), "foo-1.0.jar");
        assert_eq!(join_path("", "foo.txt"), "foo.txt");
        assert_eq!(
            join_path("com/example/foo/1.0", "foo-1.0.jar"),
            "com/example/foo/1.0/foo-1.0.jar"
        );
        assert_eq!(join_path("/a/b/", "c.bin"), "a/b/c.bin");
    }

    #[test]
    fn same_origin_compares_scheme_host_port() {
        assert!(same_origin(
            "https://art.example.com",
            "https://art.example.com/repo/x.jar"
        ));
        assert!(same_origin(
            "https://art.example.com:443",
            "https://art.example.com/x"
        )); // default port
        assert!(!same_origin(
            "https://art.example.com",
            "https://evil.example.com/x"
        )); // diff host
        assert!(!same_origin(
            "https://art.example.com",
            "http://art.example.com/x"
        )); // diff scheme
        assert!(!same_origin(
            "https://art.example.com",
            "https://art.example.com:8443/x"
        )); // diff port
        assert!(!same_origin("https://art.example.com", "not a url")); // fail-closed
    }

    #[tokio::test]
    async fn get_absolute_rejects_source_supplied_metadata_url() {
        // A malicious source returns a downloadUri pointing at cloud metadata /
        // loopback — get_absolute must fail BEFORE connecting (the DNS resolver
        // never fires for an IP literal, so this is the guard that catches it).
        let http = SourceHttp {
            client: super::super::http::build_import_client(
                &crate::config::TlsConfig::default(),
                Duration::from_secs(5),
                Duration::from_secs(5),
                false,
            )
            .unwrap(),
            base: "https://art.example.com".to_string(),
            auth: Some("u:p".to_string()),
            allow_private: false,
        };
        for bad in [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:8081/x",
            "http://[::1]/x",
            "http://10.0.0.5/x",
        ] {
            let err = http.get_absolute(bad).await.unwrap_err();
            assert!(
                err.contains("SSRF"),
                "expected SSRF rejection for {bad}, got: {err}"
            );
        }
    }
}
