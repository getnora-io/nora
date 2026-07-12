//! SSRF-guarded HTTP client for `nora import` (#599, review R2).
//!
//! `build_http_client` (`main.rs`) sets only user-agent/timeout/no_proxy/CA — it
//! has **no** redirect policy and **no** DNS resolver, so it cannot defend an
//! operator-supplied source URL against SSRF (a whole-tree grep for
//! `redirect::Policy`/`is_private`/`dns_resolver` finds nothing to reuse). This
//! module builds a purpose-built client with two layers that together cover the
//! initial request **and every redirect hop**, for both hostname and IP-literal
//! targets:
//!
//! 1. A **DNS-pinning resolver** ([`GuardedResolver`]): reqwest re-resolves every
//!    hop through this resolver, which drops blocked IPs and returns *only* the
//!    checked addresses — so reqwest connects to exactly what we vetted. A DNS
//!    rebind whose second answer is `127.0.0.1` never reaches `connect()`.
//!    Fail-closed: if every resolved address is blocked, resolution errors.
//! 2. A **redirect policy** ([`reqwest::redirect::Policy::custom`]): reqwest does
//!    NOT call the DNS resolver for IP-literal URLs (there is no name to
//!    resolve), so `302 → http://169.254.169.254/` would bypass layer 1. The
//!    policy re-checks every hop's URL host — a blocked IP-literal aborts the
//!    redirect — and caps the hop count.
//!
//! The client is also built with **`.no_proxy()`**: reqwest honors
//! `HTTP_PROXY`/`ALL_PROXY` by default, and a proxy resolves the target hostname
//! itself — so an ambient proxy would silently defeat the DNS-pinning guard (the
//! resolver would only ever see the proxy's hostname). This is an offline CLI
//! hitting one operator source, so it has no reason to honor an ambient proxy.
//!
//! Plus: a pre-flight [`precheck_url`] for an IP-literal `--url`;
//! [`is_blocked_url_host`] for a **source-supplied absolute URL** (Artifactory
//! `downloadUri` / Nexus `downloadUrl`) — attacker-influenced and reachable via
//! neither layer above (no name to resolve, not a redirect hop); and
//! [`redact_url`] to strip `user:pass@` userinfo before anything is logged
//! (reqwest's `Error` Display can stringify the URL, review Security #6).
//!
//! Contract: `import-ssrf-per-redirect-hop`. DNS-rebind is *pinned* (checked-IP
//! == connected-IP) by layer 1, not merely hoped.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use super::Result;

/// Maximum redirect hops an import request will follow. Beyond this the request
/// aborts (defence against redirect loops and slow-drip SSRF probes).
const MAX_REDIRECTS: usize = 10;

/// Parse a URL `host` component into an [`IpAddr`] if it is an IP literal.
///
/// `Url::host_str()` serializes IPv6 hosts **with** brackets (`[::1]`), which do
/// not parse as `IpAddr` directly — the exact class of bug that shipped a live
/// SSRF/loopback hole in #590 (`host_str() == "[::1]"`, `parse() == Err`). Strip
/// a single bracket pair before parsing so `[::1]` and `127.0.0.1` both resolve.
fn host_as_ip(host: &str) -> Option<IpAddr> {
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    unbracketed.parse::<IpAddr>().ok()
}

/// Is `ip` in a range an import must never reach (loopback / private / link-local
/// / ULA / cloud-metadata / unspecified / multicast)?
///
/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is un-mapped and re-checked as v4 so
/// `::ffff:169.254.169.254` cannot smuggle the metadata endpoint past a v4-only
/// check. Only **stable** `std::net` predicates are used; ULA/link-local for v6
/// are matched by prefix because `is_unique_local`/`is_unicast_link_local` are
/// still unstable.
pub(crate) fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_blocked_v4(v4),
            None => is_blocked_v6(v6),
        },
    }
}

fn is_blocked_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a.is_loopback()            // 127.0.0.0/8
        || a.is_private()      // 10/8, 172.16/12, 192.168/16
        || a.is_link_local()   // 169.254.0.0/16 (AWS/GCP/Azure IMDS 169.254.169.254)
        || a.is_broadcast()    // 255.255.255.255
        || a.is_documentation()// 192.0.2/24, 198.51.100/24, 203.0.113/24
        || a.is_unspecified()  // 0.0.0.0
        || a.is_multicast()    // 224.0.0.0/4
        || o[0] == 0           // 0.0.0.0/8 "this network"
        || (o[0] == 100 && (o[1] & 0xc0) == 0x40) // 100.64.0.0/10 CGNAT (Alibaba 100.100.*)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF protocol assignments
}

fn is_blocked_v6(a: Ipv6Addr) -> bool {
    // Un-embed a v4 address carried in IPv4-compatible `::/96` or NAT64
    // `64:ff9b::/96` form and re-check as v4 — otherwise `::169.254.169.254` or
    // `64:ff9b::a9fe:a9fe` (which reaches 169.254.169.254 under NAT64/DNS64)
    // would sail past a prefix-only check. (`::ffff:` v4-mapped is handled one
    // level up in `is_blocked_ip` via `to_ipv4_mapped`.)
    if let Some(v4) = embedded_v4(a) {
        return is_blocked_v4(v4);
    }
    a.is_loopback()            // ::1
        || a.is_unspecified()  // ::
        || a.is_multicast()    // ff00::/8
        || (a.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 ULA (AWS IMDS fd00:ec2::254)
        || (a.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
}

/// Extract an IPv4 address embedded in an IPv6 address in IPv4-compatible
/// (`::/96`) or NAT64 (`64:ff9b::/96`) form. Returns `None` for a normal v6
/// address (including `::ffff:` mapped, handled by `to_ipv4_mapped` upstream).
fn embedded_v4(a: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = a.segments();
    let tail = || {
        Ipv4Addr::new(
            (s[6] >> 8) as u8,
            (s[6] & 0xff) as u8,
            (s[7] >> 8) as u8,
            (s[7] & 0xff) as u8,
        )
    };
    // IPv4-compatible ::/96 (covers `::` and `::1` too — both stay blocked).
    if s[0..6] == [0, 0, 0, 0, 0, 0] {
        return Some(tail());
    }
    // NAT64 well-known prefix 64:ff9b::/96.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return Some(tail());
    }
    None
}

/// Pre-flight check on the operator-supplied `--url`: if its host is an IP
/// literal in a blocked range, refuse before any bytes move (hostname hosts are
/// covered by [`GuardedResolver`] at connect time). `allow_private` (from
/// `--allow-private-cidrs`) opts out of the block for private/loopback ranges.
pub fn precheck_url(url: &str, allow_private: bool) -> Result<()> {
    let parsed =
        reqwest::Url::parse(url).map_err(|e| format!("invalid --url {}: {e}", redact_url(url)))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => return Err(format!("unsupported URL scheme {other:?} (use http/https)")),
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("--url has no host: {}", redact_url(url)))?;
    if !allow_private {
        if let Some(ip) = host_as_ip(host) {
            if is_blocked_ip(ip) {
                return Err(format!(
                    "SSRF guard: --url host {ip} is loopback/private/metadata; pass --allow-private-cidrs to override"
                ));
            }
        }
    }
    Ok(())
}

/// True if `url`'s host is an IP literal in a denied range. For validating a
/// **source-supplied absolute URL** (Artifactory `downloadUri`, Nexus
/// `downloadUrl`) which bypasses both SSRF layers — the DNS resolver never fires
/// for an IP literal, and the redirect policy runs only on redirect hops, not on
/// a fresh initial request. Hostname hosts return `false`: the guarded client's
/// resolver pins them at connect. `allow_private` mirrors `--allow-private-cidrs`.
pub fn is_blocked_url_host(url: &str, allow_private: bool) -> bool {
    if allow_private {
        return false;
    }
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().and_then(host_as_ip).map(is_blocked_ip))
        .unwrap_or(false)
}

/// Strip `user:pass@` userinfo (and query) from a URL for safe logging. reqwest
/// error Display can echo the full URL including embedded credentials; never let
/// that reach a log line (review Security #6).
pub fn redact_url(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(mut u) => {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.set_query(None);
            u.to_string()
        }
        // Unparsable: fall back to a coarse redaction of any `scheme://a:b@host`.
        Err(_) => match (url.find("://"), url.find('@')) {
            (Some(s), Some(at)) if at > s + 3 => {
                format!("{}//{}", &url[..s + 1], &url[at + 1..])
            }
            _ => url.to_string(),
        },
    }
}

/// DNS resolver that drops blocked addresses and returns only vetted ones, so
/// reqwest connects to exactly the address we approved (DNS-pinned; defeats
/// rebind/TOCTOU). Used for the initial request and every redirect hop.
pub(crate) struct GuardedResolver {
    allow_private: bool,
}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let allow_private = self.allow_private;
        let host = name.as_str().to_string();
        Box::pin(async move {
            // Port 0 is a placeholder — reqwest overrides it with the URL/scheme
            // port. The system resolver is the trusted base; we only *filter*.
            let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0u16))
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .collect();
            if resolved.is_empty() {
                return Err(format!("no addresses resolved for {host}").into());
            }
            let allowed: Vec<SocketAddr> = if allow_private {
                resolved
            } else {
                resolved
                    .into_iter()
                    .filter(|sa| !is_blocked_ip(sa.ip()))
                    .collect()
            };
            if allowed.is_empty() {
                // Fail-closed: every answer was blocked (rebind to loopback, or a
                // hostname that only maps to private space).
                return Err(format!(
                    "SSRF guard: {host} resolves only to loopback/private/metadata addresses"
                )
                .into());
            }
            let addrs: reqwest::dns::Addrs = Box::new(allowed.into_iter());
            Ok(addrs)
        })
    }
}

/// Build the SSRF-guarded HTTP client for import adapters.
///
/// Mirrors `build_http_client`'s user-agent / custom-CA handling, then adds the
/// DNS-pinning resolver and the per-hop redirect guard. `allow_private` threads
/// `--allow-private-cidrs` through both layers.
///
/// Uses `connect_timeout` (fail fast if the source is unreachable) + a per-read
/// `read_timeout` (detect a stalled body) instead of a **total** timeout — a
/// multi-hour TB-scale artifact that keeps making progress must not be aborted
/// mid-stream (review R5).
pub fn build_import_client(
    tls: &crate::config::TlsConfig,
    connect_timeout: std::time::Duration,
    read_timeout: std::time::Duration,
    allow_private: bool,
) -> Result<reqwest::Client> {
    let redirect_policy =
        reqwest::redirect::Policy::custom(move |attempt| {
            match redirect_verdict(
                attempt.url().host_str(),
                attempt.previous().len(),
                allow_private,
            ) {
                RedirectVerdict::Follow => attempt.follow(),
                RedirectVerdict::TooMany => attempt.error(SsrfRedirectError(format!(
                    "exceeded {MAX_REDIRECTS} redirects"
                ))),
                RedirectVerdict::Blocked(ip) => {
                    attempt.error(SsrfRedirectError(format!("redirect to blocked IP {ip}")))
                }
            }
        });

    // SAFETY(reqwest-client-bypass): build_http_client is deliberately NOT reused
    // here — it has no redirect policy and no DNS resolver, so it cannot provide
    // the SSRF defence this client exists to add (review R2, issue #599). This
    // builder replicates its user-agent/CA handling and adds no_proxy + the
    // DNS-pinning resolver + per-hop redirect guard on top.
    let mut builder = reqwest::ClientBuilder::new() // nosemgrep: reqwest-client-bypass
        .user_agent(crate::USER_AGENT)
        .connect_timeout(connect_timeout)
        .read_timeout(read_timeout)
        // CRITICAL: no_proxy. The DNS-pinning [`GuardedResolver`] is authoritative
        // only for DIRECT connections — reqwest honors HTTP_PROXY/HTTPS_PROXY/
        // ALL_PROXY by default, and a proxy resolves the *target* hostname itself,
        // so an ambient proxy silently defeats the SSRF guard (the resolver would
        // only ever see the proxy's own hostname). This is an offline migration
        // CLI that connects to exactly one operator-supplied source, so it has no
        // reason to honor an ambient proxy (review: SSRF-via-proxy).
        .no_proxy()
        .redirect(redirect_policy)
        .dns_resolver(Arc::new(GuardedResolver { allow_private }));

    if let Some(ref ca_path) = tls.ca_cert {
        let pem = std::fs::read(ca_path).map_err(|e| format!("read CA cert {ca_path}: {e}"))?;
        let cert = reqwest::tls::Certificate::from_pem(&pem)
            .map_err(|e| format!("parse CA cert {ca_path}: {e}"))?;
        builder = builder.add_root_certificate(cert);
    }

    builder
        .build()
        .map_err(|e| format!("build import HTTP client: {e}"))
}

/// Decision for one redirect hop — extracted from the reqwest closure so the
/// per-hop SSRF logic is unit-testable without constructing a reqwest `Attempt`.
#[derive(Debug, PartialEq, Eq)]
enum RedirectVerdict {
    Follow,
    TooMany,
    Blocked(IpAddr),
}

/// Per-hop verdict: cap the hop count, and (unless opted out) block a redirect to
/// an IP-literal in a denied range. Hostname hops fall through to `Follow` — the
/// DNS-pinning [`GuardedResolver`] re-checks them at connect time.
fn redirect_verdict(host: Option<&str>, previous: usize, allow_private: bool) -> RedirectVerdict {
    if previous >= MAX_REDIRECTS {
        return RedirectVerdict::TooMany;
    }
    if !allow_private {
        if let Some(ip) = host.and_then(host_as_ip) {
            if is_blocked_ip(ip) {
                return RedirectVerdict::Blocked(ip);
            }
        }
    }
    RedirectVerdict::Follow
}

/// Error type surfaced from the redirect policy so a blocked hop aborts the
/// request instead of silently following it.
#[derive(Debug)]
struct SsrfRedirectError(String);

impl std::fmt::Display for SsrfRedirectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SSRF guard: {}", self.0)
    }
}

impl std::error::Error for SsrfRedirectError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_ipv4_loopback_private_metadata() {
        for s in [
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "169.254.169.254", // AWS/GCP/Azure IMDS
            "100.100.100.200", // Alibaba metadata (CGNAT 100.64/10)
            "0.0.0.0",
            "255.255.255.255",
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(is_blocked_ip(ip), "{s} should be blocked");
        }
    }

    #[test]
    fn blocks_ipv6_loopback_ula_linklocal_and_mapped_metadata() {
        for s in [
            "::1",
            "::",
            "fc00::1",
            "fd00:ec2::254", // AWS IMDS over IPv6 (ULA)
            "fe80::1",
            "::ffff:169.254.169.254", // v4-mapped metadata must not slip through
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::169.254.169.254",  // IPv4-compatible ::/96 embedding of metadata
            "::7f00:1",           // ::127.0.0.1 (IPv4-compatible loopback)
            "64:ff9b::a9fe:a9fe", // NAT64 64:ff9b::/96 embedding of 169.254.169.254
            "64:ff9b::10.0.0.5",  // NAT64 embedding of RFC1918
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(is_blocked_ip(ip), "{s} should be blocked");
        }
    }

    #[test]
    fn allows_public_addresses() {
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_blocked_ip(ip), "{s} should be allowed");
        }
    }

    #[test]
    fn host_as_ip_handles_bracketed_ipv6() {
        // The #590 regression: host_str() returns "[::1]" for IPv6 literals.
        assert_eq!(host_as_ip("[::1]"), Some("::1".parse().unwrap()));
        assert_eq!(host_as_ip("127.0.0.1"), Some("127.0.0.1".parse().unwrap()));
        assert_eq!(host_as_ip("example.com"), None);
    }

    #[test]
    fn precheck_rejects_ip_literal_metadata_and_loopback() {
        assert!(precheck_url("http://169.254.169.254/latest/meta-data/", false).is_err());
        assert!(precheck_url("http://127.0.0.1:8081/", false).is_err());
        assert!(precheck_url("http://[::1]/", false).is_err());
        assert!(precheck_url("http://10.0.0.5/api", false).is_err());
    }

    #[test]
    fn precheck_allows_public_and_hostnames_and_honors_optout() {
        assert!(precheck_url("https://artifactory.example.com/artifactory", false).is_ok());
        assert!(precheck_url("http://93.184.216.34/", false).is_ok());
        // Hostnames pass precheck (resolver enforces at connect).
        assert!(precheck_url("http://internal-nexus/", false).is_ok());
        // Opt-out lets a private literal through.
        assert!(precheck_url("http://10.0.0.5/", true).is_ok());
    }

    #[test]
    fn precheck_rejects_non_http_scheme() {
        assert!(precheck_url("file:///etc/passwd", false).is_err());
        assert!(precheck_url("gopher://evil/", false).is_err());
    }

    #[test]
    fn redirect_verdict_blocks_metadata_and_loopback_hops() {
        // IP-literal hops to denied ranges are blocked (DNS resolver never sees
        // them — there is no name to resolve).
        assert_eq!(
            redirect_verdict(Some("169.254.169.254"), 1, false),
            RedirectVerdict::Blocked("169.254.169.254".parse().unwrap())
        );
        assert_eq!(
            redirect_verdict(Some("[::1]"), 1, false),
            RedirectVerdict::Blocked("::1".parse().unwrap())
        );
        // Hostname hops fall through — the resolver re-checks them at connect.
        assert_eq!(
            redirect_verdict(Some("evil.example.com"), 1, false),
            RedirectVerdict::Follow
        );
        // Public literal is fine.
        assert_eq!(
            redirect_verdict(Some("93.184.216.34"), 1, false),
            RedirectVerdict::Follow
        );
        // Hop cap.
        assert_eq!(
            redirect_verdict(Some("example.com"), MAX_REDIRECTS, false),
            RedirectVerdict::TooMany
        );
        // Opt-out disables the IP block.
        assert_eq!(
            redirect_verdict(Some("10.0.0.1"), 1, true),
            RedirectVerdict::Follow
        );
    }

    #[test]
    fn redact_strips_userinfo_and_query() {
        assert_eq!(
            redact_url("https://user:s3cret@nexus.example.com/repo?token=abc"),
            "https://nexus.example.com/repo"
        );
        // No creds: unchanged host/path (query dropped).
        assert_eq!(
            redact_url("https://nexus.example.com/repo"),
            "https://nexus.example.com/repo"
        );
    }
}
