// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Rate limiting configuration and middleware
//!
//! Provides rate limiting to protect against:
//! - Brute-force authentication attacks
//! - DoS attacks on upload endpoints
//! - General API abuse

use crate::auth::resolve_client_ip;
use crate::config::{RateLimitConfig, TrustedProxies};
use std::net::IpAddr;
use std::time::Duration;
use tower_governor::errors::GovernorError;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::KeyExtractor;

/// Convert a "requests per second" value to a replenishment period.
///
/// `GovernorConfigBuilder::per_second(N)` sets the replenishment interval to
/// N *seconds*, not N requests/second. So `per_second(200)` means 1 token
/// every 200 seconds = 0.005 rps — the opposite of what we want.
///
/// For N rps the interval is 1/N s, in nanoseconds so that any rate is kept as
/// configured: whole milliseconds capped every rate above 1000/s at 1000/s and
/// rounded rates between 500 and 1000/s up to 1000/s. The interval never drops
/// to zero, which the limiter refuses to build.
fn rps_to_period(rps: u64) -> Duration {
    debug_assert!(rps > 0, "rate limit rps must be > 0");
    Duration::from_nanos((1_000_000_000 / rps.max(1)).max(1))
}

/// Key extractor that resolves the real client IP using NORA's trusted proxy
/// configuration, rather than blindly trusting X-Forwarded-For headers (#541).
///
/// Uses [`resolve_client_ip`] which only honors XFF/X-Real-IP from peers in
/// the configured `trusted_proxies` list. Untrusted peers always get rate-limited
/// by their TCP peer IP, preventing XFF spoofing to bypass rate limits.
#[derive(Debug, Clone)]
pub struct TrustedProxyKeyExtractor {
    trusted_proxies: TrustedProxies,
}

impl TrustedProxyKeyExtractor {
    pub fn new(trusted_proxies: TrustedProxies) -> Self {
        Self { trusted_proxies }
    }
}

impl KeyExtractor for TrustedProxyKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &axum::http::Request<T>) -> Result<Self::Key, GovernorError> {
        let peer_ip = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip())
            .ok_or(GovernorError::UnableToExtractKey)?;

        let client_ip = resolve_client_ip(peer_ip, req.headers(), &self.trusted_proxies);

        debug_assert!(
            client_ip.is_ipv4() || client_ip.is_ipv6(),
            "resolved IP must be valid"
        );

        Ok(client_ip)
    }
}

/// The quota one limiter enforces: one request replenished every `interval`, at most
/// `burst` at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    pub interval: Duration,
    pub burst: u32,
}

impl Quota {
    /// Requests per second this quota admits once its burst is spent.
    pub fn per_second(&self) -> f64 {
        1e9 / self.interval.as_nanos() as f64
    }
}

/// The quotas of the three limiters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimiterQuotas {
    pub auth: Quota,
    pub upload: Quota,
    pub general: Quota,
}

/// The one place a configured rate becomes a quota: each limiter gets its own rate as an
/// interval of 1/N s and its own burst, unchanged.
pub fn limiter_quotas(config: &RateLimitConfig) -> LimiterQuotas {
    let quota = |rps, burst| Quota {
        interval: rps_to_period(rps),
        burst,
    };
    LimiterQuotas {
        auth: quota(config.auth_rps, config.auth_burst),
        upload: quota(config.upload_rps, config.upload_burst),
        general: quota(config.general_rps, config.general_burst),
    }
}

/// A rate limiter layer keyed by `K`.
pub type Limiter<K> = tower_governor::GovernorLayer<
    K,
    governor::middleware::StateInformationMiddleware,
    axum::body::Body,
>;

/// Build a limiter for `quota`, and return with it the quota its limiter enforces — read back
/// from the built limiter, so a caller can log and test what is enforced, not what was asked.
fn limiter<K: KeyExtractor<Key = IpAddr>>(key_extractor: K, quota: Quota) -> (Limiter<K>, Quota) {
    let config = GovernorConfigBuilder::default()
        .key_extractor(key_extractor)
        .period(quota.interval)
        .burst_size(quota.burst)
        .use_headers()
        .finish()
        .expect("failed to build a rate limiter: zero interval or burst");
    // Read with a key no client has; a limited answer carries the quota too.
    let enforced = match config.limiter().check_key(&IpAddr::from([0, 0, 0, 0])) {
        Ok(state) => state.quota(),
        Err(not_until) => not_until.quota(),
    };
    let enforced = Quota {
        interval: enforced.replenish_interval(),
        burst: enforced.burst_size().get(),
    };
    (tower_governor::GovernorLayer::new(config), enforced)
}

/// Create rate limiter layer for auth endpoints (strict protection against brute-force).
///
/// Uses [`TrustedProxyKeyExtractor`] to resolve real client IPs, preventing
/// both proxy-IP-sharing (all clients in one bucket) and XFF spoofing.
pub fn auth_rate_limiter(
    quota: Quota,
    trusted_proxies: TrustedProxies,
) -> (Limiter<TrustedProxyKeyExtractor>, Quota) {
    limiter(TrustedProxyKeyExtractor::new(trusted_proxies), quota)
}

/// Create rate limiter layer for upload endpoints
///
/// High limits to accommodate Docker client's aggressive parallel layer uploads.
/// Keyed by [`TrustedProxyKeyExtractor`], like the auth limiter: an untrusted peer
/// cannot mint a fresh bucket per request by varying X-Forwarded-For (#541 fixed
/// only the auth limiter; `SmartIpKeyExtractor` here trusted XFF from any peer).
pub fn upload_rate_limiter(
    quota: Quota,
    trusted_proxies: TrustedProxies,
) -> (Limiter<TrustedProxyKeyExtractor>, Quota) {
    limiter(TrustedProxyKeyExtractor::new(trusted_proxies), quota)
}

/// Create rate limiter layer for general endpoints (lenient). Keyed by
/// [`TrustedProxyKeyExtractor`] for the same reason as the upload limiter.
pub fn general_rate_limiter(
    quota: Quota,
    trusted_proxies: TrustedProxies,
) -> (Limiter<TrustedProxyKeyExtractor>, Quota) {
    limiter(TrustedProxyKeyExtractor::new(trusted_proxies), quota)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RateLimitConfig;
    use std::net::SocketAddr;

    #[test]
    fn test_default_config() {
        let config = RateLimitConfig::default();
        assert_eq!(config.auth_rps, 1);
        assert_eq!(config.auth_burst, 5);
        assert_eq!(config.upload_rps, 200);
        assert_eq!(config.general_rps, 100);
    }

    #[test]
    fn test_auth_rate_limiter_creation() {
        let config = RateLimitConfig::default();
        let _limiter = auth_rate_limiter(
            limiter_quotas(&config).auth,
            TrustedProxies::default_loopback(),
        )
        .0;
    }

    #[test]
    fn test_upload_rate_limiter_creation() {
        let config = RateLimitConfig::default();
        let _limiter = upload_rate_limiter(
            limiter_quotas(&config).upload,
            TrustedProxies::default_loopback(),
        )
        .0;
    }

    #[test]
    fn test_general_rate_limiter_creation() {
        let config = RateLimitConfig::default();
        let _limiter = general_rate_limiter(
            limiter_quotas(&config).general,
            TrustedProxies::default_loopback(),
        )
        .0;
    }

    /// A request routed through `layer`, from `peer`, carrying `xff` as X-Forwarded-For.
    async fn status_through(
        layer: &Limiter<TrustedProxyKeyExtractor>,
        peer: [u8; 4],
        xff: &str,
    ) -> axum::http::StatusCode {
        use tower::ServiceExt;
        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(layer.clone());
        let mut req = axum::http::Request::builder()
            .uri("/")
            .header("x-forwarded-for", xff)
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(SocketAddr::from((peer, 10000))));
        app.oneshot(req).await.unwrap().status()
    }

    // The upload and general limiters must bucket an untrusted peer by its TCP address, not by a
    // header it controls: a burst of one is spent by the first request, and a second request from
    // the same peer with a different X-Forwarded-For is limited (429), not given a fresh bucket.
    #[tokio::test]
    async fn edge_limiters_ignore_xff_from_an_untrusted_peer() {
        let quota = Quota {
            interval: Duration::from_secs(3600),
            burst: 1,
        };
        // The peer (2.2.2.2) is not in the trusted set, so its XFF must not be honored.
        let trusted = TrustedProxies::default_loopback();
        type Make = fn(Quota, TrustedProxies) -> (Limiter<TrustedProxyKeyExtractor>, Quota);
        for make in [upload_rate_limiter as Make, general_rate_limiter as Make] {
            let (layer, _) = make(quota, trusted.clone());
            let peer = [2, 2, 2, 2];
            assert_eq!(
                status_through(&layer, peer, "1.1.1.1").await,
                axum::http::StatusCode::OK,
                "first request spends the single token"
            );
            assert_eq!(
                status_through(&layer, peer, "9.9.9.9").await,
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "a different XFF from the same peer must not mint a fresh bucket"
            );
        }
    }

    // A trusted proxy's XFF is still honored: two different clients behind it keep their own
    // buckets, so the fix does not collapse everyone behind a reverse proxy into one limit.
    #[tokio::test]
    async fn edge_limiters_honor_xff_from_a_trusted_proxy() {
        let quota = Quota {
            interval: Duration::from_secs(3600),
            burst: 1,
        };
        let trusted = TrustedProxies::default_loopback(); // 127.0.0.1 is trusted
        let (layer, _) = upload_rate_limiter(quota, trusted);
        let proxy = [127, 0, 0, 1];
        assert_eq!(
            status_through(&layer, proxy, "1.1.1.1").await,
            axum::http::StatusCode::OK
        );
        assert_eq!(
            status_through(&layer, proxy, "2.2.2.2").await,
            axum::http::StatusCode::OK,
            "a second client behind the trusted proxy keeps its own bucket"
        );
        assert_eq!(
            status_through(&layer, proxy, "1.1.1.1").await,
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "the first client's bucket is spent"
        );
    }

    // Behind a reverse proxy that appends to X-Forwarded-For, a client that varies the header it
    // sends still lands in its own bucket: the address the proxy appended decides it.
    #[tokio::test]
    async fn edge_limiters_key_a_client_by_the_address_its_proxy_appended() {
        let quota = Quota {
            interval: Duration::from_secs(3600),
            burst: 1,
        };
        type Make = fn(Quota, TrustedProxies) -> (Limiter<TrustedProxyKeyExtractor>, Quota);
        for make in [upload_rate_limiter as Make, general_rate_limiter as Make] {
            let (layer, _) = make(quota, TrustedProxies::default_loopback());
            let proxy = [127, 0, 0, 1];
            assert_eq!(
                status_through(&layer, proxy, "1.1.1.1, 203.0.113.9").await,
                axum::http::StatusCode::OK
            );
            assert_eq!(
                status_through(&layer, proxy, "9.9.9.9, 203.0.113.9").await,
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "a different client-written part must not mint a fresh bucket"
            );
            assert_eq!(
                status_through(&layer, proxy, "1.1.1.1, 198.51.100.7").await,
                axum::http::StatusCode::OK,
                "another client behind the proxy keeps its own bucket"
            );
        }
    }

    #[test]
    fn test_custom_config() {
        let config = RateLimitConfig {
            enabled: true,
            auth_rps: 10,
            auth_burst: 20,
            upload_rps: 500,
            upload_burst: 1000,
            general_rps: 200,
            general_burst: 400,
        };
        let _auth = auth_rate_limiter(
            limiter_quotas(&config).auth,
            TrustedProxies::default_loopback(),
        )
        .0;
        let _upload = upload_rate_limiter(
            limiter_quotas(&config).upload,
            TrustedProxies::default_loopback(),
        )
        .0;
        let _general = general_rate_limiter(
            limiter_quotas(&config).general,
            TrustedProxies::default_loopback(),
        )
        .0;
    }

    #[test]
    fn a_rate_becomes_the_exact_interval_between_requests() {
        let ns = |rps| rps_to_period(rps).as_nanos();
        // The defaults keep their intervals: 1 s, 10 ms, 5 ms.
        assert_eq!(ns(1), 1_000_000_000);
        assert_eq!(ns(100), 10_000_000);
        assert_eq!(ns(200), 5_000_000);
        // Between 500 and 1000/s whole milliseconds rounded the rate up to 1000/s; above
        // 1000/s they capped it at 1000/s. Exact to the nanosecond either way rounded.
        for rps in [600, 1000, 5000, 1_000_000] {
            assert!(is_exact_interval(ns(rps), rps), "{rps}/s as {} ns", ns(rps));
        }
        // A rate beyond the clock keeps a non-zero interval.
        assert_eq!(ns(u64::MAX), 1);
    }

    /// Sends `count` GETs from one client through a router behind `layer`, `gap` apart, and
    /// returns their statuses. A macro: the three limiters are layers of different types.
    macro_rules! statuses {
        ($layer:expr, $count:expr, $gap:expr) => {{
            use tower::ServiceExt;
            let app = axum::Router::new()
                .route("/", axum::routing::get(|| async { "ok" }))
                .layer($layer);
            let mut out = Vec::new();
            for _ in 0..$count {
                let mut req = axum::http::Request::builder()
                    .uri("/")
                    .body(axum::body::Body::empty())
                    .unwrap();
                req.extensions_mut()
                    .insert(axum::extract::ConnectInfo(SocketAddr::from((
                        [127, 0, 0, 1],
                        4000,
                    ))));
                out.push(app.clone().oneshot(req).await.unwrap().status().as_u16());
                std::thread::sleep($gap);
            }
            out
        }};
    }

    fn every_rate(rps: u64, burst: u32) -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            auth_rps: rps,
            auth_burst: burst,
            upload_rps: rps,
            upload_burst: burst,
            general_rps: rps,
            general_burst: burst,
        }
    }

    // A million requests a second replenish one request every microsecond: twenty requests
    // 50 us apart all pass with a burst of one. Capped at 1000/s (one per millisecond), all but
    // the first are refused.
    #[tokio::test]
    async fn every_limiter_admits_a_configured_rate_above_a_thousand_per_second() {
        let config = every_rate(1_000_000, 1);
        let gap = std::time::Duration::from_micros(50);
        let all_pass = vec![200; 20];
        let auth = auth_rate_limiter(
            limiter_quotas(&config).auth,
            TrustedProxies::default_loopback(),
        )
        .0;
        assert_eq!(statuses!(auth, 20, gap), all_pass, "auth");
        assert_eq!(
            statuses!(
                upload_rate_limiter(
                    limiter_quotas(&config).upload,
                    TrustedProxies::default_loopback()
                )
                .0,
                20,
                gap
            ),
            all_pass,
            "upload"
        );
        assert_eq!(
            statuses!(
                general_rate_limiter(
                    limiter_quotas(&config).general,
                    TrustedProxies::default_loopback()
                )
                .0,
                20,
                gap
            ),
            all_pass,
            "general"
        );
    }

    // One request a second with a burst of three: three pass at once, the fourth is refused.
    #[tokio::test]
    async fn every_limiter_admits_exactly_its_configured_burst() {
        let config = every_rate(1, 3);
        let gap = std::time::Duration::ZERO;
        let burst = vec![200, 200, 200, 429];
        let auth = auth_rate_limiter(
            limiter_quotas(&config).auth,
            TrustedProxies::default_loopback(),
        )
        .0;
        assert_eq!(statuses!(auth, 4, gap), burst, "auth");
        assert_eq!(
            statuses!(
                upload_rate_limiter(
                    limiter_quotas(&config).upload,
                    TrustedProxies::default_loopback()
                )
                .0,
                4,
                gap
            ),
            burst,
            "upload"
        );
        assert_eq!(
            statuses!(
                general_rate_limiter(
                    limiter_quotas(&config).general,
                    TrustedProxies::default_loopback()
                )
                .0,
                4,
                gap
            ),
            burst,
            "general"
        );
    }

    // Each limiter reads its own pair of settings: the bursts differ (1, 2, 3), and of the
    // rates only the one under test is fast.
    #[tokio::test]
    async fn each_limiter_reads_its_own_rate_and_burst() {
        let config = RateLimitConfig {
            enabled: true,
            auth_rps: 1,
            auth_burst: 1,
            upload_rps: 1,
            upload_burst: 2,
            general_rps: 1,
            general_burst: 3,
        };
        let gap = std::time::Duration::ZERO;
        let auth = auth_rate_limiter(
            limiter_quotas(&config).auth,
            TrustedProxies::default_loopback(),
        )
        .0;
        assert_eq!(statuses!(auth, 4, gap), vec![200, 429, 429, 429], "auth");
        let upload = statuses!(
            upload_rate_limiter(
                limiter_quotas(&config).upload,
                TrustedProxies::default_loopback()
            )
            .0,
            4,
            gap
        );
        assert_eq!(upload, vec![200, 200, 429, 429], "upload");
        let general = statuses!(
            general_rate_limiter(
                limiter_quotas(&config).general,
                TrustedProxies::default_loopback()
            )
            .0,
            4,
            gap
        );
        assert_eq!(general, vec![200, 200, 200, 429], "general");

        let gap = std::time::Duration::from_micros(50);
        let slow = vec![200, 429, 429, 429, 429];
        for fast in ["auth", "upload", "general"] {
            let mut config = every_rate(1, 1);
            match fast {
                "auth" => config.auth_rps = 1_000_000,
                "upload" => config.upload_rps = 1_000_000,
                _ => config.general_rps = 1_000_000,
            }
            let expected = |name| {
                if name == fast {
                    vec![200; 5]
                } else {
                    slow.clone()
                }
            };
            let auth = auth_rate_limiter(
                limiter_quotas(&config).auth,
                TrustedProxies::default_loopback(),
            )
            .0;
            assert_eq!(
                statuses!(auth, 5, gap),
                expected("auth"),
                "{fast} fast: auth"
            );
            let upload = statuses!(
                upload_rate_limiter(
                    limiter_quotas(&config).upload,
                    TrustedProxies::default_loopback()
                )
                .0,
                5,
                gap
            );
            assert_eq!(upload, expected("upload"), "{fast} fast: upload");
            let general = statuses!(
                general_rate_limiter(
                    limiter_quotas(&config).general,
                    TrustedProxies::default_loopback()
                )
                .0,
                5,
                gap
            );
            assert_eq!(general, expected("general"), "{fast} fast: general");
        }
    }

    // A rate beyond what the clock can space out still builds a limiter (no zero interval,
    // which would fail the build at startup) and admits requests.
    #[tokio::test]
    async fn a_rate_beyond_the_clock_still_starts() {
        let config = every_rate(u64::MAX, 1);
        let gap = std::time::Duration::from_micros(50);
        let auth = auth_rate_limiter(
            limiter_quotas(&config).auth,
            TrustedProxies::default_loopback(),
        )
        .0;
        assert_eq!(statuses!(auth, 3, gap), vec![200; 3], "auth");
        assert_eq!(
            statuses!(
                upload_rate_limiter(
                    limiter_quotas(&config).upload,
                    TrustedProxies::default_loopback()
                )
                .0,
                3,
                gap
            ),
            vec![200; 3],
            "upload"
        );
        assert_eq!(
            statuses!(
                general_rate_limiter(
                    limiter_quotas(&config).general,
                    TrustedProxies::default_loopback()
                )
                .0,
                3,
                gap
            ),
            vec![200; 3],
            "general"
        );
    }

    /// The interval is 1/rps s to the nanosecond (|interval - 1e9/rps| <= 1 ns) and never zero.
    fn is_exact_interval(interval_ns: u128, rps: u64) -> bool {
        let rps = u128::from(rps);
        interval_ns != 0 && (interval_ns * rps).abs_diff(1_000_000_000) <= rps
    }

    // Every limiter enforces its own rate as an interval exact to the nanosecond and its own
    // burst, over the whole range — every power of two and its neighbours, 2^32 + 200 and
    // u64::MAX, bursts up to u32::MAX. Read from the built limiters, not from request timing,
    // which cannot tell 1 us from 20 us. Rates and bursts rotate between the limiters so that
    // reading a neighbour's setting differs too.
    #[test]
    fn every_limiter_enforces_its_own_exact_rate_and_burst_over_the_range() {
        let mut rates: Vec<u64> = vec![600, 999, 1_500_000, (1 << 32) + 200, u64::MAX];
        for k in 0..64 {
            let p = 1u64 << k;
            rates.extend([p - 1, p, p + 1]);
        }
        rates.retain(|r| *r > 0);
        let bursts: [u32; 9] = [1, 5, 200, 500, 65_535, 65_536, 100_000, 1 << 24, u32::MAX];
        let n = rates.len();
        for i in 0..n {
            let (a, u, g) = (rates[i], rates[(i + 7) % n], rates[(i + 13) % n]);
            let config = RateLimitConfig {
                enabled: true,
                auth_rps: a,
                auth_burst: bursts[i % 9],
                upload_rps: u,
                upload_burst: bursts[(i + 3) % 9],
                general_rps: g,
                general_burst: bursts[(i + 5) % 9],
            };
            let quotas = limiter_quotas(&config);
            for (name, quota, rps, burst) in [
                ("auth", quotas.auth, a, config.auth_burst),
                ("upload", quotas.upload, u, config.upload_burst),
                ("general", quotas.general, g, config.general_burst),
            ] {
                let t = quota.interval.as_nanos();
                assert!(is_exact_interval(t, rps), "{name} {rps}/s as {t} ns");
                assert_eq!(quota.burst, burst, "{name} burst");
            }
            let (_, auth) = auth_rate_limiter(quotas.auth, TrustedProxies::default_loopback());
            assert_eq!(auth, quotas.auth, "auth enforced");
            assert_eq!(
                upload_rate_limiter(quotas.upload, TrustedProxies::default_loopback()).1,
                quotas.upload,
                "upload enforced"
            );
            assert_eq!(
                general_rate_limiter(quotas.general, TrustedProxies::default_loopback()).1,
                quotas.general,
                "general enforced"
            );
        }
        // The defaults keep their intervals: 1 s, 5 ms, 10 ms; bursts 5, 500, 200.
        let quotas = limiter_quotas(&RateLimitConfig::default());
        let ms = std::time::Duration::from_millis;
        assert_eq!((quotas.auth.interval, quotas.auth.burst), (ms(1000), 5));
        assert_eq!((quotas.upload.interval, quotas.upload.burst), (ms(5), 500));
        assert_eq!(
            (quotas.general.interval, quotas.general.burst),
            (ms(10), 200)
        );
    }

    /// The quota a layer actually enforces, read through the layer itself.
    fn applied<K: KeyExtractor<Key = IpAddr>>(layer: &Limiter<K>) -> Quota {
        use tower::Layer as _;
        let service = layer.layer(());
        let quota = match service.limiter.check_key(&IpAddr::from([127, 0, 0, 1])) {
            Ok(state) => state.quota(),
            Err(not_until) => not_until.quota(),
        };
        Quota {
            interval: quota.replenish_interval(),
            burst: quota.burst_size().get(),
        }
    }

    // What a builder reports is what its layer enforces, read independently through the layer.
    #[test]
    fn every_limiter_reports_what_its_layer_enforces() {
        for (rps, burst) in [(1, 1), (600, 5), (5_000_000, 100_000), (u64::MAX, u32::MAX)] {
            let quota = Quota {
                interval: rps_to_period(rps),
                burst,
            };
            let (layer, reported) = auth_rate_limiter(quota, TrustedProxies::default_loopback());
            assert_eq!(reported, applied(&layer), "auth {rps} {burst}");
            let (layer, reported) = upload_rate_limiter(quota, TrustedProxies::default_loopback());
            assert_eq!(reported, applied(&layer), "upload {rps} {burst}");
            let (layer, reported) = general_rate_limiter(quota, TrustedProxies::default_loopback());
            assert_eq!(reported, applied(&layer), "general {rps} {burst}");
        }
    }

    // The limiters are built only in this file and `main.rs`'s `rate_limited_routes`; neither
    // has a build-only twin (`cfg(not(test))`) that tests cannot see.
    #[test]
    fn the_limiter_code_has_no_build_only_twin() {
        let here = include_str!("rate_limit.rs");
        let production = &here[..here.find("#[cfg(test)]\nmod tests {").unwrap()];
        assert!(!production.contains("cfg(not(test))"), "rate_limit.rs");
        assert!(!production.contains("cfg(test)"), "rate_limit.rs");
        let main = include_str!("main.rs");
        let routes = &main[main.find("fn rate_limited_routes").unwrap()..];
        let routes = &routes[..routes.find("\n}\n").unwrap()];
        assert!(!routes.contains("cfg("), "rate_limited_routes");
    }

    /// The `x-ratelimit-limit` header of the first response: the burst the limiter was built with.
    macro_rules! announced_burst {
        ($layer:expr) => {{
            use tower::ServiceExt;
            let app = axum::Router::new()
                .route("/", axum::routing::get(|| async { "ok" }))
                .layer($layer);
            let mut req = axum::http::Request::builder()
                .uri("/")
                .body(axum::body::Body::empty())
                .unwrap();
            req.extensions_mut()
                .insert(axum::extract::ConnectInfo(SocketAddr::from((
                    [127, 0, 0, 1],
                    4000,
                ))));
            let resp = app.oneshot(req).await.unwrap();
            resp.headers()["x-ratelimit-limit"]
                .to_str()
                .unwrap()
                .parse::<u32>()
                .unwrap()
        }};
    }

    // Each limiter answers with its own burst, exactly, also above the small bursts the
    // request-counting tests can afford (the defaults are 5, 500 and 200).
    #[tokio::test]
    async fn every_limiter_answers_with_its_own_burst() {
        for (auth_burst, upload_burst, general_burst) in
            [(5, 500, 200), (10, 1000, 400), (u32::MAX, 7, 65)]
        {
            let config = RateLimitConfig {
                enabled: true,
                auth_rps: 1,
                auth_burst,
                upload_rps: 200,
                upload_burst,
                general_rps: 100,
                general_burst,
            };
            let auth = auth_rate_limiter(
                limiter_quotas(&config).auth,
                TrustedProxies::default_loopback(),
            )
            .0;
            assert_eq!(announced_burst!(auth), auth_burst, "auth");
            assert_eq!(
                announced_burst!(
                    upload_rate_limiter(
                        limiter_quotas(&config).upload,
                        TrustedProxies::default_loopback()
                    )
                    .0
                ),
                upload_burst,
                "upload"
            );
            assert_eq!(
                announced_burst!(
                    general_rate_limiter(
                        limiter_quotas(&config).general,
                        TrustedProxies::default_loopback()
                    )
                    .0
                ),
                general_burst,
                "general"
            );
        }
    }

    #[test]
    fn test_trusted_proxy_extractor_uses_peer_for_untrusted() {
        use axum::http::Request;

        let proxies = TrustedProxies::parse("10.0.0.0/8");
        let extractor = TrustedProxyKeyExtractor::new(proxies);

        // Untrusted peer (192.168.1.1) with spoofed XFF — should use peer IP
        let mut req = Request::builder().body(()).unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(SocketAddr::from((
                [192, 168, 1, 1],
                1234,
            ))));
        req.headers_mut()
            .insert("x-forwarded-for", "1.2.3.4".parse().unwrap());

        let key = extractor.extract(&req).unwrap();
        assert_eq!(key, IpAddr::from([192, 168, 1, 1]));
    }

    #[test]
    fn test_trusted_proxy_extractor_uses_xff_for_trusted() {
        use axum::http::Request;

        let proxies = TrustedProxies::parse("10.0.0.0/8");
        let extractor = TrustedProxyKeyExtractor::new(proxies);

        // Trusted peer (10.0.0.1) with real XFF — should use XFF client IP
        let mut req = Request::builder().body(()).unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(SocketAddr::from((
                [10, 0, 0, 1],
                1234,
            ))));
        req.headers_mut()
            .insert("x-forwarded-for", "5.6.7.8".parse().unwrap());

        let key = extractor.extract(&req).unwrap();
        assert_eq!(key, IpAddr::from([5, 6, 7, 8]));
    }

    #[test]
    fn test_trusted_proxy_extractor_no_connect_info() {
        use axum::http::Request;

        let proxies = TrustedProxies::default_loopback();
        let extractor = TrustedProxyKeyExtractor::new(proxies);

        let req = Request::builder().body(()).unwrap();
        let result = extractor.extract(&req);
        assert!(result.is_err());
    }

    /// Over a dual-stack socket an IPv4 peer is `::ffff:a.b.c.d`. The limiters
    /// key it as its IPv4 address: the loopback proxy stays trusted, so each
    /// client behind it gets its own bucket, and a direct client gets the same
    /// bucket over either socket.
    #[test]
    fn a_v4_mapped_peer_keys_as_its_ipv4_address() {
        use axum::http::Request;

        let extractor = TrustedProxyKeyExtractor::new(TrustedProxies::default_loopback());
        let key = |peer: &str, xff: Option<&str>| {
            let mut req = Request::builder().body(()).unwrap();
            req.extensions_mut()
                .insert(axum::extract::ConnectInfo(SocketAddr::new(
                    peer.parse().unwrap(),
                    1234,
                )));
            if let Some(xff) = xff {
                req.headers_mut()
                    .insert("x-forwarded-for", xff.parse().unwrap());
            }
            extractor.extract(&req).unwrap()
        };
        assert_eq!(
            key("::ffff:127.0.0.1", Some("198.51.100.7")),
            IpAddr::from([198, 51, 100, 7])
        );
        assert_eq!(
            key("::ffff:127.0.0.1", Some("203.0.113.10")),
            IpAddr::from([203, 0, 113, 10])
        );
        assert_eq!(
            key("::ffff:203.0.113.5", None),
            IpAddr::from([203, 0, 113, 5])
        );
    }
}
