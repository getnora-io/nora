// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Rate limiting configuration and middleware
//!
//! Provides rate limiting to protect against:
//! - Brute-force authentication attacks
//! - DoS attacks on upload endpoints
//! - General API abuse

use crate::config::RateLimitConfig;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::SmartIpKeyExtractor;

/// Convert a "requests per second" value to a replenishment period.
///
/// `GovernorConfigBuilder::per_second(N)` sets the replenishment interval to
/// N *seconds*, not N requests/second. So `per_second(200)` means 1 token
/// every 200 seconds = 0.005 rps — the opposite of what we want.
///
/// For N rps we need: interval = 1000/N milliseconds per token.
/// For rps > 1000 the result is clamped to 1ms (= 1000 rps effective max).
fn rps_to_period(rps: u64) -> u64 {
    debug_assert!(rps > 0, "rate limit rps must be > 0");
    (1000 / rps.max(1)).max(1)
}

/// Create rate limiter layer for auth endpoints (strict protection against brute-force)
pub fn auth_rate_limiter(
    config: &RateLimitConfig,
) -> tower_governor::GovernorLayer<
    tower_governor::key_extractor::PeerIpKeyExtractor,
    governor::middleware::StateInformationMiddleware,
    axum::body::Body,
> {
    let gov_config = GovernorConfigBuilder::default()
        .per_millisecond(rps_to_period(config.auth_rps))
        .burst_size(config.auth_burst)
        .use_headers()
        .finish()
        .expect("failed to build auth rate limiter: invalid RateLimitConfig");

    tower_governor::GovernorLayer::new(gov_config)
}

/// Create rate limiter layer for upload endpoints
///
/// High limits to accommodate Docker client's aggressive parallel layer uploads
pub fn upload_rate_limiter(
    config: &RateLimitConfig,
) -> tower_governor::GovernorLayer<
    SmartIpKeyExtractor,
    governor::middleware::StateInformationMiddleware,
    axum::body::Body,
> {
    let gov_config = GovernorConfigBuilder::default()
        .key_extractor(SmartIpKeyExtractor)
        .per_millisecond(rps_to_period(config.upload_rps))
        .burst_size(config.upload_burst)
        .use_headers()
        .finish()
        .expect("failed to build upload rate limiter: invalid RateLimitConfig");

    tower_governor::GovernorLayer::new(gov_config)
}

/// Create rate limiter layer for general endpoints (lenient)
pub fn general_rate_limiter(
    config: &RateLimitConfig,
) -> tower_governor::GovernorLayer<
    SmartIpKeyExtractor,
    governor::middleware::StateInformationMiddleware,
    axum::body::Body,
> {
    let gov_config = GovernorConfigBuilder::default()
        .key_extractor(SmartIpKeyExtractor)
        .per_millisecond(rps_to_period(config.general_rps))
        .burst_size(config.general_burst)
        .use_headers()
        .finish()
        .expect("failed to build general rate limiter: invalid RateLimitConfig");

    tower_governor::GovernorLayer::new(gov_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RateLimitConfig;

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
        let _limiter = auth_rate_limiter(&config);
    }

    #[test]
    fn test_upload_rate_limiter_creation() {
        let config = RateLimitConfig::default();
        let _limiter = upload_rate_limiter(&config);
    }

    #[test]
    fn test_general_rate_limiter_creation() {
        let config = RateLimitConfig::default();
        let _limiter = general_rate_limiter(&config);
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
        let _auth = auth_rate_limiter(&config);
        let _upload = upload_rate_limiter(&config);
        let _general = general_rate_limiter(&config);
    }

    #[test]
    fn test_rps_to_period() {
        // 1 rps → 1000ms per token
        assert_eq!(rps_to_period(1), 1000);
        // 200 rps → 5ms per token
        assert_eq!(rps_to_period(200), 5);
        // 100 rps → 10ms per token
        assert_eq!(rps_to_period(100), 10);
        // 10 rps → 100ms per token
        assert_eq!(rps_to_period(10), 100);
        // 1000 rps → 1ms per token
        assert_eq!(rps_to_period(1000), 1);
        // >1000 rps → clamped to 1ms (prevents zero period)
        assert_eq!(rps_to_period(2000), 1);
        assert_eq!(rps_to_period(10000), 1);
    }
}
