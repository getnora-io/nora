//! Rate limiting configuration and middleware
//!
//! Provides rate limiting to protect against:
//! - Brute-force authentication attacks
//! - DoS attacks on upload endpoints
//! - General API abuse

use crate::config::RateLimitConfig;
use tower_governor::governor::GovernorConfigBuilder;

/// Create rate limiter layer for auth endpoints (strict protection against brute-force)
pub fn auth_rate_limiter(
    config: &RateLimitConfig,
) -> tower_governor::GovernorLayer<
    tower_governor::key_extractor::PeerIpKeyExtractor,
    governor::middleware::StateInformationMiddleware,
    axum::body::Body,
> {
    let gov_config = GovernorConfigBuilder::default()
        .per_second(config.auth_rps)
        .burst_size(config.auth_burst)
        .use_headers()
        .finish()
        .expect("Failed to build auth rate limiter");

    tower_governor::GovernorLayer::new(gov_config)
}

/// Create rate limiter layer for upload endpoints
///
/// High limits to accommodate Docker client's aggressive parallel layer uploads
pub fn upload_rate_limiter(
    config: &RateLimitConfig,
) -> tower_governor::GovernorLayer<
    tower_governor::key_extractor::PeerIpKeyExtractor,
    governor::middleware::StateInformationMiddleware,
    axum::body::Body,
> {
    let gov_config = GovernorConfigBuilder::default()
        .per_second(config.upload_rps)
        .burst_size(config.upload_burst)
        .use_headers()
        .finish()
        .expect("Failed to build upload rate limiter");

    tower_governor::GovernorLayer::new(gov_config)
}

/// Create rate limiter layer for general endpoints (lenient)
pub fn general_rate_limiter(
    config: &RateLimitConfig,
) -> tower_governor::GovernorLayer<
    tower_governor::key_extractor::PeerIpKeyExtractor,
    governor::middleware::StateInformationMiddleware,
    axum::body::Body,
> {
    let gov_config = GovernorConfigBuilder::default()
        .per_second(config.general_rps)
        .burst_size(config.general_burst)
        .use_headers()
        .finish()
        .expect("Failed to build general rate limiter");

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
}
