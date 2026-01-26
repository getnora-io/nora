//! Rate limiting configuration and middleware
//!
//! Provides rate limiting to protect against:
//! - Brute-force authentication attacks
//! - DoS attacks on upload endpoints
//! - General API abuse

use tower_governor::governor::GovernorConfigBuilder;

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Requests per second for auth endpoints (strict)
    pub auth_rps: u32,
    /// Burst size for auth endpoints
    pub auth_burst: u32,
    /// Requests per second for upload endpoints
    pub upload_rps: u32,
    /// Burst size for upload endpoints
    pub upload_burst: u32,
    /// Requests per second for general endpoints (lenient)
    pub general_rps: u32,
    /// Burst size for general endpoints
    pub general_burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            auth_rps: 1,       // 1 req/sec for auth (strict)
            auth_burst: 5,     // Allow burst of 5
            upload_rps: 10,    // 10 req/sec for uploads
            upload_burst: 20,  // Allow burst of 20
            general_rps: 100,  // 100 req/sec general
            general_burst: 200, // Allow burst of 200
        }
    }
}

/// Create rate limiter layer for auth endpoints (strict protection against brute-force)
///
/// Default: 1 request per second, burst of 5
pub fn auth_rate_limiter() -> tower_governor::GovernorLayer<
    tower_governor::key_extractor::PeerIpKeyExtractor,
    governor::middleware::StateInformationMiddleware,
    axum::body::Body,
> {
    let config = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(5)
        .use_headers()
        .finish()
        .unwrap();

    tower_governor::GovernorLayer::new(config)
}

/// Create rate limiter layer for upload endpoints
///
/// Default: 10 requests per second, burst of 20
pub fn upload_rate_limiter() -> tower_governor::GovernorLayer<
    tower_governor::key_extractor::PeerIpKeyExtractor,
    governor::middleware::StateInformationMiddleware,
    axum::body::Body,
> {
    let config = GovernorConfigBuilder::default()
        .per_second(10)
        .burst_size(20)
        .use_headers()
        .finish()
        .unwrap();

    tower_governor::GovernorLayer::new(config)
}

/// Create rate limiter layer for general endpoints (lenient)
///
/// Default: 100 requests per second, burst of 200
pub fn general_rate_limiter() -> tower_governor::GovernorLayer<
    tower_governor::key_extractor::PeerIpKeyExtractor,
    governor::middleware::StateInformationMiddleware,
    axum::body::Body,
> {
    let config = GovernorConfigBuilder::default()
        .per_second(100)
        .burst_size(200)
        .use_headers()
        .finish()
        .unwrap();

    tower_governor::GovernorLayer::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RateLimitConfig::default();
        assert_eq!(config.auth_rps, 1);
        assert_eq!(config.auth_burst, 5);
        assert_eq!(config.upload_rps, 10);
        assert_eq!(config.general_rps, 100);
    }

    #[test]
    fn test_auth_rate_limiter_creation() {
        let _limiter = auth_rate_limiter();
    }

    #[test]
    fn test_upload_rate_limiter_creation() {
        let _limiter = upload_rate_limiter();
    }

    #[test]
    fn test_general_rate_limiter_creation() {
        let _limiter = general_rate_limiter();
    }
}
