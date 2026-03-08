//! Transport-level rate limiting using a token bucket per source IP.
//!
//! Applied before SIP parsing — drops packets (UDP) or closes connections (TCP)
//! that exceed the configured rate. This protects against flooding attacks at the
//! transport layer, complementing the script-level rate limiting in proxy_utils.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use tracing::warn;

/// Token bucket for a single source IP.
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// Transport-level rate limiter.
///
/// Each source IP gets a token bucket. Tokens are refilled at `rate` per second,
/// up to a maximum of `burst`. Each packet consumes one token. When tokens are
/// exhausted, the packet is dropped.
pub struct TransportRateLimiter {
    buckets: Arc<DashMap<IpAddr, Bucket>>,
    /// Tokens added per second.
    rate: f64,
    /// Maximum tokens (burst capacity).
    burst: f64,
}

impl TransportRateLimiter {
    pub fn new(packets_per_sec: u32, burst: u32) -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            rate: packets_per_sec as f64,
            burst: burst as f64,
        }
    }

    /// Check if a packet from `source` should be allowed.
    /// Returns `true` if allowed, `false` if rate-limited.
    pub fn allow(&self, source: IpAddr) -> bool {
        let now = Instant::now();

        let mut entry = self.buckets.entry(source).or_insert_with(|| Bucket {
            tokens: self.burst,
            last_refill: now,
        });

        let bucket = entry.value_mut();

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.burst);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            warn!(source = %source, "transport rate limit exceeded");
            false
        }
    }

    /// Remove stale entries (IPs not seen for a while) to prevent memory growth.
    /// Call periodically (e.g. every 60s).
    pub fn cleanup_stale(&self, max_age_secs: f64) {
        let now = Instant::now();
        self.buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_refill).as_secs_f64() < max_age_secs
        });
    }

    /// Number of tracked source IPs.
    pub fn tracked_sources(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_within_rate() {
        let limiter = TransportRateLimiter::new(10, 10);
        let source: IpAddr = "10.0.0.1".parse().unwrap();

        // Should allow 10 packets (burst)
        for _ in 0..10 {
            assert!(limiter.allow(source));
        }
    }

    #[test]
    fn blocks_over_burst() {
        let limiter = TransportRateLimiter::new(10, 5);
        let source: IpAddr = "10.0.0.2".parse().unwrap();

        // Use up all 5 burst tokens
        for _ in 0..5 {
            assert!(limiter.allow(source));
        }

        // 6th should be blocked
        assert!(!limiter.allow(source));
    }

    #[test]
    fn refills_over_time() {
        let limiter = TransportRateLimiter::new(1000, 1);
        let source: IpAddr = "10.0.0.3".parse().unwrap();

        // Use the one token
        assert!(limiter.allow(source));
        assert!(!limiter.allow(source));

        // Wait for refill (1000/sec → 1ms per token)
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(limiter.allow(source));
    }

    #[test]
    fn independent_per_ip() {
        let limiter = TransportRateLimiter::new(10, 2);
        let source_a: IpAddr = "10.0.0.1".parse().unwrap();
        let source_b: IpAddr = "10.0.0.2".parse().unwrap();

        // Exhaust A
        assert!(limiter.allow(source_a));
        assert!(limiter.allow(source_a));
        assert!(!limiter.allow(source_a));

        // B should still have tokens
        assert!(limiter.allow(source_b));
        assert!(limiter.allow(source_b));
    }

    #[test]
    fn cleanup_removes_stale() {
        let limiter = TransportRateLimiter::new(10, 10);
        let source: IpAddr = "10.0.0.1".parse().unwrap();

        limiter.allow(source);
        assert_eq!(limiter.tracked_sources(), 1);

        // Cleanup with very short max age — entry is "fresh" so it stays
        limiter.cleanup_stale(60.0);
        assert_eq!(limiter.tracked_sources(), 1);

        // Cleanup with 0 max age — everything is stale
        limiter.cleanup_stale(0.0);
        assert_eq!(limiter.tracked_sources(), 0);
    }
}
