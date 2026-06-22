//! Auto-ban store — per-source-IP failure tracking with TTL bans.
//!
//! Feeds the transport ACL ([`crate::transport::acl::TransportAcl::is_allowed`])
//! so a banned source is dropped at accept/recv, before any SIP parsing. Two
//! failure signals increment the same per-IP counter:
//!   * an auth challenge issued without valid credentials ([`crate::script::api`]
//!     auth path), and
//!   * a non-ACK INVITE **server**-transaction timeout (dispatcher) — the peer
//!     sent an INVITE, got a final response, and never ACKed it.
//!
//! A successful authentication resets the counter, so a legitimate client that
//! challenges-then-succeeds never accumulates. Sources matching `trusted_cidrs`
//! are never counted and never banned (own infrastructure: BGCF, trunks,
//! monitoring).
//!
//! The whole feature is opt-in: it is only constructed when
//! `security.failed_auth_ban` is configured.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use ipnet::IpNet;

/// Process-wide auto-ban store. `None` until installed at startup (only when
/// `security.failed_auth_ban` is configured), so the whole feature is opt-in and
/// every hot-path check is a cheap `OnceLock` read. Mirrors
/// [`crate::metrics::try_metrics`].
static AUTO_BAN: OnceLock<Arc<AutoBanStore>> = OnceLock::new();

/// Install the process-wide auto-ban store (idempotent — a second call is a
/// no-op). Called once at server startup before any traffic is accepted.
pub fn set_auto_ban(store: Arc<AutoBanStore>) {
    let _ = AUTO_BAN.set(store);
}

/// The process-wide auto-ban store, or `None` when `security.failed_auth_ban`
/// is not configured. Read on the accept/recv path (ACL), the auth path, and the
/// transaction-timeout path.
pub fn auto_ban() -> Option<&'static Arc<AutoBanStore>> {
    AUTO_BAN.get()
}

/// Process-wide request-level security filter (PIKE-style per-source rate
/// limiting + scanner User-Agent blocking). `None` until installed at startup,
/// and only installed when `security.rate_limit` or `security.scanner_block` is
/// configured — so the dispatcher hot-path check is a cheap `OnceLock` read that
/// no-ops until the feature is turned on. Mirrors [`AUTO_BAN`].
static SECURITY_FILTER: OnceLock<Arc<SecurityFilter>> = OnceLock::new();

/// Install the process-wide request security filter (idempotent — a second call
/// is a no-op). Called once at server startup before any traffic is accepted.
pub fn set_security_filter(filter: Arc<SecurityFilter>) {
    let _ = SECURITY_FILTER.set(filter);
}

/// The process-wide request security filter, or `None` when neither
/// `security.rate_limit` nor `security.scanner_block` is configured. Read on the
/// dispatcher's inbound-request path before transaction/dialog processing.
pub fn security_filter() -> Option<&'static Arc<SecurityFilter>> {
    SECURITY_FILTER.get()
}

/// Fixed-window failure counter for one source IP.
#[derive(Debug, Clone, Copy)]
struct FailureWindow {
    count: u32,
    window_start: Instant,
}

/// Per-source-IP auto-ban store. Cheap, lock-free reads (DashMap), `Send + Sync`,
/// shared as an `Arc` between the transport ACL, the auth path, and the dispatcher.
pub struct AutoBanStore {
    /// IP → current failure window.
    failures: DashMap<IpAddr, FailureWindow>,
    /// IP → ban expiry instant.
    bans: DashMap<IpAddr, Instant>,
    /// Sources that are never counted and never banned.
    trusted: Vec<IpNet>,
    threshold: u32,
    window: Duration,
    ban_duration: Duration,
}

impl AutoBanStore {
    /// Build a store from the `failed_auth_ban` policy and `trusted_cidrs`.
    /// Invalid CIDRs in `trusted_cidrs` are ignored (logged by the caller).
    pub fn new(
        threshold: u32,
        window_secs: u32,
        ban_duration_secs: u32,
        trusted_cidrs: &[String],
    ) -> Self {
        let trusted = trusted_cidrs
            .iter()
            .filter_map(|cidr| cidr.parse::<IpNet>().ok())
            .collect();
        Self {
            failures: DashMap::new(),
            bans: DashMap::new(),
            trusted,
            // Guard against a zero policy disabling the feature by accident.
            threshold: threshold.max(1),
            window: Duration::from_secs(u64::from(window_secs.max(1))),
            ban_duration: Duration::from_secs(u64::from(ban_duration_secs.max(1))),
        }
    }

    fn is_trusted(&self, source: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(&source))
    }

    /// Record one failure for `source`. Returns `true` if this call newly banned
    /// the IP (so the caller can log/metric the transition once).
    pub fn record_failure(&self, source: IpAddr) -> bool {
        self.record_failure_at(source, Instant::now())
    }

    fn record_failure_at(&self, source: IpAddr, now: Instant) -> bool {
        if self.is_trusted(source) {
            return false;
        }
        if self.is_banned_at(source, now) {
            // Already banned — nothing to escalate.
            return false;
        }

        let newly_banned = {
            let mut entry = self
                .failures
                .entry(source)
                .or_insert(FailureWindow { count: 0, window_start: now });
            // Roll the window if it has elapsed.
            if now.duration_since(entry.window_start) > self.window {
                entry.count = 0;
                entry.window_start = now;
            }
            entry.count += 1;
            entry.count >= self.threshold
            // `entry` (shard write guard) dropped here, before we touch `bans`
            // or `failures` again — never hold a DashMap guard across another
            // op on the same map.
        };

        if newly_banned {
            self.failures.remove(&source);
            self.bans.insert(source, now + self.ban_duration);
        }
        newly_banned
    }

    /// A successful authentication from `source` clears its failure count.
    pub fn record_success(&self, source: IpAddr) {
        self.failures.remove(&source);
    }

    /// Whether `source` is currently banned. Trusted sources are never banned.
    /// Expired bans are lazily removed.
    pub fn is_banned(&self, source: IpAddr) -> bool {
        self.is_banned_at(source, Instant::now())
    }

    fn is_banned_at(&self, source: IpAddr, now: Instant) -> bool {
        if self.is_trusted(source) {
            return false;
        }
        // Copy the expiry out so we never hold the shard read guard across the
        // `remove()` below (would deadlock on the same shard).
        let expiry = self.bans.get(&source).map(|entry| *entry.value());
        match expiry {
            Some(exp) if exp > now => true,
            Some(_) => {
                self.bans.remove(&source);
                false
            }
            None => false,
        }
    }

    /// Number of currently-tracked bans (may include not-yet-pruned expired
    /// entries; published as a metric and pruned periodically).
    pub fn active_bans(&self) -> usize {
        self.bans.len()
    }

    /// Drop expired bans and stale failure windows. Call periodically to keep
    /// memory bounded under scanner churn.
    pub fn prune(&self) {
        self.prune_at(Instant::now());
    }

    fn prune_at(&self, now: Instant) {
        self.bans.retain(|_, expiry| *expiry > now);
        self.failures
            .retain(|_, window| now.duration_since(window.window_start) <= self.window);
    }
}

/// Verdict for one inbound request, returned by [`SecurityFilter::evaluate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityVerdict {
    /// Source is permitted — proceed to transaction/dialog/script processing.
    Allow,
    /// Source's `User-Agent` matched a `security.scanner_block` signature —
    /// drop silently (no response) so the server is not fingerprinted.
    Scanner,
    /// Source exceeded `security.rate_limit.max_requests` within the window (or
    /// is inside the resulting ban) — drop silently.
    RateLimited,
}

/// Fixed-window per-source-IP rate limiter with TTL bans. Replaces the Kamailio
/// PIKE module: once a source sends more than `max_requests` within `window`, it
/// is banned for `ban_duration` and every further request is dropped until the
/// ban expires.
struct RateLimitState {
    /// IP → current request-count window.
    windows: DashMap<IpAddr, FailureWindow>,
    /// IP → ban expiry instant.
    bans: DashMap<IpAddr, Instant>,
    max_requests: u32,
    window: Duration,
    ban_duration: Duration,
}

impl RateLimitState {
    /// Count one request from `source`. Returns `true` when the request is
    /// within the limit, `false` when the source is over the limit (and now
    /// banned) or already inside an active ban.
    fn check_at(&self, source: IpAddr, now: Instant) -> bool {
        // Active ban? (Copy the expiry out before any mutation so we never hold
        // a DashMap shard guard across a second op on the same map.)
        let ban_expiry = self.bans.get(&source).map(|entry| *entry.value());
        match ban_expiry {
            Some(expiry) if expiry > now => return false,
            Some(_) => {
                self.bans.remove(&source);
            }
            None => {}
        }

        let over_limit = {
            let mut entry = self
                .windows
                .entry(source)
                .or_insert(FailureWindow { count: 0, window_start: now });
            if now.duration_since(entry.window_start) > self.window {
                entry.count = 0;
                entry.window_start = now;
            }
            entry.count += 1;
            entry.count > self.max_requests
            // shard write guard dropped here, before touching `bans`/`windows`.
        };

        if over_limit {
            self.windows.remove(&source);
            self.bans.insert(source, now + self.ban_duration);
            return false;
        }
        true
    }

    fn active_bans(&self) -> usize {
        self.bans.len()
    }

    fn prune_at(&self, now: Instant) {
        self.bans.retain(|_, expiry| *expiry > now);
        self.windows
            .retain(|_, window| now.duration_since(window.window_start) <= self.window);
    }
}

/// Request-level security filter: per-source rate limiting (`rate_limit`) plus
/// scanner User-Agent blocking (`scanner_block`), both bypassed for
/// `trusted_cidrs`. Consulted by the dispatcher before any request processing.
///
/// The whole feature is opt-in: [`SecurityFilter::from_config`] returns `None`
/// unless at least one of `rate_limit` / `scanner_block` is configured.
pub struct SecurityFilter {
    /// Per-source rate limiter — `None` when `rate_limit` is not configured.
    rate_limit: Option<RateLimitState>,
    /// Lower-cased `User-Agent` substrings to block. Empty = scanner blocking off.
    scanner_user_agents: Vec<String>,
    /// Sources exempt from both rate limiting and scanner blocking (own
    /// infrastructure: AS, trunks, monitoring).
    trusted: Vec<IpNet>,
}

impl SecurityFilter {
    /// Build a filter from the `security` config block. Returns `None` when
    /// neither `rate_limit` nor `scanner_block` is set (feature is opt-in, so
    /// the dispatcher check is a no-op). Invalid `trusted_cidrs` are ignored.
    pub fn from_config(config: &crate::config::SecurityConfig) -> Option<Arc<Self>> {
        let rate_limit = config.rate_limit.as_ref().map(|policy| RateLimitState {
            windows: DashMap::new(),
            bans: DashMap::new(),
            // Guard against a zero policy permitting nothing / dividing by zero.
            max_requests: policy.max_requests.max(1),
            window: Duration::from_secs(u64::from(policy.window_secs.max(1))),
            ban_duration: Duration::from_secs(u64::from(policy.ban_duration_secs.max(1))),
        });

        let scanner_user_agents: Vec<String> = config
            .scanner_block
            .as_ref()
            .map(|block| {
                block
                    .user_agents
                    .iter()
                    .map(|agent| agent.to_lowercase())
                    .collect()
            })
            .unwrap_or_default();

        if rate_limit.is_none() && scanner_user_agents.is_empty() {
            return None;
        }

        let trusted = config
            .trusted_cidrs
            .iter()
            .filter_map(|cidr| cidr.parse::<IpNet>().ok())
            .collect();

        Some(Arc::new(Self {
            rate_limit,
            scanner_user_agents,
            trusted,
        }))
    }

    fn is_trusted(&self, source: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(&source))
    }

    /// Whether `user_agent` matches a configured scanner signature
    /// (case-insensitive substring — sipvicious advertises `friendly-scanner`).
    fn is_scanner(&self, user_agent: Option<&str>) -> bool {
        if self.scanner_user_agents.is_empty() {
            return false;
        }
        match user_agent {
            Some(agent) => {
                let agent = agent.to_lowercase();
                self.scanner_user_agents
                    .iter()
                    .any(|needle| agent.contains(needle))
            }
            None => false,
        }
    }

    /// Evaluate one inbound request from `source` carrying `user_agent`. Trusted
    /// sources always pass. Scanner blocking is checked before the rate limit so
    /// a flood of scanner traffic doesn't burn a rate-limit ban slot it doesn't
    /// need.
    pub fn evaluate(&self, source: IpAddr, user_agent: Option<&str>) -> SecurityVerdict {
        self.evaluate_at(source, user_agent, Instant::now())
    }

    fn evaluate_at(
        &self,
        source: IpAddr,
        user_agent: Option<&str>,
        now: Instant,
    ) -> SecurityVerdict {
        if self.is_trusted(source) {
            return SecurityVerdict::Allow;
        }
        if self.is_scanner(user_agent) {
            return SecurityVerdict::Scanner;
        }
        if let Some(ref rate) = self.rate_limit {
            if !rate.check_at(source, now) {
                return SecurityVerdict::RateLimited;
            }
        }
        SecurityVerdict::Allow
    }

    /// Drop expired rate-limit bans and stale windows. Call periodically to keep
    /// memory bounded under scanner churn. No-op when rate limiting is off.
    pub fn prune(&self) {
        if let Some(ref rate) = self.rate_limit {
            rate.prune_at(Instant::now());
        }
    }

    /// Number of currently-tracked rate-limit bans (0 when rate limiting is off).
    pub fn rate_limit_bans(&self) -> usize {
        self.rate_limit.as_ref().map_or(0, RateLimitState::active_bans)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn bans_after_threshold_failures() {
        let store = AutoBanStore::new(3, 600, 3600, &[]);
        let source = ip("203.0.113.7");
        assert!(!store.record_failure(source)); // 1
        assert!(!store.record_failure(source)); // 2
        assert!(!store.is_banned(source));
        assert!(store.record_failure(source)); // 3 -> ban, returns true
        assert!(store.is_banned(source));
        assert_eq!(store.active_bans(), 1);
    }

    #[test]
    fn success_resets_the_counter() {
        let store = AutoBanStore::new(3, 600, 3600, &[]);
        let source = ip("203.0.113.8");
        store.record_failure(source);
        store.record_failure(source);
        store.record_success(source); // legit auth — wipe the count
        store.record_failure(source);
        store.record_failure(source);
        assert!(!store.is_banned(source)); // only 2 since reset
        assert!(store.record_failure(source)); // now 3 -> ban
    }

    #[test]
    fn trusted_cidr_never_banned() {
        let store = AutoBanStore::new(2, 600, 3600, &["10.0.0.0/8".to_string()]);
        let source = ip("10.1.2.3");
        for _ in 0..10 {
            assert!(!store.record_failure(source));
        }
        assert!(!store.is_banned(source));
        assert_eq!(store.active_bans(), 0);
    }

    #[test]
    fn window_rolls_so_slow_failures_do_not_ban() {
        let store = AutoBanStore::new(3, 600, 3600, &[]);
        let source = ip("203.0.113.9");
        let t0 = Instant::now();
        assert!(!store.record_failure_at(source, t0));
        assert!(!store.record_failure_at(source, t0 + Duration::from_secs(10)));
        // Past the window — counter rolls, so this is "1" again, not "3".
        assert!(!store.record_failure_at(source, t0 + Duration::from_secs(700)));
        assert!(!store.is_banned_at(source, t0 + Duration::from_secs(700)));
    }

    #[test]
    fn ban_expires_after_ttl() {
        let store = AutoBanStore::new(1, 600, 60, &[]);
        let source = ip("203.0.113.10");
        let t0 = Instant::now();
        assert!(store.record_failure_at(source, t0)); // threshold 1 -> immediate ban
        assert!(store.is_banned_at(source, t0 + Duration::from_secs(30)));
        assert!(!store.is_banned_at(source, t0 + Duration::from_secs(61))); // expired
    }

    #[test]
    fn prune_drops_expired_entries() {
        let store = AutoBanStore::new(1, 600, 60, &[]);
        let source = ip("203.0.113.11");
        let t0 = Instant::now();
        store.record_failure_at(source, t0);
        assert_eq!(store.active_bans(), 1);
        store.prune_at(t0 + Duration::from_secs(61));
        assert_eq!(store.active_bans(), 0);
    }

    #[test]
    fn already_banned_failure_is_noop() {
        let store = AutoBanStore::new(1, 600, 3600, &[]);
        let source = ip("203.0.113.12");
        assert!(store.record_failure(source)); // ban
        assert!(!store.record_failure(source)); // already banned -> not "newly banned"
        assert!(store.is_banned(source));
    }

    // --- SecurityFilter (rate_limit + scanner_block) -----------------------

    use crate::config::{RateLimitConfig, ScannerBlockConfig, SecurityConfig};

    fn security_config(
        rate_limit: Option<RateLimitConfig>,
        user_agents: Vec<&str>,
        trusted_cidrs: Vec<&str>,
    ) -> SecurityConfig {
        SecurityConfig {
            rate_limit,
            scanner_block: if user_agents.is_empty() {
                None
            } else {
                Some(ScannerBlockConfig {
                    user_agents: user_agents.into_iter().map(String::from).collect(),
                })
            },
            trusted_cidrs: trusted_cidrs.into_iter().map(String::from).collect(),
            failed_auth_ban: None,
            apiban: None,
        }
    }

    #[test]
    fn filter_opt_in_none_when_unconfigured() {
        // No rate_limit, no scanner_block -> feature stays off.
        let config = security_config(None, vec![], vec!["10.0.0.0/8"]);
        assert!(SecurityFilter::from_config(&config).is_none());
    }

    #[test]
    fn scanner_block_matches_case_insensitive_substring() {
        let config = security_config(None, vec!["sipvicious", "friendly-scanner"], vec![]);
        let filter = SecurityFilter::from_config(&config).unwrap();
        let source = ip("203.0.113.20");

        // Exact, mixed-case, and substring-within-larger-UA all match.
        assert_eq!(
            filter.evaluate(source, Some("friendly-scanner")),
            SecurityVerdict::Scanner
        );
        assert_eq!(
            filter.evaluate(source, Some("SIPVICIOUS")),
            SecurityVerdict::Scanner
        );
        assert_eq!(
            filter.evaluate(source, Some("Mozilla sipvicious/0.3.0")),
            SecurityVerdict::Scanner
        );
        // A legit UA and a missing UA both pass.
        assert_eq!(
            filter.evaluate(source, Some("Acme-SIP/1.0")),
            SecurityVerdict::Allow
        );
        assert_eq!(filter.evaluate(source, None), SecurityVerdict::Allow);
    }

    #[test]
    fn rate_limit_bans_after_max_requests() {
        let config = security_config(
            Some(RateLimitConfig {
                window_secs: 10,
                max_requests: 3,
                ban_duration_secs: 3600,
            }),
            vec![],
            vec![],
        );
        let filter = SecurityFilter::from_config(&config).unwrap();
        let source = ip("203.0.113.21");
        let t0 = Instant::now();

        // First 3 within the window pass.
        for _ in 0..3 {
            assert_eq!(filter.evaluate_at(source, None, t0), SecurityVerdict::Allow);
        }
        // 4th trips the limit -> banned.
        assert_eq!(
            filter.evaluate_at(source, None, t0),
            SecurityVerdict::RateLimited
        );
        assert_eq!(filter.rate_limit_bans(), 1);
        // Still banned a moment later (well inside ban_duration).
        assert_eq!(
            filter.evaluate_at(source, None, t0 + Duration::from_secs(5)),
            SecurityVerdict::RateLimited
        );
    }

    #[test]
    fn rate_limit_window_rolls() {
        let config = security_config(
            Some(RateLimitConfig {
                window_secs: 10,
                max_requests: 3,
                ban_duration_secs: 3600,
            }),
            vec![],
            vec![],
        );
        let filter = SecurityFilter::from_config(&config).unwrap();
        let source = ip("203.0.113.22");
        let t0 = Instant::now();

        for _ in 0..3 {
            assert_eq!(filter.evaluate_at(source, None, t0), SecurityVerdict::Allow);
        }
        // Past the window — counter rolls, so this is request #1 again, not #4.
        assert_eq!(
            filter.evaluate_at(source, None, t0 + Duration::from_secs(11)),
            SecurityVerdict::Allow
        );
        assert_eq!(filter.rate_limit_bans(), 0);
    }

    #[test]
    fn rate_limit_ban_expires() {
        let config = security_config(
            Some(RateLimitConfig {
                window_secs: 10,
                max_requests: 1,
                ban_duration_secs: 60,
            }),
            vec![],
            vec![],
        );
        let filter = SecurityFilter::from_config(&config).unwrap();
        let source = ip("203.0.113.23");
        let t0 = Instant::now();

        assert_eq!(filter.evaluate_at(source, None, t0), SecurityVerdict::Allow);
        assert_eq!(
            filter.evaluate_at(source, None, t0),
            SecurityVerdict::RateLimited
        );
        // After the ban TTL the source is allowed again.
        assert_eq!(
            filter.evaluate_at(source, None, t0 + Duration::from_secs(61)),
            SecurityVerdict::Allow
        );
    }

    #[test]
    fn trusted_cidr_bypasses_both_checks() {
        let config = security_config(
            Some(RateLimitConfig {
                window_secs: 10,
                max_requests: 1,
                ban_duration_secs: 3600,
            }),
            vec!["sipvicious"],
            vec!["10.0.0.0/8"],
        );
        let filter = SecurityFilter::from_config(&config).unwrap();
        let trusted = ip("10.1.2.3");
        let t0 = Instant::now();

        // Scanner UA from a trusted source is still allowed.
        assert_eq!(
            filter.evaluate_at(trusted, Some("sipvicious"), t0),
            SecurityVerdict::Allow
        );
        // And it never accrues a rate-limit ban no matter how many it sends.
        for _ in 0..50 {
            assert_eq!(
                filter.evaluate_at(trusted, None, t0),
                SecurityVerdict::Allow
            );
        }
        assert_eq!(filter.rate_limit_bans(), 0);
    }

    #[test]
    fn prune_drops_expired_rate_limit_bans() {
        let config = security_config(
            Some(RateLimitConfig {
                window_secs: 10,
                max_requests: 1,
                ban_duration_secs: 60,
            }),
            vec![],
            vec![],
        );
        let filter = SecurityFilter::from_config(&config).unwrap();
        let source = ip("203.0.113.24");
        let now = Instant::now();
        filter.evaluate_at(source, None, now);
        filter.evaluate_at(source, None, now); // ban
        assert_eq!(filter.rate_limit_bans(), 1);
        if let Some(ref rate) = filter.rate_limit {
            rate.prune_at(now + Duration::from_secs(61));
        }
        assert_eq!(filter.rate_limit_bans(), 0);
    }
}
