//! SIP-aware DNS resolver implementing RFC 3263 server location.

use std::net::{IpAddr, SocketAddr};
use hickory_resolver::TokioResolver;
use tracing::{debug, warn};

use crate::sip::uri::strip_ipv6_brackets;

/// A resolved SIP target: address + transport hint from SRV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    pub address: SocketAddr,
    pub transport: Option<String>,
}

/// SIP DNS resolver (RFC 3263).
///
/// Wraps a `hickory-resolver` async resolver. Constructed once at startup and
/// shared across the dispatcher via `Arc`.
#[derive(Clone)]
pub struct SipResolver {
    resolver: TokioResolver,
}

impl SipResolver {
    /// Create a resolver using system DNS configuration.
    pub fn from_system() -> Result<Self, Box<dyn std::error::Error>> {
        let resolver = TokioResolver::builder_tokio()?.build();
        Ok(Self { resolver })
    }

    /// Resolve a SIP target to one or more socket addresses.
    ///
    /// Follows RFC 3263 procedure:
    /// - Numeric IP → direct use
    /// - Explicit port → A/AAAA lookup only (SRV records define their own port)
    /// - No port → SRV lookup first, fallback to A/AAAA on default port 5060/5061
    pub async fn resolve(
        &self,
        host: &str,
        port: Option<u16>,
        scheme: &str,
        transport_hint: Option<&str>,
    ) -> Vec<ResolvedTarget> {
        // Strip brackets from IPv6 addresses (SIP URIs store as [::1])
        let host = strip_ipv6_brackets(host);

        // 1. Numeric IP — no DNS needed
        if let Ok(ip) = host.parse::<IpAddr>() {
            let default_port = if scheme == "sips" { 5061 } else { 5060 };
            return vec![ResolvedTarget {
                address: SocketAddr::new(ip, port.unwrap_or(default_port)),
                transport: transport_hint.map(|s| s.to_string()),
            }];
        }

        // 2. Explicit port provided — skip SRV, go straight to A/AAAA
        if let Some(port) = port {
            return self.resolve_a_aaaa(host, port, transport_hint).await;
        }

        // 3. No port — try SRV lookup first (RFC 3263 §4)
        let default_port = if scheme == "sips" { 5061 } else { 5060 };
        let srv_results = self.resolve_srv(host, scheme, transport_hint).await;
        if !srv_results.is_empty() {
            return srv_results;
        }

        // 4. No SRV records — fall back to A/AAAA with default port
        debug!(host = %host, port = default_port, "no SRV records, falling back to A/AAAA");
        self.resolve_a_aaaa(host, default_port, transport_hint).await
    }

    /// Perform SRV lookup for a SIP domain.
    ///
    /// Tries service names based on scheme and transport hint:
    /// - `sips` scheme → `_sips._tcp.host`
    /// - `sip` + UDP → `_sip._udp.host`
    /// - `sip` + TCP → `_sip._tcp.host`
    /// - No hint → try UDP first, then TCP
    async fn resolve_srv(
        &self,
        host: &str,
        scheme: &str,
        transport_hint: Option<&str>,
    ) -> Vec<ResolvedTarget> {
        let service_names: Vec<(String, &str)> = match (scheme, transport_hint) {
            ("sips", _) => vec![("_sips._tcp".to_string(), "tls")],
            (_, Some(transport)) => {
                let proto = match transport.to_lowercase().as_str() {
                    "udp" => "_udp",
                    "tcp" => "_tcp",
                    "tls" => "_tcp",
                    "sctp" => "_sctp",
                    _ => "_udp",
                };
                vec![(format!("_sip.{proto}"), transport)]
            }
            _ => vec![
                ("_sip._udp".to_string(), "udp"),
                ("_sip._tcp".to_string(), "tcp"),
            ],
        };

        let mut results = Vec::new();

        for (service_prefix, transport) in &service_names {
            let srv_name = format!("{service_prefix}.{host}.");
            match self.resolver.srv_lookup(&srv_name).await {
                Ok(lookup) => {
                    let mut records: Vec<_> = lookup.iter().collect();
                    // Sort by priority (ascending), then by weight (descending)
                    records.sort_by(|a, b| {
                        a.priority()
                            .cmp(&b.priority())
                            .then_with(|| b.weight().cmp(&a.weight()))
                    });

                    for record in records {
                        let target_host = record.target().to_string();
                        let target_host = target_host.trim_end_matches('.');
                        let port = record.port();

                        // Resolve the SRV target hostname to IP addresses
                        let addresses =
                            self.resolve_a_aaaa(target_host, port, Some(transport)).await;
                        results.extend(addresses);
                    }

                    if !results.is_empty() {
                        debug!(
                            host = %host,
                            srv = %srv_name,
                            count = results.len(),
                            "SRV lookup succeeded"
                        );
                        return results;
                    }
                }
                Err(error) => {
                    debug!(
                        host = %host,
                        srv = %srv_name,
                        %error,
                        "SRV lookup failed"
                    );
                }
            }
        }

        results
    }

    /// Perform a NAPTR lookup and return the first matching SIP URI replacement.
    ///
    /// Used for ENUM (e164.arpa) lookups. Returns the URI from the first
    /// NAPTR record whose service field contains "E2U+sip".
    pub async fn naptr_lookup(&self, query_name: &str) -> Option<String> {
        use hickory_resolver::proto::rr::RecordType;
        use hickory_resolver::proto::rr::record_data::RData;

        match self.resolver.lookup(query_name, RecordType::NAPTR).await {
            Ok(lookup) => {
                for rdata in lookup.iter() {
                    if let RData::NAPTR(naptr) = rdata {
                        let services = String::from_utf8_lossy(naptr.services());
                        if services.contains("E2U+sip") || services.contains("e2u+sip") {
                            let replacement = naptr.replacement().to_string();
                            if !replacement.is_empty() && replacement != "." {
                                return Some(replacement.trim_end_matches('.').to_string());
                            }
                            // Check regexp field for URI extraction
                            let regexp = String::from_utf8_lossy(naptr.regexp());
                            if !regexp.is_empty() {
                                // NAPTR regexp format: "!pattern!replacement!"
                                let parts: Vec<&str> = regexp.split('!').collect();
                                if parts.len() >= 3 && !parts[2].is_empty() {
                                    return Some(parts[2].to_string());
                                }
                            }
                        }
                    }
                }
                None
            }
            Err(error) => {
                debug!(query = %query_name, %error, "NAPTR lookup failed");
                None
            }
        }
    }

    /// Resolve a hostname to IP addresses via A/AAAA lookup.
    async fn resolve_a_aaaa(
        &self,
        host: &str,
        port: u16,
        transport: Option<&str>,
    ) -> Vec<ResolvedTarget> {
        match self.resolver.lookup_ip(host).await {
            Ok(lookup) => lookup
                .iter()
                .map(|ip| ResolvedTarget {
                    address: SocketAddr::new(ip, port),
                    transport: transport.map(|s| s.to_string()),
                })
                .collect(),
            Err(error) => {
                warn!(host = %host, %error, "DNS A/AAAA lookup failed");
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_numeric_ipv4() {
        let resolver = SipResolver::from_system().unwrap();
        let results = resolver.resolve("192.168.1.100", Some(5080), "sip", None).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, "192.168.1.100:5080".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn resolve_numeric_ipv4_default_port() {
        let resolver = SipResolver::from_system().unwrap();
        let results = resolver.resolve("10.0.0.1", None, "sip", None).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, "10.0.0.1:5060".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn resolve_numeric_ipv4_sips_default_port() {
        let resolver = SipResolver::from_system().unwrap();
        let results = resolver.resolve("10.0.0.1", None, "sips", None).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, "10.0.0.1:5061".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn resolve_numeric_ipv6() {
        let resolver = SipResolver::from_system().unwrap();
        let results = resolver.resolve("::1", Some(5060), "sip", None).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, "[::1]:5060".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn resolve_bracketed_ipv6() {
        let resolver = SipResolver::from_system().unwrap();
        // SIP URIs store IPv6 with brackets — resolver should strip them
        let results = resolver.resolve("[::1]", Some(5060), "sip", None).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, "[::1]:5060".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn resolve_bracketed_ipv6_full() {
        let resolver = SipResolver::from_system().unwrap();
        let results = resolver.resolve("[2001:db8::1]", Some(5080), "sip", None).await;
        assert_eq!(results.len(), 1);
        let expected: SocketAddr = "[2001:db8::1]:5080".parse().unwrap();
        assert_eq!(results[0].address, expected);
    }

    #[tokio::test]
    async fn resolve_localhost() {
        let resolver = SipResolver::from_system().unwrap();
        let results = resolver.resolve("localhost", Some(5090), "sip", None).await;
        assert!(!results.is_empty(), "localhost should resolve");
        assert_eq!(results[0].address.port(), 5090);
        assert!(
            results[0].address.ip().is_loopback(),
            "localhost should resolve to loopback"
        );
    }

    #[tokio::test]
    async fn resolve_transport_hint_preserved() {
        let resolver = SipResolver::from_system().unwrap();
        let results = resolver
            .resolve("192.168.1.1", Some(5060), "sip", Some("tcp"))
            .await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].transport.as_deref(), Some("tcp"));
    }

    #[tokio::test]
    async fn resolve_nonexistent_domain_returns_empty() {
        let resolver = SipResolver::from_system().unwrap();
        let results = resolver
            .resolve("this-domain-should-not-exist-xyzzy.invalid", None, "sip", None)
            .await;
        assert!(results.is_empty());
    }
}
