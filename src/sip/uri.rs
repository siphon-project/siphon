use std::fmt;

/// Format an IP address or hostname for use in SIP URIs/headers.
/// Wraps IPv6 addresses in brackets per RFC 3261.
pub fn format_sip_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// Strip brackets from an IPv6 host for use with standard parsers.
pub fn strip_ipv6_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// SIP URI as defined in RFC 3261
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipUri {
    pub scheme: String, // "sip" or "sips"
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub params: Vec<(String, Option<String>)>, // URI parameters
    pub headers: Vec<(String, Option<String>)>, // URI headers (after ?)
}

impl SipUri {
    pub fn new(host: String) -> Self {
        Self {
            scheme: "sip".to_string(),
            user: None,
            host,
            port: None,
            params: Vec::new(),
            headers: Vec::new(),
        }
    }

    pub fn with_user(mut self, user: String) -> Self {
        self.user = Some(user);
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn with_param(mut self, name: String, value: Option<String>) -> Self {
        self.params.push((name, value));
        self
    }

    pub fn get_param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_deref().unwrap_or(""))
    }

}

impl fmt::Display for SipUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.scheme)?;

        if let Some(ref user) = self.user {
            write!(f, "{user}@")?;
        }

        write!(f, "{}", format_sip_host(&self.host))?;

        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }

        for (name, value) in &self.params {
            write!(f, ";{name}")?;
            if let Some(ref v) = value {
                write!(f, "={v}")?;
            }
        }

        if !self.headers.is_empty() {
            write!(f, "?")?;
            let mut first = true;
            for (name, value) in &self.headers {
                if !first {
                    write!(f, "&")?;
                }
                first = false;
                write!(f, "{name}")?;
                if let Some(ref v) = value {
                    write!(f, "={v}")?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_sip_host_ipv4() {
        assert_eq!(format_sip_host("192.168.1.1"), "192.168.1.1");
    }

    #[test]
    fn format_sip_host_ipv6_bare() {
        assert_eq!(format_sip_host("2001:db8::1"), "[2001:db8::1]");
        assert_eq!(format_sip_host("::1"), "[::1]");
        assert_eq!(format_sip_host("fe80::1%25eth0"), "[fe80::1%25eth0]");
    }

    #[test]
    fn format_sip_host_ipv6_already_bracketed() {
        assert_eq!(format_sip_host("[::1]"), "[::1]");
        assert_eq!(format_sip_host("[2001:db8::1]"), "[2001:db8::1]");
    }

    #[test]
    fn format_sip_host_hostname() {
        assert_eq!(format_sip_host("example.com"), "example.com");
        assert_eq!(format_sip_host("proxy.atlanta.com"), "proxy.atlanta.com");
    }

    #[test]
    fn strip_ipv6_brackets_with_brackets() {
        assert_eq!(strip_ipv6_brackets("[::1]"), "::1");
        assert_eq!(strip_ipv6_brackets("[2001:db8::1]"), "2001:db8::1");
    }

    #[test]
    fn strip_ipv6_brackets_without_brackets() {
        assert_eq!(strip_ipv6_brackets("::1"), "::1");
        assert_eq!(strip_ipv6_brackets("example.com"), "example.com");
        assert_eq!(strip_ipv6_brackets("192.168.1.1"), "192.168.1.1");
    }

    #[test]
    fn strip_ipv6_brackets_partial() {
        assert_eq!(strip_ipv6_brackets("[::1"), "[::1");
        assert_eq!(strip_ipv6_brackets("::1]"), "::1]");
    }

    #[test]
    fn sip_uri_to_string_ipv6_bare_host() {
        let uri = SipUri::new("2001:db8::1".to_string())
            .with_user("alice".to_string())
            .with_port(5060);
        assert_eq!(uri.to_string(), "sip:alice@[2001:db8::1]:5060");
    }

    #[test]
    fn sip_uri_to_string_ipv6_bracketed_host() {
        let uri = SipUri::new("[::1]".to_string())
            .with_port(5060);
        assert_eq!(uri.to_string(), "sip:[::1]:5060");
    }

    #[test]
    fn sip_uri_to_string_ipv4_unchanged() {
        let uri = SipUri::new("192.168.1.1".to_string())
            .with_user("bob".to_string())
            .with_port(5060);
        assert_eq!(uri.to_string(), "sip:bob@192.168.1.1:5060");
    }

    #[test]
    fn sip_uri_to_string_hostname_unchanged() {
        let uri = SipUri::new("biloxi.com".to_string())
            .with_user("bob".to_string());
        assert_eq!(uri.to_string(), "sip:bob@biloxi.com");
    }
}

