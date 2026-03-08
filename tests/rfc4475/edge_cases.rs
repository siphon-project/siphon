//! Edge case tests for RFC compliance

use siphon::sip::parse_sip_message;

/// Test: Very long header values
#[test]
fn test_long_header_value() {
    let long_value = "a".repeat(1000);
    let message = format!("INVITE sip:user@example.com SIP/2.0\r\n\
                          Via: {}\r\n\
                          Call-ID: test@example.com\r\n\
                          CSeq: 1 INVITE\r\n\
                          Content-Length: 0\r\n\
                          \r\n", long_value);

    let result = parse_sip_message(&message);
    assert!(result.is_ok(), "Should handle long header values");
}

/// Test: Multiple headers of same type
#[test]
fn test_multiple_same_headers() {
    let message = "INVITE sip:user@example.com SIP/2.0\r\n\
                   Via: SIP/2.0/UDP proxy1.example.com:5060;branch=z9hG4bK1\r\n\
                   Via: SIP/2.0/UDP proxy2.example.com:5060;branch=z9hG4bK2\r\n\
                   Via: SIP/2.0/UDP proxy3.example.com:5060;branch=z9hG4bK3\r\n\
                   Call-ID: test@example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok());
    
    let (_, msg) = result.unwrap();
    let via_headers = msg.headers.get_all("Via").unwrap();
    assert_eq!(via_headers.len(), 3);
}

/// Test: Empty header value
#[test]
fn test_empty_header_value() {
    let message = "INVITE sip:user@example.com SIP/2.0\r\n\
                   User-Agent: \r\n\
                   Call-ID: test@example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    // Empty header values are valid per RFC
    assert!(result.is_ok());
}

/// Test: Header with only whitespace
#[test]
fn test_whitespace_only_header() {
    let message = "INVITE sip:user@example.com SIP/2.0\r\n\
                   User-Agent:   \r\n\
                   Call-ID: test@example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok());
}

/// Test: URI with IPv6 address
#[test]
fn test_ipv6_uri() {
    let message = "INVITE sip:user@[2001:db8::1]:5060 SIP/2.0\r\n\
                   Call-ID: test@example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok());
    
    let (_, msg) = result.unwrap();
    let uri = msg.request_uri().unwrap();
    assert!(uri.host.contains("2001:db8::1") || uri.host.contains("[2001:db8::1]"));
}

/// Test: SIPS URI
#[test]
fn test_sips_uri() {
    let message = "INVITE sips:user@example.com SIP/2.0\r\n\
                   Call-ID: test@example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok());
    
    let (_, msg) = result.unwrap();
    let uri = msg.request_uri().unwrap();
    assert_eq!(uri.scheme, "sips");
}



