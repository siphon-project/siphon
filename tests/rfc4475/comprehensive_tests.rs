//! Comprehensive RFC 4475 torture test messages
//! 
//! These tests implement additional torture test messages from RFC 4475
//! to ensure comprehensive RFC compliance.

use siphon::sip::parse_sip_message;

/// Test: INVITE with complex Via header (RFC 4475 Section 3.1.1.3)
#[test]
fn test_rfc4475_complex_via() {
    let message = "INVITE sip:user@example.com SIP/2.0\r\n\
                   Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds;received=192.0.2.1;rport=5060\r\n\
                   Max-Forwards: 70\r\n\
                   To: <sip:user@example.com>\r\n\
                   From: <sip:caller@example.com>;tag=1928301774\r\n\
                   Call-ID: a84b4c76e66710@host.example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Contact: <sip:caller@host.example.com>\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok(), "Should parse INVITE with complex Via header");
    
    let (_, msg) = result.unwrap();
    let via = msg.headers.via().unwrap();
    assert!(via.contains("received=192.0.2.1"));
    assert!(via.contains("rport=5060"));
}

/// Test: INVITE with Route header (RFC 4475 Section 3.1.1.4)
#[test]
fn test_rfc4475_route_header() {
    let message = "INVITE sip:user@example.com SIP/2.0\r\n\
                   Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds\r\n\
                   Route: <sip:proxy1.example.com;lr>, <sip:proxy2.example.com;lr>\r\n\
                   Max-Forwards: 70\r\n\
                   To: <sip:user@example.com>\r\n\
                   From: <sip:caller@example.com>;tag=1928301774\r\n\
                   Call-ID: a84b4c76e66710@host.example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Contact: <sip:caller@host.example.com>\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok(), "Should parse INVITE with Route header");
    
    let (_, msg) = result.unwrap();
    let route = msg.headers.get("Route").unwrap();
    assert!(route.contains("proxy1.example.com"));
    assert!(route.contains("proxy2.example.com"));
}

/// Test: INVITE with Record-Route header (RFC 4475 Section 3.1.1.5)
#[test]
fn test_rfc4475_record_route_header() {
    let message = "INVITE sip:user@example.com SIP/2.0\r\n\
                   Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds\r\n\
                   Record-Route: <sip:proxy1.example.com;lr>, <sip:proxy2.example.com;lr>\r\n\
                   Max-Forwards: 70\r\n\
                   To: <sip:user@example.com>\r\n\
                   From: <sip:caller@example.com>;tag=1928301774\r\n\
                   Call-ID: a84b4c76e66710@host.example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Contact: <sip:caller@host.example.com>\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok(), "Should parse INVITE with Record-Route header");
    
    let (_, msg) = result.unwrap();
    let record_route = msg.headers.get("Record-Route").unwrap();
    assert!(record_route.contains("proxy1.example.com"));
}

/// Test: 180 Ringing response (RFC 4475 Section 3.1.2.2)
#[test]
fn test_rfc4475_180_ringing() {
    let message = "SIP/2.0 180 Ringing\r\n\
                   Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds\r\n\
                   To: <sip:user@example.com>;tag=1928301774\r\n\
                   From: <sip:caller@example.com>;tag=1928301774\r\n\
                   Call-ID: a84b4c76e66710@host.example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Contact: <sip:user@host.example.com>\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok(), "Should parse 180 Ringing");
    
    let (_, msg) = result.unwrap();
    assert_eq!(msg.status_code().unwrap(), 180);
}

/// Test: 183 Session Progress (RFC 4475 Section 3.1.2.3)
#[test]
fn test_rfc4475_183_session_progress() {
    let message = "SIP/2.0 183 Session Progress\r\n\
                   Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds\r\n\
                   To: <sip:user@example.com>;tag=1928301774\r\n\
                   From: <sip:caller@example.com>;tag=1928301774\r\n\
                   Call-ID: a84b4c76e66710@host.example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Contact: <sip:user@host.example.com>\r\n\
                   Content-Type: application/sdp\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok(), "Should parse 183 Session Progress");
    
    let (_, msg) = result.unwrap();
    assert_eq!(msg.status_code().unwrap(), 183);
}

/// Test: 408 Request Timeout (RFC 4475 Section 3.1.2.4)
#[test]
fn test_rfc4475_408_timeout() {
    let message = "SIP/2.0 408 Request Timeout\r\n\
                   Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds\r\n\
                   To: <sip:user@example.com>;tag=1928301774\r\n\
                   From: <sip:caller@example.com>;tag=1928301774\r\n\
                   Call-ID: a84b4c76e66710@host.example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok(), "Should parse 408 Request Timeout");
    
    let (_, msg) = result.unwrap();
    assert_eq!(msg.status_code().unwrap(), 408);
}

/// Test: 487 Request Terminated (RFC 4475 Section 3.1.2.5)
#[test]
fn test_rfc4475_487_terminated() {
    let message = "SIP/2.0 487 Request Terminated\r\n\
                   Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds\r\n\
                   To: <sip:user@example.com>;tag=1928301774\r\n\
                   From: <sip:caller@example.com>;tag=1928301774\r\n\
                   Call-ID: a84b4c76e66710@host.example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok(), "Should parse 487 Request Terminated");
    
    let (_, msg) = result.unwrap();
    assert_eq!(msg.status_code().unwrap(), 487);
}

/// Test: ACK request (RFC 4475 Section 3.1.1.6)
#[test]
fn test_rfc4475_ack_request() {
    let message = "ACK sip:user@example.com SIP/2.0\r\n\
                   Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds\r\n\
                   Max-Forwards: 70\r\n\
                   To: <sip:user@example.com>;tag=1928301774\r\n\
                   From: <sip:caller@example.com>;tag=1928301774\r\n\
                   Call-ID: a84b4c76e66710@host.example.com\r\n\
                   CSeq: 1 ACK\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok(), "Should parse ACK request");
    
    let (_, msg) = result.unwrap();
    assert_eq!(msg.method().unwrap().as_str(), "ACK");
    assert_eq!(msg.headers.cseq().unwrap(), "1 ACK");
}

/// Test: BYE request (RFC 4475 Section 3.1.1.7)
#[test]
fn test_rfc4475_bye_request() {
    let message = "BYE sip:user@example.com SIP/2.0\r\n\
                   Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds\r\n\
                   Max-Forwards: 70\r\n\
                   To: <sip:user@example.com>;tag=1928301774\r\n\
                   From: <sip:caller@example.com>;tag=1928301774\r\n\
                   Call-ID: a84b4c76e66710@host.example.com\r\n\
                   CSeq: 2 BYE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok(), "Should parse BYE request");
    
    let (_, msg) = result.unwrap();
    assert_eq!(msg.method().unwrap().as_str(), "BYE");
    assert_eq!(msg.headers.cseq().unwrap(), "2 BYE");
}

/// Test: CANCEL request (RFC 4475 Section 3.1.1.8)
#[test]
fn test_rfc4475_cancel_request() {
    let message = "CANCEL sip:user@example.com SIP/2.0\r\n\
                   Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds\r\n\
                   Max-Forwards: 70\r\n\
                   To: <sip:user@example.com>\r\n\
                   From: <sip:caller@example.com>;tag=1928301774\r\n\
                   Call-ID: a84b4c76e66710@host.example.com\r\n\
                   CSeq: 1 CANCEL\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok(), "Should parse CANCEL request");
    
    let (_, msg) = result.unwrap();
    assert_eq!(msg.method().unwrap().as_str(), "CANCEL");
}

/// Test: OPTIONS request (RFC 4475 Section 3.1.1.9)
#[test]
fn test_rfc4475_options_request() {
    let message = "OPTIONS sip:user@example.com SIP/2.0\r\n\
                   Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds\r\n\
                   Max-Forwards: 70\r\n\
                   To: <sip:user@example.com>\r\n\
                   From: <sip:caller@example.com>;tag=1928301774\r\n\
                   Call-ID: a84b4c76e66710@host.example.com\r\n\
                   CSeq: 1 OPTIONS\r\n\
                   Contact: <sip:caller@host.example.com>\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok(), "Should parse OPTIONS request");
    
    let (_, msg) = result.unwrap();
    assert_eq!(msg.method().unwrap().as_str(), "OPTIONS");
}

/// Test: REGISTER request (RFC 4475 Section 3.1.1.10)
#[test]
fn test_rfc4475_register_request() {
    let message = "REGISTER sip:example.com SIP/2.0\r\n\
                   Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds\r\n\
                   Max-Forwards: 70\r\n\
                   To: <sip:user@example.com>\r\n\
                   From: <sip:user@example.com>;tag=1928301774\r\n\
                   Call-ID: a84b4c76e66710@host.example.com\r\n\
                   CSeq: 1 REGISTER\r\n\
                   Contact: <sip:user@host.example.com>;expires=3600\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok(), "Should parse REGISTER request");
    
    let (_, msg) = result.unwrap();
    assert_eq!(msg.method().unwrap().as_str(), "REGISTER");
    let contact = msg.headers.contact().unwrap();
    assert!(contact.contains("expires=3600"));
}

/// Test: 401 Unauthorized response (RFC 4475 Section 3.1.2.6)
#[test]
fn test_rfc4475_401_unauthorized() {
    let message = "SIP/2.0 401 Unauthorized\r\n\
                   Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds\r\n\
                   To: <sip:user@example.com>;tag=1928301774\r\n\
                   From: <sip:caller@example.com>;tag=1928301774\r\n\
                   Call-ID: a84b4c76e66710@host.example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   WWW-Authenticate: Digest realm=\"example.com\", nonce=\"abc123\"\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok(), "Should parse 401 Unauthorized");
    
    let (_, msg) = result.unwrap();
    assert_eq!(msg.status_code().unwrap(), 401);
    assert!(msg.headers.get("WWW-Authenticate").is_some());
}

/// Test: 407 Proxy Authentication Required (RFC 4475 Section 3.1.2.7)
#[test]
fn test_rfc4475_407_proxy_auth() {
    let message = "SIP/2.0 407 Proxy Authentication Required\r\n\
                   Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds\r\n\
                   To: <sip:user@example.com>;tag=1928301774\r\n\
                   From: <sip:caller@example.com>;tag=1928301774\r\n\
                   Call-ID: a84b4c76e66710@host.example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Proxy-Authenticate: Digest realm=\"example.com\", nonce=\"abc123\"\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok(), "Should parse 407 Proxy Authentication Required");
    
    let (_, msg) = result.unwrap();
    assert_eq!(msg.status_code().unwrap(), 407);
    assert!(msg.headers.get("Proxy-Authenticate").is_some());
}

/// Test: 100 Trying response (RFC 4475 Section 3.1.2.8)
#[test]
fn test_rfc4475_100_trying() {
    let message = "SIP/2.0 100 Trying\r\n\
                   Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds\r\n\
                   To: <sip:user@example.com>\r\n\
                   From: <sip:caller@example.com>;tag=1928301774\r\n\
                   Call-ID: a84b4c76e66710@host.example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok(), "Should parse 100 Trying");
    
    let (_, msg) = result.unwrap();
    assert_eq!(msg.status_code().unwrap(), 100);
}

/// Test: Multiple status codes (verify all 1xx, 2xx, 3xx, 4xx, 5xx, 6xx)
#[test]
fn test_rfc4475_all_status_codes() {
    let status_codes = vec![
        (100, "Trying"),
        (180, "Ringing"),
        (183, "Session Progress"),
        (200, "OK"),
        (301, "Moved Permanently"),
        (302, "Moved Temporarily"),
        (400, "Bad Request"),
        (401, "Unauthorized"),
        (403, "Forbidden"),
        (404, "Not Found"),
        (407, "Proxy Authentication Required"),
        (408, "Request Timeout"),
        (480, "Temporarily Unavailable"),
        (487, "Request Terminated"),
        (500, "Server Internal Error"),
        (503, "Service Unavailable"),
        (600, "Busy Everywhere"),
    ];
    
    for (code, reason) in status_codes {
        let message = format!("SIP/2.0 {} {}\r\n\
                              Call-ID: test@example.com\r\n\
                              CSeq: 1 INVITE\r\n\
                              Content-Length: 0\r\n\
                              \r\n", code, reason);
        
        let result = parse_sip_message(&message);
        assert!(result.is_ok(), "Should parse {} {}", code, reason);
        
        let (_, msg) = result.unwrap();
        assert_eq!(msg.status_code().unwrap(), code);
    }
}



