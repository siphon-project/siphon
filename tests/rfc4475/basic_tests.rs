//! Basic torture test messages from RFC 4475

use siphon::sip::parse_sip_message;

/// Test 1: Basic INVITE (RFC 4475 Section 3.1.1.1)
#[test]
fn test_rfc4475_basic_invite() {
    let message = concat!(
        "INVITE sip:user@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds\r\n",
        "Max-Forwards: 70\r\n",
        "To: <sip:user@example.com>\r\n",
        "From: <sip:caller@example.com>;tag=1928301774\r\n",
        "Call-ID: a84b4c76e66710@host.example.com\r\n",
        "CSeq: 1 INVITE\r\n",
        "Contact: <sip:caller@host.example.com>\r\n",
        "Content-Type: application/sdp\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );

    let result = parse_sip_message(message);
    assert!(result.is_ok(), "Should parse basic INVITE");
}

/// Test 2: INVITE with SDP body (RFC 4475 Section 3.1.1.2)
#[test]
fn test_rfc4475_invite_with_sdp() {
    let sdp = concat!(
        "v=0\r\n",
        "o=user 53655765 2353687637 IN IP4 192.0.2.1\r\n",
        "s=-\r\n",
        "c=IN IP4 192.0.2.1\r\n",
        "t=0 0\r\n",
        "m=audio 6000 RTP/AVP 0\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
    );
    let message = format!(
        concat!(
            "INVITE sip:user@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds\r\n",
            "Max-Forwards: 70\r\n",
            "To: <sip:user@example.com>\r\n",
            "From: <sip:caller@example.com>;tag=1928301774\r\n",
            "Call-ID: a84b4c76e66710@host.example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:caller@host.example.com>\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {}\r\n",
            "\r\n",
            "{}",
        ),
        sdp.len(), sdp,
    );

    let result = parse_sip_message(&message);
    assert!(result.is_ok(), "Should parse INVITE with SDP");

    let (_, msg) = result.unwrap();
    assert_eq!(msg.body.len(), sdp.len());
}

/// Test 3: 200 OK response (RFC 4475 Section 3.1.2.1)
#[test]
fn test_rfc4475_200_ok() {
    let message = concat!(
        "SIP/2.0 200 OK\r\n",
        "Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds\r\n",
        "To: <sip:user@example.com>;tag=1928301774\r\n",
        "From: <sip:caller@example.com>;tag=1928301774\r\n",
        "Call-ID: a84b4c76e66710@host.example.com\r\n",
        "CSeq: 1 INVITE\r\n",
        "Contact: <sip:user@host.example.com>\r\n",
        "Content-Type: application/sdp\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );

    let result = parse_sip_message(message);
    assert!(result.is_ok(), "Should parse 200 OK");

    let (_, msg) = result.unwrap();
    assert_eq!(msg.status_code().unwrap(), 200);
}
