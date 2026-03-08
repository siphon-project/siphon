use siphon::sip::headers::SipHeaders;

#[test]
fn test_header_add() {
    let mut headers = SipHeaders::new();
    headers.add("Via", "SIP/2.0/UDP host.example.com:5060".to_string());
    
    assert_eq!(headers.get("Via").unwrap(), "SIP/2.0/UDP host.example.com:5060");
}

#[test]
fn test_header_case_insensitive() {
    let mut headers = SipHeaders::new();
    headers.add("Via", "test".to_string());
    
    assert_eq!(headers.get("via").unwrap(), "test");
    assert_eq!(headers.get("VIA").unwrap(), "test");
    assert_eq!(headers.get("ViA").unwrap(), "test");
}

#[test]
fn test_multiple_values() {
    let mut headers = SipHeaders::new();
    headers.add("Via", "first".to_string());
    headers.add("Via", "second".to_string());
    
    let values = headers.get_all("Via").unwrap();
    assert_eq!(values.len(), 2);
    assert_eq!(values[0], "first");
    assert_eq!(values[1], "second");
}

#[test]
fn test_header_set() {
    let mut headers = SipHeaders::new();
    headers.add("Via", "first".to_string());
    headers.set("Via", "second".to_string());
    
    let values = headers.get_all("Via").unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0], "second");
}

#[test]
fn test_header_remove() {
    let mut headers = SipHeaders::new();
    headers.add("Via", "test".to_string());
    headers.remove("Via");
    
    assert!(headers.get("Via").is_none());
}

#[test]
fn test_convenience_methods() {
    let mut headers = SipHeaders::new();
    headers.add("Via", "SIP/2.0/UDP host:5060".to_string());
    headers.add("To", "<sip:user@example.com>".to_string());
    headers.add("From", "<sip:caller@example.com>".to_string());
    headers.add("Call-ID", "test@example.com".to_string());
    headers.add("CSeq", "1 INVITE".to_string());
    headers.add("Max-Forwards", "70".to_string());
    headers.add("Content-Length", "100".to_string());
    
    assert!(headers.via().is_some());
    assert!(headers.to().is_some());
    assert!(headers.from().is_some());
    assert!(headers.call_id().is_some());
    assert!(headers.cseq().is_some());
    assert_eq!(headers.max_forwards(), Some(70));
    assert_eq!(headers.content_length(), Some(100));
}



