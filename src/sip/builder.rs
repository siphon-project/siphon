use crate::sip::message::*;
use crate::sip::uri::SipUri;
use crate::sip::headers::SipHeaders;

/// Builder for constructing SIP messages
pub struct SipMessageBuilder {
    start_line: Option<StartLine>,
    headers: SipHeaders,
    body: Vec<u8>,
}

impl SipMessageBuilder {
    pub fn new() -> Self {
        Self {
            start_line: None,
            headers: SipHeaders::new(),
            body: Vec::new(),
        }
    }

    /// Build a request message
    pub fn request(mut self, method: Method, uri: SipUri) -> Self {
        self.start_line = Some(StartLine::Request(RequestLine {
            method,
            request_uri: uri,
            version: Version::sip_2_0(),
        }));
        self
    }

    /// Build a response message
    pub fn response(mut self, status_code: u16, reason_phrase: String) -> Self {
        self.start_line = Some(StartLine::Response(StatusLine {
            version: Version::sip_2_0(),
            status_code,
            reason_phrase,
        }));
        self
    }

    /// Add a header
    pub fn header(mut self, name: &str, value: String) -> Self {
        self.headers.add(name, value);
        self
    }

    /// Set a header (replaces existing)
    pub fn set_header(mut self, name: &str, value: String) -> Self {
        self.headers.set(name, value);
        self
    }

    /// Add Via header
    pub fn via(mut self, value: String) -> Self {
        self.headers.add("Via", value);
        self
    }

    /// Add To header
    pub fn to(mut self, value: String) -> Self {
        self.headers.add("To", value);
        self
    }

    /// Add From header
    pub fn from(mut self, value: String) -> Self {
        self.headers.add("From", value);
        self
    }

    /// Add Call-ID header
    pub fn call_id(mut self, value: String) -> Self {
        self.headers.add("Call-ID", value);
        self
    }

    /// Add CSeq header
    pub fn cseq(mut self, value: String) -> Self {
        self.headers.add("CSeq", value);
        self
    }

    /// Add Contact header
    pub fn contact(mut self, value: String) -> Self {
        self.headers.add("Contact", value);
        self
    }

    /// Set Content-Length header
    pub fn content_length(mut self, length: usize) -> Self {
        self.headers.set("Content-Length", length.to_string());
        self
    }

    /// Set Content-Type header
    pub fn content_type(mut self, content_type: String) -> Self {
        self.headers.set("Content-Type", content_type);
        self
    }

    /// Set Max-Forwards header
    pub fn max_forwards(mut self, max: u8) -> Self {
        self.headers.set("Max-Forwards", max.to_string());
        self
    }

    /// Set message body
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body.clone();
        self.headers.set("Content-Length", body.len().to_string());
        self
    }

    /// Set body as string
    pub fn body_str(mut self, body: &str) -> Self {
        let body_bytes = body.as_bytes().to_vec();
        self.body = body_bytes.clone();
        self.headers.set("Content-Length", body_bytes.len().to_string());
        self
    }

    /// Build the SIP message
    pub fn build(self) -> Result<SipMessage, String> {
        let start_line = self.start_line.ok_or("Start line not set")?;
        
        Ok(SipMessage {
            start_line,
            headers: self.headers,
            body: self.body,
        })
    }
}

impl Default for SipMessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SipMessage {
    /// Convert SIP message to wire format
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        
        // Start line
        match &self.start_line {
            StartLine::Request(req) => {
                result.extend_from_slice(req.method.as_str().as_bytes());
                result.push(b' ');
                result.extend_from_slice(req.request_uri.to_string().as_bytes());
                result.push(b' ');
                result.extend_from_slice(req.version.to_string().as_bytes());
                result.extend_from_slice(b"\r\n");
            }
            StartLine::Response(resp) => {
                result.extend_from_slice(resp.version.to_string().as_bytes());
                result.push(b' ');
                result.extend_from_slice(resp.status_code.to_string().as_bytes());
                result.push(b' ');
                result.extend_from_slice(resp.reason_phrase.as_bytes());
                result.extend_from_slice(b"\r\n");
            }
        }
        
        // Headers
        for name in self.headers.names() {
            if let Some(values) = self.headers.get_all(&name.to_lowercase()) {
                for value in values {
                    result.extend_from_slice(name.as_bytes());
                    result.extend_from_slice(b": ");
                    result.extend_from_slice(value.as_bytes());
                    result.extend_from_slice(b"\r\n");
                }
            }
        }
        
        // Empty line
        result.extend_from_slice(b"\r\n");
        
        // Body
        result.extend_from_slice(&self.body);
        
        result
    }
}

impl std::fmt::Display for SipMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.to_bytes()))
    }
}

