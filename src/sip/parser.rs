//! RFC 3261 SIP message parser built with nom.

use nom::{
    IResult, Parser,
    bytes::complete::{tag, take_until, take_while, take_while1},
    character::complete::{char, space1, digit1, multispace0},
    sequence::{preceded, terminated, delimited},
    multi::many0,
    combinator::{opt, map_res},
    branch::alt,
};
use crate::sip::message::*;
use crate::sip::uri::SipUri;
use crate::sip::headers::SipHeaders;

/// Parse a SIP message (request or response)
pub fn parse_sip_message(input: &str) -> IResult<&str, SipMessage> {
    let (input, start_line) = parse_start_line(input)?;
    let (input, headers) = parse_headers(input)?;
    let (input, body) = parse_body(input, &headers)?;

    Ok((input, SipMessage {
        start_line,
        headers,
        body: body.as_bytes().to_vec(),
    }))
}

/// Parse start line (request or response)
fn parse_start_line(input: &str) -> IResult<&str, StartLine> {
    alt((
        parse_request_line.map(StartLine::Request),
        parse_status_line.map(StartLine::Response),
    )).parse(input)
}

/// Parse request line: METHOD SP Request-URI SP SIP-Version CRLF
fn parse_request_line(input: &str) -> IResult<&str, RequestLine> {
    let (input, method_str) = take_while1(|c: char| c.is_alphanumeric() || matches!(c, '-' | '.'))(input)?;
    let method = Method::from_str(method_str);

    let (input, _) = space1(input)?;
    let (input, uri) = parse_uri(input)?;
    let (input, _) = space1(input)?;
    let (input, version) = parse_version(input)?;
    let (input, _) = parse_crlf(input)?;

    Ok((input, RequestLine {
        method,
        request_uri: uri,
        version,
    }))
}

/// Parse status line: SIP-Version SP Status-Code SP Reason-Phrase CRLF
fn parse_status_line(input: &str) -> IResult<&str, StatusLine> {
    let (input, version) = parse_version(input)?;
    let (input, _) = space1(input)?;
    let (input, status_code) = map_res(digit1, |s: &str| s.parse::<u16>()).parse(input)?;
    let (input, _) = space1(input)?;
    let (input, reason_phrase) = take_until("\r\n")(input)?;
    let (input, _) = parse_crlf(input)?;

    Ok((input, StatusLine {
        version,
        status_code,
        reason_phrase: reason_phrase.to_string(),
    }))
}

/// Parse SIP version: SIP/2.0
fn parse_version(input: &str) -> IResult<&str, Version> {
    let (input, _) = tag("SIP/")(input)?;
    let (input, major) = map_res(digit1, |s: &str| s.parse::<u8>()).parse(input)?;
    let (input, _) = char('.')(input)?;
    let (input, minor) = map_res(digit1, |s: &str| s.parse::<u8>()).parse(input)?;

    Ok((input, Version { major, minor }))
}

/// Parse a SIP URI from a standalone string (not embedded in a nom pipeline).
///
/// Returns the parsed `SipUri` or an error message.
pub fn parse_uri_standalone(input: &str) -> Result<SipUri, String> {
    let input = input.trim();
    match parse_uri(input) {
        Ok((_rest, uri)) => Ok(uri),
        Err(error) => Err(format!("failed to parse SIP URI '{input}': {error}")),
    }
}

/// Parse SIP URI: sip:user@host:port;params?headers
fn parse_uri(input: &str) -> IResult<&str, SipUri> {
    let (input, scheme) = alt((tag("sip:"), tag("sips:"))).parse(input)?;
    let scheme = scheme.trim_end_matches(':').to_string();

    // Parse user part (optional)
    let (input, user) = opt(terminated(
        take_while1(|c: char| !matches!(c, '@' | ':' | ';' | '?' | ' ' | '\r' | '\n')),
        char('@')
    )).parse(input)?;

    // Parse host (stop before port separator or URI parameters)
    // Host can be domain name, IPv4, or IPv6 in brackets
    let (input, host_str) = if input.starts_with('[') {
        // IPv6 address in brackets
        let (input, ipv6) = delimited(
            char('['),
            take_while1(|c: char| c != ']'),
            char(']')
        ).parse(input)?;
        (input, format!("[{}]", ipv6))
    } else {
        // Domain name or IPv4 - take until : or ; or ? or space
        let (input, host) = take_while1(|c: char| {
            c.is_alphanumeric() || matches!(c, '.' | '-')
        })(input)?;
        (input, host.to_string())
    };

    // Parse port (optional)
    let (input, port) = opt(preceded(
        char(':'),
        map_res(take_while1(|c: char| c.is_ascii_digit()), |s: &str| s.parse::<u16>())
    )).parse(input)?;

    // Parse URI parameters (optional)
    let (input, params) = opt(parse_uri_params).parse(input)?;
    let params = params.unwrap_or_default();

    // Parse URI headers (optional, after ?)
    let (input, headers) = opt(preceded(
        char('?'),
        parse_uri_headers
    )).parse(input)?;
    let headers = headers.unwrap_or_default();

    Ok((input, SipUri {
        scheme,
        user: user.map(|s| s.to_string()),
        host: host_str.to_string(),
        port,
        params,
        headers,
    }))
}

/// Parse URI parameters: ;param=value;param2
fn parse_uri_params(input: &str) -> IResult<&str, Vec<(String, Option<String>)>> {
    many0(preceded(
        char(';'),
        (
            take_while1(|c: char| !matches!(c, '=' | ';' | '?' | ' ' | '\r' | '\n')),
            opt(preceded(
                char('='),
                take_while(|c: char| !matches!(c, ';' | '?' | ' ' | '\r' | '\n'))
            )),
        )
    )).parse(input)
    .map(|(input, params)| {
        let params: Vec<(String, Option<String>)> = params
            .into_iter()
            .map(|(name, value)| (name.to_string(), value.map(|s| s.to_string())))
            .collect();
        (input, params)
    })
}

/// Parse URI headers: header=value&header2=value2
fn parse_uri_headers(input: &str) -> IResult<&str, Vec<(String, Option<String>)>> {
    many0(preceded(
        opt(char('&')),
        (
            take_while1(|c: char| !matches!(c, '=' | '&' | ' ' | '\r' | '\n')),
            opt(preceded(
                char('='),
                take_while(|c: char| !matches!(c, '&' | ' ' | '\r' | '\n'))
            )),
        )
    )).parse(input)
    .map(|(input, headers)| {
        let headers: Vec<(String, Option<String>)> = headers
            .into_iter()
            .map(|(name, value)| (name.to_string(), value.map(|s| s.to_string())))
            .collect();
        (input, headers)
    })
}

/// Parse headers section until empty line
fn parse_headers(input: &str) -> IResult<&str, SipHeaders> {
    let mut headers = SipHeaders::new();
    let mut remaining = input;

    loop {
        if remaining.is_empty() {
            return Ok((remaining, headers));
        }
        if let Some(after) = remaining.strip_prefix("\r\n") {
            return Ok((after, headers));
        }
        if let Some(after) = remaining.strip_prefix('\n') {
            return Ok((after, headers));
        }

        // Skip leading whitespace (but NOT CRLF — those are checked above)
        remaining = remaining.trim_start_matches([' ', '\t']);

        match parse_header_line(remaining) {
            Ok((input, (name, value))) => {
                headers.add(&name, value);
                remaining = input;
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
}

/// Parse a single header line (handles folding)
fn parse_header_line(input: &str) -> IResult<&str, (String, String)> {
    let input = input.trim_start_matches([' ', '\t']);

    // Parse header name
    let (input, name) = take_while1(|c: char| !matches!(c, ':' | '\r' | '\n' | ' ' | '\t'))(input)?;
    let (input, _) = char(':')(input)?;
    let (input, _) = multispace0(input)?;

    // Parse header value (may be folded with SP/TAB on next line)
    let mut value = String::new();
    let mut remaining = input;

    loop {
        let (input, line_value) = take_until("\r\n")(remaining)?;
        value.push_str(line_value);

        let (input, _) = parse_crlf(input)?;

        if input.is_empty() {
            return Ok((input, (name.trim().to_string(), value.trim().to_string())));
        }

        let trimmed = input.trim_start_matches([' ', '\t']);
        if trimmed.is_empty() {
            return Ok((input, (name.trim().to_string(), value.trim().to_string())));
        }

        if input.starts_with([' ', '\t']) {
            let (input, _) = take_while1(|c: char| matches!(c, ' ' | '\t'))(input)?;
            value.push(' ');
            remaining = input;
        } else {
            return Ok((input, (name.trim().to_string(), value.trim().to_string())));
        }
    }
}

/// Parse body based on Content-Length header
fn parse_body<'a>(input: &'a str, headers: &SipHeaders) -> IResult<&'a str, &'a str> {
    if let Some(content_length) = headers.content_length() {
        if content_length == 0 {
            Ok((input, ""))
        } else if input.len() >= content_length {
            Ok((&input[content_length..], &input[..content_length]))
        } else {
            Ok((input, ""))
        }
    } else {
        Ok((input, ""))
    }
}

/// Parse CRLF
fn parse_crlf(input: &str) -> IResult<&str, &str> {
    alt((
        tag("\r\n"),
        tag("\n"),
    )).parse(input)
}
