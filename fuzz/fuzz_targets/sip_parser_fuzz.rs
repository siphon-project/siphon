#![no_main]

use libfuzzer_sys::fuzz_target;
use siphon::sip::parse_sip_message;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        // The parser must never panic on any input.
        let _ = parse_sip_message(input);
    }
});
