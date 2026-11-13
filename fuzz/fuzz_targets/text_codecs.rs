//! Hex and base64 decoders: no panics, and decoded bytes re-encode to input
//! that decodes to the same bytes.
#![no_main]

use bytepeel_core::{decode_b64, decode_hex};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(bytes) = decode_hex(s) {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(decode_hex(&hex).unwrap(), bytes);
    }
    if let Ok(b) = decode_b64(s) {
        if !b.bytes.is_empty() {
            let again = decode_b64(&std_b64(&b.bytes)).unwrap();
            assert_eq!(again.bytes, b.bytes);
        }
    }
});

fn std_b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            o.push(if i <= c.len() {
                A[((n >> (18 - 6 * i)) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    o
}
