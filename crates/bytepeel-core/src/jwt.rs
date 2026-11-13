//! JSON Web Tokens: `header.payload.signature` (JWS) or the five-part JWE form.
//!
//! Recognition reads only the structure and the header: 3 or 5 dot-separated
//! unpadded base64url segments whose first segment decodes to printable UTF-8
//! JSON containing an `"alg"` member. Anything else is not a JWT, so plain
//! prose, version numbers and dotted domains are never claimed.
//!
//! For a JWS whose payload is a JSON object, the top-level numeric `exp`, `nbf`
//! and `iat` claims are converted to ISO-8601 UTC with Howard Hinnant's
//! `civil_from_days`. A fractional part is truncated toward zero; exponent
//! notation, non-numbers and values that overflow `i64` are ignored.

use crate::text;
use crate::value::iso_utc;

/// One dot-separated segment: its byte range in the input text and its bytes.
pub(crate) struct Part {
    pub range: [usize; 2],
    pub decoded: Vec<u8>,
}

/// A recognised token.
pub(crate) struct Jwt {
    /// `"jws"` (3 parts) or `"jwe"` (5 parts).
    pub kind: &'static str,
    pub parts: Vec<Part>,
    /// Top-level integer time claims of a JWS payload, in `exp`, `nbf`, `iat`
    /// order, as `(claim, ISO-8601 UTC)`.
    pub times: Vec<(&'static str, String)>,
}

const CLAIMS: [&str; 3] = ["exp", "nbf", "iat"];

fn is_url_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
}

/// Recognise a JWT in `s` (whitespace around the token is allowed).
pub(crate) fn decode_jwt(s: &str) -> Option<Jwt> {
    let t = s.trim();
    let base = s.len() - s.trim_start().len();
    let segs: Vec<&str> = t.split('.').collect();
    if !matches!(segs.len(), 3 | 5) {
        return None;
    }
    // Every segment is unpadded base64url (segments may be empty).
    if !segs.iter().all(|p| p.bytes().all(is_url_char)) {
        return None;
    }

    // Ranges of each segment within `s`.
    let mut parts = Vec::with_capacity(segs.len());
    let mut at = base;
    for seg in &segs {
        parts.push(Part {
            range: [at, at + seg.len()],
            decoded: Vec::new(),
        });
        at += seg.len() + 1;
    }

    // The header must be canonical base64url for printable UTF-8 JSON with "alg".
    let header = text::decode_b64(segs[0]).ok()?;
    if header.noncanonical {
        return None;
    }
    let htext = std::str::from_utf8(&header.bytes).ok()?;
    if !text::is_printable(htext) || !htext.starts_with('{') || !htext.contains("\"alg\"") {
        return None;
    }

    // Decode the remaining (non-empty) segments.
    for (part, seg) in parts.iter_mut().zip(&segs) {
        if seg.is_empty() {
            continue;
        }
        part.decoded = text::decode_b64(seg).ok()?.bytes;
    }

    let kind = if segs.len() == 3 { "jws" } else { "jwe" };
    let mut times = Vec::new();
    if kind == "jws" {
        if let Ok(payload) = std::str::from_utf8(&parts[1].decoded) {
            times = extract_times(payload);
        }
    }
    Some(Jwt { kind, parts, times })
}

/// Top-level integer `exp`/`nbf`/`iat` of a JSON object, in that order.
fn extract_times(s: &str) -> Vec<(&'static str, String)> {
    let b = s.as_bytes();
    let mut i = skip_ws(b, 0);
    if b.get(i) != Some(&b'{') {
        return Vec::new();
    }
    i += 1;
    let mut vals: [Option<i64>; 3] = [None; 3];
    loop {
        i = skip_ws(b, i);
        match b.get(i) {
            Some(b'}') | None => break,
            Some(b',') => {
                i += 1;
                continue;
            }
            Some(b'"') => {}
            _ => return Vec::new(),
        }
        let Some((key, after)) = scan_string(s, i) else {
            return Vec::new();
        };
        i = skip_ws(b, after);
        if b.get(i) != Some(&b':') {
            return Vec::new();
        }
        i = skip_ws(b, i + 1);

        let claim = CLAIMS.iter().position(|c| *c == key);
        let parsed = claim.and_then(|ci| scan_int(b, i).map(|(v, after)| (ci, v, after)));
        let taken = if let Some((ci, v, after)) = parsed {
            if vals[ci].is_none() {
                vals[ci] = Some(v);
            }
            i = after;
            true
        } else {
            false
        };
        if !taken {
            match skip_value(b, i) {
                Some(after) => i = after,
                None => return Vec::new(),
            }
        }
    }
    let mut out = Vec::new();
    for (ci, name) in CLAIMS.iter().enumerate() {
        if let Some(v) = vals[ci] {
            out.push((*name, iso_utc(v)));
        }
    }
    out
}

/// A JSON string starting at `start` (a quote). Returns its raw contents (with
/// escapes intact, which never equals a claim name) and the index after it.
fn scan_string(s: &str, start: usize) -> Option<(&str, usize)> {
    let b = s.as_bytes();
    if b.get(start) != Some(&b'"') {
        return None;
    }
    let from = start + 1;
    let mut i = from;
    while i < b.len() {
        match b[i] {
            b'"' => return Some((&s[from..i], i + 1)),
            b'\\' => i += 2,
            _ => i += 1,
        }
    }
    None
}

/// A JSON number at `start` if it has no exponent, as an `i64` (a fractional
/// part is dropped). `None` for non-integers and overflow.
fn scan_int(b: &[u8], start: usize) -> Option<(i64, usize)> {
    let mut i = start;
    let neg = b.get(i) == Some(&b'-');
    if neg {
        i += 1;
    }
    let from = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == from {
        return None;
    }
    let mut mag: i64 = 0;
    for &c in &b[from..i] {
        mag = mag.checked_mul(10)?.checked_add(i64::from(c - b'0'))?;
    }
    let mut end = i;
    if b.get(end) == Some(&b'.') {
        end += 1;
        let f0 = end;
        while end < b.len() && b[end].is_ascii_digit() {
            end += 1;
        }
        if end == f0 {
            return None;
        }
    }
    if matches!(b.get(end), Some(b'e' | b'E')) {
        return None;
    }
    Some((if neg { -mag } else { mag }, end))
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\n' | b'\r' | b'\t') {
        i += 1;
    }
    i
}

fn skip_string_body(b: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    while i < b.len() {
        match b[i] {
            b'"' => return Some(i + 1),
            b'\\' => i += 2,
            _ => i += 1,
        }
    }
    None
}

fn lit(b: &[u8], start: usize, w: &[u8]) -> Option<usize> {
    if b[start..].starts_with(w) {
        Some(start + w.len())
    } else {
        None
    }
}

/// Skip one JSON value, returning the index after it. `None` if malformed.
fn skip_value(b: &[u8], start: usize) -> Option<usize> {
    match b.get(start)? {
        b'"' => skip_string_body(b, start),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut i = start;
            while i < b.len() {
                match b[i] {
                    b'"' => {
                        i = skip_string_body(b, i)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(i + 1);
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            None
        }
        b't' => lit(b, start, b"true"),
        b'f' => lit(b, start, b"false"),
        b'n' => lit(b, start, b"null"),
        c if *c == b'-' || c.is_ascii_digit() => {
            let mut i = start;
            if b.get(i) == Some(&b'-') {
                i += 1;
            }
            let from = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i == from {
                return None;
            }
            if b.get(i) == Some(&b'.') {
                i += 1;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
            }
            if matches!(b.get(i), Some(b'e' | b'E')) {
                i += 1;
                if matches!(b.get(i), Some(b'+' | b'-')) {
                    i += 1;
                }
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
            }
            Some(i)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc(-1), "1969-12-31T23:59:59Z");
        assert_eq!(iso_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(iso_utc(4_102_444_800), "2100-01-01T00:00:00Z");
        assert_eq!(iso_utc(2_147_483_648), "2038-01-19T03:14:08Z");
    }

    #[test]
    fn only_top_level_integer_claims() {
        let want = vec![("exp", "1970-01-01T00:00:00Z".to_string())];
        assert_eq!(extract_times(r#"{"exp":0}"#), want);
        assert!(extract_times(r#"{"x":{"exp":5}}"#).is_empty());
        assert!(extract_times(r#"{"a":"exp"}"#).is_empty());
        assert!(extract_times(r#"{"exp":"5"}"#).is_empty());
        assert!(extract_times("[1,2,3]").is_empty());
        // Order is fixed: exp, nbf, iat.
        let names: Vec<_> = extract_times(r#"{"iat":1,"nbf":2,"exp":3}"#)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, ["exp", "nbf", "iat"]);
    }

    #[test]
    fn not_a_token() {
        for s in ["a.b.c", "1.2.3", "www.example.com", "ey.J9.x", ""] {
            assert!(decode_jwt(s).is_none(), "{s}");
        }
    }
}
