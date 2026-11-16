//! A strict, allocation-light JSON reader for `--get` into JWT header and
//! payload claims: it finds the byte range of the value at a path without
//! building a tree. Every value it skips or returns is validated against the
//! JSON grammar (RFC 8259), so a returned range is always valid JSON text.

use crate::Diag;

/// Nesting limit, so hostile input cannot exhaust the stack.
const MAX_DEPTH: usize = 128;

/// The byte range of the value at `segs` in the JSON document `text`.
/// Segments are object keys (matched exactly, after unescaping; the first of
/// duplicate keys wins) or array indices. `what` names the document in errors.
pub(crate) fn find(text: &str, segs: &[&str], what: &str) -> Result<[usize; 2], Diag> {
    let b = text.as_bytes();
    let malformed = || {
        Diag::new(
            "PATH_NOT_MESSAGE",
            format!("'{what}' is not valid JSON"),
            None,
        )
    };
    let start = ws(b, 0);
    let end = value_end(b, start, 0).ok_or_else(malformed)?;
    if ws(b, end) != b.len() {
        return Err(malformed());
    }
    let mut cur = [start, end];
    for (n, seg) in segs.iter().enumerate() {
        // `what` is the path before the document; empty at the top level.
        let at = || match (what.is_empty(), n) {
            (true, 0) => "the top level".to_string(),
            (true, _) => segs[..n].join("."),
            (false, 0) => what.to_string(),
            (false, _) => format!("{what}.{}", segs[..n].join(".")),
        };
        cur = match b[cur[0]] {
            b'{' => member(b, cur[0], seg).ok_or_else(|| {
                Diag::new(
                    "PATH_NOT_FOUND",
                    format!("no key '{seg}' at '{}'", at()),
                    None,
                )
            })?,
            b'[' => {
                let idx: usize = seg.parse().map_err(|_| {
                    Diag::new(
                        "PATH_NOT_FOUND",
                        format!("'{seg}' is not an array index"),
                        None,
                    )
                })?;
                element(b, cur[0], idx).ok_or_else(|| {
                    Diag::new(
                        "PATH_NOT_FOUND",
                        format!("no index '{idx}' at '{}'", at()),
                        None,
                    )
                })?
            }
            _ => {
                return Err(Diag::new(
                    "PATH_NOT_MESSAGE",
                    format!("'{}' is not a JSON object or array", at()),
                    None,
                ));
            }
        };
    }
    Ok(cur)
}

/// The unescaped contents of the JSON string literal `s` (quotes included),
/// or `None` if `s` is not one string.
pub(crate) fn string_value(s: &str) -> Option<String> {
    let b = s.as_bytes();
    if string_end(b, 0)? != b.len() {
        return None;
    }
    unescape(&s[1..s.len() - 1])
}

/// The range of `key`'s value in the (already validated) object at `open`.
fn member(b: &[u8], open: usize, key: &str) -> Option<[usize; 2]> {
    let mut i = ws(b, open + 1);
    if b[i] == b'}' {
        return None;
    }
    loop {
        let kend = string_end(b, i)?;
        let k = unescape(std::str::from_utf8(&b[i + 1..kend - 1]).ok()?)?;
        let vstart = ws(b, ws(b, kend) + 1);
        let vend = value_end(b, vstart, 0)?;
        if k == key {
            return Some([vstart, vend]);
        }
        i = ws(b, vend);
        if b[i] == b'}' {
            return None;
        }
        i = ws(b, i + 1);
    }
}

/// The range of element `idx` in the (already validated) array at `open`.
fn element(b: &[u8], open: usize, idx: usize) -> Option<[usize; 2]> {
    let mut i = ws(b, open + 1);
    if b[i] == b']' {
        return None;
    }
    for n in 0.. {
        let end = value_end(b, i, 0)?;
        if n == idx {
            return Some([i, end]);
        }
        i = ws(b, end);
        if b[i] == b']' {
            return None;
        }
        i = ws(b, i + 1);
    }
    None
}

fn ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\n' | b'\r' | b'\t') {
        i += 1;
    }
    i
}

/// The index just past the valid JSON value at `i`.
fn value_end(b: &[u8], i: usize, depth: usize) -> Option<usize> {
    if depth > MAX_DEPTH {
        return None;
    }
    match *b.get(i)? {
        b'"' => string_end(b, i),
        b'{' => {
            let mut j = ws(b, i + 1);
            if b.get(j) == Some(&b'}') {
                return Some(j + 1);
            }
            loop {
                j = string_end(b, j)?;
                j = ws(b, j);
                if b.get(j) != Some(&b':') {
                    return None;
                }
                j = value_end(b, ws(b, j + 1), depth + 1)?;
                j = ws(b, j);
                match b.get(j)? {
                    b',' => j = ws(b, j + 1),
                    b'}' => return Some(j + 1),
                    _ => return None,
                }
            }
        }
        b'[' => {
            let mut j = ws(b, i + 1);
            if b.get(j) == Some(&b']') {
                return Some(j + 1);
            }
            loop {
                j = value_end(b, j, depth + 1)?;
                j = ws(b, j);
                match b.get(j)? {
                    b',' => j = ws(b, j + 1),
                    b']' => return Some(j + 1),
                    _ => return None,
                }
            }
        }
        b't' => literal(b, i, b"true"),
        b'f' => literal(b, i, b"false"),
        b'n' => literal(b, i, b"null"),
        _ => number_end(b, i),
    }
}

fn literal(b: &[u8], i: usize, w: &[u8]) -> Option<usize> {
    b[i..].starts_with(w).then_some(i + w.len())
}

fn digits(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    i
}

fn number_end(b: &[u8], mut i: usize) -> Option<usize> {
    if b.get(i) == Some(&b'-') {
        i += 1;
    }
    match b.get(i)? {
        b'0' => i += 1,
        b'1'..=b'9' => i = digits(b, i),
        _ => return None,
    }
    if b.get(i) == Some(&b'.') {
        let j = digits(b, i + 1);
        if j == i + 1 {
            return None;
        }
        i = j;
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let j = digits(b, i);
        if j == i {
            return None;
        }
        i = j;
    }
    Some(i)
}

/// The index just past the string literal at `i` (which must be a quote).
fn string_end(b: &[u8], i: usize) -> Option<usize> {
    if b.get(i) != Some(&b'"') {
        return None;
    }
    let mut j = i + 1;
    loop {
        match *b.get(j)? {
            b'"' => return Some(j + 1),
            b'\\' => match *b.get(j + 1)? {
                b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => j += 2,
                b'u' => {
                    let hex = b.get(j + 2..j + 6)?;
                    if !hex.iter().all(u8::is_ascii_hexdigit) {
                        return None;
                    }
                    j += 6;
                }
                _ => return None,
            },
            c if c < 0x20 => return None,
            _ => j += 1,
        }
    }
}

/// Unescape a validated string body. Lone surrogates become U+FFFD.
fn unescape(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            '/' => out.push('/'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'u' => {
                let hi = hex4(&mut chars)?;
                let cp = if (0xd800..0xdc00).contains(&hi) {
                    if let Some(rest) = chars.as_str().strip_prefix("\\u") {
                        let mut look = rest.chars();
                        let lo = hex4(&mut look)?;
                        if (0xdc00..0xe000).contains(&lo) {
                            chars = look;
                            0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
                        } else {
                            0xfffd
                        }
                    } else {
                        0xfffd
                    }
                } else {
                    hi
                };
                out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
            }
            _ => return None,
        }
    }
    Some(out)
}

fn hex4(chars: &mut std::str::Chars) -> Option<u32> {
    let mut v = 0;
    for _ in 0..4 {
        v = v * 16 + chars.next()?.to_digit(16)?;
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get<'a>(t: &'a str, p: &str) -> Result<&'a str, Diag> {
        let segs: Vec<&str> = if p.is_empty() {
            vec![]
        } else {
            p.split('.').collect()
        };
        find(t, &segs, "payload").map(|[s, e]| &t[s..e])
    }

    #[test]
    fn navigates_objects_and_arrays() {
        let t = r#" {"sub":"1234","ab":{"x":[1, 2.5e3 ,{"y":null}]},"sub":"dup"} "#;
        assert_eq!(get(t, "sub").unwrap(), r#""1234""#);
        assert_eq!(get(t, "ab.x.1").unwrap(), "2.5e3");
        assert_eq!(get(t, "ab.x.2.y").unwrap(), "null");
        assert_eq!(get(t, "").unwrap(), t.trim());
        assert_eq!(get(t, "nope").unwrap_err().code, "PATH_NOT_FOUND");
        assert_eq!(get(t, "ab.x.9").unwrap_err().code, "PATH_NOT_FOUND");
        assert_eq!(get(t, "sub.x").unwrap_err().code, "PATH_NOT_MESSAGE");
    }

    #[test]
    fn rejects_malformed_json() {
        for t in [
            "{",
            r#"{"a":01}"#,
            r#"{"a":1,}"#,
            r#"{"a":"\x"}"#,
            "{\"a\":\"\u{1}\"}",
            r#"{"a":1} x"#,
            r#"{"a":tru}"#,
            r#"[1 2]"#,
        ] {
            assert_eq!(get(t, "a").unwrap_err().code, "PATH_NOT_MESSAGE", "{t}");
        }
        let deep = "[".repeat(10_000) + &"]".repeat(10_000);
        assert!(get(&deep, "0").is_err());
    }

    #[test]
    fn unescapes_strings() {
        assert_eq!(
            string_value(r#""a\n\"é😀\ud800x""#).unwrap(),
            "a\n\"é😀\u{fffd}x"
        );
        assert_eq!(string_value("1"), None);
    }
}
