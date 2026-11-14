//! Text encodings: hex, base64, PEM.

use crate::{Alphabet, Diag};

/// True when every char is printable or one of `\t`, `\n`, `\r`.
pub(crate) fn is_printable(t: &str) -> bool {
    t.chars().all(printable_char)
}

/// Fraction of chars that are printable (1.0 for the empty string).
pub(crate) fn printable_ratio(t: &str) -> f64 {
    let (mut total, mut ok) = (0usize, 0usize);
    for c in t.chars() {
        total += 1;
        if printable_char(c) {
            ok += 1;
        }
    }
    if total == 0 {
        1.0
    } else {
        ok as f64 / total as f64
    }
}

fn printable_char(c: char) -> bool {
    !c.is_control() || matches!(c, '\n' | '\r' | '\t')
}

// ---------------------------------------------------------------- hex

pub(crate) struct HexInfo {
    tokens: usize,
    all_pairs: bool,
    has_0x: bool,
    all_decimal: bool,
}

fn is_hex_sep(c: u8) -> bool {
    c.is_ascii_whitespace() || c == b':'
}

fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => c - b'A' + 10,
    }
}

pub(crate) fn hex_scan(s: &str) -> Result<(Vec<u8>, HexInfo), Diag> {
    let base = s.len() - s.trim_start().len();
    let b = s.trim().as_bytes();
    let mut digits = Vec::with_capacity(b.len());
    let mut info = HexInfo {
        tokens: 0,
        all_pairs: true,
        has_0x: false,
        all_decimal: true,
    };
    let mut i = 0;
    while i < b.len() {
        if is_hex_sep(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && !is_hex_sep(b[i]) {
            i += 1;
        }
        let mut tok_start = start;
        if i - start >= 2 && b[start] == b'0' && (b[start + 1] | 0x20) == b'x' {
            tok_start += 2;
            info.has_0x = true;
        }
        let tok = &b[tok_start..i];
        if tok.is_empty() {
            continue;
        }
        if !tok.len().is_multiple_of(2) {
            return Err(Diag::new(
                "ODD_LENGTH",
                "hex token has an odd number of digits",
                Some(base + start),
            ));
        }
        for (j, &c) in tok.iter().enumerate() {
            if !c.is_ascii_hexdigit() {
                return Err(Diag::new(
                    "INVALID_CHAR",
                    format!("byte 0x{c:02x} is not a hex digit"),
                    Some(base + tok_start + j),
                ));
            }
            if !c.is_ascii_digit() {
                info.all_decimal = false;
            }
            digits.push(c);
        }
        info.tokens += 1;
        if tok.len() != 2 {
            info.all_pairs = false;
        }
    }
    if digits.is_empty() {
        return Err(Diag::new("EMPTY", "no hex digits found", None));
    }
    let bytes = digits
        .chunks_exact(2)
        .map(|p| (hex_val(p[0]) << 4) | hex_val(p[1]))
        .collect();
    Ok((bytes, info))
}

/// Strictly decode hex text. Whitespace and `:` separate tokens; each token
/// may carry a `0x` prefix and must have an even number of digits.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, Diag> {
    hex_scan(s).map(|(b, _)| b)
}

pub(crate) fn hex_candidate(s: &str) -> Option<(Vec<u8>, f64)> {
    let (bytes, info) = hex_scan(s).ok()?;
    let mut conf = if info.has_0x || (info.tokens > 1 && info.all_pairs) {
        0.95
    } else if info.tokens > 1 {
        0.85
    } else if bytes.len() >= 4 {
        0.9
    } else {
        0.6
    };
    // A single run of decimal digits is more likely a number than hex,
    // unless it has a leading zero (numbers rarely do; hex bytes often do).
    if info.all_decimal && info.tokens == 1 && !info.has_0x && !s.trim().starts_with('0') {
        conf *= 0.5;
    }
    Some((bytes, conf))
}

// ---------------------------------------------------------------- base64

/// Result of decoding base64 text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct B64 {
    pub alphabet: Alphabet,
    /// True if padding was present, or none was needed.
    pub padded: bool,
    pub bytes: Vec<u8>,
    /// Unused trailing bits were non-zero: valid-ish, but suspicious.
    pub noncanonical: bool,
}

/// Decode base64 text: standard (`+/`) or URL-safe (`-_`) alphabet, padded or
/// unpadded, with line breaks allowed (PEM-style wrapping). Other whitespace
/// inside the data is rejected.
pub fn decode_b64(s: &str) -> Result<B64, Diag> {
    let base = s.len() - s.trim_start().len();
    let t = s.trim();
    let mut sextets: Vec<u8> = Vec::with_capacity(t.len());
    let (mut std_at, mut url_at) = (None::<usize>, None::<usize>);
    let (mut pad, mut pad_at) = (0usize, None::<usize>);
    for (i, &c) in t.as_bytes().iter().enumerate() {
        let off = base + i;
        if c == b'\n' || c == b'\r' {
            continue;
        }
        if c == b'=' {
            pad += 1;
            pad_at.get_or_insert(off);
            continue;
        }
        if pad > 0 {
            return Err(Diag::new(
                "BAD_PADDING",
                "data after '=' padding",
                Some(off),
            ));
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'/' => {
                std_at.get_or_insert(off);
                if c == b'+' { 62 } else { 63 }
            }
            b'-' | b'_' => {
                url_at.get_or_insert(off);
                if c == b'-' { 62 } else { 63 }
            }
            _ => {
                return Err(Diag::new(
                    "INVALID_CHAR",
                    format!("byte 0x{c:02x} is not a base64 character"),
                    Some(off),
                ));
            }
        };
        sextets.push(v);
    }
    if let (Some(_), Some(u)) = (std_at, url_at) {
        return Err(Diag::new(
            "MIXED_ALPHABET",
            "mixes standard (+/) and URL-safe (-_) base64 characters",
            Some(u),
        ));
    }
    let n = sextets.len();
    if n == 0 {
        return Err(Diag::new("EMPTY", "no base64 characters found", None));
    }
    if n % 4 == 1 {
        return Err(Diag::new(
            "INVALID_LENGTH",
            format!("{n} base64 characters cannot encode whole bytes"),
            None,
        ));
    }
    if pad > 0 && pad != (4 - n % 4) % 4 {
        return Err(Diag::new(
            "BAD_PADDING",
            format!("{pad} '=' characters do not match the data length"),
            pad_at,
        ));
    }
    let mut out = Vec::with_capacity(n * 3 / 4);
    let mut noncanonical = false;
    for c in sextets.chunks(4) {
        let s = |i: usize| u32::from(c[i]);
        match c.len() {
            4 => {
                let v = (s(0) << 18) | (s(1) << 12) | (s(2) << 6) | s(3);
                out.extend_from_slice(&[(v >> 16) as u8, (v >> 8) as u8, v as u8]);
            }
            3 => {
                let v = (s(0) << 18) | (s(1) << 12) | (s(2) << 6);
                out.extend_from_slice(&[(v >> 16) as u8, (v >> 8) as u8]);
                noncanonical |= c[2] & 0x03 != 0;
            }
            _ => {
                let v = (s(0) << 18) | (s(1) << 12);
                out.push((v >> 16) as u8);
                noncanonical |= c[1] & 0x0f != 0;
            }
        }
    }
    Ok(B64 {
        alphabet: if url_at.is_some() {
            Alphabet::Url
        } else {
            Alphabet::Std
        },
        padded: pad > 0 || n.is_multiple_of(4),
        bytes: out,
        noncanonical,
    })
}

pub(crate) fn b64_candidate(s: &str) -> Option<(B64, f64)> {
    let b = decode_b64(s).ok()?;
    let t = s.trim();
    let (mut len, mut digit, mut special, mut all_hex) = (0usize, false, false, true);
    for c in t.bytes().filter(|c| !matches!(c, b'\n' | b'\r' | b'=')) {
        len += 1;
        digit |= c.is_ascii_digit();
        special |= matches!(c, b'+' | b'/' | b'-' | b'_');
        all_hex &= c.is_ascii_hexdigit();
    }
    let mut conf: f64 = 0.75;
    if len >= 16 {
        conf += 0.1;
    }
    if special || t.contains('=') {
        conf += 0.1;
    }
    if !b.padded {
        conf -= 0.05;
    }
    if b.noncanonical {
        conf *= 0.3;
    }
    if all_hex {
        conf *= 0.5;
    }
    // Words like "HelloWorld" are valid base64; real base64 nearly always has a digit or symbol.
    if !digit && !special {
        conf *= 0.6;
    }
    Some((b, conf.min(0.99)))
}

pub(crate) fn noncanonical_diag() -> Diag {
    Diag::new(
        "NONCANONICAL_BASE64",
        "unused trailing bits are not zero; this may not really be base64",
        None,
    )
}

// ---------------------------------------------------------------- PEM

/// One PEM block: its label, decoded body and `BEGIN..END` range.
pub(crate) struct PemBlock {
    pub label: String,
    pub b64: B64,
    /// Range of the whole block: the `BEGIN` line start to the `END` line end.
    pub range: [usize; 2],
}

/// Every PEM block in the text, plus the non-whitespace bytes outside them.
pub(crate) struct PemBundle {
    pub blocks: Vec<PemBlock>,
    /// Bytes of non-whitespace text outside all blocks (up to any break).
    pub ignored: usize,
    /// A *later* block was broken after at least one good block. The good
    /// blocks are kept and this is reported as a warning on the node.
    pub error: Option<Diag>,
}

/// `None` if there is no PEM block; `Some(Err)` if the *first* block is broken.
///
/// All blocks are decoded, so a certificate chain or a key + cert file becomes
/// a bundle. A later broken block (a `BEGIN` without its `END`, or a body that
/// is not base64) stops the scan: the blocks decoded so far are kept and the
/// error is returned in `PemBundle::error` as a warning. If the first block is
/// broken, nothing is recognised (today's behavior).
pub(crate) fn decode_pem(s: &str) -> Option<Result<PemBundle, Diag>> {
    const BEGIN: &str = "-----BEGIN ";
    let mut blocks: Vec<PemBlock> = Vec::new();
    let mut cursor = 0;
    let mut stop_at = s.len();
    let mut error: Option<Diag> = None;
    while let Some(rel) = s[cursor..].find(BEGIN) {
        let begin = cursor + rel;
        let after = &s[begin + BEGIN.len()..];
        let Some(label_end) = after.find("-----") else {
            // A `BEGIN` with no closing dashes is not PEM (as before).
            if blocks.is_empty() {
                return None;
            }
            stop_at = begin;
            break;
        };
        let label = &after[..label_end];
        if label.contains('\n') {
            if blocks.is_empty() {
                return None;
            }
            stop_at = begin;
            break;
        }
        let body_start = begin + BEGIN.len() + label_end + 5;
        let end_marker = format!("-----END {label}-----");
        let Some(rel_end) = s[body_start..].find(&end_marker) else {
            let d = Diag::new(
                "PEM_UNTERMINATED",
                format!("missing {end_marker}"),
                Some(begin),
            );
            if blocks.is_empty() {
                return Some(Err(d));
            }
            stop_at = begin;
            error = Some(d);
            break;
        };
        let body: String = s[body_start..body_start + rel_end]
            .lines()
            .filter(|l| !l.contains(':')) // RFC 1421 headers, e.g. Proc-Type
            .map(str::trim)
            .collect();
        let b64 = match decode_b64(&body) {
            Ok(b) => b,
            Err(mut e) => {
                e.offset = Some(body_start);
                if blocks.is_empty() {
                    return Some(Err(e));
                }
                stop_at = begin;
                error = Some(e);
                break;
            }
        };
        let end = body_start + rel_end + end_marker.len();
        blocks.push(PemBlock {
            label: label.to_string(),
            b64,
            range: [begin, end],
        });
        cursor = end;
    }
    if blocks.is_empty() {
        return None;
    }
    let ignored = count_ignored(s, &blocks, stop_at);
    Some(Ok(PemBundle {
        blocks,
        ignored,
        error,
    }))
}

/// Number of non-whitespace bytes outside every block, considering only
/// `s[..limit]`. When a later block is broken, `limit` is that block's start,
/// so the cut-off text is not also reported as trailing data.
fn count_ignored(s: &str, blocks: &[PemBlock], limit: usize) -> usize {
    let mut ignored = 0;
    let mut cursor = 0;
    for b in blocks {
        if b.range[0] >= limit {
            break;
        }
        ignored += non_ws(&s[cursor..b.range[0]]);
        cursor = b.range[1];
    }
    ignored + non_ws(&s[cursor..limit])
}

fn non_ws(t: &str) -> usize {
    t.bytes().filter(|b| !b.is_ascii_whitespace()).count()
}
