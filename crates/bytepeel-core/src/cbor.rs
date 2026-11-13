//! CBOR (RFC 8949): a schemaless parser into the shared [`Value`] tree.
//!
//! Indefinite-length strings, arrays and maps are supported (chunks are
//! concatenated for strings). Reserved additional information (28-30), breaks
//! in the wrong place, invalid UTF-8 and deep nesting are hard errors when the
//! format is forced.

use crate::detect;
use crate::node::{Codec, Detail, Node};
use crate::value::{self, Value, ValueKind};
use crate::{Diag, Options};

/// Hard recursion cap, independent of `Options::depth`.
const MAX_NEST: usize = 100;

fn truncated(at: usize) -> Diag {
    Diag::new(
        "CBOR_TRUNCATED",
        "CBOR item runs past the end of the buffer",
        Some(at),
    )
}

fn reserved(at: usize) -> Diag {
    Diag::new(
        "CBOR_RESERVED",
        "reserved CBOR additional information (28-30, or 31 for this type)",
        Some(at),
    )
}

fn invalid(at: usize, msg: &str) -> Diag {
    Diag::new("CBOR_INVALID", msg.to_string(), Some(at))
}

fn bad_utf8(at: usize) -> Diag {
    Diag::new(
        "CBOR_BAD_UTF8",
        "CBOR text string is not valid UTF-8",
        Some(at),
    )
}

fn unexpected_break(at: usize) -> Diag {
    Diag::new(
        "CBOR_BREAK",
        "unexpected break (0xff) where an item was expected",
        Some(at),
    )
}

fn too_deep(at: usize) -> Diag {
    Diag::new(
        "NESTING_TOO_DEEP",
        format!("more than {MAX_NEST} nested CBOR items"),
        Some(at),
    )
}

/// Parse `buf` as a CBOR sequence (one or more items) covering the whole
/// buffer. This is structural only: byte strings get `decoded: None`. Run
/// [`crate::detect::enrich_values`] afterwards to fill nested nodes once.
pub(crate) fn parse_sequence(buf: &[u8]) -> Result<Vec<Value>, Diag> {
    let mut pos = 0;
    let mut items = Vec::new();
    while pos < buf.len() {
        items.push(parse_one(buf, &mut pos, 0)?);
    }
    Ok(items)
}

/// Auto-detection: a self-describe prefix, or exactly one item covering the
/// whole buffer whose top level (after tags) is a map or array. The `bool` is
/// whether every map key is a text string (used for tie-breaking).
pub(crate) fn detect(buf: &[u8]) -> Option<(Vec<Value>, f64, bool)> {
    if buf.len() < 2 {
        return None;
    }
    let self_describe = buf.len() >= 3 && buf[0] == 0xd9 && buf[1] == 0xd9 && buf[2] == 0xf7;
    let items = parse_sequence(buf).ok()?;
    if items.len() != 1 {
        return None;
    }
    if self_describe {
        let text_keys = value::keys_all_text(&items);
        return Some((items, 0.99, text_keys));
    }
    match &items[0].untagged().kind {
        ValueKind::Map(_) | ValueKind::Array(_) => {
            let conf = value::structure_confidence(&items, 23, 23);
            let text_keys = value::keys_all_text(&items);
            Some((items, conf, text_keys))
        }
        _ => None,
    }
}

/// Build the CBOR node for a parsed sequence.
pub(crate) fn node(items: Vec<Value>, confidence: f64, len: usize) -> Node {
    Node {
        codec: Codec::Cbor,
        range: [0, len],
        confidence,
        detail: Detail::Values { items },
        warnings: vec![],
    }
}

fn take<'a>(buf: &'a [u8], pos: &mut usize, n: usize, at: usize) -> Result<&'a [u8], Diag> {
    if buf.len() - *pos < n {
        return Err(truncated(at));
    }
    let s = &buf[*pos..*pos + n];
    *pos += n;
    Ok(s)
}

fn read_u8(buf: &[u8], pos: &mut usize, at: usize) -> Result<u8, Diag> {
    if *pos >= buf.len() {
        return Err(truncated(at));
    }
    let b = buf[*pos];
    *pos += 1;
    Ok(b)
}

fn read_be(buf: &[u8], pos: &mut usize, n: usize, at: usize) -> Result<u64, Diag> {
    let s = take(buf, pos, n, at)?;
    Ok(s.iter().fold(0u64, |a, &b| (a << 8) | u64::from(b)))
}

/// The length for a definite-length string/array/map (`ai` != 31).
fn definite_len(buf: &[u8], pos: &mut usize, at: usize, ai: u8) -> Result<usize, Diag> {
    match ai {
        0..=23 => Ok(usize::from(ai)),
        24 => Ok(usize::from(read_u8(buf, pos, at)?)),
        25 => Ok(read_be(buf, pos, 2, at)? as usize),
        26 => Ok(read_be(buf, pos, 4, at)? as usize),
        27 => usize::try_from(read_be(buf, pos, 8, at)?).map_err(|_| truncated(at)),
        28..=30 => Err(reserved(at)),
        _ => Err(reserved(at)),
    }
}

/// The value for major types 0 (uint), 1 (nint) and 6 (tag).
fn decode_uint(buf: &[u8], pos: &mut usize, at: usize, ai: u8) -> Result<u64, Diag> {
    match ai {
        0..=23 => Ok(u64::from(ai)),
        24 => Ok(u64::from(read_u8(buf, pos, at)?)),
        25 => read_be(buf, pos, 2, at),
        26 => read_be(buf, pos, 4, at),
        27 => read_be(buf, pos, 8, at),
        28..=30 => Err(reserved(at)),
        _ => Err(reserved(at)),
    }
}

fn parse_one(buf: &[u8], pos: &mut usize, nest: usize) -> Result<Value, Diag> {
    if nest > MAX_NEST {
        return Err(too_deep(*pos));
    }
    let start = *pos;
    let head = read_u8(buf, pos, start)?;
    let major = head >> 5;
    let ai = head & 0x1f;
    let mut indefinite = false;
    let kind = match major {
        0 => ValueKind::Uint(decode_uint(buf, pos, start, ai)?),
        1 => ValueKind::Nint(decode_uint(buf, pos, start, ai)?),
        2 => {
            let (kind, ind) = parse_bytes(buf, pos, start, ai)?;
            indefinite = ind;
            kind
        }
        3 => {
            let (text, ind) = parse_text(buf, pos, start, ai)?;
            indefinite = ind;
            ValueKind::Text(text)
        }
        4 => {
            let (items, ind) = parse_array(buf, pos, start, ai, nest)?;
            indefinite = ind;
            ValueKind::Array(items)
        }
        5 => {
            let (entries, ind) = parse_map(buf, pos, start, ai, nest)?;
            indefinite = ind;
            ValueKind::Map(entries)
        }
        6 => {
            let n = decode_uint(buf, pos, start, ai)?;
            let inner = parse_one(buf, pos, nest + 1)?;
            ValueKind::Tag(n, Box::new(inner))
        }
        _ => parse_simple(buf, pos, start, ai)?,
    };
    Ok(Value {
        range: [start, *pos],
        kind,
        indefinite,
    })
}

/// A byte string, structurally: any nested `decoded` node is filled later by
/// [`crate::detect::enrich_values`].
fn parse_bytes(
    buf: &[u8],
    pos: &mut usize,
    start: usize,
    ai: u8,
) -> Result<(ValueKind, bool), Diag> {
    let (data, indefinite) = read_bytes(buf, pos, start, ai)?;
    Ok((
        ValueKind::Bytes {
            data,
            decoded: None,
        },
        indefinite,
    ))
}

/// A byte string's content (chunks concatenated) and whether it was indefinite.
fn read_bytes(buf: &[u8], pos: &mut usize, start: usize, ai: u8) -> Result<(Vec<u8>, bool), Diag> {
    let mut data = Vec::new();
    let indefinite;
    if ai == 31 {
        indefinite = true;
        loop {
            let chunk = *pos;
            let h = read_u8(buf, pos, chunk)?;
            if h == 0xff {
                break;
            }
            let cai = h & 0x1f;
            if h >> 5 != 2 || cai == 31 {
                return Err(invalid(
                    chunk,
                    "an indefinite byte-string chunk must be a definite byte string",
                ));
            }
            let n = definite_len(buf, pos, chunk, cai)?;
            data.extend_from_slice(take(buf, pos, n, chunk)?);
        }
    } else {
        indefinite = false;
        let n = definite_len(buf, pos, start, ai)?;
        data.extend_from_slice(take(buf, pos, n, start)?);
    }
    Ok((data, indefinite))
}

fn parse_text(buf: &[u8], pos: &mut usize, start: usize, ai: u8) -> Result<(String, bool), Diag> {
    if ai == 31 {
        let mut bytes = Vec::new();
        loop {
            let chunk = *pos;
            let h = read_u8(buf, pos, chunk)?;
            if h == 0xff {
                break;
            }
            let cai = h & 0x1f;
            if h >> 5 != 3 || cai == 31 {
                return Err(invalid(
                    chunk,
                    "an indefinite text-string chunk must be a definite text string",
                ));
            }
            let n = definite_len(buf, pos, chunk, cai)?;
            bytes.extend_from_slice(take(buf, pos, n, chunk)?);
        }
        let text = String::from_utf8(bytes).map_err(|_| bad_utf8(start))?;
        Ok((text, true))
    } else {
        let n = definite_len(buf, pos, start, ai)?;
        let content = *pos;
        let b = take(buf, pos, n, start)?;
        let text = std::str::from_utf8(b)
            .map_err(|_| bad_utf8(content))?
            .to_string();
        Ok((text, false))
    }
}

fn parse_array(
    buf: &[u8],
    pos: &mut usize,
    start: usize,
    ai: u8,
    nest: usize,
) -> Result<(Vec<Value>, bool), Diag> {
    let mut items = Vec::new();
    if ai == 31 {
        loop {
            let peek = *pos;
            let h = read_u8(buf, pos, peek)?;
            if h == 0xff {
                return Ok((items, true));
            }
            *pos = peek;
            items.push(parse_one(buf, pos, nest + 1)?);
        }
    } else {
        let n = definite_len(buf, pos, start, ai)?;
        if n > buf.len() - *pos {
            return Err(truncated(start));
        }
        for _ in 0..n {
            items.push(parse_one(buf, pos, nest + 1)?);
        }
        Ok((items, false))
    }
}

fn parse_map(
    buf: &[u8],
    pos: &mut usize,
    start: usize,
    ai: u8,
    nest: usize,
) -> Result<(Vec<(Value, Value)>, bool), Diag> {
    let mut entries = Vec::new();
    if ai == 31 {
        loop {
            let peek = *pos;
            let h = read_u8(buf, pos, peek)?;
            if h == 0xff {
                return Ok((entries, true));
            }
            *pos = peek;
            let k = parse_one(buf, pos, nest + 1)?;
            let v = parse_one(buf, pos, nest + 1)?;
            entries.push((k, v));
        }
    } else {
        let n = definite_len(buf, pos, start, ai)?;
        if n > (buf.len() - *pos) / 2 {
            return Err(truncated(start));
        }
        for _ in 0..n {
            let k = parse_one(buf, pos, nest + 1)?;
            let v = parse_one(buf, pos, nest + 1)?;
            entries.push((k, v));
        }
        Ok((entries, false))
    }
}

fn parse_simple(buf: &[u8], pos: &mut usize, start: usize, ai: u8) -> Result<ValueKind, Diag> {
    Ok(match ai {
        0..=19 => ValueKind::Simple(ai),
        20 => ValueKind::Bool(false),
        21 => ValueKind::Bool(true),
        22 => ValueKind::Null,
        23 => ValueKind::Undefined,
        24 => {
            let b = read_u8(buf, pos, start)?;
            if b < 32 {
                return Err(reserved(start));
            }
            ValueKind::Simple(b)
        }
        25 => ValueKind::Float {
            value: f16_to_f64(read_be(buf, pos, 2, start)? as u16),
            width: 16,
        },
        26 => ValueKind::Float {
            value: f64::from(f32::from_bits(read_be(buf, pos, 4, start)? as u32)),
            width: 32,
        },
        27 => ValueKind::Float {
            value: f64::from_bits(read_be(buf, pos, 8, start)?),
            width: 64,
        },
        28..=30 => return Err(reserved(start)),
        _ => return Err(unexpected_break(start)),
    })
}

/// Decode a tag-24 byte-string payload as CBOR only, bounded by `--depth`.
///
/// `depth` is the payload buffer's own depth; its byte strings are then one
/// level deeper. Nested detection runs once, during enrichment.
pub(crate) fn embedded(buf: &[u8], depth: usize, opts: &Options) -> Option<Node> {
    if depth >= opts.depth {
        return None;
    }
    let mut items = parse_sequence(buf).ok()?;
    if items.is_empty() {
        return None;
    }
    detect::enrich_values(&mut items, depth, opts);
    Some(node(items, 1.0, buf.len()))
}

/// IEEE 754 half-precision to double.
fn f16_to_f64(bits: u16) -> f64 {
    let sign = u32::from(bits >> 15);
    let exp = u32::from((bits >> 10) & 0x1f);
    let mant = u32::from(bits & 0x3ff);
    let value = if exp == 0 {
        // subnormal (mant == 0 is signed zero)
        (f64::from(mant) / 1024.0) * 2f64.powi(-14)
    } else if exp == 31 {
        if mant == 0 {
            f64::INFINITY
        } else {
            return f64::NAN;
        }
    } else {
        (1.0 + f64::from(mant) / 1024.0) * 2f64.powi(exp as i32 - 15)
    };
    if sign == 1 { -value } else { value }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn halves() {
        assert_eq!(f16_to_f64(0x0000), 0.0);
        assert!(f16_to_f64(0x8000).is_sign_negative());
        assert_eq!(f16_to_f64(0x3c00), 1.0);
        assert_eq!(f16_to_f64(0x7bff), 65504.0);
        assert_eq!(f16_to_f64(0x0001), 5.960_464_477_539_063e-8);
        assert_eq!(f16_to_f64(0x7c00), f64::INFINITY);
        assert!(f16_to_f64(0x7e00).is_nan());
    }
}
