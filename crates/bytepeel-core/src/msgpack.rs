//! MessagePack: a schemaless parser into the shared [`Value`] tree.
//!
//! Integer negatives map to `ValueKind::Nint` (`-1 - n`), strings must be
//! valid UTF-8, and extension values become `ValueKind::Ext`. Parsing is
//! structural; a `bin` value's nested `decoded` node is filled later by
//! [`crate::detect::enrich_values`]. Reserved `0xc1`, truncation and deep
//! nesting are hard errors when the format is forced.

use crate::Diag;
use crate::node::{Codec, Detail, Node};
use crate::value::{self, Value, ValueKind};

/// Hard recursion cap, independent of `Options::depth`.
const MAX_NEST: usize = 100;

fn truncated(at: usize) -> Diag {
    Diag::new(
        "MSGPACK_TRUNCATED",
        "MessagePack item runs past the end of the buffer",
        Some(at),
    )
}

fn reserved(at: usize) -> Diag {
    Diag::new(
        "MSGPACK_RESERVED",
        "reserved MessagePack byte 0xc1",
        Some(at),
    )
}

fn bad_utf8(at: usize) -> Diag {
    Diag::new(
        "MSGPACK_BAD_UTF8",
        "MessagePack string is not valid UTF-8",
        Some(at),
    )
}

fn too_deep(at: usize) -> Diag {
    Diag::new(
        "NESTING_TOO_DEEP",
        format!("more than {MAX_NEST} nested MessagePack items"),
        Some(at),
    )
}

/// Parse `buf` as a MessagePack sequence covering the whole buffer. This is
/// structural only: `bin` values get `decoded: None`. Run
/// [`crate::detect::enrich_values`] afterwards to fill nested nodes once.
pub(crate) fn parse_sequence(buf: &[u8]) -> Result<Vec<Value>, Diag> {
    let mut pos = 0;
    let mut items = Vec::new();
    while pos < buf.len() {
        items.push(parse_one(buf, &mut pos, 0)?);
    }
    Ok(items)
}

/// Auto-detection: exactly one item covering the whole buffer whose top level
/// is a map or array.
pub(crate) fn detect(buf: &[u8]) -> Option<(Vec<Value>, f64, bool)> {
    if buf.len() < 2 {
        return None;
    }
    // Exactly one item: parse it and stop, rather than parsing the whole
    // buffer as a sequence (millions of one-byte items for zeros) to count.
    let mut pos = 0;
    let item = parse_one(buf, &mut pos, 0).ok()?;
    if pos != buf.len() {
        return None;
    }
    let items = vec![item];
    match &items[0].kind {
        ValueKind::Map(_) | ValueKind::Array(_) => {
            let conf = value::structure_confidence(&items, 127, 31);
            let text_keys = value::keys_all_text(&items);
            Some((items, conf, text_keys))
        }
        _ => None,
    }
}

/// Build the MessagePack node for a parsed sequence.
pub(crate) fn node(items: Vec<Value>, confidence: f64, len: usize) -> Node {
    Node {
        codec: Codec::Msgpack,
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

fn read_len_u8(buf: &[u8], pos: &mut usize, at: usize) -> Result<usize, Diag> {
    Ok(usize::from(read_u8(buf, pos, at)?))
}

fn read_len_u16(buf: &[u8], pos: &mut usize, at: usize) -> Result<usize, Diag> {
    Ok(read_be(buf, pos, 2, at)? as usize)
}

fn read_len_u32(buf: &[u8], pos: &mut usize, at: usize) -> Result<usize, Diag> {
    usize::try_from(read_be(buf, pos, 4, at)?).map_err(|_| truncated(at))
}

/// Read a length whose width (1, 2 or 4 bytes) depends on the type byte.
fn read_len(buf: &[u8], pos: &mut usize, at: usize, width: u8) -> Result<usize, Diag> {
    match width {
        1 => read_len_u8(buf, pos, at),
        2 => read_len_u16(buf, pos, at),
        _ => read_len_u32(buf, pos, at),
    }
}

fn read_bin_at(buf: &[u8], pos: &mut usize, at: usize, width: u8) -> Result<ValueKind, Diag> {
    let n = read_len(buf, pos, at, width)?;
    read_bin(buf, pos, at, n)
}

fn read_ext_at(buf: &[u8], pos: &mut usize, at: usize, width: u8) -> Result<ValueKind, Diag> {
    let n = read_len(buf, pos, at, width)?;
    read_ext(buf, pos, at, n)
}

fn read_text_at(buf: &[u8], pos: &mut usize, at: usize, width: u8) -> Result<String, Diag> {
    let n = read_len(buf, pos, at, width)?;
    read_text(buf, pos, at, n)
}

fn parse_items_at(
    buf: &[u8],
    pos: &mut usize,
    start: usize,
    width: u8,
    nest: usize,
) -> Result<Vec<Value>, Diag> {
    let n = read_len(buf, pos, start, width)?;
    parse_items(buf, pos, start, n, nest)
}

fn parse_pairs_at(
    buf: &[u8],
    pos: &mut usize,
    start: usize,
    width: u8,
    nest: usize,
) -> Result<Vec<(Value, Value)>, Diag> {
    let n = read_len(buf, pos, start, width)?;
    parse_pairs(buf, pos, start, n, nest)
}

/// Read `n` raw bytes, checking the length before allocating.
fn read_n(buf: &[u8], pos: &mut usize, at: usize, n: usize) -> Result<Vec<u8>, Diag> {
    Ok(take(buf, pos, n, at)?.to_vec())
}

fn read_text(buf: &[u8], pos: &mut usize, at: usize, n: usize) -> Result<String, Diag> {
    let content = *pos;
    let s = take(buf, pos, n, at)?;
    std::str::from_utf8(s)
        .map_err(|_| bad_utf8(content))
        .map(str::to_string)
}

/// A `bin` value, structurally: `decoded` is filled later by
/// [`crate::detect::enrich_values`].
fn read_bin(buf: &[u8], pos: &mut usize, at: usize, n: usize) -> Result<ValueKind, Diag> {
    let data = read_n(buf, pos, at, n)?;
    Ok(ValueKind::Bytes {
        data,
        decoded: None,
    })
}

fn read_ext(buf: &[u8], pos: &mut usize, at: usize, n: usize) -> Result<ValueKind, Diag> {
    let type_ = read_u8(buf, pos, at)? as i8;
    let data = read_n(buf, pos, at, n)?;
    Ok(ValueKind::Ext { type_, data })
}

fn int_kind(v: i64) -> ValueKind {
    if v < 0 {
        ValueKind::Nint((-1 - v) as u64)
    } else {
        ValueKind::Uint(v as u64)
    }
}

fn parse_items(
    buf: &[u8],
    pos: &mut usize,
    start: usize,
    n: usize,
    nest: usize,
) -> Result<Vec<Value>, Diag> {
    // Every item needs at least one byte, so a huge count fails immediately.
    if n > buf.len() - *pos {
        return Err(truncated(start));
    }
    let mut items = Vec::new();
    for _ in 0..n {
        items.push(parse_one(buf, pos, nest + 1)?);
    }
    Ok(items)
}

fn parse_pairs(
    buf: &[u8],
    pos: &mut usize,
    start: usize,
    n: usize,
    nest: usize,
) -> Result<Vec<(Value, Value)>, Diag> {
    if n > (buf.len() - *pos) / 2 {
        return Err(truncated(start));
    }
    let mut entries = Vec::new();
    for _ in 0..n {
        let k = parse_one(buf, pos, nest + 1)?;
        let v = parse_one(buf, pos, nest + 1)?;
        entries.push((k, v));
    }
    Ok(entries)
}

fn parse_one(buf: &[u8], pos: &mut usize, nest: usize) -> Result<Value, Diag> {
    if nest > MAX_NEST {
        return Err(too_deep(*pos));
    }
    crate::limits::charge(*pos)?;
    let start = *pos;
    let b = read_u8(buf, pos, start)?;
    let kind = match b {
        0x00..=0x7f => ValueKind::Uint(u64::from(b)),
        0x80..=0x8f => ValueKind::Map(parse_pairs(buf, pos, start, usize::from(b & 0x0f), nest)?),
        0x90..=0x9f => ValueKind::Array(parse_items(buf, pos, start, usize::from(b & 0x0f), nest)?),
        0xa0..=0xbf => ValueKind::Text(read_text(buf, pos, start, usize::from(b & 0x1f))?),
        0xc0 => ValueKind::Null,
        0xc1 => return Err(reserved(start)),
        0xc2 => ValueKind::Bool(false),
        0xc3 => ValueKind::Bool(true),
        0xc4 => read_bin_at(buf, pos, start, 1)?,
        0xc5 => read_bin_at(buf, pos, start, 2)?,
        0xc6 => read_bin_at(buf, pos, start, 4)?,
        0xc7 => read_ext_at(buf, pos, start, 1)?,
        0xc8 => read_ext_at(buf, pos, start, 2)?,
        0xc9 => read_ext_at(buf, pos, start, 4)?,
        0xca => ValueKind::Float {
            value: f64::from(f32::from_bits(read_be(buf, pos, 4, start)? as u32)),
            width: 32,
        },
        0xcb => ValueKind::Float {
            value: f64::from_bits(read_be(buf, pos, 8, start)?),
            width: 64,
        },
        0xcc => ValueKind::Uint(read_be(buf, pos, 1, start)?),
        0xcd => ValueKind::Uint(read_be(buf, pos, 2, start)?),
        0xce => ValueKind::Uint(read_be(buf, pos, 4, start)?),
        0xcf => ValueKind::Uint(read_be(buf, pos, 8, start)?),
        0xd0 => int_kind(i64::from(read_u8(buf, pos, start)? as i8)),
        0xd1 => int_kind(i64::from(read_be(buf, pos, 2, start)? as u16 as i16)),
        0xd2 => int_kind(i64::from(read_be(buf, pos, 4, start)? as u32 as i32)),
        0xd3 => int_kind(read_be(buf, pos, 8, start)? as i64),
        0xd4 => read_ext(buf, pos, start, 1)?,
        0xd5 => read_ext(buf, pos, start, 2)?,
        0xd6 => read_ext(buf, pos, start, 4)?,
        0xd7 => read_ext(buf, pos, start, 8)?,
        0xd8 => read_ext(buf, pos, start, 16)?,
        0xd9 => ValueKind::Text(read_text_at(buf, pos, start, 1)?),
        0xda => ValueKind::Text(read_text_at(buf, pos, start, 2)?),
        0xdb => ValueKind::Text(read_text_at(buf, pos, start, 4)?),
        0xdc => ValueKind::Array(parse_items_at(buf, pos, start, 2, nest)?),
        0xdd => ValueKind::Array(parse_items_at(buf, pos, start, 4, nest)?),
        0xde => ValueKind::Map(parse_pairs_at(buf, pos, start, 2, nest)?),
        0xdf => ValueKind::Map(parse_pairs_at(buf, pos, start, 4, nest)?),
        // Negative fixint: -32..=-1.
        0xe0..=0xff => int_kind(i64::from(b as i8)),
    };
    Ok(Value {
        range: [start, *pos],
        kind,
        indefinite: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_ints() {
        assert_eq!(int_kind(-1), ValueKind::Nint(0));
        assert_eq!(int_kind(-2), ValueKind::Nint(1));
        assert_eq!(int_kind(-128), ValueKind::Nint(127));
        assert_eq!(int_kind(i64::MIN), ValueKind::Nint(i64::MAX as u64));
        assert_eq!(int_kind(0), ValueKind::Uint(0));
        assert_eq!(int_kind(i64::MAX), ValueKind::Uint(i64::MAX as u64));
    }
}
