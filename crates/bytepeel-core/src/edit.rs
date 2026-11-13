//! Re-encoding: change one protobuf field and re-serialize every layer.
//!
//! Edits are byte-exact splices. Only the target field's payload changes;
//! the length prefixes of enclosing LEN fields are rewritten, and each outer
//! layer is re-encoded in its original style (see `reencode.rs`). Every other
//! byte is preserved, including field order, unknown fields and non-canonical
//! encodings elsewhere. The result is decoded again and checked before it is
//! returned.

use crate::node::{AltKind, Codec, Detail, Field, FieldValue, Node};
use crate::path::{message_fields, parse_path};
use crate::{Diag, Options, compress, reencode, text, varint};

/// A new value for a field, parsed from the CLI syntax (see [`parse_value`]).
#[derive(Debug, Clone, PartialEq)]
pub enum NewValue {
    /// A decimal integer: `42`, `-2`.
    Int(i128),
    /// A zigzag (sint32/sint64) integer: `sint:-2`.
    Sint(i64),
    /// A floating-point number: `1.5`, `float:1e-3`, `float:NaN`.
    Float(f64),
    Bool(bool),
    /// A UTF-8 string: `"text"` (JSON escapes) or `str:text`.
    Str(String),
    /// Raw bytes: `hex:0a0b`, `b64:CgM=`.
    Bytes(Vec<u8>),
}

fn bad_value(s: &str) -> Diag {
    Diag::new(
        "BAD_VALUE",
        format!(
            "cannot parse value '{s}'; use an integer (42, -2), sint:N, a float (1.5, float:NaN), \
             true/false, \"text\" or str:text, hex:.. or b64:.."
        ),
        None,
    )
}

/// Parse a value in the CLI syntax.
pub fn parse_value(s: &str) -> Result<NewValue, Diag> {
    if let Some(r) = s.strip_prefix("str:") {
        return Ok(NewValue::Str(r.to_string()));
    }
    if let Some(r) = s.strip_prefix("hex:") {
        return crate::decode_hex(r).map(NewValue::Bytes).or_else(|_| {
            if r.is_empty() {
                Ok(NewValue::Bytes(vec![]))
            } else {
                Err(bad_value(s))
            }
        });
    }
    if let Some(r) = s.strip_prefix("b64:") {
        if r.is_empty() {
            return Ok(NewValue::Bytes(vec![]));
        }
        return crate::decode_b64(r)
            .map(|b| NewValue::Bytes(b.bytes))
            .map_err(|_| bad_value(s));
    }
    if let Some(r) = s.strip_prefix("sint:") {
        return r
            .parse::<i64>()
            .map(NewValue::Sint)
            .map_err(|_| bad_value(s));
    }
    if let Some(r) = s.strip_prefix("float:") {
        return parse_float(r)
            .map(NewValue::Float)
            .ok_or_else(|| bad_value(s));
    }
    match s {
        "true" => return Ok(NewValue::Bool(true)),
        "false" => return Ok(NewValue::Bool(false)),
        _ => {}
    }
    if s.starts_with('"') {
        return json_string(s)
            .map(NewValue::Str)
            .ok_or_else(|| bad_value(s));
    }
    let digits = s.strip_prefix('-').unwrap_or(s);
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        return s
            .parse::<i128>()
            .map(NewValue::Int)
            .map_err(|_| bad_value(s));
    }
    if s.bytes().any(|b| b.is_ascii_digit()) {
        if let Some(f) = parse_float(s) {
            return Ok(NewValue::Float(f));
        }
    }
    Err(bad_value(s))
}

fn parse_float(s: &str) -> Option<f64> {
    match s {
        "NaN" | "nan" => Some(f64::NAN),
        "Infinity" | "inf" => Some(f64::INFINITY),
        "-Infinity" | "-inf" => Some(f64::NEG_INFINITY),
        _ if s
            .bytes()
            .all(|b| b.is_ascii_digit() || b"+-.eE".contains(&b)) =>
        {
            s.parse().ok()
        }
        _ => None,
    }
}

/// A JSON string literal (with escapes) to its value.
fn json_string(s: &str) -> Option<String> {
    let inner = s.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::new();
    let mut it = inner.chars();
    while let Some(c) = it.next() {
        match c {
            '"' => return None,
            '\\' => out.push(match it.next()? {
                '"' => '"',
                '\\' => '\\',
                '/' => '/',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'b' => '\u{8}',
                'f' => '\u{c}',
                'u' => {
                    let h: String = it.by_ref().take(4).collect();
                    let cp = u32::from_str_radix(&h, 16).ok()?;
                    char::from_u32(cp)?
                }
                _ => return None,
            }),
            c => out.push(c),
        }
    }
    Some(out)
}

/// Set the protobuf field at `path` (as for [`crate::select`]) to `value`,
/// re-encoding every enclosing layer. The output decodes (with the same
/// options) to a tree where `path` holds exactly the new value.
pub fn set(input: &[u8], opts: &Options, path: &str, value: &NewValue) -> Result<Vec<u8>, Diag> {
    let root = crate::peel(input, opts)?;
    // Validates the path and gives the same errors as --get.
    let target = crate::select(&root, path)?;
    let expected = encode_payload(target, value)?;
    let segs = parse_path(path)?;
    let out = rebuild(&root, input, &segs, value)?;

    let again = crate::peel(&out, opts)
        .map_err(|e| verify_failed(&format!("{}: {}", e.code, e.message)))?;
    let f = crate::select(&again, path)
        .map_err(|e| verify_failed(&format!("{}: {}", e.code, e.message)))?;
    if f.payload().as_deref() != Some(&expected[..])
        || f.value.wire_name() != target.value.wire_name()
    {
        return Err(verify_failed("the field does not hold the new value"));
    }
    Ok(out)
}

fn verify_failed(why: &str) -> Diag {
    Diag::new(
        "REENCODE_VERIFY_FAILED",
        format!(
            "the re-encoded output does not decode back as expected ({why}); \
             pin the layers with --in/--as and try again"
        ),
        None,
    )
}

fn unsupported(what: impl Into<String>) -> Diag {
    Diag::new("REENCODE_UNSUPPORTED", what, None)
}

/// Re-encode `node` (parsed from `buf`) with the field at `segs` changed.
fn rebuild(node: &Node, buf: &[u8], segs: &[(u32, usize)], v: &NewValue) -> Result<Vec<u8>, Diag> {
    match &node.detail {
        Detail::Message { fields } => {
            let mut out = Vec::with_capacity(buf.len());
            edit_fields(buf, [0, buf.len()], fields, segs, v, &mut out)?;
            Ok(out)
        }
        Detail::Layer { decoded, child } => {
            let inner = rebuild(child, decoded, segs, v)?;
            encode_layer(&node.codec, buf, &inner)
        }
        Detail::Parts { .. } if matches!(node.codec, Codec::Jwt { .. }) => Err(unsupported(
            "editing a JWT would invalidate its signature; decode the part, edit it, and re-sign it",
        )),
        _ => Err(unsupported(format!(
            "re-encoding a {} layer is not supported yet",
            node.codec.name()
        ))),
    }
}

/// Re-encode a text or compression layer around its new decoded bytes.
fn encode_layer(codec: &Codec, orig: &[u8], inner: &[u8]) -> Result<Vec<u8>, Diag> {
    let text = || {
        std::str::from_utf8(orig).map_err(|_| unsupported("the layer's original text is not UTF-8"))
    };
    Ok(match codec {
        Codec::Hex => reencode::hex_like(text()?, inner).into_bytes(),
        Codec::Dump { style } => reencode::dump_like(text()?, style, inner).into_bytes(),
        Codec::Base64 { alphabet, padded } => {
            reencode::base64_like(text()?, *alphabet, *padded, inner).into_bytes()
        }
        Codec::Pem { label } => {
            let t = text()?;
            let range = match text::decode_pem(t) {
                Some(Ok(b)) if b.blocks.len() == 1 => b.blocks[0].range,
                _ => return Err(unsupported("could not locate the PEM block again")),
            };
            reencode::pem_like(t, range, label, inner)?.into_bytes()
        }
        Codec::Gzip { .. } => compress::recompress("gzip", orig, inner)?,
        Codec::Zlib => compress::recompress("zlib", orig, inner)?,
        Codec::Zstd => compress::recompress("zstd", orig, inner)?,
        c => {
            return Err(unsupported(format!(
                "re-encoding a {} layer is not supported yet",
                c.name()
            )));
        }
    })
}

/// Copy `buf[region]` to `out`, replacing the field selected by `segs`.
/// Field ranges are absolute in `buf` (nested messages share the buffer).
fn edit_fields(
    buf: &[u8],
    region: [usize; 2],
    fields: &[Field],
    segs: &[(u32, usize)],
    v: &NewValue,
    out: &mut Vec<u8>,
) -> Result<(), Diag> {
    let (num, idx) = segs[0];
    let f = fields
        .iter()
        .filter(|f| f.number == num)
        .nth(idx)
        .expect("path was validated by select");
    let [fs, fe] = f.range;
    let (_, tag_len) = varint::decode(&buf[fs..fe]).expect("parsed tag");
    let tag = &buf[fs..fs + tag_len];
    out.extend_from_slice(&buf[region[0]..fs]);
    out.extend_from_slice(tag);
    let rest = &segs[1..];
    match &f.value {
        _ if rest.is_empty() => {
            let payload = encode_payload(f, v)?;
            if matches!(f.value, FieldValue::Len { .. }) {
                out.extend_from_slice(&varint::encode(payload.len() as u64));
            }
            out.extend_from_slice(&payload);
        }
        FieldValue::Group { fields: inner } => {
            // Start tag, fields, end tag: only the fields change.
            let end_tag = varint::encode(u64::from(num) << 3 | 4).len();
            edit_fields(buf, [fs + tag_len, fe - end_tag], inner, rest, v, out)?;
            out.extend_from_slice(&buf[fe - end_tag..fe]);
        }
        FieldValue::Len {
            data_range, alts, ..
        } => {
            let [ds, de] = *data_range;
            // Enter the same interpretation as `select`: the first message
            // alt, or a string whose decoded layers end in a message.
            let mut inner = Vec::new();
            let mut entered = false;
            for a in alts {
                match &a.kind {
                    AltKind::Message(sub) => {
                        edit_fields(buf, [ds, de], sub, rest, v, &mut inner)?;
                        entered = true;
                    }
                    AltKind::String {
                        decoded: Some(n), ..
                    } if message_fields(n).is_some() => {
                        inner = rebuild(n, &buf[ds..de], rest, v)?;
                        entered = true;
                    }
                    _ => continue,
                }
                break;
            }
            if !entered {
                unreachable!("path was validated by select");
            }
            out.extend_from_slice(&varint::encode(inner.len() as u64));
            out.extend_from_slice(&inner);
        }
        _ => unreachable!("select only descends into LEN fields and groups"),
    }
    out.extend_from_slice(&buf[fe..region[1]]);
    Ok(())
}

fn mismatch(f: &Field, hint: &str) -> Diag {
    Diag::new(
        "TYPE_MISMATCH",
        format!("field {} is {}; {hint}", f.number, f.value.wire_name()),
        None,
    )
}

fn out_of_range(f: &Field, range: &str) -> Diag {
    Diag::new(
        "VALUE_OUT_OF_RANGE",
        format!(
            "field {} is {}: the value must be in {range}",
            f.number,
            f.value.wire_name()
        ),
        None,
    )
}

/// The new payload bytes for `f` (tag and LEN prefix excluded), in the
/// field's existing wire type.
fn encode_payload(f: &Field, v: &NewValue) -> Result<Vec<u8>, Diag> {
    match (&f.value, v) {
        (FieldValue::Varint { .. }, NewValue::Int(n)) => {
            if *n < i128::from(i64::MIN) || *n > i128::from(u64::MAX) {
                return Err(out_of_range(f, "[-2^63, 2^64)"));
            }
            // Negative values use the 10-byte two's complement form (int32/int64).
            Ok(varint::encode(if *n < 0 {
                *n as i64 as u64
            } else {
                *n as u64
            }))
        }
        (FieldValue::Varint { .. }, NewValue::Sint(n)) => {
            Ok(varint::encode(((*n << 1) ^ (*n >> 63)) as u64))
        }
        (FieldValue::Varint { .. }, NewValue::Bool(b)) => Ok(vec![u8::from(*b)]),
        (FieldValue::Varint { .. }, _) => Err(mismatch(f, "use an integer, sint:N or true/false")),
        (FieldValue::I64 { .. }, NewValue::Int(n)) => {
            if *n < i128::from(i64::MIN) || *n > i128::from(u64::MAX) {
                return Err(out_of_range(f, "[-2^63, 2^64)"));
            }
            Ok((*n as u64).to_le_bytes().to_vec())
        }
        (FieldValue::I64 { .. }, NewValue::Float(x)) => Ok(x.to_bits().to_le_bytes().to_vec()),
        (FieldValue::I32 { .. }, NewValue::Int(n)) => {
            if *n < i128::from(i32::MIN) || *n > i128::from(u32::MAX) {
                return Err(out_of_range(f, "[-2^31, 2^32)"));
            }
            Ok((*n as u32).to_le_bytes().to_vec())
        }
        (FieldValue::I32 { .. }, NewValue::Float(x)) => {
            let y = *x as f32;
            if x.is_finite() && !y.is_finite() {
                return Err(out_of_range(f, "the float32 range"));
            }
            Ok(y.to_bits().to_le_bytes().to_vec())
        }
        (FieldValue::I64 { .. } | FieldValue::I32 { .. }, _) => {
            Err(mismatch(f, "use an integer or a float"))
        }
        (FieldValue::Len { .. }, NewValue::Str(s)) => Ok(s.as_bytes().to_vec()),
        (FieldValue::Len { .. }, NewValue::Bytes(b)) => Ok(b.clone()),
        (FieldValue::Len { .. }, _) => Err(mismatch(
            f,
            "use \"text\", str:text, hex:.. or b64:.. (or a path into its message)",
        )),
        (FieldValue::Group { .. }, _) => Err(mismatch(f, "set one of its fields instead")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_syntax() {
        assert_eq!(parse_value("42").unwrap(), NewValue::Int(42));
        assert_eq!(parse_value("-2").unwrap(), NewValue::Int(-2));
        assert_eq!(parse_value("sint:-2").unwrap(), NewValue::Sint(-2));
        assert_eq!(parse_value("1.5").unwrap(), NewValue::Float(1.5));
        assert_eq!(parse_value("float:1").unwrap(), NewValue::Float(1.0));
        assert!(matches!(parse_value("float:NaN").unwrap(), NewValue::Float(x) if x.is_nan()));
        assert_eq!(parse_value("true").unwrap(), NewValue::Bool(true));
        assert_eq!(
            parse_value(r#""a\"bé""#).unwrap(),
            NewValue::Str("a\"bé".into())
        );
        assert_eq!(
            parse_value("str:hi there").unwrap(),
            NewValue::Str("hi there".into())
        );
        assert_eq!(
            parse_value("hex:0a0b").unwrap(),
            NewValue::Bytes(vec![10, 11])
        );
        assert_eq!(parse_value("hex:").unwrap(), NewValue::Bytes(vec![]));
        assert_eq!(
            parse_value("b64:CgM=").unwrap(),
            NewValue::Bytes(vec![10, 3])
        );
        for bad in ["", "hello", "\"unterminated", "hex:0g", "sint:x", "1.2.3x"] {
            assert_eq!(parse_value(bad).unwrap_err().code, "BAD_VALUE", "{bad}");
        }
    }
}
