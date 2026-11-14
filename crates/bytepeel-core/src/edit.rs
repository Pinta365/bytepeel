//! Re-encoding: change one protobuf field and re-serialize every layer.
//!
//! Edits are byte-exact splices. Only the target field's payload changes;
//! the length prefixes of enclosing LEN fields are rewritten, and each outer
//! layer is re-encoded in its original style (see `reencode.rs`). Every other
//! byte is preserved, including field order, unknown fields and non-canonical
//! encodings elsewhere. The result is decoded again and checked before it is
//! returned.

use crate::node::{AltKind, Asn1, Asn1Value, Codec, Detail, Field, FieldValue, Node, TagClass};
use crate::path::{
    bundle_parts, der_items, field_children, map_index, message_fields, parse_path, values_items,
};
use crate::value::{Value, ValueKind};
use crate::{Diag, Options, cbor, compress, der, encode_value, msgpack, reencode, text, varint};

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
    /// `null` (CBOR and MessagePack only).
    Null,
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
             true/false, null, \"text\" or str:text, hex:.. or b64:.."
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
        "null" => return Ok(NewValue::Null),
        _ => {}
    }
    if s.starts_with('"') {
        return json_string(s)
            .map(NewValue::Str)
            .ok_or_else(|| bad_value(s));
    }
    let digits = s
        .strip_prefix('-')
        .or_else(|| s.strip_prefix('+'))
        .unwrap_or(s);
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

/// One edit for [`edit`]. Paths are the `--get` paths of the decoded tree.
#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    /// Change the protobuf field, CBOR/MessagePack value or DER element at
    /// the path.
    Set(String, NewValue),
    /// Add: a protobuf field `PARENT.N` (appended to the parent message, or
    /// the top-level message for `N`), a CBOR/MessagePack map key or array
    /// index (inserted there; an index equal to the length appends), or a DER
    /// element index (inserted; the value is one complete element as
    /// `hex:`/`b64:`).
    Add(String, NewValue),
    /// Remove the field, value or element at the path.
    Del(String),
}

/// Set the field at `path` to `value`: `edit(input, opts, &Op::Set(..))`.
pub fn set(input: &[u8], opts: &Options, path: &str, value: &NewValue) -> Result<Vec<u8>, Diag> {
    edit(input, opts, &Op::Set(path.to_string(), value.clone()))
}

/// Apply one edit and re-encode every enclosing layer in its original style.
/// The output is decoded again with the same options and checked; the result
/// is returned only if it holds exactly the requested change.
pub fn edit(input: &[u8], opts: &Options, op: &Op) -> Result<Vec<u8>, Diag> {
    let root = crate::peel(input, opts)?;
    if crate::is_values(&root) {
        return values_op(&root, input, opts, op);
    }
    if crate::is_der(&root) {
        return der_op(&root, input, opts, op);
    }
    protobuf_op(&root, input, opts, op)
}

fn reparse(out: &[u8], opts: &Options) -> Result<Node, Diag> {
    crate::peel(out, opts).map_err(vf)
}

/// A selection error on the re-encoded output is a verification failure.
fn vf(e: Diag) -> Diag {
    verify_failed(&format!("{}: {}", e.code, e.message))
}

// ---------------------------------------------------------------- protobuf ops

fn protobuf_op(root: &Node, input: &[u8], opts: &Options, op: &Op) -> Result<Vec<u8>, Diag> {
    match op {
        Op::Set(path, value) => {
            // Validates the path and gives the same errors as --get.
            let target = crate::select(root, path)?;
            let expected = encode_payload(target, value)?;
            let segs = parse_path(path)?;
            let out = rebuild(
                root,
                input,
                &Edit::Field(&segs, &FieldAction::Replace(value)),
            )?;
            let again = reparse(&out, opts)?;
            let f = crate::select(&again, path).map_err(vf)?;
            if f.payload().as_deref() != Some(&expected[..])
                || f.value.wire_name() != target.value.wire_name()
            {
                return Err(verify_failed("the field does not hold the new value"));
            }
            Ok(out)
        }
        Op::Del(path) => {
            crate::select(root, path)?;
            let segs = parse_path(path)?;
            let (prefix, (num, _)) = (&segs[..segs.len() - 1], segs[segs.len() - 1]);
            let before = pb_count(root, prefix, num)?;
            let out = rebuild(root, input, &Edit::Field(&segs, &FieldAction::Delete))?;
            let again = reparse(&out, opts)?;
            if pb_count(&again, prefix, num).map_err(vf)? + 1 != before {
                return Err(verify_failed("the field was not removed"));
            }
            Ok(out)
        }
        Op::Add(path, value) => {
            if path.trim_end().ends_with(']') {
                return Err(Diag::new(
                    "BAD_PATH",
                    "an added field's path ends in its field number (e.g. 1.3), not an index",
                    None,
                ));
            }
            let segs = parse_path(path)?;
            let (prefix, (num, _)) = (&segs[..segs.len() - 1], segs[segs.len() - 1]);
            if num == 0 {
                return Err(Diag::new(
                    "FIELD_NUMBER_ZERO",
                    "field number 0 is invalid",
                    None,
                ));
            }
            if num > (1 << 29) - 1 {
                return Err(Diag::new(
                    "FIELD_NUMBER_TOO_LARGE",
                    "field numbers go up to 536870911",
                    None,
                ));
            }
            let before = pb_count(root, prefix, num)?;
            let (wire, payload) = new_field_payload(num, value)?;
            let mut bytes = varint::encode(u64::from(num) << 3 | wire);
            if wire == 2 {
                bytes.extend_from_slice(&varint::encode(payload.len() as u64));
            }
            bytes.extend_from_slice(&payload);
            let out = rebuild(
                root,
                input,
                &Edit::Field(prefix, &FieldAction::Append(&bytes)),
            )?;
            let again = reparse(&out, opts)?;
            let f = crate::select(&again, &format!("{path}[{before}]")).map_err(vf)?;
            let wire_name = ["VARINT", "I64", "LEN"][wire as usize];
            if f.payload().as_deref() != Some(&payload[..]) || f.value.wire_name() != wire_name {
                return Err(verify_failed("the new field does not hold the value"));
            }
            Ok(out)
        }
    }
}

/// The fields of the message at `prefix` (the top-level message when empty).
fn pb_children<'a>(root: &'a Node, prefix: &[(u32, usize)]) -> Result<&'a [Field], Diag> {
    if prefix.is_empty() {
        return message_fields(root).ok_or_else(|| {
            Diag::new(
                "PATH_NOT_MESSAGE",
                "the input did not decode to a protobuf message",
                None,
            )
        });
    }
    let p = prefix
        .iter()
        .map(|(n, i)| {
            if *i == 0 {
                n.to_string()
            } else {
                format!("{n}[{i}]")
            }
        })
        .collect::<Vec<_>>()
        .join(".");
    let f = crate::select(root, &p)?;
    field_children(f).ok_or_else(|| {
        Diag::new(
            "PATH_NOT_MESSAGE",
            format!("field at '{p}' is not a message"),
            None,
        )
    })
}

fn pb_count(root: &Node, prefix: &[(u32, usize)], num: u32) -> Result<usize, Diag> {
    Ok(pb_children(root, prefix)?
        .iter()
        .filter(|f| f.number == num)
        .count())
}

/// Wire type and payload of a new field: integers and bools are VARINT,
/// floats are I64 (double), strings and bytes are LEN.
fn new_field_payload(num: u32, v: &NewValue) -> Result<(u64, Vec<u8>), Diag> {
    Ok(match v {
        NewValue::Int(n) => {
            if *n < i128::from(i64::MIN) || *n > i128::from(u64::MAX) {
                return Err(Diag::new(
                    "VALUE_OUT_OF_RANGE",
                    "a VARINT must be in [-2^63, 2^64)",
                    None,
                ));
            }
            (
                0,
                varint::encode(if *n < 0 { *n as i64 as u64 } else { *n as u64 }),
            )
        }
        NewValue::Sint(n) => (0, varint::encode(((*n << 1) ^ (*n >> 63)) as u64)),
        NewValue::Bool(b) => (0, vec![u8::from(*b)]),
        NewValue::Float(x) => (1, x.to_bits().to_le_bytes().to_vec()),
        NewValue::Str(s) => (2, s.as_bytes().to_vec()),
        NewValue::Bytes(b) => (2, b.clone()),
        NewValue::Null => {
            return Err(Diag::new(
                "TYPE_MISMATCH",
                format!("field {num}: protobuf has no null; use --del to remove a field"),
                None,
            ));
        }
    })
}

// ---------------------------------------------------------------- CBOR/MessagePack ops

fn values_op(root: &Node, input: &[u8], opts: &Options, op: &Op) -> Result<Vec<u8>, Diag> {
    let codec = innermost(root).codec.clone();
    let vbuf = innermost_buf(root, input);
    let encode = |v: &NewValue, like: &ValueKind| match codec {
        Codec::Cbor => encode_value::cbor_scalar(v, like),
        _ => encode_value::msgpack_scalar(v, like),
    };
    let check_codec = |again: &Node| {
        if innermost(again).codec == codec {
            Ok(())
        } else {
            Err(verify_failed(&format!(
                "the data now decodes as {} instead of {}",
                innermost(again).codec.name(),
                codec.name()
            )))
        }
    };
    match op {
        Op::Set(path, value) => {
            // Validates the path with the same errors as --get.
            let target = crate::select_value(root, path)?.untagged();
            let item = encode(value, &target.kind)?;
            let expected = parse_one(&codec, &item)?;
            let out = rebuild(root, input, &Edit::Splices(&[(target.range, item)]))?;
            let again = reparse(&out, opts)?;
            check_codec(&again)?;
            let got = crate::select_value(&again, path).map_err(vf)?.untagged();
            if structural(got) != structural(&expected) {
                return Err(verify_failed("the value does not hold the new item"));
            }
            Ok(out)
        }
        Op::Del(path) => {
            crate::select_value(root, path)?;
            let (parent, last) = split_last(path);
            let c = container(root, parent)?;
            let (range, count) = match &c.kind {
                ValueKind::Array(items) => {
                    let i: usize = last.parse().expect("validated by select_value");
                    (items[i].range, items.len())
                }
                ValueKind::Map(entries) => {
                    let i = map_index(entries, last).expect("validated by select_value");
                    (
                        [entries[i].0.range[0], entries[i].1.range[1]],
                        entries.len(),
                    )
                }
                _ => unreachable!("container() returns maps and arrays"),
            };
            let mut splices: Vec<([usize; 2], Vec<u8>)> = header_splice(&codec, vbuf, c, count - 1)
                .into_iter()
                .collect();
            splices.push((range, vec![]));
            let out = rebuild(root, input, &Edit::Splices(&splices))?;
            let again = reparse(&out, opts)?;
            check_codec(&again)?;
            if container_len(container(&again, parent).map_err(vf)?) + 1 != count {
                return Err(verify_failed("the item was not removed"));
            }
            Ok(out)
        }
        Op::Add(path, value) => {
            let (parent, last) = split_last(path);
            let c = container(root, parent)?;
            let item = encode(value, &ValueKind::Null)?;
            let expected = parse_one(&codec, &item)?;
            let (pos, bytes, count) = match &c.kind {
                ValueKind::Map(entries) => {
                    if map_index(entries, last).is_some() {
                        return Err(Diag::new(
                            "ALREADY_EXISTS",
                            format!("key '{last}' already exists; use PATH=VALUE to change it"),
                            None,
                        ));
                    }
                    let mut bytes = encode(&NewValue::Str(last.to_string()), &ValueKind::Null)?;
                    bytes.extend_from_slice(&item);
                    let end = end_pos(c, entries.last().map(|e| e.1.range[1]));
                    (end, bytes, entries.len())
                }
                ValueKind::Array(items) => {
                    let i: usize = last.parse().map_err(|_| {
                        Diag::new("BAD_PATH", format!("'{last}' is not an array index"), None)
                    })?;
                    if i > items.len() {
                        return Err(Diag::new(
                            "PATH_NOT_FOUND",
                            format!(
                                "index {i} is past the end (the array has {} items)",
                                items.len()
                            ),
                            None,
                        ));
                    }
                    let pos = match items.get(i) {
                        Some(v) => v.range[0],
                        None => end_pos(c, items.last().map(|v| v.range[1])),
                    };
                    (pos, item.clone(), items.len())
                }
                _ => unreachable!("container() returns maps and arrays"),
            };
            let mut splices: Vec<([usize; 2], Vec<u8>)> = header_splice(&codec, vbuf, c, count + 1)
                .into_iter()
                .collect();
            splices.push(([pos, pos], bytes));
            let out = rebuild(root, input, &Edit::Splices(&splices))?;
            let again = reparse(&out, opts)?;
            check_codec(&again)?;
            let got = crate::select_value(&again, path).map_err(vf)?.untagged();
            if structural(got) != structural(&expected)
                || container_len(container(&again, parent).map_err(vf)?) != count + 1
            {
                return Err(verify_failed("the new item is not where it should be"));
            }
            Ok(out)
        }
    }
}

/// `a.b.c` -> (`a.b`, `c`); `c` -> (``, `c`).
fn split_last(path: &str) -> (&str, &str) {
    path.rsplit_once('.').unwrap_or(("", path))
}

/// The map or array at `parent` (the single top-level item when empty),
/// with tags followed.
fn container<'a>(root: &'a Node, parent: &str) -> Result<&'a Value, Diag> {
    let v = if parent.is_empty() {
        match values_items(root) {
            Some([only]) => only,
            _ => {
                return Err(unsupported(
                    "adding or removing top-level items of a multi-item sequence is not supported",
                ));
            }
        }
    } else {
        crate::select_value(root, parent)?
    }
    .untagged();
    match v.kind {
        ValueKind::Array(_) | ValueKind::Map(_) => Ok(v),
        _ => Err(Diag::new(
            "PATH_NOT_MESSAGE",
            format!("'{parent}' is not a map or array"),
            None,
        )),
    }
}

fn container_len(c: &Value) -> usize {
    match &c.kind {
        ValueKind::Array(items) => items.len(),
        ValueKind::Map(entries) => entries.len(),
        _ => 0,
    }
}

/// Where a new item goes after the last one: after `last_end`, or for an
/// empty container right after the header (definite) / before the break
/// byte (indefinite).
fn end_pos(c: &Value, last_end: Option<usize>) -> usize {
    match last_end {
        Some(e) => e,
        None if c.indefinite => c.range[1] - 1,
        None => c.range[1],
    }
}

/// Rewrite a definite container's header for `n` items. Indefinite (CBOR)
/// containers have no count.
fn header_splice(codec: &Codec, buf: &[u8], c: &Value, n: usize) -> Option<([usize; 2], Vec<u8>)> {
    if c.indefinite {
        return None;
    }
    let s = c.range[0];
    let map = matches!(c.kind, ValueKind::Map(_));
    let (len, head) = match codec {
        Codec::Cbor => {
            let len = match buf[s] & 0x1f {
                24 => 2,
                25 => 3,
                26 => 5,
                27 => 9,
                _ => 1,
            };
            let mut head = Vec::new();
            encode_value::cbor_head(if map { 5 } else { 4 }, n as u64, &mut head);
            (len, head)
        }
        _ => {
            let len = match buf[s] {
                0xdc | 0xde => 3,
                0xdd | 0xdf => 5,
                _ => 1,
            };
            (len, encode_value::msgpack_container_head(map, n as u64))
        }
    };
    Some(([s, s + len], head))
}

/// The decoded buffer of the innermost layer (what value ranges index).
fn innermost_buf<'a>(node: &'a Node, buf: &'a [u8]) -> &'a [u8] {
    match &node.detail {
        Detail::Layer { decoded, child } => innermost_buf(child, decoded),
        _ => buf,
    }
}

/// The node at the end of the layer chain.
fn innermost(node: &Node) -> &Node {
    match &node.detail {
        Detail::Layer { child, .. } => innermost(child),
        _ => node,
    }
}

/// Decode exactly one item of `codec` from `bytes`.
fn parse_one(codec: &Codec, bytes: &[u8]) -> Result<Value, Diag> {
    let items = match codec {
        Codec::Cbor => cbor::parse_sequence(bytes)?,
        _ => msgpack::parse_sequence(bytes)?,
    };
    items
        .into_iter()
        .next()
        .ok_or_else(|| verify_failed("the encoder produced no item"))
}

/// A value's kind with ranges and nested detection stripped, for comparison.
fn structural(v: &Value) -> ValueKind {
    match &v.kind {
        ValueKind::Bytes { data, .. } => ValueKind::Bytes {
            data: data.clone(),
            decoded: None,
        },
        ValueKind::Float { value, width } => ValueKind::Float {
            // Compare bit patterns so NaN equals NaN.
            value: f64::from_bits(value.to_bits()),
            width: *width,
        },
        k => k.clone(),
    }
}

// ---------------------------------------------------------------- rebuilding

/// What to change, carried down through the layers.
enum Edit<'a> {
    /// A protobuf edit: the path to the field (replace/delete) or to the
    /// parent message (append; empty = top level).
    Field(&'a [(u32, usize)], &'a FieldAction<'a>),
    /// CBOR/MessagePack: sorted, non-overlapping byte replacements in the
    /// value buffer.
    Splices(&'a [([usize; 2], Vec<u8>)]),
    /// DER: a child-index path (the first index picks a PEM bundle's block).
    Der(&'a [usize], &'a DerAction<'a>),
}

enum FieldAction<'a> {
    Replace(&'a NewValue),
    Delete,
    /// Encoded field bytes (tag included) to append.
    Append(&'a [u8]),
}

enum DerAction<'a> {
    /// A complete new element.
    Replace(&'a [u8]),
    Delete,
    /// A complete element, inserted before the index (or appended at the end).
    Insert(&'a [u8]),
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

/// Re-encode `node` (parsed from `buf`) with `edit` applied.
fn rebuild(node: &Node, buf: &[u8], edit: &Edit<'_>) -> Result<Vec<u8>, Diag> {
    match (&node.detail, edit) {
        (Detail::Message { fields }, Edit::Field(segs, action)) => {
            let mut out = Vec::with_capacity(buf.len());
            edit_fields(buf, [0, buf.len()], fields, segs, action, &mut out)?;
            Ok(out)
        }
        (Detail::Values { .. }, Edit::Splices(splices)) => {
            let mut out = Vec::with_capacity(buf.len());
            let mut at = 0;
            for ([s, e], bytes) in splices.iter() {
                out.extend_from_slice(&buf[at..*s]);
                out.extend_from_slice(bytes);
                at = *e;
            }
            out.extend_from_slice(&buf[at..]);
            Ok(out)
        }
        (Detail::Der { items }, Edit::Der(segs, action)) => {
            let mut out = Vec::with_capacity(buf.len());
            der_splice(buf, [0, buf.len()], items, segs, action, &mut out);
            Ok(out)
        }
        (Detail::Parts { parts, .. }, Edit::Der(segs, action)) if node.codec == Codec::Bundle => {
            // The first index picks the block; only that block is re-encoded.
            let part = &parts[segs[0]];
            let (Codec::Pem { label }, Detail::Layer { decoded, child }) =
                (&part.codec, &part.detail)
            else {
                return Err(unsupported("a bundle part is not a PEM block"));
            };
            let der = rebuild(child, decoded, &Edit::Der(&segs[1..], action))?;
            let t = std::str::from_utf8(buf)
                .map_err(|_| unsupported("the bundle's original text is not UTF-8"))?;
            Ok(reencode::pem_like(t, part.range, label, &der)?.into_bytes())
        }
        (Detail::Layer { decoded, child }, _) => {
            let inner = rebuild(child, decoded, edit)?;
            encode_layer(&node.codec, buf, &inner)
        }
        (Detail::Parts { .. }, _) if matches!(node.codec, Codec::Jwt { .. }) => Err(unsupported(
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
        Codec::Dump { style, start } => {
            reencode::dump_like(text()?, style, *start, inner).into_bytes()
        }
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

/// Copy `buf[region]` to `out`, applying `action` at `segs`. Field ranges
/// are absolute in `buf` (nested messages share the buffer). For an append,
/// `segs` is the parent message's path and may be empty.
fn edit_fields(
    buf: &[u8],
    region: [usize; 2],
    fields: &[Field],
    segs: &[(u32, usize)],
    action: &FieldAction<'_>,
    out: &mut Vec<u8>,
) -> Result<(), Diag> {
    let Some(&(num, idx)) = segs.first() else {
        // The target message itself: only reached for an append.
        out.extend_from_slice(&buf[region[0]..region[1]]);
        if let FieldAction::Append(bytes) = action {
            out.extend_from_slice(bytes);
        }
        return Ok(());
    };
    let f = fields
        .iter()
        .filter(|f| f.number == num)
        .nth(idx)
        .expect("path was validated by select");
    let [fs, fe] = f.range;
    let (_, tag_len) = varint::decode(&buf[fs..fe]).expect("parsed tag");
    let tag = &buf[fs..fs + tag_len];
    out.extend_from_slice(&buf[region[0]..fs]);
    let rest = &segs[1..];
    match (&f.value, action) {
        (_, FieldAction::Delete) if rest.is_empty() => {}
        (_, FieldAction::Replace(v)) if rest.is_empty() => {
            let payload = encode_payload(f, v)?;
            out.extend_from_slice(tag);
            if matches!(f.value, FieldValue::Len { .. }) {
                out.extend_from_slice(&varint::encode(payload.len() as u64));
            }
            out.extend_from_slice(&payload);
        }
        (FieldValue::Group { fields: inner }, _) => {
            // Start tag, fields, end tag: only the fields change. The end tag
            // starts where the last inner field ends (it may be an overlong
            // varint, so its length cannot be derived from the number).
            let start = fs + tag_len;
            let end = inner.last().map_or(start, |f| f.range[1]);
            out.extend_from_slice(tag);
            edit_fields(buf, [start, end], inner, rest, action, out)?;
            out.extend_from_slice(&buf[end..fe]);
        }
        (
            FieldValue::Len {
                data_range, alts, ..
            },
            _,
        ) => {
            let [ds, de] = *data_range;
            // Enter the same interpretation as `select`: the first message
            // alt, or a string whose decoded layers end in a message.
            let mut inner = Vec::new();
            let mut entered = false;
            for a in alts {
                match &a.kind {
                    AltKind::Message(sub) => {
                        edit_fields(buf, [ds, de], sub, rest, action, &mut inner)?;
                        entered = true;
                    }
                    AltKind::String {
                        decoded: Some(n), ..
                    } if message_fields(n).is_some() => {
                        inner = rebuild(n, &buf[ds..de], &Edit::Field(rest, action))?;
                        entered = true;
                    }
                    // An empty LEN field is an empty message: fields can be
                    // added to it.
                    AltKind::Empty => {
                        edit_fields(buf, [ds, de], &[], rest, action, &mut inner)?;
                        entered = true;
                    }
                    _ => continue,
                }
                break;
            }
            if !entered {
                unreachable!("path was validated by select");
            }
            out.extend_from_slice(tag);
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

// ---------------------------------------------------------------- DER

/// Edits on DER. A changed element keeps its tag and its content is encoded
/// for its type; an added element is one complete element given as bytes.
/// The length of every enclosing element (including encapsulating BIT/OCTET
/// STRINGs) is rewritten.
fn der_op(root: &Node, input: &[u8], opts: &Options, op: &Op) -> Result<Vec<u8>, Diag> {
    let path = match op {
        Op::Set(p, _) | Op::Add(p, _) | Op::Del(p) => p,
    };
    let segs: Vec<usize> = path
        .split('.')
        .map(|p| {
            p.parse().map_err(|_| {
                Diag::new(
                    "BAD_PATH",
                    format!("invalid path segment '{p}' (DER paths are child indices, e.g. 0.0.6)"),
                    None,
                )
            })
        })
        .collect::<Result<_, _>>()?;
    let prefix = &segs[..segs.len() - 1];
    let need_der = |again: &Node| {
        if crate::is_der(again) {
            Ok(())
        } else {
            Err(verify_failed("the data no longer decodes as DER"))
        }
    };
    match op {
        Op::Set(_, value) => {
            let target = crate::select_der(root, path)?;
            let content = der_content(target, value)?;
            let mut elem = der_tag_bytes(target, input_for(root, input, target)).to_vec();
            elem.extend_from_slice(&der_length(content.len()));
            elem.extend_from_slice(&content);
            let out = rebuild(root, input, &Edit::Der(&segs, &DerAction::Replace(&elem)))?;
            let again = reparse(&out, opts)?;
            need_der(&again)?;
            let got = crate::select_der(&again, path).map_err(vf)?;
            let bit_string = target.class == TagClass::Universal && target.number == 3;
            let expected = if bit_string {
                &content[1..]
            } else {
                &content[..]
            };
            if (got.class, got.number, got.constructed) != (target.class, target.number, false)
                || got.payload().as_deref() != Some(expected)
            {
                return Err(verify_failed("the element does not hold the new value"));
            }
            Ok(out)
        }
        Op::Del(_) => {
            crate::select_der(root, path)?;
            let before = der_children(root, prefix)?.len();
            let out = rebuild(root, input, &Edit::Der(&segs, &DerAction::Delete))?;
            let again = reparse(&out, opts)?;
            need_der(&again)?;
            if der_children(&again, prefix).map_err(vf)?.len() + 1 != before {
                return Err(verify_failed("the element was not removed"));
            }
            Ok(out)
        }
        Op::Add(_, value) => {
            let before = der_children(root, prefix)?.len();
            let idx = segs[segs.len() - 1];
            if idx > before {
                return Err(Diag::new(
                    "PATH_NOT_FOUND",
                    format!("index {idx} is past the end (there are {before} elements)"),
                    None,
                ));
            }
            let NewValue::Bytes(elem) = value else {
                return Err(Diag::new(
                    "TYPE_MISMATCH",
                    "an added DER element is one complete element as hex:.. or b64:.. (e.g. hex:020105)",
                    None,
                ));
            };
            let mut st = der::Stats::default();
            let parsed = match der::parse(elem, &mut st) {
                Ok(items) if items.len() == 1 => items.into_iter().next().expect("one item"),
                _ => {
                    return Err(Diag::new(
                        "BAD_VALUE",
                        "the added bytes are not exactly one complete DER element",
                        None,
                    ));
                }
            };
            let out = rebuild(root, input, &Edit::Der(&segs, &DerAction::Insert(elem)))?;
            let again = reparse(&out, opts)?;
            need_der(&again)?;
            let got = crate::select_der(&again, path).map_err(vf)?;
            if (got.class, got.number, got.constructed, got.payload())
                != (
                    parsed.class,
                    parsed.number,
                    parsed.constructed,
                    parsed.payload(),
                )
                || der_children(&again, prefix).map_err(vf)?.len() != before + 1
            {
                return Err(verify_failed("the new element is not where it should be"));
            }
            Ok(out)
        }
    }
}

/// The elements under `prefix`: the top-level elements when it is empty (for
/// a PEM bundle, the first index picks the block).
fn der_children<'a>(root: &'a Node, prefix: &[usize]) -> Result<&'a [Asn1], Diag> {
    let (mut items, rest) = match bundle_parts(root) {
        Some(parts) => {
            let Some((&block, rest)) = prefix.split_first() else {
                return Err(unsupported(
                    "adding or removing whole PEM blocks is not supported",
                ));
            };
            let part = parts.get(block).ok_or_else(|| {
                Diag::new("PATH_NOT_FOUND", format!("no bundle block {block}"), None)
            })?;
            let items = der_items(part).ok_or_else(|| {
                Diag::new(
                    "PATH_NOT_MESSAGE",
                    format!("bundle block {block} is not DER"),
                    None,
                )
            })?;
            (items, rest)
        }
        None => (
            der_items(root).ok_or_else(|| {
                Diag::new("PATH_NOT_MESSAGE", "the input did not decode to DER", None)
            })?,
            prefix,
        ),
    };
    for &i in rest {
        let e = items
            .get(i)
            .ok_or_else(|| Diag::new("PATH_NOT_FOUND", format!("no element at index {i}"), None))?;
        items = e.children().ok_or_else(|| {
            Diag::new(
                "PATH_NOT_MESSAGE",
                format!("element {} has no children", e.tag_name()),
                None,
            )
        })?;
    }
    Ok(items)
}

/// The DER buffer `target` was parsed from: the decoded bytes of the layer
/// (or bundle block) that holds it. Element ranges index into this buffer.
fn input_for<'a>(node: &'a Node, buf: &'a [u8], target: &Asn1) -> &'a [u8] {
    match &node.detail {
        Detail::Der { .. } => buf,
        Detail::Layer { decoded, child } => input_for(child, decoded, target),
        Detail::Parts { parts, .. } => {
            // The block whose DER contains `target` (by identity).
            for p in parts {
                if let Detail::Layer { decoded, child } = &p.detail {
                    if contains(child, target) {
                        return input_for(child, decoded, target);
                    }
                }
            }
            buf
        }
        _ => buf,
    }
}

fn contains(node: &Node, target: &Asn1) -> bool {
    fn walk(items: &[Asn1], t: &Asn1) -> bool {
        items
            .iter()
            .any(|e| std::ptr::eq(e, t) || e.children().is_some_and(|c| walk(c, t)))
    }
    match &node.detail {
        Detail::Der { items } => walk(items, target),
        Detail::Layer { child, .. } => contains(child, target),
        _ => false,
    }
}

/// The identifier octets of `e` (its tag, including high-tag-number form).
fn der_tag_bytes<'a>(e: &Asn1, buf: &'a [u8]) -> &'a [u8] {
    let s = e.range[0];
    let mut n = 1;
    if buf[s] & 0x1f == 0x1f {
        while buf[s + n] & 0x80 != 0 {
            n += 1;
        }
        n += 1;
    }
    &buf[s..s + n]
}

/// A minimal DER length.
fn der_length(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let bytes = (n as u64).to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    let mut out = vec![0x80 | (8 - skip) as u8];
    out.extend_from_slice(&bytes[skip..]);
    out
}

/// Copy `buf[region]` to `out`, applying `action` at `segs` and re-encoding
/// the length of every element on the way down.
fn der_splice(
    buf: &[u8],
    region: [usize; 2],
    items: &[Asn1],
    segs: &[usize],
    action: &DerAction<'_>,
    out: &mut Vec<u8>,
) {
    let idx = segs[0];
    if segs.len() == 1 {
        if let DerAction::Insert(elem) = action {
            if idx == items.len() {
                out.extend_from_slice(&buf[region[0]..region[1]]);
                out.extend_from_slice(elem);
                return;
            }
        }
        let e = &items[idx];
        out.extend_from_slice(&buf[region[0]..e.range[0]]);
        match action {
            DerAction::Replace(elem) => out.extend_from_slice(elem),
            DerAction::Delete => {}
            DerAction::Insert(elem) => {
                out.extend_from_slice(elem);
                out.extend_from_slice(&buf[e.range[0]..e.range[1]]);
            }
        }
        out.extend_from_slice(&buf[e.range[1]..region[1]]);
        return;
    }
    let e = &items[idx];
    out.extend_from_slice(&buf[region[0]..e.range[0]]);
    let children = e.children().expect("validated by the caller");
    let [cs, ce] = e.content;
    // An encapsulating BIT STRING keeps its unused-bits byte.
    let prefix = matches!(
        e.value,
        Asn1Value::Encapsulated {
            unused_bits: Some(_),
            ..
        }
    );
    let mut content = Vec::new();
    if prefix {
        content.push(buf[cs]);
    }
    let start = if prefix { cs + 1 } else { cs };
    der_splice(buf, [start, ce], children, &segs[1..], action, &mut content);
    out.extend_from_slice(der_tag_bytes(e, buf));
    out.extend_from_slice(&der_length(content.len()));
    out.extend_from_slice(&content);
    out.extend_from_slice(&buf[e.range[1]..region[1]]);
}

fn der_mismatch(e: &Asn1, hint: &str) -> Diag {
    Diag::new(
        "TYPE_MISMATCH",
        format!("element is {}; {hint}", e.tag_name()),
        None,
    )
}

/// The new content octets for `e`, encoded for its type. `hex:`/`b64:` set
/// the content verbatim (for a BIT STRING: the bits, with 0 unused bits).
fn der_content(e: &Asn1, v: &NewValue) -> Result<Vec<u8>, Diag> {
    if e.constructed {
        return Err(der_mismatch(e, "set one of its children instead"));
    }
    let universal = e.class == TagClass::Universal;
    if let NewValue::Bytes(b) = v {
        return Ok(if universal && e.number == 3 {
            let mut c = vec![0];
            c.extend_from_slice(b);
            c
        } else {
            b.clone()
        });
    }
    if !universal {
        // Context/application/private primitives are untyped: text only.
        return match v {
            NewValue::Str(s) => Ok(s.as_bytes().to_vec()),
            _ => Err(der_mismatch(e, "use \"text\", hex:.. or b64:..")),
        };
    }
    let text_only = |check: fn(char) -> bool, what: &str| -> Result<Vec<u8>, Diag> {
        match v {
            NewValue::Str(s) => match s.chars().find(|&c| !check(c)) {
                None => Ok(s.as_bytes().to_vec()),
                Some(c) => Err(Diag::new(
                    "VALUE_OUT_OF_RANGE",
                    format!("{c:?} is not allowed in a {what}"),
                    None,
                )),
            },
            _ => Err(der_mismatch(e, "use \"text\"")),
        }
    };
    match (e.number, v) {
        (1, NewValue::Bool(b)) => Ok(vec![if *b { 0xff } else { 0 }]),
        (1, _) => Err(der_mismatch(e, "use true or false")),
        (2 | 10, NewValue::Int(n)) => Ok(der_int(*n)),
        (2 | 10, _) => Err(der_mismatch(
            e,
            "use an integer, or hex:.. for wider values",
        )),
        (5, NewValue::Null) => Ok(vec![]),
        (5, _) => Err(der_mismatch(e, "use null")),
        (6, NewValue::Str(s)) => der_oid(s).ok_or_else(|| {
            Diag::new(
                "BAD_VALUE",
                format!("'{s}' is not a dotted OID (e.g. \"2.5.4.3\")"),
                None,
            )
        }),
        (6, _) => Err(der_mismatch(e, "use a dotted OID string, e.g. \"2.5.4.3\"")),
        (23 | 24, NewValue::Str(s)) => der_time(s, e.number == 23),
        (23 | 24, _) => Err(der_mismatch(
            e,
            "use a time string, e.g. \"2030-01-01T00:00:00Z\"",
        )),
        (4 | 12, NewValue::Str(s)) => Ok(s.as_bytes().to_vec()),
        (18, _) => text_only(|c| c.is_ascii_digit() || c == ' ', "NumericString"),
        (19, _) => text_only(
            |c| c.is_ascii_alphanumeric() || " '()+,-./:=?".contains(c),
            "PrintableString",
        ),
        (22, _) => text_only(|c| c.is_ascii(), "IA5String"),
        (26, _) => text_only(|c| (' '..='~').contains(&c), "VisibleString"),
        (25 | 27, _) => text_only(|_| true, "string"),
        (20 | 21, NewValue::Str(s)) => s
            .chars()
            .map(|c| u8::try_from(u32::from(c)).ok())
            .collect::<Option<Vec<u8>>>()
            .ok_or_else(|| {
                Diag::new(
                    "VALUE_OUT_OF_RANGE",
                    "T61/Videotex strings hold Latin-1 only",
                    None,
                )
            }),
        (30, NewValue::Str(s)) => {
            if s.chars().any(|c| u32::from(c) > 0xffff) {
                return Err(Diag::new(
                    "VALUE_OUT_OF_RANGE",
                    "a BMPString holds only U+0000..U+FFFF",
                    None,
                ));
            }
            Ok(s.encode_utf16().flat_map(u16::to_be_bytes).collect())
        }
        (28, NewValue::Str(s)) => Ok(s.chars().flat_map(|c| u32::from(c).to_be_bytes()).collect()),
        _ => Err(der_mismatch(
            e,
            "use hex:.. or b64:.. to set its content bytes",
        )),
    }
}

/// Minimal two's complement, big-endian.
fn der_int(n: i128) -> Vec<u8> {
    let b = n.to_be_bytes();
    let mut i = 0;
    while i < 15 && ((b[i] == 0 && b[i + 1] & 0x80 == 0) || (b[i] == 0xff && b[i + 1] & 0x80 != 0))
    {
        i += 1;
    }
    b[i..].to_vec()
}

fn der_oid(s: &str) -> Option<Vec<u8>> {
    let arcs: Vec<u128> = s
        .split('.')
        .map(|a| a.parse().ok())
        .collect::<Option<_>>()?;
    if arcs.len() < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40) {
        return None;
    }
    let mut out = Vec::new();
    let first = arcs[0].checked_mul(40)?.checked_add(arcs[1])?;
    for a in std::iter::once(first).chain(arcs[2..].iter().copied()) {
        let mut chunk = vec![(a & 0x7f) as u8];
        let mut v = a >> 7;
        while v > 0 {
            chunk.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        chunk.reverse();
        out.extend_from_slice(&chunk);
    }
    Some(out)
}

/// A UTCTime/GeneralizedTime from its own form or from ISO 8601
/// (`2030-01-01T00:00:00Z`, `...T00:00:00.5+02:00`).
fn der_time(s: &str, utc: bool) -> Result<Vec<u8>, Diag> {
    if der::time_iso(s, utc).is_some() {
        return Ok(s.as_bytes().to_vec());
    }
    let bad = || {
        Diag::new(
            "BAD_VALUE",
            format!("'{s}' is not a time; use e.g. \"2030-01-01T00:00:00Z\""),
            None,
        )
    };
    let b = s.as_bytes();
    if !s.is_ascii()
        || b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return Err(bad());
    }
    let (date, time) = (&s[..10], &s[11..19]);
    let mut rest = &s[19..];
    let mut frac = "";
    if let Some(r) = rest.strip_prefix('.') {
        let n = r.bytes().take_while(u8::is_ascii_digit).count();
        frac = &rest[..1 + n];
        rest = &r[n..];
    }
    let zone = match rest {
        "Z" => "Z".to_string(),
        z if z.len() == 6 && (z.starts_with('+') || z.starts_with('-')) && &z[3..4] == ":" => {
            format!("{}{}", &z[..3], &z[4..])
        }
        _ => return Err(bad()),
    };
    let digits: String = format!("{date}{time}")
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    let raw = if utc {
        if !frac.is_empty() {
            return Err(Diag::new(
                "VALUE_OUT_OF_RANGE",
                "UTCTime has no fractional seconds",
                None,
            ));
        }
        let year: u32 = digits[..4].parse().map_err(|_| bad())?;
        if !(1950..=2049).contains(&year) {
            return Err(Diag::new(
                "VALUE_OUT_OF_RANGE",
                "UTCTime covers the years 1950-2049",
                None,
            ));
        }
        format!("{}{zone}", &digits[2..])
    } else {
        format!("{digits}{frac}{zone}")
    };
    if der::time_iso(&raw, utc).is_none() {
        return Err(bad());
    }
    Ok(raw.into_bytes())
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
        assert_eq!(parse_value("null").unwrap(), NewValue::Null);
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
