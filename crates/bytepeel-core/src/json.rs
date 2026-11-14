//! Compact JSON output. Schema documented in docs/DESIGN.md.
//!
//! 64-bit integers are emitted as decimal strings so that consumers using
//! IEEE doubles (JavaScript, jq) never silently lose precision.

use std::fmt::Write as _;

use crate::node::{Alt, AltKind, Asn1, Asn1Value, Codec, Detail, Field, FieldValue, Node};
use crate::value::{self, Value, ValueKind};
use crate::{Diag, der, text, varint};

const TEXT_CAP: usize = crate::node::TEXT_HEAD;
/// A bytes leaf keeps exactly what its `hex` shows.
const HEX_CAP: usize = crate::node::BYTES_HEAD;
const PACKED_CAP: usize = 64;

pub fn node_to_json(n: &Node) -> String {
    let mut o = String::new();
    node(&mut o, n);
    o
}

pub fn field_to_json(f: &Field) -> String {
    let mut o = String::new();
    field(&mut o, f);
    o
}

pub fn asn1_to_json(e: &Asn1) -> String {
    let mut o = String::new();
    asn1(&mut o, e);
    o
}

pub fn diag_to_json(d: &Diag) -> String {
    let mut o = String::from("{\"error\":");
    diag(&mut o, d);
    o.push('}');
    o
}

pub fn value_to_json(v: &Value) -> String {
    let mut o = String::new();
    value(&mut o, v);
    o
}

fn values_arr(o: &mut String, items: &[Value]) {
    o.push('[');
    for (i, v) in items.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        value(o, v);
    }
    o.push(']');
}

fn value(o: &mut String, v: &Value) {
    let _ = write!(
        o,
        "{{\"type\":\"{}\",\"range\":[{},{}]",
        value::type_name(&v.kind),
        v.range[0],
        v.range[1]
    );
    if v.indefinite {
        o.push_str(",\"indefinite\":true");
    }
    match &v.kind {
        ValueKind::Uint(n) => {
            let _ = write!(o, ",\"value\":\"{n}\"");
        }
        ValueKind::Nint(n) => {
            let _ = write!(o, ",\"value\":\"{}\"", -(*n as i128) - 1);
        }
        ValueKind::Float { value: x, width } => {
            // Shortest form that round-trips at the source width. Half floats
            // are exact in f32, so they use the f32 form.
            let v = if *width == 64 {
                fmt_f64(*x)
            } else {
                fmt_f32(*x as f32)
            };
            let _ = write!(o, ",\"value\":{v},\"width\":{width}");
        }
        ValueKind::Bool(b) => {
            let _ = write!(o, ",\"value\":{b}");
        }
        ValueKind::Null | ValueKind::Undefined => {}
        ValueKind::Simple(n) => {
            let _ = write!(o, ",\"value\":{n}");
        }
        ValueKind::Bytes { data, decoded } => {
            let _ = write!(o, ",\"len\":{}", data.len());
            hex_kv(o, data);
            if let Some(n) = decoded {
                o.push_str(",\"decoded\":");
                node(o, n);
            }
        }
        ValueKind::Text(t) => text_kv(o, "value", t),
        ValueKind::Array(items) => {
            o.push_str(",\"items\":");
            values_arr(o, items);
        }
        ValueKind::Map(entries) => {
            o.push_str(",\"entries\":[");
            for (i, (k, val)) in entries.iter().enumerate() {
                if i > 0 {
                    o.push(',');
                }
                o.push_str("{\"key\":");
                value(o, k);
                o.push_str(",\"value\":");
                value(o, val);
                o.push('}');
            }
            o.push(']');
        }
        ValueKind::Ext { type_, data } => {
            let _ = write!(o, ",\"ext_type\":{type_}");
            let _ = write!(o, ",\"len\":{}", data.len());
            hex_kv(o, data);
            if let Some(iso) = value::ext_iso(*type_, data) {
                let _ = write!(o, ",\"iso\":\"{iso}\"");
            }
        }
        ValueKind::Tag(n, inner) => {
            let _ = write!(o, ",\"tag\":\"{n}\"");
            if let Some(name) = value::tag_name(*n) {
                let _ = write!(o, ",\"name\":\"{name}\"");
            }
            if *n == 1 {
                if let Some(iso) = value::epoch_iso(inner) {
                    let _ = write!(o, ",\"iso\":\"{iso}\"");
                }
            } else if *n == 2 || *n == 3 {
                if let ValueKind::Bytes { data, .. } = &inner.kind {
                    let _ = write!(o, ",\"int\":\"{}\"", value::bignum_decimal(data, *n == 3));
                }
            } else if *n == 37 {
                if let ValueKind::Bytes { data, .. } = &inner.kind {
                    if data.len() == 16 {
                        let _ = write!(o, ",\"uuid\":\"{}\"", value::uuid_string(data));
                    }
                }
            }
            o.push_str(",\"value\":");
            value(o, inner);
        }
    }
    o.push('}');
}

pub(crate) fn esc(o: &mut String, s: &str) {
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
}

fn text_kv(o: &mut String, key: &str, text: &str) {
    let mut it = text.chars();
    let head: String = it.by_ref().take(TEXT_CAP).collect();
    let _ = write!(o, ",\"{key}\":");
    esc(o, &head);
    if it.next().is_some() {
        o.push_str(",\"truncated\":true");
    }
}

fn hex_kv(o: &mut String, bytes: &[u8]) {
    hex_head_kv(o, bytes, bytes.len());
}

/// `"hex"` of the first `HEX_CAP` bytes of `head`, where `len` is the length
/// of the whole data (`head` may be just its start).
fn hex_head_kv(o: &mut String, head: &[u8], len: usize) {
    o.push_str(",\"hex\":\"");
    for b in head.iter().take(HEX_CAP) {
        let _ = write!(o, "{b:02x}");
    }
    o.push('"');
    if len > HEX_CAP {
        o.push_str(",\"truncated\":true");
    }
}

fn fmt_f64(x: f64) -> String {
    if x.is_nan() {
        "\"NaN\"".into()
    } else if x.is_infinite() {
        if x > 0.0 {
            "\"Infinity\""
        } else {
            "\"-Infinity\""
        }
        .into()
    } else if x == 0.0 {
        "0".into()
    } else if x.abs() >= 1e15 || x.abs() < 1e-6 {
        format!("{x:e}")
    } else {
        format!("{x}")
    }
}

fn fmt_f32(x: f32) -> String {
    if x.is_nan() {
        "\"NaN\"".into()
    } else if x.is_infinite() {
        if x > 0.0 {
            "\"Infinity\""
        } else {
            "\"-Infinity\""
        }
        .into()
    } else if x == 0.0 {
        "0".into()
    } else if x.abs() >= 1e15 || x.abs() < 1e-6 {
        format!("{x:e}")
    } else {
        format!("{x}")
    }
}

fn diag(o: &mut String, d: &Diag) {
    o.push_str("{\"code\":");
    esc(o, d.code);
    o.push_str(",\"message\":");
    esc(o, &d.message);
    match d.offset {
        Some(off) => {
            let _ = write!(o, ",\"offset\":{off}");
        }
        None => o.push_str(",\"offset\":null"),
    }
    o.push('}');
}

fn node(o: &mut String, n: &Node) {
    o.push_str("{\"codec\":");
    esc(o, n.codec.name());
    match &n.codec {
        Codec::Base64 { alphabet, padded } => {
            let _ = write!(
                o,
                ",\"alphabet\":\"{}\",\"padded\":{padded}",
                alphabet.name()
            );
        }
        Codec::Pem { label } => {
            o.push_str(",\"label\":");
            esc(o, label);
        }
        Codec::Gzip { name: Some(name) } => {
            o.push_str(",\"name\":");
            esc(o, name);
        }
        Codec::Dump { style, start } => {
            let _ = write!(o, ",\"style\":\"{style}\"");
            if *start != 0 {
                let _ = write!(o, ",\"start\":{start}");
            }
        }
        Codec::Jwt { kind } => {
            let _ = write!(o, ",\"kind\":\"{kind}\"");
        }
        _ => {}
    }
    let _ = write!(
        o,
        ",\"range\":[{},{}],\"confidence\":{:.2}",
        n.range[0], n.range[1], n.confidence
    );
    match &n.detail {
        Detail::Layer { decoded, child } => {
            let _ = write!(o, ",\"decoded_len\":{},\"child\":", decoded.len());
            node(o, child);
        }
        Detail::Message { fields } => {
            o.push_str(",\"fields\":");
            fields_arr(o, fields);
        }
        Detail::Der { items } => {
            o.push_str(",\"items\":");
            asn1_arr(o, items);
        }
        Detail::Values { items } => {
            o.push_str(",\"items\":");
            values_arr(o, items);
        }
        Detail::Parts { parts, times } => {
            o.push_str(",\"parts\":[");
            for (i, p) in parts.iter().enumerate() {
                if i > 0 {
                    o.push(',');
                }
                node(o, p);
            }
            o.push(']');
            if !times.is_empty() {
                o.push_str(",\"times\":{");
                for (i, (claim, iso)) in times.iter().enumerate() {
                    if i > 0 {
                        o.push(',');
                    }
                    esc(o, claim);
                    o.push(':');
                    esc(o, iso);
                }
                o.push('}');
            }
        }
        Detail::Text { text, len } => {
            // `text` is the leaf's head: at most TEXT_CAP characters.
            text_kv(o, "text", text);
            if *len > text.len() {
                o.push_str(",\"truncated\":true");
            }
        }
        Detail::Bytes { len, head } => {
            let _ = write!(o, ",\"len\":{len}");
            hex_head_kv(o, head, *len);
        }
    }
    if !n.warnings.is_empty() {
        o.push_str(",\"warnings\":[");
        for (i, w) in n.warnings.iter().enumerate() {
            if i > 0 {
                o.push(',');
            }
            diag(o, w);
        }
        o.push(']');
    }
    o.push('}');
}

fn fields_arr(o: &mut String, fields: &[Field]) {
    o.push('[');
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        field(o, f);
    }
    o.push(']');
}

fn field(o: &mut String, f: &Field) {
    let _ = write!(
        o,
        "{{\"field\":{},\"wire\":\"{}\",\"range\":[{},{}]",
        f.number,
        f.value.wire_name(),
        f.range[0],
        f.range[1]
    );
    match &f.value {
        FieldValue::Varint { value, .. } => {
            let _ = write!(
                o,
                ",\"uint\":\"{value}\",\"int\":\"{}\",\"sint\":\"{}\"",
                *value as i64,
                varint::zigzag(*value)
            );
        }
        FieldValue::I64 { value } => {
            let _ = write!(
                o,
                ",\"fixed64\":\"{value}\",\"sfixed64\":\"{}\",\"double\":{}",
                *value as i64,
                fmt_f64(f64::from_bits(*value))
            );
        }
        FieldValue::I32 { value } => {
            let _ = write!(
                o,
                ",\"fixed32\":{value},\"sfixed32\":{},\"float\":{}",
                *value as i32,
                fmt_f32(f32::from_bits(*value))
            );
        }
        FieldValue::Len { data, alts, .. } => {
            let _ = write!(o, ",\"len\":{},\"alts\":[", data.len());
            for (i, a) in alts.iter().enumerate() {
                if i > 0 {
                    o.push(',');
                }
                alt(o, a, data);
            }
            o.push(']');
        }
        FieldValue::Group { fields } => {
            o.push_str(",\"fields\":");
            fields_arr(o, fields);
        }
    }
    o.push('}');
}

fn alt(o: &mut String, a: &Alt, data: &[u8]) {
    let _ = write!(o, "{{\"as\":\"{}\",\"score\":{:.2}", a.kind.name(), a.score);
    match &a.kind {
        AltKind::Message(fields) => {
            o.push_str(",\"fields\":");
            fields_arr(o, fields);
        }
        AltKind::String { text, decoded } => {
            text_kv(o, "value", text);
            if let Some(n) = decoded {
                o.push_str(",\"decoded\":");
                node(o, n);
            }
        }
        AltKind::PackedVarint(values) => {
            o.push_str(",\"values\":[");
            for (i, v) in values.iter().take(PACKED_CAP).enumerate() {
                if i > 0 {
                    o.push(',');
                }
                let _ = write!(o, "\"{v}\"");
            }
            o.push(']');
            if values.len() > PACKED_CAP {
                o.push_str(",\"truncated\":true");
            }
        }
        AltKind::PackedFixed32(values) => {
            let shown = &values[..values.len().min(PACKED_CAP)];
            o.push_str(",\"values\":[");
            join(o, shown.iter().map(|v| v.to_string()));
            o.push_str("],\"floats\":[");
            join(o, shown.iter().map(|&v| fmt_f32(f32::from_bits(v))));
            o.push(']');
            if values.len() > PACKED_CAP {
                o.push_str(",\"truncated\":true");
            }
        }
        AltKind::PackedFixed64(values) => {
            let shown = &values[..values.len().min(PACKED_CAP)];
            o.push_str(",\"values\":[");
            join(o, shown.iter().map(|v| format!("\"{v}\"")));
            o.push_str("],\"doubles\":[");
            join(o, shown.iter().map(|&v| fmt_f64(f64::from_bits(v))));
            o.push(']');
            if values.len() > PACKED_CAP {
                o.push_str(",\"truncated\":true");
            }
        }
        AltKind::Bytes => hex_kv(o, data),
        AltKind::Empty => {}
    }
    o.push('}');
}

fn join(o: &mut String, items: impl Iterator<Item = String>) {
    for (i, s) in items.enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push_str(&s);
    }
}

fn asn1_arr(o: &mut String, items: &[Asn1]) {
    o.push('[');
    for (i, e) in items.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        asn1(o, e);
    }
    o.push(']');
}

fn asn1(o: &mut String, e: &Asn1) {
    o.push_str("{\"tag\":");
    esc(o, &e.tag_name());
    let content_len = e.content[1] - e.content[0];
    let _ = write!(
        o,
        ",\"range\":[{},{}],\"len\":{content_len}",
        e.range[0], e.range[1]
    );
    match &e.value {
        Asn1Value::Constructed(items) => {
            o.push_str(",\"children\":");
            asn1_arr(o, items);
        }
        Asn1Value::Encapsulated { unused_bits, items } => {
            if let Some(u) = unused_bits {
                let _ = write!(o, ",\"unused_bits\":{u}");
            }
            o.push_str(",\"encapsulated\":true,\"children\":");
            asn1_arr(o, items);
        }
        Asn1Value::Bool(b) => {
            let _ = write!(o, ",\"bool\":{b}");
        }
        Asn1Value::Int => {
            if e.raw.len() <= der::INT_DECIMAL_MAX {
                let _ = write!(o, ",\"int\":\"{}\"", der::int_decimal(&e.raw));
            }
            if e.raw.len() > 8 {
                hex_kv(o, &e.raw);
            }
        }
        Asn1Value::Null => {}
        Asn1Value::Oid(oid) => {
            let _ = write!(o, ",\"oid\":\"{oid}\"");
            if let Some(n) = der::oid_name(oid) {
                let _ = write!(o, ",\"name\":\"{n}\"");
            }
        }
        Asn1Value::Text(t) => text_kv(o, "value", t),
        Asn1Value::Time { text, iso } => {
            text_kv(o, "value", text);
            if let Some(iso) = iso {
                o.push_str(",\"iso\":");
                esc(o, iso);
            }
        }
        Asn1Value::BitString { unused_bits } => {
            let _ = write!(o, ",\"unused_bits\":{unused_bits}");
            hex_kv(o, &e.raw[1..]);
        }
        Asn1Value::Bytes => {
            hex_kv(o, &e.raw);
            if let Ok(t) = std::str::from_utf8(&e.raw) {
                if !t.is_empty() && text::is_printable(t) {
                    text_kv(o, "text", t);
                }
            }
        }
    }
    o.push('}');
}
