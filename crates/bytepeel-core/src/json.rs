//! Compact JSON output. Schema documented in docs/DESIGN.md.
//!
//! 64-bit integers are emitted as decimal strings so that consumers using
//! IEEE doubles (JavaScript, jq) never silently lose precision.

use std::fmt::Write as _;

use crate::node::{Alt, AltKind, Codec, Detail, Field, FieldValue, Node};
use crate::{Diag, varint};

const TEXT_CAP: usize = 1024;
const HEX_CAP: usize = 64;
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

pub fn diag_to_json(d: &Diag) -> String {
    let mut o = String::from("{\"error\":");
    diag(&mut o, d);
    o.push('}');
    o
}

fn esc(o: &mut String, s: &str) {
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
    o.push_str(",\"hex\":\"");
    for b in bytes.iter().take(HEX_CAP) {
        let _ = write!(o, "{b:02x}");
    }
    o.push('"');
    if bytes.len() > HEX_CAP {
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
        Detail::Text { text } => text_kv(o, "text", text),
        Detail::Bytes { bytes } => {
            let _ = write!(o, ",\"len\":{}", bytes.len());
            hex_kv(o, bytes);
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
        AltKind::Bytes => hex_kv(o, data),
        AltKind::Empty => {}
    }
    o.push('}');
}
