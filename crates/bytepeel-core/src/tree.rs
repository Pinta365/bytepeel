//! Human-readable outline output.

use std::fmt::Write as _;

use crate::node::{AltKind, Asn1, Asn1Value, Codec, Detail, Field, FieldValue, Node};
use crate::value::{Value, ValueKind};
use crate::{der, value, varint};

pub fn node_to_tree(n: &Node) -> String {
    let mut o = String::new();
    node(&mut o, n, 0);
    o
}

pub fn field_to_tree(f: &Field) -> String {
    let mut o = String::new();
    field(&mut o, f, 0);
    o
}

pub fn asn1_to_tree(e: &Asn1) -> String {
    let mut o = String::new();
    asn1(&mut o, e, 0);
    o
}

pub fn value_to_tree(v: &Value) -> String {
    let mut o = String::new();
    value(&mut o, v, 0);
    o
}

fn value(o: &mut String, v: &Value, d: usize) {
    indent(o, d);
    let ind = if v.indefinite { " (indefinite)" } else { "" };
    let _ = write!(
        o,
        "{} [{}..{}]{ind}",
        value::type_name(&v.kind),
        v.range[0],
        v.range[1]
    );
    match &v.kind {
        ValueKind::Uint(n) => {
            let _ = writeln!(o, " {n}");
        }
        ValueKind::Nint(n) => {
            let _ = writeln!(o, " {}", -(*n as i128) - 1);
        }
        ValueKind::Float { value: x, width } => {
            if *width == 64 {
                let _ = writeln!(o, " {x} width={width}");
            } else {
                let _ = writeln!(o, " {} width={width}", *x as f32);
            }
        }
        ValueKind::Bool(b) => {
            let _ = writeln!(o, " {b}");
        }
        ValueKind::Null | ValueKind::Undefined => o.push('\n'),
        ValueKind::Simple(n) => {
            let _ = writeln!(o, " {n}");
        }
        ValueKind::Bytes { data, decoded } => {
            let _ = write!(o, " len={} ", data.len());
            hex_preview(o, data);
            o.push('\n');
            if let Some(n) = decoded {
                node(o, n, d + 1);
            }
        }
        ValueKind::Text(t) => {
            o.push(' ');
            quote(o, t, 80);
            o.push('\n');
        }
        ValueKind::Array(items) => {
            o.push('\n');
            for item in items {
                value(o, item, d + 1);
            }
        }
        ValueKind::Map(entries) => {
            o.push('\n');
            // Each entry: the key at d+1, then its value one deeper.
            for (k, val) in entries {
                value(o, k, d + 1);
                value(o, val, d + 2);
            }
        }
        ValueKind::Ext { type_, data } => {
            let _ = write!(o, " type={type_} len={} ", data.len());
            hex_preview(o, data);
            if let Some(iso) = value::ext_iso(*type_, data) {
                let _ = write!(o, " iso={iso}");
            }
            o.push('\n');
        }
        ValueKind::Tag(n, inner) => {
            let _ = write!(o, " {n}");
            if let Some(name) = value::tag_name(*n) {
                let _ = write!(o, " ({name})");
            }
            if *n == 1 {
                if let Some(iso) = value::epoch_iso(inner) {
                    let _ = write!(o, " iso={iso}");
                }
            } else if *n == 2 || *n == 3 {
                if let ValueKind::Bytes { data, .. } = &inner.kind {
                    let _ = write!(o, " int={}", value::bignum_decimal(data, *n == 3));
                }
            } else if *n == 37 {
                if let ValueKind::Bytes { data, .. } = &inner.kind {
                    if data.len() == 16 {
                        let _ = write!(o, " uuid={}", value::uuid_string(data));
                    }
                }
            }
            o.push('\n');
            value(o, inner, d + 1);
        }
    }
}

fn indent(o: &mut String, d: usize) {
    for _ in 0..d {
        o.push_str("  ");
    }
}

fn quote(o: &mut String, s: &str, cap: usize) {
    let mut it = s.chars();
    let head: String = it.by_ref().take(cap).collect();
    let _ = write!(o, "{head:?}");
    if it.next().is_some() {
        o.push('…');
    }
}

fn hex_preview(o: &mut String, bytes: &[u8]) {
    for b in bytes.iter().take(32) {
        let _ = write!(o, "{b:02x}");
    }
    if bytes.len() > 32 {
        o.push('…');
    }
}

fn node(o: &mut String, n: &Node, d: usize) {
    indent(o, d);
    o.push_str(n.codec.name());
    match &n.codec {
        Codec::Base64 { alphabet, padded } => {
            let p = if *padded { "padded" } else { "unpadded" };
            let _ = write!(o, "({},{p})", alphabet.name());
        }
        Codec::Pem { label } => {
            let _ = write!(o, "({label})");
        }
        Codec::Gzip { name: Some(name) } => {
            let _ = write!(o, "({name:?})");
        }
        Codec::Dump { style } => {
            let _ = write!(o, "({style})");
        }
        Codec::Jwt { kind } => {
            let _ = write!(o, "({kind})");
        }
        _ => {}
    }
    let _ = write!(
        o,
        " [{}..{}] conf={:.2}",
        n.range[0], n.range[1], n.confidence
    );
    match &n.detail {
        Detail::Layer { decoded, child } => {
            let _ = writeln!(o, " -> {} bytes", decoded.len());
            node(o, child, d + 1);
        }
        Detail::Message { fields } => {
            o.push('\n');
            for f in fields {
                field(o, f, d + 1);
            }
        }
        Detail::Der { items } => {
            o.push('\n');
            for e in items {
                asn1(o, e, d + 1);
            }
        }
        Detail::Values { items } => {
            o.push('\n');
            for v in items {
                value(o, v, d + 1);
            }
        }
        Detail::Parts { parts, times } => {
            if matches!(n.codec, Codec::Bundle) {
                let _ = write!(o, " ({} blocks)", parts.len());
            }
            o.push('\n');
            for p in parts {
                node(o, p, d + 1);
            }
            if !times.is_empty() {
                indent(o, d + 1);
                for (i, (claim, iso)) in times.iter().enumerate() {
                    if i > 0 {
                        o.push(' ');
                    }
                    let _ = write!(o, "{claim}={iso}");
                }
                o.push('\n');
            }
        }
        Detail::Text { text } => {
            o.push(' ');
            quote(o, text, 80);
            o.push('\n');
        }
        Detail::Bytes { bytes } => {
            let _ = write!(o, " len={} ", bytes.len());
            hex_preview(o, bytes);
            o.push('\n');
        }
    }
    for w in &n.warnings {
        indent(o, d + 1);
        let _ = writeln!(o, "! {}: {}", w.code, w.message);
    }
}

fn field(o: &mut String, f: &Field, d: usize) {
    indent(o, d);
    let _ = write!(
        o,
        "#{} {} [{}..{}]",
        f.number,
        f.value.wire_name(),
        f.range[0],
        f.range[1]
    );
    match &f.value {
        FieldValue::Varint { value, .. } => {
            let _ = writeln!(
                o,
                " uint={value} int={} sint={}",
                *value as i64,
                varint::zigzag(*value)
            );
        }
        FieldValue::I64 { value } => {
            let _ = writeln!(
                o,
                " fixed64={value} sfixed64={} double={}",
                *value as i64,
                f64::from_bits(*value)
            );
        }
        FieldValue::I32 { value } => {
            let _ = writeln!(
                o,
                " fixed32={value} sfixed32={} float={}",
                *value as i32,
                f32::from_bits(*value)
            );
        }
        FieldValue::Len { data, alts, .. } => {
            let _ = write!(o, " len={}:", data.len());
            for (i, a) in alts.iter().enumerate() {
                if i > 0 {
                    o.push_str(" |");
                }
                let _ = write!(o, " {} {:.2}", a.kind.name(), a.score);
                if i == 0 {
                    if let AltKind::String { text, .. } = &a.kind {
                        o.push(' ');
                        quote(o, text, 60);
                    }
                }
            }
            o.push('\n');
            if let Some(top) = alts.first() {
                match &top.kind {
                    AltKind::Message(fs) => {
                        for f in fs {
                            field(o, f, d + 1);
                        }
                    }
                    AltKind::String {
                        decoded: Some(n), ..
                    } => node(o, n, d + 1),
                    _ => {}
                }
            }
        }
        FieldValue::Group { fields } => {
            o.push('\n');
            for f in fields {
                field(o, f, d + 1);
            }
        }
    }
}

fn asn1(o: &mut String, e: &Asn1, d: usize) {
    indent(o, d);
    let _ = write!(o, "{} [{}..{}]", e.tag_name(), e.range[0], e.range[1]);
    match &e.value {
        Asn1Value::Constructed(items) => {
            o.push('\n');
            for c in items {
                asn1(o, c, d + 1);
            }
        }
        Asn1Value::Encapsulated { items, .. } => {
            o.push_str(" (encapsulated)\n");
            for c in items {
                asn1(o, c, d + 1);
            }
        }
        Asn1Value::Bool(b) => {
            let _ = writeln!(o, " {b}");
        }
        Asn1Value::Int if e.raw.len() <= der::INT_DECIMAL_MAX => {
            let _ = writeln!(o, " {}", der::int_decimal(&e.raw));
        }
        Asn1Value::Int => {
            let _ = write!(o, " ({} bytes) ", e.raw.len());
            hex_preview(o, &e.raw);
            o.push('\n');
        }
        Asn1Value::Null => o.push('\n'),
        Asn1Value::Oid(oid) => {
            let _ = write!(o, " {oid}");
            if let Some(n) = der::oid_name(oid) {
                let _ = write!(o, " ({n})");
            }
            o.push('\n');
        }
        Asn1Value::Text(t) => {
            o.push(' ');
            quote(o, t, 80);
            o.push('\n');
        }
        Asn1Value::Time { text, iso } => {
            let _ = writeln!(o, " {}", iso.as_deref().unwrap_or(text));
        }
        Asn1Value::BitString { unused_bits } => {
            let _ = write!(o, " unused={unused_bits} ");
            hex_preview(o, &e.raw[1..]);
            o.push('\n');
        }
        Asn1Value::Bytes => {
            let _ = write!(o, " len={} ", e.raw.len());
            match std::str::from_utf8(&e.raw) {
                Ok(t) if !t.is_empty() && crate::text::is_printable(t) => quote(o, t, 80),
                _ => hex_preview(o, &e.raw),
            }
            o.push('\n');
        }
    }
}
