//! Human-readable outline output.

use std::fmt::Write as _;

use crate::node::{AltKind, Codec, Detail, Field, FieldValue, Node};
use crate::varint;

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
