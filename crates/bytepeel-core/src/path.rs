//! Field selection by path, e.g. `1.3[2].4`.

use crate::Diag;
use crate::node::{AltKind, Asn1, Codec, Detail, Field, FieldValue, Node};
use crate::value::{Value, ValueKind};

/// Select a protobuf field by path.
///
/// Segments are field numbers separated by `.`; `N[i]` picks the i-th
/// occurrence of a repeated field (default 0). Text layers (hex/base64/PEM,
/// including base64 inside string fields) are descended automatically, and a
/// LEN field is entered through its best-ranked `message` interpretation.
pub fn select<'a>(root: &'a Node, path: &str) -> Result<&'a Field, Diag> {
    let segs = parse_path(path)?;
    let mut fields = message_fields(root).ok_or_else(|| {
        Diag::new(
            "PATH_NOT_MESSAGE",
            "the input did not decode to a protobuf message",
            None,
        )
    })?;
    let mut cur: Option<&Field> = None;
    for (i, &(num, idx)) in segs.iter().enumerate() {
        if let Some(parent) = cur {
            fields = field_children(parent).ok_or_else(|| {
                Diag::new(
                    "PATH_NOT_MESSAGE",
                    format!(
                        "field at '{}' has no message interpretation",
                        prefix(&segs, i)
                    ),
                    None,
                )
            })?;
        }
        let found = fields
            .iter()
            .filter(|f| f.number == num)
            .nth(idx)
            .ok_or_else(|| {
                Diag::new(
                    "PATH_NOT_FOUND",
                    format!("no field '{}'", prefix(&segs, i + 1)),
                    None,
                )
            })?;
        cur = Some(found);
    }
    Ok(cur.expect("path has at least one segment"))
}

fn prefix(segs: &[(u32, usize)], n: usize) -> String {
    segs[..n]
        .iter()
        .map(|(f, i)| {
            if *i == 0 {
                f.to_string()
            } else {
                format!("{f}[{i}]")
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn parse_path(p: &str) -> Result<Vec<(u32, usize)>, Diag> {
    if p.trim().is_empty() {
        return Err(Diag::new("BAD_PATH", "empty path", None));
    }
    p.split('.')
        .map(|seg| {
            let bad = || {
                Diag::new(
                    "BAD_PATH",
                    format!("invalid path segment '{seg}' (expected N or N[i])"),
                    None,
                )
            };
            let (num, idx) = match seg.split_once('[') {
                Some((n, rest)) => {
                    let i = rest.strip_suffix(']').ok_or_else(bad)?;
                    (n, i.parse::<usize>().map_err(|_| bad())?)
                }
                None => (seg, 0),
            };
            Ok((num.parse::<u32>().map_err(|_| bad())?, idx))
        })
        .collect()
}

fn message_fields(node: &Node) -> Option<&[Field]> {
    match &node.detail {
        Detail::Message { fields } => Some(fields),
        Detail::Layer { child, .. } => message_fields(child),
        _ => None,
    }
}

fn field_children(f: &Field) -> Option<&[Field]> {
    match &f.value {
        FieldValue::Group { fields } => Some(fields),
        FieldValue::Len { alts, .. } => alts.iter().find_map(|a| match &a.kind {
            AltKind::Message(fs) => Some(&fs[..]),
            AltKind::String {
                decoded: Some(n), ..
            } => message_fields(n),
            _ => None,
        }),
        _ => None,
    }
}

/// Select a DER element by path.
///
/// Segments are 0-based child indices separated by `.`: the first indexes the
/// top-level elements, so `0.0.6` is the subjectPublicKeyInfo of a certificate.
/// For a PEM bundle, the first segment picks the block and the rest is the DER
/// path within it, so `1.0.0.5` is the second certificate's subject. Text
/// layers are descended automatically, and BIT STRING / OCTET STRING elements
/// with encapsulated DER are entered like constructed ones.
pub fn select_der<'a>(root: &'a Node, path: &str) -> Result<&'a Asn1, Diag> {
    let segs = parse_indices(path)?;
    let (mut items, start) = match bundle_parts(root) {
        Some(parts) => {
            let block = segs[0];
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
            if segs.len() == 1 {
                return Err(Diag::new(
                    "PATH_NOT_FOUND",
                    "a bundle path needs an element index after the block",
                    None,
                ));
            }
            (items, 1)
        }
        None => (
            der_items(root).ok_or_else(|| {
                Diag::new("PATH_NOT_MESSAGE", "the input did not decode to DER", None)
            })?,
            0,
        ),
    };
    let mut cur: Option<&'a Asn1> = None;
    for (i, &idx) in segs[start..].iter().enumerate() {
        if let Some(parent) = cur {
            items = parent.children().ok_or_else(|| {
                Diag::new(
                    "PATH_NOT_MESSAGE",
                    format!("element at '{}' has no children", join(&segs[..start + i])),
                    None,
                )
            })?;
        }
        cur = Some(items.get(idx).ok_or_else(|| {
            Diag::new(
                "PATH_NOT_FOUND",
                format!("no element '{}'", join(&segs[..=start + i])),
                None,
            )
        })?);
    }
    Ok(cur.expect("path has at least one segment"))
}

/// Select a CBOR or MessagePack value by path.
///
/// Each segment is a map key or an array index (`users.0.name`). A segment
/// matches a text key exactly; a numeric segment indexes an array, or matches
/// an integer map key. If the top level has several items (a forced
/// CBOR/MessagePack sequence), the first segment indexes them. CBOR tags are
/// followed transparently.
pub fn select_value<'a>(root: &'a Node, path: &str) -> Result<&'a Value, Diag> {
    let segs = parse_value_path(path)?;
    let items = values_items(root).ok_or_else(|| {
        Diag::new(
            "PATH_NOT_MESSAGE",
            "the input did not decode to CBOR/MessagePack",
            None,
        )
    })?;
    let (mut cur, start) = if items.len() == 1 {
        (&items[0], 0)
    } else {
        let idx: usize = segs[0].parse().map_err(|_| {
            Diag::new(
                "PATH_NOT_FOUND",
                format!(
                    "'{}' is not an index into the CBOR/MessagePack sequence",
                    segs[0]
                ),
                None,
            )
        })?;
        let v = items.get(idx).ok_or_else(|| {
            Diag::new("PATH_NOT_FOUND", format!("no element '{}'", segs[0]), None)
        })?;
        (v, 1)
    };
    for (i, seg) in segs.iter().enumerate().skip(start) {
        let v = cur.untagged();
        cur = match &v.kind {
            ValueKind::Map(entries) => map_lookup(entries, seg).ok_or_else(|| {
                Diag::new(
                    "PATH_NOT_FOUND",
                    format!("no key '{}' at '{}'", seg, prefix_str(&segs, i)),
                    None,
                )
            })?,
            ValueKind::Array(arr) => {
                let idx: usize = seg.parse().map_err(|_| {
                    Diag::new(
                        "PATH_NOT_FOUND",
                        format!("'{}' is not an array index", seg),
                        None,
                    )
                })?;
                arr.get(idx).ok_or_else(|| {
                    Diag::new(
                        "PATH_NOT_FOUND",
                        format!("no index '{idx}' at '{}'", prefix_str(&segs, i)),
                        None,
                    )
                })?
            }
            _ => {
                return Err(Diag::new(
                    "PATH_NOT_MESSAGE",
                    format!("'{}' is not a map or array", prefix_str(&segs, i)),
                    None,
                ));
            }
        };
    }
    Ok(cur)
}

fn map_lookup<'a>(entries: &'a [(Value, Value)], seg: &str) -> Option<&'a Value> {
    for (k, v) in entries {
        if let ValueKind::Text(t) = &k.untagged().kind {
            if t == seg {
                return Some(v);
            }
        }
    }
    if let Ok(want) = seg.parse::<i128>() {
        for (k, v) in entries {
            let key = match &k.untagged().kind {
                ValueKind::Uint(n) => Some(*n as i128),
                ValueKind::Nint(n) => Some(-(*n as i128) - 1),
                _ => None,
            };
            if key == Some(want) {
                return Some(v);
            }
        }
    }
    None
}

fn prefix_str(segs: &[&str], n: usize) -> String {
    segs[..n].join(".")
}

fn parse_value_path(p: &str) -> Result<Vec<&str>, Diag> {
    if p.trim().is_empty() {
        return Err(Diag::new("BAD_PATH", "empty path", None));
    }
    let segs: Vec<&str> = p.split('.').collect();
    if segs.iter().any(|s| s.is_empty()) {
        return Err(Diag::new(
            "BAD_PATH",
            "CBOR/MessagePack paths do not allow empty segments",
            None,
        ));
    }
    Ok(segs)
}

/// True when `node` (after any text layers) is CBOR or MessagePack.
pub fn is_values(node: &Node) -> bool {
    values_items(node).is_some()
}

fn values_items(node: &Node) -> Option<&[Value]> {
    match &node.detail {
        Detail::Values { items } => Some(items),
        Detail::Layer { child, .. } => values_items(child),
        _ => None,
    }
}

/// True when `node` (after any text layers) is DER, so paths are element
/// indices. A PEM bundle counts when every block is DER.
pub fn is_der(node: &Node) -> bool {
    if let Some(parts) = bundle_parts(node) {
        return !parts.is_empty() && parts.iter().all(|p| der_items(p).is_some());
    }
    der_items(node).is_some()
}

/// The parts of a PEM bundle node, if `node` (after text layers) is one.
fn bundle_parts(node: &Node) -> Option<&[Node]> {
    match &node.detail {
        Detail::Parts { parts, .. } if matches!(node.codec, Codec::Bundle) => Some(parts),
        Detail::Layer { child, .. } => bundle_parts(child),
        _ => None,
    }
}

fn der_items(node: &Node) -> Option<&[Asn1]> {
    match &node.detail {
        Detail::Der { items } => Some(items),
        Detail::Layer { child, .. } => der_items(child),
        _ => None,
    }
}

fn join(segs: &[usize]) -> String {
    segs.iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn parse_indices(p: &str) -> Result<Vec<usize>, Diag> {
    if p.trim().is_empty() {
        return Err(Diag::new("BAD_PATH", "empty path", None));
    }
    p.split('.')
        .map(|seg| {
            seg.parse::<usize>().map_err(|_| {
                Diag::new(
                    "BAD_PATH",
                    format!(
                        "invalid path segment '{seg}' (DER paths are child indices, e.g. 0.0.6)"
                    ),
                    None,
                )
            })
        })
        .collect()
}
