//! Field selection by path, e.g. `1.3[2].4`.

use crate::Diag;
use crate::node::{AltKind, Detail, Field, FieldValue, Node};

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
