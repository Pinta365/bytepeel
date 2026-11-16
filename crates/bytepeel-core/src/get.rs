//! `--get` across formats: one path walks protobuf, DER, CBOR/MessagePack and
//! JWT layers in turn.
//!
//! Each format's segments are walked natively (field numbers, child indices,
//! map keys, JWT parts and JSON keys). When the next segment cannot descend
//! natively but the current item holds a decoded node (a protobuf string that
//! is base64 DER, a CBOR byte string that is protobuf, a JWT part that is not
//! JSON), the rest of the path continues in that node's format. Native descent
//! always wins, so every single-format path keeps its meaning. Text that is a
//! JSON object or array (a decoded text layer, a protobuf string, a
//! CBOR/MessagePack text string) is walked by JSON keys and array indices.

use crate::Diag;
use crate::json;
use crate::jsonpath;
use crate::node::{AltKind, Asn1, Detail, Field, FieldValue, Node};
use crate::path::{
    self, JwtPick, bundle_parts, der_items, field_children, jwt_parts, map_index, message_fields,
    values_items,
};
use crate::tree;
use crate::value::{Value, ValueKind};

/// What a path selected.
#[derive(Debug)]
pub enum Pick<'a> {
    Field(&'a Field),
    Element(&'a Asn1),
    Value(&'a Value),
    Jwt(JwtPick<'a>),
    Json(JsonPick<'a>),
}

/// A value inside JSON text.
#[derive(Debug)]
pub struct JsonPick<'a> {
    /// The whole JSON document.
    pub doc: &'a str,
    /// The path within the document (the segments after the text's holder).
    pub path: String,
    /// The selected value's byte range in `doc`.
    pub range: [usize; 2],
}

impl JsonPick<'_> {
    /// The selected value as JSON text.
    pub fn value(&self) -> &str {
        &self.doc[self.range[0]..self.range[1]]
    }

    /// `{"path":..,"range":[s,e],"value":<JSON>}`.
    pub fn to_json(&self) -> String {
        let mut o = String::from("{\"path\":");
        json::esc(&mut o, &self.path);
        o.push_str(&format!(
            ",\"range\":[{},{}],\"value\":{}}}",
            self.range[0],
            self.range[1],
            self.value()
        ));
        o
    }

    /// A string's unescaped text, any other value verbatim.
    pub fn payload(&self) -> Vec<u8> {
        let v = self.value();
        jsonpath::string_value(v).map_or_else(|| v.as_bytes().to_vec(), String::into_bytes)
    }
}

impl Pick<'_> {
    /// The selection as JSON, in its own format's schema.
    pub fn to_json(&self) -> String {
        match self {
            Pick::Field(f) => json::field_to_json(f),
            Pick::Element(e) => json::asn1_to_json(e),
            Pick::Value(v) => json::value_to_json(v),
            Pick::Jwt(p) => p.to_json(),
            Pick::Json(p) => p.to_json(),
        }
    }

    /// The selection as an indented outline.
    pub fn to_tree(&self) -> String {
        match self {
            Pick::Field(f) => tree::field_to_tree(f),
            Pick::Element(e) => tree::asn1_to_tree(e),
            Pick::Value(v) => tree::value_to_tree(v),
            Pick::Jwt(p) => p.to_tree(),
            Pick::Json(p) => format!("{} = {}\n", p.path, p.value()),
        }
    }

    /// The selection's payload bytes, or `NO_PAYLOAD` for a group, a
    /// constructed element or a map/array value.
    pub fn payload(&self) -> Result<Vec<u8>, Diag> {
        let none = |what: &str| {
            Diag::new(
                "NO_PAYLOAD",
                format!("{what} has no single payload; use the JSON output"),
                None,
            )
        };
        match self {
            Pick::Field(f) => f.payload().ok_or_else(|| none("a group")),
            Pick::Element(e) => e.payload().ok_or_else(|| none("a constructed element")),
            Pick::Value(v) => v.payload().ok_or_else(|| none("this value")),
            Pick::Jwt(p) => Ok(p.payload()),
            Pick::Json(p) => Ok(p.payload()),
        }
    }
}

/// Select by a path that may cross formats, e.g. `2.0.0.5` for the subject
/// of a base64 certificate in protobuf string field 2, or `token.payload.sub`
/// for a JWT in a CBOR byte string.
pub fn get<'a>(root: &'a Node, path: &str) -> Result<Pick<'a>, Diag> {
    walk(root, &segments(path)?, 0, &mut None)
}

fn segments(path: &str) -> Result<Vec<&str>, Diag> {
    if path.trim().is_empty() {
        return Err(Diag::new("BAD_PATH", "empty path", None));
    }
    let segs: Vec<&str> = path.split('.').collect();
    if segs.iter().any(|s| s.is_empty()) {
        return Err(Diag::new(
            "BAD_PATH",
            "paths do not allow empty segments",
            None,
        ));
    }
    Ok(segs)
}

/// What holds a decoded node that a path crossed into.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Holder<'a> {
    Field(&'a Field),
    Value(&'a Value),
    /// A JWT part that is not JSON.
    Jwt,
}

/// Where a path crosses into a decoded node: `segs[at..]` continue in `node`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Crossing<'a> {
    pub at: usize,
    pub holder: Holder<'a>,
    pub node: &'a Node,
}

/// [`get`], plus the last place the path crossed formats.
pub(crate) fn locate<'a>(
    root: &'a Node,
    path: &str,
) -> Result<(Pick<'a>, Option<Crossing<'a>>), Diag> {
    let mut cx = None;
    let pick = walk(root, &segments(path)?, 0, &mut cx)?;
    Ok((pick, cx))
}

/// The decoded node of a selection that has no children in its own format
/// (a string or bytes field, a byte string), as a crossing at `at`.
pub(crate) fn leaf_crossing<'a>(pick: &Pick<'a>, at: usize) -> Option<Crossing<'a>> {
    match pick {
        Pick::Field(f) if field_children(f).is_none() => decoded_alt(f).map(|node| Crossing {
            at,
            holder: Holder::Field(f),
            node,
        }),
        Pick::Value(v) => match &v.untagged().kind {
            ValueKind::Bytes {
                decoded: Some(n), ..
            } => Some(Crossing {
                at,
                holder: Holder::Value(v),
                node: n,
            }),
            _ => None,
        },
        _ => None,
    }
}

fn at(segs: &[&str], n: usize) -> String {
    segs[..n].join(".")
}

fn not_found(msg: String) -> Diag {
    Diag::new("PATH_NOT_FOUND", msg, None)
}

fn no_children(segs: &[&str], n: usize, what: &str) -> Diag {
    Diag::new(
        "PATH_NOT_MESSAGE",
        format!("{what} at '{}' has nothing to descend into", at(segs, n)),
        None,
    )
}

/// Walk `segs[i..]` starting in `node` (text layers are skipped).
fn walk<'a>(
    node: &'a Node,
    segs: &[&str],
    i: usize,
    cx: &mut Option<Crossing<'a>>,
) -> Result<Pick<'a>, Diag> {
    if let Some(parts) = bundle_parts(node) {
        let block: usize = segs[i]
            .parse()
            .map_err(|_| bad_index(segs[i], "a PEM bundle block"))?;
        let part = parts
            .get(block)
            .ok_or_else(|| not_found(format!("no bundle block '{}'", at(segs, i + 1))))?;
        if i + 1 == segs.len() {
            return Err(not_found(
                "a bundle path needs an element index after the block".into(),
            ));
        }
        return walk(part, segs, i + 1, cx);
    }
    if let Some(items) = der_items(node) {
        return walk_der(items, segs, i);
    }
    if let Some(items) = values_items(node) {
        return walk_values(items, segs, i, cx);
    }
    if jwt_parts(node).is_some() {
        return walk_jwt(node, segs, i, cx);
    }
    if let Some(fields) = message_fields(node) {
        return walk_fields(fields, segs, i, cx);
    }
    if let Some(doc) = text_doc(node) {
        return walk_json(doc, segs, i);
    }
    Err(Diag::new(
        "PATH_NOT_MESSAGE",
        if i == 0 {
            "the input did not decode to protobuf, DER, CBOR/MessagePack, a JWT or JSON".to_string()
        } else {
            format!(
                "the data decoded at '{}' is not protobuf, DER, CBOR/MessagePack, a JWT or JSON",
                at(segs, i)
            )
        },
        None,
    ))
}

fn bad_index(seg: &str, what: &str) -> Diag {
    Diag::new(
        "BAD_PATH",
        format!("'{seg}' is not an index into {what}"),
        None,
    )
}

fn walk_fields<'a>(
    mut fields: &'a [Field],
    segs: &[&str],
    mut i: usize,
    cx: &mut Option<Crossing<'a>>,
) -> Result<Pick<'a>, Diag> {
    loop {
        let (num, idx) = path::parse_path(segs[i])?[0];
        let f = fields
            .iter()
            .filter(|f| f.number == num)
            .nth(idx)
            .ok_or_else(|| not_found(format!("no field '{}'", at(segs, i + 1))))?;
        i += 1;
        if i == segs.len() {
            return Ok(Pick::Field(f));
        }
        if let Some(children) = field_children(f) {
            fields = children;
            continue;
        }
        // A string or bytes field whose content decodes to another format.
        return match decoded_alt(f) {
            Some(node) => {
                *cx = Some(Crossing {
                    at: i,
                    holder: Holder::Field(f),
                    node,
                });
                walk(node, segs, i, cx)
            }
            None => match json_alt(f) {
                Some(doc) => walk_json(doc, segs, i),
                None => Err(no_children(segs, i, "the field")),
            },
        };
    }
}

/// The decoded node of a LEN field's best-ranked string or bytes alt that
/// has one.
fn decoded_alt(f: &Field) -> Option<&Node> {
    match &f.value {
        FieldValue::Len { alts, .. } => alts.iter().find_map(|a| match &a.kind {
            AltKind::String {
                decoded: Some(n), ..
            }
            | AltKind::Bytes { decoded: Some(n) } => Some(&**n),
            _ => None,
        }),
        _ => None,
    }
}

/// The text of a LEN field's string alt, when it is a JSON object or array.
fn json_alt(f: &Field) -> Option<&str> {
    match &f.value {
        FieldValue::Len { alts, .. } => alts.iter().find_map(|a| match &a.kind {
            AltKind::String { text, .. } if is_json_doc(text) => Some(text.as_str()),
            _ => None,
        }),
        _ => None,
    }
}

/// The whole text of a node that is (after any layers) JSON text. A layer's
/// decoded bytes hold the full text; a root text node holds it only when it
/// is short enough to be kept whole.
fn text_doc(node: &Node) -> Option<&str> {
    match &node.detail {
        Detail::Layer { decoded, child } => match &child.detail {
            Detail::Text { .. } => std::str::from_utf8(decoded).ok().filter(|t| is_json_doc(t)),
            _ => text_doc(child),
        },
        Detail::Text { text, len } if *len == text.len() => {
            Some(text.as_str()).filter(|t| is_json_doc(t))
        }
        _ => None,
    }
}

/// A JSON object or array (not a bare scalar: a number or a quoted word is
/// text, not a document to walk).
fn is_json_doc(t: &str) -> bool {
    matches!(t.trim_start().as_bytes().first(), Some(b'{' | b'['))
        && jsonpath::find(t, &[], "").is_ok()
}

fn walk_json<'a>(doc: &'a str, segs: &[&str], i: usize) -> Result<Pick<'a>, Diag> {
    let range = jsonpath::find(doc, &segs[i..], &at(segs, i))?;
    Ok(Pick::Json(JsonPick {
        doc,
        path: segs[i..].join("."),
        range,
    }))
}

fn walk_der<'a>(mut items: &'a [Asn1], segs: &[&str], mut i: usize) -> Result<Pick<'a>, Diag> {
    loop {
        let idx: usize = segs[i].parse().map_err(|_| {
            Diag::new(
                "BAD_PATH",
                format!(
                    "invalid path segment '{}' (DER paths are child indices, e.g. 0.0.6)",
                    segs[i]
                ),
                None,
            )
        })?;
        let e = items
            .get(idx)
            .ok_or_else(|| not_found(format!("no element '{}'", at(segs, i + 1))))?;
        i += 1;
        if i == segs.len() {
            return Ok(Pick::Element(e));
        }
        items = e
            .children()
            .ok_or_else(|| no_children(segs, i, "the element"))?;
    }
}

fn walk_values<'a>(
    items: &'a [Value],
    segs: &[&str],
    mut i: usize,
    cx: &mut Option<Crossing<'a>>,
) -> Result<Pick<'a>, Diag> {
    let mut cur = if items.len() == 1 {
        &items[0]
    } else {
        let idx: usize = segs[i]
            .parse()
            .map_err(|_| bad_index(segs[i], "the CBOR/MessagePack sequence"))?;
        i += 1;
        items
            .get(idx)
            .ok_or_else(|| not_found(format!("no element '{}'", at(segs, i))))?
    };
    while i < segs.len() {
        let seg = segs[i];
        cur = match &cur.untagged().kind {
            ValueKind::Map(entries) => {
                let k = map_index(entries, seg)
                    .ok_or_else(|| not_found(format!("no key '{seg}' at '{}'", at(segs, i))))?;
                &entries[k].1
            }
            ValueKind::Array(arr) => {
                let idx: usize = seg
                    .parse()
                    .map_err(|_| not_found(format!("'{seg}' is not an array index")))?;
                arr.get(idx)
                    .ok_or_else(|| not_found(format!("no index '{idx}' at '{}'", at(segs, i))))?
            }
            // A byte string that decodes to another format.
            ValueKind::Bytes {
                decoded: Some(node),
                ..
            } => {
                *cx = Some(Crossing {
                    at: i,
                    holder: Holder::Value(cur),
                    node,
                });
                return walk(node, segs, i, cx);
            }
            ValueKind::Text(t) if is_json_doc(t) => return walk_json(t, segs, i),
            _ => return Err(no_children(segs, i, "the value")),
        };
        i += 1;
    }
    Ok(Pick::Value(cur))
}

fn walk_jwt<'a>(
    node: &'a Node,
    segs: &[&str],
    i: usize,
    cx: &mut Option<Crossing<'a>>,
) -> Result<Pick<'a>, Diag> {
    let rest = segs[i..].join(".");
    if i + 1 < segs.len() {
        let part = path::select_jwt(node, segs[i])?;
        if !part_is_json(&part) {
            // Not JSON (e.g. a JWE part, or a binary payload): continue in
            // whatever the part decodes to.
            *cx = Some(Crossing {
                at: i + 1,
                holder: Holder::Jwt,
                node: part.node,
            });
            return walk(part.node, segs, i + 1, cx);
        }
    }
    path::select_jwt(node, &rest).map(Pick::Jwt)
}

fn part_is_json(p: &JwtPick) -> bool {
    match &p.node.detail {
        crate::node::Detail::Layer { decoded, .. } => std::str::from_utf8(decoded)
            .is_ok_and(|t| crate::jsonpath::find(t, &[], p.part).is_ok()),
        _ => false,
    }
}
