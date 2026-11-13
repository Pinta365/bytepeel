//! Zero-dependency recursive decoder for encoded and binary data.
//!
//! `bytepeel-core` takes opaque input (a hex dump, a base64 blob, a PEM block,
//! raw bytes) and peels it layer by layer into a [`Node`] tree. Where the bytes
//! are genuinely ambiguous (a protobuf length-delimited field could be a string,
//! a submessage or packed varints) it keeps the top interpretations with scores
//! instead of silently picking one.
//!
//! ```
//! use bytepeel_core::{peel, Options, Detail};
//!
//! let node = peel(b"SGVsbG8gd29ybGQ=", &Options::default()).unwrap();
//! assert_eq!(node.codec.name(), "base64");
//! let Detail::Layer { child, .. } = &node.detail else { panic!() };
//! assert!(matches!(&child.detail, Detail::Text { text } if text == "Hello world"));
//! ```
#![forbid(unsafe_code)]

mod cbor;
mod compress;
mod der;
mod detect;
mod dump;
mod edit;
mod encode_value;
mod error;
mod json;
mod jwt;
mod msgpack;
mod node;
mod path;
mod protobuf;
mod reencode;
mod text;
mod tree;
mod value;
pub mod varint;

pub use edit::{NewValue, parse_value, set};
pub use error::Diag;
pub use node::{
    Alphabet, Alt, AltKind, Asn1, Asn1Value, Codec, Detail, Field, FieldValue, Node, TagClass,
};
pub use path::{is_der, is_values, select, select_der, select_value};
pub use text::{B64, decode_b64, decode_hex};
pub use value::{Value, ValueKind};

/// How to read the top-level input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputForm {
    /// Detect hex / base64 / PEM text, otherwise treat as raw bytes.
    Auto,
    /// The input is hex text (whitespace, `:` and `0x` prefixes allowed).
    Hex,
    /// The input is base64 text (standard or URL-safe, padded or not).
    Base64,
    /// The input is raw bytes; no text encoding is detected at the top level.
    Raw,
}

/// Force the interpretation of the first non-text-encoding layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Force {
    Protobuf,
    Der,
    Cbor,
    Msgpack,
    Text,
    Bytes,
}

/// Decoding options.
#[derive(Debug, Clone)]
pub struct Options {
    /// Maximum nesting of layers and protobuf messages.
    pub depth: usize,
    /// Maximum interpretations kept per protobuf LEN field (at least 1).
    pub alts: usize,
    /// How to read the top-level input.
    pub input: InputForm,
    /// Force the interpretation of the first decoded byte layer.
    pub force: Option<Force>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            depth: 16,
            alts: 3,
            input: InputForm::Auto,
            force: None,
        }
    }
}

/// Decode `input` into a tree of layers.
///
/// Auto-detection never fails: anything undecodable ends as a `bytes` leaf.
/// Errors are only returned when the caller forced a form (`InputForm::Hex`,
/// `InputForm::Base64`, or `Options::force`) and the data does not match it.
pub fn peel(input: &[u8], opts: &Options) -> Result<Node, Diag> {
    detect::peel(input, opts)
}

/// Serialize a node tree as compact JSON. See `docs/DESIGN.md` for the schema.
pub fn to_json(node: &Node) -> String {
    json::node_to_json(node)
}

/// Serialize a single protobuf field (e.g. the result of [`select`]) as JSON.
pub fn field_to_json(field: &Field) -> String {
    json::field_to_json(field)
}

/// Serialize a diagnostic as `{"error":{"code":..,"message":..,"offset":..}}`.
pub fn diag_to_json(diag: &Diag) -> String {
    json::diag_to_json(diag)
}

/// Render a node tree as an indented, human-readable outline.
pub fn to_tree(node: &Node) -> String {
    tree::node_to_tree(node)
}

/// Serialize a single CBOR value (e.g. the result of [`select_value`]) as JSON.
pub fn value_to_json(v: &Value) -> String {
    json::value_to_json(v)
}

/// Render a single CBOR value as an indented outline.
pub fn value_to_tree(v: &Value) -> String {
    tree::value_to_tree(v)
}

/// Serialize a single DER element (e.g. the result of [`select_der`]) as JSON.
pub fn asn1_to_json(e: &Asn1) -> String {
    json::asn1_to_json(e)
}

/// Render a single DER element as an indented outline.
pub fn asn1_to_tree(e: &Asn1) -> String {
    tree::asn1_to_tree(e)
}

/// Render a single protobuf field as an indented outline.
pub fn field_to_tree(field: &Field) -> String {
    tree::field_to_tree(field)
}
