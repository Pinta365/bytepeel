//! The decoded tree.
//!
//! Every `range` is a half-open `[start, end)` byte range into the buffer the
//! node or field was parsed from. A `Layer` node starts a new buffer (its
//! `decoded` bytes) for its child; a string's `decoded` node starts a new
//! buffer at that string's bytes.

use crate::Diag;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alphabet {
    Std,
    Url,
}

impl Alphabet {
    pub fn name(self) -> &'static str {
        match self {
            Alphabet::Std => "std",
            Alphabet::Url => "url",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Codec {
    Hex,
    Base64 { alphabet: Alphabet, padded: bool },
    Pem { label: String },
    Protobuf,
    Utf8,
    Bytes,
}

impl Codec {
    pub fn name(&self) -> &'static str {
        match self {
            Codec::Hex => "hex",
            Codec::Base64 { .. } => "base64",
            Codec::Pem { .. } => "pem",
            Codec::Protobuf => "protobuf",
            Codec::Utf8 => "utf8",
            Codec::Bytes => "bytes",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub codec: Codec,
    pub range: [usize; 2],
    /// How confident the detector is in `codec` (0..=1).
    pub confidence: f64,
    pub detail: Detail,
    pub warnings: Vec<Diag>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Detail {
    /// A text encoding (hex/base64/PEM); `child` describes the decoded bytes.
    Layer { decoded: Vec<u8>, child: Box<Node> },
    /// A protobuf message.
    Message { fields: Vec<Field> },
    /// Printable UTF-8 text.
    Text { text: String },
    /// Opaque bytes (nothing more specific was found, or the format is not yet supported).
    Bytes { bytes: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    pub number: u32,
    /// Range of the whole field, tag included.
    pub range: [usize; 2],
    pub value: FieldValue,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    Varint {
        raw: Vec<u8>,
        value: u64,
    },
    I64 {
        value: u64,
    },
    I32 {
        value: u32,
    },
    Len {
        data_range: [usize; 2],
        data: Vec<u8>,
        /// Interpretations, best first. Scores sum to ~1 before truncation.
        alts: Vec<Alt>,
    },
    Group {
        fields: Vec<Field>,
    },
}

impl FieldValue {
    pub fn wire_name(&self) -> &'static str {
        match self {
            FieldValue::Varint { .. } => "VARINT",
            FieldValue::I64 { .. } => "I64",
            FieldValue::I32 { .. } => "I32",
            FieldValue::Len { .. } => "LEN",
            FieldValue::Group { .. } => "GROUP",
        }
    }
}

impl Field {
    /// The field's payload bytes (tag excluded). `None` for groups.
    pub fn payload(&self) -> Option<Vec<u8>> {
        match &self.value {
            FieldValue::Varint { raw, .. } => Some(raw.clone()),
            FieldValue::I64 { value } => Some(value.to_le_bytes().to_vec()),
            FieldValue::I32 { value } => Some(value.to_le_bytes().to_vec()),
            FieldValue::Len { data, .. } => Some(data.clone()),
            FieldValue::Group { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Alt {
    pub kind: AltKind,
    pub score: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AltKind {
    Message(Vec<Field>),
    String {
        text: String,
        /// Set when the string itself decodes further (e.g. it is base64).
        decoded: Option<Box<Node>>,
    },
    PackedVarint(Vec<u64>),
    Bytes,
    Empty,
}

impl AltKind {
    pub fn name(&self) -> &'static str {
        match self {
            AltKind::Message(_) => "message",
            AltKind::String { .. } => "string",
            AltKind::PackedVarint(_) => "packed_varint",
            AltKind::Bytes => "bytes",
            AltKind::Empty => "empty",
        }
    }
}
