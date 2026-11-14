//! The decoded tree.
//!
//! Every `range` is a half-open `[start, end)` byte range into the buffer the
//! node or field was parsed from. A `Layer` node starts a new buffer (its
//! `decoded` bytes) for its child; a string's `decoded` node starts a new
//! buffer at that string's bytes.

use crate::Diag;
use crate::value::Value;

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
    /// A hex dump with an offset column (`style` is `xxd` or `hexdump`).
    /// `start` is the decimal offset the first line starts at (nonzero for
    /// `xxd -s` / `hexdump -s`); child ranges stay 0-based.
    Dump {
        style: &'static str,
        start: usize,
    },
    Base64 {
        alphabet: Alphabet,
        padded: bool,
    },
    Pem {
        label: String,
    },
    /// Two or more PEM blocks: a certificate chain or a key + cert file.
    Bundle,
    /// A JSON Web Token; `kind` is `jws` (3 parts) or `jwe` (5 parts).
    Jwt {
        kind: &'static str,
    },
    /// gzip; `name` is the original file name from the header, if any.
    Gzip {
        name: Option<String>,
    },
    Zlib,
    Zstd,
    Protobuf,
    Der,
    /// CBOR (RFC 8949): a sequence of one or more [`Value`]s.
    Cbor,
    /// MessagePack: a sequence of one or more [`Value`]s.
    Msgpack,
    Utf8,
    Bytes,
}

impl Codec {
    pub fn name(&self) -> &'static str {
        match self {
            Codec::Hex => "hex",
            Codec::Dump { .. } => "dump",
            Codec::Base64 { .. } => "base64",
            Codec::Pem { .. } => "pem",
            Codec::Bundle => "bundle",
            Codec::Jwt { .. } => "jwt",
            Codec::Gzip { .. } => "gzip",
            Codec::Zlib => "zlib",
            Codec::Zstd => "zstd",
            Codec::Protobuf => "protobuf",
            Codec::Der => "der",
            Codec::Cbor => "cbor",
            Codec::Msgpack => "msgpack",
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

/// Bytes kept in a [`Detail::Bytes`] leaf for its preview.
pub const BYTES_HEAD: usize = 64;

/// Characters kept in a [`Detail::Text`] leaf.
pub const TEXT_HEAD: usize = 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum Detail {
    /// A text encoding (hex/base64/PEM); `child` describes the decoded bytes.
    Layer { decoded: Vec<u8>, child: Box<Node> },
    /// A protobuf message.
    Message { fields: Vec<Field> },
    /// DER-encoded ASN.1: one or more top-level elements.
    Der { items: Vec<Asn1> },
    /// CBOR or MessagePack: normally one top-level value; a sequence may have
    /// several when forced with `--as cbor` / `--as msgpack`.
    Values { items: Vec<Value> },
    /// A JWT or a PEM bundle: one node per part (base64 segments, or PEM
    /// blocks). `times` is `Detail::Parts`' only JWT-specific field: the
    /// top-level time claims of a JWS payload (`exp`, `nbf`, `iat`), in that
    /// order, as `(claim, ISO-8601 UTC)`; it is empty for bundles.
    Parts {
        parts: Vec<Node>,
        times: Vec<(&'static str, String)>,
    },
    /// Printable UTF-8 text. Only the first [`TEXT_HEAD`] characters are kept
    /// (what the JSON shows): the full text is the parent's bytes, so a large
    /// text is not stored twice.
    Text {
        /// The first `TEXT_HEAD` characters (all of a shorter text).
        text: String,
        /// Byte length of the whole text; `text` is all of it when equal.
        len: usize,
    },
    /// Opaque bytes (nothing more specific was found, or the format is not
    /// yet supported). Only the first [`BYTES_HEAD`] bytes are kept, for the
    /// preview: the full bytes are the parent's (the input, a layer's
    /// `decoded`, a field's or value's data), so a large leaf is not stored twice.
    Bytes {
        /// Length of the whole leaf.
        len: usize,
        /// Its first `min(len, BYTES_HEAD)` bytes.
        head: Vec<u8>,
    },
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
    /// Little-endian 4-byte values (packed `fixed32` / `sfixed32` / `float`).
    PackedFixed32(Vec<u32>),
    /// Little-endian 8-byte values (packed `fixed64` / `sfixed64` / `double`).
    PackedFixed64(Vec<u64>),
    Bytes {
        /// Set when the raw bytes are themselves another format (compressed,
        /// DER, CBOR/MessagePack); see `docs/DESIGN.md` for the threshold.
        decoded: Option<Box<Node>>,
    },
    Empty,
}

impl AltKind {
    pub fn name(&self) -> &'static str {
        match self {
            AltKind::Message(_) => "message",
            AltKind::String { .. } => "string",
            AltKind::PackedVarint(_) => "packed_varint",
            AltKind::PackedFixed32(_) => "packed_fixed32",
            AltKind::PackedFixed64(_) => "packed_fixed64",
            AltKind::Bytes { .. } => "bytes",
            AltKind::Empty => "empty",
        }
    }
}

/// ASN.1 tag class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagClass {
    Universal,
    Application,
    Context,
    Private,
}

/// One DER element (tag, length, value).
#[derive(Debug, Clone, PartialEq)]
pub struct Asn1 {
    pub class: TagClass,
    pub number: u32,
    pub constructed: bool,
    /// Range of the whole element, header included.
    pub range: [usize; 2],
    /// Range of the content (header excluded).
    pub content: [usize; 2],
    /// Content bytes of a primitive element (empty when constructed).
    pub raw: Vec<u8>,
    pub value: Asn1Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Asn1Value {
    /// A constructed element (SEQUENCE, SET, `[0]`, ...).
    Constructed(Vec<Asn1>),
    /// A BIT STRING or OCTET STRING whose content is itself DER.
    /// `unused_bits` is `Some(0)` for a BIT STRING.
    Encapsulated {
        unused_bits: Option<u8>,
        items: Vec<Asn1>,
    },
    Bool(bool),
    /// INTEGER or ENUMERATED; the value is `raw` (big-endian two's complement).
    Int,
    Null,
    /// OBJECT IDENTIFIER or RELATIVE-OID in dotted form.
    Oid(String),
    /// A character string, decoded per its type.
    Text(String),
    /// UTCTime or GeneralizedTime; `iso` is set when the value is well formed.
    Time {
        text: String,
        iso: Option<String>,
    },
    /// A BIT STRING that is not itself DER; the bits are `raw[1..]`.
    BitString {
        unused_bits: u8,
    },
    /// Anything else; the content is `raw`.
    Bytes,
}

impl Asn1 {
    /// Human-readable tag, e.g. `SEQUENCE`, `[0]`, `[APPLICATION 3]`.
    pub fn tag_name(&self) -> String {
        match self.class {
            TagClass::Universal => match crate::der::universal_name(self.number) {
                Some(n) => n.to_string(),
                None => format!("[UNIVERSAL {}]", self.number),
            },
            TagClass::Application => format!("[APPLICATION {}]", self.number),
            TagClass::Context => format!("[{}]", self.number),
            TagClass::Private => format!("[PRIVATE {}]", self.number),
        }
    }

    /// The element's payload: content bytes, minus the unused-bits byte for a
    /// BIT STRING. `None` for constructed elements.
    pub fn payload(&self) -> Option<Vec<u8>> {
        if self.constructed {
            return None;
        }
        match self.value {
            Asn1Value::BitString { .. }
            | Asn1Value::Encapsulated {
                unused_bits: Some(_),
                ..
            } => Some(self.raw.get(1..).unwrap_or_default().to_vec()),
            _ => Some(self.raw.clone()),
        }
    }

    /// Child elements, for constructed or encapsulating elements.
    pub fn children(&self) -> Option<&[Asn1]> {
        match &self.value {
            Asn1Value::Constructed(items) | Asn1Value::Encapsulated { items, .. } => Some(items),
            _ => None,
        }
    }
}
