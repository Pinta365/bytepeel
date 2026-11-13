//! A codec-neutral value tree, shared by CBOR (RFC 8949) and, later,
//! MessagePack. Values carry byte ranges like the rest of the tree.

use crate::node::Node;

/// One decoded value: a byte range and its kind.
#[derive(Debug, Clone, PartialEq)]
pub struct Value {
    pub range: [usize; 2],
    pub kind: ValueKind,
    /// True when this value used an indefinite-length form (CBOR).
    pub indefinite: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ValueKind {
    Uint(u64),
    /// `-1 - n` (CBOR major type 1).
    Nint(u64),
    /// A float, remembering its source width (16, 32 or 64 bits).
    Float {
        value: f64,
        width: u8,
    },
    Bool(bool),
    Null,
    Undefined,
    /// A CBOR simple value (0..=255).
    Simple(u8),
    Bytes {
        data: Vec<u8>,
        /// Set when the bytes are themselves CBOR/DER/protobuf/... .
        decoded: Option<Box<Node>>,
    },
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Tag(u64, Box<Value>),
}

impl Value {
    /// The bytes `--format raw` writes: a byte string's bytes, or a text
    /// string's UTF-8. `None` for everything else.
    pub fn payload(&self) -> Option<Vec<u8>> {
        match &self.kind {
            ValueKind::Bytes { data, .. } => Some(data.clone()),
            ValueKind::Text(t) => Some(t.as_bytes().to_vec()),
            _ => None,
        }
    }

    /// The innermost value, following tags.
    pub fn untagged(&self) -> &Value {
        match &self.kind {
            ValueKind::Tag(_, inner) => inner.untagged(),
            _ => self,
        }
    }
}

/// The JSON/tree discriminant for a value kind.
pub(crate) fn type_name(k: &ValueKind) -> &'static str {
    match k {
        ValueKind::Uint(_) => "uint",
        ValueKind::Nint(_) => "nint",
        ValueKind::Float { .. } => "float",
        ValueKind::Bool(_) => "bool",
        ValueKind::Null => "null",
        ValueKind::Undefined => "undefined",
        ValueKind::Simple(_) => "simple",
        ValueKind::Bytes { .. } => "bytes",
        ValueKind::Text(_) => "text",
        ValueKind::Array(_) => "array",
        ValueKind::Map(_) => "map",
        ValueKind::Tag(..) => "tag",
    }
}

/// Well-known CBOR tag names (RFC 8949 Appendix B and common registrations).
pub(crate) fn tag_name(n: u64) -> Option<&'static str> {
    Some(match n {
        0 => "datetime",
        1 => "epoch",
        2 => "bignum",
        3 => "negbignum",
        4 => "decimal",
        5 => "bigfloat",
        21 => "base64url",
        22 => "base64",
        23 => "base16",
        24 => "cbor",
        32 => "uri",
        37 => "uuid",
        55799 => "self-describe",
        _ => return None,
    })
}

/// A tag-1 (epoch) value as an ISO-8601 UTC string, when it is a number.
pub(crate) fn epoch_iso(v: &Value) -> Option<String> {
    match &v.kind {
        ValueKind::Uint(n) if *n <= i64::MAX as u64 => Some(iso_utc(*n as i64)),
        ValueKind::Nint(n) => {
            let val = -(*n as i128) - 1;
            if val >= i64::MIN as i128 {
                Some(iso_utc(val as i64))
            } else {
                None
            }
        }
        ValueKind::Float { value, .. } if value.is_finite() => {
            let secs = value.trunc();
            if (-9.223_372_036_854_776e18..=9.223_372_036_854_776e18).contains(&secs) {
                Some(iso_utc(secs as i64))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// A CBOR bignum (tag 2/3) as a decimal string. `data` is the big-endian
/// unsigned magnitude; tag 3 means `-1 - magnitude`.
pub(crate) fn bignum_decimal(data: &[u8], negative: bool) -> String {
    let mut mag = data.to_vec();
    if negative {
        let mut carry = true;
        for b in mag.iter_mut().rev() {
            if !carry {
                break;
            }
            let (v, c) = b.overflowing_add(1);
            *b = v;
            carry = c;
        }
        if carry {
            mag.insert(0, 1);
        }
    }
    let mut signed = vec![0u8];
    signed.extend_from_slice(&mag);
    let d = crate::der::int_decimal(&signed);
    if negative { format!("-{d}") } else { d }
}

/// A 16-byte value as a canonical UUID string.
pub(crate) fn uuid_string(data: &[u8]) -> String {
    let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Epoch seconds to `YYYY-MM-DDTHH:MM:SSZ` (Howard Hinnant's `civil_from_days`).
///
/// Shared by CBOR tag 1 and JWT `exp`/`nbf`/`iat`.
pub(crate) fn iso_utc(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);
    let (h, mi, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Days since 1970-01-01 -> (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc(-1), "1969-12-31T23:59:59Z");
        assert_eq!(iso_utc(1_363_896_240), "2013-03-21T20:04:00Z");
    }

    #[test]
    fn bignums() {
        // 2^64 = 18446744073709551616
        assert_eq!(
            bignum_decimal(&[1, 0, 0, 0, 0, 0, 0, 0, 0], false),
            "18446744073709551616"
        );
        // -1 - 2^64 = -18446744073709551617
        assert_eq!(
            bignum_decimal(&[1, 0, 0, 0, 0, 0, 0, 0, 0], true),
            "-18446744073709551617"
        );
        assert_eq!(bignum_decimal(&[], true), "-1");
        assert_eq!(bignum_decimal(&[], false), "0");
    }

    #[test]
    fn uuids() {
        assert_eq!(
            uuid_string(&[
                0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                0x77, 0x88
            ]),
            "12345678-9abc-def0-1122-334455667788"
        );
    }
}
