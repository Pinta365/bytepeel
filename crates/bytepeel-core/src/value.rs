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
    /// A MessagePack extension: its signed type and raw data.
    Ext {
        type_: i8,
        data: Vec<u8>,
    },
}

impl Value {
    /// The bytes `--format raw` writes: a byte string's or extension's bytes,
    /// or a text string's UTF-8. `None` for everything else.
    pub fn payload(&self) -> Option<Vec<u8>> {
        match &self.kind {
            ValueKind::Bytes { data, .. } => Some(data.clone()),
            ValueKind::Text(t) => Some(t.as_bytes().to_vec()),
            ValueKind::Ext { data, .. } => Some(data.clone()),
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
        ValueKind::Ext { .. } => "ext",
    }
}

/// Every map key anywhere in `values` is a text string.
///
/// Shared by CBOR and MessagePack detection (and available to the candidate
/// ranking). CBOR tags are followed.
/// Auto-detection confidence for a structurally valid CBOR/MessagePack tree.
///
/// Maps are the strong signal: 0.9 when every key is text or a small integer
/// (at most `max_uint` / `-1 - max_nint`), 0.7 with other keys. A tree with no
/// map at all (arrays of scalars) is weak evidence, since many protobuf
/// messages whose first tag is for field 16+ also parse that way: 0.6, so a
/// plausible protobuf reading (0.9) wins and the array shows up only in
/// `AMBIGUOUS_FORMAT`.
pub(crate) fn structure_confidence(values: &[Value], max_uint: u64, max_nint: u64) -> f64 {
    if !values.iter().any(contains_map) {
        0.6
    } else if keys_simple(values, max_uint, max_nint) {
        0.9
    } else {
        0.7
    }
}

fn contains_map(v: &Value) -> bool {
    match &v.kind {
        ValueKind::Map(_) => true,
        ValueKind::Array(items) => items.iter().any(contains_map),
        ValueKind::Tag(_, inner) => contains_map(inner),
        _ => false,
    }
}

pub(crate) fn keys_all_text(values: &[Value]) -> bool {
    values.iter().all(value_keys_all_text)
}

fn value_keys_all_text(v: &Value) -> bool {
    match &v.kind {
        ValueKind::Map(entries) => entries.iter().all(|(k, val)| {
            matches!(&k.untagged().kind, ValueKind::Text(_)) && value_keys_all_text(val)
        }),
        ValueKind::Array(items) => items.iter().all(value_keys_all_text),
        ValueKind::Tag(_, inner) => value_keys_all_text(inner),
        _ => true,
    }
}

/// Every map key anywhere in `values` is a text string, a `Uint` `<= max_uint`,
/// or a `Nint` whose stored `n` (value `-1 - n`) is `<= max_nint`.
///
/// Shared by CBOR (`23, 23`) and MessagePack (its fixint ranges, `127, 31`).
pub(crate) fn keys_simple(values: &[Value], max_uint: u64, max_nint: u64) -> bool {
    values
        .iter()
        .all(|v| value_keys_simple(v, max_uint, max_nint))
}

fn value_keys_simple(v: &Value, max_uint: u64, max_nint: u64) -> bool {
    match &v.kind {
        ValueKind::Map(entries) => entries.iter().all(|(k, val)| {
            is_simple_key(k, max_uint, max_nint) && value_keys_simple(val, max_uint, max_nint)
        }),
        ValueKind::Array(items) => items
            .iter()
            .all(|x| value_keys_simple(x, max_uint, max_nint)),
        ValueKind::Tag(_, inner) => value_keys_simple(inner, max_uint, max_nint),
        _ => true,
    }
}

fn is_simple_key(k: &Value, max_uint: u64, max_nint: u64) -> bool {
    match &k.untagged().kind {
        ValueKind::Text(_) => true,
        ValueKind::Uint(n) => *n <= max_uint,
        ValueKind::Nint(n) => *n <= max_nint,
        _ => false,
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
        ValueKind::Uint(n) if *n <= i64::MAX as u64 => iso_utc_checked(*n as i64),
        ValueKind::Nint(n) => {
            let val = -(*n as i128) - 1;
            if val >= i64::MIN as i128 {
                iso_utc_checked(val as i64)
            } else {
                None
            }
        }
        ValueKind::Float { value, .. } if value.is_finite() => {
            let secs = value.trunc();
            if (-9.223_372_036_854_776e18..=9.223_372_036_854_776e18).contains(&secs) {
                iso_utc_checked(secs as i64)
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
/// This is unchecked: a year outside `0000..=9999` is formatted with a wrong
/// width. Callers that put the result in output use [`iso_utc_checked`].
pub(crate) fn iso_utc(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);
    let (h, mi, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// True when epoch seconds fall in a year RFC 3339 can represent (0000..=9999).
fn in_year_range(epoch: i64) -> bool {
    let (y, _, _) = civil_from_days(epoch.div_euclid(86_400));
    (0..=9999).contains(&y)
}

/// Like [`iso_utc`], but `None` when the year is outside `0000..=9999`.
///
/// Shared by CBOR tag 1, MessagePack timestamps and JWT `exp`/`nbf`/`iat`, so
/// none of them emit an out-of-range (malformed) date.
pub(crate) fn iso_utc_checked(epoch: i64) -> Option<String> {
    in_year_range(epoch).then(|| iso_utc(epoch))
}

/// Epoch seconds plus nanoseconds to ISO-8601 UTC, trimming trailing zero
/// digits from the fraction (so whole seconds get no fraction at all).
fn iso_utc_nanos(secs: i64, nanos: u32) -> String {
    let base = iso_utc(secs);
    if nanos == 0 {
        return base;
    }
    let frac = format!("{nanos:09}");
    let frac = frac.trim_end_matches('0');
    format!("{}.{}Z", &base[..base.len() - 1], frac)
}

/// Like [`iso_utc_nanos`], but `None` outside the `0000..=9999` year range.
pub(crate) fn iso_utc_nanos_checked(secs: i64, nanos: u32) -> Option<String> {
    in_year_range(secs).then(|| iso_utc_nanos(secs, nanos))
}

/// A MessagePack timestamp extension (type -1) as ISO-8601 UTC.
///
/// Handles the 4-byte (seconds), 8-byte (30-bit nanoseconds + 34-bit seconds)
/// and 12-byte (nanoseconds + signed seconds, for dates before 1970) forms.
pub(crate) fn ext_iso(type_: i8, data: &[u8]) -> Option<String> {
    if type_ != -1 {
        return None;
    }
    let (secs, nanos) = match data.len() {
        4 => (
            i64::from(u32::from_be_bytes([data[0], data[1], data[2], data[3]])),
            0,
        ),
        8 => {
            let v = u64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]);
            ((v & 0x3_FFFF_FFFF) as i64, (v >> 34) as u32)
        }
        12 => (
            i64::from_be_bytes([
                data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
            ]),
            u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
        ),
        _ => return None,
    };
    if nanos >= 1_000_000_000 {
        return None;
    }
    iso_utc_nanos_checked(secs, nanos)
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
    fn iso_year_range() {
        // In range, including before 1970.
        assert_eq!(iso_utc_checked(-1).unwrap(), "1969-12-31T23:59:59Z");
        assert_eq!(
            iso_utc_nanos_checked(-1, 500_000_000).unwrap(),
            "1969-12-31T23:59:59.5Z"
        );
        // 9999-12-31T23:59:59Z is the last representable second.
        assert_eq!(
            iso_utc_checked(253_402_300_799).unwrap(),
            "9999-12-31T23:59:59Z"
        );
        // Year 10000 and i64::MIN are out of RFC 3339 range.
        assert!(iso_utc_checked(253_402_300_800).is_none());
        assert!(iso_utc_checked(i64::MIN).is_none());
        assert!(iso_utc_nanos_checked(i64::MIN, 0).is_none());
    }

    #[test]
    fn key_thresholds() {
        let v = |kind| Value {
            range: [0, 0],
            kind,
            indefinite: false,
        };
        let map = |k| v(ValueKind::Map(vec![(k, v(ValueKind::Null))]));
        // CBOR allows 23, MessagePack's fixint range allows 127.
        assert!(keys_simple(&[map(v(ValueKind::Uint(23)))], 23, 23));
        assert!(!keys_simple(&[map(v(ValueKind::Uint(24)))], 23, 23));
        assert!(keys_simple(&[map(v(ValueKind::Uint(24)))], 127, 31));
        assert!(!keys_simple(&[map(v(ValueKind::Uint(128)))], 127, 31));
        // Nint stores -1 - value: 23 means -24.
        assert!(keys_simple(&[map(v(ValueKind::Nint(23)))], 23, 23));
        assert!(!keys_simple(&[map(v(ValueKind::Nint(24)))], 23, 23));
        assert!(keys_simple(&[map(v(ValueKind::Nint(31)))], 127, 31));
        assert!(!keys_simple(&[map(v(ValueKind::Nint(32)))], 127, 31));
        // Non-integer keys.
        assert!(keys_simple(&[map(v(ValueKind::Text("k".into())))], 23, 23));
        assert!(!keys_simple(&[map(v(ValueKind::Bool(true)))], 127, 31));
        // All-text is stricter, and recursion reaches nested maps.
        assert!(keys_all_text(&[map(v(ValueKind::Text("k".into())))]));
        assert!(!keys_all_text(&[map(v(ValueKind::Uint(1)))]));
        let nested = v(ValueKind::Array(vec![map(v(ValueKind::Uint(1)))]));
        assert!(keys_simple(std::slice::from_ref(&nested), 23, 23));
        assert!(!keys_all_text(std::slice::from_ref(&nested)));
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
