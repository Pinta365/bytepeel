//! DER-encoded ASN.1 (definite lengths only; BER indefinite length is rejected).
//!
//! BIT STRING and OCTET STRING contents that are themselves well-formed DER
//! (X.509 extensions, public keys, ECDSA signatures) are decoded in place;
//! their children keep absolute offsets in the same buffer.

use crate::Diag;
use crate::node::{Asn1, Asn1Value, TagClass};

/// Maximum nesting of constructed and encapsulated elements.
const MAX_NEST: usize = 100;

#[derive(Default)]
pub(crate) struct Stats {
    /// Non-minimal length or integer encodings (valid BER, not DER).
    pub noncanonical: usize,
    /// Universal-tag elements whose content did not match their type.
    pub malformed: usize,
}

pub(crate) fn parse(buf: &[u8], st: &mut Stats) -> Result<Vec<Asn1>, Diag> {
    items(buf, 0, buf.len(), 0, st)
}

/// Auto-detection: the buffer must be exactly one well-formed SEQUENCE.
/// Returns the items and a confidence.
pub(crate) fn detect(buf: &[u8]) -> Option<(Vec<Asn1>, Stats)> {
    if buf.len() < 4 || buf[0] != 0x30 {
        return None;
    }
    let mut st = Stats::default();
    let items = parse(buf, &mut st).ok()?;
    if items.len() != 1 || st.malformed > 0 {
        return None;
    }
    Some((items, st))
}

pub(crate) fn confidence(st: &Stats) -> f64 {
    if st.noncanonical > 0 { 0.8 } else { 0.95 }
}

struct Header {
    class: TagClass,
    constructed: bool,
    number: u32,
    content: [usize; 2],
}

fn truncated(off: usize) -> Diag {
    Diag::new(
        "TRUNCATED_ELEMENT",
        "ASN.1 element runs past the end of its container",
        Some(off),
    )
}

fn header(buf: &[u8], pos: usize, end: usize, st: &mut Stats) -> Result<Header, Diag> {
    if pos >= end {
        return Err(truncated(pos));
    }
    let b0 = buf[pos];
    let class = match b0 >> 6 {
        0 => TagClass::Universal,
        1 => TagClass::Application,
        2 => TagClass::Context,
        _ => TagClass::Private,
    };
    let constructed = b0 & 0x20 != 0;
    let mut i = pos + 1;
    let mut number = u32::from(b0 & 0x1f);
    if number == 0x1f {
        number = 0;
        loop {
            if i >= end {
                return Err(truncated(i));
            }
            let b = buf[i];
            i += 1;
            if number > (u32::MAX >> 7) {
                return Err(Diag::new(
                    "BAD_TAG",
                    "tag number exceeds 32 bits",
                    Some(pos),
                ));
            }
            number = (number << 7) | u32::from(b & 0x7f);
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    if i >= end {
        return Err(truncated(i));
    }
    let lpos = i;
    let l0 = buf[i];
    i += 1;
    let len = if l0 < 0x80 {
        usize::from(l0)
    } else if l0 == 0x80 {
        return Err(Diag::new(
            "INDEFINITE_LENGTH",
            "indefinite length (BER) is not supported",
            Some(lpos),
        ));
    } else {
        let n = usize::from(l0 & 0x7f);
        if n > 8 {
            return Err(Diag::new(
                "BAD_LENGTH",
                format!("length uses {n} bytes (at most 8 supported)"),
                Some(lpos),
            ));
        }
        if n > end - i {
            return Err(truncated(lpos));
        }
        let v = buf[i..i + n]
            .iter()
            .fold(0u64, |a, &b| (a << 8) | u64::from(b));
        if v < 0x80 || buf[i] == 0 {
            st.noncanonical += 1;
        }
        i += n;
        usize::try_from(v).map_err(|_| truncated(lpos))?
    };
    if len > end - i {
        return Err(truncated(lpos));
    }
    Ok(Header {
        class,
        constructed,
        number,
        content: [i, i + len],
    })
}

fn items(buf: &[u8], s: usize, e: usize, nest: usize, st: &mut Stats) -> Result<Vec<Asn1>, Diag> {
    if nest > MAX_NEST {
        return Err(Diag::new(
            "NESTING_TOO_DEEP",
            format!("more than {MAX_NEST} nested ASN.1 elements"),
            Some(s),
        ));
    }
    let mut out = Vec::new();
    let mut pos = s;
    while pos < e {
        let h = header(buf, pos, e, st)?;
        let [cs, ce] = h.content;
        let (raw, value) = if h.constructed {
            if h.class == TagClass::Universal && !matches!(h.number, 8 | 11 | 16 | 17 | 29) {
                // Constructed strings are BER-only.
                st.malformed += 1;
            }
            (
                Vec::new(),
                Asn1Value::Constructed(items(buf, cs, ce, nest + 1, st)?),
            )
        } else {
            let c = &buf[cs..ce];
            let v = if h.class == TagClass::Universal {
                primitive(buf, h.number, cs, ce, nest, st)
            } else {
                Asn1Value::Bytes
            };
            (c.to_vec(), v)
        };
        out.push(Asn1 {
            class: h.class,
            number: h.number,
            constructed: h.constructed,
            range: [pos, ce],
            content: h.content,
            raw,
            value,
        });
        pos = ce;
    }
    Ok(out)
}

fn primitive(
    buf: &[u8],
    number: u32,
    cs: usize,
    ce: usize,
    nest: usize,
    st: &mut Stats,
) -> Asn1Value {
    let c = &buf[cs..ce];
    let v = match number {
        1 if c.len() == 1 => Some(Asn1Value::Bool(c[0] != 0)),
        2 | 10 if !c.is_empty() => {
            if c.len() > 1 && ((c[0] == 0 && c[1] < 0x80) || (c[0] == 0xff && c[1] >= 0x80)) {
                st.noncanonical += 1;
            }
            Some(Asn1Value::Int)
        }
        3 if !c.is_empty() && c[0] <= 7 => {
            let unused = c[0];
            Some(
                match (unused == 0)
                    .then(|| encapsulated(buf, cs + 1, ce, nest))
                    .flatten()
                {
                    Some(items) => Asn1Value::Encapsulated {
                        unused_bits: Some(0),
                        items,
                    },
                    None => Asn1Value::BitString {
                        unused_bits: unused,
                    },
                },
            )
        }
        4 => Some(match encapsulated(buf, cs, ce, nest) {
            Some(items) => Asn1Value::Encapsulated {
                unused_bits: None,
                items,
            },
            None => Asn1Value::Bytes,
        }),
        5 if c.is_empty() => Some(Asn1Value::Null),
        6 => oid(c, false).map(Asn1Value::Oid),
        13 => oid(c, true).map(Asn1Value::Oid),
        12 | 18 | 19 | 22 | 25 | 26 | 27 => std::str::from_utf8(c)
            .ok()
            .map(|t| Asn1Value::Text(t.to_string())),
        20 | 21 => Some(Asn1Value::Text(c.iter().map(|&b| char::from(b)).collect())),
        30 => utf16be(c).map(Asn1Value::Text),
        28 => utf32be(c).map(Asn1Value::Text),
        23 | 24 => std::str::from_utf8(c).ok().map(|t| Asn1Value::Time {
            text: t.to_string(),
            iso: time_iso(t, number == 23),
        }),
        // Types with no special rendering: shown as bytes.
        7 | 8 | 9 | 11 | 14 | 29 => Some(Asn1Value::Bytes),
        _ => None,
    };
    v.unwrap_or_else(|| {
        st.malformed += 1;
        Asn1Value::Bytes
    })
}

/// Decode `[s, e)` as nested DER if it is cleanly and completely DER.
fn encapsulated(buf: &[u8], s: usize, e: usize, nest: usize) -> Option<Vec<Asn1>> {
    if e - s < 2 {
        return None;
    }
    let mut st = Stats::default();
    let items = items(buf, s, e, nest + 1, &mut st).ok()?;
    if st.malformed > 0 || st.noncanonical > 0 {
        return None;
    }
    // A lone primitive with a non-universal tag (or an untyped universal one)
    // is too weak a signal: random bytes parse that way too often.
    if let [only] = &items[..] {
        if !only.constructed
            && (only.class != TagClass::Universal
                || (matches!(only.value, Asn1Value::Bytes) && only.number != 4))
        {
            return None;
        }
    }
    Some(items)
}

fn oid(c: &[u8], relative: bool) -> Option<String> {
    if c.is_empty() || c[c.len() - 1] & 0x80 != 0 {
        return None;
    }
    let mut arcs: Vec<u128> = Vec::new();
    let mut v: u128 = 0;
    let mut start = true;
    for &b in c {
        if start && b == 0x80 {
            return None; // non-minimal subidentifier
        }
        if v > (u128::MAX >> 7) {
            return None;
        }
        v = (v << 7) | u128::from(b & 0x7f);
        start = b & 0x80 == 0;
        if start {
            arcs.push(v);
            v = 0;
        }
    }
    let mut out = String::new();
    for (i, a) in arcs.iter().enumerate() {
        if i == 0 && !relative {
            let (x, y) = match *a {
                a if a < 40 => (0, a),
                a if a < 80 => (1, a - 40),
                a => (2, a - 80),
            };
            out.push_str(&format!("{x}.{y}"));
        } else {
            if !out.is_empty() {
                out.push('.');
            }
            out.push_str(&a.to_string());
        }
    }
    Some(out)
}

fn utf16be(c: &[u8]) -> Option<String> {
    if c.len() % 2 != 0 {
        return None;
    }
    let units = c.chunks(2).map(|p| u16::from_be_bytes([p[0], p[1]]));
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .ok()
}

fn utf32be(c: &[u8]) -> Option<String> {
    if c.len() % 4 != 0 {
        return None;
    }
    c.chunks(4)
        .map(|p| char::from_u32(u32::from_be_bytes([p[0], p[1], p[2], p[3]])))
        .collect()
}

/// ISO 8601 form of a UTCTime (`YYMMDDHHMM[SS]Z|±hhmm`) or GeneralizedTime
/// (`YYYYMMDDHH[MM[SS[.f+]]][Z|±hhmm]`). `None` if malformed.
pub(crate) fn time_iso(t: &str, utc: bool) -> Option<String> {
    // Valid times are ASCII. Bailing out here also keeps every `&t[..]` slice
    // below on a char boundary (multi-byte UTF-8 used to panic).
    if !t.is_ascii() {
        return None;
    }
    let b = t.as_bytes();
    let digits = b.iter().take_while(|c| c.is_ascii_digit()).count();
    let (year, rest) = if utc {
        let yy: u32 = t.get(..2)?.parse().ok()?;
        (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
    } else {
        (t.get(..4)?.parse().ok()?, 4)
    };
    let date_digits = digits.checked_sub(rest)?;
    // MMDDHH, then optional minutes and seconds (UTCTime requires minutes).
    if !matches!(date_digits, 8 | 10) && !(date_digits == 6 && !utc) {
        return None;
    }
    let two = |i: usize| -> Option<u32> { t.get(i..i + 2)?.parse().ok() };
    let (mo, d, h) = (two(rest)?, two(rest + 2)?, two(rest + 4)?);
    let mi = if date_digits >= 8 { two(rest + 6)? } else { 0 };
    let s = if date_digits == 10 { two(rest + 8)? } else { 0 };
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let mut i = digits;
    let mut frac = "";
    if !utc && b.get(i) == Some(&b'.') {
        let n = b[i + 1..].iter().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 {
            return None;
        }
        frac = &t[i..i + 1 + n];
        i += 1 + n;
    }
    let zone = match &t[i..] {
        "Z" => "Z".to_string(),
        "" if !utc => String::new(),
        z if z.len() == 5 && (z.starts_with('+') || z.starts_with('-')) => {
            let (zh, zm): (u32, u32) = (z[1..3].parse().ok()?, z[3..5].parse().ok()?);
            if zh > 23 || zm > 59 {
                return None;
            }
            format!("{}:{}", &z[..3], &z[3..])
        }
        _ => return None,
    };
    Some(format!(
        "{year:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}{frac}{zone}"
    ))
}

/// Widest INTEGER rendered in decimal; wider ones (RSA moduli) are hex only.
pub(crate) const INT_DECIMAL_MAX: usize = 16;

/// Big-endian two's complement integer as a decimal string (any width).
pub(crate) fn int_decimal(c: &[u8]) -> String {
    if c.is_empty() {
        return "0".into();
    }
    let neg = c[0] & 0x80 != 0;
    let mut mag: Vec<u8> = c.to_vec();
    if neg {
        // Magnitude of a negative number: invert and add one.
        for b in mag.iter_mut() {
            *b = !*b;
        }
        for b in mag.iter_mut().rev() {
            let (v, carry) = b.overflowing_add(1);
            *b = v;
            if !carry {
                break;
            }
        }
    }
    let mut digits = Vec::new();
    while mag.iter().any(|&b| b != 0) {
        let mut rem = 0u32;
        for b in mag.iter_mut() {
            let cur = (rem << 8) | u32::from(*b);
            *b = (cur / 10) as u8;
            rem = cur % 10;
        }
        digits.push(b'0' + rem as u8);
    }
    if digits.is_empty() {
        digits.push(b'0');
    }
    if neg {
        digits.push(b'-');
    }
    digits.reverse();
    String::from_utf8(digits).expect("ascii digits")
}

pub(crate) fn universal_name(n: u32) -> Option<&'static str> {
    Some(match n {
        0 => "END OF CONTENTS",
        1 => "BOOLEAN",
        2 => "INTEGER",
        3 => "BIT STRING",
        4 => "OCTET STRING",
        5 => "NULL",
        6 => "OBJECT IDENTIFIER",
        7 => "ObjectDescriptor",
        8 => "EXTERNAL",
        9 => "REAL",
        10 => "ENUMERATED",
        11 => "EMBEDDED PDV",
        12 => "UTF8String",
        13 => "RELATIVE-OID",
        14 => "TIME",
        16 => "SEQUENCE",
        17 => "SET",
        18 => "NumericString",
        19 => "PrintableString",
        20 => "T61String",
        21 => "VideotexString",
        22 => "IA5String",
        23 => "UTCTime",
        24 => "GeneralizedTime",
        25 => "GraphicString",
        26 => "VisibleString",
        27 => "GeneralString",
        28 => "UniversalString",
        29 => "CHARACTER STRING",
        30 => "BMPString",
        _ => return None,
    })
}

/// Well-known OID names (X.509, PKCS, CMS, common algorithms and curves).
pub(crate) fn oid_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        // X.520 attribute types
        "2.5.4.3" => "commonName",
        "2.5.4.4" => "surname",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "countryName",
        "2.5.4.7" => "localityName",
        "2.5.4.8" => "stateOrProvinceName",
        "2.5.4.9" => "streetAddress",
        "2.5.4.10" => "organizationName",
        "2.5.4.11" => "organizationalUnitName",
        "2.5.4.12" => "title",
        "2.5.4.42" => "givenName",
        "2.5.4.97" => "organizationIdentifier",
        "0.9.2342.19200300.100.1.1" => "userId",
        "0.9.2342.19200300.100.1.25" => "domainComponent",
        "1.2.840.113549.1.9.1" => "emailAddress",
        // X.509 extensions
        "2.5.29.14" => "subjectKeyIdentifier",
        "2.5.29.15" => "keyUsage",
        "2.5.29.17" => "subjectAltName",
        "2.5.29.18" => "issuerAltName",
        "2.5.29.19" => "basicConstraints",
        "2.5.29.20" => "cRLNumber",
        "2.5.29.21" => "cRLReason",
        "2.5.29.30" => "nameConstraints",
        "2.5.29.31" => "cRLDistributionPoints",
        "2.5.29.32" => "certificatePolicies",
        "2.5.29.32.0" => "anyPolicy",
        "2.5.29.35" => "authorityKeyIdentifier",
        "2.5.29.37" => "extKeyUsage",
        "1.3.6.1.5.5.7.1.1" => "authorityInfoAccess",
        "1.3.6.1.4.1.11129.2.4.2" => "ctPrecertificateSCTs",
        "1.3.6.1.4.1.11129.2.4.3" => "ctPrecertificatePoison",
        // Extended key usage, access methods, policy qualifiers
        "1.3.6.1.5.5.7.3.1" => "serverAuth",
        "1.3.6.1.5.5.7.3.2" => "clientAuth",
        "1.3.6.1.5.5.7.3.3" => "codeSigning",
        "1.3.6.1.5.5.7.3.4" => "emailProtection",
        "1.3.6.1.5.5.7.3.8" => "timeStamping",
        "1.3.6.1.5.5.7.3.9" => "OCSPSigning",
        "1.3.6.1.5.5.7.48.1" => "ocsp",
        "1.3.6.1.5.5.7.48.2" => "caIssuers",
        "1.3.6.1.5.5.7.2.1" => "cps",
        "1.3.6.1.5.5.7.2.2" => "unotice",
        "2.23.140.1.2.1" => "domain-validated",
        "2.23.140.1.2.2" => "organization-validated",
        "2.23.140.1.1" => "extended-validation",
        // Public key and signature algorithms
        "1.2.840.113549.1.1.1" => "rsaEncryption",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.7" => "RSAES-OAEP",
        "1.2.840.113549.1.1.8" => "mgf1",
        "1.2.840.10045.2.1" => "ecPublicKey",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.2.840.10045.3.1.7" => "prime256v1",
        "1.3.132.0.10" => "secp256k1",
        "1.3.132.0.34" => "secp384r1",
        "1.3.132.0.35" => "secp521r1",
        "1.3.101.110" => "X25519",
        "1.3.101.111" => "X448",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        "1.2.840.10040.4.1" => "dsa",
        // Hashes and MACs
        "1.3.14.3.2.26" => "sha1",
        "2.16.840.1.101.3.4.2.1" => "sha256",
        "2.16.840.1.101.3.4.2.2" => "sha384",
        "2.16.840.1.101.3.4.2.3" => "sha512",
        "1.2.840.113549.2.9" => "hmacWithSHA256",
        // Symmetric ciphers and password-based encryption
        "2.16.840.1.101.3.4.1.2" => "aes128-CBC",
        "2.16.840.1.101.3.4.1.42" => "aes256-CBC",
        "2.16.840.1.101.3.4.1.6" => "aes128-GCM",
        "2.16.840.1.101.3.4.1.46" => "aes256-GCM",
        "1.2.840.113549.1.5.12" => "PBKDF2",
        "1.2.840.113549.1.5.13" => "PBES2",
        // PKCS#7 / CMS content types and PKCS#9 attributes
        "1.2.840.113549.1.7.1" => "data",
        "1.2.840.113549.1.7.2" => "signedData",
        "1.2.840.113549.1.7.3" => "envelopedData",
        "1.2.840.113549.1.7.6" => "encryptedData",
        "1.2.840.113549.1.9.3" => "contentType",
        "1.2.840.113549.1.9.4" => "messageDigest",
        "1.2.840.113549.1.9.5" => "signingTime",
        "1.2.840.113549.1.9.14" => "extensionRequest",
        "1.2.840.113549.1.9.16.1.4" => "tstInfo",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_any_width() {
        assert_eq!(int_decimal(&[0x05]), "5");
        assert_eq!(int_decimal(&[0x00]), "0");
        assert_eq!(int_decimal(&[0xff]), "-1");
        assert_eq!(int_decimal(&[0x80]), "-128");
        assert_eq!(int_decimal(&[0x00, 0x80]), "128");
        assert_eq!(int_decimal(&[0x01, 0x00, 0x01]), "65537");
        // 2^64 needs nine bytes: beyond u64.
        assert_eq!(
            int_decimal(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0]),
            "18446744073709551616"
        );
        assert_eq!(
            int_decimal(&[0x80, 0, 0, 0, 0, 0, 0, 0]),
            "-9223372036854775808"
        );
    }

    #[test]
    fn oids() {
        assert_eq!(
            oid(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
                false
            )
            .unwrap(),
            "1.2.840.113549.1.1.11"
        );
        assert_eq!(oid(&[0x55, 0x04, 0x03], false).unwrap(), "2.5.4.3");
        // First subidentifier ≥ 80 belongs to arc 2.
        assert_eq!(oid(&[0x88, 0x37, 0x03], false).unwrap(), "2.999.3");
        assert_eq!(oid(&[0x01, 0x02], true).unwrap(), "1.2");
        assert_eq!(oid(&[0x80, 0x01], false), None); // non-minimal
        assert_eq!(oid(&[0x2a, 0x86], false), None); // truncated
        assert_eq!(oid(&[], false), None);
    }

    #[test]
    fn times() {
        assert_eq!(
            time_iso("261112093000Z", true).unwrap(),
            "2026-11-12T09:30:00Z"
        );
        assert_eq!(
            time_iso("991231235959Z", true).unwrap(),
            "1999-12-31T23:59:59Z"
        );
        assert_eq!(
            time_iso("20261112093000.123Z", false).unwrap(),
            "2026-11-12T09:30:00.123Z"
        );
        assert_eq!(
            time_iso("2026111209+0200", false).unwrap(),
            "2026-11-12T09:00:00+02:00"
        );
        assert_eq!(time_iso("261312093000Z", true), None); // month 13
        assert_eq!(time_iso("26111209300Z", true), None); // odd digit count
        assert_eq!(time_iso("261112093000", true), None); // UTCTime needs a zone
    }

    #[test]
    fn header_errors() {
        let mut st = Stats::default();
        assert_eq!(
            parse(&[0x30, 0x80, 0x00, 0x00], &mut st).unwrap_err().code,
            "INDEFINITE_LENGTH"
        );
        let e = parse(&[0x30, 0x05, 0x02, 0x01], &mut st).unwrap_err();
        assert_eq!((e.code, e.offset), ("TRUNCATED_ELEMENT", Some(1)));
        assert_eq!(
            parse(&[0x30, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0], &mut st)
                .unwrap_err()
                .code,
            "BAD_LENGTH"
        );
        // Long-form length for a short value is BER, not DER.
        let mut st = Stats::default();
        parse(&[0x04, 0x81, 0x01, 0xaa], &mut st).unwrap();
        assert_eq!(st.noncanonical, 1);
    }

    #[test]
    fn high_tag_numbers() {
        let mut st = Stats::default();
        let items = parse(&[0x9f, 0x81, 0x00, 0x01, 0xaa], &mut st).unwrap();
        assert_eq!((items[0].class, items[0].number), (TagClass::Context, 128));
    }
}
