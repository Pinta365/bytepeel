//! Scalar encoders for `bytepeel set` on CBOR and MessagePack.
//!
//! These turn a [`NewValue`] back into one CBOR or MessagePack item, in the
//! shape a decoded value would have. The splicing/verification around them
//! (which decides where the bytes go and that they decode back) lives in
//! `edit.rs`; here we only build the item.

use crate::{Diag, NewValue, ValueKind};

fn sint_unsupported() -> Diag {
    Diag::new(
        "TYPE_MISMATCH",
        "sint:N is zigzag, protobuf only; use a plain integer",
        None,
    )
}

fn out_of_range(n: i128, range: &str) -> Diag {
    Diag::new(
        "VALUE_OUT_OF_RANGE",
        format!("{n} is outside the encodable range {range}"),
        None,
    )
}

// ---------------------------------------------------------------- CBOR

/// Encode `v` as one CBOR item. `like` is the (already untagged) kind being
/// replaced; it only constrains float width.
pub(crate) fn cbor_scalar(v: &NewValue, like: &ValueKind) -> Result<Vec<u8>, Diag> {
    Ok(match v {
        NewValue::Int(n) => cbor_int(*n)?,
        NewValue::Sint(_) => return Err(sint_unsupported()),
        NewValue::Float(x) => cbor_float(*x, like),
        NewValue::Bool(b) => vec![if *b { 0xf5 } else { 0xf4 }],
        NewValue::Null => vec![0xf6],
        NewValue::Str(s) => {
            let mut out = Vec::new();
            cbor_head(3, s.len() as u64, &mut out);
            out.extend_from_slice(s.as_bytes());
            out
        }
        NewValue::Bytes(b) => {
            let mut out = Vec::new();
            cbor_head(2, b.len() as u64, &mut out);
            out.extend_from_slice(b);
            out
        }
    })
}

fn cbor_int(n: i128) -> Result<Vec<u8>, Diag> {
    let low = -(1i128 << 64);
    let high = (1i128 << 64) - 1;
    if n < low || n > high {
        return Err(out_of_range(n, "[-2^64, 2^64-1]"));
    }
    let mut out = Vec::new();
    if n >= 0 {
        cbor_head(0, n as u64, &mut out);
    } else {
        cbor_head(1, (-n - 1) as u64, &mut out);
    }
    Ok(out)
}

/// A minimal CBOR header for `major` with the given argument.
fn cbor_head(major: u8, n: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.push(m | 24);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn cbor_float(x: f64, like: &ValueKind) -> Vec<u8> {
    let min = like_float_width(like);
    let width = if x.is_nan() || x.is_infinite() {
        if min > 16 { min } else { 16 }
    } else if min <= 16 && fits_f16(x) {
        16
    } else if min <= 32 && fits_f32(x) {
        32
    } else {
        64
    };
    match width {
        16 => {
            let bits = if x.is_nan() {
                0x7e00
            } else if x.is_infinite() {
                if x.is_sign_negative() { 0xfc00 } else { 0x7c00 }
            } else {
                f32_to_f16_bits(x as f32)
            };
            vec![0xf9, (bits >> 8) as u8, bits as u8]
        }
        32 => {
            let bits = if x.is_nan() {
                0x7fc0_0000
            } else if x.is_infinite() {
                if x.is_sign_negative() {
                    0xff80_0000
                } else {
                    0x7f80_0000
                }
            } else {
                (x as f32).to_bits()
            };
            let mut out = vec![0xfa];
            out.extend_from_slice(&bits.to_be_bytes());
            out
        }
        _ => {
            let bits = if x.is_nan() {
                0x7ff8_0000_0000_0000
            } else if x.is_infinite() {
                if x.is_sign_negative() {
                    0xfff0_0000_0000_0000
                } else {
                    0x7ff0_0000_0000_0000
                }
            } else {
                x.to_bits()
            };
            let mut out = vec![0xfb];
            out.extend_from_slice(&bits.to_be_bytes());
            out
        }
    }
}

/// The float width of `like`, or 0 (no minimum) for anything else.
fn like_float_width(like: &ValueKind) -> u8 {
    match like {
        ValueKind::Float { width, .. } => *width,
        _ => 0,
    }
}

fn fits_f32(x: f64) -> bool {
    (x as f32) as f64 == x
}

fn fits_f16(x: f64) -> bool {
    let y = x as f32;
    if (y as f64) != x {
        return false;
    }
    f16_to_f64(f32_to_f16_bits(y)) == x
}

// ---------------------------------------------------------------- MessagePack

/// Encode `v` as one MessagePack item. `like` constrains float width; when
/// `like` is `Ext`, `Bytes` still becomes `bin` (nothing here produces `ext`).
pub(crate) fn msgpack_scalar(v: &NewValue, like: &ValueKind) -> Result<Vec<u8>, Diag> {
    Ok(match v {
        NewValue::Int(n) => msgpack_int(*n)?,
        NewValue::Sint(_) => return Err(sint_unsupported()),
        NewValue::Float(x) => msgpack_float(*x, like),
        NewValue::Bool(b) => vec![if *b { 0xc3 } else { 0xc2 }],
        NewValue::Null => vec![0xc0],
        NewValue::Str(s) => {
            let mut out = msgpack_str_head(s.len() as u64);
            out.extend_from_slice(s.as_bytes());
            out
        }
        NewValue::Bytes(b) => {
            let mut out = msgpack_bin_head(b.len() as u64);
            out.extend_from_slice(b);
            out
        }
    })
}

fn msgpack_int(n: i128) -> Result<Vec<u8>, Diag> {
    let low = i128::from(i64::MIN);
    let high = (1i128 << 64) - 1;
    if n < low || n > high {
        return Err(out_of_range(n, "[-2^63, 2^64-1]"));
    }
    if n >= 0 {
        let n = n as u64;
        if n < 128 {
            Ok(vec![n as u8])
        } else if n <= 0xff {
            Ok(vec![0xcc, n as u8])
        } else if n <= 0xffff {
            let mut out = vec![0xcd];
            out.extend_from_slice(&(n as u16).to_be_bytes());
            Ok(out)
        } else if n <= 0xffff_ffff {
            let mut out = vec![0xce];
            out.extend_from_slice(&(n as u32).to_be_bytes());
            Ok(out)
        } else {
            let mut out = vec![0xcf];
            out.extend_from_slice(&n.to_be_bytes());
            Ok(out)
        }
    } else {
        let n = n as i64;
        if n >= -32 {
            Ok(vec![n as i8 as u8])
        } else if n >= i64::from(i8::MIN) {
            Ok(vec![0xd0, n as i8 as u8])
        } else if n >= i64::from(i16::MIN) {
            let mut out = vec![0xd1];
            out.extend_from_slice(&(n as i16).to_be_bytes());
            Ok(out)
        } else if n >= i64::from(i32::MIN) {
            let mut out = vec![0xd2];
            out.extend_from_slice(&(n as i32).to_be_bytes());
            Ok(out)
        } else {
            let mut out = vec![0xd3];
            out.extend_from_slice(&n.to_be_bytes());
            Ok(out)
        }
    }
}

fn msgpack_str_head(n: u64) -> Vec<u8> {
    if n < 32 {
        vec![0xa0 | n as u8]
    } else if n <= 0xff {
        vec![0xd9, n as u8]
    } else if n <= 0xffff {
        let mut out = vec![0xda];
        out.extend_from_slice(&(n as u16).to_be_bytes());
        out
    } else {
        let mut out = vec![0xdb];
        out.extend_from_slice(&(n as u32).to_be_bytes());
        out
    }
}

fn msgpack_bin_head(n: u64) -> Vec<u8> {
    if n <= 0xff {
        vec![0xc4, n as u8]
    } else if n <= 0xffff {
        let mut out = vec![0xc5];
        out.extend_from_slice(&(n as u16).to_be_bytes());
        out
    } else {
        let mut out = vec![0xc6];
        out.extend_from_slice(&(n as u32).to_be_bytes());
        out
    }
}

fn msgpack_float(x: f64, like: &ValueKind) -> Vec<u8> {
    let min = like_float_width(like);
    let width = if min <= 32 && (x.is_nan() || x.is_infinite() || fits_f32(x)) {
        32
    } else {
        64
    };
    if width == 32 {
        let bits = if x.is_nan() {
            0x7fc0_0000
        } else if x.is_infinite() {
            if x.is_sign_negative() {
                0xff80_0000
            } else {
                0x7f80_0000
            }
        } else {
            (x as f32).to_bits()
        };
        let mut out = vec![0xca];
        out.extend_from_slice(&bits.to_be_bytes());
        out
    } else {
        let bits = if x.is_nan() {
            0x7ff8_0000_0000_0000
        } else if x.is_infinite() {
            if x.is_sign_negative() {
                0xfff0_0000_0000_0000
            } else {
                0x7ff0_0000_0000_0000
            }
        } else {
            x.to_bits()
        };
        let mut out = vec![0xcb];
        out.extend_from_slice(&bits.to_be_bytes());
        out
    }
}

// ---------------------------------------------------------------- half floats

/// IEEE 754 half-precision to double (mirrors the CBOR decoder).
fn f16_to_f64(bits: u16) -> f64 {
    let sign = u32::from(bits >> 15);
    let exp = u32::from((bits >> 10) & 0x1f);
    let mant = u32::from(bits & 0x3ff);
    let value = if exp == 0 {
        (f64::from(mant) / 1024.0) * 2f64.powi(-14)
    } else if exp == 31 {
        if mant == 0 {
            f64::INFINITY
        } else {
            return f64::NAN;
        }
    } else {
        (1.0 + f64::from(mant) / 1024.0) * 2f64.powi(exp as i32 - 15)
    };
    if sign == 1 { -value } else { value }
}

/// Round an `f32` to the nearest half (ties to even).
fn f32_to_f16_bits(x: f32) -> u16 {
    let bits = x.to_bits();
    let sign = ((bits >> 16) & 0x8000) as u16;
    let mut exp = ((bits >> 23) & 0xff) as i32;
    let mut mant = bits & 0x007f_ffff;
    if exp == 0xff {
        let m = if mant == 0 {
            0
        } else {
            ((mant >> 13) | 1) as u16
        };
        return sign | 0x7c00 | m;
    }
    exp = exp - 127 + 15;
    if exp >= 0x1f {
        return sign | 0x7c00;
    }
    if exp <= 0 {
        if exp < -10 {
            return sign;
        }
        mant |= 0x0080_0000;
        let shift = (14 - exp) as u32;
        let mut h = (mant >> shift) as u16;
        let rem = mant & ((1u32 << shift) - 1);
        let halfway = 1u32 << (shift - 1);
        if rem > halfway || (rem == halfway && (h & 1) == 1) {
            h += 1;
        }
        return sign | h;
    }
    let mut h = (((exp as u32) << 10) | (mant >> 13)) as u16;
    let rem = mant & 0x1fff;
    if rem > 0x1000 || (rem == 0x1000 && (h & 1) == 1) {
        h += 1;
    }
    sign | h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cbor1(bytes: &[u8]) -> ValueKind {
        let mut items = crate::cbor::parse_sequence(bytes).expect("cbor parses");
        assert_eq!(items.len(), 1, "{bytes:02x?}");
        items.remove(0).kind
    }

    fn mp1(bytes: &[u8]) -> ValueKind {
        let mut items = crate::msgpack::parse_sequence(bytes).expect("msgpack parses");
        assert_eq!(items.len(), 1, "{bytes:02x?}");
        items.remove(0).kind
    }

    #[test]
    fn cbor_int_boundaries() {
        let cases: [(i128, Vec<u8>); 12] = [
            (0, vec![0x00]),
            (23, vec![0x17]),
            (24, vec![0x18, 0x18]),
            (255, vec![0x18, 0xff]),
            (256, vec![0x19, 0x01, 0x00]),
            (65535, vec![0x19, 0xff, 0xff]),
            (65536, vec![0x1a, 0x00, 0x01, 0x00, 0x00]),
            (0xffff_ffff, vec![0x1a, 0xff, 0xff, 0xff, 0xff]),
            (0x1_0000_0000, vec![0x1b, 0, 0, 0, 1, 0, 0, 0, 0]),
            (-1, vec![0x20]),
            (-24, vec![0x37]),
            (-25, vec![0x38, 0x18]),
        ];
        for (n, want) in cases {
            let out = cbor_scalar(&NewValue::Int(n), &ValueKind::Uint(0)).unwrap();
            assert_eq!(out, want, "{n}");
            match cbor1(&out) {
                ValueKind::Uint(v) => assert_eq!(i128::from(v), n, "{n}"),
                ValueKind::Nint(m) => assert_eq!(-(m as i128) - 1, n, "{n}"),
                k => panic!("{n}: {k:?}"),
            }
        }
        // Extremes.
        let out = cbor_scalar(&NewValue::Int(u64::MAX as i128), &ValueKind::Uint(0)).unwrap();
        assert_eq!(out, [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        let out = cbor_scalar(&NewValue::Int(-(1i128 << 64)), &ValueKind::Uint(0)).unwrap();
        assert_eq!(out, [0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // Out of range.
        for n in [1i128 << 64, -(1i128 << 64) - 1] {
            assert_eq!(
                cbor_scalar(&NewValue::Int(n), &ValueKind::Uint(0))
                    .unwrap_err()
                    .code,
                "VALUE_OUT_OF_RANGE",
                "{n}"
            );
        }
    }

    #[test]
    fn msgpack_int_boundaries() {
        let cases: [(i128, Vec<u8>); 16] = [
            (0, vec![0x00]),
            (23, vec![0x17]),
            (24, vec![0x18]),
            (127, vec![0x7f]),
            (128, vec![0xcc, 0x80]),
            (255, vec![0xcc, 0xff]),
            (256, vec![0xcd, 0x01, 0x00]),
            (65536, vec![0xce, 0x00, 0x01, 0x00, 0x00]),
            (0x1_0000_0000, vec![0xcf, 0, 0, 0, 1, 0, 0, 0, 0]),
            (-1, vec![0xff]),
            (-32, vec![0xe0]),
            (-33, vec![0xd0, 0xdf]),
            (-128, vec![0xd0, 0x80]),
            (-129, vec![0xd1, 0xff, 0x7f]),
            (-32769, vec![0xd2, 0xff, 0xff, 0x7f, 0xff]),
            (i64::MIN as i128, vec![0xd3, 0x80, 0, 0, 0, 0, 0, 0, 0]),
        ];
        for (n, want) in cases {
            let out = msgpack_scalar(&NewValue::Int(n), &ValueKind::Uint(0)).unwrap();
            assert_eq!(out, want, "{n}");
            match mp1(&out) {
                ValueKind::Uint(v) => assert_eq!(i128::from(v), n, "{n}"),
                ValueKind::Nint(m) => assert_eq!(-(m as i128) - 1, n, "{n}"),
                k => panic!("{n}: {k:?}"),
            }
        }
        let out = msgpack_scalar(&NewValue::Int(u64::MAX as i128), &ValueKind::Uint(0)).unwrap();
        assert_eq!(out, [0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        for n in [1i128 << 64, i128::from(i64::MIN) - 1] {
            assert_eq!(
                msgpack_scalar(&NewValue::Int(n), &ValueKind::Uint(0))
                    .unwrap_err()
                    .code,
                "VALUE_OUT_OF_RANGE",
                "{n}"
            );
        }
    }

    #[test]
    fn sint_is_rejected() {
        for out in [
            cbor_scalar(&NewValue::Sint(-2), &ValueKind::Uint(0)).unwrap_err(),
            msgpack_scalar(&NewValue::Sint(-2), &ValueKind::Uint(0)).unwrap_err(),
        ] {
            assert_eq!(out.code, "TYPE_MISMATCH");
            assert!(out.message.contains("zigzag"), "{}", out.message);
        }
    }

    #[test]
    fn cbor_float_widths() {
        let cases: [(f64, u8, u8); 7] = [
            (0.5, 16, 0xf9),
            (0.1, 64, 0xfb),
            (1e-8, 64, 0xfb),
            (65504.0, 16, 0xf9),
            (65520.0, 32, 0xfa),
            (5.960_464_477_539_063e-8, 16, 0xf9),
            (-0.0, 16, 0xf9),
        ];
        for (x, width, head) in cases {
            let out = cbor_scalar(&NewValue::Float(x), &ValueKind::Null).unwrap();
            assert_eq!(out[0], head, "{x}");
            match cbor1(&out) {
                ValueKind::Float { value, width: w } => {
                    assert_eq!(w, width, "{x}");
                    assert_eq!(value.to_bits(), x.to_bits(), "{x}");
                }
                k => panic!("{x}: {k:?}"),
            }
        }
        // A double field stays double even for a half-exact value.
        let out = cbor_scalar(
            &NewValue::Float(0.5),
            &ValueKind::Float {
                value: 1.0,
                width: 64,
            },
        )
        .unwrap();
        assert_eq!(out, [0xfb, 0x3f, 0xe0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn msgpack_float_widths() {
        for (x, width, head) in [
            (0.5f64, 32u8, 0xca),
            (0.1, 64, 0xcb),
            (1e-8, 64, 0xcb),
            (-0.0, 32, 0xca),
        ] {
            let out = msgpack_scalar(&NewValue::Float(x), &ValueKind::Null).unwrap();
            assert_eq!(out[0], head, "{x}");
            match mp1(&out) {
                ValueKind::Float { value, width: w } => {
                    assert_eq!(w, width, "{x}");
                    assert_eq!(value.to_bits(), x.to_bits(), "{x}");
                }
                k => panic!("{x}: {k:?}"),
            }
        }
        let out = msgpack_scalar(
            &NewValue::Float(0.5),
            &ValueKind::Float {
                value: 1.0,
                width: 64,
            },
        )
        .unwrap();
        assert_eq!(out, [0xcb, 0x3f, 0xe0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn nan_and_inf() {
        assert_eq!(
            cbor_scalar(&NewValue::Float(f64::NAN), &ValueKind::Null).unwrap(),
            [0xf9, 0x7e, 0x00]
        );
        assert_eq!(
            cbor_scalar(&NewValue::Float(f64::INFINITY), &ValueKind::Null).unwrap(),
            [0xf9, 0x7c, 0x00]
        );
        assert_eq!(
            cbor_scalar(&NewValue::Float(f64::NEG_INFINITY), &ValueKind::Null).unwrap(),
            [0xf9, 0xfc, 0x00]
        );
        // A double-like NaN stays 64-bit canonical.
        assert_eq!(
            cbor_scalar(
                &NewValue::Float(f64::NAN),
                &ValueKind::Float {
                    value: 0.0,
                    width: 64
                }
            )
            .unwrap(),
            [0xfb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            msgpack_scalar(&NewValue::Float(f64::NAN), &ValueKind::Null).unwrap(),
            [0xca, 0x7f, 0xc0, 0x00, 0x00]
        );
        assert_eq!(
            msgpack_scalar(&NewValue::Float(f64::INFINITY), &ValueKind::Null).unwrap(),
            [0xca, 0x7f, 0x80, 0x00, 0x00]
        );
        // NaN/Inf round-trip as NaN/Inf at the chosen width.
        match cbor1(&cbor_scalar(&NewValue::Float(f64::NAN), &ValueKind::Null).unwrap()) {
            ValueKind::Float { value, width } => {
                assert!(value.is_nan());
                assert_eq!(width, 16);
            }
            k => panic!("{k:?}"),
        }
    }

    #[test]
    fn strings_and_bytes() {
        // CBOR text lengths.
        assert_eq!(
            cbor_scalar(&NewValue::Str(String::new()), &ValueKind::Null).unwrap(),
            [0x60]
        );
        for (len, head) in [
            (23usize, vec![0x77]),
            (24, vec![0x78, 0x18]),
            (255, vec![0x78, 0xff]),
            (256, vec![0x79, 0x01, 0x00]),
        ] {
            let s = "a".repeat(len);
            let out = cbor_scalar(&NewValue::Str(s.clone()), &ValueKind::Null).unwrap();
            assert_eq!(&out[..head.len()], &head[..], "len {len}");
            assert_eq!(&out[head.len()..], s.as_bytes(), "len {len}");
            assert_eq!(cbor1(&out), ValueKind::Text(s), "len {len}");
        }
        assert_eq!(
            cbor_scalar(&NewValue::Bytes(vec![]), &ValueKind::Null).unwrap(),
            [0x40]
        );

        // MessagePack str heads.
        assert_eq!(
            msgpack_scalar(&NewValue::Str(String::new()), &ValueKind::Null).unwrap(),
            [0xa0]
        );
        for (len, head) in [
            (31usize, vec![0xbf]),
            (32, vec![0xd9, 0x20]),
            (255, vec![0xd9, 0xff]),
            (256, vec![0xda, 0x01, 0x00]),
        ] {
            let s = "a".repeat(len);
            let out = msgpack_scalar(&NewValue::Str(s.clone()), &ValueKind::Null).unwrap();
            assert_eq!(&out[..head.len()], &head[..], "len {len}");
            assert_eq!(&out[head.len()..], s.as_bytes(), "len {len}");
            assert_eq!(mp1(&out), ValueKind::Text(s), "len {len}");
        }
        // MessagePack bin heads.
        assert_eq!(
            msgpack_scalar(&NewValue::Bytes(vec![]), &ValueKind::Null).unwrap(),
            [0xc4, 0x00]
        );
        for (len, head) in [(255usize, vec![0xc4, 0xff]), (256, vec![0xc5, 0x01, 0x00])] {
            let b = vec![7u8; len];
            let out = msgpack_scalar(&NewValue::Bytes(b.clone()), &ValueKind::Null).unwrap();
            assert_eq!(&out[..head.len()], &head[..], "len {len}");
            match mp1(&out) {
                ValueKind::Bytes { data, .. } => assert_eq!(data.len(), len),
                k => panic!("{len}: {k:?}"),
            }
        }
        // Bytes replacing an Ext becomes bin.
        assert_eq!(
            msgpack_scalar(
                &NewValue::Bytes(vec![1, 2, 3]),
                &ValueKind::Ext {
                    type_: -1,
                    data: vec![]
                }
            )
            .unwrap(),
            [0xc4, 0x03, 1, 2, 3]
        );
    }

    #[test]
    fn bool_and_null() {
        assert_eq!(
            cbor_scalar(&NewValue::Bool(true), &ValueKind::Null).unwrap(),
            [0xf5]
        );
        assert_eq!(
            cbor_scalar(&NewValue::Bool(false), &ValueKind::Null).unwrap(),
            [0xf4]
        );
        assert_eq!(
            cbor_scalar(&NewValue::Null, &ValueKind::Null).unwrap(),
            [0xf6]
        );
        assert_eq!(
            msgpack_scalar(&NewValue::Bool(true), &ValueKind::Null).unwrap(),
            [0xc3]
        );
        assert_eq!(
            msgpack_scalar(&NewValue::Bool(false), &ValueKind::Null).unwrap(),
            [0xc2]
        );
        assert_eq!(
            msgpack_scalar(&NewValue::Null, &ValueKind::Null).unwrap(),
            [0xc0]
        );
    }
}
