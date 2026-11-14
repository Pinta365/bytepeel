//! Compressed layers (features `deflate` and `zstd`). Fixtures were made with
//! the real `gzip`, `zstd` and Python `zlib` tools so headers are realistic.

// Helpers are shared by feature-gated tests; some go unused in some builds.
#![allow(dead_code)]

use bytepeel_core::*;

const MSG_GZ: &[u8] = include_bytes!("fixtures/msg.bin.gz");
const TWO_MEMBERS_GZ: &[u8] = include_bytes!("fixtures/two-members.gz");
const JSON_ZST: &[u8] = include_bytes!("fixtures/json.zst");
const TEXT_ZLIB: &[u8] = include_bytes!("fixtures/text.zlib");
const BOMB_ZST: &[u8] = include_bytes!("fixtures/bomb-70m.zst");

fn auto(input: &[u8]) -> Node {
    peel(input, &Options::default()).unwrap()
}

fn child(n: &Node) -> &Node {
    match &n.detail {
        Detail::Layer { child, .. } => child,
        d => panic!("not a layer: {d:?}"),
    }
}

fn text(n: &Node) -> &str {
    match &n.detail {
        Detail::Text { text, .. } => text,
        d => panic!("not text: {d:?}"),
    }
}

fn warning(n: &Node) -> &'static str {
    n.warnings.first().map(|w| w.code).unwrap_or("")
}

#[cfg(feature = "deflate")]
mod deflate {
    use super::*;

    #[test]
    fn gzip_with_filename_to_protobuf() {
        let n = auto(MSG_GZ);
        assert_eq!(
            n.codec,
            Codec::Gzip {
                name: Some("msg.bin".into())
            }
        );
        assert_eq!(child(&n).codec, Codec::Protobuf);
        let j = to_json(&n);
        assert!(j.starts_with(r#"{"codec":"gzip","name":"msg.bin","#), "{j}");
        let f = select(&n, "3").unwrap();
        assert!(matches!(f.value, FieldValue::Varint { value: 150, .. }));
    }

    #[test]
    fn base64_gzip_protobuf_layers() {
        // The usual shape in logs and HTTP bodies: base64 of gzip of protobuf.
        let b64 = b64(MSG_GZ);
        let n = auto(b64.as_bytes());
        assert_eq!(n.codec.name(), "base64");
        assert_eq!(child(&n).codec.name(), "gzip");
        assert_eq!(child(child(&n)).codec, Codec::Protobuf);
    }

    #[test]
    fn gzip_members_are_concatenated() {
        let n = auto(TWO_MEMBERS_GZ);
        assert_eq!(n.codec, Codec::Gzip { name: None });
        assert_eq!(text(child(&n)), r#"{"user":"ada","id":7}{"more":true}"#);
    }

    #[test]
    fn zlib_to_text() {
        let n = auto(TEXT_ZLIB);
        assert_eq!(n.codec, Codec::Zlib);
        assert_eq!(text(child(&n)), "hello zlib world ".repeat(4));
    }

    #[test]
    fn gzip_crc_mismatch_is_reported() {
        let mut bad = MSG_GZ.to_vec();
        let at = bad.len() - 8;
        bad[at] ^= 0xff;
        let n = auto(&bad);
        assert_eq!(n.codec, Codec::Bytes);
        assert_eq!(warning(&n), "CHECKSUM_MISMATCH");
        assert_eq!(n.warnings[0].offset, Some(at));
    }

    #[test]
    fn truncated_gzip_is_corrupt() {
        let n = auto(&MSG_GZ[..MSG_GZ.len() - 12]);
        assert_eq!(n.codec, Codec::Bytes);
        assert_eq!(warning(&n), "CORRUPT_DATA");
    }

    #[test]
    fn trailing_bytes_after_gzip_are_flagged() {
        let mut v = MSG_GZ.to_vec();
        v.extend_from_slice(&[0, 0, 0, 0]);
        let n = auto(&v);
        assert_eq!(n.codec.name(), "gzip");
        assert_eq!(warning(&n), "TRAILING_DATA");
        assert_eq!(n.warnings[0].offset, Some(MSG_GZ.len()));
    }

    #[test]
    fn weak_zlib_header_falls_through() {
        // 48 89 is a valid zlib header (FCHECK ok) but uncommon: if it does not
        // inflate, it is not reported as broken zlib.
        let n = auto(&[0x48, 0x89, 0x01, 0x02, 0x03]);
        assert_ne!(warning(&n), "CORRUPT_DATA");
        // 78 9c is the usual header: report it.
        let n = auto(&[0x78, 0x9c, 0xff, 0xff]);
        assert_eq!(warning(&n), "CORRUPT_DATA");
    }
}

#[cfg(feature = "zstd")]
mod zstd {
    use super::*;

    #[test]
    fn zstd_to_text() {
        let n = auto(JSON_ZST);
        assert_eq!(n.codec, Codec::Zstd);
        assert_eq!(text(child(&n)), r#"{"user":"ada","id":7}"#);
    }

    #[test]
    fn zstd_checksum_mismatch() {
        // Frame made with --check: the last 4 bytes are the content checksum.
        let mut bad = JSON_ZST.to_vec();
        let at = bad.len() - 1;
        bad[at] ^= 0xff;
        let n = auto(&bad);
        assert_eq!(n.codec, Codec::Bytes);
        assert_eq!(warning(&n), "CHECKSUM_MISMATCH");
    }

    #[test]
    fn decompression_bomb_is_capped() {
        // 2 KB that expands to 70 MiB of zeros.
        let n = auto(BOMB_ZST);
        assert_eq!(n.codec, Codec::Bytes);
        assert_eq!(warning(&n), "OUTPUT_TOO_LARGE");
    }
}

#[cfg(not(feature = "deflate"))]
#[test]
fn gzip_without_feature_is_unsupported() {
    let n = auto(MSG_GZ);
    assert_eq!(n.codec, Codec::Bytes);
    assert_eq!(warning(&n), "UNSUPPORTED_FORMAT");
    assert!(n.warnings[0].message.contains("`deflate` feature"));
}

#[cfg(not(feature = "zstd"))]
#[test]
fn zstd_without_feature_is_unsupported() {
    let n = auto(JSON_ZST);
    assert_eq!(warning(&n), "UNSUPPORTED_FORMAT");
}

#[test]
fn compressed_json_is_valid_and_deterministic() {
    for input in [MSG_GZ, TWO_MEMBERS_GZ, JSON_ZST, TEXT_ZLIB, BOMB_ZST] {
        let a = to_json(&auto(input));
        assert_eq!(a, to_json(&auto(input)));
        assert!(a.starts_with('{') && a.ends_with('}'));
        let _ = to_tree(&auto(input));
    }
}

fn b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= c.len() {
                o.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                o.push('=');
            }
        }
    }
    o
}
