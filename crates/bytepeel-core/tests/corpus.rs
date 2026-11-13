//! Correctness corpus: the edge cases throwaway decoding scripts get wrong.

use bytepeel_core::*;

// ------------------------------------------------------------ helpers

fn h(s: &str) -> Vec<u8> {
    decode_hex(s).unwrap()
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

/// URL-safe base64, unpadded (JWT segments).
fn b64url(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut o = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        o.push(A[((n >> 18) & 63) as usize] as char);
        o.push(A[((n >> 12) & 63) as usize] as char);
        if c.len() > 1 {
            o.push(A[((n >> 6) & 63) as usize] as char);
        }
        if c.len() > 2 {
            o.push(A[(n & 63) as usize] as char);
        }
    }
    o
}

fn jws(header: &str, payload: &str, sig: &[u8]) -> String {
    format!(
        "{}.{}.{}",
        b64url(header.as_bytes()),
        b64url(payload.as_bytes()),
        b64url(sig)
    )
}

fn hs256_token(payload: &str) -> String {
    jws(r#"{"alg":"HS256","typ":"JWT"}"#, payload, &[0x11; 32])
}

fn none_token(payload: &str) -> String {
    jws(r#"{"alg":"none"}"#, payload, b"")
}

fn jwe_token() -> String {
    format!(
        "{}..{}.{}.{}",
        b64url(br#"{"alg":"dir","enc":"A256GCM"}"#),
        b64url(b"iviv"),
        b64url(b"ciphertext"),
        b64url(b"tagtag")
    )
}

fn parts_of(n: &Node) -> (&[Node], &[(&'static str, String)]) {
    match &n.detail {
        Detail::Parts { parts, times } => (parts, times),
        d => panic!("not a Parts node: {d:?}"),
    }
}

/// Structural DER equality, ignoring absolute byte ranges.
fn same_der(a: &Asn1, b: &Asn1) -> bool {
    if a.class != b.class
        || a.number != b.number
        || a.constructed != b.constructed
        || a.raw != b.raw
        || a.content[1] - a.content[0] != b.content[1] - b.content[0]
    {
        return false;
    }
    match (&a.value, &b.value) {
        (Asn1Value::Constructed(x), Asn1Value::Constructed(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same_der(p, q))
        }
        (
            Asn1Value::Encapsulated {
                unused_bits: u,
                items: x,
            },
            Asn1Value::Encapsulated {
                unused_bits: v,
                items: y,
            },
        ) => u == v && x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same_der(p, q)),
        _ => a.value == b.value,
    }
}

fn cbor_opts() -> Options {
    Options {
        input: InputForm::Raw,
        force: Some(Force::Cbor),
        ..Options::default()
    }
}

/// Parse `hex` as a forced CBOR sequence.
fn cbor(hex: &str) -> Node {
    peel(&h(hex), &cbor_opts()).unwrap()
}

fn values_of(n: &Node) -> &[Value] {
    match &n.detail {
        Detail::Values { items } => items,
        d => panic!("not Values: {d:?}"),
    }
}

fn msgpack_opts() -> Options {
    Options {
        input: InputForm::Raw,
        force: Some(Force::Msgpack),
        ..Options::default()
    }
}

/// Parse `hex` as a forced MessagePack sequence.
fn msgpack(hex: &str) -> Node {
    peel(&h(hex), &msgpack_opts()).unwrap()
}

fn msgpack_bytes(bytes: &[u8]) -> Node {
    peel(bytes, &msgpack_opts()).unwrap()
}

fn auto(input: &[u8]) -> Node {
    peel(input, &Options::default()).unwrap()
}

fn forced_pb(bytes: &[u8]) -> Result<Node, Diag> {
    let opts = Options {
        input: InputForm::Raw,
        force: Some(Force::Protobuf),
        ..Options::default()
    };
    peel(bytes, &opts)
}

fn msg(n: &Node) -> &[Field] {
    match &n.detail {
        Detail::Message { fields } => fields,
        Detail::Layer { child, .. } => msg(child),
        d => panic!("not a message: {d:?}"),
    }
}

fn child(n: &Node) -> &Node {
    match &n.detail {
        Detail::Layer { child, .. } => child,
        d => panic!("not a layer: {d:?}"),
    }
}

fn varint_value(f: &Field) -> u64 {
    match &f.value {
        FieldValue::Varint { value, .. } => *value,
        v => panic!("not a varint: {v:?}"),
    }
}

fn top_alt(f: &Field) -> &Alt {
    match &f.value {
        FieldValue::Len { alts, .. } => &alts[0],
        v => panic!("not LEN: {v:?}"),
    }
}

// ------------------------------------------------------------ varints

#[test]
fn varint_basics() {
    assert_eq!(varint::decode(&[0x96, 0x01]), Ok((150, 2)));
    assert_eq!(varint::decode(&[0x96]), Err(varint::VarintError::Truncated));
    let max = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
    assert_eq!(varint::decode(&max), Ok((u64::MAX, 10)));
    let over = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
    assert_eq!(varint::decode(&over), Err(varint::VarintError::Overflow));
    for v in [0, 1, 127, 128, 150, 300, u64::from(u32::MAX), u64::MAX] {
        let e = varint::encode(v);
        assert_eq!(varint::decode(&e), Ok((v, e.len())));
    }
}

#[test]
fn zigzag() {
    assert_eq!(varint::zigzag(0), 0);
    assert_eq!(varint::zigzag(1), -1);
    assert_eq!(varint::zigzag(2), 1);
    assert_eq!(varint::zigzag(3), -2);
    assert_eq!(varint::zigzag(u64::MAX), i64::MIN);
}

// ------------------------------------------------------------ protobuf

#[test]
fn classic_varint_field() {
    let n = auto(&h("089601"));
    assert_eq!(n.codec, Codec::Protobuf);
    let f = &msg(&n)[0];
    assert_eq!(f.number, 1);
    assert_eq!(varint_value(f), 150);
    assert_eq!(f.range, [0, 3]);
}

#[test]
fn negative_int64_is_ten_bytes_and_all_views_are_reported() {
    // field 2 = int64(-2): a negative int is sign-extended to 10 bytes
    let n = auto(&h("10feffffffffffffffff01"));
    let f = &msg(&n)[0];
    assert_eq!(varint_value(f), 18446744073709551614);
    let j = field_to_json(f);
    assert!(j.contains(r#""uint":"18446744073709551614""#), "{j}");
    assert!(j.contains(r#""int":"-2""#), "{j}");
    assert!(j.contains(r#""sint":"9223372036854775807""#), "{j}");
}

#[test]
fn string_field_ranks_string_first() {
    let n = auto(&h("0a03666f6f"));
    let a = top_alt(&msg(&n)[0]);
    assert!(matches!(&a.kind, AltKind::String { text, .. } if text == "foo"));
    assert!(a.score > 0.8);
}

#[test]
fn nested_message_and_path_select() {
    let n = auto(&h("1a03089601"));
    let a = top_alt(&msg(&n)[0]);
    assert!(matches!(&a.kind, AltKind::Message(_)), "{a:?}");
    let f = select(&n, "3.1").unwrap();
    assert_eq!(varint_value(f), 150);
    assert_eq!(f.payload().unwrap(), vec![0x96, 0x01]);
    assert_eq!(select(&n, "3.9").unwrap_err().code, "PATH_NOT_FOUND");
    assert_eq!(select(&n, "3.x").unwrap_err().code, "BAD_PATH");
}

#[test]
fn repeated_field_index() {
    let n = auto(&h("0801080208 03"));
    assert_eq!(varint_value(select(&n, "1[2]").unwrap()), 3);
}

#[test]
fn fixed_width_fields() {
    // field 1 double NaN, field 2 float +inf
    let n = auto(&h("09 000000000000f87f 15 0000807f"));
    let fields = msg(&n);
    let j1 = field_to_json(&fields[0]);
    let j2 = field_to_json(&fields[1]);
    assert!(j1.contains(r#""double":"NaN""#), "{j1}");
    assert!(j2.contains(r#""float":"Infinity""#), "{j2}");
}

#[test]
fn groups() {
    let n = auto(&h("0b10010c"));
    match &msg(&n)[0].value {
        FieldValue::Group { fields } => {
            assert_eq!(fields[0].number, 2);
            assert_eq!(varint_value(&fields[0]), 1);
        }
        v => panic!("{v:?}"),
    }
}

#[test]
fn forced_protobuf_errors_have_codes_and_offsets() {
    let cases = [
        ("0b1001", "UNTERMINATED_GROUP", Some(3)),
        ("0a05666f", "TRUNCATED_FIELD", Some(0)),
        ("0001", "FIELD_NUMBER_ZERO", Some(0)),
        ("0e", "INVALID_WIRE_TYPE", Some(0)),
        ("08ff", "TRUNCATED_VARINT", Some(1)),
        ("0c", "UNEXPECTED_END_GROUP", Some(0)),
        ("08ffffffffffffffffff02", "VARINT_OVERFLOW", Some(1)),
    ];
    for (hex, code, offset) in cases {
        let e = forced_pb(&h(hex)).unwrap_err();
        assert_eq!((e.code, e.offset), (code, offset), "{hex}");
    }
}

#[test]
fn empty_len_field() {
    let n = auto(&h("0a00 0801"));
    assert!(matches!(top_alt(&msg(&n)[0]).kind, AltKind::Empty));
}

// ------------------------------------------------------------ base64

#[test]
fn base64_std_padded() {
    let n = auto(b"SGVsbG8gd29ybGQ=\n");
    assert_eq!(
        n.codec,
        Codec::Base64 {
            alphabet: Alphabet::Std,
            padded: true
        }
    );
    assert!(matches!(&child(&n).detail, Detail::Text { text } if text == "Hello world"));
}

#[test]
fn base64_url_unpadded() {
    let opts = Options {
        input: InputForm::Base64,
        ..Options::default()
    };
    let n = peel(b"-_8", &opts).unwrap();
    assert_eq!(
        n.codec,
        Codec::Base64 {
            alphabet: Alphabet::Url,
            padded: false
        }
    );
    let Detail::Layer { decoded, .. } = &n.detail else {
        panic!()
    };
    assert_eq!(decoded, &[0xfb, 0xff]);
}

#[test]
fn base64_errors() {
    assert_eq!(decode_b64("+_AA").unwrap_err().code, "MIXED_ALPHABET");
    assert_eq!(decode_b64("SGVsbG8==").unwrap_err().code, "BAD_PADDING");
    assert_eq!(decode_b64("SGVsbG8=x").unwrap_err().code, "BAD_PADDING");
    assert_eq!(decode_b64("SGVsb").unwrap_err().code, "INVALID_LENGTH");
    assert_eq!(decode_b64("SGVs bG8=").unwrap_err().code, "INVALID_CHAR");
    assert!(decode_b64("SGVsbG9=").unwrap().noncanonical);
    assert!(!decode_b64("SGVsbG8=").unwrap().noncanonical);
    // PEM-style line wrapping is fine
    assert_eq!(decode_b64("SGVs\r\nbG8=").unwrap().bytes, b"Hello");
}

#[test]
fn plain_words_are_not_base64() {
    let n = auto(b"HelloWorld");
    assert_eq!(n.codec, Codec::Utf8);
}

// ------------------------------------------------------------ hex

#[test]
fn hex_forms() {
    for input in [
        "08 96 01",
        "089601",
        "0x089601",
        "08:96:01",
        "0x08 0x96 0x01",
    ] {
        let n = auto(input.as_bytes());
        assert_eq!(n.codec, Codec::Hex, "{input}");
        assert_eq!(varint_value(&msg(&n)[0]), 150, "{input}");
    }
}

#[test]
fn decimal_number_is_not_hex() {
    assert_eq!(auto(b"12345678").codec, Codec::Utf8);
}

#[test]
fn hex_errors() {
    assert_eq!(decode_hex("0a3").unwrap_err().code, "ODD_LENGTH");
    let e = decode_hex("0a zz").unwrap_err();
    assert_eq!((e.code, e.offset), ("INVALID_CHAR", Some(3)));
}

// ------------------------------------------------------------ layering

#[test]
fn base64_protobuf_base64_text() {
    let inner = b64(b"Hello, world!!");
    let mut proto = vec![0x0a, inner.len() as u8];
    proto.extend_from_slice(inner.as_bytes());
    proto.extend_from_slice(&[0x10, 0x2a]); // field 2 = 42
    let outer = b64(&proto);

    let n = auto(outer.as_bytes());
    assert_eq!(n.codec.name(), "base64");
    let pb = child(&n);
    assert_eq!(pb.codec, Codec::Protobuf);
    let AltKind::String {
        decoded: Some(d), ..
    } = &top_alt(&msg(pb)[0]).kind
    else {
        panic!("string field should decode further")
    };
    assert_eq!(d.codec.name(), "base64");
    assert!(matches!(&child(d).detail, Detail::Text { text } if text == "Hello, world!!"));
    assert_eq!(varint_value(select(&n, "2").unwrap()), 42);
}

#[test]
fn pem_with_der_payload() {
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        b64(&h("3003020105"))
    );
    let n = auto(pem.as_bytes());
    assert_eq!(
        n.codec,
        Codec::Pem {
            label: "CERTIFICATE".into()
        }
    );
    let c = child(&n);
    assert_eq!(c.codec, Codec::Der);
    assert!(c.warnings.is_empty());
}

#[test]
fn pem_bundle_chain_and_select() {
    let single = auto(ISRG_X2.as_bytes());
    let chain = format!("{ISRG_X2}{ISRG_X2}");
    let n = auto(chain.as_bytes());
    assert_eq!(n.codec, Codec::Bundle);
    assert_eq!(n.confidence, 0.99);
    assert_eq!(n.range, [0, chain.len()]);
    assert!(n.warnings.is_empty(), "{:?}", n.warnings);

    let (parts, times) = parts_of(&n);
    assert_eq!(parts.len(), 2);
    assert!(times.is_empty());
    for p in parts {
        assert!(
            matches!(&p.codec, Codec::Pem { label } if label == "CERTIFICATE"),
            "{:?}",
            p.codec
        );
        assert_eq!(p.confidence, 0.99);
        assert_eq!(child(p).codec, Codec::Der);
    }
    // Each block's range begins at its own BEGIN marker.
    for p in parts {
        assert_eq!(
            &chain[p.range[0]..p.range[0] + 10],
            "-----BEGIN",
            "{:?}",
            p.range
        );
    }

    // `1.<der path>` addresses the second certificate's subject.
    let sub_b = select_der(&n, "1.0.0.5").unwrap();
    let sub_s = select_der(&single, "0.0.5").unwrap();
    assert_eq!(sub_b.tag_name(), "SEQUENCE");
    assert!(same_der(sub_b, sub_s));
    // The first block's subject needs the block index first: `0.0.0.5`.
    assert!(same_der(select_der(&n, "0.0.0.5").unwrap(), sub_s));

    assert!(is_der(&n));
    assert_eq!(select_der(&n, "9.0").unwrap_err().code, "PATH_NOT_FOUND");
    assert_eq!(select_der(&n, "1").unwrap_err().code, "PATH_NOT_FOUND");

    let t = to_tree(&n);
    assert!(t.starts_with("bundle [0.."), "{t}");
    assert!(t.contains("(2 blocks)"), "{t}");
    let j = to_json(&n);
    assert!(j.contains(r#""codec":"bundle""#), "{j}");
    assert!(
        j.contains(r#""parts":["#) && !j.contains(r#""times""#),
        "{j}"
    );
}

#[test]
fn pem_bundle_key_and_cert() {
    let der = h("3003020105");
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n\
         -----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        b64(&der),
        b64(&der)
    );
    let n = auto(pem.as_bytes());
    assert_eq!(n.codec, Codec::Bundle);
    let (parts, _) = parts_of(&n);
    assert_eq!(parts.len(), 2);
    assert_eq!(
        parts[0].codec,
        Codec::Pem {
            label: "CERTIFICATE".into()
        }
    );
    assert_eq!(
        parts[1].codec,
        Codec::Pem {
            label: "PRIVATE KEY".into()
        }
    );
    // Select into the second block: block 1, top-level element 0, child 0.
    let e = select_der(&n, "1.0.0").unwrap();
    assert_eq!(e.tag_name(), "INTEGER");
    assert!(
        asn1_to_json(e).contains(r#""int":"5""#),
        "{}",
        asn1_to_json(e)
    );
}

#[test]
fn pem_bundle_ignores_surrounding_text() {
    let block = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        b64(&h("3003020105"))
    );
    let text =
        format!("subject=/CN=x\n{block}Bag Attributes\n  friendlyName: y\n{block}trailing\n");
    let n = auto(text.as_bytes());
    assert_eq!(n.codec, Codec::Bundle);
    let (parts, _) = parts_of(&n);
    assert_eq!(parts.len(), 2);
    assert!(parts.iter().all(|p| p.warnings.is_empty()));
    assert_eq!(n.warnings.len(), 1);
    assert_eq!(n.warnings[0].code, "TRAILING_DATA");
    // The message reports the non-whitespace bytes outside the blocks.
    let mut ignored = 0;
    let mut cursor = 0;
    for p in parts {
        ignored += text[cursor..p.range[0]]
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .count();
        cursor = p.range[1];
    }
    ignored += text[cursor..]
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .count();
    assert!(
        n.warnings[0].message.contains(&format!("{ignored} bytes")),
        "{}",
        n.warnings[0].message
    );
}

#[test]
fn single_pem_block_is_unchanged() {
    let pem = format!("-----BEGIN X-----\n{}\n-----END X-----\n", b64(b"\x01\x02"));
    let n = auto(pem.as_bytes());
    assert_eq!(n.codec, Codec::Pem { label: "X".into() });
    assert!(n.warnings.is_empty());
    assert_eq!(child(&n).codec, Codec::Bytes);

    // Text around a single block stays on the pem node (with a counted warning).
    let padded = format!("before\n{pem}after\n");
    let n = auto(padded.as_bytes());
    assert_eq!(n.codec, Codec::Pem { label: "X".into() });
    assert_eq!(n.warnings.len(), 1);
    assert_eq!(n.warnings[0].code, "TRAILING_DATA");
    assert!(
        n.warnings[0].message.contains(" bytes"),
        "{}",
        n.warnings[0].message
    );
}

#[test]
fn pem_truncated_tail_keeps_good_block() {
    // A complete certificate followed by a copy cut off mid-base64 (no END).
    let truncated = &ISRG_X2[..ISRG_X2.find("-----END").unwrap() / 2];
    let text = format!("{ISRG_X2}{truncated}");
    let n = auto(text.as_bytes());
    // The good block is kept; the cut-off block is reported as a warning.
    assert_eq!(
        n.codec,
        Codec::Pem {
            label: "CERTIFICATE".into()
        }
    );
    assert_eq!(child(&n).codec, Codec::Der);
    assert_eq!(n.warnings.len(), 1, "{:?}", n.warnings);
    assert_eq!(n.warnings[0].code, "PEM_UNTERMINATED");
    assert_eq!(n.warnings[0].offset, Some(ISRG_X2.len()));
    // The cut-off region is not double-counted as trailing data.
    assert!(!to_json(&n).contains("TRAILING_DATA"), "{}", to_json(&n));
}

#[test]
fn pem_bundle_truncated_tail() {
    let truncated = &ISRG_X2[..ISRG_X2.find("-----END").unwrap() / 2];
    let text = format!("{ISRG_X2}{ISRG_X2}{truncated}");
    let n = auto(text.as_bytes());
    assert_eq!(n.codec, Codec::Bundle);
    let (parts, _) = parts_of(&n);
    assert_eq!(parts.len(), 2);
    assert!(parts.iter().all(|p| child(p).codec == Codec::Der));
    assert_eq!(n.warnings.len(), 1, "{:?}", n.warnings);
    assert_eq!(n.warnings[0].code, "PEM_UNTERMINATED");
    assert_eq!(n.warnings[0].offset, Some(2 * ISRG_X2.len()));
    let t = to_tree(&n);
    assert!(t.contains("(2 blocks)"), "{t}");
    assert!(t.contains("PEM_UNTERMINATED"), "{t}");
}

#[test]
fn pem_later_bad_base64_is_a_warning() {
    // A later block with a matching END but a body that is not base64.
    let bad = "-----BEGIN X-----\n!!!!\n-----END X-----\n";
    let text = format!("{ISRG_X2}{bad}");
    let n = auto(text.as_bytes());
    assert_eq!(
        n.codec,
        Codec::Pem {
            label: "CERTIFICATE".into()
        }
    );
    assert_eq!(n.warnings.len(), 1, "{:?}", n.warnings);
    assert_eq!(n.warnings[0].code, "INVALID_CHAR");
    let body_start = ISRG_X2.len() + "-----BEGIN X-----".len();
    assert_eq!(n.warnings[0].offset, Some(body_start));
}

#[test]
fn pem_mismatched_end_label_is_not_a_block() {
    // A missing END (here a mismatched label) is not recognised as PEM, as before.
    let pem = "-----BEGIN CERTIFICATE-----\nAA==\n-----END PRIVATE KEY-----\n";
    assert_eq!(auto(pem.as_bytes()).codec, Codec::Utf8);
    let no_end = "-----BEGIN CERTIFICATE-----\nAA==\n";
    assert_eq!(auto(no_end.as_bytes()).codec, Codec::Utf8);
}

#[test]
fn magic_formats_are_not_misread_as_protobuf() {
    // Truncated compressed streams: corrupt when the decoder is compiled in,
    // unsupported otherwise. Either way, never protobuf.
    let deflate = if cfg!(feature = "deflate") {
        "CORRUPT_DATA"
    } else {
        "UNSUPPORTED_FORMAT"
    };
    let zstd = if cfg!(feature = "zstd") {
        "CORRUPT_DATA"
    } else {
        "UNSUPPORTED_FORMAT"
    };
    for (hex, code) in [
        ("1f8b0800000000000000", deflate),
        ("28b52ffd0000", zstd),
        ("789c0300", deflate),
        ("89504e470d0a1a0a0000", "UNSUPPORTED_FORMAT"),
        ("504b0304140000000000", "UNSUPPORTED_FORMAT"),
    ] {
        let n = auto(&h(hex));
        assert_eq!(n.codec, Codec::Bytes, "{hex}");
        assert_eq!(n.warnings[0].code, code, "{hex}");
    }
}

#[test]
fn depth_zero_disables_layers() {
    let opts = Options {
        depth: 0,
        ..Options::default()
    };
    assert_eq!(peel(b"SGVsbG8gd29ybGQ=", &opts).unwrap().codec, Codec::Utf8);
}

#[test]
fn alts_limit() {
    let opts = Options {
        alts: 1,
        ..Options::default()
    };
    let n = peel(&h("1a03089601"), &opts).unwrap();
    match &msg(&n)[0].value {
        FieldValue::Len { alts, .. } => assert_eq!(alts.len(), 1),
        v => panic!("{v:?}"),
    }
}

// ------------------------------------------------------------ DER

const ISRG_X2: &str = include_str!("fixtures/isrg-root-x2.pem");

fn der(input: &[u8]) -> Result<Node, Diag> {
    let opts = Options {
        input: InputForm::Raw,
        force: Some(Force::Der),
        ..Options::default()
    };
    peel(input, &opts)
}

#[test]
fn der_certificate() {
    let n = auto(ISRG_X2.as_bytes());
    assert_eq!(child(&n).codec, Codec::Der);
    let el = |p: &str| select_der(&n, p).unwrap();
    assert_eq!(el("0").tag_name(), "SEQUENCE");
    assert_eq!(el("0.0.0").tag_name(), "[0]");
    // Serial numbers are 16 bytes here: still rendered in decimal.
    assert!(
        asn1_to_json(el("0.0.1")).contains(r#""int":"87493402998870891108772069816698636114""#)
    );
    assert_eq!(
        el("0.0.2.0").value,
        Asn1Value::Oid("1.2.840.10045.4.3.3".into())
    );
    assert!(asn1_to_json(el("0.0.2.0")).contains(r#""name":"ecdsa-with-SHA384""#));
    let not_before = asn1_to_json(el("0.0.4.0"));
    assert!(
        not_before.contains(r#""iso":"2020-09-04T00:00:00Z""#),
        "{not_before}"
    );
    // Issuer CN is a PrintableString.
    assert_eq!(
        el("0.0.3.1.0.1").value,
        Asn1Value::Text("Internet Security Research Group".into())
    );
    // The ECDSA signature BIT STRING encapsulates SEQUENCE { r, s }.
    let sig = el("0.2");
    assert!(matches!(
        sig.value,
        Asn1Value::Encapsulated {
            unused_bits: Some(0),
            ..
        }
    ));
    assert_eq!(el("0.2.0.1").tag_name(), "INTEGER");
    // A 49-byte integer is hex only.
    let s_json = asn1_to_json(el("0.2.0.1"));
    assert!(
        !s_json.contains(r#""int""#) && s_json.contains(r#""hex":"008bf5"#),
        "{s_json}"
    );
    // Raw payload of a BIT STRING drops the unused-bits byte.
    assert_eq!(el("0.0.6.1").payload().unwrap()[0], 0x04);
    assert_eq!(select_der(&n, "0.9").unwrap_err().code, "PATH_NOT_FOUND");
    assert_eq!(
        select_der(&n, "0.0.1.0").unwrap_err().code,
        "PATH_NOT_MESSAGE"
    );
    assert_eq!(select_der(&n, "0.x").unwrap_err().code, "BAD_PATH");
}

#[test]
fn der_encapsulation_needs_clean_der() {
    // subjectKeyIdentifier style: OCTET STRING { OCTET STRING (20 bytes) }.
    let ski = h("0416 0414 d287b4e3df37279355f656ea81e536cc8c1e3fbd");
    let n = der(&ski).unwrap();
    let Detail::Der { items } = &n.detail else {
        panic!()
    };
    assert!(matches!(
        items[0].value,
        Asn1Value::Encapsulated {
            unused_bits: None,
            ..
        }
    ));
    // Opaque bytes, and a lone context-tagged primitive, stay bytes.
    for hex in ["0404deadbeef", "0404 8002 abcd"] {
        let n = der(&h(hex)).unwrap();
        let Detail::Der { items } = &n.detail else {
            panic!()
        };
        assert_eq!(items[0].value, Asn1Value::Bytes, "{hex}");
    }
}

#[test]
fn der_integers_and_noncanonical_lengths() {
    let n = auto(&h("3006 0201ff 020100"));
    assert_eq!(n.codec, Codec::Der);
    let j = to_json(&n);
    assert!(
        j.contains(r#""int":"-1""#) && j.contains(r#""int":"0""#),
        "{j}"
    );
    // Long-form length for a 3-byte body: valid BER, flagged as non-DER.
    let n = auto(&h("308103 020105"));
    assert_eq!(n.codec, Codec::Der);
    assert_eq!(n.warnings[0].code, "NONCANONICAL_DER");
    assert!(n.confidence < 0.95);
}

#[test]
fn der_errors_have_codes_and_offsets() {
    let e = der(&h("3080 020105 0000")).unwrap_err();
    assert_eq!((e.code, e.offset), ("INDEFINITE_LENGTH", Some(1)));
    let e = der(&h("3005 0201")).unwrap_err();
    assert_eq!((e.code, e.offset), ("TRUNCATED_ELEMENT", Some(1)));
    let e = der(&h("3003 0205 01")).unwrap_err();
    assert_eq!((e.code, e.offset), ("TRUNCATED_ELEMENT", Some(3)));
}

#[test]
fn protobuf_starting_with_0x30_is_not_der() {
    // Field 6 varint 150: 0x30 is also the SEQUENCE tag.
    let n = auto(&h("309601"));
    assert_eq!(n.codec, Codec::Protobuf);
    // Parses as DER, but a BOOLEAN of length 2 is malformed: not DER.
    let n = auto(&h("3004 0102 0101"));
    assert_ne!(n.codec, Codec::Der);
}

// ------------------------------------------------------------ dumps

const XXD: &str = "00000000: 0a03 666f 6f12 0568 656c 6c6f 1896 01    ..foo..hello...\n";
const HEXDUMP: &str =
    "00000000  0a 03 66 6f 6f 12 05 68  65 6c 6c 6f 18 96 01     |..foo..hello...|\n0000000f\n";

#[test]
fn xxd_and_hexdump_input() {
    for (input, style) in [(XXD, "xxd"), (HEXDUMP, "hexdump")] {
        let n = auto(input.as_bytes());
        assert_eq!(n.codec, Codec::Dump { style, start: 0 }, "{style}");
        assert_eq!(varint_value(select(&n, "3").unwrap()), 150);
    }
}

#[test]
fn dump_ascii_column_is_ignored() {
    // The ASCII column of 0xca 0xfe 0xba 0xbe would never be hex, but a
    // column made of hex-looking text must not be read as data either.
    let n = auto(b"00000000: 6361 6665  cafe\n");
    assert_eq!(
        n.codec,
        Codec::Dump {
            style: "xxd",
            start: 0
        }
    );
    assert_eq!(
        child(&n).detail,
        Detail::Text {
            text: "cafe".into()
        }
    );
}

// A dump produced by `xxd -s 0x40` / `hexdump -C -s 64`: same bytes as above,
// but every offset is shifted by 64.
const XXD_OFFSET: &str = "00000040: 0a03 666f 6f12 0568 656c 6c6f 1896 01    ..foo..hello...\n";
const HEXDUMP_OFFSET: &str =
    "00000040  0a 03 66 6f 6f 12 05 68  65 6c 6c 6f 18 96 01     |..foo..hello...|\n0000004f\n";

#[test]
fn dump_nonzero_start_input() {
    for (input, style) in [(XXD_OFFSET, "xxd"), (HEXDUMP_OFFSET, "hexdump")] {
        let n = auto(input.as_bytes());
        assert_eq!(n.codec, Codec::Dump { style, start: 64 }, "{style}");
        assert_eq!(varint_value(select(&n, "3").unwrap()), 150);
        // Child byte ranges stay relative to the decoded bytes (0-based).
        assert_eq!(child(&n).range, [0, 15], "{style}");
        let j = to_json(&n);
        assert!(j.contains("\"start\":64"), "{style}: {j}");
        let t = to_tree(&n);
        assert!(t.contains("start=64"), "{style}: {t}");
    }
}

#[test]
fn zero_start_dump_has_no_start_field() {
    // Existing (offset-0) output is unchanged: no `"start"` key at all.
    assert!(!to_json(&auto(XXD.as_bytes())).contains("\"start\""));
}

#[test]
fn nonzero_leading_numbers_are_not_dumps() {
    // A nonzero leading number must not turn prose into a dump.
    assert_eq!(auto(b"1234: foo").codec, Codec::Utf8);
    assert_ne!(auto(b"1234: this is not a hex dump\n").codec.name(), "dump");
    // Numbered lines of hex are contiguous "offsets"; a nonzero start needs
    // an 8-digit offset column, so this stays text.
    assert_ne!(auto(b"1: ab\n2: cd\n3: ef\n").codec.name(), "dump");
    assert_ne!(auto(b"0040  ab cd  |..|\n0042\n").codec.name(), "dump");
}

#[test]
fn malformed_dump_errors_when_forced_as_hex() {
    let opts = Options {
        input: InputForm::Hex,
        ..Options::default()
    };
    let e = peel(b"00000000: 0a03\n00000010: 0a03\n", &opts).unwrap_err();
    assert_eq!((e.code, e.offset), ("BAD_DUMP", Some(15)));
    // Plain hex is still plain hex under --in hex.
    assert_eq!(peel(b"0a03666f6f", &opts).unwrap().codec, Codec::Hex);
}

// ------------------------------------------------------------ JWT

#[test]
fn jwt_hs256() {
    let payload = r#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#;
    let token = hs256_token(payload);
    let n = auto(token.as_bytes());
    assert_eq!(n.codec, Codec::Jwt { kind: "jws" });
    assert_eq!(n.range, [0, token.len()]);
    assert_eq!(n.confidence, 0.97);

    let (parts, times) = parts_of(&n);
    assert_eq!(parts.len(), 3);
    for p in parts {
        assert_eq!(
            p.codec,
            Codec::Base64 {
                alphabet: Alphabet::Url,
                padded: false
            }
        );
    }
    // Ranges are the segments themselves, dots excluded.
    assert_eq!(parts[0].range[0], 0);
    assert_eq!(parts[1].range[0], parts[0].range[1] + 1);
    assert_eq!(parts[2].range[0], parts[1].range[1] + 1);
    assert_eq!(parts[2].range[1], token.len());
    // Header and payload are text leaves; the signature is random bytes.
    assert!(
        matches!(&child(&parts[0]).detail, Detail::Text { text } if text.starts_with("{\"alg\""))
    );
    assert!(matches!(&child(&parts[1]).detail, Detail::Text { text } if text == payload));

    let got: Vec<(String, String)> = times
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect();
    assert_eq!(
        got,
        [("iat".to_string(), "2018-01-18T01:30:22Z".to_string())]
    );

    let j = to_json(&n);
    assert!(j.contains(r#""codec":"jwt","kind":"jws""#), "{j}");
    assert!(j.contains(r#""parts":["#), "{j}");
    assert!(
        j.contains(r#""times":{"iat":"2018-01-18T01:30:22Z"}"#),
        "{j}"
    );
    let t = to_tree(&n);
    assert!(t.starts_with("jwt(jws) [0.."), "{t}");
    assert!(t.contains("iat=2018-01-18T01:30:22Z"), "{t}");
}

#[test]
fn jwt_alg_none_has_empty_signature() {
    // `alg: none` tokens end in a dot with an empty signature segment.
    let token = none_token(r#"{"exp":0}"#);
    assert!(token.ends_with('.'));
    let n = auto(token.as_bytes());
    assert_eq!(n.codec, Codec::Jwt { kind: "jws" });
    let (parts, _) = parts_of(&n);
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[2].range[0], parts[2].range[1]);
    let c = child(&parts[2]);
    assert_eq!(c.codec, Codec::Bytes);
    assert!(matches!(&c.detail, Detail::Bytes { bytes } if bytes.is_empty()));
}

#[test]
fn jwt_jwe_with_empty_encrypted_key() {
    let token = jwe_token();
    let n = auto(token.as_bytes());
    assert_eq!(n.codec, Codec::Jwt { kind: "jwe" });
    let (parts, times) = parts_of(&n);
    assert_eq!(parts.len(), 5);
    assert_eq!(parts[1].range[0], parts[1].range[1]);
    assert!(times.is_empty());
    let j = to_json(&n);
    assert!(j.contains(r#""kind":"jwe""#), "{j}");
    assert!(!j.contains(r#""times""#), "{j}");
    let t = to_tree(&n);
    assert!(t.starts_with("jwt(jwe) [0.."), "{t}");
}

#[test]
fn jwt_nested_in_protobuf_string() {
    let token = none_token(r#"{"exp":0}"#);
    let mut proto = vec![0x0a, token.len() as u8];
    proto.extend_from_slice(token.as_bytes());
    let n = forced_pb(&proto).unwrap();
    let f = &msg(&n)[0];
    assert_eq!(f.number, 1);
    let FieldValue::Len { alts, .. } = &f.value else {
        panic!("not LEN")
    };
    let d = alts
        .iter()
        .find_map(|a| match &a.kind {
            AltKind::String {
                decoded: Some(d), ..
            } if matches!(&d.codec, Codec::Jwt { .. }) => Some(d),
            _ => None,
        })
        .expect("the string alt should decode to the nested JWT");
    assert_eq!(d.codec, Codec::Jwt { kind: "jws" });
    assert!(to_json(d).contains(r#""exp":"1970-01-01T00:00:00Z""#));
}

#[test]
fn dotted_text_is_not_a_jwt() {
    for s in ["a.b.c", "1.2.3", "www.example.com"] {
        assert_ne!(auto(s.as_bytes()).codec.name(), "jwt", "{s}");
    }
    // Three base64url segments, but the header is not JSON with "alg".
    let no_alg = jws(r#"{"typ":"JWT"}"#, r#"{"x":1}"#, b"sig");
    assert_ne!(auto(no_alg.as_bytes()).codec.name(), "jwt", "{no_alg}");
    let not_json = format!("{}.{}.{}", b64url(b"not json"), b64url(b"{}"), b64url(b"x"));
    assert_ne!(auto(not_json.as_bytes()).codec.name(), "jwt", "{not_json}");
}

#[test]
fn jwt_time_claims() {
    let cases = [
        (0i64, "1970-01-01T00:00:00Z"),
        (-1, "1969-12-31T23:59:59Z"),
        (1_709_164_800, "2024-02-29T00:00:00Z"),
        (4_102_444_800, "2100-01-01T00:00:00Z"),
        (2_147_483_648, "2038-01-19T03:14:08Z"),
    ];
    for (epoch, iso) in cases {
        let token = hs256_token(&format!("{{\"exp\":{epoch}}}"));
        let n = auto(token.as_bytes());
        let (_, times) = parts_of(&n);
        assert_eq!(times.len(), 1, "{epoch}");
        assert_eq!(times[0].0, "exp", "{epoch}");
        assert_eq!(times[0].1, iso, "{epoch}");
    }
}

#[test]
fn jwt_time_claims_order_and_fraction() {
    // Fixed order exp, nbf, iat; a fractional part is truncated toward zero.
    let token = hs256_token(r#"{"iat":1,"nbf":2,"exp":1516239022.5}"#);
    let n = auto(token.as_bytes());
    let (_, times) = parts_of(&n);
    let got: Vec<(&str, &str)> = times.iter().map(|(k, v)| (*k, v.as_str())).collect();
    assert_eq!(
        got,
        [
            ("exp", "2018-01-18T01:30:22Z"),
            ("nbf", "1970-01-01T00:00:02Z"),
            ("iat", "1970-01-01T00:00:01Z"),
        ]
    );
}

#[test]
fn jwt_time_claims_are_top_level_numbers_only() {
    for payload in [
        r#"{"x":{"exp":5}}"#,
        r#"{"a":"exp"}"#,
        r#"{"exp":"5"}"#,
        r#"{"exp":null}"#,
        r#"[{"exp":5}]"#,
    ] {
        let token = hs256_token(payload);
        let n = auto(token.as_bytes());
        assert_eq!(n.codec.name(), "jwt", "{payload}");
        let (_, times) = parts_of(&n);
        assert!(times.is_empty(), "{payload} -> {times:?}");
    }
}

// ------------------------------------------------------------ CBOR

#[test]
fn cbor_rfc8949_uints() {
    for (hex, val) in [
        ("00", 0u64),
        ("01", 1),
        ("0a", 10),
        ("17", 23),
        ("1818", 24),
        ("1819", 25),
        ("1864", 100),
        ("1903e8", 1000),
        ("1a000f4240", 1_000_000),
        ("1b000000e8d4a51000", 1_000_000_000_000),
        ("1bffffffffffffffff", u64::MAX),
    ] {
        let n = cbor(hex);
        assert_eq!(values_of(&n)[0].kind, ValueKind::Uint(val), "{hex}");
        assert!(
            to_json(&n).contains(&format!("\"value\":\"{val}\"")),
            "{hex}: {}",
            to_json(&n)
        );
    }
}

#[test]
fn cbor_rfc8949_nints() {
    for (hex, n, dec) in [
        ("20", 0u64, "-1"),
        ("29", 9, "-10"),
        ("3863", 99, "-100"),
        ("3903e7", 999, "-1000"),
        ("3bffffffffffffffff", u64::MAX, "-18446744073709551616"),
    ] {
        let node = cbor(hex);
        assert_eq!(values_of(&node)[0].kind, ValueKind::Nint(n), "{hex}");
        assert!(
            to_json(&node).contains(&format!("\"value\":\"{dec}\"")),
            "{hex}"
        );
    }
}

#[test]
fn cbor_rfc8949_bignums() {
    // 2^64 and -1 - 2^64.
    let j = to_json(&cbor("c249010000000000000000"));
    assert!(
        j.contains(r#""name":"bignum""#) && j.contains(r#""int":"18446744073709551616""#),
        "{j}"
    );
    let j = to_json(&cbor("c349010000000000000000"));
    assert!(
        j.contains(r#""name":"negbignum""#) && j.contains(r#""int":"-18446744073709551617""#),
        "{j}"
    );
}

#[test]
fn cbor_rfc8949_floats() {
    for (hex, val, width) in [
        ("f90000", 0.0f64, 16u8),
        ("f93c00", 1.0, 16),
        ("f93e00", 1.5, 16),
        ("f97bff", 65504.0, 16),
        ("f90001", 5.960_464_477_539_063e-8, 16),
        ("fa47c35000", 100000.0, 32),
        ("fb3ff199999999999a", 1.1, 64),
    ] {
        match values_of(&cbor(hex))[0].kind {
            ValueKind::Float { value, width: w } => {
                assert_eq!(w, width, "{hex}");
                assert_eq!(value, val, "{hex}");
            }
            _ => panic!("{hex} is not a float"),
        }
        assert!(
            to_json(&cbor(hex)).contains(&format!("\"width\":{width}")),
            "{hex}"
        );
    }
    // -0.0, +Infinity and NaN.
    match values_of(&cbor("f98000"))[0].kind {
        ValueKind::Float { value, .. } => assert!(value == 0.0 && value.is_sign_negative()),
        _ => panic!(),
    }
    match values_of(&cbor("f97c00"))[0].kind {
        ValueKind::Float { value, .. } => assert_eq!(value, f64::INFINITY),
        _ => panic!(),
    }
    assert!(to_json(&cbor("f97e00")).contains(r#""value":"NaN""#));
}

#[test]
fn cbor_rfc8949_simple() {
    assert_eq!(values_of(&cbor("f4"))[0].kind, ValueKind::Bool(false));
    assert_eq!(values_of(&cbor("f5"))[0].kind, ValueKind::Bool(true));
    assert_eq!(values_of(&cbor("f6"))[0].kind, ValueKind::Null);
    assert_eq!(values_of(&cbor("f7"))[0].kind, ValueKind::Undefined);
    assert_eq!(values_of(&cbor("f0"))[0].kind, ValueKind::Simple(16));
    assert_eq!(values_of(&cbor("f8ff"))[0].kind, ValueKind::Simple(255));
}

#[test]
fn cbor_rfc8949_strings_arrays_maps() {
    assert_eq!(
        values_of(&cbor("4401020304"))[0].kind,
        ValueKind::Bytes {
            data: vec![1, 2, 3, 4],
            decoded: None
        }
    );
    assert_eq!(
        values_of(&cbor("6449455446"))[0].kind,
        ValueKind::Text("IETF".into())
    );
    assert_eq!(
        values_of(&cbor("62c3bc"))[0].kind,
        ValueKind::Text("ü".into())
    );
    assert_eq!(
        values_of(&cbor("63e6b0b4"))[0].kind,
        ValueKind::Text("水".into())
    );

    // [1, [2, 3], [4, 5]]
    match &values_of(&cbor("8301820203820405"))[0].kind {
        ValueKind::Array(items) => {
            assert_eq!(items.len(), 3);
            assert_eq!(items[0].kind, ValueKind::Uint(1));
            assert!(matches!(items[1].kind, ValueKind::Array(ref x) if x.len() == 2));
        }
        _ => panic!("not an array"),
    }
    // {"a": 1, "b": [2, 3]}
    match &values_of(&cbor("a26161016162820203"))[0].kind {
        ValueKind::Map(entries) => {
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].0.kind, ValueKind::Text("a".into()));
            assert_eq!(entries[0].1.kind, ValueKind::Uint(1));
            assert_eq!(entries[1].0.kind, ValueKind::Text("b".into()));
        }
        _ => panic!("not a map"),
    }
}

#[test]
fn cbor_indefinite() {
    let n = cbor("5f42010243030405ff");
    assert!(values_of(&n)[0].indefinite);
    assert_eq!(
        values_of(&n)[0].kind,
        ValueKind::Bytes {
            data: vec![1, 2, 3, 4, 5],
            decoded: None
        }
    );
    assert!(
        to_json(&n).contains(r#""indefinite":true"#),
        "{}",
        to_json(&n)
    );

    let n = cbor("7f657374726561646d696e67ff");
    assert!(values_of(&n)[0].indefinite);
    assert_eq!(values_of(&n)[0].kind, ValueKind::Text("streaming".into()));

    let n = cbor("9fff");
    assert!(values_of(&n)[0].indefinite);
    assert_eq!(values_of(&n)[0].kind, ValueKind::Array(vec![]));

    // {_ "a": 1, "b": [_ 2, 3]}
    let n = cbor("bf61610161629f0203ffff");
    match &values_of(&n)[0].kind {
        ValueKind::Map(entries) => {
            assert_eq!(entries.len(), 2);
            assert!(entries[1].1.indefinite);
            assert!(matches!(entries[1].1.kind, ValueKind::Array(ref x) if x.len() == 2));
        }
        _ => panic!("not a map"),
    }
}

#[test]
fn cbor_tags() {
    // tag 0 (datetime): the text is already ISO.
    let n = cbor("c074323031332d30332d32315432303a30343a30305a");
    assert!(
        matches!(&values_of(&n)[0].kind, ValueKind::Tag(0, inner) if inner.kind == ValueKind::Text("2013-03-21T20:04:00Z".into()))
    );
    assert!(to_json(&n).contains(r#""name":"datetime""#));

    // tag 1 (epoch), int and float.
    let j = to_json(&cbor("c11a514b67b0"));
    assert!(
        j.contains(r#""name":"epoch""#) && j.contains(r#""iso":"2013-03-21T20:04:00Z""#),
        "{j}"
    );
    assert!(to_json(&cbor("c1fb41d452d9ec200000")).contains(r#""iso":"2013-03-21T20:04:00Z""#));

    // tag 24 (embedded CBOR): the bytes decode as CBOR.
    match &values_of(&cbor("d818456449455446"))[0].kind {
        ValueKind::Tag(24, inner) => match &inner.kind {
            ValueKind::Bytes {
                decoded: Some(d), ..
            } => {
                assert_eq!(d.codec, Codec::Cbor);
                assert!(to_json(d).contains(r#""value":"IETF""#));
            }
            _ => panic!("tag 24 should carry decoded CBOR"),
        },
        _ => panic!("not tag 24"),
    }

    // tag 32 (uri) and tag 37 (uuid).
    assert!(
        to_json(&cbor("d82076687474703a2f2f7777772e6578616d706c652e636f6d"))
            .contains(r#""name":"uri""#)
    );
    let j = to_json(&cbor("d82550123456789abcdef01122334455667788"));
    assert!(
        j.contains(r#""uuid":"12345678-9abc-def0-1122-334455667788""#),
        "{j}"
    );
}

#[test]
fn cbor_detection() {
    // A realistic map, detected without forcing.
    let n = auto(include_bytes!("fixtures/record.cbor"));
    assert_eq!(n.codec, Codec::Cbor);
    assert_eq!(n.confidence, 0.9);
    assert!(values_of(&n).len() == 1);
    // A plain array.
    assert_eq!(auto(&h("83010203")).codec, Codec::Cbor);
    // A self-describe tag is near-certain.
    assert_eq!(auto(&h("d9d9f783010203")).confidence, 0.99);
    // Protobuf bytes are not CBOR.
    assert_eq!(auto(&h("089601")).codec, Codec::Protobuf);
    // Plain text is not CBOR.
    assert_eq!(auto(b"hello world").codec, Codec::Utf8);
}

#[test]
fn cbor_bytes_key_lowers_confidence() {
    // {bytes(0x01): 1} has a non-text, non-small-int key.
    let n = auto(&h("a1410101"));
    assert_eq!(n.codec, Codec::Cbor);
    assert_eq!(n.confidence, 0.7);
}

#[test]
fn cbor_ambiguity_is_reported() {
    // Also a plausible protobuf (field 16 LEN len 0), but CBOR scores higher.
    let n = auto(&h("820100"));
    assert_eq!(n.codec, Codec::Cbor);
    assert_eq!(n.warnings.len(), 1);
    assert_eq!(n.warnings[0].code, "AMBIGUOUS_FORMAT");
    assert!(
        n.warnings[0].message.contains("protobuf") && n.warnings[0].message.contains("0.54"),
        "{}",
        n.warnings[0].message
    );

    // Here protobuf scores higher than the CBOR map (a bytes key).
    let n = auto(&h("a2010241081800"));
    assert_eq!(n.codec, Codec::Protobuf);
    assert_eq!(n.warnings.len(), 1);
    assert_eq!(n.warnings[0].code, "AMBIGUOUS_FORMAT");
    assert!(
        n.warnings[0].message.contains("cbor") && n.warnings[0].message.contains("0.70"),
        "{}",
        n.warnings[0].message
    );
}

#[test]
fn cbor_errors_have_codes_and_offsets() {
    for (hex, code, off) in [
        ("1c", "CBOR_RESERVED", 0),
        ("f800", "CBOR_RESERVED", 0),
        ("ff", "CBOR_BREAK", 0),
        ("62c3", "CBOR_TRUNCATED", 0),
        ("61ff", "CBOR_BAD_UTF8", 1),
    ] {
        let e = peel(&h(hex), &cbor_opts()).unwrap_err();
        assert_eq!((e.code, e.offset), (code, Some(off)), "{hex}");
    }
    // Nesting cap (101 arrays around one value).
    let mut deep = vec![0x81u8; 101];
    deep.push(0x00);
    assert_eq!(
        peel(&deep, &cbor_opts()).unwrap_err().code,
        "NESTING_TOO_DEEP"
    );
    // Forced, a CBOR sequence may hold several items.
    let n = peel(&h("0001"), &cbor_opts()).unwrap();
    assert_eq!(values_of(&n).len(), 2);
}

#[test]
fn cbor_select_value() {
    let n = auto(include_bytes!("fixtures/record.cbor"));
    assert!(is_values(&n));
    assert!(!is_der(&n));
    assert_eq!(select_value(&n, "id").unwrap().kind, ValueKind::Uint(42));
    assert_eq!(
        select_value(&n, "name").unwrap().kind,
        ValueKind::Text("Alice".into())
    );
    assert_eq!(
        select_value(&n, "tags.1").unwrap().kind,
        ValueKind::Text("b".into())
    );
    assert_eq!(select_value(&n, "nope").unwrap_err().code, "PATH_NOT_FOUND");
    assert_eq!(
        select_value(&n, "id.x").unwrap_err().code,
        "PATH_NOT_MESSAGE"
    );
    assert_eq!(select_value(&n, "a..b").unwrap_err().code, "BAD_PATH");

    // Array indices, and integer map keys.
    assert_eq!(
        select_value(&cbor("83010203"), "1").unwrap().kind,
        ValueKind::Uint(2)
    );
    assert_eq!(
        select_value(&cbor("a1016161"), "1").unwrap().kind,
        ValueKind::Text("a".into())
    );
    // value_to_json / value_to_tree on a selection.
    let v = select_value(&n, "name").unwrap();
    assert_eq!(
        value_to_json(v),
        r#"{"type":"text","range":[11,17],"value":"Alice"}"#
    );
    assert!(value_to_tree(v).starts_with("text [11..17] \"Alice\""));
}

// ------------------------------------------------------------ MessagePack

#[test]
fn msgpack_integers() {
    for (hex, kind) in [
        ("00", ValueKind::Uint(0)),
        ("7f", ValueKind::Uint(127)),
        ("ccff", ValueKind::Uint(255)),
        ("cd0100", ValueKind::Uint(256)),
        ("ce00010000", ValueKind::Uint(65536)),
        ("cfffffffffffffffff", ValueKind::Uint(u64::MAX)),
        ("ff", ValueKind::Nint(0)),                               // -1
        ("e0", ValueKind::Nint(31)),                              // -32
        ("d0ff", ValueKind::Nint(0)),                             // int8 -1
        ("d080", ValueKind::Nint(127)),                           // int8 -128
        ("d18000", ValueKind::Nint(32767)),                       // int16 min
        ("d280000000", ValueKind::Nint(2147483647)),              // int32 min
        ("d38000000000000000", ValueKind::Nint(i64::MAX as u64)), // int64 min
        ("d37fffffffffffffff", ValueKind::Uint(i64::MAX as u64)), // int64 max
    ] {
        assert_eq!(values_of(&msgpack(hex))[0].kind, kind, "{hex}");
    }
    assert!(to_json(&msgpack("d38000000000000000")).contains(r#""value":"-9223372036854775808""#));
    assert!(to_json(&msgpack("cfffffffffffffffff")).contains(r#""value":"18446744073709551615""#));
}

#[test]
fn msgpack_floats_and_simple() {
    match values_of(&msgpack("ca3fc00000"))[0].kind {
        ValueKind::Float { value, width } => {
            assert_eq!(value, 1.5);
            assert_eq!(width, 32);
        }
        _ => panic!(),
    }
    match values_of(&msgpack("cb3ff8000000000000"))[0].kind {
        ValueKind::Float { value, width } => {
            assert_eq!(value, 1.5);
            assert_eq!(width, 64);
        }
        _ => panic!(),
    }
    assert_eq!(values_of(&msgpack("c0"))[0].kind, ValueKind::Null);
    assert_eq!(values_of(&msgpack("c2"))[0].kind, ValueKind::Bool(false));
    assert_eq!(values_of(&msgpack("c3"))[0].kind, ValueKind::Bool(true));
}

#[test]
fn msgpack_strings() {
    assert_eq!(
        values_of(&msgpack("a568656c6c6f"))[0].kind,
        ValueKind::Text("hello".into())
    );
    assert_eq!(
        values_of(&msgpack("d90568656c6c6f"))[0].kind,
        ValueKind::Text("hello".into())
    );
    assert_eq!(
        values_of(&msgpack("da000568656c6c6f"))[0].kind,
        ValueKind::Text("hello".into())
    );
    // A string that is not valid UTF-8.
    let e = peel(&h("d901ff"), &msgpack_opts()).unwrap_err();
    assert_eq!((e.code, e.offset), ("MSGPACK_BAD_UTF8", Some(2)));
}

#[test]
fn msgpack_bin_and_nested() {
    assert_eq!(
        values_of(&msgpack("c403010203"))[0].kind,
        ValueKind::Bytes {
            data: vec![1, 2, 3],
            decoded: None
        }
    );
    // A bin value whose bytes are DER is decoded once via nested detection.
    match &values_of(&msgpack("c4053003020105"))[0].kind {
        ValueKind::Bytes {
            decoded: Some(d), ..
        } => assert_eq!(d.codec, Codec::Der),
        _ => panic!("bin should decode to DER"),
    }
}

#[test]
fn msgpack_arrays_and_maps() {
    assert!(
        matches!(values_of(&msgpack("93010203"))[0].kind, ValueKind::Array(ref x) if x.len() == 3)
    );
    assert!(
        matches!(values_of(&msgpack("dc00020102"))[0].kind, ValueKind::Array(ref x) if x.len() == 2)
    );
    match &values_of(&msgpack("81a16101"))[0].kind {
        ValueKind::Map(entries) => {
            assert_eq!(entries[0].0.kind, ValueKind::Text("a".into()));
            assert_eq!(entries[0].1.kind, ValueKind::Uint(1));
        }
        _ => panic!(),
    }
    assert!(
        matches!(values_of(&msgpack("de0001a16101"))[0].kind, ValueKind::Map(ref e) if e.len() == 1)
    );
}

#[test]
fn msgpack_ext_and_timestamps() {
    // Generic extensions of every width.
    for (hex, ty, data) in [
        ("d40500", 5i8, vec![0u8]),
        ("d5050001", 5, vec![0, 1]),
        ("d60500010203", 5, vec![0, 1, 2, 3]),
        ("c70305010203", 5, vec![1, 2, 3]),
        ("c8000305010203", 5, vec![1, 2, 3]),
        ("c90000000305010203", 5, vec![1, 2, 3]),
    ] {
        assert_eq!(
            values_of(&msgpack(hex))[0].kind,
            ValueKind::Ext { type_: ty, data },
            "{hex}"
        );
    }
    assert!(to_json(&msgpack("c70305010203")).contains(r#""ext_type":5"#));

    // ext type -1 with a non-timestamp length has no iso.
    let j = to_json(&msgpack("d4ff00"));
    assert!(
        j.contains(r#""ext_type":-1"#) && !j.contains(r#""iso""#),
        "{j}"
    );

    // timestamp 32: 2017-01-30T07:54:33Z.
    let mut b = vec![0xd6, 0xff];
    b.extend_from_slice(&1_485_762_873u32.to_be_bytes());
    let j = to_json(&msgpack_bytes(&b));
    assert!(j.contains(r#""iso":"2017-01-30T07:54:33Z""#), "{j}");

    // timestamp 64: nanoseconds in the upper 30 bits.
    let v = (123_456_789u64 << 34) | 1_485_762_873;
    let mut b = vec![0xd7, 0xff];
    b.extend_from_slice(&v.to_be_bytes());
    let j = to_json(&msgpack_bytes(&b));
    assert!(
        j.contains(r#""iso":"2017-01-30T07:54:33.123456789Z""#),
        "{j}"
    );

    // timestamp 96: nanoseconds + signed seconds, before 1970.
    let mut b = vec![0xc7, 0x0c, 0xff];
    b.extend_from_slice(&500_000_000u32.to_be_bytes());
    b.extend_from_slice(&(-1i64).to_be_bytes());
    let j = to_json(&msgpack_bytes(&b));
    assert!(j.contains(r#""iso":"1969-12-31T23:59:59.5Z""#), "{j}");
}

#[test]
fn msgpack_errors_and_bounds() {
    assert_eq!(
        peel(&h("c1"), &msgpack_opts()).unwrap_err().code,
        "MSGPACK_RESERVED"
    );
    let e = peel(&h("c4030102"), &msgpack_opts()).unwrap_err();
    assert_eq!((e.code, e.offset), ("MSGPACK_TRUNCATED", Some(0)));
    // Huge declared lengths must fail fast, before any allocation.
    for hex in ["ddffffffff", "dfffffffff", "c6ffffffff", "dbffffffff"] {
        assert_eq!(
            peel(&h(hex), &msgpack_opts()).unwrap_err().code,
            "MSGPACK_TRUNCATED",
            "{hex}"
        );
    }
    // Nesting cap (101 arrays around one value).
    let mut deep = vec![0x91u8; 101];
    deep.push(0x00);
    assert_eq!(
        peel(&deep, &msgpack_opts()).unwrap_err().code,
        "NESTING_TOO_DEEP"
    );
    // Forced, a sequence may hold several items.
    assert_eq!(
        values_of(&peel(&h("0001"), &msgpack_opts()).unwrap()).len(),
        2
    );
}

#[test]
fn msgpack_detection() {
    let n = auto(include_bytes!("fixtures/record.msgpack"));
    assert_eq!(n.codec, Codec::Msgpack);
    assert_eq!(n.confidence, 0.9);

    // A MessagePack map with string keys is not CBOR.
    assert_eq!(auto(&h("82a16101a162920102")).codec, Codec::Msgpack);
    // A CBOR map with text keys is not MessagePack.
    assert_eq!(auto(&h("a26161016162820203")).codec, Codec::Cbor);
    // Plain protobuf is not mistaken for MessagePack.
    assert_eq!(auto(&h("089601")).codec, Codec::Protobuf);

    // A buffer that is valid as several codecs: CBOR array [0, 1] (no map:
    // weak, 0.6), MessagePack map {24: 0, 24: 1} (0.9) and protobuf. The map
    // wins, and every other interpretation is named in one warning.
    let n = auto(&h("8218001801"));
    assert_eq!(n.codec, Codec::Msgpack);
    assert_eq!(n.warnings.len(), 1);
    assert_eq!(n.warnings[0].code, "AMBIGUOUS_FORMAT");
    assert!(
        n.warnings[0].message.contains("cbor") && n.warnings[0].message.contains("protobuf"),
        "{}",
        n.warnings[0].message
    );
}

#[test]
fn msgpack_select_value() {
    let n = auto(include_bytes!("fixtures/record.msgpack"));
    assert!(is_values(&n));
    assert_eq!(
        select_value(&n, "name").unwrap().kind,
        ValueKind::Text("Alice".into())
    );
    assert_eq!(
        select_value(&n, "tags.1").unwrap().kind,
        ValueKind::Text("b".into())
    );
    assert_eq!(select_value(&n, "id").unwrap().kind, ValueKind::Uint(42));
    assert_eq!(select_value(&n, "nope").unwrap_err().code, "PATH_NOT_FOUND");
}

// ------------------------------------------------------------ JSON

// ------------------------------------------------------------ packed fixed

/// Field 1: packed doubles [51.5074, -0.1278]; field 2: packed floats
/// [1.5, 2.25, -3]; field 3: packed varints [1, 2, 3, 150, 127, 5, 6].
fn packed_fixed_msg() -> Vec<u8> {
    let mut m = vec![0x0a, 16];
    for d in [51.5074f64, -0.1278] {
        m.extend_from_slice(&d.to_le_bytes());
    }
    m.extend_from_slice(&[0x12, 12]);
    for f in [1.5f32, 2.25, -3.0] {
        m.extend_from_slice(&f.to_le_bytes());
    }
    m.extend_from_slice(&h("1a08 01020396017f0506"));
    m
}

#[test]
fn packed_fixed_width_alts() {
    let n = forced_pb(&packed_fixed_msg()).unwrap();
    let f = msg(&n);
    match &top_alt(&f[0]).kind {
        AltKind::PackedFixed64(v) => {
            assert_eq!(f64::from_bits(v[0]), 51.5074);
            assert_eq!(f64::from_bits(v[1]), -0.1278);
        }
        k => panic!("field 1: {}", k.name()),
    }
    match &top_alt(&f[1]).kind {
        AltKind::PackedFixed32(v) => {
            let fs: Vec<f32> = v.iter().map(|&x| f32::from_bits(x)).collect();
            assert_eq!(fs, [1.5, 2.25, -3.0]);
        }
        k => panic!("field 2: {}", k.name()),
    }
    // Small varints read as floats are denormal: packed_varint still wins.
    assert_eq!(top_alt(&f[2]).kind.name(), "packed_varint");
    let j = field_to_json(&f[1]);
    assert!(j.contains(r#""as":"packed_fixed32""#), "{j}");
    assert!(
        j.contains(r#""values":[1069547520,1074790400,3225419776],"floats":[1.5,2.25,-3]"#),
        "{j}"
    );
    let j = field_to_json(&f[0]);
    assert!(
        j.contains(
            r#""values":["4632445839417212613","13817144537404334827"],"doubles":[51.5074,-0.1278]"#
        ),
        "{j}"
    );
}

#[test]
fn printable_payload_keeps_fixed_alts_low() {
    // 8 printable bytes: a fixed64 reading is listed but never preferred.
    let n = forced_pb(b"\x0a\x08abcdefgh").unwrap();
    assert_eq!(top_alt(&msg(&n)[0]).kind.name(), "string");
}

// ------------------------------------------------------------ JWT --get

fn jwt_get_token() -> String {
    jws(
        r#"{"alg":"HS256","typ":"JWT"}"#,
        r#"{"sub":"1234","name":"Jö \"x\"","roles":["admin","dev"],"n":{"a":[1,2.5]},"sub":"dup"}"#,
        b"\x01\x02sig",
    )
}

#[test]
fn jwt_get_parts_and_claims() {
    let token = jwt_get_token();
    let n = auto(token.as_bytes());
    assert!(is_jwt(&n));
    assert!(!is_der(&n) && !is_values(&n));

    let p = select_jwt(&n, "payload").unwrap();
    assert_eq!((p.part, p.index, p.json), ("payload", 1, None));
    assert_eq!(select_jwt(&n, "1").unwrap().part, "payload");
    let sig = select_jwt(&n, "signature").unwrap();
    assert_eq!(sig.payload(), b"\x01\x02sig");

    let sub = select_jwt(&n, "payload.sub").unwrap();
    assert_eq!(sub.json.unwrap().1, r#""1234""#, "first duplicate key wins");
    assert_eq!(sub.payload(), b"1234");
    let name = select_jwt(&n, "payload.name").unwrap();
    assert_eq!(String::from_utf8(name.payload()).unwrap(), "Jö \"x\"");
    assert_eq!(select_jwt(&n, "payload.roles.1").unwrap().payload(), b"dev");
    assert_eq!(select_jwt(&n, "payload.n.a.1").unwrap().payload(), b"2.5");
    assert_eq!(
        select_jwt(&n, "payload.n").unwrap().payload(),
        br#"{"a":[1,2.5]}"#
    );
    assert_eq!(select_jwt(&n, "header.alg").unwrap().payload(), b"HS256");
    let j = select_jwt(&n, "payload.sub").unwrap().to_json();
    assert_eq!(
        j,
        r#"{"part":"payload","index":1,"path":"sub","range":[7,13],"value":"1234"}"#
    );
    assert_eq!(
        select_jwt(&n, "header.alg").unwrap().to_tree(),
        "header.alg = \"HS256\"\n"
    );

    let code = |p: &str| select_jwt(&n, p).unwrap_err().code;
    assert_eq!(code("bogus"), "PATH_NOT_FOUND");
    assert_eq!(code("3"), "PATH_NOT_FOUND");
    assert_eq!(code("payload.nope"), "PATH_NOT_FOUND");
    assert_eq!(code("payload.roles.7"), "PATH_NOT_FOUND");
    assert_eq!(code("payload.sub.x"), "PATH_NOT_MESSAGE");
    assert_eq!(code("signature.x"), "PATH_NOT_MESSAGE");
    assert_eq!(code("payload..sub"), "BAD_PATH");
    assert_eq!(code(""), "BAD_PATH");
}

#[test]
fn jwe_part_names() {
    let n = auto(jwe_token().as_bytes());
    let names: Vec<&str> = (0..5)
        .map(|i| select_jwt(&n, &i.to_string()).unwrap().part)
        .collect();
    assert_eq!(
        names,
        ["header", "encrypted_key", "iv", "ciphertext", "tag"]
    );
    assert_eq!(select_jwt(&n, "iv").unwrap().index, 2);
    assert_eq!(
        select_jwt(&n, "payload").unwrap_err().code,
        "PATH_NOT_FOUND"
    );
}

#[test]
fn jwt_get_rejects_invalid_json() {
    // A payload that only looks like JSON never yields a value.
    let token = jws(r#"{"alg":"none"}"#, r#"{"a":01}"#, b"");
    let n = auto(token.as_bytes());
    assert_eq!(
        select_jwt(&n, "payload.a").unwrap_err().code,
        "PATH_NOT_MESSAGE"
    );
}

// ------------------------------------------------------------ nested warnings

#[cfg(feature = "deflate")]
#[test]
fn corrupt_stream_in_byte_string_keeps_its_warning() {
    // A CBOR byte string holding a gzip stream with a broken CRC: the bytes
    // leaf is kept as `decoded` so the CHECKSUM_MISMATCH warning is visible.
    let mut gz = include_bytes!("fixtures/msg.bin.gz").to_vec();
    let at = gz.len() - 8;
    gz[at] ^= 0xff;
    let mut cbor = vec![0x81, 0x58, gz.len() as u8];
    cbor.extend_from_slice(&gz);
    let n = auto(&cbor);
    let j = to_json(&n);
    assert!(j.contains(r#""code":"CHECKSUM_MISMATCH""#), "{j}");
}

#[test]
fn json_is_valid_and_deterministic() {
    let inputs: Vec<Vec<u8>> = vec![
        h("089601"),
        h("10feffffffffffffffff01"),
        h("0a03666f6f"),
        h("1a03089601"),
        h("09000000000000f87f150000807f"),
        h("0b10010c"),
        h("0a00"),
        h("3003020105"),
        h("3006 0201ff 020100"),
        h("308103 020105"),
        ISRG_X2.as_bytes().to_vec(),
        format!("{ISRG_X2}{ISRG_X2}").into_bytes(),
        format!(
            "{ISRG_X2}{}",
            &ISRG_X2[..ISRG_X2.find("-----END").unwrap() / 2]
        )
        .into_bytes(),
        format!("subject=/CN=x\n{ISRG_X2}Bag Attributes\n    friendlyName: y\n{ISRG_X2}tail\n")
            .into_bytes(),
        XXD.as_bytes().to_vec(),
        include_bytes!("fixtures/msg.bin.gz").to_vec(),
        include_bytes!("fixtures/two-members.gz").to_vec(),
        include_bytes!("fixtures/json.zst").to_vec(),
        include_bytes!("fixtures/text.zlib").to_vec(),
        HEXDUMP.as_bytes().to_vec(),
        XXD_OFFSET.as_bytes().to_vec(),
        HEXDUMP_OFFSET.as_bytes().to_vec(),
        h("3012 0c03e282ac 1e04d83dde00 170d3236313131323039333030305a"),
        h("deadbeef"),
        b"SGVsbG8gd29ybGQ=".to_vec(),
        b"with \"quotes\" \\ and \t tabs".to_vec(),
        format!(
            "-----BEGIN X-----\n{}\n-----END X-----\ntrailing",
            b64(b"\x01\x02")
        )
        .into_bytes(),
        vec![0x0a, 0x02, 0x01, 0x02],
        hs256_token(r#"{"exp":1516239022,"nbf":0,"iat":-1}"#).into_bytes(),
        none_token(r#"{"exp":0}"#).into_bytes(),
        jwe_token().into_bytes(),
        b"a.b.c".to_vec(),
        include_bytes!("fixtures/record.cbor").to_vec(),
        include_bytes!("fixtures/record.msgpack").to_vec(),
        h("82a16101a162920102"),
        h("8218001801"),
        h("81a174c7037f010203"),
        h("83010203"),
        h("a26161016162820203"),
        h("5f42010243030405ff"),
        h("7f657374726561646d696e67ff"),
        h("c11a514b67b0"),
        h("c249010000000000000000"),
        h("820100"),
        h("f98000"),
        packed_fixed_msg(),
        Vec::new(),
    ];
    for input in inputs {
        let a = to_json(&auto(&input));
        let b = to_json(&auto(&input));
        assert_eq!(a, b);
        json_check::validate(&a).unwrap_or_else(|e| panic!("{e}\n{a}"));
        let _ = to_tree(&auto(&input));
    }
    let e = diag_to_json(&Diag::new("X", "a \"quoted\"\nmessage", Some(3)));
    json_check::validate(&e).unwrap();
    let token = jwt_get_token();
    let n = auto(token.as_bytes());
    for path in [
        "payload",
        "signature",
        "payload.name",
        "payload.n",
        "header.alg",
    ] {
        let j = select_jwt(&n, path).unwrap().to_json();
        json_check::validate(&j).unwrap_or_else(|e| panic!("{e}\n{j}"));
    }
}

/// Minimal strict JSON validator (keeps the core crate's dev-deps at zero).
mod json_check {
    pub fn validate(s: &str) -> Result<(), String> {
        let b = s.as_bytes();
        let mut i = 0;
        value(b, &mut i)?;
        ws(b, &mut i);
        if i == b.len() {
            Ok(())
        } else {
            Err(format!("trailing data at {i}"))
        }
    }
    fn ws(b: &[u8], i: &mut usize) {
        while *i < b.len() && matches!(b[*i], b' ' | b'\n' | b'\r' | b'\t') {
            *i += 1;
        }
    }
    fn err<T>(i: usize, what: &str) -> Result<T, String> {
        Err(format!("expected {what} at {i}"))
    }
    fn value(b: &[u8], i: &mut usize) -> Result<(), String> {
        ws(b, i);
        match b.get(*i) {
            Some(b'{') => {
                *i += 1;
                ws(b, i);
                if b.get(*i) == Some(&b'}') {
                    *i += 1;
                    return Ok(());
                }
                loop {
                    ws(b, i);
                    string(b, i)?;
                    ws(b, i);
                    if b.get(*i) != Some(&b':') {
                        return err(*i, "':'");
                    }
                    *i += 1;
                    value(b, i)?;
                    ws(b, i);
                    match b.get(*i) {
                        Some(b',') => *i += 1,
                        Some(b'}') => {
                            *i += 1;
                            return Ok(());
                        }
                        _ => return err(*i, "',' or '}'"),
                    }
                }
            }
            Some(b'[') => {
                *i += 1;
                ws(b, i);
                if b.get(*i) == Some(&b']') {
                    *i += 1;
                    return Ok(());
                }
                loop {
                    value(b, i)?;
                    ws(b, i);
                    match b.get(*i) {
                        Some(b',') => *i += 1,
                        Some(b']') => {
                            *i += 1;
                            return Ok(());
                        }
                        _ => return err(*i, "',' or ']'"),
                    }
                }
            }
            Some(b'"') => string(b, i),
            Some(b't') => lit(b, i, b"true"),
            Some(b'f') => lit(b, i, b"false"),
            Some(b'n') => lit(b, i, b"null"),
            Some(c) if *c == b'-' || c.is_ascii_digit() => number(b, i),
            _ => err(*i, "a value"),
        }
    }
    fn lit(b: &[u8], i: &mut usize, w: &[u8]) -> Result<(), String> {
        if b[*i..].starts_with(w) {
            *i += w.len();
            Ok(())
        } else {
            err(*i, "literal")
        }
    }
    fn string(b: &[u8], i: &mut usize) -> Result<(), String> {
        if b.get(*i) != Some(&b'"') {
            return err(*i, "string");
        }
        *i += 1;
        loop {
            match b.get(*i) {
                None => return err(*i, "closing quote"),
                Some(b'"') => {
                    *i += 1;
                    return Ok(());
                }
                Some(b'\\') => {
                    *i += 1;
                    match b.get(*i) {
                        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => *i += 1,
                        Some(b'u') => {
                            if b.len() < *i + 5
                                || !b[*i + 1..*i + 5].iter().all(u8::is_ascii_hexdigit)
                            {
                                return err(*i, "\\uXXXX");
                            }
                            *i += 5;
                        }
                        _ => return err(*i, "escape"),
                    }
                }
                Some(c) if *c < 0x20 => return err(*i, "no raw control chars"),
                Some(_) => *i += 1,
            }
        }
    }
    fn number(b: &[u8], i: &mut usize) -> Result<(), String> {
        let digits = |i: &mut usize| {
            let s = *i;
            while *i < b.len() && b[*i].is_ascii_digit() {
                *i += 1;
            }
            *i > s
        };
        if b.get(*i) == Some(&b'-') {
            *i += 1;
        }
        if b.get(*i) == Some(&b'0') {
            *i += 1;
        } else if !digits(i) {
            return err(*i, "digits");
        }
        if b.get(*i) == Some(&b'.') {
            *i += 1;
            if !digits(i) {
                return err(*i, "fraction digits");
            }
        }
        if matches!(b.get(*i), Some(b'e' | b'E')) {
            *i += 1;
            if matches!(b.get(*i), Some(b'+' | b'-')) {
                *i += 1;
            }
            if !digits(i) {
                return err(*i, "exponent digits");
            }
        }
        Ok(())
    }
}

#[test]
fn cbor_tag24_chain_is_linear_and_bounded_by_depth() {
    // 40 nested tag-24 byte strings. Each level used to be parsed twice, so
    // the work doubled per level; it must now finish instantly, and --depth
    // must bound how many levels are decoded.
    fn bstr(b: &[u8]) -> Vec<u8> {
        let mut v = match b.len() {
            n if n < 24 => vec![0x40 | n as u8],
            n if n < 256 => vec![0x58, n as u8],
            n => vec![0x59, (n >> 8) as u8, n as u8],
        };
        v.extend_from_slice(b);
        v
    }
    let mut x = vec![0xa1, 0x61, 0x61, 0x01];
    for _ in 0..40 {
        let mut t = vec![0xd8, 0x18];
        t.extend(bstr(&x));
        x = t;
    }
    x.insert(0, 0x81);
    for depth in [4, 16, 64] {
        let opts = Options {
            depth,
            ..Options::default()
        };
        let start = std::time::Instant::now();
        let json = to_json(&peel(&x, &opts).unwrap());
        assert!(
            start.elapsed().as_secs() < 2,
            "depth {depth} took {:?}",
            start.elapsed()
        );
        let levels = json.matches(r#""codec":"cbor""#).count();
        assert!(levels <= depth, "depth {depth} decoded {levels} levels");
    }
}

#[test]
fn ambiguous_chain_is_linear_and_bounded_by_depth() {
    // Every level is a CBOR array(2) whose first element is a byte string
    // holding a MessagePack bin whose content is the next level (plus a
    // trailing 0). Both parsers reach the same nested region, so before
    // candidate parsing was structural, nested detection ran once per parser
    // per level and the work grew ~1.8x per level.
    let mut item: Vec<u8> = vec![0x82, 0x01, 0x02]; // CBOR [1, 2] core
    for _ in 0..48 {
        let mut bin = Vec::new();
        if item.len() <= 0xff {
            bin.push(0xc4);
            bin.push(item.len() as u8);
        } else {
            bin.push(0xc5);
            bin.extend_from_slice(&(item.len() as u16).to_be_bytes());
        }
        bin.extend_from_slice(&item);

        let mut level = vec![0x82];
        if bin.len() <= 0xff {
            level.push(0x58);
            level.push(bin.len() as u8);
        } else {
            level.push(0x59);
            level.extend_from_slice(&(bin.len() as u16).to_be_bytes());
        }
        level.extend_from_slice(&bin);
        level.push(0x00);
        item = level;
    }
    assert!(item.len() > 0xff, "the chain should need 2-byte lengths");

    for depth in [16usize, 64] {
        for force in [None, Some(Force::Cbor), Some(Force::Msgpack)] {
            let opts = Options {
                depth,
                force,
                input: InputForm::Raw,
                ..Options::default()
            };
            let start = std::time::Instant::now();
            let n = peel(&item, &opts).unwrap();
            let elapsed = start.elapsed();
            assert!(
                matches!(&n.codec, Codec::Cbor | Codec::Msgpack),
                "depth {depth} force {force:?}: {}",
                n.codec.name()
            );
            assert!(
                elapsed.as_secs() < 2,
                "depth {depth} force {force:?} took {elapsed:?}"
            );
        }
    }
}

#[test]
fn iso_year_range_is_enforced() {
    fn ts96(secs: i64, nanos: u32) -> Vec<u8> {
        let mut b = vec![0xc7, 0x0c, 0xff];
        b.extend_from_slice(&nanos.to_be_bytes());
        b.extend_from_slice(&secs.to_be_bytes());
        b
    }
    // In range, before 1970: the iso is kept.
    let j = to_json(&msgpack_bytes(&ts96(-1, 500_000_000)));
    assert!(j.contains(r#""iso":"1969-12-31T23:59:59.5Z""#), "{j}");
    // i64::MIN and the first second of year 10000 are out of RFC 3339 range.
    for secs in [i64::MIN, 253_402_300_800] {
        let j = to_json(&msgpack_bytes(&ts96(secs, 0)));
        assert!(j.contains(r#""ext_type":-1"#), "{j}");
        assert!(!j.contains("\"iso\""), "secs {secs}: {j}");
    }
    // CBOR tag 1 with an out-of-range epoch: no iso; an in-range one keeps it.
    let j = to_json(&cbor("c13b7fffffffffffffff")); // tag 1, nint i64::MIN
    assert!(
        j.contains(r#""name":"epoch""#) && !j.contains("\"iso\""),
        "{j}"
    );
    assert!(to_json(&cbor("c11a514b67b0")).contains(r#""iso":"2013-03-21T20:04:00Z""#));
}

#[test]
fn select_ext_value_payload_is_raw() {
    // MessagePack map {"x": ext type 5 [1, 2, 3]}.
    let n = auto(&h("81a178c70305010203"));
    let v = select_value(&n, "x").unwrap();
    assert_eq!(v.payload(), Some(vec![1, 2, 3]));
    assert!(
        value_to_json(v).contains(r#""ext_type":5"#),
        "{}",
        value_to_json(v)
    );
}

#[test]
fn map_less_value_trees_lose_to_plausible_protobuf() {
    // 81 1b <8 bytes> is CBOR [uint64] (an array, no map: 0.6) and also
    // protobuf field 432 as I64 (tag 0x81 0x1b), plausibility 0.9.
    let n = auto(&h("811b0000000000000005"));
    assert_eq!(n.codec, Codec::Protobuf, "{}", to_json(&n));
    assert_eq!(n.warnings[0].code, "AMBIGUOUS_FORMAT");
    assert!(
        n.warnings[0].message.contains("cbor (0.60)"),
        "{}",
        n.warnings[0].message
    );
    // With a text-keyed map inside, CBOR keeps its 0.9.
    assert_eq!(auto(&h("81a1616101")).codec, Codec::Cbor);
}

#[test]
fn der_time_with_multibyte_zone_does_not_panic() {
    // GeneralizedTime "2026111209+a\u{e9}b": a 5-byte zone whose bytes 2..4
    // are one char. Slicing it by byte index used to panic (exit 101).
    let mut buf = vec![0x30, 0x11, 0x18, 0x0f];
    buf.extend_from_slice("2026111209+a\u{e9}b".as_bytes());
    let n = auto(&buf);
    assert_eq!(n.codec, Codec::Der);
    let j = to_json(&n);
    assert!(
        j.contains(r#""tag":"GeneralizedTime""#) && !j.contains(r#""iso""#),
        "{j}"
    );
    // Same for UTCTime under --as der.
    let mut utc = vec![0x17, 0x0f];
    utc.extend_from_slice("26111209300+\u{e9}1".as_bytes());
    let opts = Options {
        input: InputForm::Raw,
        force: Some(Force::Der),
        ..Options::default()
    };
    assert!(peel(&utc, &opts).is_ok());
}

#[test]
fn float_width_uses_source_precision() {
    let cbor = |hex: &str| {
        let opts = Options {
            input: InputForm::Raw,
            force: Some(Force::Cbor),
            ..Options::default()
        };
        to_json(&peel(&h(hex), &opts).unwrap())
    };
    // CBOR [float32 0.1, 1]: printed as 0.1, not 0.10000000149011612.
    let j = cbor("82fa3dcccccd01");
    assert!(j.contains(r#""value":0.1,"width":32"#), "{j}");
    // CBOR [half 0x3555, 1]: the f32 shortest form of 0.333251953125.
    let j = cbor("82f9355501");
    assert!(
        j.contains(r#""width":16"#) && !j.contains("0.333251953125"),
        "{j}"
    );
    // Doubles keep full precision.
    let j = cbor("82fb3fb999999999999a01");
    assert!(j.contains(r#""value":0.1,"width":64"#), "{j}");
}
