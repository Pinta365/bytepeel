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
fn magic_formats_are_not_misread_as_protobuf() {
    for hex in ["1f8b0800000000000000", "28b52ffd0000", "789c0300"] {
        let n = auto(&h(hex));
        assert_eq!(n.codec, Codec::Bytes, "{hex}");
        assert_eq!(n.warnings[0].code, "UNSUPPORTED_FORMAT", "{hex}");
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
        assert_eq!(n.codec, Codec::Dump { style }, "{style}");
        assert_eq!(varint_value(select(&n, "3").unwrap()), 150);
    }
}

#[test]
fn dump_ascii_column_is_ignored() {
    // The ASCII column of 0xca 0xfe 0xba 0xbe would never be hex, but a
    // column made of hex-looking text must not be read as data either.
    let n = auto(b"00000000: 6361 6665  cafe\n");
    assert_eq!(n.codec, Codec::Dump { style: "xxd" });
    assert_eq!(
        child(&n).detail,
        Detail::Text {
            text: "cafe".into()
        }
    );
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

// ------------------------------------------------------------ JSON

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
        XXD.as_bytes().to_vec(),
        HEXDUMP.as_bytes().to_vec(),
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
