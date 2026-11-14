//! Re-encoding (`bytepeel set`): byte-exact splicing through every layer.

use bytepeel_core::*;

fn h(s: &str) -> Vec<u8> {
    decode_hex(s).unwrap()
}

fn set1(input: &[u8], path: &str, value: &str) -> Result<Vec<u8>, Diag> {
    set(
        input,
        &Options::default(),
        path,
        &parse_value(value).unwrap(),
    )
}

fn set_s(input: &str, path: &str, value: &str) -> String {
    String::from_utf8(set1(input.as_bytes(), path, value).unwrap()).unwrap()
}

fn field<'a>(n: &'a Node, path: &str) -> &'a Field {
    select(n, path).unwrap()
}

fn uint(f: &Field) -> u64 {
    match &f.value {
        FieldValue::Varint { value, .. } => *value,
        v => panic!("not a varint: {v:?}"),
    }
}

fn b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            o.push(if i <= c.len() {
                A[((n >> (18 - 6 * i)) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    o
}

#[test]
fn varint_in_hex_keeps_the_hex_style() {
    assert_eq!(set_s("08 96 01\n", "1", "300"), "08 ac 02\n");
    assert_eq!(set_s("089601", "1", "1"), "0801");
    assert_eq!(set_s("08:96:01", "1", "150"), "08:96:01");
}

#[test]
fn dump_keeps_nonzero_start_offsets() {
    // A dump from `xxd -s 0x40`: editing a protobuf field must keep the
    // shifted offset column, and an unchanged value must round-trip exactly.
    let input = "00000040: 0a03 666f 6f12 0568 656c 6c6f 1896 01    ..foo..hello...\n";
    assert_eq!(set_s(input, "1", "\"foo\""), input);
    let out = set_s(input, "1", "\"hi\"");
    assert!(out.starts_with("00000040: "), "{out}");
    assert!(out.contains("6869"), "{out}");
    let n = peel(out.as_bytes(), &Options::default()).unwrap();
    assert_eq!(
        n.codec,
        Codec::Dump {
            style: "xxd",
            start: 64
        }
    );
    match &field(&n, "1").value {
        FieldValue::Len { data, .. } => assert_eq!(data, b"hi"),
        v => panic!("{v:?}"),
    }
    assert!(to_json(&n).contains("\"start\":64"));
}

#[test]
fn setting_the_current_value_is_the_identity() {
    // Nothing but the field's own bytes may change.
    for input in [
        "08 96 01 12 03 66 6f 6f\n",
        "0896011203666f6f",
        "1a03089601",
    ] {
        let n = peel(input.as_bytes(), &Options::default()).unwrap();
        let path = if input.starts_with("1a") { "3.1" } else { "1" };
        let cur = uint(field(&n, path)).to_string();
        assert_eq!(set_s(input, path, &cur), input, "{input}");
    }
}

#[test]
fn negative_and_zigzag_varints() {
    let out = set1(b"0801", "1", "-2").unwrap();
    assert_eq!(out, b"08feffffffffffffffff01");
    let out = set1(b"0801", "1", "sint:-2").unwrap();
    assert_eq!(out, b"0803");
    let out = set1(b"0801", "1", "false").unwrap();
    assert_eq!(out, b"0800");
}

#[test]
fn nested_message_lengths_are_rewritten() {
    // 3 { 1: 150 } -> 3 { 1: 300000 }: the inner varint grows by one byte, so
    // field 3's length prefix changes from 3 to 4.
    let out = set1(b"1a03089601", "3.1", "300000").unwrap();
    assert_eq!(out, b"1a0408e0a712");
    let n = peel(&out, &Options::default()).unwrap();
    assert_eq!(uint(field(&n, "3.1")), 300_000);
}

#[test]
fn string_length_changes_and_neighbors_survive() {
    // 1: "foo", 2: 150, 3: "bar" -> 1: "hello world"
    let out = set1(b"0a03666f6f1096011a03626172", "1", "\"hello world\"").unwrap();
    assert_eq!(out, b"0a0b68656c6c6f20776f726c641096011a03626172");
    let out = set1(b"0a03666f6f", "1", "hex:00ff").unwrap();
    assert_eq!(out, b"0a0200ff");
}

#[test]
fn repeated_field_index() {
    let out = set1(b"08 01 08 02 08 03", "1[1]", "9").unwrap();
    assert_eq!(out, b"08 01 08 09 08 03");
}

#[test]
fn fixed_width_fields() {
    // 1: double 1.5 -> 2.25; 2: fixed32 7 -> float32 0.5
    let input = h("09000000000000f83f1507000000");
    let out = set(&input, &opts_raw(), "1", &parse_value("2.25").unwrap()).unwrap();
    let out = set(&out, &opts_raw(), "2", &parse_value("float:0.5").unwrap()).unwrap();
    assert_eq!(out, h("090000000000000240150000003f"));
    let e = set(
        &input,
        &opts_raw(),
        "2",
        &parse_value("4294967296").unwrap(),
    )
    .unwrap_err();
    assert_eq!(e.code, "VALUE_OUT_OF_RANGE");
}

fn opts_raw() -> Options {
    Options {
        input: InputForm::Raw,
        ..Options::default()
    }
}

#[test]
fn groups() {
    // 1: group { 2: 1 }
    let out = set1(b"0b10010c", "1.2", "5").unwrap();
    assert_eq!(out, b"0b10050c");
}

#[test]
fn base64_protobuf_base64_protobuf() {
    // Outer base64 -> protobuf field 1 is a string that is itself base64 of a
    // protobuf message { 1: "hello world!", 2: 7 }. Edit the innermost field.
    let inner = h("0a0c68656c6c6f20776f726c6421 1007");
    let mut outer = vec![0x0a];
    let s = b64(&inner);
    outer.push(s.len() as u8);
    outer.extend_from_slice(s.as_bytes());
    outer.extend_from_slice(&h("102a"));
    let text = b64(&outer);
    let out = set_s(&text, "1.2", "8");
    let n = peel(out.as_bytes(), &Options::default()).unwrap();
    assert_eq!(n.codec.name(), "base64");
    assert_eq!(uint(field(&n, "1.2")), 8);
    assert_eq!(uint(field(&n, "2")), 42);
    // The untouched string field inside is unchanged.
    let inner_str = match &field(&n, "1.1").value {
        FieldValue::Len { data, .. } => data.clone(),
        v => panic!("{v:?}"),
    };
    assert_eq!(inner_str, b"hello world!");
}

#[test]
fn pem_keeps_label_and_surrounding_text() {
    // A PEM block whose body is protobuf (unusual, but exercises the layer).
    let body = b64(&h("0896011203666f6f"));
    let pem = format!("note: keep me\n-----BEGIN THING-----\n{body}\n-----END THING-----\n");
    let out = set_s(&pem, "1", "151");
    assert!(
        out.starts_with("note: keep me\n-----BEGIN THING-----\n"),
        "{out}"
    );
    let n = peel(out.as_bytes(), &Options::default()).unwrap();
    assert_eq!(uint(field(&n, "1")), 151);
}

#[cfg(feature = "deflate")]
#[test]
fn gzip_layer_keeps_its_header() {
    let gz = include_bytes!("fixtures/msg.bin.gz");
    let out = set1(gz, "3", "7").unwrap();
    // FNAME header kept verbatim.
    assert_eq!(&out[..18], &gz[..18]);
    let n = peel(&out, &Options::default()).unwrap();
    assert_eq!(
        n.codec,
        Codec::Gzip {
            name: Some("msg.bin".into())
        }
    );
    assert_eq!(uint(field(&n, "3")), 7);
    // base64(gzip(protobuf)) too.
    let out = set_s(&b64(gz), "2", "\"world\"");
    let n = peel(out.as_bytes(), &Options::default()).unwrap();
    match &field(&n, "2").value {
        FieldValue::Len { data, .. } => assert_eq!(data, b"world"),
        v => panic!("{v:?}"),
    }
}

#[test]
fn errors() {
    let code = |input: &[u8], path: &str, v: &str| set1(input, path, v).unwrap_err().code;
    assert_eq!(code(b"0a03666f6f", "1", "42"), "TYPE_MISMATCH");
    assert_eq!(code(b"089601", "1", "\"x\""), "TYPE_MISMATCH");
    assert_eq!(code(b"0b10010c", "1", "1"), "TYPE_MISMATCH");
    assert_eq!(code(b"089601", "2", "1"), "PATH_NOT_FOUND");
    assert_eq!(
        code(b"089601", "1", "18446744073709551616"),
        "VALUE_OUT_OF_RANGE"
    );
    // DER is not editable yet.
    assert_eq!(code(b"3003020105", "0", "1"), "PATH_NOT_MESSAGE");
}

#[test]
fn jwt_payloads_are_not_editable() {
    // A protobuf payload inside a JWT has no --get path (the token is not a
    // message), so set reports the same error instead of silently producing
    // a token whose signature no longer matches.
    let seg = |b: &[u8]| {
        b64(b)
            .trim_end_matches('=')
            .replace('+', "-")
            .replace('/', "_")
    };
    let tok = format!(
        "{}.{}.c2ln",
        seg(br#"{"alg":"none"}"#),
        seg(&h("0896011203666f6f"))
    );
    assert_eq!(
        set1(tok.as_bytes(), "1", "1").unwrap_err().code,
        "PATH_NOT_MESSAGE"
    );
}

#[test]
fn verification_catches_a_changed_interpretation() {
    // Setting field 1 to 40 printable chars makes the whole protobuf printable
    // ("\n(" + text), so auto-detection would now read it as text. `set`
    // notices instead of returning bytes that no longer decode as intended...
    let long = format!("str:{}", "a".repeat(40));
    let e = set(
        &h("0a03666f6f"),
        &opts_raw(),
        "1",
        &parse_value(&long).unwrap(),
    )
    .unwrap_err();
    assert_eq!(e.code, "REENCODE_VERIFY_FAILED");
    // ...and pinning the interpretation makes it work.
    let opts = Options {
        input: InputForm::Raw,
        force: Some(Force::Protobuf),
        ..Options::default()
    };
    let out = set(&h("0a03666f6f"), &opts, "1", &parse_value(&long).unwrap()).unwrap();
    assert_eq!(out.len(), 42);
}

// ------------------------------------------------------------ CBOR / MessagePack

fn cbor_opts() -> Options {
    Options {
        input: InputForm::Raw,
        force: Some(Force::Cbor),
        ..Options::default()
    }
}

fn mp_opts() -> Options {
    Options {
        input: InputForm::Raw,
        force: Some(Force::Msgpack),
        ..Options::default()
    }
}

fn setv(input: &[u8], opts: &Options, path: &str, value: &str) -> Result<Vec<u8>, Diag> {
    set(input, opts, path, &parse_value(value).unwrap())
}

fn val<'a>(n: &'a Node, path: &str) -> &'a Value {
    select_value(n, path).unwrap().untagged()
}

#[test]
fn cbor_map_value_is_spliced() {
    // {"name": "ada", "id": 7} -> id = 300 (grows by two bytes), name = "grace"
    let input = h("a2 646e616d65 63616461 626964 07");
    let out = setv(&input, &cbor_opts(), "id", "300").unwrap();
    assert_eq!(out, h("a2 646e616d65 63616461 626964 19012c"));
    let out = setv(&out, &cbor_opts(), "name", "\"grace\"").unwrap();
    assert_eq!(out, h("a2 646e616d65 656772616365 626964 19012c"));
    // Auto-detection works too (text keys: confidence 0.9).
    let out = set1(&input, "id", "-1").unwrap();
    assert_eq!(out, h("a2 646e616d65 63616461 626964 20"));
}

#[test]
fn cbor_array_index_and_type_change() {
    // [1, "two", 3.5] -> [1, null, true]: values are self-describing, so the
    // type may change.
    let input = h("83 01 6374776f f9 4300");
    let out = setv(&input, &cbor_opts(), "1", "null").unwrap();
    let out = setv(&out, &cbor_opts(), "2", "true").unwrap();
    assert_eq!(out, h("83 01 f6 f5"));
    let out = setv(&input, &cbor_opts(), "2", "hex:0a0b").unwrap();
    assert_eq!(out, h("83 01 6374776f 420a0b"));
}

#[test]
fn cbor_tags_are_kept_and_float_width_never_narrows() {
    // {"ts": 1(1700000000)} -> the tag stays, the epoch changes.
    let input = h("a1 627473 c1 1a6553f100");
    let out = setv(&input, &cbor_opts(), "ts", "0").unwrap();
    assert_eq!(out, h("a1 627473 c1 00"));
    let n = peel(&out, &cbor_opts()).unwrap();
    assert!(matches!(val(&n, "ts").kind, ValueKind::Uint(0)));
    // A double stays a double even when the value fits a half.
    let input = h("81 fb3ff0000000000000"); // [1.0]
    let out = setv(&input, &cbor_opts(), "0", "0.5").unwrap();
    assert_eq!(out, h("81 fb3fe0000000000000"));
    // A half becomes a double when the value needs it.
    let input = h("81 f93c00"); // [1.0] as half
    let out = setv(&input, &cbor_opts(), "0", "0.1").unwrap();
    assert_eq!(out, h("81 fb3fb999999999999a"));
    // An integer becomes the smallest exact float.
    let out = setv(&h("8101"), &cbor_opts(), "0", "1.5").unwrap();
    assert_eq!(out, h("81 f93e00"));
}

#[test]
fn cbor_inside_base64_inside_indefinite_array() {
    // base64 of an indefinite array [1..=11] -> set index 1 to 1000.
    let text = b64(&h("9f 0102030405060708090a0b ff"));
    let out = set_s(&text, "1", "1000");
    let n = peel(out.as_bytes(), &Options::default()).unwrap();
    assert_eq!(n.codec.name(), "base64");
    assert!(matches!(val(&n, "1").kind, ValueKind::Uint(1000)));
    assert!(val(&n, "0").range == [1, 2]);
}

#[test]
fn msgpack_values() {
    // {"a": 1, "b": [1, 2]} (fixmap, fixstr, fixarray)
    let input = h("82 a161 01 a162 92 01 02");
    let out = setv(&input, &mp_opts(), "a", "200").unwrap();
    assert_eq!(out, h("82 a161 cc c8 a162 92 01 02"));
    let out = setv(&input, &mp_opts(), "b.1", "-33").unwrap();
    assert_eq!(out, h("82 a161 01 a162 92 01 d0df"));
    let out = setv(&input, &mp_opts(), "b", "str:hello").unwrap();
    assert_eq!(out, h("82 a161 01 a162 a568656c6c6f"));
    // float32 stays 32 when exact, widens otherwise.
    let input = h("91 ca3fc00000"); // [1.5]
    assert_eq!(
        setv(&input, &mp_opts(), "0", "0.25").unwrap(),
        h("91 ca3e800000")
    );
    assert_eq!(
        setv(&input, &mp_opts(), "0", "0.1").unwrap(),
        h("91 cb3fb999999999999a")
    );
    // null and bin.
    assert_eq!(setv(&input, &mp_opts(), "0", "null").unwrap(), h("91 c0"));
    assert_eq!(
        setv(&input, &mp_opts(), "0", "hex:ff").unwrap(),
        h("91 c401ff")
    );
    // Auto-detected msgpack keeps being msgpack after the edit.
    let out = set1(&h("82 a161 01 a162 92 01 02"), "a", "2").unwrap();
    assert_eq!(
        peel(&out, &Options::default()).unwrap().codec,
        Codec::Msgpack
    );
}

#[test]
fn value_errors() {
    let code = |input: &[u8], opts: &Options, path: &str, v: &str| {
        setv(input, opts, path, v).unwrap_err().code
    };
    let m = h("a1 6161 01");
    assert_eq!(code(&m, &cbor_opts(), "a", "sint:1"), "TYPE_MISMATCH");
    assert_eq!(
        code(&m, &cbor_opts(), "a", "18446744073709551616"),
        "VALUE_OUT_OF_RANGE"
    );
    assert_eq!(code(&m, &cbor_opts(), "b", "1"), "PATH_NOT_FOUND");
    assert_eq!(code(&m, &cbor_opts(), "a.x", "1"), "PATH_NOT_MESSAGE");
    let mp = h("81 a161 01");
    assert_eq!(
        code(&mp, &mp_opts(), "a", "-9223372036854775809"),
        "VALUE_OUT_OF_RANGE"
    );
    // The whole tree cannot be replaced: paths select a value inside it.
    assert_eq!(
        setv(&h("81 01"), &cbor_opts(), "", "1").unwrap_err().code,
        "BAD_PATH"
    );
}

#[test]
fn value_edit_that_changes_detection_is_caught() {
    // 82 18 00 18 01 is CBOR [0, 1] but auto-detects as a MessagePack map
    // (AMBIGUOUS_FORMAT). Editing it as MessagePack with auto options works;
    // forcing CBOR edits the CBOR reading of the same bytes.
    let amb = h("8218001801");
    // MessagePack: key 24 (first entry) -> its value 0 becomes 5.
    let out = set1(&amb, "24", "5").unwrap();
    assert_eq!(out, h("82 18 05 18 01"));
    // CBOR: array index 1 (the item `18 01`) becomes 5.
    let out = setv(&amb, &cbor_opts(), "1", "5").unwrap();
    assert_eq!(out, h("82 18 00 05"));
}

// ------------------------------------------------------------ DER

const ISRG_X2: &str = include_str!("fixtures/isrg-root-x2.pem");

fn der_opts() -> Options {
    Options {
        input: InputForm::Raw,
        force: Some(Force::Der),
        ..Options::default()
    }
}

fn el<'a>(n: &'a Node, path: &str) -> &'a Asn1 {
    select_der(n, path).unwrap()
}

#[test]
fn der_integer_grows_and_every_ancestor_length_is_rewritten() {
    // SEQUENCE { SEQUENCE { INTEGER 5 }, BOOLEAN true }
    let input = h("3008 3003 020105 0101ff");
    let out = setv(&input, &der_opts(), "0.0.0", "65537").unwrap();
    assert_eq!(out, h("300a 3005 0203010001 0101ff"));
    let out = setv(&input, &der_opts(), "0.0.0", "-129").unwrap();
    assert_eq!(out, h("3009 3004 0202ff7f 0101ff"));
    let out = setv(&input, &der_opts(), "0.1", "false").unwrap();
    assert_eq!(out, h("3008 3003 020105 010100"));
}

#[test]
fn der_long_form_lengths_change_size() {
    // An OCTET STRING of 120 bytes inside a SEQUENCE -> 200 bytes: both
    // lengths move from short form to long form.
    let mut input = vec![0x30, 122, 0x04, 120];
    input.extend(std::iter::repeat_n(0xab, 120));
    let new = format!("hex:{}", "cd".repeat(200));
    let out = setv(&input, &der_opts(), "0.0", &new).unwrap();
    assert_eq!(&out[..6], &[0x30, 0x81, 203, 0x04, 0x81, 200]);
    assert_eq!(out.len(), 3 + 3 + 200);
}

#[test]
fn der_certificate_fields_through_pem() {
    // Issuer CN (PrintableString) and notBefore (UTCTime) of a real cert.
    let out = String::from_utf8(set1(ISRG_X2.as_bytes(), "0.0.3.1.0.1", "\"Test Root\"").unwrap())
        .unwrap();
    assert!(out.starts_with("-----BEGIN CERTIFICATE-----\n"), "{out}");
    let n = peel(out.as_bytes(), &Options::default()).unwrap();
    assert_eq!(
        el(&n, "0.0.3.1.0.1").value,
        Asn1Value::Text("Test Root".into())
    );
    // Everything else, e.g. the subject CN, is unchanged.
    assert_eq!(
        el(&n, "0.0.5.2.0.1").value,
        Asn1Value::Text("ISRG Root X2".into())
    );

    let out = set1(ISRG_X2.as_bytes(), "0.0.4.0", "\"2030-01-02T03:04:05Z\"").unwrap();
    let n = peel(&out, &Options::default()).unwrap();
    let j = asn1_to_json(el(&n, "0.0.4.0"));
    assert!(j.contains(r#""value":"300102030405Z""#), "{j}");
    // The serial number via hex (16 bytes, larger than any integer literal).
    let out = set1(ISRG_X2.as_bytes(), "0.0.1", "hex:01").unwrap();
    let n = peel(&out, &Options::default()).unwrap();
    assert_eq!(el(&n, "0.0.1").payload().unwrap(), vec![1]);
}

#[test]
fn der_encapsulated_bit_string_keeps_unused_bits_byte() {
    // The ECDSA signature: BIT STRING (0 unused) { SEQUENCE { INTEGER r, INTEGER s } }.
    let out = set1(ISRG_X2.as_bytes(), "0.2.0.0", "1").unwrap();
    let n = peel(&out, &Options::default()).unwrap();
    let sig = el(&n, "0.2");
    assert!(
        matches!(
            sig.value,
            Asn1Value::Encapsulated {
                unused_bits: Some(0),
                ..
            }
        ),
        "{sig:?}"
    );
    assert_eq!(el(&n, "0.2.0.0").payload().unwrap(), vec![1]);
}

#[test]
fn der_identity_edit_is_byte_exact() {
    let n = peel(ISRG_X2.as_bytes(), &Options::default()).unwrap();
    let cn = match &el(&n, "0.0.5.2.0.1").value {
        Asn1Value::Text(t) => t.clone(),
        v => panic!("{v:?}"),
    };
    let out = set1(ISRG_X2.as_bytes(), "0.0.5.2.0.1", &format!("str:{cn}")).unwrap();
    assert_eq!(out, ISRG_X2.as_bytes());
}

#[test]
fn der_in_a_pem_bundle_edits_only_that_block() {
    let bundle = format!("{ISRG_X2}{ISRG_X2}");
    let out =
        String::from_utf8(set1(bundle.as_bytes(), "1.0.0.5.2.0.1", "\"Second\"").unwrap()).unwrap();
    assert!(out.starts_with(ISRG_X2), "first block changed");
    let n = peel(out.as_bytes(), &Options::default()).unwrap();
    assert_eq!(n.codec, Codec::Bundle);
    assert_eq!(
        select_der(&n, "1.0.0.5.2.0.1").unwrap().value,
        Asn1Value::Text("Second".into())
    );
    assert_eq!(
        select_der(&n, "0.0.0.5.2.0.1").unwrap().value,
        Asn1Value::Text("ISRG Root X2".into())
    );
}

#[test]
fn der_value_types() {
    let one = |hex: &str, v: &str| setv(&h(hex), &der_opts(), "0", v);
    // OID
    assert_eq!(
        one("0603550403", "\"1.2.840.113549.1.1.11\"").unwrap(),
        h("06092a864886f70d01010b")
    );
    // NULL, BOOLEAN
    assert_eq!(one("0500", "null").unwrap(), h("0500"));
    // BMPString, IA5String, UTF8String
    assert_eq!(one("1e00", "\"é\"").unwrap(), h("1e0200e9"));
    assert_eq!(one("1600", "\"a@b.c\"").unwrap(), h("1605614062 2e63"));
    assert_eq!(one("0c00", "\"€\"").unwrap(), h("0c03e282ac"));
    // GeneralizedTime from ISO with fraction and offset
    assert_eq!(
        one("1800", "\"2026-11-13T10:00:00.5+02:00\"").unwrap(),
        b"\x18\x1520261113100000.5+0200".to_vec()
    );
    // BIT STRING bytes get a 0 unused-bits byte
    assert_eq!(one("030100", "hex:ff").unwrap(), h("030200ff"));
    // A context-tagged primitive takes text or bytes
    assert_eq!(one("8000", "\"x\"").unwrap(), h("800178"));
}

#[test]
fn der_errors() {
    let code =
        |hex: &str, path: &str, v: &str| setv(&h(hex), &der_opts(), path, v).unwrap_err().code;
    assert_eq!(code("3003020105", "0", "1"), "TYPE_MISMATCH"); // constructed
    assert_eq!(code("020105", "0", "\"x\""), "TYPE_MISMATCH");
    assert_eq!(code("1300", "0", "\"a@b\""), "VALUE_OUT_OF_RANGE"); // PrintableString
    assert_eq!(
        code("1700", "0", "\"2060-01-01T00:00:00Z\""),
        "VALUE_OUT_OF_RANGE"
    ); // UTCTime range
    assert_eq!(code("1700", "0", "\"tomorrow\""), "BAD_VALUE");
    assert_eq!(code("0603550403", "0", "\"3.1\""), "BAD_VALUE");
    assert_eq!(code("020105", "1", "1"), "PATH_NOT_FOUND");
}

// ------------------------------------------------------------ add / delete

fn op(input: &[u8], opts: &Options, op: Op) -> Result<Vec<u8>, Diag> {
    edit(input, opts, &op)
}

fn add(path: &str, v: &str) -> Op {
    Op::Add(path.into(), parse_value(v).unwrap())
}

fn del(path: &str) -> Op {
    Op::Del(path.into())
}

#[test]
fn protobuf_add_fields() {
    let d = Options::default();
    // Top level: appended at the end, wire type from the value.
    assert_eq!(op(b"089601", &d, add("3", "42")).unwrap(), b"089601182a");
    assert_eq!(
        op(b"089601", &d, add("2", "str:hi")).unwrap(),
        b"08960112026869"
    );
    assert_eq!(
        op(b"089601", &d, add("4", "1.5")).unwrap(),
        b"08960121000000000000f83f"
    );
    assert_eq!(
        op(b"089601", &d, add("5", "sint:-1")).unwrap(),
        b"0896012801"
    );
    // A second occurrence of an existing field number is appended too.
    assert_eq!(op(b"089601", &d, add("1", "2")).unwrap(), b"0896010802");
    // Into a nested message: field 3's length grows from 3 to 5.
    assert_eq!(
        op(b"1a03089601", &d, add("3.2", "7")).unwrap(),
        b"1a050896011007"
    );
    // Into a group.
    assert_eq!(
        op(b"0b10010c", &d, add("1.3", "7")).unwrap(),
        b"0b100118070c"
    );
}

#[test]
fn protobuf_add_inside_base64_string() {
    let inner = h("0a0c68656c6c6f20776f726c6421 1007");
    let s = b64(&inner);
    let mut outer = vec![0x0a, s.len() as u8];
    outer.extend_from_slice(s.as_bytes());
    let text = b64(&outer);
    let out = op(text.as_bytes(), &Options::default(), add("1.3", "99")).unwrap();
    let n = peel(&out, &Options::default()).unwrap();
    assert_eq!(uint(field(&n, "1.3")), 99);
    assert_eq!(uint(field(&n, "1.2")), 7);
}

#[test]
fn protobuf_delete_fields() {
    let d = Options::default();
    assert_eq!(
        op(b"0801 1203666f6f 1802", &d, del("2")).unwrap(),
        b"0801 1802"
    );
    // A repeated field by index; the others stay in order.
    assert_eq!(
        op(b"0801 0802 0803", &d, del("1[1]")).unwrap(),
        b"0801 0803"
    );
    // Nested: the parent length shrinks.
    assert_eq!(
        op(b"1a050896011007", &d, del("3.2")).unwrap(),
        b"1a03089601"
    );
}

#[test]
fn protobuf_add_delete_errors() {
    let d = Options::default();
    let code = |input: &[u8], o: Op| op(input, &d, o).unwrap_err().code;
    assert_eq!(code(b"089601", add("2[1]", "1")), "BAD_PATH");
    assert_eq!(code(b"089601", add("0", "1")), "FIELD_NUMBER_ZERO");
    assert_eq!(
        code(b"089601", add("536870912", "1")),
        "FIELD_NUMBER_TOO_LARGE"
    );
    assert_eq!(code(b"089601", add("2", "null")), "TYPE_MISMATCH");
    assert_eq!(code(b"089601", add("1.2", "1")), "PATH_NOT_MESSAGE");
    assert_eq!(code(b"089601", del("2")), "PATH_NOT_FOUND");
}

#[test]
fn cbor_add_and_delete() {
    let c = cbor_opts();
    // {"a": [1, 2]}
    let m = h("a1 6161 82 01 02");
    assert_eq!(
        op(&m, &c, add("b", "true")).unwrap(),
        h("a2 6161 82 01 02 6162 f5")
    );
    assert_eq!(
        op(&m, &c, add("a.0", "0")).unwrap(),
        h("a1 6161 83 00 01 02")
    );
    assert_eq!(
        op(&m, &c, add("a.1", "9")).unwrap(),
        h("a1 6161 83 01 09 02")
    );
    assert_eq!(
        op(&m, &c, add("a.2", "3")).unwrap(),
        h("a1 6161 83 01 02 03")
    );
    assert_eq!(op(&m, &c, del("a.0")).unwrap(), h("a1 6161 81 02"));
    assert_eq!(op(&m, &c, del("a")).unwrap(), h("a0"));
    // Into an empty container.
    assert_eq!(op(&h("a0"), &c, add("k", "1")).unwrap(), h("a1 616b 01"));
    assert_eq!(op(&h("80"), &c, add("0", "1")).unwrap(), h("81 01"));
    // Errors.
    assert_eq!(
        op(&m, &c, add("a", "1")).unwrap_err().code,
        "ALREADY_EXISTS"
    );
    assert_eq!(
        op(&m, &c, add("a.3", "1")).unwrap_err().code,
        "PATH_NOT_FOUND"
    );
    assert_eq!(op(&m, &c, add("a.x", "1")).unwrap_err().code, "BAD_PATH");
    assert_eq!(
        op(&m, &c, add("a.0.z", "1")).unwrap_err().code,
        "PATH_NOT_MESSAGE"
    );
}

#[test]
fn cbor_header_grows_and_indefinite_containers_keep_their_break() {
    let c = cbor_opts();
    // A 23-item array (header 0x97) gains an item: header becomes 98 18.
    let mut arr = vec![0x97];
    arr.extend(std::iter::repeat_n(0x01, 23));
    let out = op(&arr, &c, add("23", "2")).unwrap();
    assert_eq!(&out[..2], &[0x98, 24]);
    assert_eq!(out.len(), 2 + 24);
    // And shrinks back.
    assert_eq!(op(&out, &c, del("23")).unwrap(), arr);
    // Indefinite: no count; items go before the break.
    let ind = h("9f 01 02 ff");
    assert_eq!(op(&ind, &c, add("2", "3")).unwrap(), h("9f 01 02 03 ff"));
    assert_eq!(op(&ind, &c, del("0")).unwrap(), h("9f 02 ff"));
    assert_eq!(op(&h("9f ff"), &c, add("0", "1")).unwrap(), h("9f 01 ff"));
    // A tagged container keeps its tag.
    assert_eq!(
        op(&h("d9d9f7 a0"), &c, add("x", "1")).unwrap(),
        h("d9d9f7 a1 6178 01")
    );
}

#[test]
fn msgpack_add_and_delete() {
    let m = mp_opts();
    let input = h("82 a161 01 a162 92 01 02");
    assert_eq!(
        op(&input, &m, add("c", "null")).unwrap(),
        h("83 a161 01 a162 92 01 02 a163 c0")
    );
    assert_eq!(op(&input, &m, del("a")).unwrap(), h("81 a162 92 01 02"));
    assert_eq!(
        op(&input, &m, add("b.0", "str:z")).unwrap(),
        h("82 a161 01 a162 93 a17a 01 02")
    );
    // fixmap with 15 entries -> map16 with 16.
    let mut map = vec![0x8f];
    for k in 0..15u8 {
        map.extend([0xa1, b'a' + k, 0x01]);
    }
    let out = op(&map, &m, add("z", "1")).unwrap();
    assert_eq!(&out[..3], &[0xde, 0x00, 0x10]);
    assert_eq!(op(&out, &m, del("z")).unwrap(), map);
}

#[test]
fn der_insert_and_delete() {
    let d = der_opts();
    let seq = h("3003 020105");
    assert_eq!(
        op(&seq, &d, add("0.1", "hex:0101ff")).unwrap(),
        h("3006 020105 0101ff")
    );
    assert_eq!(
        op(&seq, &d, add("0.0", "hex:0500")).unwrap(),
        h("3005 0500 020105")
    );
    assert_eq!(
        op(&h("3006 020105 0101ff"), &d, del("0.0")).unwrap(),
        h("3003 0101ff")
    );
    // Into an encapsulating OCTET STRING: both lengths follow.
    let oct = h("3007 0405 3003 020105");
    assert_eq!(
        op(&oct, &d, add("0.0.0.1", "hex:0500")).unwrap(),
        h("3009 0407 3005 020105 0500")
    );
    // Errors.
    let code = |o: Op| op(&seq, &d, o).unwrap_err().code;
    assert_eq!(code(add("0.1", "5")), "TYPE_MISMATCH");
    assert_eq!(code(add("0.1", "hex:0201")), "BAD_VALUE"); // truncated element
    assert_eq!(code(add("0.1", "hex:05000500")), "BAD_VALUE"); // two elements
    assert_eq!(code(add("0.2", "hex:0500")), "PATH_NOT_FOUND");
    assert_eq!(code(add("0.0.0", "hex:0500")), "PATH_NOT_MESSAGE"); // INTEGER is primitive
    assert_eq!(code(del("0.1")), "PATH_NOT_FOUND");
}

#[test]
fn der_delete_a_certificate_extension() {
    // ISRG Root X2 extensions: [3] { SEQUENCE { keyUsage, basicConstraints, SKI } }.
    let n = peel(ISRG_X2.as_bytes(), &Options::default()).unwrap();
    let before = select_der(&n, "0.0.7.0").unwrap().children().unwrap().len();
    let out = op(ISRG_X2.as_bytes(), &Options::default(), del("0.0.7.0.0")).unwrap();
    let n = peel(&out, &Options::default()).unwrap();
    assert_eq!(
        select_der(&n, "0.0.7.0").unwrap().children().unwrap().len(),
        before - 1
    );
    // In a bundle, only the addressed block changes.
    let bundle = format!("{ISRG_X2}{ISRG_X2}");
    let out =
        String::from_utf8(op(bundle.as_bytes(), &Options::default(), del("1.0.0.7.0.0")).unwrap())
            .unwrap();
    assert!(out.starts_with(ISRG_X2));
    let n = peel(out.as_bytes(), &Options::default()).unwrap();
    assert_eq!(
        select_der(&n, "1.0.0.7.0")
            .unwrap()
            .children()
            .unwrap()
            .len(),
        before - 1
    );
    assert_eq!(
        select_der(&n, "0.0.0.7.0")
            .unwrap()
            .children()
            .unwrap()
            .len(),
        before
    );
}

// ------------------------------------------------------------ review fixes

#[test]
fn add_into_group_with_overlong_end_tag() {
    // Group 1 { 2: 5 } whose end tag is the overlong varint `8c 00`.
    let d = Options::default();
    assert_eq!(
        op(b"0b1005 8c00", &d, add("1.3", "42")).unwrap(),
        // (the hex style keeps the original 3-byte token grouping)
        b"0b1005 182a8c 00"
    );
    assert_eq!(
        op(b"0b10050c", &d, add("1.3", "42")).unwrap(),
        b"0b1005182a0c"
    );
}

#[test]
fn empty_submessage_takes_adds_and_last_delete_verifies() {
    let d = Options::default();
    // Deleting the only field leaves `0a 00`, an empty message.
    assert_eq!(op(b"0a020801", &d, del("1.1")).unwrap(), b"0a00");
    // Adding into an empty LEN field.
    assert_eq!(op(b"0a00", &d, add("1.1", "5")).unwrap(), b"0a020805");
}

#[test]
fn single_hex_token_grows_as_one_token() {
    assert_eq!(set_s("0x089601", "1", "100000"), "0x08a08d06");
    assert_eq!(
        set_s("0x08 0x96 0x01", "1", "100000"),
        "0x08 0xa0 0x8d 0x06"
    );
    assert_eq!(set_s("089601", "1", "100000"), "08a08d06");
}

#[test]
fn plus_sign_integers() {
    assert!(matches!(parse_value("+5").unwrap(), NewValue::Int(5)));
    assert_eq!(set_s("089601", "1", "+5"), "0805");
}
