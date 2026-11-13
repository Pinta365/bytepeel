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
