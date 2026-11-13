use std::io::Write;
use std::process::{Command, Stdio};

fn run(args: &[&str], stdin: &[u8]) -> (i32, Vec<u8>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bytepeel"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The CLI may exit (e.g. on a usage error) before reading stdin.
    if let Err(e) = child.stdin.take().unwrap().write_all(stdin) {
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
    }
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap(),
        out.stdout,
        String::from_utf8(out.stderr).unwrap(),
    )
}

#[test]
fn help() {
    let (code, out, _) = run(&["--help"], b"");
    assert_eq!(code, 0);
    assert!(String::from_utf8(out).unwrap().contains("USAGE"));
}

#[test]
fn json_from_hex_stdin() {
    let (code, out, _) = run(&[], b"08 96 01\n");
    assert_eq!(code, 0);
    let s = String::from_utf8(out).unwrap();
    assert!(s.starts_with(r#"{"codec":"hex""#), "{s}");
    assert!(s.contains(r#""uint":"150""#), "{s}");
}

#[test]
fn get_raw_payload() {
    let (code, out, _) = run(&["--get", "3.1", "--format=raw"], b"1a03089601");
    assert_eq!(code, 0);
    assert_eq!(out, vec![0x96, 0x01]);
}

#[test]
fn tree_format() {
    let (code, out, _) = run(&["--format", "tree"], b"089601");
    assert_eq!(code, 0);
    assert!(String::from_utf8(out).unwrap().contains("#1 VARINT"));
}

#[test]
fn usage_error_is_json_exit_2() {
    let (code, _, err) = run(&["--bogus"], b"");
    assert_eq!(code, 2);
    assert!(err.contains(r#""code":"USAGE""#), "{err}");
    let (code, _, err) = run(&["--format", "raw"], b"00");
    assert_eq!(code, 2);
    assert!(err.contains("requires --get"), "{err}");
}

#[test]
fn forced_decode_error_exit_1() {
    let (code, _, err) = run(&["--in", "hex", "--as", "protobuf"], b"0a05666f");
    assert_eq!(code, 1);
    assert!(err.contains(r#""code":"TRUNCATED_FIELD""#), "{err}");
    assert!(err.contains(r#""offset":0"#), "{err}");
}

#[test]
fn missing_file_is_io_error() {
    let (code, _, err) = run(&["/nonexistent/bytepeel-test"], b"");
    assert_eq!(code, 2);
    assert!(err.contains(r#""code":"IO""#), "{err}");
}

#[test]
fn der_get_and_raw() {
    // SEQUENCE { INTEGER 5, OCTET STRING "hi" }
    let (code, out, _) = run(
        &["--get", "0.1", "--format", "raw"],
        b"3007 020105 04026869",
    );
    assert_eq!(code, 0);
    assert_eq!(out, b"hi");
    let (code, out, _) = run(&["--get", "0.0"], b"3007 020105 04026869");
    assert_eq!(code, 0);
    assert!(String::from_utf8(out).unwrap().contains(r#""int":"5""#));
    let (code, _, err) = run(&["--get", "0", "--format", "raw"], b"3007 020105 04026869");
    assert_eq!(code, 1);
    assert!(err.contains("NO_PAYLOAD"), "{err}");
}

#[test]
fn forced_der_error() {
    let (code, _, err) = run(&["--in", "hex", "--as", "der"], b"3080020105");
    assert_eq!(code, 1);
    assert!(err.contains(r#""code":"INDEFINITE_LENGTH","#), "{err}");
}

#[test]
fn set_rewrites_in_place_style() {
    let (code, out, err) = run(&["set", "3.1=300000"], b"1a 03 08 96 01\n");
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, b"1a 04 08 e0 a7 12\n");
    // Several assignments apply in order.
    let (code, out, _) = run(&["set", "1=2", "2=str:hi"], b"0801 1200");
    assert_eq!(code, 0);
    // Hex keeps its 2-byte token grouping across the whole layer.
    assert_eq!(out, b"0802 1202 6869");
    // Options may come before the subcommand.
    let (code, out, _) = run(&["--in", "hex", "set", "1=3"], b"0801");
    assert_eq!(code, 0);
    assert_eq!(out, b"0803");
}

#[test]
fn set_errors() {
    let (code, _, err) = run(&["set"], b"0801");
    assert_eq!(code, 2);
    assert!(err.contains("USAGE"), "{err}");
    let (code, _, err) = run(&["set", "1=notavalue"], b"0801");
    assert_eq!(code, 2);
    assert!(err.contains(r#""code":"BAD_VALUE""#), "{err}");
    let (code, _, err) = run(&["set", "1=\"x\""], b"0801");
    assert_eq!(code, 1);
    assert!(err.contains(r#""code":"TYPE_MISMATCH""#), "{err}");
    let (code, _, err) = run(&["set", "1=1", "--get", "1"], b"0801");
    assert_eq!(code, 2);
    assert!(err.contains("USAGE"), "{err}");
}

#[test]
fn set_on_cbor_and_msgpack() {
    // CBOR {"id": 7} as hex text -> id = 300, hex style kept.
    let (code, out, err) = run(&["set", "id=300"], b"a1 62 69 64 07\n");
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, b"a1 62 69 64 19 01 2c\n");
    // MessagePack {"a": [1, 2]} -> a.1 = null
    let (code, out, _) = run(&["set", "a.1=null"], b"81a16192 0102");
    assert_eq!(code, 0);
    assert_eq!(out, b"81a16192 01c0");
    // sint is protobuf-only.
    let (code, _, err) = run(&["set", "id=sint:1"], b"a162696407");
    assert_eq!(code, 1);
    assert!(err.contains(r#""code":"TYPE_MISMATCH""#), "{err}");
}

#[test]
fn set_on_der() {
    // SEQUENCE { INTEGER 5 } as hex -> 65537; the SEQUENCE length follows.
    let (code, out, err) = run(&["set", "0.0=65537"], b"30 03 02 01 05\n");
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, b"30 05 02 03 01 00 01\n");
    let (code, _, err) = run(&["set", "0=1"], b"30 03 02 01 05");
    assert_eq!(code, 1);
    assert!(err.contains(r#""code":"TYPE_MISMATCH""#), "{err}");
}
