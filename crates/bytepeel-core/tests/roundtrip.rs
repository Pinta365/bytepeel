//! Property / round-trip tests: encode with our own minimal encoders, decode
//! with `bytepeel-core`, and check the bytes, fields and ranges match.
//!
//! Everything is driven by a fixed-seed xorshift64* PRNG so a failure
//! reproduces exactly. Zero external dependencies.

use bytepeel_core::{
    AltKind, Asn1, Asn1Value, Detail, Field, FieldValue, Force, InputForm, MAX_ITEMS, Node,
    Options, TagClass, decode_b64, decode_hex, peel, select, select_der, to_json, to_tree,
};

// ---------------------------------------------------------------- PRNG

/// Deterministic xorshift64* (fixed seeds make every run reproducible).
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Uniform-ish in `0..n` (`0` when `n == 0`).
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u64() as u8).collect()
    }
}

fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

// ---------------------------------------------------------------- hex / base64

fn hex_plain(data: &[u8], upper: bool) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        if upper {
            s.push_str(&format!("{b:02X}"));
        } else {
            s.push_str(&format!("{b:02x}"));
        }
    }
    s
}

fn hex_sep(data: &[u8], sep: char) -> String {
    data.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(&sep.to_string())
}

fn hex_0x_pairs(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("0x{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn b64_encode(data: &[u8], url: bool, pad: bool) -> String {
    const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let a = if url { URL } else { STD };
    let mut o = String::new();
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        o.push(a[((n >> 18) & 63) as usize] as char);
        o.push(a[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            o.push(a[((n >> 6) & 63) as usize] as char);
        } else if pad {
            o.push('=');
        }
        if chunk.len() > 2 {
            o.push(a[(n & 63) as usize] as char);
        } else if pad {
            o.push('=');
        }
    }
    o
}

#[test]
fn hex_roundtrip() {
    let mut rng = Rng::new(0x0000_0000_0000_a11c);
    for _ in 0..1500 {
        let len = rng.below(301);
        let data = rng.bytes(len);
        if len == 0 {
            // Nothing to decode: the strict decoder rejects an empty token.
            assert_eq!(decode_hex("").unwrap_err().code, "EMPTY");
            continue;
        }
        let forms = [
            hex_plain(&data, false),
            hex_plain(&data, true),
            hex_sep(&data, ' '),
            hex_sep(&data, ':'),
            format!("0x{}", hex_plain(&data, false)),
            hex_0x_pairs(&data),
        ];
        for s in forms {
            assert_eq!(decode_hex(&s).unwrap(), data, "hex form {s:?}");
        }
    }
}

#[test]
fn base64_roundtrip() {
    let mut rng = Rng::new(0x0000_0000_0000_0b64);
    for _ in 0..1500 {
        let len = rng.below(301);
        let data = rng.bytes(len);
        if len == 0 {
            assert_eq!(decode_b64("").unwrap_err().code, "EMPTY");
            continue;
        }
        for (url, pad) in [(false, true), (false, false), (true, true), (true, false)] {
            let s = b64_encode(&data, url, pad);
            assert_eq!(decode_b64(&s).unwrap().bytes, data, "b64 {s:?}");
        }
        // Line wrapping (PEM style) is allowed anywhere.
        let s = b64_encode(&data, false, true);
        if s.len() >= 8 {
            let mid = s.len() / 2;
            let wrapped = format!("{}\r\n{}\r\n", &s[..mid], &s[mid..]);
            assert_eq!(
                decode_b64(&wrapped).unwrap().bytes,
                data,
                "wrapped {wrapped:?}"
            );
        }
    }
}

// ---------------------------------------------------------------- protobuf

#[derive(Debug, Clone)]
enum PbNode {
    Varint { number: u32, value: u64 },
    I64 { number: u32, value: u64 },
    I32 { number: u32, value: u32 },
    Len { number: u32, payload: PbPayload },
    Group { number: u32, fields: Vec<PbNode> },
}

#[derive(Debug, Clone)]
enum PbPayload {
    Bytes(Vec<u8>),
    Message(Vec<PbNode>),
}

#[derive(Debug, Clone)]
struct ExpField {
    number: u32,
    range: [usize; 2],
    value: ExpPbValue,
}

#[derive(Debug, Clone)]
enum ExpPbValue {
    Varint {
        raw: Vec<u8>,
        value: u64,
    },
    I64(u64),
    I32(u32),
    Len {
        data: Vec<u8>,
        data_start: usize,
        children: Option<Vec<ExpField>>,
    },
    Group(Vec<ExpField>),
}

fn put_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn varint_bytes(v: u64) -> Vec<u8> {
    let mut o = Vec::new();
    put_varint(v, &mut o);
    o
}

/// Encode a message body, returning its bytes and the expected fields (with
/// ranges relative to the returned buffer).
fn pb_encode(nodes: &[PbNode]) -> (Vec<u8>, Vec<ExpField>) {
    let mut out = Vec::new();
    let mut exps = Vec::new();
    for n in nodes {
        exps.push(pb_encode_field(n, &mut out));
    }
    (out, exps)
}

fn pb_encode_field(n: &PbNode, out: &mut Vec<u8>) -> ExpField {
    let start = out.len();
    let (number, value) = match n {
        PbNode::Varint { number, value } => {
            put_varint(u64::from(*number) << 3, out);
            let raw = varint_bytes(*value);
            out.extend_from_slice(&raw);
            (*number, ExpPbValue::Varint { raw, value: *value })
        }
        PbNode::I64 { number, value } => {
            put_varint((u64::from(*number) << 3) | 1, out);
            out.extend_from_slice(&value.to_le_bytes());
            (*number, ExpPbValue::I64(*value))
        }
        PbNode::I32 { number, value } => {
            put_varint((u64::from(*number) << 3) | 5, out);
            out.extend_from_slice(&value.to_le_bytes());
            (*number, ExpPbValue::I32(*value))
        }
        PbNode::Len { number, payload } => {
            put_varint((u64::from(*number) << 3) | 2, out);
            let (data, children) = match payload {
                PbPayload::Bytes(b) => (b.clone(), None),
                PbPayload::Message(kids) => {
                    let (b, child_exps) = pb_encode(kids);
                    (b, Some(child_exps))
                }
            };
            put_varint(data.len() as u64, out);
            let data_start = out.len();
            out.extend_from_slice(&data);
            let children = children.map(|ks| {
                ks.iter()
                    .map(|k| shift_field(k, data_start))
                    .collect::<Vec<_>>()
            });
            (
                *number,
                ExpPbValue::Len {
                    data,
                    data_start,
                    children,
                },
            )
        }
        PbNode::Group { number, fields } => {
            put_varint((u64::from(*number) << 3) | 3, out);
            let mut exps = Vec::new();
            for f in fields {
                exps.push(pb_encode_field(f, out));
            }
            put_varint((u64::from(*number) << 3) | 4, out);
            (*number, ExpPbValue::Group(exps))
        }
    };
    ExpField {
        number,
        range: [start, out.len()],
        value,
    }
}

fn shift_field(e: &ExpField, d: usize) -> ExpField {
    let value = match &e.value {
        ExpPbValue::Varint { raw, value } => ExpPbValue::Varint {
            raw: raw.clone(),
            value: *value,
        },
        ExpPbValue::I64(v) => ExpPbValue::I64(*v),
        ExpPbValue::I32(v) => ExpPbValue::I32(*v),
        ExpPbValue::Len {
            data,
            data_start,
            children,
        } => ExpPbValue::Len {
            data: data.clone(),
            data_start: data_start + d,
            children: children
                .as_ref()
                .map(|ks| ks.iter().map(|k| shift_field(k, d)).collect()),
        },
        ExpPbValue::Group(ks) => ExpPbValue::Group(ks.iter().map(|k| shift_field(k, d)).collect()),
    };
    ExpField {
        number: e.number,
        range: [e.range[0] + d, e.range[1] + d],
        value,
    }
}

fn pb_check_fields(parsed: &[Field], exp: &[ExpField]) -> Result<(), String> {
    if parsed.len() != exp.len() {
        return Err(format!("field count {} != {}", parsed.len(), exp.len()));
    }
    for (i, (f, e)) in parsed.iter().zip(exp).enumerate() {
        pb_check_field(f, e).map_err(|m| format!("field[{i}]: {m}"))?;
    }
    Ok(())
}

fn pb_check_field(f: &Field, e: &ExpField) -> Result<(), String> {
    if f.number != e.number {
        return Err(format!("number {} != {}", f.number, e.number));
    }
    if f.range != e.range {
        return Err(format!("range {:?} != {:?}", f.range, e.range));
    }
    match (&f.value, &e.value) {
        (
            FieldValue::Varint { raw, value },
            ExpPbValue::Varint {
                raw: eraw,
                value: eval,
            },
        ) => {
            if value != eval {
                return Err(format!("varint {value} != {eval}"));
            }
            if raw != eraw {
                return Err(format!("varint raw {raw:02x?} != {eraw:02x?}"));
            }
        }
        (FieldValue::I64 { value }, ExpPbValue::I64(eval)) => {
            if value != eval {
                return Err(format!("i64 {value} != {eval}"));
            }
        }
        (FieldValue::I32 { value }, ExpPbValue::I32(eval)) => {
            if value != eval {
                return Err(format!("i32 {value} != {eval}"));
            }
        }
        (
            FieldValue::Len {
                data,
                data_range,
                alts,
            },
            ExpPbValue::Len {
                data: edata,
                data_start,
                children,
            },
        ) => {
            if data != edata {
                return Err(format!("len data {data:02x?} != {edata:02x?}"));
            }
            let want = [*data_start, data_start + edata.len()];
            if data_range != &want {
                return Err(format!("data_range {data_range:?} != {want:?}"));
            }
            if let Some(kids) = children {
                let ok = alts.iter().any(|a| match &a.kind {
                    AltKind::Message(ms) => pb_check_fields(ms, kids).is_ok(),
                    _ => false,
                });
                if !ok {
                    return Err("no message alt matching the nested fields".into());
                }
            }
        }
        (FieldValue::Group { fields }, ExpPbValue::Group(kids)) => {
            pb_check_fields(fields, kids)?;
        }
        _ => {
            return Err(format!(
                "wire mismatch: {} vs {:?}",
                f.value.wire_name(),
                e.value
            ));
        }
    }
    Ok(())
}

fn gen_field_number(rng: &mut Rng) -> u32 {
    const EDGE: [u32; 14] = [
        1,
        2,
        3,
        15,
        16,
        127,
        128,
        2047,
        2048,
        1 << 16,
        (1 << 21) - 1,
        1 << 21,
        (1 << 28) - 1,
        (1 << 29) - 1,
    ];
    if rng.below(2) == 0 {
        EDGE[rng.below(EDGE.len())]
    } else {
        (1 + rng.next_u64() % ((1u64 << 29) - 1)) as u32
    }
}

fn gen_varint_value(rng: &mut Rng) -> u64 {
    const EDGE: [u64; 15] = [
        0,
        1,
        127,
        128,
        150,
        300,
        16383,
        16384,
        (1 << 31) - 1,
        1 << 31,
        (1 << 32) - 1,
        (-1i64) as u64,
        (-2i64) as u64,
        i64::MIN as u64,
        u64::MAX,
    ];
    if rng.below(2) == 0 {
        EDGE[rng.below(EDGE.len())]
    } else {
        rng.next_u64()
    }
}

fn gen_pb_field(rng: &mut Rng, depth: usize) -> PbNode {
    let number = gen_field_number(rng);
    let choices: &[u8] = if depth < 4 {
        &[0, 0, 2, 2, 1, 5, 3]
    } else {
        &[0, 0, 2, 2, 1, 5]
    };
    match choices[rng.below(choices.len())] {
        0 => PbNode::Varint {
            number,
            value: gen_varint_value(rng),
        },
        1 => PbNode::I64 {
            number,
            value: rng.next_u64(),
        },
        5 => PbNode::I32 {
            number,
            value: rng.next_u64() as u32,
        },
        2 => {
            let payload = if depth < 4 && rng.below(2) == 0 {
                let n = 1 + rng.below(3);
                PbPayload::Message((0..n).map(|_| gen_pb_field(rng, depth + 1)).collect())
            } else {
                let len = rng.below(40);
                PbPayload::Bytes(rng.bytes(len))
            };
            PbNode::Len { number, payload }
        }
        _ => {
            let n = 1 + rng.below(3);
            let fields = (0..n).map(|_| gen_pb_field(rng, depth + 1)).collect();
            PbNode::Group { number, fields }
        }
    }
}

fn pb_opts() -> Options {
    Options {
        input: InputForm::Raw,
        force: Some(Force::Protobuf),
        alts: 8,
        ..Options::default()
    }
}

#[test]
fn protobuf_roundtrip() {
    let opts = pb_opts();
    let mut rng = Rng::new(0x0000_0000_0000_b0ff);
    for _ in 0..400 {
        let count = 1 + rng.below(6);
        let nodes: Vec<PbNode> = (0..count).map(|_| gen_pb_field(&mut rng, 0)).collect();
        let (bytes, exps) = pb_encode(&nodes);
        let n = peel(&bytes, &opts)
            .unwrap_or_else(|e| panic!("peel error {} for {}", e.code, to_hex(&bytes)));
        let Detail::Message { fields } = &n.detail else {
            panic!("not a message: {}", to_json(&n));
        };
        pb_check_fields(fields, &exps).unwrap_or_else(|m| {
            panic!("{m}\nhex={}\njson={}", to_hex(&bytes), to_json(&n));
        });
    }
}

#[test]
fn protobuf_edge_varints() {
    let opts = pb_opts();
    let cases: [(u32, u64); 6] = [
        (1, u64::MAX),
        (2, (-2i64) as u64),
        (3, (-1i64) as u64),
        (4, i64::MIN as u64),
        (536_870_911, 1),
        (15, 0),
    ];
    let nodes: Vec<PbNode> = cases
        .iter()
        .map(|&(number, value)| PbNode::Varint { number, value })
        .collect();
    let (bytes, exps) = pb_encode(&nodes);
    let n = peel(&bytes, &opts).unwrap();
    let Detail::Message { fields } = &n.detail else {
        panic!()
    };
    pb_check_fields(fields, &exps).unwrap();
    // A negative int64 must be a 10-byte varint on the wire.
    let Detail::Message { fields } = &n.detail else {
        panic!()
    };
    let FieldValue::Varint { raw, .. } = &fields[1].value else {
        panic!()
    };
    assert_eq!(raw.len(), 10, "-2 should be a 10-byte varint");
}

// ---------------------------------------------------------------- DER

#[derive(Debug, Clone)]
enum DerNode {
    Seq(Vec<DerNode>),
    Set(Vec<DerNode>),
    Ctx(u32, Vec<DerNode>),
    Int(Vec<u8>),
    Oid(Vec<u8>, String),
    Utf8(String),
    Printable(String),
    Octet(Vec<u8>),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone)]
struct ExpAsn1 {
    class: TagClass,
    number: u32,
    constructed: bool,
    range: [usize; 2],
    content: [usize; 2],
    raw: Vec<u8>,
    kind: ExpKind,
}

#[derive(Debug, Clone)]
enum ExpKind {
    Constructed(Vec<ExpAsn1>),
    Int,
    Oid(String),
    Text(String),
    Bool(bool),
    Null,
    Octet,
}

/// Minimal DER length octets.
fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let mut v = n;
    let mut bytes = Vec::new();
    while v > 0 {
        bytes.push((v & 0xff) as u8);
        v >>= 8;
    }
    bytes.reverse();
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend_from_slice(&bytes);
    out
}

fn der_write(n: &DerNode, out: &mut Vec<u8>) -> ExpAsn1 {
    let start = out.len();
    let (tag, class, number, constructed) = match n {
        DerNode::Seq(_) => (0x30u8, TagClass::Universal, 16, true),
        DerNode::Set(_) => (0x31, TagClass::Universal, 17, true),
        DerNode::Ctx(n, _) => (0xa0 | *n as u8, TagClass::Context, *n, true),
        DerNode::Int(_) => (0x02, TagClass::Universal, 2, false),
        DerNode::Oid(..) => (0x06, TagClass::Universal, 6, false),
        DerNode::Utf8(_) => (0x0c, TagClass::Universal, 12, false),
        DerNode::Printable(_) => (0x13, TagClass::Universal, 19, false),
        DerNode::Octet(_) => (0x04, TagClass::Universal, 4, false),
        DerNode::Bool(_) => (0x01, TagClass::Universal, 1, false),
        DerNode::Null => (0x05, TagClass::Universal, 5, false),
    };
    out.push(tag);
    let (content, kind) = match n {
        DerNode::Seq(kids) | DerNode::Set(kids) | DerNode::Ctx(_, kids) => {
            let mut content = Vec::new();
            let mut exps = Vec::new();
            for k in kids {
                exps.push(der_write(k, &mut content));
            }
            (content, ExpKind::Constructed(exps))
        }
        DerNode::Int(raw) => (raw.clone(), ExpKind::Int),
        DerNode::Oid(raw, s) => (raw.clone(), ExpKind::Oid(s.clone())),
        DerNode::Utf8(s) => (s.clone().into_bytes(), ExpKind::Text(s.clone())),
        DerNode::Printable(s) => (s.clone().into_bytes(), ExpKind::Text(s.clone())),
        DerNode::Octet(raw) => (raw.clone(), ExpKind::Octet),
        DerNode::Bool(b) => (vec![if *b { 0xff } else { 0x00 }], ExpKind::Bool(*b)),
        DerNode::Null => (Vec::new(), ExpKind::Null),
    };
    let len = der_len(content.len());
    let cs = out.len() + len.len();
    out.extend_from_slice(&len);
    out.extend_from_slice(&content);
    let ce = out.len();
    // Children were laid out in a scratch buffer starting at 0; rebase them to
    // where their content landed inside `out`.
    let kind = match kind {
        ExpKind::Constructed(kids) => {
            ExpKind::Constructed(kids.iter().map(|k| shift_asn1(k, cs)).collect())
        }
        other => other,
    };
    let raw = if constructed { Vec::new() } else { content };
    ExpAsn1 {
        class,
        number,
        constructed,
        range: [start, ce],
        content: [cs, ce],
        raw,
        kind,
    }
}

/// Rebase an expected element (and its children) by `d` bytes.
fn shift_asn1(e: &ExpAsn1, d: usize) -> ExpAsn1 {
    let kind = match &e.kind {
        ExpKind::Constructed(kids) => {
            ExpKind::Constructed(kids.iter().map(|k| shift_asn1(k, d)).collect())
        }
        other => other.clone(),
    };
    let mut out = e.clone();
    out.range = [e.range[0] + d, e.range[1] + d];
    out.content = [e.content[0] + d, e.content[1] + d];
    out.kind = kind;
    out
}

fn der_peel(bytes: &[u8]) -> Node {
    let opts = Options {
        input: InputForm::Raw,
        force: Some(Force::Der),
        ..Options::default()
    };
    peel(bytes, &opts).unwrap_or_else(|e| panic!("DER peel {} for {}", e.code, to_hex(bytes)))
}

fn der_check(parsed: &Asn1, exp: &ExpAsn1) -> Result<(), String> {
    if parsed.class != exp.class {
        return Err(format!("class {:?} != {:?}", parsed.class, exp.class));
    }
    if parsed.number != exp.number {
        return Err(format!("number {} != {}", parsed.number, exp.number));
    }
    if parsed.constructed != exp.constructed {
        return Err("constructed flag differs".into());
    }
    if parsed.range != exp.range {
        return Err(format!("range {:?} != {:?}", parsed.range, exp.range));
    }
    if parsed.content != exp.content {
        return Err(format!("content {:?} != {:?}", parsed.content, exp.content));
    }
    if parsed.raw != exp.raw {
        return Err(format!("raw {:02x?} != {:02x?}", parsed.raw, exp.raw));
    }
    match (&parsed.value, &exp.kind) {
        (Asn1Value::Constructed(items), ExpKind::Constructed(exps)) => {
            if items.len() != exps.len() {
                return Err(format!("child count {} != {}", items.len(), exps.len()));
            }
            for (i, (it, ex)) in items.iter().zip(exps).enumerate() {
                der_check(it, ex).map_err(|m| format!("child[{i}]: {m}"))?;
            }
        }
        (Asn1Value::Int, ExpKind::Int)
        | (Asn1Value::Bool(_), ExpKind::Bool(_))
        | (Asn1Value::Null, ExpKind::Null) => {
            if let (Asn1Value::Bool(b), ExpKind::Bool(e)) = (&parsed.value, &exp.kind) {
                if b != e {
                    return Err(format!("bool {b} != {e}"));
                }
            }
        }
        (Asn1Value::Oid(s), ExpKind::Oid(e)) => {
            if s != e {
                return Err(format!("oid {s} != {e}"));
            }
        }
        (Asn1Value::Text(s), ExpKind::Text(e)) => {
            if s != e {
                return Err(format!("text {s:?} != {e:?}"));
            }
        }
        // An OCTET STRING whose content is itself clean DER is reported as
        // `Encapsulated`; either view is fine, `raw` was already compared.
        (Asn1Value::Bytes, ExpKind::Octet) | (Asn1Value::Encapsulated { .. }, ExpKind::Octet) => {}
        (v, k) => return Err(format!("value {v:?} does not match {k:?}")),
    }
    Ok(())
}

fn canonical_int(raw: &mut Vec<u8>) {
    if raw.is_empty() {
        raw.push(0);
        return;
    }
    if raw[0] & 0x80 != 0 {
        while raw.len() > 1 && raw[0] == 0xff && raw[1] & 0x80 != 0 {
            raw.remove(0);
        }
        if raw[0] & 0x80 == 0 {
            raw.insert(0, 0xff);
        }
    } else {
        while raw.len() > 1 && raw[0] == 0 && raw[1] & 0x80 == 0 {
            raw.remove(0);
        }
        if raw[0] & 0x80 != 0 {
            raw.insert(0, 0x00);
        }
    }
}

fn gen_int(rng: &mut Rng) -> Vec<u8> {
    let len = 1 + rng.below(40);
    let mut raw = rng.bytes(len);
    if rng.bool() {
        raw[0] |= 0x80;
    } else {
        raw[0] &= 0x7f;
    }
    canonical_int(&mut raw);
    raw
}

/// Big-endian two's complement as `i128` (valid for `<= 16` bytes).
fn int_i128(raw: &[u8]) -> i128 {
    let neg = raw.first().is_some_and(|b| b & 0x80 != 0);
    let mut v: i128 = if neg { -1 } else { 0 };
    for &b in raw {
        v = (v << 8) | i128::from(b);
    }
    v
}

fn put_subid(v: u64, out: &mut Vec<u8>) {
    let mut groups = vec![(v & 0x7f) as u8];
    let mut x = v >> 7;
    while x > 0 {
        groups.push(((x & 0x7f) as u8) | 0x80);
        x >>= 7;
    }
    groups.reverse();
    out.extend_from_slice(&groups);
}

fn gen_oid(rng: &mut Rng) -> (Vec<u8>, String) {
    let a0 = rng.below(3) as u64;
    let a1 = if a0 < 2 {
        rng.below(40) as u64
    } else {
        rng.below(1_000_000) as u64
    };
    let mut arcs = vec![a0, a1];
    for _ in 0..rng.below(4) {
        arcs.push(rng.below(1_000_000) as u64);
    }
    let mut raw = Vec::new();
    put_subid(40 * a0 + a1, &mut raw);
    for &a in &arcs[2..] {
        put_subid(a, &mut raw);
    }
    let dotted = arcs
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".");
    (raw, dotted)
}

fn gen_text(rng: &mut Rng, printable: bool) -> String {
    const ANY: [char; 13] = [
        'A', 'z', '0', ' ', '~', 'é', 'ß', 'ε', '€', '中', '日', '!', '𝄞',
    ];
    const PS: [char; 12] = ['A', 'b', 'C', '9', ' ', '.', '-', '_', 'x', 'Y', '/', ':'];
    let n = rng.below(16);
    let pool: &[char] = if printable { &PS } else { &ANY };
    (0..n).map(|_| pool[rng.below(pool.len())]).collect()
}

fn gen_octet(rng: &mut Rng) -> Vec<u8> {
    const SIZES: [usize; 10] = [0, 1, 2, 5, 127, 128, 129, 255, 256, 300];
    let len = if rng.below(10) == 0 {
        SIZES[rng.below(SIZES.len())]
    } else {
        rng.below(40)
    };
    rng.bytes(len)
}

fn gen_der_primitive(rng: &mut Rng) -> DerNode {
    match rng.below(7) {
        0 => DerNode::Int(gen_int(rng)),
        1 => {
            let (raw, dotted) = gen_oid(rng);
            DerNode::Oid(raw, dotted)
        }
        2 => DerNode::Utf8(gen_text(rng, false)),
        3 => DerNode::Printable(gen_text(rng, true)),
        4 => DerNode::Octet(gen_octet(rng)),
        5 => DerNode::Bool(rng.bool()),
        _ => DerNode::Null,
    }
}

fn gen_der(rng: &mut Rng, depth: usize) -> DerNode {
    if depth >= 4 || rng.below(10) < 5 {
        return gen_der_primitive(rng);
    }
    let n = rng.below(3);
    let kids: Vec<DerNode> = (0..n).map(|_| gen_der(rng, depth + 1)).collect();
    match rng.below(4) {
        0 => DerNode::Seq(kids),
        1 => DerNode::Set(kids),
        _ => DerNode::Ctx(rng.below(4) as u32, kids),
    }
}

fn collect_ints(e: &ExpAsn1, out: &mut Vec<String>) {
    match &e.kind {
        ExpKind::Int if e.raw.len() <= 16 => out.push(int_i128(&e.raw).to_string()),
        ExpKind::Constructed(kids) => {
            for k in kids {
                collect_ints(k, out);
            }
        }
        _ => {}
    }
}

#[test]
fn der_roundtrip() {
    let mut rng = Rng::new(0x0000_0000_0000_dead);
    for _ in 0..250 {
        let count = 1 + rng.below(3);
        let nodes: Vec<DerNode> = (0..count).map(|_| gen_der(&mut rng, 0)).collect();
        let mut enc = Vec::new();
        let mut exps = Vec::new();
        for node in &nodes {
            exps.push(der_write(node, &mut enc));
        }
        let n = der_peel(&enc);
        let Detail::Der { items } = &n.detail else {
            panic!("not DER: {}", to_json(&n));
        };
        assert_eq!(items.len(), exps.len(), "hex={}", to_hex(&enc));
        for (i, (it, ex)) in items.iter().zip(&exps).enumerate() {
            der_check(it, ex).unwrap_or_else(|m| {
                panic!(
                    "element {i}: {m}\nhex={}\njson={}",
                    to_hex(&enc),
                    to_json(&n)
                );
            });
        }
        let mut decs = Vec::new();
        for e in &exps {
            collect_ints(e, &mut decs);
        }
        let json = to_json(&n);
        for d in decs {
            assert!(
                json.contains(&format!("\"int\":\"{d}\"")),
                "missing int {d} in {json}\nhex={}",
                to_hex(&enc)
            );
        }
    }
}

#[test]
fn der_integer_decimal_roundtrip() {
    let mut rng = Rng::new(0x0000_0000_0000_01d7);
    for _ in 0..300 {
        let raw = gen_int(&mut rng);
        if raw.len() > 16 {
            continue;
        }
        let mut enc = Vec::new();
        let _ = der_write(&DerNode::Int(raw.clone()), &mut enc);
        let n = der_peel(&enc);
        let want = format!("\"int\":\"{}\"", int_i128(&raw));
        assert!(
            to_json(&n).contains(&want),
            "want {want} for raw={:02x?} json={}",
            raw,
            to_json(&n)
        );
    }
}

#[test]
fn der_long_form_lengths() {
    for len in [0usize, 1, 126, 127, 128, 129, 255, 256, 257, 300] {
        let mut rng = Rng::new(0x10e ^ len as u64);
        let node = DerNode::Seq(vec![DerNode::Octet(rng.bytes(len))]);
        let mut enc = Vec::new();
        let exp = der_write(&node, &mut enc);
        let n = der_peel(&enc);
        assert!(
            n.warnings.is_empty(),
            "len {len} unexpectedly noncanonical: {}",
            to_json(&n)
        );
        let Detail::Der { items } = &n.detail else {
            panic!()
        };
        der_check(&items[0], &exp).unwrap_or_else(|m| panic!("len {len}: {m}"));
    }
}

// ---------------------------------------------------------------- selection

#[test]
fn select_and_select_der_helpers() {
    let n = peel(&decode_hex("1a03089601").unwrap(), &pb_opts()).unwrap();
    let f = select(&n, "3.1").unwrap();
    assert_eq!(f.number, 1);
    match &f.value {
        FieldValue::Varint { value, .. } => assert_eq!(*value, 150),
        v => panic!("{v:?}"),
    }

    let dn = der_peel(&decode_hex("3003020105").unwrap());
    let e = select_der(&dn, "0.0").unwrap();
    assert_eq!(e.tag_name(), "INTEGER");
    assert_eq!(e.value, Asn1Value::Int);
    assert_eq!(e.range, [2, 5]);
    assert_eq!(e.content, [4, 5]);
}

// ---------------------------------------------------------------- robustness

fn option_matrix() -> Vec<Options> {
    let forms = [
        InputForm::Auto,
        InputForm::Hex,
        InputForm::Base64,
        InputForm::Raw,
    ];
    let forces = [
        None,
        Some(Force::Protobuf),
        Some(Force::Der),
        Some(Force::Text),
        Some(Force::Bytes),
    ];
    let mut out = Vec::new();
    for depth in [0usize, 1, 16] {
        for input in forms {
            for force in forces {
                out.push(Options {
                    depth,
                    alts: 3,
                    input,
                    force,
                    max_items: MAX_ITEMS,
                });
            }
        }
    }
    out
}

/// Peel, check `to_json` is deterministic (twice on the node and again on a
/// fresh peel), render `to_tree`, and never panic.
fn exercise(bytes: &[u8], opts: &Options) {
    match peel(bytes, opts) {
        Ok(n) => {
            let j1 = to_json(&n);
            let j2 = to_json(&n);
            assert_eq!(j1, j2, "to_json changed between calls");
            let _ = to_tree(&n);
            match peel(bytes, opts) {
                Ok(n2) => assert_eq!(j1, to_json(&n2), "peel is not deterministic"),
                Err(e) => panic!("peel flipped Ok -> Err ({}): {}", e.code, to_hex(bytes)),
            }
        }
        Err(e) => match peel(bytes, opts) {
            Err(e2) => assert_eq!(e.code, e2.code, "peel error is not deterministic"),
            Ok(_) => panic!("peel flipped Err -> Ok: {}", to_hex(bytes)),
        },
    }
}

#[test]
fn random_buffers_never_panic() {
    let mut rng = Rng::new(0x0000_0000_f00d_f00d);
    let matrix = option_matrix();
    for i in 0..5000 {
        let len = rng.below(49);
        let buf = rng.bytes(len);
        exercise(&buf, &matrix[i % matrix.len()]);
    }
}

#[test]
fn mutations_never_panic() {
    let mut rng = Rng::new(0x0000_0000_0bad_5eed);
    let matrix = option_matrix();

    let mut pb = Vec::new();
    put_varint(0x08, &mut pb);
    put_varint(150, &mut pb);
    put_varint(0x0a, &mut pb);
    put_varint(3, &mut pb);
    pb.extend_from_slice(b"foo");
    pb.extend_from_slice(&[0x15, 1, 2, 3, 4]); // field 2, I32
    pb.extend_from_slice(&[0x09, 1, 2, 3, 4, 5, 6, 7, 8]); // field 1, I64

    let mut der = Vec::new();
    let _ = der_write(
        &DerNode::Seq(vec![
            DerNode::Int(vec![0x05]),
            DerNode::Utf8("hi".into()),
            DerNode::Octet(vec![1, 2, 3]),
            DerNode::Null,
            DerNode::Bool(true),
        ]),
        &mut der,
    );

    let seeds: [Vec<u8>; 4] = [
        pb,
        der,
        b"SGVsbG8gd29ybGQ=".to_vec(),
        b"-----BEGIN X-----\nSGVsbG8gd29ybGQ=\n-----END X-----\n".to_vec(),
    ];

    for seed in &seeds {
        for _ in 0..40 {
            let mut b = seed.clone();
            if b.is_empty() {
                continue;
            }
            if rng.bool() {
                let i = rng.below(b.len());
                b[i] ^= 1u8 << rng.below(8);
            } else {
                let cut = rng.below(b.len());
                b.truncate(cut);
            }
            for opts in &matrix {
                exercise(&b, opts);
            }
        }
    }
}
