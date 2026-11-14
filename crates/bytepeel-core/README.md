# bytepeel-core

The library behind [bytepeel](https://crates.io/crates/bytepeel): a recursive
decoder and editor for encoded and binary data, with no dependencies by
default.

It peels input layer by layer into a tree: hex, base64, PEM (and bundles),
JWTs, `xxd`/`hexdump -C` dumps, gzip/zlib/zstd (optional features), DER/ASN.1,
CBOR, MessagePack and schemaless protobuf, nested in any order. Every node
carries its byte range. Where the bytes are genuinely ambiguous (is a protobuf
LEN field a string, a submessage or packed varints?), the top interpretations
are kept with scores instead of one being picked silently.

```rust
use bytepeel_core::{FieldValue, Op, Options, Pick, edit, get, parse_value, peel};

let opts = Options::default();

// base64 -> protobuf -> a string field that is base64 again -> text.
let node = peel(b"ChRTR1ZzYkc4c0lIZHZjbXhrSVNFPRAq", &opts).unwrap();
println!("{}", bytepeel_core::to_json(&node)); // the whole tree as JSON

// Select one item by path (paths can cross formats, e.g. into a
// certificate held in a protobuf field).
match get(&node, "2").unwrap() {
    Pick::Field(f) => assert!(matches!(f.value, FieldValue::Varint { value: 42, .. })),
    _ => unreachable!(),
}

// Edit and re-encode every layer in its original style (here: hex).
let out = edit(b"1a 03 08 96 01", &opts, &Op::Set("3.1".into(), parse_value("300000").unwrap())).unwrap();
assert_eq!(out, b"1a 04 08 e0 a7 12");
```

## Features

| Feature | Adds | Dependency |
|---|---|---|
| `deflate` | gzip and zlib layers | `miniz_oxide` |
| `zstd` | Zstandard layers | `ruzstd` |

Both are off by default and pure Rust. The crate has no `unsafe` code.

The JSON schema, paths, heuristics and error codes are specified in
[DESIGN.md](https://github.com/pinta365/bytepeel/blob/main/docs/DESIGN.md).

## License

MIT
