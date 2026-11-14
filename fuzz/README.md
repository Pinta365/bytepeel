# Fuzzing

Coverage-guided fuzz targets for `bytepeel-core` (all features on). This crate
is excluded from the main workspace because it needs nightly Rust.

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz

cargo +nightly fuzz run -O peel_auto -- -max_total_time=300 -timeout=10 -dict=dict/bytepeel.dict
```

`dict/bytepeel.dict` holds magic bytes and tokens that random mutation rarely
assembles (DER time tags, multi-byte UTF-8, compression and CBOR/MessagePack
headers, PEM and JWT markers). Always pass it.

| Target | What it checks |
|---|---|
| `peel_auto` | Auto-detection on arbitrary bytes never errors or panics; JSON is deterministic |
| `peel_options` | Every `InputForm` × `Force` × depth × alts combination (first two bytes pick them) |
| `select_path` | `--get` paths (`path\0input`): the cross-format `get` (JSON/tree/payload) and every single-format selector |
| `set_field` | `bytepeel set` (`path\0value\0input`) never panics, and edits decode back |
| `text_codecs` | `decode_hex` / `decode_b64` never panic, and decoded bytes re-encode losslessly |

Seed a corpus from the test fixtures for faster coverage:

```sh
mkdir -p corpus/peel_auto && cp ../crates/bytepeel-core/tests/fixtures/* corpus/peel_auto/
```

A crash is written to `artifacts/<target>/`. Reproduce it with
`cargo +nightly fuzz run <target> artifacts/<target>/<file>`, then add the input
as a regression test in `crates/bytepeel-core/tests/`.
