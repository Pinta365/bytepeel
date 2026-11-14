# Changelog

All notable changes are listed here. The project follows
[Semantic Versioning](https://semver.org/); the public contract is the JSON
schema, paths and error codes in [docs/DESIGN.md](docs/DESIGN.md).

## 0.1.0 (unreleased)

First release.

### Decoding

- Text layers: hex (any separators, `0x` forms), base64 (standard and URL-safe,
  padded or not), PEM (single blocks and bundles), JWT (JWS and JWE, with
  `exp`/`nbf`/`iat` as ISO 8601), and `xxd` / `hexdump -C` dumps (including
  nonzero start offsets).
- Compression: gzip (including concatenated members), zlib and zstd, behind the
  optional `deflate` and `zstd` features of `bytepeel-core` (on in the CLI).
- Binary formats: DER/ASN.1 (with about 175 named OIDs and encapsulated
  BIT/OCTET STRINGs), CBOR, MessagePack and schemaless protobuf (ranked
  interpretations of LEN fields, packed varint/fixed32/fixed64 alternatives,
  groups, and every varint as `uint`/`int`/`sint`).
- Layers nest in any order and are detected recursively, including inside
  protobuf string and bytes fields and CBOR/MessagePack byte strings.
- Ambiguity is reported, never silently resolved: ranked alternatives, and an
  `AMBIGUOUS_FORMAT` warning when binary formats compete.
- JSON output with a byte range on every node; 64-bit integers as strings;
  long text and bytes previewed. Also a compact `tree` outline.

### Selecting and editing

- `--get PATH` selects one protobuf field, DER element, CBOR/MessagePack
  value or JWT claim; `--format raw` writes its payload. Paths cross formats.
- `bytepeel set` changes (`PATH=VALUE`), adds (`PATH+=VALUE`) and removes
  (`--del PATH`) protobuf fields, CBOR/MessagePack values and DER elements,
  re-encoding every layer in its original style, with every other byte
  preserved. Paths cross formats. Each edit is verified by decoding the
  output again.

### Limits

- Decompression is capped at 64 MiB per stream and 256 MiB per input.
- At most 1,000,000 protobuf fields, CBOR/MessagePack values and DER elements
  are decoded per input (`--max-items`).
- Nesting depth is capped (`--depth`, default 16).

### Interfaces

- `bytepeel`: the CLI, with structured JSON errors and stable error codes.
- `bytepeel mcp`: a Model Context Protocol server on stdio with `peel` and
  `set` tools.
- `bytepeel-core`: the Rust library, with no dependencies by default.
- A WebAssembly build for JavaScript (Node, Deno, Bun, browsers), published
  to npm as `bytepeel` and to JSR as `@pinta365/bytepeel`.
