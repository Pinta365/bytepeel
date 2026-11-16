# Changelog

All notable changes are listed here. The project follows
[Semantic Versioning](https://semver.org/); the public contract is the JSON
schema, paths and error codes in [docs/DESIGN.md](docs/DESIGN.md).

## 0.1.2 (2026-11-16)

- Packed fixed-width integers rank correctly: a protobuf LEN field holding
  fixed64/fixed32 ids, timestamps or counters (values sharing their high
  bits) now ranks `packed_fixed64`/`packed_fixed32` first. Before, such
  fields read as `packed_varint` or `bytes`, and `packed_fixed64` could fall
  off the default three alts.
- `--get` walks into JSON text: a decoded text layer (base64 → gzip → JSON),
  a protobuf string field or a CBOR/MessagePack text string that holds a
  JSON object or array takes key and index segments (`users.37.id`). It reads
  the whole text, so values past the truncated preview are reachable.
- `--format tree` prints floats like the JSON output (exponent form for very
  small and very large values), so a fixed64 timestamp's `double` reading is
  `8.73e-312` instead of hundreds of digits.

## 0.1.1 (2026-11-15)

- `npx bytepeel` and `npx -y bytepeel mcp`: the npm package now has a
  `bytepeel` command that runs the native CLI from a per-platform package
  (`bytepeel-linux-x64`, `-linux-arm64`, `-darwin-x64`, `-darwin-arm64`,
  `-win32-x64`), so the CLI and MCP server need no Rust toolchain.
- An MCP Registry entry (`server.json`, `io.github.Pinta365/bytepeel`).
- A Claude Code plugin (`/plugin marketplace add Pinta365/bytepeel`) with an
  agent skill that tells the agent when and how to use bytepeel, and the MCP
  server.

## 0.1.0 (2026-11-14)

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
