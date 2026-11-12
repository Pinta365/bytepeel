# bytepeel design

## Why this exists

LLM agents cannot reliably decode hex, base64 or binary formats by reading them:
they produce plausible but wrong bytes. The usual workaround, a throwaway
Python script, routinely gets the edge cases wrong: missing base64 padding,
URL-safe alphabets, 10-byte negative varints, zigzag applied to the wrong
type, or a LEN field that is a submessage being printed as garbage text.

bytepeel moves the byte-exact work into a tested tool and leaves the judgment
to the agent. When the bytes are genuinely ambiguous, it reports ranked
alternatives instead of guessing silently.

## Principles

1. **Never resolve ambiguity silently.** LEN fields carry ranked `alts`;
   varints carry every integer view (`uint`, `int`, `sint`).
2. **Every node and field has a byte range,** so results can be cited and sliced.
3. **Deterministic.** The same input and options always give byte-identical JSON.
4. **Errors are data.** Stable `code`s and byte `offset`s let an agent fix its
   call in one turn.
5. **Zero dependencies in `bytepeel-core`.** Small, auditable, builds anywhere
   including WASM.
6. **Token-frugal output.** Compact JSON, long text and hex capped (with
   `"truncated":true`), and `--get` to extract exactly one field.

## Pipeline

```
input ─┬─ text? ─► best text layer (PEM | hex | base64) ─► recurse on decoded bytes
       └─ bytes ─► magic sniff (gzip/zstd/zlib/png/zip/DER) ─► leaf + UNSUPPORTED_FORMAT
                 └► schemaless protobuf (if plausible) ─► LEN fields ranked:
                       message | string (string may decode further) | packed_varint | bytes
                 └► bytes leaf
```

`--depth` limits total nesting (text layers plus protobuf messages, default 16).

## JSON schema

### Node

```jsonc
{
  "codec": "hex" | "base64" | "pem" | "protobuf" | "utf8" | "bytes",
  "alphabet": "std" | "url", "padded": bool,   // base64 only
  "label": "CERTIFICATE",                      // pem only
  "range": [start, end],                       // half-open, in the parent buffer
  "confidence": 0.95,                          // 0..1, confidence in `codec`
  // exactly one of:
  "decoded_len": N, "child": Node,             // hex | base64 | pem
  "fields": [Field],                           // protobuf
  "text": "...", "truncated": true?,           // utf8 (capped at 1024 chars)
  "len": N, "hex": "...", "truncated": true?,  // bytes (hex capped at 64 bytes)
  "warnings": [Diag]                           // omitted when empty
}
```

### Field

```jsonc
{ "field": 1, "wire": "VARINT" | "I64" | "I32" | "LEN" | "GROUP", "range": [s, e],
  // VARINT: every view, as decimal strings
  "uint": "18446744073709551614", "int": "-2", "sint": "9223372036854775807",
  // I64
  "fixed64": "…", "sfixed64": "…", "double": 1.5,
  // I32
  "fixed32": 7, "sfixed32": 7, "float": 1.5,
  // LEN
  "len": 3, "alts": [Alt],
  // GROUP
  "fields": [Field] }
```

### Alt (LEN interpretations, best first)

```jsonc
{ "as": "message", "score": 0.67, "fields": [Field] }
{ "as": "string", "score": 0.95, "value": "...", "decoded": Node? }  // decoded: string is itself hex/base64/PEM
{ "as": "packed_varint", "score": 0.31, "values": ["8", "150"] }
{ "as": "bytes", "score": 0.02, "hex": "..." }
{ "as": "empty", "score": 1.0 }
```

### Number encoding

- 64-bit integers (varint views, `fixed64`, `sfixed64`, packed values) are
  **decimal strings**. JavaScript and jq parse JSON numbers as doubles and
  would silently corrupt values above 2^53.
- 32-bit integers are plain JSON numbers.
- Floats use the shortest round-trip form, or exponent form when very large or
  very small. NaN and ±infinity are the strings `"NaN"`, `"Infinity"` and
  `"-Infinity"`.

### Ranges

A `range` points into the buffer the node or field was parsed from:

- A layer node's child is parsed from that layer's decoded bytes.
- Protobuf fields at any nesting depth use offsets into the same message
  buffer, so nested fields have absolute offsets within it.
- A string alt's `decoded` node starts a new buffer at that string's bytes.

## Heuristics (tunable; each has a test)

| Signal | Effect |
|---|---|
| Hex: `0x` prefix or whitespace/`:`-separated byte pairs | 0.95 |
| Hex: a single all-decimal token without a leading zero | ×0.5 (probably a number) |
| Base64: ≥16 chars / has `+/-_` or `=` / unpadded | +0.1 / +0.1 / −0.05 |
| Base64: non-zero unused trailing bits | ×0.3, plus `NONCANONICAL_BASE64` warning |
| Base64: only hex chars / no digit and no symbol | ×0.5 / ×0.6 |
| Text layer threshold: top level / nested | > 0.5 / > 0.75 (nested also needs hex ≥8 chars, base64 ≥16 chars) |
| Protobuf plausibility | starts at 0.9; ×0.85 per overlong varint, ×0.5 if a field number >1000 (×0.3 if >100k), ×0.7 per group, ×0.6 per wire-type conflict, ×0.6 for a single field in ≤3 bytes |
| LEN alt: message | plausibility, ×0.3 if the payload is fully printable |
| LEN alt: string | 0.9 × printable_ratio⁴ |
| LEN alt: packed_varint | 0.25 if mostly non-printable, else 0.03 |
| LEN alt: bytes | always present at 0.02 |

Alt scores are normalized to sum to 1, then truncated to `--alts`.

## Error and warning codes

| Code | Meaning |
|---|---|
| `USAGE` | Bad CLI arguments (exit 2) |
| `IO` | File or stdin read failure (exit 2) |
| `INVALID_UTF8` | Text was required (`--in hex/base64`, `--as text`) |
| `EMPTY` | No hex digits or base64 characters |
| `INVALID_CHAR` | Not a hex digit or base64 character (offset points at it) |
| `ODD_LENGTH` | A hex token has an odd number of digits |
| `MIXED_ALPHABET` | Base64 mixes `+/` with `-_` |
| `BAD_PADDING` | Wrong `=` count, or data after padding |
| `INVALID_LENGTH` | Base64 length ≡ 1 (mod 4) |
| `PEM_UNTERMINATED` | `BEGIN` without matching `END` |
| `TRUNCATED_VARINT` | Varint runs past the end of the buffer |
| `VARINT_OVERFLOW` | Varint exceeds 64 bits |
| `FIELD_NUMBER_ZERO` / `FIELD_NUMBER_TOO_LARGE` | Invalid protobuf field number |
| `INVALID_WIRE_TYPE` | Wire type 6 or 7 |
| `TRUNCATED_FIELD` | LEN or fixed-width field runs past the end |
| `UNEXPECTED_END_GROUP` / `UNTERMINATED_GROUP` | Group tags do not pair up |
| `NESTING_TOO_DEEP` | More than 100 nested groups |
| `BAD_PATH` / `PATH_NOT_FOUND` / `PATH_NOT_MESSAGE` | `--get` path problems |
| `NO_PAYLOAD` | `--format raw` on a group |
| Warning: `NONCANONICAL_BASE64` | Unused trailing bits are set |
| Warning: `TRAILING_DATA` | Text outside the first PEM block was ignored |
| Warning: `UNSUPPORTED_FORMAT` | Recognized by magic bytes; decoder not implemented yet |

## Known limitations (MVP)

- A protobuf message whose bytes are all printable (possible when every tag is
  for field 4 or higher and every length is ≥32) is reported as text. Use
  `--as protobuf`.
- Packed fields are only tried as varints, not as fixed32/fixed64.
- Only the first PEM block is decoded.
- xxd/hexdump-style dumps (with offsets and an ASCII column) are not parsed yet.

## Roadmap

1. gzip, zlib and zstd layers (first optional dependency, behind a feature flag)
2. JWT (`header.payload.signature`) and DER/ASN.1 with OID names
3. CBOR and MessagePack
4. xxd and hexdump input formats; multiple PEM blocks
5. `cargo-fuzz` targets for every parser; property tests (encode → peel round-trip)
6. Re-encoding: `bytepeel set 1.3=42` rewrites a field and re-serializes
7. WASM build of `bytepeel-core` → npm package
