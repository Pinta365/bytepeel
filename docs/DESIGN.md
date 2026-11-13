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
input ─┬─ text? ─► best text layer (PEM | JWT | xxd/hexdump | hex | base64) ─► recurse on decoded bytes
       │            JWT recurses into one base64 layer per dot-separated part;
       │            a PEM bundle recurses into one pem layer per block
       └─ bytes ─► gzip | zlib | zstd (checksum-verified) ─► recurse on decompressed bytes
                 └► DER (a single well-formed SEQUENCE) ─► element tree
                 └► magic sniff (png/zip) ─► leaf + UNSUPPORTED_FORMAT
                 └► schemaless protobuf (if plausible) ─► LEN fields ranked:
                       message | string (string may decode further) | packed_varint | bytes
                 └► bytes leaf
```

`--depth` limits total nesting (text and compression layers plus protobuf
messages, default 16). `--as` applies after any text and compression layers.

### Cargo features (`bytepeel-core`)

The core is zero-dependency by default. Decoders that need a third-party crate
are opt-in; the `bytepeel` CLI enables all of them.

| Feature | Adds | Dependency |
|---|---|---|
| `deflate` | gzip (incl. multi-member), zlib | `miniz_oxide` |
| `zstd` | Zstandard (incl. multi-frame) | `ruzstd` |

Without a feature, a stream it would decode is a `bytes` leaf with an
`UNSUPPORTED_FORMAT` warning naming the missing feature.

## JSON schema

### Node

```jsonc
{
  "codec": "hex" | "dump" | "base64" | "pem" | "bundle" | "jwt" | "gzip" | "zlib"
         | "zstd" | "protobuf" | "der" | "utf8" | "bytes",
  "alphabet": "std" | "url", "padded": bool,   // base64 only
  "label": "CERTIFICATE",                      // pem only
  "style": "xxd" | "hexdump",                  // dump only
  "kind": "jws" | "jwe",                       // jwt only
  "name": "msg.bin",                           // gzip only, when the header has FNAME
  "range": [start, end],                       // half-open, in the parent buffer
  "confidence": 0.95,                          // 0..1, confidence in `codec`
  // exactly one of:
  "decoded_len": N, "child": Node,             // hex | dump | base64 | pem | gzip | zlib | zstd
  "fields": [Field],                           // protobuf
  "items": [Element],                          // der
  "parts": [Node], "times": {"exp": "..."},    // jwt | bundle (times: jwt only)
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

### Element (DER)

```jsonc
{ "tag": "SEQUENCE",          // universal type name, or "[0]", "[APPLICATION 3]", "[PRIVATE 1]", "[UNIVERSAL 31]"
  "range": [s, e],            // whole element, header included
  "len": N,                   // content length
  // constructed (SEQUENCE, SET, [n] constructed):
  "children": [Element],
  // BIT STRING / OCTET STRING whose content is itself clean DER:
  "unused_bits": 0,           // BIT STRING only
  "encapsulated": true, "children": [Element],
  // primitives, by universal type:
  "int": "-1",                // INTEGER, ENUMERATED: decimal string, up to 16 bytes
  "hex": "…",                 //   … plus hex when longer than 8 bytes (hex only above 16)
  "bool": true,               // BOOLEAN
  "oid": "2.5.4.3", "name": "commonName",   // OBJECT IDENTIFIER / RELATIVE-OID; name when known
  "value": "…",               // character strings (BMP/Universal/T61 decoded to UTF-8)
  "value": "200904000000Z", "iso": "2020-09-04T00:00:00Z",  // UTCTime, GeneralizedTime
  "unused_bits": 3, "hex": "…",            // BIT STRING (not encapsulated)
  "hex": "…", "text": "…"     // anything else (OCTET STRING, [n] primitive, …); text when printable UTF-8
}
```

Element ranges are absolute within the DER buffer, including elements inside
encapsulating BIT/OCTET STRINGs. NULL has no value key.

### JWT

```jsonc
{ "codec": "jwt", "kind": "jws",             // "jws" = 3 parts, "jwe" = 5
  "range": [0, N], "confidence": 0.97,
  "parts": [                                 // one base64 layer node per segment
    { "codec": "base64", "alphabet": "url", "padded": false,
      "range": [s, e],                       // the segment's range in the token
      "decoded_len": L, "child": Node }      // header/payload are utf8 JSON text
  ],
  "times": { "exp": "2026-11-12T09:30:00Z", "iat": "..." }  // omitted when none
}
```

A JWS payload that is a JSON object contributes its top-level integer `exp`,
`nbf` and `iat` claims as ISO-8601 UTC strings, always in `exp`, `nbf`, `iat`
order and only when present. A fractional part is truncated toward zero;
exponent notation, non-numbers and `i64` overflow are ignored. Nested claims
(inside objects/arrays/strings) are never read. JWE tokens carry no `times`.

### Bundle (PEM)

```jsonc
{ "codec": "bundle", "range": [0, N], "confidence": 0.99,
  "parts": [                                 // one pem layer node per block, in order
    { "codec": "pem", "label": "CERTIFICATE",
      "range": [s, e],                       // BEGIN line start .. END line end
      "decoded_len": L, "child": Node }      // child parsed from the block's DER
  ]
}
```

A single PEM block stays a plain `pem` node. Two or more blocks become a
`bundle`. Each part's `range` is its block's `BEGIN..END` extent in the input
text and its `child` starts a new buffer at the block's decoded bytes. A
`TRAILING_DATA` warning is emitted once, on the bundle, when non-whitespace
text sits outside all blocks; the message reports the number of ignored bytes.

A realistic truncated paste (a good block followed by a cut-off one) is not
discarded: the blocks decoded so far are kept and the break becomes a warning
on the resulting node — `PEM_UNTERMINATED` (offset at the cut-off `BEGIN`) or
the base64 error. The text from the broken block onward is excluded from the
`TRAILING_DATA` count. If the *first* block is broken, nothing is recognised
and the input stays text (as before).

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
- A JWT part's `child` starts a new buffer at that part's decoded bytes.
- A PEM bundle part's `range` is its block in the input text, and its `child`
  starts a new buffer at the block's decoded bytes.
- DER elements at any nesting depth (encapsulated ones included) use offsets
  into the same DER buffer.

### Paths (`--get`)

- Protobuf: field numbers separated by `.`; `N[i]` picks the i-th occurrence
  (`1.3[2].4`). A LEN field is entered through its best `message` alt.
- DER: 0-based child indices separated by `.`; the first segment indexes the
  top-level elements, so `0.0.6` is a certificate's subjectPublicKeyInfo.
  For a PEM bundle the first segment picks the block, so `1.0.0.5` is the
  second certificate's subject (`is_der` is true only when every block is DER).
  Encapsulating BIT/OCTET STRINGs are entered like constructed elements.
- Text layers are descended automatically. `--format raw` writes the payload:
  a field's bytes, or a primitive element's content (a BIT STRING without its
  unused-bits byte).

## Heuristics (tunable; each has a test)

| Signal | Effect |
|---|---|
| Hex: `0x` prefix or whitespace/`:`-separated byte pairs | 0.95 |
| Hex: a single all-decimal token without a leading zero | ×0.5 (probably a number) |
| Base64: ≥16 chars / has `+/-_` or `=` / unpadded | +0.1 / +0.1 / −0.05 |
| Base64: non-zero unused trailing bits | ×0.3, plus `NONCANONICAL_BASE64` warning |
| Base64: only hex chars / no digit and no symbol | ×0.5 / ×0.6 |
| Dump (`xxd` / `hexdump -C`) | 0.98; needs an offset-0 first line with `:` (xxd) or two spaces and a `|` column (hexdump), contiguous offsets, ≥1 byte |
| JWT | 0.97; 3 (`jws`) or 5 (`jwe`) dot-separated unpadded base64url segments whose header is canonical base64url for printable UTF-8 JSON starting with `{` and containing `"alg"`; any segment may be empty |
| PEM bundle | 0.99; 2+ `BEGIN`/`END` blocks, each label matching between `BEGIN` and `END` (one block stays a `pem` node); non-whitespace text outside all blocks → a single `TRAILING_DATA` warning carrying the ignored byte count; a *later* broken block stops the scan and becomes a warning on the node (`PEM_UNTERMINATED`, or the base64 error) with its offset, keeping the blocks before it |
| Text layer threshold: top level / nested | > 0.5 / > 0.75 (nested also needs hex ≥8 chars, base64 ≥16 chars) |
| Protobuf plausibility | starts at 0.9; ×0.85 per overlong varint, ×0.5 if a field number >1000 (×0.3 if >100k), ×0.7 per group, ×0.6 per wire-type conflict, ×0.6 for a single field in ≤3 bytes |
| DER (auto) | buffer starts with `0x30`, ≥4 bytes, parses as exactly one element with no malformed universal content: 0.95 (0.8 plus `NONCANONICAL_DER` for non-minimal lengths or integers) |
| DER encapsulation | BIT STRING (unused bits 0) / OCTET STRING content ≥2 bytes that parses completely as canonical, well-formed DER; a lone primitive must have a typed universal tag |
| gzip / zstd | magic `1f 8b 08` / `28 b5 2f fd`; decoded (confidence 1.0) only if the stream is complete and its CRC32 / content checksum matches, else a `bytes` leaf with the error as a warning |
| zlib | a valid 2-byte header (CM 8, CINFO ≤ 7, FCHECK, no FDICT) whose stream inflates with a matching Adler-32. Failures are reported only for the common headers `78 01/5e/9c/da`; other headers fall through to DER/protobuf |
| Decompressed size | capped at 64 MiB (`OUTPUT_TOO_LARGE`) |
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
| `PEM_UNTERMINATED` | `BEGIN` without matching `END`: an error when the first block is broken, a warning when a later block is cut off (earlier blocks are kept) |
| `TRUNCATED_VARINT` | Varint runs past the end of the buffer |
| `VARINT_OVERFLOW` | Varint exceeds 64 bits |
| `FIELD_NUMBER_ZERO` / `FIELD_NUMBER_TOO_LARGE` | Invalid protobuf field number |
| `INVALID_WIRE_TYPE` | Wire type 6 or 7 |
| `TRUNCATED_FIELD` | LEN or fixed-width field runs past the end |
| `UNEXPECTED_END_GROUP` / `UNTERMINATED_GROUP` | Group tags do not pair up |
| `NESTING_TOO_DEEP` | More than 100 nested groups |
| `BAD_PATH` / `PATH_NOT_FOUND` / `PATH_NOT_MESSAGE` | `--get` path problems |
| `NO_PAYLOAD` | `--format raw` on a group or constructed DER element |
| `TRUNCATED_ELEMENT` | A DER element runs past the end of its container (offset at its length) |
| `INDEFINITE_LENGTH` | BER indefinite length (`0x80`); not DER |
| `BAD_LENGTH` | DER length uses more than 8 bytes |
| `BAD_TAG` | DER tag number exceeds 32 bits |
| `BAD_DUMP` | An `xxd`/`hexdump` line is out of sequence or malformed (offset at the line) |
| Warning: `CORRUPT_DATA` | A gzip/zlib/zstd stream is truncated or invalid |
| Warning: `CHECKSUM_MISMATCH` | gzip CRC32, zlib Adler-32 or zstd content checksum does not match |
| Warning: `OUTPUT_TOO_LARGE` | Decompressed output would exceed 64 MiB |
| Warning: `NONCANONICAL_BASE64` | Unused trailing bits are set |
| Warning: `TRAILING_DATA` | Non-whitespace text outside PEM blocks (the message reports the ignored byte count), or bytes after a compressed stream, were ignored |
| Warning: `NONCANONICAL_DER` | Valid BER but not DER (non-minimal length or integer) |
| Warning: `UNSUPPORTED_FORMAT` | Recognized by magic bytes; decoder not implemented, or its Cargo feature is off |

## Known limitations (MVP)

- A protobuf message whose bytes are all printable (possible when every tag is
  for field 4 or higher and every length is ≥32) is reported as text. Use
  `--as protobuf`.
- Packed fields are only tried as varints, not as fixed32/fixed64.
- JWT time claims are read only from a JWS payload that is a JSON object;
  fractional seconds are truncated, exponent notation is ignored, and JWE
  tokens have no claims.
- Hex dumps must start at offset 0; `od` and plain `hexdump` (non `-C`) are not parsed.
- DER: only OIDs in a built-in table (~85) are named; BER indefinite
  lengths and constructed strings are not supported.
- `--get` on DER can't descend into a protobuf string or vice versa.

## Roadmap

1. CBOR and MessagePack
2. `cargo-fuzz` targets for every parser (round-trip property tests exist)
3. Re-encoding: `bytepeel set 1.3=42` rewrites a field and re-serializes
4. WASM build of `bytepeel-core` → npm package
