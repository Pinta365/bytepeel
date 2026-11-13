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
                 └► CBOR | MessagePack | schemaless protobuf:
                       map/array (or self-describe) candidates compete; the highest
                       confidence wins and every other is named in AMBIGUOUS_FORMAT
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
         | "zstd" | "protobuf" | "der" | "cbor" | "msgpack" | "utf8" | "bytes",
  "alphabet": "std" | "url", "padded": bool,   // base64 only
  "label": "CERTIFICATE",                      // pem only
  "style": "xxd" | "hexdump",                  // dump only
  "start": N,                                  // dump only, when the dump
                                               // starts at a nonzero offset
                                               // (child ranges stay 0-based)
  "kind": "jws" | "jwe",                       // jwt only
  "name": "msg.bin",                           // gzip only, when the header has FNAME
  "range": [start, end],                       // half-open, in the parent buffer
  "confidence": 0.95,                          // 0..1, confidence in `codec`
  // exactly one of:
  "decoded_len": N, "child": Node,             // hex | dump | base64 | pem | gzip | zlib | zstd
  "fields": [Field],                           // protobuf
  "items": [Element],                          // der
  "items": [Value],                            // cbor | msgpack
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
{ "as": "packed_fixed32", "score": 0.94, "values": [1069547520], "floats": [1.5] }
{ "as": "packed_fixed64", "score": 0.87, "values": ["4632445839417212613"], "doubles": [51.5074] }
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

### Value (CBOR / MessagePack)

A `cbor` or `msgpack` node carries `"items": [Value]` (normally one item; a
forced sequence may hold several). Each value has a `type`, a `range` in that
buffer, and `"indefinite":true` when it used a CBOR indefinite-length form.

```jsonc
{ "type": "uint" | "nint" | "float" | "bool" | "null" | "undefined"
         | "simple" | "bytes" | "text" | "array" | "map" | "tag" | "ext",
  "range": [s, e],
  "indefinite": true?,                        // CBOR indefinite-length form
  "value": "42",                              // uint/nint: decimal string (nint = -1-n)
  "value": 1.5, "width": 16,                  // float: shortest form that round-trips at the source width 16|32|64 (16-bit uses the f32 form)
  "value": true,                              // bool
  "value": 16,                                // simple (CBOR)
  "len": N, "hex": "…", "truncated": true?, "decoded": Node?,  // bytes
  "value": "…", "truncated": true?,           // text (capped at 1024 chars)
  "items": [Value],                           // array
  "entries": [{"key": Value, "value": Value}],// map
  "tag": "1", "name": "epoch",                // CBOR tag; name when known
  "iso": "…", "int": "…", "uuid": "…",        // tag 1 / 2,3 / 37 extras
  "value": Value,                             // tag payload
  "ext_type": -1, "len": N, "hex": "…", "iso": "…"  // MessagePack ext; iso for the timestamp type (-1)
}
```

A `bytes` value's `decoded` node starts a new buffer at those bytes and is set
when they are themselves CBOR/MessagePack/DER/protobuf/compressed, or a text
encoding (never for plain text or opaque bytes). It is also set to a `bytes`
leaf that carries a warning (a corrupt or over-budget compressed stream, an
unsupported format), so the warning is not lost.

MessagePack maps onto the same tree: positive and negative integers become
`uint`/`nint` (negatives keep the `-1-n` form, so `int64` min is
`-9223372036854775808`), floats keep width 32 or 64, `str` must be valid UTF-8,
`bin` is `bytes`, and `ext` is `ext` whose `iso` is produced for the timestamp
type `-1` (4-, 8- and 12-byte forms; the 12-byte form allows dates before
1970). Trailing zero digits are trimmed from the nanosecond fraction.

CBOR known tag names: 0 datetime, 1 epoch, 2 bignum, 3 negbignum, 4 decimal,
5 bigfloat, 21/22/23 base64url/base64/base16, 24 cbor, 32 uri, 37 uuid, 55799
self-describe. Tag 1 adds `iso` (its numeric value as ISO-8601 UTC); tags 2/3
add `int` (a decimal bignum); tag 37 with 16 bytes adds `uuid`; tag 24 forces
the byte string's `decoded` node to CBOR.

An `iso` string (CBOR tag 1, MessagePack timestamp, JWT `exp`/`nbf`/`iat`) is
emitted only when the year is inside RFC 3339's `0000..=9999`; out-of-range
epochs (e.g. `i64::MIN`, or a year past 9999) omit it rather than print a
malformed date.

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
- CBOR / MessagePack values use offsets into the same buffer; a `bytes` value's
  `decoded` node starts a new buffer.

### Paths (`--get`)

- Protobuf: field numbers separated by `.`; `N[i]` picks the i-th occurrence
  (`1.3[2].4`). A LEN field is entered through its best `message` alt.
- DER: 0-based child indices separated by `.`; the first segment indexes the
  top-level elements, so `0.0.6` is a certificate's subjectPublicKeyInfo.
  For a PEM bundle the first segment picks the block, so `1.0.0.5` is the
  second certificate's subject (`is_der` is true only when every block is DER).
  Encapsulating BIT/OCTET STRINGs are entered like constructed elements.
- CBOR / MessagePack: map keys / array indices separated by `.`
  (`users.0.name`). A segment matches a text key exactly, indexes an array, or
  matches an integer map key; CBOR tags are followed transparently and a
  multi-item sequence is indexed by the first segment. `--format raw` writes a
  `bytes` value's bytes, an `ext` value's data, or a `text` value's UTF-8.
- JWT: a part name (`header`, `payload`, `signature`; for a JWE `header`,
  `encrypted_key`, `iv`, `ciphertext`, `tag`) or its index, optionally
  followed by object keys / array indices into that part's JSON
  (`payload.sub`, `payload.roles.0`, `header.alg`). Keys match exactly after
  unescaping; the first of duplicate keys wins; keys containing `.` can't be
  addressed. The part must be strictly valid JSON (RFC 8259). Output:

  ```jsonc
  { "part": "payload", "index": 1, "node": Node }          // a whole part
  { "part": "payload", "index": 1, "path": "sub",
    "range": [7, 13],                                       // in the part's decoded text
    "value": "1234" }                                       // the JSON value, verbatim
  ```

  `value` is copied from the token, so its numbers are not re-encoded (a large
  integer stays a JSON number). `--format raw` writes a string's unescaped
  text, any other value's JSON, or a whole part's decoded bytes; `--format
  tree` prints `payload.sub = "1234"`.
- Text layers are descended automatically. `--format raw` writes the payload:
  a field's bytes, or a primitive element's content (a BIT STRING without its
  unused-bits byte).

## Re-encoding (`bytepeel set`)

```
bytepeel [OPTIONS] set EDIT... [FILE]     # writes the new data to stdout

EDIT:  PATH=VALUE    change
       PATH+=VALUE   add
       --del PATH    remove
```

Edits apply in the order given; each one is a separate decode, splice and
verification. Library: `bytepeel_core::edit(input, &opts, &Op::{Set, Add,
Del})`; `set(..)` is `edit` with `Op::Set`.

`set` changes, adds and removes protobuf fields, CBOR/MessagePack values and
DER elements, and writes the data back in the same outer format it arrived
in.

- **Byte-exact splicing.** Only the target field's payload changes. The length
  prefixes of the enclosing LEN fields are rewritten (minimal varints); every
  other byte is copied: field order, unknown fields, other fields'
  non-canonical encodings, and group start/end tags. The field's tag bytes are
  kept verbatim.
- **Paths** are the `--get` paths. Protobuf paths enter LEN fields the same
  way `--get` does (the first `message` alt, or a string whose decoded layers
  end in a message, e.g. base64 inside a string field). CBOR/MessagePack
  paths are map keys and array indices; the item inside any tags is replaced
  and the tags are kept. Because containers count items rather than bytes,
  the new item is spliced in at the old one's range and nothing else moves.
  DER paths are the `--get` child indices (the first one picks the block of
  a PEM bundle, and only that block is re-encoded). DER lengths count bytes,
  so the length of every enclosing element is rewritten, including
  encapsulating BIT/OCTET STRINGs (a BIT STRING keeps its unused-bits byte).
  Tag bytes are kept verbatim; rewritten lengths use the minimal DER form.
- **Layers are re-encoded in their original style:** hex keeps its separator,
  case, `0x` form, wrapping and surrounding whitespace; dumps keep the
  `xxd`/`hexdump -C` layout; base64 keeps its alphabet, padding, line width
  and line endings; PEM keeps its label and the text around the block. With
  unchanged bytes, these reproduce the original text exactly. gzip keeps the
  original member header (name, mtime, flags) and writes a new CRC32/ISIZE;
  zlib keeps its 2-byte header and writes a new Adler-32; zstd is re-compressed.
  Bytes after a compressed stream are kept. The compressed bytes differ from
  the original compressor's.
- **A protobuf field keeps its wire type.** Values:

  | Value | VARINT | I64 | I32 | LEN |
  |---|---|---|---|---|
  | `42`, `-2` | int (negative: 10-byte two's complement) | fixed64/sfixed64 | fixed32/sfixed32 | — |
  | `sint:-2` | zigzag | — | — | — |
  | `1.5`, `float:NaN` | — | double | float (must fit) | — |
  | `true` / `false` | 1 / 0 | — | — | — |
  | `"text"` (JSON escapes), `str:text` | — | — | — | UTF-8 |
  | `hex:0a0b`, `b64:CgM=` | — | — | — | bytes |

  `null` is `TYPE_MISMATCH` for protobuf.
- **A CBOR/MessagePack value may change type** (items are self-describing).
  Integers use the minimal encoding (CBOR: `[-2^64, 2^64)`, MessagePack:
  `[-2^63, 2^64)`); `sint:` is `TYPE_MISMATCH`. Floats use the smallest width
  that holds the value exactly (CBOR 16/32/64, MessagePack 32/64), but never
  narrower than the float being replaced, so a double stays a double. NaN
  and ±Infinity take that same width. Strings and byte strings are
  definite-length with minimal headers, even when they replace an
  indefinite-length item. `true`/`false`/`null` are the one-byte items.
  Nothing produces a MessagePack `ext`; replacing one gives a plain item.
- **A DER element keeps its tag** and the value is encoded for its type:

  | Element | Value | Content |
  |---|---|---|
  | INTEGER, ENUMERATED | `42`, `-129` | minimal two's complement |
  | BOOLEAN / NULL | `true`, `false` / `null` | `ff`, `00` / empty |
  | OBJECT IDENTIFIER | `"1.2.840.113549.1.1.11"` | OID |
  | UTF8String, Graphic/GeneralString, OCTET STRING | `"text"` | UTF-8 |
  | PrintableString, IA5String, NumericString, VisibleString | `"text"` | checked against the type's character set (`VALUE_OUT_OF_RANGE`) |
  | BMPString / UniversalString / T61, Videotex | `"text"` | UTF-16BE / UTF-32BE / Latin-1 |
  | UTCTime, GeneralizedTime | its own form (`300102030405Z`) or ISO 8601 (`"2030-01-02T03:04:05Z"`, offsets and fractions allowed for GeneralizedTime) | the type's form; UTCTime covers 1950-2049 |
  | any primitive | `hex:..`, `b64:..` | the content bytes verbatim; for a BIT STRING the bits, with 0 unused bits |
  | `[n]` and other non-universal primitives | `"text"`, `hex:..` | UTF-8 or the bytes |

  A constructed element is `TYPE_MISMATCH` (set one of its children).
  **Signatures are not updated:** editing a certificate or any other signed
  structure invalidates its signature. That is intended for building test
  fixtures; re-sign the result if it must verify.

- **Verified.** The output is decoded again with the same options; `set`
  fails with `REENCODE_VERIFY_FAILED` unless the path selects a field of the
  same wire type with exactly the new payload. This catches edits that change
  how auto-detection reads the data (pin it with `--in`/`--as`).
- **Adding (`PATH+=VALUE`):**

  | Codec | `PATH` | Placement | Encoding |
  |---|---|---|---|
  | protobuf | `PARENT.N` (`N` alone = top level); no `[i]` | appended at the end of the parent message (or group); a repeated field gets a new last occurrence | integers, `sint:`, bools → VARINT; floats → I64 (double); text and bytes → LEN. `null` is `TYPE_MISMATCH`. Field numbers 1..=2^29-1 |
  | CBOR / MessagePack map | `PARENT.KEY` | appended after the last entry | key is a text string; `ALREADY_EXISTS` if the key is present |
  | CBOR / MessagePack array | `PARENT.I`, `0 ≤ I ≤ length` | inserted before item `I` (`I` = length appends) | as for a changed value |
  | DER | `PARENT.I`, `0 ≤ I ≤ number of children` | inserted before element `I` | the value is one complete element as `hex:`/`b64:` (e.g. `hex:0101ff`); `BAD_VALUE` otherwise |

  The parent must be a message, map, array, or constructed/encapsulating
  element (`PATH_NOT_MESSAGE`). Verified: the new item is at `PATH` (for
  protobuf, the last occurrence) with the expected value, and the parent has
  one more child.
- **Removing (`--del PATH`):** the field, entry (key and value) or element
  at `PATH` is cut out. Verified: the parent has one fewer child.
- **Containers are rewritten as needed:** enclosing LEN prefixes (protobuf)
  and DER lengths up to the top, and the item count of a definite
  CBOR/MessagePack container (its header may change size, e.g. a 23-item
  CBOR array `97` becomes `98 18`, a 15-entry MessagePack fixmap becomes
  `map16`). Indefinite CBOR containers have no count: items go before the
  break byte.
- **Not editable yet:** JWT (editing would invalidate the signature),
  multi-member gzip / multi-frame zstd, PEM blocks with RFC 1421
  headers (`REENCODE_UNSUPPORTED`), data nested inside a CBOR/MessagePack
  byte string (`--get` paths do not enter it), top-level items of a
  multi-item CBOR/MessagePack sequence, and whole PEM blocks of a bundle.

## WebAssembly (`crates/bytepeel-wasm`, `npm/`)

`bytepeel-wasm` compiles the core (with `deflate` and `zstd`) to
`wasm32-unknown-unknown` with no imports and no generated glue. Its ABI:

| Export | Meaning |
|---|---|
| `bp_alloc(len) -> ptr` | allocate `len` bytes for the caller to fill |
| `bp_free(ptr, len)` | free a `bp_alloc` buffer or a `bp_call` result |
| `bp_call(op, in, in_len, arg, arg_len, opts, opts_len) -> ptr` | run one operation |

`op`: 0 peel (JSON), 1 tree, 2 get (JSON), 3 get raw payload, 4 edit. `arg`
is the path (get) or the edits as NUL-separated `kind, path, value` triples
(`set`/`add`/`del`, values in the CLI syntax). `opts` is `key=value` lines
(`in`, `as`, `depth`, `alts`). The result is `[status u8][len u32 LE][len
bytes]`: status 0 is the output, 1 is `{"error":{...}}` JSON; free it with
`bp_free(ptr, 5 + len)`.

`npm/index.js` wraps this as `load() -> { peel, tree, get, getRaw, edit }`
with typed edit values (strings are text, numbers are numbers) and
`BytepeelError`. Build: `npm/build.sh` (`--profile wasm`: release, size-optimized).

## Heuristics (tunable; each has a test)

| Signal | Effect |
|---|---|
| Hex: `0x` prefix or whitespace/`:`-separated byte pairs | 0.95 |
| Hex: a single all-decimal token without a leading zero | ×0.5 (probably a number) |
| Base64: ≥16 chars / has `+/-_` or `=` / unpadded | +0.1 / +0.1 / −0.05 |
| Base64: non-zero unused trailing bits | ×0.3, plus `NONCANONICAL_BASE64` warning |
| Base64: only hex chars / no digit and no symbol | ×0.5 / ×0.6 |
| Dump (`xxd` / `hexdump -C`) | 0.98; needs a hex-offset first line (any start, e.g. `xxd -s` / `hexdump -s`) with `:` (xxd) or two spaces and a `|` column (hexdump), contiguous offsets, ≥1 byte; the non-zero start is reported as `"start"` |
| JWT | 0.97; 3 (`jws`) or 5 (`jwe`) dot-separated unpadded base64url segments whose header is canonical base64url for printable UTF-8 JSON starting with `{` and containing `"alg"`; any segment may be empty |
| PEM bundle | 0.99; 2+ `BEGIN`/`END` blocks, each label matching between `BEGIN` and `END` (one block stays a `pem` node); non-whitespace text outside all blocks → a single `TRAILING_DATA` warning carrying the ignored byte count; a *later* broken block stops the scan and becomes a warning on the node (`PEM_UNTERMINATED`, or the base64 error) with its offset, keeping the blocks before it |
| Text layer threshold: top level / nested | > 0.5 / > 0.75 (nested also needs hex ≥8 chars, base64 ≥16 chars) |
| Protobuf plausibility | starts at 0.9; ×0.85 per overlong varint, ×0.5 if a field number >1000 (×0.3 if >100k), ×0.7 per group, ×0.6 per wire-type conflict, ×0.6 for a single field in ≤3 bytes |
| DER (auto) | buffer starts with `0x30`, ≥4 bytes, parses as exactly one element with no malformed universal content: 0.95 (0.8 plus `NONCANONICAL_DER` for non-minimal lengths or integers) |
| DER encapsulation | BIT STRING (unused bits 0) / OCTET STRING content ≥2 bytes that parses completely as canonical, well-formed DER; a lone primitive must have a typed universal tag |
| CBOR (auto) | a self-describe (`d9 d9 f7`) prefix: 0.99; otherwise the buffer must parse as exactly one item of ≥2 bytes whose top level (after tags) is a map or array, with valid UTF-8 everywhere: 0.9, or 0.7 when any map key is not a text string or a small int (`|n| ≤ 23`), or 0.6 when the tree contains no map at all |
| MessagePack (auto) | the buffer must parse as exactly one item of ≥2 bytes whose top level is a map or array: 0.9, or 0.7 when any map key is not a string or a fixint (`0..=127`, or `n ≤ 31` for `nint`), or 0.6 when the tree contains no map at all |
| CBOR / MessagePack / protobuf | when several accept the buffer, the highest confidence wins; on a tie prefer all-text map keys, then CBOR, then MessagePack, then protobuf. Every other interpretation is named with its confidence in one `AMBIGUOUS_FORMAT` warning. Map-less trees score 0.6 because many protobuf messages whose first tag is for field 16+ also parse as a CBOR/MessagePack array. Candidates are parsed structurally; nested detection (byte strings, protobuf string fields) runs once, on the winner |
| gzip / zstd | magic `1f 8b 08` / `28 b5 2f fd`; decoded (confidence 1.0) only if the stream is complete and its CRC32 / content checksum matches, else a `bytes` leaf with the error as a warning |
| zlib | a valid 2-byte header (CM 8, CINFO ≤ 7, FCHECK, no FDICT) whose stream inflates with a matching Adler-32. Failures are reported only for the common headers `78 01/5e/9c/da`; other headers fall through to DER/protobuf |
| Decompressed size | capped at 64 MiB per stream (concatenated gzip members and zstd frames share the cap) and 256 MiB in total per peel across every compressed layer (`OUTPUT_TOO_LARGE`) |
| LEN alt: message | plausibility, ×0.3 if the payload is fully printable |
| LEN alt: string | 0.9 × printable_ratio⁴ |
| LEN alt: packed_varint | 0.25 if mostly non-printable, else 0.03 |
| LEN alt: packed_fixed64 / packed_fixed32 | offered when the length is a multiple of 8 / 4: 0.3 / 0.28 × p⁴ + 0.01 if mostly non-printable (p = share of values that read as a plausible float: 0, or finite with magnitude in [1e-9, 1e12]), else 0.01. Two floats can also read as one plausible double, so both alts may appear |
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
| `NESTING_TOO_DEEP` | More than 100 nested groups, CBOR items or MessagePack items |
| `BAD_PATH` / `PATH_NOT_FOUND` / `PATH_NOT_MESSAGE` | `--get` path problems |
| `NO_PAYLOAD` | `--format raw` on a group or constructed DER element |
| `TRUNCATED_ELEMENT` | A DER element runs past the end of its container (offset at its length) |
| `INDEFINITE_LENGTH` | BER indefinite length (`0x80`); not DER |
| `BAD_LENGTH` | DER length uses more than 8 bytes |
| `BAD_TAG` | DER tag number exceeds 32 bits |
| `BAD_DUMP` | An `xxd`/`hexdump` line is out of sequence or malformed (offset at the line) |
| `CBOR_TRUNCATED` | A CBOR item runs past the end of the buffer |
| `CBOR_RESERVED` | Reserved additional information (28-30), `31` for a type that has no indefinite form, or a two-byte simple value `< 32` |
| `CBOR_BREAK` | An unexpected `0xff` break where an item was expected |
| `CBOR_BAD_UTF8` | A CBOR text string is not valid UTF-8 (offset at its content) |
| `CBOR_INVALID` | An indefinite string chunk is not a definite string of the same type |
| `MSGPACK_TRUNCATED` | A MessagePack item (or a declared length) runs past the end of the buffer |
| `MSGPACK_RESERVED` | The reserved byte `0xc1` |
| `MSGPACK_BAD_UTF8` | A MessagePack `str` is not valid UTF-8 (offset at its content) |
| Warning: `AMBIGUOUS_FORMAT` | The buffer also parses as one or more other codecs; the message names each with its confidence |
| Warning: `CORRUPT_DATA` | A gzip/zlib/zstd stream is truncated or invalid |
| Warning: `CHECKSUM_MISMATCH` | gzip CRC32, zlib Adler-32 or zstd content checksum does not match |
| Warning: `OUTPUT_TOO_LARGE` | Decompressed output would exceed 64 MiB, or the 256 MiB total budget for the input is exhausted |
| `BAD_VALUE` | A `set` value is not in the value syntax (exit 2) |
| `TYPE_MISMATCH` | A `set` value does not fit the field's wire type |
| `VALUE_OUT_OF_RANGE` | A `set` integer or float does not fit the field |
| `REENCODE_UNSUPPORTED` | A layer on the path cannot be re-encoded |
| `REENCODE_VERIFY_FAILED` | The re-encoded data does not decode back to the requested change |
| `ALREADY_EXISTS` | `PATH+=VALUE` names a map key that is already present |
| Warning: `NONCANONICAL_BASE64` | Unused trailing bits are set |
| Warning: `TRAILING_DATA` | Non-whitespace text outside PEM blocks (the message reports the ignored byte count), or bytes after a compressed stream, were ignored |
| Warning: `NONCANONICAL_DER` | Valid BER but not DER (non-minimal length or integer) |
| Warning: `UNSUPPORTED_FORMAT` | Recognized by magic bytes; decoder not implemented, or its Cargo feature is off |

## Known limitations (MVP)

- A protobuf message whose bytes are all printable (possible when every tag is
  for field 4 or higher and every length is ≥32) is reported as text. Use
  `--as protobuf`.
- JWT time claims are read only from a JWS payload that is a JSON object;
  fractional seconds are truncated, exponent notation is ignored, and JWE
  tokens have no claims.
- `od` and plain `hexdump` (non `-C`) are not parsed.
- CBOR and MessagePack are auto-detected only when the top level is a map or
  array (CBOR also accepts a self-describe tag); a bare scalar needs
  `--as cbor` / `--as msgpack`. JSON floats print `-0.0` as `0`.
- DER: only OIDs in a built-in table (~175) are named; BER indefinite
  lengths and constructed strings are not supported.
- `--get` on DER can't descend into a protobuf string or vice versa.

## Roadmap

1. Publishing (crates.io, npm) when the project goes public
2. An MCP server wrapping the library
