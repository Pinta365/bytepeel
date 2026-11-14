---
name: bytepeel
description: Decode or edit encoded and binary data with bytepeel instead of reading bytes by eye or writing a throwaway script. Use whenever you meet hex, base64 (incl. URL-safe), PEM certificates or keys, JWTs, xxd/hexdump output, gzip/zlib/zstd data, DER/ASN.1, CBOR, MessagePack or protobuf bytes, or any opaque blob in a log, header, cookie, config, test fixture or file, and when asked to change a field inside such data.
---

# bytepeel

bytepeel peels layers of encoding off data, recursively (base64 → gzip →
protobuf → a string field that is base64 again → …), and reports every layer
with byte ranges. It can also edit a value deep inside and re-encode every
layer in its original style.

**Never decode hex, base64 or binary formats by reading them, and don't write
ad-hoc decoding scripts.** Both produce plausible but wrong bytes (missing
base64 padding, URL-safe alphabets, 10-byte negative varints, zigzag on the
wrong type, a submessage printed as text). Run bytepeel and work from its
output.

## How to call it

If the bytepeel MCP tools (`peel`, `set`) are available, use them. Otherwise
run the `bytepeel` CLI, or `npx bytepeel` (same arguments) when it isn't
installed. If neither works, tell the user to install it (`npm install -g
bytepeel`, `cargo install bytepeel`, or a binary from
https://github.com/Pinta365/bytepeel/releases). If a call is denied or fails,
say so and give the command to run. Decode by hand only if the user asks, and
mark the result as unverified.

| Task | MCP | CLI |
|---|---|---|
| Overview | `peel {input, format:"tree"}` | `echo "$DATA" \| bytepeel --format tree` |
| Full detail (ranges, alts) | `peel {input}` | `bytepeel FILE` |
| One item | `peel {input, get:"3.1"}` | `bytepeel FILE --get 3.1` |
| A payload's exact bytes | `peel {file, get, format:"raw"}` (hex) | `bytepeel FILE --get 3.1 --format raw` |
| Edit | `set {input, edits:[{op,path,value}]}` | `bytepeel set 3.1=42 FILE` |

- Pass binary data as a **file** (`file` / `FILE`), never pasted. Text data
  (hex, base64, PEM, a JWT) can go inline (`input` / stdin).
- Start with `tree` to see the structure, then `--get` the part you need.
  The JSON output is complete but longer.
- Long text and bytes are previewed (`"truncated":true`). Use `--get PATH
  --format raw` for the whole value.

## Reading the output

- **Layers:** each node has a `codec` (`hex`, `base64`, `pem`, `jwt`, `gzip`,
  `protobuf`, `der`, `cbor`, `msgpack`, `utf8`, `bytes`, …), a `range` and a
  `confidence`. A text or compression layer has a `child`.
- **Ambiguity is reported, not resolved.** A protobuf LEN field lists ranked
  `alts` (`message`, `string`, `packed_varint`, `packed_fixed32/64`, `bytes`)
  with scores; the first is the best guess. If the top two are close, say so
  and use context to choose. A varint shows `uint`, `int` and `sint`: without
  a schema the right one is unknown (`sint` only for zigzag `sint32/64`).
- **64-bit integers are JSON strings** (`"uint":"18446744073709551614"`).
  Keep them as strings; don't convert them to floats.
- **Warnings** (`warnings: [{code, message, offset}]`) matter:
  `AMBIGUOUS_FORMAT` names other formats the bytes also parse as;
  `CHECKSUM_MISMATCH`, `CORRUPT_DATA` and `TRAILING_DATA` mean the data is
  damaged or has extra bytes.
- If auto-detection picked the wrong format, pin it: `--in hex|base64|raw`
  for the input text, `--as protobuf|der|cbor|msgpack|text|bytes` for the
  decoded bytes.

## Paths (`--get` and `set`)

| Format | Path | Example |
|---|---|---|
| protobuf | field numbers; `N[i]` = i-th occurrence | `1.3[2].4` |
| DER | 0-based child indices | `0.0.5` = a certificate's subject |
| PEM bundle | first index picks the block | `1.0.0.5` = 2nd cert's subject |
| CBOR / MessagePack | map keys and array indices | `users.0.name` |
| JWT | part, then JSON keys | `payload.sub`, `header.alg` |

Paths cross formats: when a segment can't go further in the current format but
the item holds decoded data, the rest of the path continues inside it. So
`2.0.0.5` is the subject of a certificate stored (base64, PEM or raw DER) in
protobuf field 2, and `p.1` is field 1 of protobuf inside CBOR byte string
`p`.

## Editing

```sh
echo '1a 03 08 96 01' | bytepeel set 3.1=300000        # -> 1a 04 08 e0 a7 12
bytepeel set 'name="new"' 'tags.0+="x"' --del old record.cbor > edited.cbor
```

`PATH=VALUE` changes, `PATH+=VALUE` adds, `--del PATH` removes; edits apply in
order. The output keeps the input's outer format (hex stays hex with the same
spacing, base64 keeps its alphabet, PEM its label, gzip its header), and every
other byte is preserved. Each edit is verified by decoding the result again.

Values: `42`, `-2`, `sint:-2` (zigzag), `1.5`, `true`, `null`, `"text"` (JSON
escapes; quote it for the shell), `str:text`, `hex:0a0b`, `b64:CgM=`. A
protobuf field keeps its wire type and a DER element its tag; CBOR and
MessagePack values may change type. In the MCP `set` tool, `value` is the same
syntax as a string (`"42"`, `"\"text\""`).

Editing a certificate or a signed token invalidates its signature. bytepeel
refuses to edit inside a JWT.

## Errors

Errors are JSON, `{"error":{"code","message","offset"}}`, on stderr (CLI exit
1 for decode errors, 2 for usage/IO) or as an MCP result with `isError`. The
`offset` points at the problem byte. Common fixes:

- `PATH_NOT_FOUND` / `PATH_NOT_MESSAGE`: run `--format tree` and fix the path.
- `INVALID_CHAR`, `ODD_LENGTH`, `BAD_PADDING`: the forced `--in` form is
  wrong, or the data was cut or mangled when copied.
- `TYPE_MISMATCH` / `VALUE_OUT_OF_RANGE`: the value doesn't fit the field's
  wire type or the element's type; see the value list above.
- `REENCODE_VERIFY_FAILED`: the edit would change how the data is
  auto-detected. Pin it with `--in` / `--as` and retry.

The full JSON schema, heuristics and every error code are in
https://github.com/Pinta365/bytepeel/blob/main/docs/DESIGN.md.
