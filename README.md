# bytepeel

Peel layers of encoding off binary data. Built so that AI coding agents can
call it instead of writing throwaway decoding scripts.

```console
$ printf 'ChRTR1ZzYkc4c0lIZHZjbXhrSVNFPRAq' | bytepeel --format tree
base64(std,padded) [0..32] conf=0.85 -> 24 bytes
  protobuf [0..24] conf=0.90
    #1 LEN [0..22] len=20: string 0.95 "SGVsbG8sIHdvcmxkISE=" | packed_varint 0.03 | bytes 0.02
      base64(std,padded) [0..20] conf=0.95 -> 14 bytes
        utf8 [0..14] conf=1.00 "Hello, world!!"
    #2 VARINT [22..24] uint=42 int=42 sint=21
```

- **Recursive:** base64 → protobuf → a string field that is base64 again →
  text, in one call.
- **Honest about ambiguity:** each protobuf LEN field lists ranked
  interpretations (`message`, `string`, `packed_varint`, `bytes`), and each
  varint shows its `uint`, `int` and `sint` views.
- **Agent-friendly:** compact JSON by default, byte ranges on everything, 64-bit
  integers as strings (safe for jq and JavaScript), and errors as
  `{"error":{"code","message","offset"}}` with stable codes.
- **Zero-dependency core** (`bytepeel-core`; gzip/zstd are opt-in features)
  and a single static binary.

## Supported today

| Layer | Notes |
|---|---|
| hex | whitespace, `:` and `0x` separators |
| hex dumps | `xxd` (any `-g`) and `hexdump -C` (with `*` repeats); the ASCII column is ignored |
| base64 | standard and URL-safe alphabets, padded and unpadded, line-wrapped |
| PEM | any label; RFC 1421 headers skipped; multiple blocks (chain, key + cert) become a `bundle` of per-block layers |
| JWT | JWS (3 parts) and JWE (5 parts); each part decoded, and `exp`/`nbf`/`iat` rendered as ISO-8601 UTC |
| protobuf | schemaless; groups, negative varints, fixed32/64 as int and float |
| DER / ASN.1 | X.509, PKCS, CMS; ~85 named OIDs, ISO times, any-width integers, DER nested in BIT/OCTET STRINGs decoded in place |
| CBOR | RFC 8949: maps, arrays, tags (epoch → ISO-8601, bignums, uuid), indefinite lengths, half/single/double floats; `--as cbor` for scalars |
| MessagePack | maps, arrays, str/bin, int64/uint64, float32/64, ext (timestamp type -1 → ISO-8601 with nanoseconds); `--as msgpack` for scalars |
| utf8 / bytes | leaves |
| gzip, zlib, zstd | checksum-verified, multi-member/frame, 64 MiB output cap (optional core features `deflate` and `zstd`, on in the CLI) |
| PNG, zip | recognized by magic bytes; decoders on the roadmap |

## Usage

```
bytepeel [OPTIONS] [FILE]            # stdin when FILE is omitted or '-'

--in <auto|hex|base64|raw>           how to read the input (default: auto)
--as <protobuf|der|cbor|msgpack|text|bytes>
                                     force interpretation of the decoded bytes
--depth <N>                          max nesting (default 16)
--alts <N>                           interpretations kept per LEN field (default 3)
--max-items <N>                      max fields/values/elements decoded in total (default 1000000)
--get <PATH>                         protobuf: field numbers, e.g. 1.3[2].4
                                     DER: 0-based child indices, e.g. 0.0.6
                                     PEM bundle: first index picks the block, e.g. 1.0.0.5
                                     CBOR/MessagePack: map keys / array indices, e.g. users.0.name
                                     JWT: part, then JSON keys, e.g. payload.sub, header.alg
                                     paths cross formats: 2.0.0.5 = a cert's subject in
                                     protobuf field 2 (base64, PEM or raw DER)
--format <json|tree|raw>             raw writes a --get selection's payload bytes
```

### Editing: `bytepeel set`

Change, add and remove protobuf fields, CBOR/MessagePack values and DER
elements, and get the data back in the same outer format, with every other
byte preserved. `PATH=VALUE` changes, `PATH+=VALUE` adds, `--del PATH`
removes:

```console
$ echo '1a 03 08 96 01' | bytepeel set 3.1=300000
1a 04 08 e0 a7 12

$ base64 -w0 msg.pb.gz | bytepeel set 2='"new name"' 3=sint:-5 > edited.b64

$ bytepeel set users.0.active=false ttl=null 'tags.0+="new"' --del legacy record.cbor > edited.cbor

$ echo '08 96 01 12 03 66 6f 6f' | bytepeel set 3+=42 --del 2
08 96 01 18 2a

$ bytepeel set '0.0.5.2.0.1="Test Root"' '0.0.4.1="2045-06-07T08:09:10Z"' ca.pem > test-ca.pem

$ echo 'a1 61 70 43 08 96 01' | bytepeel set p.1=300 'p.2+="hi"'   # protobuf in a CBOR byte string
a1 61 70 47 08 ac 02 12 02 68 69
```

Paths cross formats as `--get` paths do: `2.0.0.5.2.0.1='"Test Root"'`
changes the common name of a base64 certificate in protobuf string field 2,
and both the certificate's base64 and the protobuf around it are re-encoded.

Editing a certificate invalidates its signature; that's fine for test
fixtures, and you re-sign it if it must verify.

Hex keeps its spacing and case, base64 its alphabet and line width, PEM its
label, gzip its header. Values: `42`, `sint:-2`, `1.5`, `true`, `null`,
`"text"`, `hex:0a0b`, `b64:CgM=`. The output is decoded again and checked before it is
written (`REENCODE_VERIFY_FAILED` otherwise).

Exit codes: `0` success, `1` decode error, `2` usage or I/O error.

```console
$ echo '10 fe ff ff ff ff ff ff ff ff 01' | bytepeel
{"codec":"hex",…,"child":{"codec":"protobuf",…,"fields":[{"field":2,"wire":"VARINT","range":[0,11],"uint":"18446744073709551614","int":"-2","sint":"9223372036854775807"}]}}

$ echo 1a03089601 | bytepeel --get 3.1 --format raw | xxd
00000000: 9601

$ bytepeel cert.pem --get 0.0.4 --format tree        # X.509 validity
SEQUENCE [124..156]
  UTCTime [126..141] 2020-09-04T00:00:00Z
  UTCTime [141..156] 2040-09-17T16:00:00Z

$ bytepeel record.cbor --get tags.1 --format raw     # a CBOR map value
b

$ echo "$TOKEN" | bytepeel --get payload.sub --format raw   # a JWT claim
1234567890
```

See [docs/DESIGN.md](docs/DESIGN.md) for the full JSON schema, heuristics,
error codes and roadmap.

## MCP server

`bytepeel mcp` runs a [Model Context Protocol](https://modelcontextprotocol.io)
server on stdio, so an agent can call bytepeel as a tool. It's built into the
same binary and needs no runtime. For example, in Claude Code:

```sh
claude mcp add bytepeel -- bytepeel mcp
```

It offers two tools:

- **`peel`** decodes `input` (text) or `file` (a path), with optional `get`,
  `format` (`json`, `tree`, or `raw`, which returns the payload as hex) and
  the CLI's options (`in`, `as`, `depth`, `alts`, `max_items`).
- **`set`** applies `edits` (`[{"op":"set","path":"3.1","value":300}]`; `op`
  can also be `add` or `del`) and returns the re-encoded data. Text comes back
  as text and binary data as hex. Pass `output_file` to write the result
  instead; an existing file is replaced only with `overwrite: true`.

Errors come back as tool results with `isError: true` and the same
`{"error":{...}}` JSON the CLI prints.

## JavaScript / WebAssembly

`npm/` is a WebAssembly build with a small JS wrapper (Node, Deno, Bun,
browsers; no dependencies):

```js
import { load } from "bytepeel";
const bp = await load();
bp.get(pem, "0.0.5.2.0.1").value;    // "ISRG Root X2"
bp.edit(hex, [{ set: "3.1", value: 300000 }]);
```

See [npm/README.md](npm/README.md).

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release      # target/release/bytepeel
cd npm && npm run build && npm test   # WebAssembly build and JS tests
```

## License

MIT
