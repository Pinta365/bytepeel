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
- **Zero-dependency core** (`bytepeel-core`) and a single static binary.

## Supported today

| Layer | Notes |
|---|---|
| hex | whitespace, `:` and `0x` separators |
| hex dumps | `xxd` (any `-g`) and `hexdump -C` (with `*` repeats); the ASCII column is ignored |
| base64 | standard and URL-safe alphabets, padded and unpadded, line-wrapped |
| PEM | any label; RFC 1421 headers skipped |
| protobuf | schemaless; groups, negative varints, fixed32/64 as int and float |
| DER / ASN.1 | X.509, PKCS, CMS; ~85 named OIDs, ISO times, any-width integers, DER nested in BIT/OCTET STRINGs decoded in place |
| utf8 / bytes | leaves |
| gzip, zstd, zlib, PNG, zip | recognized by magic bytes; decoders on the roadmap |

## Usage

```
bytepeel [OPTIONS] [FILE]            # stdin when FILE is omitted or '-'

--in <auto|hex|base64|raw>           how to read the input (default: auto)
--as <protobuf|der|text|bytes>       force interpretation of the decoded bytes
--depth <N>                          max nesting (default 16)
--alts <N>                           interpretations kept per LEN field (default 3)
--get <PATH>                         protobuf: field numbers, e.g. 1.3[2].4
                                     DER: 0-based child indices, e.g. 0.0.6
--format <json|tree|raw>             raw writes a --get selection's payload bytes
```

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
```

See [docs/DESIGN.md](docs/DESIGN.md) for the full JSON schema, heuristics,
error codes and roadmap.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release      # target/release/bytepeel
```

## License

MIT
