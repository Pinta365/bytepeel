# bytepeel (WebAssembly)

Peel layers of encoding off binary data, and edit it in place, from
JavaScript: hex, xxd/hexdump dumps, base64, PEM (incl. bundles), JWT,
gzip/zlib/zstd, DER/ASN.1, CBOR, MessagePack and schemaless protobuf.

One `bytepeel.wasm` with no imports and no JS dependencies; runs in Node
(≥18), Deno, Bun and browsers.

```js
import { load, raw, BytepeelError } from "bytepeel";

const bp = await load();

bp.peel("ChRTR1ZzYkc4c0lIZHZjbXhrSVNFPRAq");   // the decoded tree (object)
bp.tree("1a03089601");                          // the text outline
bp.get(pem, "0.0.5.2.0.1").value;               // "ISRG Root X2"
bp.getRaw("1a03089601", "3.1");                 // Uint8Array [0x96, 0x01]

// Edits return the data in its original outer format (hex stays hex, PEM
// stays PEM, ...), with every other byte preserved. Each edit is verified.
const out = bp.edit("08 96 01 12 03 66 6f 6f", [
  { add: "3", value: 42 },
  { del: "2" },
]);
new TextDecoder().decode(out);                  // "08 96 01 18 2a"
```

- **Options** (all methods): `{ in: "auto"|"hex"|"base64"|"raw", as:
  "protobuf"|"der"|"cbor"|"msgpack"|"text"|"bytes", depth, alts, max_items }`.
- **Input:** a string (UTF-8) or `Uint8Array`/`ArrayBuffer`/typed array.
- **Values** are typed: a string is text (never parsed, so `"42"` is the
  text `42`); an integer `number` or a `bigint` is an integer; other numbers
  are floats; `true`/`false`/`null`; a `Uint8Array` is bytes. Use
  `raw("sint:-2")`, `raw("float:1")` for the CLI value syntax.
- **64-bit integers are JSON strings** in `peel`/`get` output, so they never
  lose precision.
- **Errors** throw `BytepeelError` with the CLI's stable `code` (e.g.
  `PATH_NOT_FOUND`) and `offset`.
- **Loading:** `load()` reads `bytepeel.wasm` next to `index.js` (file read
  in Node/Deno/Bun, `fetch` over HTTP). Pass the bytes, a URL, a
  `Response`, or a compiled `WebAssembly.Module` to load it yourself.

The JSON schema, paths and edit rules are in
[docs/DESIGN.md](../docs/DESIGN.md).

## Building

```sh
rustup target add wasm32-unknown-unknown
npm run build      # cargo build --profile wasm ... and copies bytepeel.wasm here
npm test           # node --test; also: deno test --allow-read test/, bun test test/
```
