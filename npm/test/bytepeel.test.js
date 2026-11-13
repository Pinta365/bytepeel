import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { load, raw, BytepeelError } from "../index.js";

const bp = await load();
const cert = await readFile(new URL("./isrg-root-x2.pem", import.meta.url), "utf8");
const text = (b) => new TextDecoder().decode(b);

test("peel: layered base64 -> protobuf -> base64 -> text", () => {
  const n = bp.peel("ChRTR1ZzYkc4c0lIZHZjbXhrSVNFPRAq");
  assert.equal(n.codec, "base64");
  assert.equal(n.child.codec, "protobuf");
  const f1 = n.child.fields[0];
  assert.equal(f1.alts[0].decoded.child.text, "Hello, world!!");
  // 64-bit integers are strings, so JS never loses precision.
  const big = bp.peel("10 fe ff ff ff ff ff ff ff ff 01");
  assert.equal(big.child.fields[0].uint, "18446744073709551614");
});

test("peel accepts bytes and options", () => {
  const n = bp.peel(new Uint8Array([0x08, 0x96, 0x01]), { in: "raw" });
  assert.equal(n.codec, "protobuf");
  assert.equal(bp.peel("0a03666f6f", { as: "bytes" }).child.codec, "bytes");
  assert.throws(() => bp.peel("x", { bogus: 1 }), TypeError);
});

test("tree", () => {
  assert.match(bp.tree("1a03089601"), /#3 LEN \[0\.\.5\]/);
});

test("get and getRaw dispatch by codec", () => {
  assert.equal(bp.get("1a03089601", "3.1").uint, "150");
  assert.deepEqual([...bp.getRaw("1a03089601", "3.1")], [0x96, 0x01]);
  const cn = bp.get(cert, "0.0.5.2.0.1");
  assert.equal(cn.value, "ISRG Root X2");
  assert.equal(bp.get("a1 61 61 82 01 02", "a.1").value, "2");
});

test("errors carry stable codes", () => {
  assert.throws(() => bp.get("089601", "9"), (e) => {
    assert.ok(e instanceof BytepeelError);
    assert.equal(e.code, "PATH_NOT_FOUND");
    return true;
  });
  assert.throws(() => bp.peel("zz", { in: "hex" }), (e) => e.code === "INVALID_CHAR" && e.offset === 0);
});

test("edit: typed values, add and delete, style preserved", () => {
  assert.equal(text(bp.edit("08 96 01 12 03 66 6f 6f\n", [{ set: "1", value: 300 }])), "08 ac 02 12 03 66 6f 6f\n");
  // Strings are text, never parsed as numbers.
  assert.equal(text(bp.edit("0a03666f6f", [{ set: "1", value: "42" }])), "0a023432");
  assert.equal(text(bp.edit("0801", [{ set: "1", value: raw("sint:-2") }])), "0803");
  assert.equal(text(bp.edit("0801", [{ set: "1", value: 18446744073709551615n }])), "08ffffffffffffffffff01");
  assert.equal(
    text(bp.edit("08 96 01 12 03 66 6f 6f", [{ add: "3", value: 42 }, { del: "2" }])),
    "08 96 01 18 2a",
  );
  // CBOR with JS types, including null and bytes.
  const out = bp.edit("a1 61 61 82 01 02", [
    { add: "b", value: true },
    { set: "a.0", value: null },
    { add: "c", value: new Uint8Array([0xff]) },
  ]);
  assert.equal(text(out), "a3 61 61 82 f6 02 61 62 f5 61 63 41 ff");
  assert.throws(() => bp.edit("0801", [{ set: "1", value: 2 ** 60 }]), RangeError);
});

test("edit a certificate through PEM", () => {
  const out = text(bp.edit(cert, [{ set: "0.0.5.2.0.1", value: "Test Root" }]));
  assert.ok(out.startsWith("-----BEGIN CERTIFICATE-----\n"));
  assert.equal(bp.get(out, "0.0.5.2.0.1").value, "Test Root");
  // Unchanged values reproduce the input exactly.
  assert.equal(text(bp.edit(cert, [{ set: "0.0.5.2.0.1", value: "ISRG Root X2" }])), cert);
});

test("memory does not leak across many calls", () => {
  for (let i = 0; i < 5000; i++) bp.peel(cert);
  const big = "aa".repeat(1 << 20); // 1 MiB of hex: forces memory growth
  assert.equal(bp.peel(big).decoded_len, 1 << 20);
  assert.equal(bp.get("1a03089601", "3.1").uint, "150");
});

test("load from bytes or a compiled module", async () => {
  const bytes = await readFile(new URL("../bytepeel.wasm", import.meta.url));
  const a = await load(bytes);
  const b = await load(await WebAssembly.compile(bytes));
  assert.equal(a.get("089601", "1").uint, "150");
  assert.equal(b.get("089601", "1").uint, "150");
});
