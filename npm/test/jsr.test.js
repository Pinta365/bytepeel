// The JSR entry point (mod.js) loads the embedded module.
import { test } from "node:test";
import assert from "node:assert/strict";
import { load, raw, BytepeelError } from "../mod.js";

test("mod.js loads the embedded wasm", async () => {
  const bp = await load();
  assert.equal(bp.get("1a03089601", "3.1").uint, "150");
  const out = bp.edit("089601", [{ set: "1", value: 300 }]);
  assert.equal(new TextDecoder().decode(out), "08ac02");
  assert.equal(typeof raw, "function");
  assert.equal(typeof BytepeelError, "function");
});
