// The `bytepeel` command (bin/bytepeel.js): its platform table matches the
// optional dependencies, and it runs a native binary transparently.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const npm = new URL("../", import.meta.url);
const pkg = JSON.parse(readFileSync(new URL("package.json", npm), "utf8"));
const launcher = fileURLToPath(new URL("bin/bytepeel.js", npm));

test("platform packages match the launcher and the version", () => {
  const src = readFileSync(launcher, "utf8");
  const table = [...src.matchAll(/"[a-z0-9]+-[a-z0-9]+": "(bytepeel-[a-z0-9-]+)"/g)].map((m) => m[1]);
  assert.deepEqual(table.sort(), Object.keys(pkg.optionalDependencies).sort());
  for (const v of Object.values(pkg.optionalDependencies)) assert.equal(v, pkg.version);
  assert.equal(pkg.bin.bytepeel, "bin/bytepeel.js");
  assert.ok(pkg.files.includes("bin/bytepeel.js"));
});

test("the MCP Registry entry matches the package", () => {
  const server = JSON.parse(readFileSync(new URL("../server.json", npm), "utf8"));
  assert.equal(server.name, pkg.mcpName);
  assert.equal(server.version, pkg.version);
  assert.equal(server.packages[0].identifier, pkg.name);
  assert.equal(server.packages[0].version, pkg.version);
  assert.ok(server.description.length <= 100);
});

// A native build from `cargo build`, if there is one.
const exe = process.platform === "win32" ? "bytepeel.exe" : "bytepeel";
const native = ["release", "debug"]
  .map((p) => fileURLToPath(new URL(`../target/${p}/${exe}`, npm)))
  .find(existsSync);

test("the launcher passes stdin, stdout, stderr and exit codes through", { skip: !native && "no cargo build" }, () => {
  const run = (args, input) =>
    spawnSync(process.execPath, [launcher, ...args], { input, env: { ...process.env, BYTEPEEL_BINARY: native } });
  const ok = run(["--get", "3.1", "--format", "raw"], "1a03089601");
  assert.equal(ok.status, 0);
  assert.deepEqual([...ok.stdout], [0x96, 0x01]);
  const bad = run(["--get", "9"], "089601");
  assert.equal(bad.status, 1);
  assert.equal(JSON.parse(bad.stderr).error.code, "PATH_NOT_FOUND");
});
