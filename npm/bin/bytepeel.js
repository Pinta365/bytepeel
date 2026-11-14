#!/usr/bin/env node
// The `bytepeel` command: runs the native CLI from the platform package npm
// installed (an optional dependency), so `npx bytepeel ...` and
// `npx -y bytepeel mcp` work without a Rust toolchain.
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

const PLATFORMS = {
  "linux-x64": "bytepeel-linux-x64",
  "linux-arm64": "bytepeel-linux-arm64",
  "darwin-x64": "bytepeel-darwin-x64",
  "darwin-arm64": "bytepeel-darwin-arm64",
  "win32-x64": "bytepeel-win32-x64",
};

function binary() {
  if (process.env.BYTEPEEL_BINARY) return process.env.BYTEPEEL_BINARY;
  const key = `${process.platform}-${process.arch}`;
  const pkg = PLATFORMS[key];
  if (!pkg) {
    fail(`no prebuilt bytepeel binary for ${key}`);
  }
  try {
    const require = createRequire(import.meta.url);
    const dir = dirname(require.resolve(`${pkg}/package.json`));
    return join(dir, "bin", process.platform === "win32" ? "bytepeel.exe" : "bytepeel");
  } catch {
    fail(`the ${pkg} package is not installed (was npm run with --omit=optional?)`);
  }
}

function fail(why) {
  process.stderr.write(
    JSON.stringify({
      error: {
        code: "IO",
        message: `${why}. Install the CLI with 'cargo install bytepeel' or from https://github.com/Pinta365/bytepeel/releases`,
        offset: null,
      },
    }) + "\n",
  );
  process.exit(2);
}

const r = spawnSync(binary(), process.argv.slice(2), { stdio: "inherit" });
if (r.error) fail(`could not run bytepeel: ${r.error.message}`);
if (r.signal) process.kill(process.pid, r.signal);
process.exit(r.status ?? 1);
