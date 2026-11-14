// Builds the npm platform packages (bytepeel-linux-x64, ...) that carry the
// native CLI for `npx bytepeel`. Each one is generated into npm/platforms/.
//
//   node platforms.mjs --release v0.1.1    # from that GitHub release's archives
//   node platforms.mjs --local             # this machine's target/release build
//
// The version is npm/package.json's; for --release it must match the tag.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const pkg = JSON.parse(readFileSync(join(here, "package.json"), "utf8"));

// Rust target -> npm platform package (os, cpu as npm spells them).
const TARGETS = {
  "x86_64-unknown-linux-musl": ["linux", "x64"],
  "aarch64-unknown-linux-musl": ["linux", "arm64"],
  "x86_64-apple-darwin": ["darwin", "x64"],
  "aarch64-apple-darwin": ["darwin", "arm64"],
  "x86_64-pc-windows-msvc": ["win32", "x64"],
};

const names = Object.values(TARGETS).map(([os, cpu]) => `bytepeel-${os}-${cpu}`);
const declared = Object.keys(pkg.optionalDependencies ?? {}).sort();
if (JSON.stringify(declared) !== JSON.stringify([...names].sort())) {
  die(`package.json optionalDependencies must be exactly: ${names.join(", ")}`);
}
for (const [name, v] of Object.entries(pkg.optionalDependencies)) {
  if (v !== pkg.version) die(`optionalDependencies.${name} is ${v}, expected ${pkg.version}`);
}

const out = join(here, "platforms");
rmSync(out, { recursive: true, force: true });
mkdirSync(out);

const mode = process.argv[2];
if (mode === "--release") {
  const tag = process.argv[3];
  if (tag !== `v${pkg.version}`) die(`tag ${tag} does not match package.json version ${pkg.version}`);
  const dl = mkdtempSync(join(tmpdir(), "bytepeel-release-"));
  execFileSync("gh", ["release", "download", tag, "-R", "Pinta365/bytepeel", "-D", dl], { stdio: "inherit" });
  const sums = new Map(
    readFileSync(join(dl, "SHA256SUMS"), "utf8").trim().split("\n").map((l) => {
      const [hash, file] = l.trim().split(/\s+\*?/);
      return [file, hash];
    }),
  );
  for (const [target, [os, cpu]] of Object.entries(TARGETS)) {
    const base = `bytepeel-${tag}-${target}`;
    const archive = `${base}.${os === "win32" ? "zip" : "tar.gz"}`;
    const hash = createHash("sha256").update(readFileSync(join(dl, archive))).digest("hex");
    if (sums.get(archive) !== hash) die(`checksum mismatch for ${archive}`);
    const x = join(dl, target);
    mkdirSync(x);
    if (os === "win32") execFileSync("unzip", ["-q", join(dl, archive), "-d", x]);
    else execFileSync("tar", ["xzf", join(dl, archive), "-C", x]);
    const exe = os === "win32" ? "bytepeel.exe" : "bytepeel";
    write(os, cpu, join(x, base, exe));
  }
  rmSync(dl, { recursive: true, force: true });
} else if (mode === "--local") {
  const os = process.platform;
  const cpu = process.arch;
  if (!names.includes(`bytepeel-${os}-${cpu}`)) die(`no platform package for ${os}-${cpu}`);
  const exe = os === "win32" ? "bytepeel.exe" : "bytepeel";
  write(os, cpu, join(root, "target", "release", exe));
} else {
  die("usage: node platforms.mjs --release vX.Y.Z | --local");
}
console.log(readdirSync(out).map((d) => `npm/platforms/${d}`).join("\n"));

function write(os, cpu, binary) {
  const name = `bytepeel-${os}-${cpu}`;
  const dir = join(out, name);
  const exe = os === "win32" ? "bytepeel.exe" : "bytepeel";
  mkdirSync(join(dir, "bin"), { recursive: true });
  copyFileSync(binary, join(dir, "bin", exe));
  chmodSync(join(dir, "bin", exe), 0o755);
  copyFileSync(join(root, "LICENSE"), join(dir, "LICENSE"));
  writeFileSync(
    join(dir, "README.md"),
    `# ${name}\n\nThe native \`bytepeel\` CLI for ${os} ${cpu}. Install [bytepeel](https://www.npmjs.com/package/bytepeel) instead: it picks this package automatically.\n`,
  );
  const meta = {
    name,
    version: pkg.version,
    description: `The bytepeel CLI binary for ${os} ${cpu} (used by the bytepeel package).`,
    license: pkg.license,
    author: pkg.author,
    repository: pkg.repository,
    homepage: pkg.homepage,
    os: [os],
    cpu: [cpu],
    files: [`bin/${exe}`, "README.md", "LICENSE"],
    preferUnplugged: true,
  };
  writeFileSync(join(dir, "package.json"), JSON.stringify(meta, null, 2) + "\n");
}

function die(msg) {
  console.error(`platforms.mjs: ${msg}`);
  process.exit(1);
}
