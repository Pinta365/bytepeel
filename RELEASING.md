# Releasing

Publishing is manual. Run every step from a clean `main`.

## 1. Prepare

1. Set the version in all three places: `Cargo.toml` (`workspace.package`),
   `npm/package.json` and `npm/deno.json`. The `bytepeel-core` dependency in
   `crates/bytepeel/Cargo.toml` and `crates/bytepeel-wasm/Cargo.toml` also
   names the version.
2. Move the `CHANGELOG.md` entry from "unreleased" to the release date.
3. Check everything:

   ```sh
   cargo fmt --all --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   cargo +1.87 test --workspace                 # the declared rust-version
   cargo package --workspace --exclude bytepeel-wasm
   (cd npm && npm run build && npm test && npm pack --dry-run)
   (cd npm && deno test test/jsr.test.js && deno publish --dry-run)
   ```

4. Commit, then tag: `git tag v0.1.0`.

## 2. Publish

1. Push the tag: `git push origin main v0.1.0`. The release workflow builds
   the binaries and attaches them to a draft GitHub release. Check the
   archives, then publish the release.
2. crates.io, library first:

   ```sh
   cargo publish -p bytepeel-core
   cargo publish -p bytepeel
   ```

3. npm: remove `"private": true` from `npm/package.json` (keep it off from
   then on), then `cd npm && npm run build && npm publish`.
4. JSR: `cd npm && deno publish` (the `@pinta365` scope).

A published version can't be replaced on any of the three registries; a
mistake needs a new version.
