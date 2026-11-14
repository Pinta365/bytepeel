# bytepeel

A recursive decoder for encoded and binary data, built for AI agents. It's a
Cargo workspace:

- `crates/bytepeel-core`: the library. It **must stay zero-dependency** (any
  future codec dependency goes behind an optional feature).
- `crates/bytepeel`: a thin CLI with hand-rolled argument parsing (no clap).
- `crates/bytepeel-wasm`: the WebAssembly build (minimal C ABI, no
  wasm-bindgen); `npm/` wraps it for JavaScript.
- `plugins/bytepeel`: the Claude Code plugin (agent skill + MCP config);
  `.claude-plugin/marketplace.json` makes the repo its marketplace. Keep the
  skill in step with the CLI's flags, paths and error codes.

## Rules

- The JSON output schema in `docs/DESIGN.md` is the public contract. Update the
  doc in the same change as the code.
- Output must stay deterministic and valid JSON. `json_is_valid_and_deterministic`
  in `tests/corpus.rs` checks this. Add new sample inputs to it.
- Every heuristic or threshold change needs a corpus test for the case that
  motivated it.
- Error codes are stable SCREAMING_SNAKE identifiers. Never rename one; only add.
- 64-bit integers are emitted as JSON strings.

## Commands

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cd npm && npm run build && npm test     # needs the wasm32-unknown-unknown target
```
