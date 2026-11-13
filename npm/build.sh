#!/bin/sh
# Build bytepeel.wasm from the workspace (needs the wasm32-unknown-unknown target).
set -eu
cd "$(dirname "$0")/.."
cargo build --profile wasm --target wasm32-unknown-unknown -p bytepeel-wasm
cp target/wasm32-unknown-unknown/wasm/bytepeel_wasm.wasm npm/bytepeel.wasm
cp LICENSE npm/LICENSE
ls -l npm/bytepeel.wasm
