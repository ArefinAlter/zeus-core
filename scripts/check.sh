#!/usr/bin/env sh
# Runs the Rust checks in the order CI does. One cargo command at a time: this machine class is small.
set -eu
: "${CARGO_BUILD_JOBS:=3}"
export CARGO_BUILD_JOBS
cd "$(dirname "$0")/.."
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p zeus-types --example gen_schemas
git diff --exit-code -- schemas
if command -v cargo-deny >/dev/null 2>&1; then cargo deny check; fi
