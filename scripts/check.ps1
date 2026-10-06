# Runs the Rust checks in the order CI does. One cargo command at a time: this machine class is small.
# On Windows without the MSVC build tools set RUSTUP_TOOLCHAIN to a GNU toolchain first (see CONTRIBUTING.md).
$ErrorActionPreference = 'Stop'
if (-not $env:CARGO_BUILD_JOBS) { $env:CARGO_BUILD_JOBS = '3' }
Set-Location (Join-Path $PSScriptRoot '..')
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p zeus-types --example gen_schemas
git diff --exit-code -- schemas
if (Get-Command cargo-deny -ErrorAction SilentlyContinue) { cargo deny check }
