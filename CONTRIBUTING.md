# Contributing to zeus-core

Thank you for helping. Zeus is pre-alpha; the most valuable contributions right now are review of the contracts, tests, and focused implementations of the crates and functions that are still API-only (they return `NotImplemented`; `git grep NotImplemented` lists them).

## Ground rules

- **Developer Certificate of Origin.** Every commit needs a sign-off (`git commit -s`), which adds `Signed-off-by: Your Name <you@example.com>` and certifies the statement at <https://developercertificate.org/>. There is no CLA.
- **Contracts first.** Behaviour that crosses a process boundary or is stored is specified in the `zeus` repository (`docs/spec`). If code and spec disagree, the prose of the spec wins; fix the spec in the same pull request when the spec is wrong, and say so in the description. Wire types change only together with the schemas (`spec-fixtures/` is a copy: refresh it with `node scripts/sync-spec-fixtures.mjs`).
- **Security-sensitive changes** (anything touching sessions, redaction, paths, framing, the journal or the audit log) need a test that fails without the change and a note on which invariant it protects.
- **No telemetry, no cookie-database access, no evasion features.** These are project invariants; CI greps for the forbidden patterns.
- **No `todo!()` or `unimplemented!()`.** A body that is not written yet returns the crate's typed `NotImplemented` error. Skeleton modules carry `#![expect(unused_variables, ...)]`, which turns into a lint warning (an error under `-D warnings`) as soon as the module is complete, so the marker removes itself.
- Be kind. See the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

Clone the repositories **side by side** if you work on the application too:

```
zeus-workspace/
  zeus/              the application (depends on this repository by path)
  zeus-core/         this repository
  zeus-extension/    the browser extension
```

Requirements: Rust stable (MSRV **1.90**: `redb` 4.x needs it), Node 22 for `scripts/sync-spec-fixtures.mjs`, and optionally `cargo-deny` (`cargo install cargo-deny`).

### Checks to run before opening a pull request

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p zeus-types --example gen_schemas && git diff --exit-code schemas
cargo deny check
```

### Small machines

Builds are heavy. Use `CARGO_BUILD_JOBS=3`, a shared target directory outside the repository (`CARGO_TARGET_DIR`), and run one cargo command at a time. The dev and test profiles use `debug = "line-tables-only"` to keep build output small.

### Windows without MSVC

The default Windows Rust toolchain (`x86_64-pc-windows-msvc`) needs the Visual Studio Build Tools **and a Windows SDK** to link; without them even `cargo new hello && cargo build` fails with `linker link.exe not found`. If you cannot install them, use the GNU toolchain, which links with its bundled MinGW and needs no SDK (a `gcc` on `PATH`, for example from MSYS2, is only needed by crates that compile C such as `blake3` and `aws-lc-sys`):

```powershell
rustup toolchain install stable-x86_64-pc-windows-gnu
$env:RUSTUP_TOOLCHAIN = 'stable-x86_64-pc-windows-gnu'   # per shell; does not change your rustup default
cargo test --workspace
```

Use `RUSTUP_TOOLCHAIN` per shell rather than `rustup default`, so other projects are unaffected. In Git Bash, run cargo from PowerShell instead: Git's `link.exe` (GNU coreutils) shadows the MSVC linker. CI builds on `windows-latest` with MSVC, so keep platform code behind `cfg` and test on that target when you change it. If a C-heavy dependency fails to build on `windows-gnu`, see "Build notes" in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Style

* `rustfmt` with the repository's `rustfmt.toml`; `clippy` clean with `-D warnings`.
* Public items need doc comments (`missing_docs` is a warning, so an error in CI). Other comments are sparse and explain *why*, never narrate.
* Libraries use `thiserror`; binaries use `anyhow`. Logging is `tracing` with structured fields, and URLs go through `redact_url(.., Log)`.
* Time and randomness are injected (`zeus_control::Clock`, `RandomSource`); do not call `SystemTime::now()` or a global RNG from engine code.
* Tests are hermetic: local servers on `127.0.0.1:0` only, no real network.
