# zeus-core

**The embeddable engine behind [Zeus](https://github.com/ArefinAlter/zeus), the session-aware download and file layer for AI agents.**

`zeus-core` is a Rust workspace of libraries: wire and domain types, pure control algorithms, file-system correctness primitives, integrity and provenance, the durable transfer journal, the native-messaging session protocol, the HTTP layer and the orchestrating engine. It has no daemon, no MCP server and no UI; the [`zeus`](https://github.com/ArefinAlter/zeus) repository builds those on top.

> **Status: pre-alpha implementation.** Direct HTTP downloads, durable bounded retries, journal recovery, verification, finalization, approvals and browser-proxy transport now have executable implementations and hermetic tests. This is not a completed roadmap release: URL-refresh recovery, adaptive scheduling and several control algorithms remain unfinished. Platform and real-browser acceptance still need validation. The [status table](docs/ARCHITECTURE.md#status) lists these boundaries.

## Crate map

| Crate | Responsibility | State |
|---|---|---|
| [`zeus-types`](crates/zeus-types) | Identifiers, instants, origins and URLs with redaction, the job entity and its table-driven state machine, error classes and the code registry, grants and approvals, the event catalogue, retry and scheduling constants, JSON Schema generation | **Implemented** and conformance-tested against the specification |
| [`zeus-control`](crates/zeus-control) | Pure algorithms with injectable clocks and randomness | Ranges, backoff, EWMA, AIMD, segment planning, rate limiters and fairness helpers implemented; advanced estimators, mirror selection and hedging remain unfinished |
| [`zeus-fs`](crates/zeus-fs) | Write roots, filenames, positional I/O, finalization, provenance marks and trash | Real implementations; directory-swap resistance and platform acceptance remain work |
| [`zeus-verify`](crates/zeus-verify) | File hashing, content checks, canonical JSON, durable audit and manifests | Implemented, including redacted exports; complete repair/retention workflows remain work |
| [`zeus-journal`](crates/zeus-journal) | Durable commits, transitions, recovery and resume validation | redb persistence, CRC commits, recovery, approval/grant records and durable kill-switch latch implemented |
| [`zeus-session`](crates/zeus-session) | Native protocol, framing, consent, correlation, cookies and browser-provider traits | Consent store, correlation and scoped cookie headers implemented; the daemon supplies browser providers |
| [`zeus-http`](crates/zeus-http) | Transport, probing, segmented requests and response classification | Actual reqwest transport, bounded reads, strict validators and explicit redirect handling implemented |
| [`zeus-engine`](crates/zeus-engine) | Scheduling and job execution behind the public facade | Downloads, pause/resume/cancel, durable control receipts, bounded retries, verification, events, sessions and proxy implemented; URL-refresh recovery and adaptive scheduling remain |
| [`zeus-artifact`](crates/zeus-artifact) | Shared content-addressed storage and metadata | Ingest, record-only registration, materialization, exports, collection, scrub and repair implemented; daemon outbox owns registration order |


## Quickstart

```sh
git clone https://github.com/ArefinAlter/zeus-core.git
cd zeus-core
cargo test --workspace
cargo run -p zeus-types --example gen_schemas   # regenerates schemas/zeus-types.schema.json
```

Requirements: Rust stable (MSRV **1.90**, declared in `Cargo.toml`). On Windows without the MSVC build tools, see [Windows without MSVC](CONTRIBUTING.md#windows-without-msvc).

## Contracts

The normative specifications live in the `zeus` repository (`docs/spec`). This repository keeps a verbatim copy of the JSON Schemas and every validated example in [`spec-fixtures/`](spec-fixtures) so its conformance tests run without the other repository; `node scripts/sync-spec-fixtures.mjs` refreshes it. See [`docs/CONTRACTS.md`](docs/CONTRACTS.md) for which spec each crate implements and which tests prove it.

## Design rules that hold everywhere

* Session material is secret: zeroising wrappers, `[REDACTED]` in `Debug`, never in logs, events, audit records or errors (00 section 8).
* URLs reach any log, event or record only through `redact_url`; raw URLs remain in private job state and explicit request paths.
* Only the daemon mints identifiers; only a human on a trust surface decides an approval.
* No telemetry and no network access except what a job explicitly causes.
* `unsafe` is denied crate-wide; `zeus-fs` will confine platform FFI to one commented module.

## Licence

Apache-2.0. Copyright 2026 Zeus contributors. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions are accepted under the Developer Certificate of Origin; see [CONTRIBUTING.md](CONTRIBUTING.md).
