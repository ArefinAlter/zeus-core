# zeus-core

**The embeddable engine behind [Zeus](https://github.com/ArefinAlter/zeus), the session-aware download and file layer for AI agents.**

`zeus-core` is a Rust workspace of libraries: wire and domain types, pure control algorithms, file-system correctness primitives, integrity and provenance, the durable transfer journal, the native-messaging session protocol, the HTTP layer and the orchestrating engine. It has no daemon, no MCP server and no UI; the [`zeus`](https://github.com/ArefinAlter/zeus) repository builds those on top.

> **Status: pre-alpha.** `zeus-types` is complete and conformance-tested against the specification. `zeus-control` has a working clock, randomness, range set and backoff; the remaining crates define their final public API (traits, types, signatures) and return a typed `NotImplemented` error where the body is still to be written. Nothing here is ready to use and there is no release. Expect breaking changes everywhere. The [status table](docs/ARCHITECTURE.md#status) says exactly what is real.

## Crate map

| Crate | Responsibility | State |
|---|---|---|
| [`zeus-types`](crates/zeus-types) | Identifiers, instants, origins and URLs with redaction, the job entity and its table-driven state machine, error classes and the code registry, grants and approvals, the event catalogue, retry and scheduling constants, JSON Schema generation | **Implemented** and conformance-tested against the specification |
| [`zeus-control`](crates/zeus-control) | Pure algorithms with injectable `Clock` and `RandomSource`: range sets, backoff with jitter, estimators, AIMD, bandits, segment planning, hedging, rate limiters, fairness | `Clock`, randomness, `RangeSet`, `Backoff`, `Ewma` implemented; the rest API-only |
| [`zeus-fs`](crates/zeus-fs) | Safe write roots, file-name sanitising, the `Filesystem`/`DataFile` seam of the commit protocol, atomic finalize, OS provenance marks, application trash, cloud-folder detection | API plus I/O error classification, crash decision procedure, Zone.Identifier text |
| [`zeus-verify`](crates/zeus-verify) | SHA-256 + BLAKE3 hashing, content sniffing, quarantine rules, archive limits, RFC 8785 canonical JSON, the hash-chained audit log, the provenance manifest | Hashing, JCS, chain verification (against the published vectors) and an in-memory log implemented; file-backed log and manifest writer API-only |
| [`zeus-journal`](crates/zeus-journal) | The durable journal: records, the backend-neutral store traits, group-commit policy, crash-point injection, recovery, the redb backend | Records, traits, policy and faults implemented; redb store and recovery API-only |
| [`zeus-session`](crates/zeus-session) | Native-messaging v1 as typed Rust (every message), the frame codec, negotiation, credit flow control, session material, consent and provider traits | Protocol, codec, negotiation and flow control implemented and conformance-tested; consent store, correlator and providers API-only |
| [`zeus-http`](crates/zeus-http) | The transport abstraction, header parsers, error classification, the prober and the segment fetcher, a reqwest/rustls transport | Parsers and transport classification implemented; prober, fetcher and `send` API-only |
| [`zeus-engine`](crates/zeus-engine) | `Engine` and `EngineBuilder`: enqueue, probe, control, subscribe, approvals port, grant changes | API-only |

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
* URLs reach any log, event or record only through `redact_url`; raw URLs live in the journal job record and nowhere else.
* Only the daemon mints identifiers; only a human on a trust surface decides an approval.
* No telemetry and no network access except what a job explicitly causes.
* `unsafe` is denied crate-wide; `zeus-fs` will confine platform FFI to one commented module.

## Licence

Apache-2.0. Copyright 2026 Zeus contributors. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions are accepted under the Developer Certificate of Origin; see [CONTRIBUTING.md](CONTRIBUTING.md).
