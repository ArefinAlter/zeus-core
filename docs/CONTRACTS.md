# Contracts

The normative specifications for Zeus live in the **`zeus` repository** under `docs/spec` (markdown) and `docs/spec/schema` (JSON Schema 2020-12). They win over this repository's prose. This file maps each document to the code that implements it and to the tests that prove it.

| Spec | Subject | Implemented by | Conformance tests |
|---|---|---|---|
| `00-conventions.md` | Naming, versioning, ids, instants, units, canonical JSON, redaction, error envelope, limits | `zeus-types` (`ids`, `timestamp`, `units`, `origin`, `redact`, `secret`, `error`, `limits`), `zeus-verify::canonical` | `zeus-types/tests/spec_conformance.rs` (examples, redaction vectors), `zeus-verify` JCS vector tests |
| `01-domain-model.md` | Job, spec, probe, grants, approvals, **state machine**, error classes, retry policy, events | `zeus-types` (`job`, `grant`, `state`, `event`, `policy`, `segment`) | state machine conformance against `job-state-machine.v1.json`, property tests with an independent oracle, every domain example round-tripped through the strict schema |
| `02-native-messaging-v1.md` | Extension to daemon protocol: framing, handshake, every message, flow control | `zeus-session` (`protocol`, `codec`, `negotiate`, `flow`, `material`) | `zeus-session/tests/spec_conformance.rs`: every message example round-tripped through the strict schema, catalogue equals the schema's unions, interrupt reasons equal the schema enum |
| `03-journal-and-commit-protocol.md` | Records, commit protocol, resume validation, finalization, recovery, invariants I1 to I12 | `zeus-journal` (records, traits, policy, faults), `zeus-fs` (`Filesystem`, finalize decision), `zeus-control::RangeSet` | `zeus-journal/tests/spec_conformance.rs` (record shapes), range-set property tests (I4); crash-point simulation is the implementation task's deliverable |
| `04-audit-log-and-provenance.md` | Hash-chained audit log, provenance manifest, OS metadata | `zeus-verify` (`audit`, `provenance`), `zeus-fs::provenance` | `zeus-verify/tests/spec_vectors.rs`: the published 11-record chain verifies, every tamper is detected, the manifest example parses |
| `05` to `12` | Daemon API, MCP tools, approvals, workflow plan, LLM ladder, A2A, CLI, security invariants | the `zeus` repository (`zeus-api`, `zeus-mcp`, ...) | there |

## Fixtures

`spec-fixtures/` is a verbatim copy, made by `node scripts/sync-spec-fixtures.mjs [path-to-zeus]`, of:

* `schema/`: every JSON Schema of the specification, plus the machine-readable state machine and the redaction vectors;
* `examples/`: every `validate=` example block of the markdown documents, with `examples/index.json` listing schema, definition and source line.

CI compares the copy with the `zeus` repository (`--check`). When the specification changes, refresh the copy and let the conformance tests tell you what to fix.

## How a crate proves conformance

`zeus_types::spec_testing` (cargo feature `spec-testing`, for `[dev-dependencies]` only) gives every crate the same check in one line:

```rust
let schemas = zeus_types::spec_testing::SpecSchemas::load();
zeus_types::spec_testing::assert_examples_round_trip::<MyWireType>(&schemas, "domain", "Job");
```

For every example of that definition it checks that the example validates, deserialises, re-serialises to something the **strict** schema accepts (no undeclared property, the same check the specification's own validator makes) and equals the original up to `null` versus absent.

## Contract notes found while implementing

* `00 section 8.2` calls `redact_url` idempotent. It is idempotent modulo percent-encoding of the `…` marker: the WHATWG parser encodes it as `%E2%80%A6` on a second pass, in the reference implementation as well. The conformance test compares modulo that encoding.
* `01 section 3.7` defines `eta_s` as `(bytes_total - bytes_done) / rate_ewma`; the specification example (43 s for 677,432,524 bytes at 15,728,640 B/s) uses integer division, which `Progress::compute_eta_s` follows.
* The table of causes in `01 section 7.1` does not say which cause a transient disk error uses on S71 and S72; `zeus-types::state::TRANSITIONS` allows `error` there as well as `integrity_restart` and `integrity_failed`.
* `03 section 12.3` names a `zeus-testkit` crate (`SimFs`, `SimJournal`). It is not part of this workspace yet; the traits it needs (`Filesystem`, `JournalStore`) and the fault injector are defined.
* `redb 4.x` needs rustc 1.90 (4.3.0 declares `rust-version = 1.90`), so the workspace MSRV is 1.90, not 1.88.
