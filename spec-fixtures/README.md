# spec-fixtures

A verbatim copy of the normative JSON Schemas and every validated example of the Zeus specification (the `zeus` repository, `docs/spec`), so the conformance tests of this repository need no access to the other one.

* `schema/`: every `*.schema.json`, `job-state-machine.v1.json` and `redaction-vectors.v1.json`.
* `examples/`: one file per `validate=` block of the markdown documents, named `<doc number>-L<line>.<json|jsonl>`, and `index.json` listing the schema, the definition and the source document of each.

Do not edit these files by hand. Refresh them with:

```sh
node scripts/sync-spec-fixtures.mjs ../zeus          # copy
node scripts/sync-spec-fixtures.mjs --check ../zeus  # fail if stale (CI)
```

Tests read them through `zeus_types::spec_testing` (cargo feature `spec-testing`).
