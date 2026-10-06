//! Conformance-test helpers shared by every crate (cargo feature `spec-testing`, intended for
//! `[dev-dependencies]` only).
//!
//! The fixtures under `spec-fixtures/` at the repository root are copies, made by
//! `scripts/sync-spec-fixtures.mjs`, of the normative JSON Schemas and of every validated example in
//! the specification documents (zeus repository, `docs/spec`). With them, a crate proves its wire types
//! agree with the contract in a few lines:
//!
//! ```ignore
//! let schemas = zeus_types::spec_testing::SpecSchemas::load();
//! zeus_types::spec_testing::assert_examples_round_trip::<MyType>(&schemas, "domain", "Job");
//! ```
//!
//! For every example of `<schema>#/$defs/<def>` the helper checks that (1) the example validates against
//! the normative schema, (2) it deserialises into the Rust type, (3) the re-serialised value validates
//! against the *strict* schema (no property the schema does not declare, the same check the spec's own
//! validator makes), and (4) it equals the original up to `null` versus absent.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use jsonschema::{Registry, Resource};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// Base URI of the normative schemas.
pub const SCHEMA_BASE: &str = "https://zeus.invalid/schema/";

/// The `spec-fixtures` directory of this repository.
#[must_use]
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec-fixtures"))
}

/// Reads and parses a JSON fixture relative to `spec-fixtures/` (for example `schema/job-state-machine.v1.json`).
///
/// # Panics
/// Panics with the path when the file is missing or not JSON: a test setup error.
#[must_use]
pub fn read_fixture_json(relative: &str) -> Value {
    let path = fixtures_dir().join(relative);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// One validated example block of the specification.
#[derive(Debug, Clone)]
pub struct Example {
    /// Schema name, for example `domain`.
    pub schema: String,
    /// Definition name inside `$defs`, for example `Job`.
    pub def: String,
    /// Fixture file, relative to `spec-fixtures/`.
    pub file: String,
    /// The documents (one for a `json` block, one per line for `jsonl`).
    pub docs: Vec<Value>,
}

/// Every example in the specification, in document order.
///
/// # Panics
/// Panics when the fixture index is missing: run `node scripts/sync-spec-fixtures.mjs`.
#[must_use]
pub fn examples() -> Vec<Example> {
    let index = read_fixture_json("examples/index.json");
    index
        .as_array()
        .expect("examples/index.json is an array")
        .iter()
        .map(|e| {
            let file = e["file"].as_str().expect("file").to_owned();
            let text = fs::read_to_string(fixtures_dir().join(&file)).expect("example file");
            let docs = if e["kind"] == "jsonl" {
                text.lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(|l| serde_json::from_str(l).expect("jsonl line"))
                    .collect()
            } else {
                vec![serde_json::from_str(&text).expect("json example")]
            };
            Example {
                schema: e["schema"].as_str().expect("schema").to_owned(),
                def: e["def"].as_str().expect("def").to_owned(),
                file,
                docs,
            }
        })
        .collect()
}

/// All documents of the examples for `<schema>#/$defs/<def>`.
#[must_use]
pub fn examples_for(schema: &str, def: &str) -> Vec<Value> {
    examples()
        .into_iter()
        .filter(|e| e.schema == schema && e.def == def)
        .flat_map(|e| e.docs)
        .collect()
}

/// Removes `null` members everywhere: for Zeus wire types "absent" and `null` both mean "not set".
#[must_use]
pub fn strip_nulls(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k.clone(), strip_nulls(v)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(strip_nulls).collect()),
        other => other.clone(),
    }
}

/// The normative schemas, loaded into a plain and a strict registry.
pub struct SpecSchemas {
    plain: Registry<'static>,
    strict: Registry<'static>,
}

impl std::fmt::Debug for SpecSchemas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SpecSchemas")
    }
}

impl SpecSchemas {
    /// Loads every `*.schema.json` of `spec-fixtures/schema`.
    ///
    /// # Panics
    /// Panics when a schema file is unreadable or does not compile: a setup error.
    #[must_use]
    pub fn load() -> Self {
        let mut schemas = Vec::new();
        for entry in fs::read_dir(fixtures_dir().join("schema")).expect("spec-fixtures/schema") {
            let path = entry.expect("dir entry").path();
            if path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().ends_with(".schema.json"))
            {
                schemas.push(
                    serde_json::from_str::<Value>(&fs::read_to_string(&path).expect("schema file"))
                        .expect("schema JSON"),
                );
            }
        }
        let strict = strictify(&schemas);
        Self {
            plain: build_registry(&schemas),
            strict: build_registry(&strict),
        }
    }

    /// Validates `doc` against `<schema>#/$defs/<def>`; with `strict`, additional properties are errors.
    pub fn check(&self, strict: bool, schema: &str, def: &str, doc: &Value) -> Result<(), String> {
        let registry = if strict { &self.strict } else { &self.plain };
        let reference = format!("{SCHEMA_BASE}{schema}#/$defs/{def}");
        let validator = jsonschema::options()
            .with_registry(registry)
            .build(&json!({ "$ref": reference }))
            .map_err(|e| e.to_string())?;
        let errors: Vec<String> = validator
            .iter_errors(doc)
            .map(|e| format!("{e} at {}", e.instance_path()))
            .collect();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

fn build_registry(schemas: &[Value]) -> Registry<'static> {
    let mut registry = Registry::new();
    for s in schemas {
        let id = s["$id"].as_str().expect("$id").to_owned();
        registry = registry
            .add(&id, Resource::from_contents(s.clone()))
            .expect("schema registers");
    }
    registry.prepare().expect("schemas resolve")
}

/// Port of `strictify` in `docs/spec/tools/validate-spec.mjs`: adds `unevaluatedProperties: false` to every
/// object schema that declares `properties`, except `allOf` members and the targets of `allOf` references.
fn strictify(schemas: &[Value]) -> Vec<Value> {
    let mut targets = BTreeSet::new();
    for s in schemas {
        collect_allof_targets(s, s["$id"].as_str().unwrap_or_default(), &mut targets);
    }
    schemas
        .iter()
        .map(|s| {
            let mut clone = s.clone();
            walk_strict(
                &mut clone,
                "",
                false,
                s["$id"].as_str().unwrap_or_default(),
                &targets,
            );
            clone
        })
        .collect()
}

fn collect_allof_targets(node: &Value, id: &str, out: &mut BTreeSet<String>) {
    match node {
        Value::Array(items) => items.iter().for_each(|n| collect_allof_targets(n, id, out)),
        Value::Object(map) => {
            if let Some(Value::Array(members)) = map.get("allOf") {
                for r in members
                    .iter()
                    .filter_map(|m| m.get("$ref").and_then(Value::as_str))
                {
                    out.insert(if r.starts_with('#') {
                        format!("{id}{r}")
                    } else {
                        r.to_owned()
                    });
                }
            }
            map.values().for_each(|v| collect_allof_targets(v, id, out));
        }
        _ => {}
    }
}

fn walk_strict(node: &mut Value, path: &str, in_allof: bool, id: &str, targets: &BTreeSet<String>) {
    match node {
        Value::Array(items) => {
            let is_allof = path.ends_with("/allOf");
            for (i, n) in items.iter_mut().enumerate() {
                walk_strict(n, &format!("{path}/{i}"), is_allof, id, targets);
            }
        }
        Value::Object(map) => {
            let def_name = path
                .strip_prefix("/$defs/")
                .filter(|rest| !rest.contains('/'));
            let skip =
                in_allof || def_name.is_some_and(|d| targets.contains(&format!("{id}#/$defs/{d}")));
            let has_props = map.get("properties").is_some_and(Value::is_object);
            let type_ok = map.get("type").is_none_or(|t| t == "object");
            let allof_without_ref =
                map.get("allOf").is_some_and(Value::is_array) && !map.contains_key("$ref");
            if !skip
                && ((has_props && type_ok) || allof_without_ref)
                && !map.contains_key("unevaluatedProperties")
                && !map.contains_key("additionalProperties")
            {
                map.insert("unevaluatedProperties".into(), Value::Bool(false));
                map.entry("type")
                    .or_insert_with(|| Value::String("object".into()));
            }
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                if matches!(k.as_str(), "enum" | "const" | "default" | "examples") {
                    continue;
                }
                if let Some(child) = map.get_mut(&k) {
                    walk_strict(child, &format!("{path}/{k}"), false, id, targets);
                }
            }
        }
        _ => {}
    }
}

/// Runs the four checks of the module documentation on every example of `<schema>#/$defs/<def>`.
///
/// # Panics
/// Panics with every failure when a check fails, or when the specification has no such example.
pub fn assert_examples_round_trip<T: DeserializeOwned + Serialize>(
    schemas: &SpecSchemas,
    schema: &str,
    def: &str,
) {
    let docs = examples_for(schema, def);
    assert!(
        !docs.is_empty(),
        "the specification has no example for {schema}#{def}; did it change? (run scripts/sync-spec-fixtures.mjs)"
    );
    let mut failures = Vec::new();
    for (i, doc) in docs.iter().enumerate() {
        let label = format!("{schema}#{def} example {i}");
        if let Err(e) = schemas.check(false, schema, def, doc) {
            failures.push(format!("{label}: the fixture itself is invalid: {e}"));
            continue;
        }
        match serde_json::from_value::<T>(doc.clone()) {
            Err(e) => failures.push(format!("{label}: does not deserialise: {e}")),
            Ok(typed) => match serde_json::to_value(&typed) {
                Err(e) => failures.push(format!("{label}: does not serialise: {e}")),
                Ok(out) => {
                    if let Err(e) = schemas.check(true, schema, def, &out) {
                        failures.push(format!(
                            "{label}: output violates the strict schema: {e}\n{out:#}"
                        ));
                    }
                    if strip_nulls(&out) != strip_nulls(doc) {
                        failures.push(format!(
                            "{label}: round trip differs\n  original: {}\n  output:   {}",
                            strip_nulls(doc),
                            strip_nulls(&out)
                        ));
                    }
                }
            },
        }
    }
    assert!(
        failures.is_empty(),
        "{} conformance failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}
