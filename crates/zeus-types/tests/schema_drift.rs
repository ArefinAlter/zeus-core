//! The committed `schemas/zeus-types.schema.json` must match what the Rust types generate today.
//! Regenerate with `cargo run -p zeus-types --example gen_schemas`.

use std::path::PathBuf;

#[test]
fn committed_schema_is_current() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas/zeus-types.schema.json");
    let committed: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&path).expect("schemas/zeus-types.schema.json is committed"),
    )
    .expect("valid JSON");
    assert_eq!(
        committed,
        zeus_types::schema::bundle(),
        "stale: run `cargo run -p zeus-types --example gen_schemas`"
    );
}

#[test]
fn generated_schema_is_a_valid_2020_12_document() {
    let schema = zeus_types::schema::bundle();
    assert!(
        jsonschema::meta::is_valid(&schema),
        "the bundle must satisfy the 2020-12 meta-schema"
    );
    let defs = schema["$defs"].as_object().unwrap();
    for name in [
        "Job",
        "JobSpec",
        "JobSummary",
        "ProbeResult",
        "Progress",
        "Segment",
        "SessionGrant",
        "Approval",
        "Event",
        "ErrorEnvelope",
    ] {
        assert!(defs.contains_key(name), "missing definition {name}");
    }
}
