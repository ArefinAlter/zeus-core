//! The published test vectors of 04 section 4.7 and the manifest example of 04 section 3.5, read from
//! the fixtures copied out of the specification (`spec-fixtures/`).

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use zeus_verify::audit::{ChainStart, verify_records};
use zeus_verify::provenance::ManifestLine;

fn example(schema: &str, def: &str) -> Vec<Value> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec-fixtures");
    let index: Value =
        serde_json::from_str(&fs::read_to_string(root.join("examples/index.json")).unwrap())
            .unwrap();
    let entry = index
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["schema"] == schema && e["def"] == def)
        .unwrap_or_else(|| panic!("no example for {schema}#{def}"));
    fs::read_to_string(root.join(entry["file"].as_str().unwrap()))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn the_published_eleven_record_chain_verifies() {
    let records = example("audit-record.v1", "AuditRecord");
    assert_eq!(records.len(), 11);
    let head = verify_records(&records, &ChainStart::Genesis, None)
        .unwrap()
        .unwrap();
    assert_eq!(head.seq, 11);
    assert_eq!(
        head.hash.to_hex(),
        "0bf55ec3cae965128968b92a062399b8262f131eec57d9f7da687e6b1a3fbb72"
    );
    assert_eq!(
        head.chain_id.to_string(),
        "chain_01M3TC5H007DRT2QA1P1NY311K"
    );
}

#[test]
fn flipping_any_character_of_the_published_chain_is_detected() {
    let records = example("audit-record.v1", "AuditRecord");
    for i in 0..records.len() {
        let mut tampered = records.clone();
        tampered[i]["ts"] = Value::String("2099-01-01T00:00:00.000Z".into());
        assert!(
            verify_records(&tampered, &ChainStart::Genesis, None).is_err(),
            "record {} edited",
            i + 1
        );
    }
}

#[test]
fn manifest_example_parses_into_the_typed_lines() {
    let lines = example("provenance-manifest.v0", "ManifestLine");
    assert_eq!(lines.len(), 4);
    let typed: Vec<ManifestLine> = lines
        .iter()
        .map(|v| serde_json::from_value(v.clone()).unwrap())
        .collect();
    assert!(matches!(typed[0], ManifestLine::Header(_)));
    assert!(
        typed[1..]
            .iter()
            .all(|l| matches!(l, ManifestLine::File(_)))
    );
    // The pointers refer to records of the verified chain.
    let ManifestLine::File(first) = &typed[1] else {
        unreachable!()
    };
    assert_eq!(first.audit.seq, 7);
    assert_eq!(
        first.audit.hash.to_hex(),
        "180a9271bfe48c75d6580e81535a1e359c5fb32549ac4385a1e67f9c70914c65"
    );
}
