//! Artifact records match the normative portable contract.
use zeus_artifact::{Artifact, ImportRecord};
use zeus_types::spec_testing::{SpecSchemas, assert_examples_round_trip};
#[test]
fn artifact_examples_round_trip() {
    let schemas = SpecSchemas::load();
    assert_examples_round_trip::<Artifact>(&schemas, "artifact.v1", "Artifact");
    assert_examples_round_trip::<ImportRecord>(&schemas, "artifact.v1", "ImportRecord");
}
