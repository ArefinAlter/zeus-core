//! Every message example of `docs/spec/02-native-messaging-v1.md` decodes into the typed catalogue,
//! re-encodes to something the strict normative schema accepts, and survives the round trip.

use zeus_session::{DaemonMessage, ExtensionMessage};
use zeus_types::spec_testing::{SpecSchemas, assert_examples_round_trip};

#[test]
fn extension_to_daemon_examples_round_trip() {
    assert_examples_round_trip::<ExtensionMessage>(
        &SpecSchemas::load(),
        "native-messaging.v1",
        "ExtensionToDaemonMessage",
    );
}

#[test]
fn daemon_to_extension_examples_round_trip() {
    assert_examples_round_trip::<DaemonMessage>(
        &SpecSchemas::load(),
        "native-messaging.v1",
        "DaemonToExtensionMessage",
    );
}

fn message_types(union: &str) -> Vec<String> {
    let schema =
        zeus_types::spec_testing::read_fixture_json("schema/native-messaging.v1.schema.json");
    let defs = &schema["$defs"];
    defs[union]["oneOf"]
        .as_array()
        .expect("oneOf")
        .iter()
        .map(|member| {
            let name = member["$ref"].as_str().unwrap().rsplit('/').next().unwrap();
            defs[name]["allOf"][1]["properties"]["type"]["const"]
                .as_str()
                .unwrap_or_else(|| panic!("no type const in {name}"))
                .to_owned()
        })
        .collect()
}

#[test]
fn the_typed_catalogue_covers_exactly_the_types_of_the_schema() {
    use std::collections::BTreeSet;
    use zeus_session::protocol::{DaemonBody, ExtensionBody};
    let ours = |t: &[&str]| t.iter().map(|s| (*s).to_owned()).collect::<BTreeSet<_>>();
    assert_eq!(
        ours(ExtensionBody::TYPES),
        message_types("ExtensionToDaemonMessage")
            .into_iter()
            .collect()
    );
    assert_eq!(
        ours(DaemonBody::TYPES),
        message_types("DaemonToExtensionMessage")
            .into_iter()
            .collect()
    );
}

#[test]
fn interrupt_reasons_match_the_schema_enum() {
    use zeus_session::protocol::InterruptReason;
    let schema =
        zeus_types::spec_testing::read_fixture_json("schema/native-messaging.v1.schema.json");
    let wire: Vec<String> = schema["$defs"]["InterruptReason"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(wire.len(), 30);
    for name in &wire {
        let reason: InterruptReason =
            serde_json::from_value(serde_json::Value::String(name.clone()))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            &serde_json::to_value(reason).unwrap(),
            &serde_json::Value::String(name.clone())
        );
        // Every reason has a rescue decision; none panics.
        let _ = reason.rescue_offer();
        let _ = reason.hint_class();
    }
}

#[test]
fn limits_defaults_are_inside_the_schema_bounds() {
    use zeus_types::spec_testing::SpecSchemas;
    let doc = serde_json::to_value(zeus_session::Limits::default()).unwrap();
    SpecSchemas::load()
        .check(true, "native-messaging.v1", "Limits", &doc)
        .unwrap();
}
