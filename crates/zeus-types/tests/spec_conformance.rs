//! Conformance of the Rust types to the normative specification (zeus repository, `docs/spec`),
//! using the fixtures in `spec-fixtures/` and the helpers of `zeus_types::spec_testing`.

use std::collections::BTreeSet;

use zeus_types::spec_testing::{
    SpecSchemas, assert_examples_round_trip, examples_for, read_fixture_json,
};
use zeus_types::state::{self, TRANSITIONS};
use zeus_types::{
    Approval, ErrorEnvelope, Event, EventKind, Job, JobId, JobSpec, JobState, ProbeResult,
    Progress, RedactMode, Segment, SessionGrant, TransitionActor, redact_url,
};

#[test]
fn every_domain_and_common_example_round_trips_through_the_rust_types() {
    let schemas = SpecSchemas::load();
    assert_examples_round_trip::<JobId>(&schemas, "common", "JobId");
    assert_examples_round_trip::<ErrorEnvelope>(&schemas, "common", "ErrorEnvelope");
    assert_examples_round_trip::<Job>(&schemas, "domain", "Job");
    assert_examples_round_trip::<JobSpec>(&schemas, "domain", "JobSpec");
    assert_examples_round_trip::<ProbeResult>(&schemas, "domain", "ProbeResult");
    assert_examples_round_trip::<Segment>(&schemas, "domain", "Segment");
    assert_examples_round_trip::<Progress>(&schemas, "domain", "Progress");
    assert_examples_round_trip::<SessionGrant>(&schemas, "domain", "SessionGrant");
    assert_examples_round_trip::<Approval>(&schemas, "domain", "Approval");
    assert_examples_round_trip::<Event>(&schemas, "domain", "Event");
}

#[test]
fn event_examples_carry_the_documented_event_types() {
    let mut seen = BTreeSet::new();
    for doc in examples_for("domain", "Event") {
        let event: Event = serde_json::from_value(doc).unwrap();
        let kind = event
            .payload
            .kind()
            .expect("unknown event type in a spec example");
        seen.insert(kind);
    }
    // Every catalogue event except daemon.stopping appears in the examples of 01 section 9.3.
    for kind in EventKind::ALL
        .iter()
        .filter(|k| **k != EventKind::DaemonStopping)
    {
        assert!(seen.contains(kind), "no example for {kind}");
    }
}

#[test]
fn rust_output_for_a_minimal_job_validates_against_the_strict_schema() {
    use zeus_types::{HttpUrl, IdGenerator, Source, SourceKind, Timestamp};
    let schemas = SpecSchemas::load();
    let spec = JobSpec::new(
        HttpUrl::parse("https://files.example.com/a.zip").unwrap(),
        Source::new(SourceKind::Cli),
    );
    let job = Job::new(
        IdGenerator::new().job_id(),
        spec,
        JobState::Queued,
        Timestamp::UNIX_EPOCH,
    );
    schemas
        .check(true, "domain", "Job", &serde_json::to_value(&job).unwrap())
        .unwrap();
    schemas
        .check(
            true,
            "domain",
            "JobSummary",
            &serde_json::to_value(job.summary()).unwrap(),
        )
        .unwrap();
}

fn actor_from_str(s: &str) -> TransitionActor {
    match s {
        "client" => TransitionActor::Client,
        "human" => TransitionActor::Human,
        "engine" => TransitionActor::Engine,
        "policy" => TransitionActor::Policy,
        "system" => TransitionActor::System,
        other => panic!("unknown actor {other}"),
    }
}

#[test]
fn state_machine_conformance() {
    let machine = read_fixture_json("schema/job-state-machine.v1.json");
    let rows = machine["transitions"].as_array().unwrap();
    assert_eq!(
        rows.len(),
        TRANSITIONS.len(),
        "row count differs from the normative table"
    );

    let states = machine["states"].as_array().unwrap();
    assert_eq!(states.len(), JobState::ALL.len());
    for (json, state) in states.iter().zip(JobState::ALL) {
        assert_eq!(json["name"].as_str().unwrap(), state.as_str());
        assert_eq!(
            json["terminal"].as_bool().unwrap(),
            state.is_terminal(),
            "{state}"
        );
    }

    let events: Vec<&str> = machine["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let ours: Vec<&str> = EventKind::ALL.iter().map(|k| k.name()).collect();
    assert_eq!(events, ours);

    let mut edges = BTreeSet::new();
    for row in rows {
        let id = row["id"].as_str().unwrap();
        let def =
            state::transition_def(id).unwrap_or_else(|| panic!("{id} missing from TRANSITIONS"));
        let from: Vec<Option<JobState>> = row["from"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().map(|s| s.parse().unwrap()))
            .collect();
        assert_eq!(def.from, from.as_slice(), "{id} from");
        assert_eq!(def.to.as_str(), row["to"].as_str().unwrap(), "{id} to");
        assert_eq!(
            def.trigger,
            row["trigger"].as_str().unwrap(),
            "{id} trigger"
        );
        assert_eq!(def.guard, row["guard"].as_str().unwrap(), "{id} guard");
        let actors: Vec<TransitionActor> = row["actors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| actor_from_str(v.as_str().unwrap()))
            .collect();
        assert_eq!(def.actors, actors.as_slice(), "{id} actors");
        let events: Vec<&str> = row["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let ours: Vec<&str> = def.events.iter().map(|e| e.name()).collect();
        assert_eq!(ours, events, "{id} events");
        for f in &from {
            edges.insert((*f, def.to));
        }
    }

    // Every pair of states not in the table is rejected, every pair in it is accepted.
    let mut all_from: Vec<Option<JobState>> = vec![None];
    all_from.extend(JobState::ALL.map(Some));
    for from in all_from {
        for to in JobState::ALL {
            assert_eq!(
                state::is_legal(from, to),
                edges.contains(&(from, to)),
                "{from:?} -> {to}"
            );
        }
    }
}

#[test]
fn transition_causes_are_consistent_with_events() {
    // A transition that emits job.state_changed must allow at least one cause; creation has none.
    for def in TRANSITIONS {
        let emits_state_changed = def.events.contains(&EventKind::JobStateChanged);
        assert_eq!(emits_state_changed, !def.causes.is_empty(), "{}", def.id);
    }
}

#[test]
fn redaction_vectors() {
    let vectors = read_fixture_json("schema/redaction-vectors.v1.json");
    let cases = vectors["cases"].as_array().unwrap();
    assert!(
        cases.len() >= 30,
        "vector file looks truncated ({})",
        cases.len()
    );
    let mut failures = Vec::new();
    for case in cases {
        let mode = match case["mode"].as_str().unwrap() {
            "log" => RedactMode::Log,
            "record" => RedactMode::Record,
            "strict" => RedactMode::Strict,
            other => panic!("unknown mode {other}"),
        };
        let input = case["input"].as_str().unwrap();
        let got = redact_url(input, mode);
        let (want_url, want_redacted) = (
            case["expected"].as_str().unwrap(),
            case["redacted"].as_bool().unwrap(),
        );
        if got.url != want_url || got.redacted != want_redacted {
            failures.push(format!(
                "{} [{}]\n  input:    {input}\n  expected: {want_url} ({want_redacted})\n  got:      {} ({})",
                case["name"], case["mode"], got.url, got.redacted
            ));
        }
        // Idempotence (00 section 8.2): redacting a redacted URL changes nothing further. The WHATWG
        // parser percent-encodes the ellipsis marker on the second pass; the specification's
        // "idempotent" holds modulo that encoding (the reference implementation behaves the same).
        let again = redact_url(&got.url, mode);
        if again.url.replace("%E2%80%A6", "\u{2026}") != got.url {
            failures.push(format!("not idempotent: {} -> {}", got.url, again.url));
        }
    }
    assert!(
        failures.is_empty(),
        "{} vector failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn progress_example_matches_the_eta_formula() {
    let doc = examples_for("domain", "Progress").remove(0);
    let p: Progress = serde_json::from_value(doc).unwrap();
    // 01 section 3.7: eta_s = (bytes_total - bytes_done) / rate_ewma, integer division.
    assert_eq!(
        Progress::compute_eta_s(p.bytes_done, p.bytes_total, p.rate_ewma),
        p.eta_s
    );
}
