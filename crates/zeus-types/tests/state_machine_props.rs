//! Property tests of the job state machine, derived from the normative table in
//! `spec-fixtures/schema/job-state-machine.v1.json` (an independent oracle, not `TRANSITIONS`).

use std::collections::BTreeSet;

use proptest::prelude::*;
use zeus_types::state::{self, TransitionError};
use zeus_types::{JobState, TransitionActor};

/// `(id, from, to, actors)` rows read straight from the JSON file.
struct Row {
    id: String,
    from: Vec<Option<JobState>>,
    to: JobState,
    actors: Vec<String>,
}

fn oracle() -> Vec<Row> {
    let path = zeus_types::spec_testing::fixtures_dir().join("schema/job-state-machine.v1.json");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    doc["transitions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| Row {
            id: t["id"].as_str().unwrap().to_owned(),
            from: t["from"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().map(|s| s.parse().unwrap()))
                .collect(),
            to: t["to"].as_str().unwrap().parse().unwrap(),
            actors: t["actors"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect(),
        })
        .collect()
}

fn actor_name(actor: TransitionActor) -> &'static str {
    match actor {
        TransitionActor::Client => "client",
        TransitionActor::Human => "human",
        TransitionActor::Engine => "engine",
        TransitionActor::Policy => "policy",
        TransitionActor::System => "system",
    }
}

const ACTORS: [TransitionActor; 5] = [
    TransitionActor::Client,
    TransitionActor::Human,
    TransitionActor::Engine,
    TransitionActor::Policy,
    TransitionActor::System,
];

fn any_state() -> impl Strategy<Value = Option<JobState>> {
    prop_oneof![
        Just(None),
        (0..JobState::ALL.len()).prop_map(|i| Some(JobState::ALL[i]))
    ]
}

proptest! {
    /// `apply` accepts exactly the (from, id, actor) triples the oracle lists.
    #[test]
    fn apply_agrees_with_the_oracle(from in any_state(), row_ix in 0usize..44, actor_ix in 0usize..5) {
        let rows = oracle();
        let row = &rows[row_ix % rows.len()];
        let actor = ACTORS[actor_ix];
        let expected_ok = row.from.contains(&from) && row.actors.iter().any(|a| a == actor_name(actor));
        let result = state::apply(from, &row.id, actor);
        prop_assert_eq!(result.is_ok(), expected_ok);
        match result {
            Ok((to, _)) => prop_assert_eq!(to, row.to),
            Err(TransitionError::WrongSource { .. }) => prop_assert!(!row.from.contains(&from)),
            Err(TransitionError::ActorNotPermitted { .. }) => prop_assert!(row.from.contains(&from)),
            Err(other) => prop_assert!(false, "unexpected error {other:?}"),
        }
    }

    /// Random walks that only ever choose rows from the current state never leave the table, never
    /// leave a terminal state, and every step is an edge of the oracle graph.
    #[test]
    fn random_walks_stay_on_the_graph(choices in proptest::collection::vec(any::<u8>(), 1..60)) {
        let rows = oracle();
        let edges: BTreeSet<(Option<JobState>, JobState)> =
            rows.iter().flat_map(|r| r.from.iter().map(move |f| (*f, r.to))).collect();
        let mut current: Option<JobState> = None;
        for choice in choices {
            let options: Vec<_> = state::transitions_from(current).collect();
            if options.is_empty() {
                prop_assert!(current.is_some_and(JobState::is_terminal), "only terminal states have no exits: {current:?}");
                break;
            }
            let def = options[usize::from(choice) % options.len()];
            let actor = def.actors[0];
            let (next, _) = state::apply(current, def.id, actor).expect("a row listed from `current` applies");
            prop_assert!(edges.contains(&(current, next)));
            current = Some(next);
        }
    }

    /// `apply_edge` finds a row iff the oracle has the edge and one of its actors matches.
    #[test]
    fn apply_edge_agrees_with_the_oracle(from in any_state(), to_ix in 0usize..12, actor_ix in 0usize..5) {
        let rows = oracle();
        let to = JobState::ALL[to_ix];
        let actor = ACTORS[actor_ix];
        let has_edge = rows.iter().any(|r| r.to == to && r.from.contains(&from));
        let permitted = rows.iter().any(|r| r.to == to && r.from.contains(&from) && r.actors.iter().any(|a| a == actor_name(actor)));
        let result = state::apply_edge(from, to, actor);
        prop_assert_eq!(result.is_ok(), permitted);
        if !has_edge {
            let no_edge = matches!(result, Err(TransitionError::NoSuchEdge { .. }));
            prop_assert!(no_edge);
        }
    }
}
