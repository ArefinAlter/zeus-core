//! The journal records agree with `journal.v1.schema.json` and the examples of 03 section 4.

use zeus_journal::{
    IdempotencyRow, InvalidationRow, JobRecord, Meta, RangeRow, ReservationRow, UnitCrcRow,
};
use zeus_types::spec_testing::{SpecSchemas, assert_examples_round_trip};

#[test]
fn journal_examples_round_trip_through_the_rust_records() {
    let schemas = SpecSchemas::load();
    assert_examples_round_trip::<Meta>(&schemas, "journal.v1", "Meta");
    assert_examples_round_trip::<JobRecord>(&schemas, "journal.v1", "JobRecord");
    assert_examples_round_trip::<RangeRow>(&schemas, "journal.v1", "RangeRow");
    assert_examples_round_trip::<UnitCrcRow>(&schemas, "journal.v1", "UnitCrcRow");
    assert_examples_round_trip::<InvalidationRow>(&schemas, "journal.v1", "InvalidationRow");
    assert_examples_round_trip::<IdempotencyRow>(&schemas, "journal.v1", "IdempotencyRow");
    assert_examples_round_trip::<ReservationRow>(&schemas, "journal.v1", "ReservationRow");
}
