//! Segments: planned units of parallel work (01 section 3.6).
//!
//! A segment is a *view*, not stored truth. The committed range set (03 section 3.4) is the truth;
//! segments are recomputed from it and the work plan whenever a job (re)starts, and may be split at
//! any time for work stealing.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::TypesError;
use crate::units::ByteRange;

/// State of a planned segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SegmentState {
    /// Not started.
    Pending,
    /// A worker is transferring it.
    Active,
    /// Fully committed.
    Done,
    /// Its retry budget is spent; job-level classification applies.
    Failed,
}

/// A planned work unit over the half-open interval `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Segment {
    /// Position in the current plan.
    pub index: u32,
    /// First byte.
    pub start: u64,
    /// One past the last byte.
    pub end: u64,
    /// Bytes of this interval already committed (not necessarily contiguous from `start`).
    pub committed_bytes: u64,
    /// State.
    pub state: SegmentState,
}

impl Segment {
    /// A pending segment over `range`.
    #[must_use]
    pub fn pending(index: u32, range: ByteRange) -> Self {
        Self {
            index,
            start: range.start,
            end: range.end,
            committed_bytes: 0,
            state: SegmentState::Pending,
        }
    }

    /// The interval.
    pub fn range(&self) -> Result<ByteRange, TypesError> {
        ByteRange::new(self.start, self.end)
    }

    /// Bytes not yet committed.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.end
            .saturating_sub(self.start)
            .saturating_sub(self.committed_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_example() {
        let text = r#"{ "index": 3, "start": 50331648, "end": 67108864, "committed_bytes": 4194304, "state": "active" }"#;
        let seg: Segment = serde_json::from_str(text).unwrap();
        assert_eq!(seg.remaining(), 16_777_216 - 4_194_304);
        assert_eq!(seg.range().unwrap().len(), 16_777_216);
    }
}
