//! Segment planning, work stealing and chunk-size optimisation (01 section 3.6, research.md 8.7 and 8.11).
//!
//! The committed [`RangeSet`] is the truth; a plan is recomputed from it whenever a job (re)starts.
//! Default segment size is 16 MiB, adaptive between 8 and 32 MiB; when a worker idles and more than
//! 4 MiB remain in the largest unfinished segment, that segment is split and the idle worker takes
//! the tail half.
#![expect(
    unused_variables,
    reason = "skeleton: bodies are filled in by the zeus-control implementation task"
)]

use zeus_types::policy::scheduling::{
    SEGMENT_BYTES, SEGMENT_MAX_BYTES, SEGMENT_MIN_BYTES, STEAL_THRESHOLD_BYTES,
};
use zeus_types::{ByteRange, Segment};

use crate::error::{ControlError, Result};
use crate::range_set::RangeSet;

/// Inputs of the initial plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanParams {
    /// Total size, or `None` for an unknown length (then a single streaming segment is planned).
    pub total: Option<u64>,
    /// Upper bound on concurrent connections.
    pub max_connections: u32,
    /// Preferred segment size.
    pub segment_bytes: u64,
    /// Smallest segment worth a connection.
    pub min_segment_bytes: u64,
    /// Largest segment.
    pub max_segment_bytes: u64,
    /// Whether the server supports ranged requests (otherwise one segment from the first uncommitted byte).
    pub range_support: bool,
}

impl Default for PlanParams {
    fn default() -> Self {
        Self {
            total: None,
            max_connections: 8,
            segment_bytes: SEGMENT_BYTES,
            min_segment_bytes: SEGMENT_MIN_BYTES,
            max_segment_bytes: SEGMENT_MAX_BYTES,
            range_support: true,
        }
    }
}

/// Plans pending segments covering exactly the uncommitted bytes of `[0, total)`, ordered by start.
/// Committed ranges are never planned again.
pub fn plan_segments(params: &PlanParams, committed: &RangeSet) -> Result<Vec<Segment>> {
    Err(ControlError::NotImplemented("plan_segments"))
}

/// The result of a steal decision: split `victim` at `split_at`; the idle worker takes `[split_at, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Steal {
    /// Index of the segment to shorten.
    pub victim: u32,
    /// New start of the stolen tail; the victim's end becomes this offset.
    pub split_at: u64,
}

/// Chooses the segment with the most remaining bytes and, if more than `threshold` remain, where to
/// split it. `active` segments are measured from their committed progress, not their nominal size.
pub fn plan_steal(segments: &[Segment], threshold: u64) -> Result<Option<Steal>> {
    Err(ControlError::NotImplemented("plan_steal"))
}

/// The default steal threshold (4 MiB).
pub const DEFAULT_STEAL_THRESHOLD: u64 = STEAL_THRESHOLD_BYTES;

/// Chunk-size optimisation (research.md 8.11): the segment size that balances per-request overhead
/// against the tail cost of the last segment, given the file size, connection count and round-trip time.
pub fn optimal_segment_bytes(
    total: u64,
    connections: u32,
    rtt_ms: u64,
    throughput_bps: u64,
) -> Result<u64> {
    Err(ControlError::NotImplemented("optimal_segment_bytes"))
}

/// Splits `range` into pieces of at most `piece_bytes` (the last may be shorter). Used by the
/// in-browser proxy, which requests at most `max_range_bytes` per stream.
pub fn slice_range(range: ByteRange, piece_bytes: u64) -> Result<Vec<ByteRange>> {
    if piece_bytes == 0 {
        return Err(ControlError::invalid("piece_bytes", "must be positive"));
    }
    let mut out = Vec::new();
    let mut start = range.start;
    while start < range.end {
        let end = start.saturating_add(piece_bytes).min(range.end);
        out.push(ByteRange { start, end });
        start = end;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slicing() {
        let pieces = slice_range(ByteRange::new(10, 35).unwrap(), 10).unwrap();
        let got: Vec<_> = pieces.iter().map(|r| (r.start, r.end)).collect();
        assert_eq!(got, [(10, 20), (20, 30), (30, 35)]);
        assert!(slice_range(ByteRange::new(0, 1).unwrap(), 0).is_err());
        assert!(
            slice_range(ByteRange::new(5, 5).unwrap(), 4)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn defaults_match_the_specification() {
        let p = PlanParams::default();
        assert_eq!(
            (p.segment_bytes, p.min_segment_bytes, p.max_segment_bytes),
            (16 << 20, 8 << 20, 32 << 20)
        );
        assert_eq!(DEFAULT_STEAL_THRESHOLD, 4 << 20);
    }
}
