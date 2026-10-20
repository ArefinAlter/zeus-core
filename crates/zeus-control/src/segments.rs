//! Segment planning, work stealing and chunk-size optimisation (01 section 3.6, research.md 8.7 and 8.11).
//!
//! The committed [`RangeSet`] is the truth; a plan is recomputed from it whenever a job (re)starts.
//! Default segment size is 16 MiB, adaptive between 8 and 32 MiB; when a worker idles and more than
//! 4 MiB remain in the largest unfinished segment, that segment is split and the idle worker takes
//! the tail half.
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
    if params.max_connections == 0
        || params.min_segment_bytes == 0
        || params.max_segment_bytes < params.min_segment_bytes
    {
        return Err(ControlError::invalid("plan", "invalid segment limits"));
    }
    let total = params.total.unwrap_or(zeus_types::limits::MAX_SAFE_INTEGER);
    let gaps = committed.uncovered(total);
    let mut result = Vec::new();
    let size = params
        .segment_bytes
        .clamp(params.min_segment_bytes, params.max_segment_bytes);
    for gap in gaps {
        let pieces = if params.range_support && params.total.is_some() {
            slice_range(gap, size)?
        } else {
            vec![gap]
        };
        for range in pieces {
            let index = u32::try_from(result.len())
                .map_err(|_| ControlError::invalid("plan", "too many segments"))?;
            result.push(Segment::pending(index, range));
        }
    }
    Ok(result)
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
    let victim = segments
        .iter()
        .filter(|s| s.state == zeus_types::SegmentState::Active && s.remaining() > threshold)
        .max_by_key(|s| s.remaining());
    Ok(victim.filter(|s| s.remaining() > 1).map(|s| Steal {
        victim: s.index,
        split_at: s.end - s.remaining() / 2,
    }))
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
    if connections == 0 {
        return Err(ControlError::invalid("connections", "must be positive"));
    }
    let per_worker = total.div_ceil(u64::from(connections));
    let latency_budget = throughput_bps.saturating_mul(rtt_ms).saturating_mul(4) / 1000;
    Ok(per_worker
        .min(latency_budget.max(SEGMENT_MIN_BYTES))
        .clamp(SEGMENT_MIN_BYTES, SEGMENT_MAX_BYTES))
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

#[cfg(test)]
mod runtime_tests {
    use super::*;
    #[test]
    fn plan_is_exact_complement_of_durable_ranges() {
        let mut committed = RangeSet::new();
        committed.insert(ByteRange { start: 10, end: 20 });
        let params = PlanParams {
            total: Some(35),
            max_connections: 2,
            segment_bytes: 8,
            min_segment_bytes: 1,
            max_segment_bytes: 8,
            range_support: true,
        };
        let plan = plan_segments(&params, &committed).unwrap();
        let mut covered = committed.clone();
        for segment in &plan {
            assert!(segment.end - segment.start <= 8);
            assert_eq!(committed.covered_in(segment.range().unwrap()), 0);
            covered.insert(segment.range().unwrap());
        }
        assert_eq!(covered.covered_bytes(), 35);
    }
}
