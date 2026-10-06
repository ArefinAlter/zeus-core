//! Credit-based flow control and stream validation for the in-browser fetch proxy (02 section 9.5).
//!
//! One credit permits one `fetch.chunk`. The extension starts a stream with `fetch.range.credits`
//! credits, spends one per chunk and stops reading the response body at zero (which applies TCP
//! backpressure to the origin). The daemon replenishes after a chunk was written with `pwrite` and
//! handed to the commit pipeline, in batches of `credits / 2`, and withholds credits when the job's
//! unacknowledged bytes reach `max_unacked_bytes` (03 section 5.3).

use crate::error::SessionError;
use crate::protocol::{FetchChunkBody, Limits};

/// The sender's (extension's) view of its credits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditWindow {
    available: u32,
    max: u32,
}

impl CreditWindow {
    /// A window with `initial` credits, never growing beyond `max` (`limits.max_credit_window`).
    #[must_use]
    pub fn new(initial: u8, max: u8) -> Self {
        let max = u32::from(max.max(1));
        Self {
            available: u32::from(initial).min(max),
            max,
        }
    }

    /// Credits left.
    #[must_use]
    pub const fn available(&self) -> u32 {
        self.available
    }

    /// Spends one credit for one chunk. At zero this is `nm.credit_exceeded`: the sender must stop reading.
    pub fn consume(&mut self) -> Result<(), SessionError> {
        if self.available == 0 {
            return Err(SessionError::Protocol("chunk sent with zero credits"));
        }
        self.available -= 1;
        Ok(())
    }

    /// Adds credits from a `fetch.credit`, capped at the window maximum.
    pub fn grant(&mut self, credits: u8) {
        self.available = (self.available + u32::from(credits)).min(self.max);
    }
}

/// How many credits the daemon returns each time: half the initial window, at least 1, so there is
/// not one `fetch.credit` message per chunk.
#[must_use]
pub fn replenish_batch(initial_credits: u8) -> u8 {
    (initial_credits / 2).max(1)
}

/// The receiver's (daemon's) check of one stream's chunks: consecutive `index`, contiguous `offset`,
/// `length` equal to the decoded length, credits respected, and no chunk beyond the requested range.
#[derive(Debug, Clone)]
pub struct InboundStream {
    next_index: u64,
    next_offset: u64,
    end_offset: Option<u64>,
    max_chunk_bytes: u64,
    credits: CreditWindow,
}

impl InboundStream {
    /// Starts tracking a stream requested at `offset` with `length` bytes (`None` for the whole
    /// resource) and `credits` initial credits.
    #[must_use]
    pub fn new(offset: u64, length: Option<u64>, credits: u8, limits: &Limits) -> Self {
        Self {
            next_index: 0,
            next_offset: offset,
            end_offset: length.map(|l| offset.saturating_add(l)),
            max_chunk_bytes: limits.max_chunk_bytes,
            credits: CreditWindow::new(credits, limits.max_credit_window),
        }
    }

    /// Validates a chunk and advances the stream. Every violation is `nm.stream_protocol_violation` or
    /// `nm.credit_exceeded`, after which the daemon cancels the stream.
    pub fn accept(&mut self, chunk: &FetchChunkBody) -> Result<(), SessionError> {
        if !chunk.length_matches() {
            return Err(SessionError::Protocol(
                "chunk length differs from the decoded data",
            ));
        }
        if u64::from(chunk.length) > self.max_chunk_bytes {
            return Err(SessionError::Protocol("chunk larger than max_chunk_bytes"));
        }
        if chunk.index != self.next_index {
            return Err(SessionError::Protocol("chunk index is not consecutive"));
        }
        if chunk.offset != self.next_offset {
            return Err(SessionError::Protocol(
                "chunk offset leaves a gap or overlaps",
            ));
        }
        let end = chunk.offset.saturating_add(u64::from(chunk.length));
        if self.end_offset.is_some_and(|limit| end > limit) {
            return Err(SessionError::Protocol("chunk beyond the requested range"));
        }
        self.credits.consume()?;
        self.next_index += 1;
        self.next_offset = end;
        Ok(())
    }

    /// Credits to send back now, if a batch is due. `acknowledged` is true once the chunk has been
    /// written and handed to the commit pipeline; the daemon passes `false` while `max_unacked_bytes`
    /// is reached, which withholds credits (backpressure).
    pub fn credits_to_return(&mut self, initial_credits: u8, acknowledged: bool) -> Option<u8> {
        if !acknowledged {
            return None;
        }
        let batch = replenish_batch(initial_credits);
        // Credits spent so far are returned once at least one batch is outstanding.
        let spent = u32::from(initial_credits).saturating_sub(self.credits.available());
        if spent >= u32::from(batch) {
            self.credits.grant(batch);
            Some(batch)
        } else {
            None
        }
    }

    /// The next byte offset the stream expects (where the daemon resumes after a loss).
    #[must_use]
    pub const fn next_offset(&self) -> u64 {
        self.next_offset
    }

    /// Chunks accepted so far.
    #[must_use]
    pub const fn chunks(&self) -> u64 {
        self.next_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ChunkData, StreamId};

    fn chunk(index: u64, offset: u64, len: usize) -> FetchChunkBody {
        FetchChunkBody {
            stream_id: StreamId::new("s1").unwrap(),
            index,
            offset,
            length: len as u32,
            data: ChunkData::new(vec![7; len]),
        }
    }

    #[test]
    fn the_sender_stops_at_zero_credits() {
        let mut w = CreditWindow::new(2, 32);
        assert!(w.consume().is_ok() && w.consume().is_ok());
        assert!(matches!(w.consume(), Err(SessionError::Protocol(_))));
        w.grant(4);
        assert_eq!(w.available(), 4);
        w.grant(255);
        assert_eq!(w.available(), 32, "capped at the window maximum");
    }

    #[test]
    fn contiguous_chunks_are_accepted_and_gaps_are_not() {
        let limits = Limits::default();
        let mut s = InboundStream::new(1000, Some(300), 8, &limits);
        assert!(s.accept(&chunk(0, 1000, 100)).is_ok());
        assert!(s.accept(&chunk(1, 1100, 100)).is_ok());
        assert!(s.accept(&chunk(2, 1201, 99)).is_err(), "offset gap");
        assert!(s.accept(&chunk(3, 1200, 100)).is_err(), "index skipped");
        assert!(
            s.accept(&chunk(2, 1200, 101)).is_err(),
            "beyond the requested range"
        );
        assert!(s.accept(&chunk(2, 1200, 100)).is_ok());
        assert_eq!((s.next_offset(), s.chunks()), (1300, 3));
    }

    #[test]
    fn a_mislabelled_length_is_a_violation() {
        let mut s = InboundStream::new(0, None, 8, &Limits::default());
        let mut c = chunk(0, 0, 10);
        c.length = 11;
        assert!(s.accept(&c).is_err());
    }

    #[test]
    fn credits_are_enforced_by_the_receiver_too() {
        let mut s = InboundStream::new(0, None, 2, &Limits::default());
        assert!(s.accept(&chunk(0, 0, 4)).is_ok());
        assert!(s.accept(&chunk(1, 4, 4)).is_ok());
        assert!(
            s.accept(&chunk(2, 8, 4)).is_err(),
            "nm.credit_exceeded: a third chunk with two credits"
        );
    }

    #[test]
    fn credits_come_back_in_batches_and_can_be_withheld() {
        let mut s = InboundStream::new(0, None, 8, &Limits::default());
        for i in 0..3 {
            s.accept(&chunk(i, i * 4, 4)).unwrap();
        }
        assert_eq!(s.credits_to_return(8, true), None, "3 spent, batch is 4");
        s.accept(&chunk(3, 12, 4)).unwrap();
        assert_eq!(
            s.credits_to_return(8, false),
            None,
            "withheld while max_unacked_bytes is reached"
        );
        assert_eq!(s.credits_to_return(8, true), Some(4));
        assert_eq!(replenish_batch(8), 4);
        assert_eq!(replenish_batch(1), 1);
    }
}
