//! Event subscription (01 section 9.2).
//!
//! Durable events are totally ordered by `seq` and **replayable**: a subscriber that reconnects asks for
//! `since_seq` and receives the stored events above it before live ones. Ephemeral `job.progress` events
//! are coalesced (a slow subscriber sees only the newest per job) and never replayed. A subscriber that
//! falls behind the broadcast buffer is told ([`EngineEvent::Lagged`]) and re-reads state; if its
//! `since_seq` is older than retention it receives [`EngineEvent::ReplayTruncated`] first.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use zeus_types::{Event, EventSeq};

/// What a subscriber receives.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "events dominate the stream; the other variants are rare"
)]
pub enum EngineEvent {
    /// An event, durable (with `seq`) or ephemeral (with `after_seq`).
    Event(Event),
    /// The subscriber missed `missed` events because it was too slow; it should re-read current state
    /// (`jobs.list`) and de-duplicate by `seq` afterwards.
    Lagged {
        /// How many events were dropped.
        missed: u64,
    },
    /// The requested `since_seq` is older than the retained history; the replay starts at `first_available`.
    ReplayTruncated {
        /// The oldest `seq` still stored.
        first_available: EventSeq,
    },
}

/// A stream of [`EngineEvent`]s: replay first, then live events. Dropping it unsubscribes.
pub struct EventSubscription {
    inner: Pin<Box<dyn Stream<Item = EngineEvent> + Send>>,
}

impl EventSubscription {
    /// Wraps a stream. Used by the engine; embedders and tests may build one over a fixed list.
    #[must_use]
    pub fn new(inner: Pin<Box<dyn Stream<Item = EngineEvent> + Send>>) -> Self {
        Self { inner }
    }

    /// A subscription that yields `events` and then ends.
    #[must_use]
    pub fn from_events(events: Vec<EngineEvent>) -> Self {
        Self::new(Box::pin(futures::stream::iter(events)))
    }
}

impl Stream for EventSubscription {
    type Item = EngineEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

impl std::fmt::Debug for EventSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventSubscription").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use super::*;

    #[tokio::test]
    async fn a_fixed_subscription_yields_in_order_then_ends() {
        let mut sub = EventSubscription::from_events(vec![
            EngineEvent::Lagged { missed: 3 },
            EngineEvent::ReplayTruncated {
                first_available: EventSeq::FIRST,
            },
        ]);
        assert_eq!(sub.next().await, Some(EngineEvent::Lagged { missed: 3 }));
        assert!(matches!(
            sub.next().await,
            Some(EngineEvent::ReplayTruncated { .. })
        ));
        assert_eq!(sub.next().await, None);
    }
}
