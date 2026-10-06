//! Request/response correlation over one connection (02 section 6.1).
//!
//! The sender of a request picks its `id`; the response carries it in `re`. A [`RequestCorrelator`]
//! hands out ids (`e<counter>` for the extension, `d<counter>` for the daemon), registers a waiting
//! slot per request with its timeout, delivers a response to the right slot, and fails everything
//! outstanding when the connection closes. A request that is not answered in time is `nm.timeout`
//! (class `timeout`, retryable) and a late response is discarded.
#![expect(
    unused_variables,
    dead_code,
    reason = "skeleton: registration and delivery are filled in by the zeus-session implementation task"
)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::oneshot;

use crate::error::{SessionError, SessionResult};
use crate::protocol::MessageId;

/// Tracks outstanding requests whose response type is `T`.
#[derive(Debug)]
pub struct RequestCorrelator<T> {
    prefix: char,
    counter: AtomicU64,
    pending: Mutex<HashMap<MessageId, oneshot::Sender<SessionResult<T>>>>,
}

/// A registered request waiting for its answer.
#[derive(Debug)]
pub struct PendingResponse<T> {
    id: MessageId,
    receiver: oneshot::Receiver<SessionResult<T>>,
    timeout: Duration,
}

impl<T: Send + 'static> RequestCorrelator<T> {
    /// A correlator minting ids `<prefix><n>` (`e` for the extension, `d` for the daemon).
    #[must_use]
    pub fn new(prefix: char) -> Self {
        Self {
            prefix,
            counter: AtomicU64::new(0),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// The next unused id. Ids are unique per sender per connection.
    #[must_use]
    pub fn next_id(&self) -> MessageId {
        let n = self.counter.fetch_add(1, Ordering::Relaxed) + 1;
        // `<prefix><decimal>` is always a valid MessageId (at most 21 characters).
        MessageId::new(format!("{}{n}", self.prefix)).unwrap_or_else(|_| unreachable_id())
    }

    /// Registers `id` to wait for at most `timeout`. Fails with [`SessionError::DuplicateId`] when `id`
    /// is still outstanding (`nm.duplicate_id`).
    pub fn register(&self, id: MessageId, timeout: Duration) -> SessionResult<PendingResponse<T>> {
        Err(SessionError::NotImplemented("RequestCorrelator::register"))
    }

    /// Delivers a response to the waiting slot named by `re`. Returns false when nothing waits for it
    /// (a late or unsolicited response, to be discarded).
    pub fn resolve(&self, re: &MessageId, response: SessionResult<T>) -> bool {
        false
    }

    /// Fails every outstanding request, for example with [`SessionError::ConnectionLost`] when the
    /// connection closes.
    pub fn fail_all(&self, make_error: impl Fn() -> SessionError) {}

    /// Number of requests still waiting.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

impl<T> PendingResponse<T> {
    /// The request id.
    #[must_use]
    pub fn id(&self) -> &MessageId {
        &self.id
    }

    /// Waits for the answer, the timeout (`SessionError::Timeout`) or a connection failure.
    pub async fn wait(self) -> SessionResult<T> {
        Err(SessionError::NotImplemented("PendingResponse::wait"))
    }
}

fn unreachable_id() -> MessageId {
    // A fixed valid id used only if formatting somehow produced an invalid one.
    MessageId::new("x").unwrap_or_else(|_| unreachable!("`x` is a valid message id"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_sequential_and_prefixed() {
        let c: RequestCorrelator<()> = RequestCorrelator::new('e');
        assert_eq!(c.next_id().as_str(), "e1");
        assert_eq!(c.next_id().as_str(), "e2");
        let d: RequestCorrelator<()> = RequestCorrelator::new('d');
        assert_eq!(d.next_id().as_str(), "d1");
        assert_eq!(c.outstanding(), 0);
    }
}
