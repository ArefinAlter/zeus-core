//! Request/response correlation over one connection (02 section 6.1).
//!
//! The sender of a request picks its `id`; the response carries it in `re`. A [`RequestCorrelator`]
//! hands out ids (`e<counter>` for the extension, `d<counter>` for the daemon), registers a waiting
//! slot per request with its timeout, delivers a response to the right slot, and fails everything
//! outstanding when the connection closes. A request that is not answered in time is `nm.timeout`
//! (class `timeout`, retryable) and a late response is discarded.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::oneshot;

use crate::error::{SessionError, SessionResult};
use crate::protocol::MessageId;

/// Tracks outstanding requests whose response type is `T`.
#[derive(Debug)]
pub struct RequestCorrelator<T> {
    prefix: char,
    counter: AtomicU64,
    pending: Arc<Mutex<HashMap<MessageId, oneshot::Sender<SessionResult<T>>>>>,
}

/// A registered request waiting for its answer.
#[derive(Debug)]
pub struct PendingResponse<T> {
    id: MessageId,
    receiver: oneshot::Receiver<SessionResult<T>>,
    timeout: Duration,
    pending: Arc<Mutex<HashMap<MessageId, oneshot::Sender<SessionResult<T>>>>>,
}

impl<T: Send + 'static> RequestCorrelator<T> {
    /// A correlator minting ids `<prefix><n>` (`e` for the extension, `d` for the daemon).
    #[must_use]
    pub fn new(prefix: char) -> Self {
        Self {
            prefix,
            counter: AtomicU64::new(0),
            pending: Arc::new(Mutex::new(HashMap::new())),
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
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.retain(|_, sender| !sender.is_closed());
        if pending.contains_key(&id) {
            return Err(SessionError::DuplicateId);
        }
        if pending.len() >= 1024 {
            return Err(SessionError::Protocol("too many outstanding requests"));
        }
        let (sender, receiver) = oneshot::channel();
        pending.insert(id.clone(), sender);
        Ok(PendingResponse {
            id,
            receiver,
            timeout,
            pending: self.pending.clone(),
        })
    }

    /// Delivers a response to the waiting slot named by `re`. Returns false when nothing waits for it
    /// (a late or unsolicited response, to be discarded).
    pub fn resolve(&self, re: &MessageId, response: SessionResult<T>) -> bool {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(re)
            .is_some_and(|sender| sender.send(response).is_ok())
    }

    /// Fails every outstanding request, for example with [`SessionError::ConnectionLost`] when the
    /// connection closes.
    pub fn fail_all(&self, make_error: impl Fn() -> SessionError) {
        let pending = std::mem::take(
            &mut *self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for (_, sender) in pending {
            let _ = sender.send(Err(make_error()));
        }
    }

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
    pub async fn wait(mut self) -> SessionResult<T> {
        tokio::time::timeout(self.timeout, &mut self.receiver)
            .await
            .map_err(|_| SessionError::Timeout)?
            .map_err(|_| SessionError::ConnectionLost)?
    }
}

impl<T> Drop for PendingResponse<T> {
    fn drop(&mut self) {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.id);
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

#[cfg(test)]
mod runtime_tests {
    use super::*;
    #[tokio::test]
    async fn timeout_removes_slot_and_late_reply_is_discarded() {
        let correlator = RequestCorrelator::<u32>::new('d');
        let id = correlator.next_id();
        let pending = correlator
            .register(id.clone(), Duration::from_millis(1))
            .unwrap();
        assert!(matches!(pending.wait().await, Err(SessionError::Timeout)));
        assert_eq!(correlator.outstanding(), 0);
        assert!(!correlator.resolve(&id, Ok(1)));
    }
    #[tokio::test]
    async fn correlation_and_disconnect_have_no_cross_request_delivery() {
        let c = RequestCorrelator::<u32>::new('d');
        let a = c.next_id();
        let b = c.next_id();
        let first = c.register(a.clone(), Duration::from_secs(1)).unwrap();
        let second = c.register(b.clone(), Duration::from_secs(1)).unwrap();
        assert!(matches!(
            c.register(a, Duration::from_secs(1)),
            Err(SessionError::DuplicateId)
        ));
        assert!(c.resolve(&b, Ok(7)));
        assert_eq!(second.wait().await.unwrap(), 7);
        c.fail_all(|| SessionError::ConnectionLost);
        assert!(matches!(
            first.wait().await,
            Err(SessionError::ConnectionLost)
        ));
        assert_eq!(c.outstanding(), 0);
    }
}
