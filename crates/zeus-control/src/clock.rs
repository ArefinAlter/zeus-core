//! Injectable time (00 section 6): a wall clock for instants that survive restarts, and a monotonic
//! clock for measuring elapsed time. Production code takes `Arc<dyn Clock>`; tests use [`ManualClock`].

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use zeus_types::Timestamp;

/// A source of time.
///
/// `monotonic()` is measured from an arbitrary origin fixed when the clock was created; only
/// differences between two readings of the *same* clock are meaningful. Never subtract wall-clock
/// instants to measure elapsed time (00 section 6.2).
pub trait Clock: Send + Sync + fmt::Debug {
    /// The current wall-clock instant, for display, absolute deadlines and cross-process ordering.
    fn now(&self) -> Timestamp;

    /// Elapsed monotonic time since the clock's origin. Never decreases.
    fn monotonic(&self) -> Duration;
}

/// A shareable clock.
pub type SharedClock = Arc<dyn Clock>;

/// The operating system's clocks.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// A clock whose monotonic origin is now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }

    fn monotonic(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// A clock that only moves when told to, for deterministic tests. Cloning shares the same time.
#[derive(Debug, Clone)]
pub struct ManualClock {
    state: Arc<Mutex<ManualState>>,
}

#[derive(Debug)]
struct ManualState {
    wall: Timestamp,
    monotonic: Duration,
}

impl ManualClock {
    /// A manual clock showing `start` and a monotonic reading of zero.
    #[must_use]
    pub fn new(start: Timestamp) -> Self {
        Self {
            state: Arc::new(Mutex::new(ManualState {
                wall: start,
                monotonic: Duration::ZERO,
            })),
        }
    }

    /// Advances both the wall clock and the monotonic clock. The wall clock saturates at the
    /// largest representable instant.
    pub fn advance(&self, by: Duration) {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        s.wall = s.wall.checked_add(by).unwrap_or(s.wall);
        s.monotonic += by;
    }

    /// Moves only the wall clock (a manual clock step, possibly backwards); the monotonic clock is
    /// unaffected, as on a real system.
    pub fn set_wall(&self, to: Timestamp) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .wall = to;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Timestamp {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .wall
    }

    fn monotonic(&self) -> Duration {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .monotonic
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_moves_only_when_told() {
        let start = Timestamp::parse("2026-10-05T09:00:00.000Z").unwrap();
        let clock = ManualClock::new(start);
        assert_eq!(clock.now(), start);
        assert_eq!(clock.monotonic(), Duration::ZERO);
        let shared = clock.clone();
        clock.advance(Duration::from_millis(1500));
        assert_eq!(shared.now().to_string(), "2026-10-05T09:00:01.500Z");
        assert_eq!(shared.monotonic(), Duration::from_millis(1500));
    }

    #[test]
    fn wall_clock_steps_do_not_touch_the_monotonic_clock() {
        let start = Timestamp::parse("2026-10-05T09:00:00.000Z").unwrap();
        let clock = ManualClock::new(start);
        clock.advance(Duration::from_secs(10));
        clock.set_wall(start);
        assert_eq!(clock.now(), start);
        assert_eq!(clock.monotonic(), Duration::from_secs(10));
    }

    #[test]
    fn system_clock_is_monotonic() {
        let clock = SystemClock::new();
        let a = clock.monotonic();
        let b = clock.monotonic();
        assert!(b >= a);
        assert!(clock.now().unix_millis() > 1_700_000_000_000);
    }
}
