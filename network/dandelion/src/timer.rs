//! Safety timeout mechanisms

use std::time::{Duration, Instant};

/// Tracks timeout state
#[derive(Clone, Debug)]
pub struct TimeoutTracker {
    started: Instant,
    timeout: Duration,
}

impl TimeoutTracker {
    pub fn new(timeout: Duration) -> Self {
        Self {
            started: Instant::now(),
            timeout,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.started.elapsed() > self.timeout
    }

    pub fn remaining(&self) -> Duration {
        self.timeout.saturating_sub(self.started.elapsed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_not_expired() {
        let tracker = TimeoutTracker::new(Duration::from_secs(10));
        assert!(!tracker.is_expired());
    }

    #[test]
    fn test_timeout_expired() {
        let mut tracker = TimeoutTracker::new(Duration::from_millis(100));
        tracker.started = Instant::now() - Duration::from_secs(1);
        assert!(tracker.is_expired());
    }

    #[test]
    fn test_remaining_time() {
        let tracker = TimeoutTracker::new(Duration::from_secs(10));
        let remaining = tracker.remaining();
        assert!(remaining > Duration::from_secs(9));
        assert!(remaining <= Duration::from_secs(10));
    }
}