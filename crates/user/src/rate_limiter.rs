use std::time::Instant;

use crate::normalize::NormalizedEvent;

pub struct RateLimiter {
    max_per_second: u32,
    window_start: Instant,
    count: u32,
}

impl RateLimiter {
    pub fn new(max_per_second: u32) -> Self {
        Self {
            max_per_second,
            window_start: Instant::now(),
            count: 0,
        }
    }

    pub fn allow(&mut self, event: &NormalizedEvent) -> bool {
        if is_process_lifecycle(event) {
            return true;
        }

        let now = Instant::now();
        if now.duration_since(self.window_start).as_secs() >= 1 {
            self.window_start = now;
            self.count = 0;
        }

        if self.count < self.max_per_second {
            self.count += 1;
            true
        } else {
            false
        }
    }
}

fn is_process_lifecycle(event: &NormalizedEvent) -> bool {
    matches!(
        event,
        NormalizedEvent::ProcessStart(_)
            | NormalizedEvent::ProcessExit(_)
            | NormalizedEvent::ProcessRelationship(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::{ProcessExit, ProcessStart};

    fn sample_process_start() -> NormalizedEvent {
        NormalizedEvent::ProcessStart(ProcessStart {
            pid: 1,
            tid: 1,
            ppid: 0,
            uid: 1000,
            gid: 1000,
            comm: "sh".to_string(),
            exe_path: "/bin/sh".to_string(),
            source: None,
            timestamp_ns: 1000,
            filename_truncated: false,
        })
    }

    fn sample_process_exit() -> NormalizedEvent {
        NormalizedEvent::ProcessExit(ProcessExit {
            pid: 1,
            tid: 1,
            comm: "sh".to_string(),
            group_dead: true,
            uid: 1000,
            gid: 1000,
            timestamp_ns: 2000,
        })
    }

    fn sample_file_open() -> NormalizedEvent {
        NormalizedEvent::FileOpen(crate::normalize::FileOpen {
            pid: 1,
            tid: 1,
            ppid: 0,
            uid: 1000,
            gid: 1000,
            comm: "cat".to_string(),
            exe_path: "/bin/cat".to_string(),
            filename: "/etc/passwd".to_string(),
            flags: 0,
            filename_truncated: false,
            alert: false,
            detection_type: None,
            timestamp_ns: 3000,
        })
    }

    #[test]
    fn process_lifecycle_always_allowed() {
        let mut limiter = RateLimiter::new(0);
        assert!(limiter.allow(&sample_process_start()));
        assert!(limiter.allow(&sample_process_exit()));
    }

    #[test]
    fn non_lifecycle_within_limit_allowed() {
        let mut limiter = RateLimiter::new(2);
        assert!(limiter.allow(&sample_file_open()));
        assert!(limiter.allow(&sample_file_open()));
    }

    #[test]
    fn non_lifecycle_over_limit_rejected() {
        let mut limiter = RateLimiter::new(1);
        assert!(limiter.allow(&sample_file_open()));
        assert!(!limiter.allow(&sample_file_open()));
    }

    #[test]
    fn process_lifecycle_does_not_consume_budget() {
        let mut limiter = RateLimiter::new(1);
        assert!(limiter.allow(&sample_process_start()));
        assert!(limiter.allow(&sample_file_open()));
        assert!(!limiter.allow(&sample_file_open()));
    }
}
