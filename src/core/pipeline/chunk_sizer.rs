//! Adaptive chunk sizer — adjusts chunk size based on network throughput.
//!
//! Uses an exponential moving average (EMA) of measured throughput
//! (bytes/second) to decide whether to scale chunk size up or down.
//! Larger chunks reduce per-chunk overhead (framing, encryption, hashing)
//! but may cause more retransmissions on lossy links; smaller chunks are
//! more responsive but less efficient on clean links.
//!
//! # Algorithm
//!
//! After each batch of chunks is sent, the caller reports `(bytes, elapsed)`.
//! The sizer computes instantaneous throughput and updates the EMA.  If
//! throughput improved by ≥ `SCALE_UP_THRESHOLD`, chunk size doubles (up to
//! `MAX_CHUNK_SIZE`).  If throughput dropped by ≥ `SCALE_DOWN_THRESHOLD`,
//! chunk size halves (down to `MIN_CHUNK_SIZE`).  Otherwise it stays put.

use std::time::Duration;

use crate::core::config::{
    ADAPTIVE_CHUNK_SCALE_DOWN_THRESHOLD, ADAPTIVE_CHUNK_SCALE_UP_THRESHOLD, CHUNK_SIZE,
    MAX_CHUNK_SIZE, MIN_CHUNK_SIZE,
};

/// Adaptive chunk sizer that tracks throughput and adjusts chunk size.
#[allow(dead_code)]
pub struct AdaptiveChunkSizer {
    /// Current active chunk size in bytes.
    current_size: usize,
    /// Exponential moving average of throughput (bytes/sec).
    ema_throughput: Option<f64>,
    /// EMA smoothing factor (α).  Higher = more responsive.
    alpha: f64,
}

#[allow(dead_code)]
impl AdaptiveChunkSizer {
    /// Create a new sizer starting at the default `CHUNK_SIZE`.
    pub fn new() -> Self {
        // α = 2 / (N + 1) where N = ADAPTIVE_CHUNK_SAMPLE_WINDOW
        let n = crate::core::config::ADAPTIVE_CHUNK_SAMPLE_WINDOW as f64;
        Self {
            current_size: CHUNK_SIZE,
            ema_throughput: None,
            alpha: 2.0 / (n + 1.0),
        }
    }

    /// Current chunk size in bytes.
    pub fn chunk_size(&self) -> usize {
        self.current_size
    }

    /// Report a completed batch and let the sizer adjust.
    ///
    /// * `bytes_sent` — total payload bytes sent in this batch.
    /// * `elapsed` — wall-clock time the batch took.
    pub fn report(&mut self, bytes_sent: u64, elapsed: Duration) {
        let secs = elapsed.as_secs_f64();
        if secs <= 0.0 || bytes_sent == 0 {
            return;
        }

        let throughput = bytes_sent as f64 / secs;

        let prev_ema = self.ema_throughput.unwrap_or(throughput);
        let new_ema = self.alpha * throughput + (1.0 - self.alpha) * prev_ema;
        self.ema_throughput = Some(new_ema);

        // Skip scaling on the very first sample (no baseline yet)
        if prev_ema == throughput && self.ema_throughput.is_some() {
            return;
        }

        let ratio = new_ema / prev_ema;

        if ratio >= ADAPTIVE_CHUNK_SCALE_UP_THRESHOLD {
            let next = (self.current_size * 2).min(MAX_CHUNK_SIZE);
            if next != self.current_size {
                tracing::debug!(
                    event = "chunk_size_up",
                    from = self.current_size,
                    to = next,
                    ratio,
                    ema = new_ema,
                    "Scaling chunk size up"
                );
                self.current_size = next;
            }
        } else if ratio <= ADAPTIVE_CHUNK_SCALE_DOWN_THRESHOLD {
            let next = (self.current_size / 2).max(MIN_CHUNK_SIZE);
            if next != self.current_size {
                tracing::debug!(
                    event = "chunk_size_down",
                    from = self.current_size,
                    to = next,
                    ratio,
                    ema = new_ema,
                    "Scaling chunk size down"
                );
                self.current_size = next;
            }
        }
    }
}

impl Default for AdaptiveChunkSizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn starts_at_default_chunk_size() {
        let sizer = AdaptiveChunkSizer::new();
        assert_eq!(sizer.chunk_size(), CHUNK_SIZE);
    }

    #[test]
    fn scales_up_on_increasing_throughput() {
        let mut sizer = AdaptiveChunkSizer::new();
        // Start with moderate throughput baseline
        sizer.report(1 * 1024 * 1024, Duration::from_secs(1));
        // Then jump to much higher throughput
        for _ in 0..20 {
            sizer.report(500 * 1024 * 1024, Duration::from_millis(100));
        }
        assert!(sizer.chunk_size() > CHUNK_SIZE);
        assert!(sizer.chunk_size() <= MAX_CHUNK_SIZE);
    }

    #[test]
    fn scales_down_on_low_throughput() {
        let mut sizer = AdaptiveChunkSizer::new();
        // Start with moderate baseline, then jump to high to force scale up
        sizer.report(1 * 1024 * 1024, Duration::from_secs(1));
        for _ in 0..10 {
            sizer.report(500 * 1024 * 1024, Duration::from_millis(100));
        }
        let high_size = sizer.chunk_size();
        assert!(high_size > CHUNK_SIZE, "should scale up first");
        // Now report very low throughput
        for _ in 0..20 {
            sizer.report(1024, Duration::from_secs(1));
        }
        assert!(sizer.chunk_size() < high_size);
        assert!(sizer.chunk_size() >= MIN_CHUNK_SIZE);
    }

    #[test]
    fn never_exceeds_bounds() {
        let mut sizer = AdaptiveChunkSizer::new();
        // Hammer with extreme throughput
        for _ in 0..100 {
            sizer.report(1_000_000_000, Duration::from_millis(1));
        }
        assert!(sizer.chunk_size() <= MAX_CHUNK_SIZE);

        // Hammer with near-zero throughput
        for _ in 0..100 {
            sizer.report(1, Duration::from_secs(10));
        }
        assert!(sizer.chunk_size() >= MIN_CHUNK_SIZE);
    }

    #[test]
    fn stable_throughput_no_change() {
        let mut sizer = AdaptiveChunkSizer::new();
        let constant = 10 * 1024 * 1024u64; // 10 MB/s
        let dur = Duration::from_secs(1);
        // Prime the EMA
        sizer.report(constant, dur);
        let initial = sizer.chunk_size();
        // Keep reporting same throughput — should not change
        for _ in 0..20 {
            sizer.report(constant, dur);
        }
        assert_eq!(sizer.chunk_size(), initial);
    }

    #[test]
    fn zero_duration_ignored() {
        let mut sizer = AdaptiveChunkSizer::new();
        sizer.report(1024, Duration::ZERO);
        assert_eq!(sizer.chunk_size(), CHUNK_SIZE);
    }
}
