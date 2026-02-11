use std::time::{Instant, SystemTime};

/// Formats the current wall-clock time as an absolute `HH:MM` (UTC) string.
///
/// The timestamp is computed once at call time and stored — it is never
/// re-derived at render time.
pub fn format_timestamp_now() -> String {
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    format!("{:02}:{:02}", hours, mins)
}

/// Formats elapsed time since an instant in human-readable format (Xs, Xm, Xh)
pub fn format_elapsed(timestamp: Instant) -> String {
    let elapsed = timestamp.elapsed().as_secs();

    if elapsed < 60 {
        format!("{}s", elapsed)
    } else if elapsed < 3600 {
        format!("{}m", elapsed / 60)
    } else {
        format!("{}h", elapsed / 3600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_format_elapsed() {
        let now = Instant::now();

        // Seconds
        let past = now - Duration::from_secs(30);
        assert_eq!(format_elapsed(past), "30s");

        // Minutes
        let past = now - Duration::from_secs(120);
        assert_eq!(format_elapsed(past), "2m");

        // Hours
        let past = now - Duration::from_secs(7200);
        assert_eq!(format_elapsed(past), "2h");
    }
}
