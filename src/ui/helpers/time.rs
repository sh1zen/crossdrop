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

/// Formats the current wall-clock time as `dd-mm-yyyy HH:MM` (UTC).
///
/// Used for transfer history records that need an absolute, human-readable
/// timestamp persisted to disk.
pub fn format_absolute_timestamp_now() -> String {
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = duration.as_secs();

    // Civil date computation from Unix timestamp (UTC)
    let days = (total_secs / 86400) as i64;
    let time_secs = total_secs % 86400;
    let hours = time_secs / 3600;
    let mins = (time_secs % 3600) / 60;

    // Days since 1970-01-01 → (year, month, day)
    // Algorithm from Howard Hinnant (public domain)
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{:02}-{:02}-{:04} {:02}:{:02}", d, m, y, hours, mins)
}

/// Formats elapsed time since an instant in human-readable format (Xs, Xm, Xh)
#[allow(dead_code)]
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

    #[test]
    fn test_format_absolute_timestamp_basic() {
        let ts = format_absolute_timestamp_now();
        // Should be dd-mm-yyyy HH:MM format
        assert_eq!(ts.len(), 16, "Timestamp should be 16 chars: {}", ts);
        assert_eq!(&ts[2..3], "-");
        assert_eq!(&ts[5..6], "-");
        assert_eq!(&ts[10..11], " ");
        assert_eq!(&ts[13..14], ":");
    }
}
