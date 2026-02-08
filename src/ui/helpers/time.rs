use std::time::Instant;

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
