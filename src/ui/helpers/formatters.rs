use crate::workers::app::App;

/// Converts bytes to human-readable file size format
pub fn format_file_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Shortens peer ID to first 12 characters
pub fn short_peer_id(id: &str) -> String {
    if id.len() > 12 {
        id[..12].to_string()
    } else {
        id.to_string()
    }
}

/// Gets display name for a peer, falling back to shortened ID
pub fn get_display_name(app: &App, id: &str) -> String {
    app.peers.names
        .get(id)
        .cloned()
        .unwrap_or_else(|| short_peer_id(id))
}

/// Truncates filename to max length with ellipsis
pub fn truncate_filename(name: &str, max_len: usize) -> String {
    if name.len() <= max_len {
        name.to_string()
    } else if max_len <= 3 {
        "...".to_string()
    } else {
        format!("{}...", &name[..max_len - 3])
    }
}

/// Formats cipher key as hex with ellipsis for display
pub fn format_cipher_key(key: &[u8; 32]) -> String {
    let hex = hex::encode(key);
    // Show first 8 and last 4 characters: "12345678...cdef"
    format!("{}...{}", &hex[..8], &hex[hex.len() - 4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_file_size() {
        assert_eq!(format_file_size(0), "0 B");
        assert_eq!(format_file_size(512), "512 B");
        assert_eq!(format_file_size(1024), "1.00 KB");
        assert_eq!(format_file_size(1536), "1.50 KB");
        assert_eq!(format_file_size(1048576), "1.00 MB");
        assert_eq!(format_file_size(1073741824), "1.00 GB");
    }

    #[test]
    fn test_short_peer_id() {
        assert_eq!(short_peer_id("abc"), "abc");
        assert_eq!(short_peer_id("abcdefghijkl"), "abcdefghijkl");
        assert_eq!(short_peer_id("abcdefghijklmnopqrstuvwxyz"), "abcdefghijkl");
    }

    #[test]
    fn test_truncate_filename() {
        assert_eq!(truncate_filename("short.txt", 20), "short.txt");
        assert_eq!(truncate_filename("verylongfilename.txt", 10), "verylon...");
        assert_eq!(truncate_filename("test", 2), "...");
    }
}
