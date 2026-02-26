use tokio::fs;

pub(super) async fn read_dir_entries(path: &str) -> Vec<crate::workers::peer::RemoteEntry> {
    let mut entries = Vec::new();
    if let Ok(mut read_dir) = fs::read_dir(path).await {
        while let Ok(Some(entry)) = read_dir.next_entry().await {
            if let Ok(meta) = entry.metadata().await {
                entries.push(crate::workers::peer::RemoteEntry {
                    name: entry.file_name().to_string_lossy().into_owned(),
                    is_dir: meta.is_dir(),
                    size: meta.len(),
                });
            }
        }
    }
    entries
}
