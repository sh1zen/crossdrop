//! Sender pipeline — streams file data from disk with read-ahead buffering.
//!
//! Instead of loading the entire file into memory, this module reads chunks
//! asynchronously and maintains a bounded read-ahead channel so the data
//! channel stays saturated while the next batch is being read from storage.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────┐   prefetch_tx   ┌─────────────────────┐
//! │ DiskRead │ ───────────────►│ Send loop           │──► WebRTC DC
//! │ (async)  │   bounded chan  │ (brotli+encrypt+tx) │
//! └──────────┘                 └─────────────────────┘
//! ```
//!
//! The producer task reads `SENDER_READ_AHEAD_CHUNKS` chunks ahead; the
//! consumer (send loop) drains them for encryption and transmission.
//!
//! # Integrity
//!
//! Chunk hashes are sent to the receiver BEFORE the chunks themselves,
//! enabling per-chunk verification and targeted retransmission of corrupted chunks.

use crate::core::config::SENDER_READ_AHEAD_CHUNKS;
use crate::core::pipeline::merkle::{hash_chunk, IncrementalMerkleBuilder};
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
use tokio::sync::mpsc;

// ── Public types ───────────────────────────────────────────────────────────────

/// A chunk read from disk, ready to be processed and sent.
pub struct ReadChunk {
    /// 0-based sequence number.
    pub seq: u32,
    /// Raw (uncompressed, unencrypted) chunk data.
    pub data: Vec<u8>,
    /// Pre-computed SHA3-256 hash for the Merkle tree.
    pub hash: [u8; 32],
}

/// Aggregated output from the disk reader task.
pub struct ReaderResult;

// ── Reader ─────────────────────────────────────────────────────────────────────

/// Spawn a disk reader that prefetches chunks into a bounded channel.
///
/// Returns a `(Receiver<ReadChunk>, JoinHandle<Result<ReaderResult>>)` pair.
/// Chunks before `start_chunk` are still hashed for correctness but not sent.
///
/// # Parameters
///
/// * `file_path`    — path to the source file.
/// * `filesize`     — total size in bytes.
/// * `total_chunks` — number of chunks the file is divided into.
/// * `chunk_size`   — nominal chunk size (the last chunk may be smaller).
/// * `start_chunk`  — first chunk to place in the channel (for resume).
pub fn spawn_reader(
    file_path: std::path::PathBuf,
    filesize: u64,
    total_chunks: u32,
    chunk_size: usize,
    start_chunk: u32,
) -> (
    mpsc::Receiver<ReadChunk>,
    tokio::task::JoinHandle<Result<ReaderResult>>,
) {
    let (tx, rx) = mpsc::channel(SENDER_READ_AHEAD_CHUNKS);

    let handle = tokio::spawn(async move {
        let mut file = tokio::fs::File::open(&file_path).await?;
        let mut merkle_builder = IncrementalMerkleBuilder::with_capacity(total_chunks as usize);

        for seq in 0..total_chunks {
            let offset = seq as u64 * chunk_size as u64;
            let len = (chunk_size as u64).min(filesize.saturating_sub(offset)) as usize;

            file.seek(SeekFrom::Start(offset)).await?;
            let mut buf = vec![0u8; len];
            file.read_exact(&mut buf).await?;

            let hash = hash_chunk(&buf);
            merkle_builder.add_leaf(hash);

            if seq >= start_chunk {
                // Stop if the consumer (send loop) has been dropped.
                if tx
                    .send(ReadChunk {
                        seq,
                        data: buf,
                        hash,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }

        Ok(ReaderResult)
    });

    (rx, handle)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::CHUNK_SIZE;

    fn test_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join("crossdrop_test")
            .join("sender")
            .join(name);
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    fn cleanup(path: &std::path::Path) {
        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn reader_produces_all_chunks() {
        let dir = test_dir("reader_all");
        let file_path = dir.join("test.bin");
        let data = vec![0xABu8; CHUNK_SIZE * 3 + 100];
        std::fs::write(&file_path, &data).unwrap();

        let filesize = data.len() as u64;
        let total_chunks = filesize.div_ceil(CHUNK_SIZE as u64) as u32;

        let (mut rx, _handle) = spawn_reader(file_path, filesize, total_chunks, CHUNK_SIZE, 0);

        let mut received = Vec::new();
        while let Some(chunk) = rx.recv().await {
            received.push(chunk);
        }

        assert_eq!(received.len(), total_chunks as usize);
        assert_eq!(received[0].seq, 0);
        assert_eq!(received.last().unwrap().seq, total_chunks - 1);
        assert_eq!(received.last().unwrap().data.len(), 100);

        cleanup(&dir);
    }

    #[tokio::test]
    async fn reader_skips_chunks_for_resume() {
        let dir = test_dir("reader_resume");
        let file_path = dir.join("resume.bin");
        let data = vec![0xCDu8; CHUNK_SIZE * 4];
        std::fs::write(&file_path, &data).unwrap();

        let filesize = data.len() as u64;
        let (mut rx, _handle) = spawn_reader(file_path, filesize, 4, CHUNK_SIZE, 2);

        let mut received = Vec::new();
        while let Some(chunk) = rx.recv().await {
            received.push(chunk);
        }

        assert_eq!(received.len(), 2);
        assert_eq!(received[0].seq, 2);
        assert_eq!(received[1].seq, 3);

        cleanup(&dir);
    }
}
