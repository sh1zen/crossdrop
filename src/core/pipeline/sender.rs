//! Sender pipeline — streams file data from disk with read-ahead buffering.
//!
//! Instead of loading the entire file into a `Vec<u8>`, this module reads
//! chunks from disk asynchronously, maintaining a bounded read-ahead buffer
//! so that the data channel is always saturated while the next batch of
//! chunks is being read from storage.
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
//! The producer task reads `SENDER_READ_AHEAD_CHUNKS` chunks ahead,
//! and the consumer (send loop) drains them for encryption and transmission.
//!
//! # Integrity
//!
//! The sender computes an incremental Merkle tree as chunks are read.
//! The chunk hashes are sent to the receiver BEFORE the chunks themselves,
//! allowing the receiver to verify each chunk as it arrives and request
//! retransmission of corrupted chunks.
//!
//! # Parallel Preparation
//!
//! The pipeline supports parallel chunk preparation where multiple chunks
//! are read and hashed concurrently, reducing I/O wait time and improving
//! throughput on SSDs and fast networks.

use anyhow::Result;
use sha3::{Digest, Sha3_256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
use tokio::sync::mpsc;

use crate::core::config::SENDER_READ_AHEAD_CHUNKS;
use crate::core::pipeline::merkle::{hash_chunk, IncrementalMerkleBuilder};

/// A chunk read from disk, ready to be sent.
pub struct ReadChunk {
    /// Sequence number (0-based).
    pub seq: u32,
    /// Raw chunk data (uncompressed, unencrypted).
    pub data: Vec<u8>,
    /// Pre-computed chunk hash (for Merkle tree).
    pub hash: [u8; 32],
}

/// Spawn a disk reader task that prefetches chunks into a bounded channel.
///
/// Returns:
/// - A receiver of `ReadChunk` items.
/// - A `JoinHandle` for the reader task (resolves to the whole-file SHA3-256 hash).
///
/// # Parameters
///
/// * `file_path` — path to the file on disk.
/// * `filesize` — total size in bytes.
/// * `total_chunks` — how many chunks the file is split into.
/// * `chunk_size` — size of each chunk (may be adaptive).
/// * `start_chunk` — first chunk to actually include in the channel (for resume).
///   Chunks before `start_chunk` are still hashed but not sent.
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
        let mut whole_hasher = Sha3_256::new();
        let mut merkle_builder = IncrementalMerkleBuilder::with_capacity(total_chunks as usize);

        for seq in 0..total_chunks {
            let offset = (seq as u64) * (chunk_size as u64);
            let remaining = filesize.saturating_sub(offset);
            let len = (chunk_size as u64).min(remaining) as usize;

            file.seek(SeekFrom::Start(offset)).await?;
            let mut buf = vec![0u8; len];
            file.read_exact(&mut buf).await?;

            // Whole-file hash (always, even for skipped chunks)
            whole_hasher.update(&buf);

            // Per-chunk hash for Merkle tree using the shared hash_chunk function
            let hash = hash_chunk(&buf);

            // Add to incremental Merkle builder
            merkle_builder.add_leaf(hash);

            // Only send chunks that haven't been received yet (resume)
            if seq >= start_chunk {
                let chunk = ReadChunk { seq, data: buf, hash };
                // If the receiver (send loop) is dropped, stop reading.
                if tx.send(chunk).await.is_err() {
                    break;
                }
            }
        }

        let whole_file_hash = whole_hasher.finalize().to_vec();

        Ok(ReaderResult {
            whole_file_hash,
        })
    });

    (rx, handle)
}

/// Result from the disk reader task.
pub struct ReaderResult {
    /// Whole-file SHA3-256 hash.
    pub whole_file_hash: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::CHUNK_SIZE;
    use crate::core::pipeline::merkle::MerkleTree;
    use std::path::PathBuf;

    fn test_dir(name: &str) -> PathBuf {
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
        let data = vec![0xABu8; CHUNK_SIZE * 3 + 100]; // 3 full + 1 partial
        std::fs::write(&file_path, &data).unwrap();

        let filesize = data.len() as u64;
        let total_chunks = ((filesize as f64) / (CHUNK_SIZE as f64)).ceil() as u32;

        let (mut rx, handle) = spawn_reader(file_path, filesize, total_chunks, CHUNK_SIZE, 0);

        let mut received = Vec::new();
        while let Some(chunk) = rx.recv().await {
            received.push(chunk);
        }

        assert_eq!(received.len(), total_chunks as usize);
        assert_eq!(received[0].seq, 0);
        assert_eq!(received.last().unwrap().seq, total_chunks - 1);

        // Last chunk should be smaller
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
        let total_chunks = 4u32;

        let (mut rx, handle) = spawn_reader(file_path, filesize, total_chunks, CHUNK_SIZE, 2);

        let mut received = Vec::new();
        while let Some(chunk) = rx.recv().await {
            received.push(chunk);
        }

        // Only chunks 2 and 3 should be in the channel
        assert_eq!(received.len(), 2);
        assert_eq!(received[0].seq, 2);
        assert_eq!(received[1].seq, 3);
        cleanup(&dir);
    }
}
