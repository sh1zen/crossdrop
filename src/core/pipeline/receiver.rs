//! Streaming file receiver with bounded memory usage.
//!
//! Writes received chunks directly to a temporary file on disk via
//! positional seek+write, avoiding the previous full-file in-memory buffer
//! that was vulnerable to DoS (a malicious peer could claim an arbitrarily
//! large `filesize` in the Metadata frame and force a huge allocation).
//!
//! # Memory model
//!
//! Per-file memory usage is O(total_chunks × 32 bytes) for Merkle hashes
//! plus a small `ChunkBitmap`.  The file data itself lives entirely on disk
//! in a sparse temporary file.
//!
//! # Concurrency
//!
//! Each `StreamingFileWriter` is independent — multiple instances can run
//! in parallel for different file IDs, enabling concurrent multi-file
//! reception from multiple peers without shared buffer contention.

use anyhow::{anyhow, Result};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};
use tracing::warn;

use crate::core::config::{CHUNK_SIZE, RECEIVER_WRITE_BUFFER_CHUNKS};
use crate::core::pipeline::chunk::ChunkBitmap;
use crate::core::pipeline::merkle::MerkleTree;

/// Read-back buffer size used when computing the whole-file SHA3-256 hash
/// during finalization.  256 KB keeps memory bounded while providing good
/// sequential-read throughput.
const HASH_READ_BUFFER: usize = 256 * 1024;

/// Streaming file writer that writes received chunks directly to a temporary
/// file on disk, avoiding full-file memory allocation.
///
/// # Memory model
///
/// - Creates a sparse temp file — no upfront physical disk allocation.
/// - Memory per file: O(total_chunks × 32) for per-chunk hashes + bitmap.
/// - File data is never held in RAM; chunks are written directly to disk.
///
/// # Duplicate-chunk safety
///
/// A [`ChunkBitmap`] tracks which chunks have been received.  Duplicate
/// chunks (e.g. from sender retries) are silently ignored, preventing the
/// `received_chunks` counter from being inflated.
pub struct StreamingFileWriter {
    file: fs::File,
    temp_path: PathBuf,
    final_path: PathBuf,
    filesize: u64,
    total_chunks: u32,
    received_chunks: u32,
    chunk_hashes: Vec<Option<[u8; 32]>>,
    bitmap: ChunkBitmap,
    filename: String,
    /// In-memory write buffer: seq → chunk data.
    /// Chunks accumulate here and are flushed to disk in sequential runs
    /// or when the buffer reaches `RECEIVER_WRITE_BUFFER_CHUNKS` capacity.
    write_buffer: BTreeMap<u32, Vec<u8>>,
    /// Next sequential chunk expected for a contiguous flush.
    /// Tracks how far we've flushed sequentially to enable run coalescing.
    next_flush_seq: u32,
}

/// Result of finalizing a streaming file receive.
///
/// Holds computed integrity data and paths.  The caller inspects
/// [`sha3_256`] / [`merkle_root`] and then calls either [`commit`]
/// (atomic rename to final path) or [`abort`] (delete temp file).
pub struct FinalizedFile {
    /// SHA3-256 hash of the complete file (read back from disk).
    pub sha3_256: Vec<u8>,
    /// Merkle root computed from per-chunk SHA3-256 hashes.
    pub merkle_root: [u8; 32],
    /// Original filename from the sender's Metadata frame.
    pub filename: String,
    /// Total file size in bytes.
    pub filesize: u64,
    temp_path: PathBuf,
    final_path: PathBuf,
}

impl StreamingFileWriter {
    /// Create a new streaming writer.
    ///
    /// A sparse temporary file is created at `<save_path>.crossdrop-tmp`.
    /// The caller is responsible for computing `save_path` (including
    /// path sanitization).
    ///
    /// # Errors
    ///
    /// Returns an error if the temp file cannot be created.
    pub async fn new(
        filename: String,
        filesize: u64,
        total_chunks: u32,
        save_path: PathBuf,
    ) -> Result<Self> {
        // Build temp path: append ".crossdrop-tmp" to the full filename
        let temp_path = {
            let mut name = save_path.as_os_str().to_owned();
            name.push(".crossdrop-tmp");
            PathBuf::from(name)
        };

        // Ensure parent directory exists
        if let Some(parent) = temp_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Create temp file — sparse on NTFS / ext4 / APFS
        let file = fs::OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)
            .await?;

        // Pre-allocate logical size (no physical blocks allocated for
        // unwritten regions on sparse-capable filesystems).
        file.set_len(filesize).await?;

        Ok(Self {
            file,
            temp_path,
            final_path: save_path,
            filesize,
            total_chunks,
            received_chunks: 0,
            chunk_hashes: vec![None; total_chunks as usize],
            bitmap: ChunkBitmap::new(total_chunks),
            filename,
            write_buffer: BTreeMap::new(),
            next_flush_seq: 0,
        })
    }

    /// Accept a chunk: validate, hash, buffer in memory, and flush when
    /// a sequential run is ready or the buffer reaches capacity.
    ///
    /// Duplicate chunks (same `seq` already received) are silently skipped.
    ///
    /// # Errors
    ///
    /// Returns an error if `seq >= total_chunks` or the chunk data would
    /// extend past the declared file size.
    pub async fn write_chunk(&mut self, seq: u32, data: &[u8]) -> Result<()> {
        if seq >= self.total_chunks {
            return Err(anyhow!(
                "Chunk seq {} >= total_chunks {}",
                seq,
                self.total_chunks
            ));
        }

        // Idempotent: skip duplicate chunks
        if self.bitmap.is_set(seq) {
            return Ok(());
        }

        let offset = (seq as u64) * (CHUNK_SIZE as u64);
        let end = offset + data.len() as u64;
        if end > self.filesize {
            return Err(anyhow!(
                "Chunk {} extends past file end ({} > {})",
                seq,
                end,
                self.filesize
            ));
        }

        // Per-chunk SHA3-256 hash for incremental Merkle tree
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let mut h = [0u8; 32];
        h.copy_from_slice(&hasher.finalize());
        self.chunk_hashes[seq as usize] = Some(h);

        self.bitmap.set(seq);
        self.received_chunks += 1;

        // Buffer the chunk data
        self.write_buffer.insert(seq, data.to_vec());

        // Flush strategy: flush a sequential run starting at next_flush_seq,
        // or force-flush everything if buffer is at capacity.
        if seq == self.next_flush_seq || self.write_buffer.len() >= RECEIVER_WRITE_BUFFER_CHUNKS {
            self.flush_buffer().await?;
        }

        Ok(())
    }

    /// Flush buffered chunks to disk.
    ///
    /// First, drains any contiguous run starting at `next_flush_seq` and
    /// writes them as a single coalesced I/O.  If the buffer is still at
    /// or above capacity after that, force-flushes remaining chunks
    /// individually (out-of-order stragglers).
    async fn flush_buffer(&mut self) -> Result<()> {
        // Phase 1: drain sequential run from next_flush_seq
        while let Some(data) = self.write_buffer.remove(&self.next_flush_seq) {
            let offset = (self.next_flush_seq as u64) * (CHUNK_SIZE as u64);
            self.file.seek(SeekFrom::Start(offset)).await?;
            self.file.write_all(&data).await?;
            self.next_flush_seq += 1;
        }

        // Phase 2: if still over capacity, flush remaining chunks individually
        if self.write_buffer.len() >= RECEIVER_WRITE_BUFFER_CHUNKS {
            let seqs: Vec<u32> = self.write_buffer.keys().copied().collect();
            for seq in seqs {
                if let Some(data) = self.write_buffer.remove(&seq) {
                    let offset = (seq as u64) * (CHUNK_SIZE as u64);
                    self.file.seek(SeekFrom::Start(offset)).await?;
                    self.file.write_all(&data).await?;
                }
            }
        }

        Ok(())
    }

    /// Number of unique chunks received so far.
    pub fn received_chunks(&self) -> u32 {
        self.received_chunks
    }

    /// Total expected chunk count.
    pub fn total_chunks(&self) -> u32 {
        self.total_chunks
    }

    /// Original filename from the sender's Metadata frame.
    pub fn filename(&self) -> &str {
        &self.filename
    }

    /// Finalize the receive: flush any remaining buffered chunks, then
    /// read back the full file to compute the whole-file SHA3-256 hash,
    /// and build the Merkle root from per-chunk hashes.
    ///
    /// Returns a [`FinalizedFile`] that can be committed or aborted.
    pub async fn finalize(mut self) -> Result<FinalizedFile> {
        // Flush any chunks still sitting in the write buffer
        let remaining: Vec<(u32, Vec<u8>)> = self.write_buffer.into_iter().collect();
        self.write_buffer = BTreeMap::new();
        for (seq, data) in remaining {
            let offset = (seq as u64) * (CHUNK_SIZE as u64);
            self.file.seek(SeekFrom::Start(offset)).await?;
            self.file.write_all(&data).await?;
        }

        // Ensure all data reaches physical media
        self.file.flush().await?;
        self.file.sync_all().await?;

        // Read back entire file to compute SHA3-256
        self.file.seek(SeekFrom::Start(0)).await?;
        let mut hasher = Sha3_256::new();
        let mut buf = vec![0u8; HASH_READ_BUFFER];
        loop {
            let n = self.file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let sha3_hash = hasher.finalize().to_vec();

        // Build Merkle root from incrementally collected chunk hashes
        let all_present = self.chunk_hashes.iter().all(|h| h.is_some());
        let merkle_root = if all_present && !self.chunk_hashes.is_empty() {
            let leaves: Vec<[u8; 32]> = self.chunk_hashes.iter().map(|h| h.unwrap()).collect();
            *MerkleTree::build(&leaves).root()
        } else {
            [0u8; 32]
        };

        // File handle dropped when `self` is destructured below
        Ok(FinalizedFile {
            sha3_256: sha3_hash,
            merkle_root,
            filename: self.filename,
            filesize: self.filesize,
            temp_path: self.temp_path,
            final_path: self.final_path,
        })
    }

    /// Abort the receive: close the file handle and delete the temp file.
    #[allow(dead_code)]
    pub async fn abort(self) {
        let Self {
            file, temp_path, ..
        } = self;
        drop(file); // Close handle first (required on Windows)
        if let Err(e) = fs::remove_file(&temp_path).await {
            warn!(
                event = "recv_abort_cleanup_failed",
                path = %temp_path.display(),
                error = %e,
                "Failed to clean up temp file on abort"
            );
        }
    }
}

impl FinalizedFile {
    /// Atomically commit the received file to its final destination.
    ///
    /// Creates parent directories if needed, then renames the temp file.
    pub async fn commit(self) -> Result<PathBuf> {
        if let Some(parent) = self.final_path.parent() {
            if !parent.exists() {
                let _ = fs::create_dir_all(parent).await;
            }
        }
        fs::rename(&self.temp_path, &self.final_path)
            .await
            .map_err(|e| {
                // Attempt cleanup on rename failure
                let tp = self.temp_path.clone();
                tokio::spawn(async move {
                    let _ = fs::remove_file(&tp).await;
                });
                anyhow!("Failed to rename temp file to final path: {}", e)
            })?;
        Ok(self.final_path)
    }

    /// Abort: delete the temporary file without committing.
    pub async fn abort(self) {
        let _ = fs::remove_file(&self.temp_path).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Helper: create a temp directory for test files.
    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("crossdrop_test").join(name);
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    /// Helper: clean up test directory.
    fn cleanup(path: &Path) {
        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn test_streaming_writer_basic() {
        let dir = test_dir("streaming_basic");
        let save_path = dir.join("test_file.bin");

        // 3 chunks, ~144KB file (3 × 48KB)
        let filesize = (CHUNK_SIZE * 3) as u64;
        let total_chunks = 3u32;

        let mut writer =
            StreamingFileWriter::new("test_file.bin".into(), filesize, total_chunks, save_path)
                .await
                .unwrap();

        // Write chunks out of order
        let chunk0 = vec![0xAAu8; CHUNK_SIZE];
        let chunk2 = vec![0xCCu8; CHUNK_SIZE];
        let chunk1 = vec![0xBBu8; CHUNK_SIZE];

        writer.write_chunk(2, &chunk2).await.unwrap();
        writer.write_chunk(0, &chunk0).await.unwrap();
        writer.write_chunk(1, &chunk1).await.unwrap();

        assert_eq!(writer.received_chunks(), 3);
        assert_eq!(writer.total_chunks(), 3);

        // Finalize
        let finalized = writer.finalize().await.unwrap();

        // Verify hash matches expected
        let mut expected_data = Vec::new();
        expected_data.extend_from_slice(&chunk0);
        expected_data.extend_from_slice(&chunk1);
        expected_data.extend_from_slice(&chunk2);
        let mut hasher = Sha3_256::new();
        hasher.update(&expected_data);
        let expected_hash = hasher.finalize().to_vec();

        assert_eq!(finalized.sha3_256, expected_hash);
        assert_eq!(finalized.filename, "test_file.bin");
        assert_eq!(finalized.filesize, filesize);

        // Commit
        let path = finalized.commit().await.unwrap();
        assert!(path.exists());

        // Verify file content
        let content = std::fs::read(&path).unwrap();
        assert_eq!(content, expected_data);

        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_streaming_writer_duplicate_chunks() {
        let dir = test_dir("streaming_dup");
        let save_path = dir.join("dup_test.bin");

        let filesize = (CHUNK_SIZE * 2) as u64;
        let mut writer =
            StreamingFileWriter::new("dup_test.bin".into(), filesize, 2, save_path)
                .await
                .unwrap();

        let chunk = vec![0x42u8; CHUNK_SIZE];

        writer.write_chunk(0, &chunk).await.unwrap();
        assert_eq!(writer.received_chunks(), 1);

        // Duplicate — should be skipped
        writer.write_chunk(0, &chunk).await.unwrap();
        assert_eq!(writer.received_chunks(), 1); // NOT 2

        writer.write_chunk(1, &chunk).await.unwrap();
        assert_eq!(writer.received_chunks(), 2);

        writer.abort().await;
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_streaming_writer_out_of_bounds() {
        let dir = test_dir("streaming_oob");
        let save_path = dir.join("oob_test.bin");

        let filesize = CHUNK_SIZE as u64;
        let mut writer =
            StreamingFileWriter::new("oob_test.bin".into(), filesize, 1, save_path)
                .await
                .unwrap();

        // seq beyond total_chunks
        let result = writer.write_chunk(5, &[0u8; 100]).await;
        assert!(result.is_err());

        writer.abort().await;
        cleanup(&dir);
    }


    #[tokio::test]
    async fn test_streaming_writer_abort_cleanup() {
        let dir = test_dir("streaming_abort");
        let save_path = dir.join("abort_test.bin");

        let writer = StreamingFileWriter::new(
            "abort_test.bin".into(),
            CHUNK_SIZE as u64,
            1,
            save_path.clone(),
        )
        .await
        .unwrap();

        // Temp file should exist
        let temp_path = {
            let mut name = save_path.as_os_str().to_owned();
            name.push(".crossdrop-tmp");
            PathBuf::from(name)
        };
        assert!(temp_path.exists());

        writer.abort().await;

        // Temp file should be cleaned up
        assert!(!temp_path.exists());
        // Final file should NOT exist
        assert!(!save_path.exists());

        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_streaming_writer_last_chunk_smaller() {
        let dir = test_dir("streaming_last");
        let save_path = dir.join("partial.bin");

        // File is 1.5 chunks: 48KB + 24KB = 72KB
        let filesize = (CHUNK_SIZE + CHUNK_SIZE / 2) as u64;
        let total_chunks = 2u32;

        let mut writer =
            StreamingFileWriter::new("partial.bin".into(), filesize, total_chunks, save_path)
                .await
                .unwrap();

        let chunk0 = vec![0xAAu8; CHUNK_SIZE];
        let chunk1 = vec![0xBBu8; CHUNK_SIZE / 2]; // Last chunk is smaller

        writer.write_chunk(0, &chunk0).await.unwrap();
        writer.write_chunk(1, &chunk1).await.unwrap();

        let finalized = writer.finalize().await.unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&chunk0);
        expected.extend_from_slice(&chunk1);
        // The sparse file has zero-fill for the remaining bytes
        expected.resize(filesize as usize, 0);

        let mut hasher = Sha3_256::new();
        hasher.update(&expected);
        let expected_hash = hasher.finalize().to_vec();

        assert_eq!(finalized.sha3_256, expected_hash);
        assert_eq!(finalized.filesize, filesize);

        let path = finalized.commit().await.unwrap();
        let content = std::fs::read(&path).unwrap();
        assert_eq!(content.len(), filesize as usize);

        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_merkle_root_consistency() {
        let dir = test_dir("streaming_merkle");
        let save_path = dir.join("merkle_test.bin");

        let filesize = (CHUNK_SIZE * 2) as u64;
        let mut writer =
            StreamingFileWriter::new("merkle_test.bin".into(), filesize, 2, save_path)
                .await
                .unwrap();

        let chunk0 = vec![0x11u8; CHUNK_SIZE];
        let chunk1 = vec![0x22u8; CHUNK_SIZE];

        writer.write_chunk(0, &chunk0).await.unwrap();
        writer.write_chunk(1, &chunk1).await.unwrap();

        let finalized = writer.finalize().await.unwrap();

        // Manually compute expected Merkle root
        let mut h0 = Sha3_256::new();
        h0.update(&chunk0);
        let mut hash0 = [0u8; 32];
        hash0.copy_from_slice(&h0.finalize());

        let mut h1 = Sha3_256::new();
        h1.update(&chunk1);
        let mut hash1 = [0u8; 32];
        hash1.copy_from_slice(&h1.finalize());

        let expected_root = *MerkleTree::build(&[hash0, hash1]).root();
        assert_eq!(finalized.merkle_root, expected_root);

        finalized.abort().await;
        cleanup(&dir);
    }
}
