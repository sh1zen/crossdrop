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
//! # Incremental Integrity Verification
//!
//! The receiver receives chunk hashes from the sender BEFORE chunks arrive.
//! As each chunk arrives, the receiver:
//! 1. Computes the chunk's SHA3-256 hash
//! 2. Compares it against the expected hash from the Merkle tree
//! 3. If mismatch, the chunk is marked as failed and can be requested for retransmission
//!
//! This enables early detection of corruption and targeted retransmission.
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

use crate::core::config::{CHUNK_SIZE, HASH_READ_BUFFER, RECEIVER_WRITE_BUFFER_CHUNKS};
use crate::core::pipeline::chunk::ChunkBitmap;
use crate::core::pipeline::merkle::{ChunkHashVerifier, ChunkVerificationError, MerkleTree};


/// Result of writing a chunk to the streaming file writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkWriteResult {
    /// Chunk was written successfully.
    Written(ChunkVerificationStatus),
    /// Chunk was a duplicate and skipped.
    Duplicate,
}

/// Status of chunk verification during write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkVerificationStatus {
    /// Chunk hash verified successfully against expected hash.
    Verified,
    /// Chunk hash did not match expected hash (corruption detected).
    HashMismatch,
    /// Chunk sequence number was invalid.
    InvalidSequence,
    /// No verifier was set, chunk accepted without verification.
    NoVerifier,
}

/// Streaming file writer that writes received chunks directly to a temporary
/// file on disk, avoiding full-file memory allocation.
///
/// # Memory model
///
/// - Creates a sparse temp file — no upfront physical disk allocation.
/// - Memory per file: O(total_chunks × 32) for per-chunk hashes + bitmap.
/// - File data is never held in RAM; chunks are written directly to disk.
///
/// # Incremental Verification
///
/// When a `ChunkHashVerifier` is set, each chunk is verified against its
/// expected hash before being written. Failed chunks are tracked for
/// retransmission requests.
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
    /// Optional chunk hash verifier for incremental verification.
    /// Set when the sender sends the MerkleTree message before chunks.
    verifier: Option<ChunkHashVerifier>,
    /// Chunks that failed verification (for retransmission requests).
    failed_chunks: Vec<u32>,
    /// Incremental whole-file SHA3-256 hasher, updated as sequential
    /// chunks are flushed to disk.  Eliminates the need to read back
    /// the entire file during finalization.
    whole_file_hasher: Sha3_256,
    /// Tracks how far we've hashed sequentially for the whole-file hash.
    /// Equals `next_flush_seq` when all chunks arrive in order (common case
    /// with ordered SCTP data channels).
    hash_frontier: u32,
    /// Last buffer size milestone at which we warned (for rate-limiting).
    /// Only warn when buffer size crosses a new multiple of RECEIVER_WRITE_BUFFER_CHUNKS.
    last_buffer_warn_milestone: usize,
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
    /// Chunks that failed verification during receive.
    pub failed_chunks: Vec<u32>,
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
            verifier: None,
            failed_chunks: Vec::new(),
            whole_file_hasher: Sha3_256::new(),
            hash_frontier: 0,
            last_buffer_warn_milestone: 0,
        })
    }

    /// Resume a streaming writer from an existing temp file.
    ///
    /// Opens the temp file WITHOUT truncating, restores the chunk bitmap,
    /// and sets the received_chunks counter.  The sender can then skip
    /// already-received chunks, avoiding re-transmission of the entire file.
    ///
    /// # Parameters
    ///
    /// * `bitmap` — chunk bitmap from the persisted transaction state.
    ///   Chunks marked as received in the bitmap are assumed to be on disk.
    pub async fn resume(
        filename: String,
        filesize: u64,
        total_chunks: u32,
        save_path: PathBuf,
        bitmap: ChunkBitmap,
    ) -> Result<Self> {
        let temp_path = {
            let mut name = save_path.as_os_str().to_owned();
            name.push(".crossdrop-tmp");
            PathBuf::from(name)
        };

        // If the temp file doesn't exist, fall back to a fresh writer
        if !temp_path.exists() {
            return Self::new(filename, filesize, total_chunks, save_path).await;
        }

        // Open existing temp file without truncating
        let file = fs::OpenOptions::new()
            .write(true)
            .read(true)
            .open(&temp_path)
            .await?;

        // Count how many chunks are already received
        let mut received_chunks = 0u32;
        for i in 0..total_chunks {
            if bitmap.is_set(i) {
                received_chunks += 1;
            }
        }

        // Find the contiguous prefix length for hash_frontier / next_flush_seq.
        // All chunks 0..frontier are present, so the incremental hasher can
        // skip them (they'll be read back during finalize if needed).
        let mut frontier = 0u32;
        while frontier < total_chunks && bitmap.is_set(frontier) {
            frontier += 1;
        }

        tracing::info!(
            event = "streaming_writer_resumed",
            filename = %filename,
            received_chunks = received_chunks,
            total_chunks = total_chunks,
            frontier = frontier,
            "Resumed streaming writer from existing temp file"
        );

        Ok(Self {
            file,
            temp_path,
            final_path: save_path,
            filesize,
            total_chunks,
            received_chunks,
            chunk_hashes: vec![None; total_chunks as usize],
            bitmap,
            filename,
            write_buffer: BTreeMap::new(),
            next_flush_seq: frontier,
            verifier: None,
            failed_chunks: Vec::new(),
            // The incremental hasher starts from 0 — we haven't hashed
            // the already-received chunks.  Finalize will read them back.
            whole_file_hasher: Sha3_256::new(),
            hash_frontier: 0,
            last_buffer_warn_milestone: 0,
        })
    }

    /// Set the chunk hash verifier for incremental verification.
    /// Called when the sender sends the MerkleTree message before chunks.
    pub fn set_verifier(&mut self, verifier: ChunkHashVerifier) {
        self.verifier = Some(verifier);
    }

    /// Add chunk hashes incrementally for verification.
    /// Called when the sender sends ChunkHashBatch messages during transfer.
    /// This enables incremental Merkle verification without pre-computing all hashes.
    pub fn add_chunk_hashes(&mut self, start_index: u32, hashes: Vec<[u8; 32]>) {
        if let Some(ref mut verifier) = self.verifier {
            verifier.add_hashes(start_index, hashes);
        } else {
            // Create a new verifier if we don't have one yet
            // We need to know total_chunks, which we have
            let total = self.total_chunks as usize;
            let mut verifier = ChunkHashVerifier::with_capacity(total);
            verifier.add_hashes(start_index, hashes);
            self.verifier = Some(verifier);
        }
    }

    /// Accept a chunk: validate, verify hash, buffer in memory, and flush when
    /// a sequential run is ready or the buffer reaches capacity.
    ///
    /// If a verifier is set, the chunk's hash is compared against the expected
    /// hash. If they don't match, the chunk is still written (to allow later
    /// retransmission to overwrite it), but the failure is tracked.
    ///
    /// Duplicate chunks (same `seq` already received) are silently skipped.
    ///
    /// # Errors
    ///
    /// Returns an error if `seq >= total_chunks` or the chunk data would
    /// extend past the declared file size.
    pub async fn write_chunk(&mut self, seq: u32, data: &[u8]) -> Result<ChunkWriteResult> {
        if seq >= self.total_chunks {
            return Err(anyhow!(
                "Chunk seq {} >= total_chunks {}",
                seq,
                self.total_chunks
            ));
        }

        // Idempotent: skip duplicate chunks
        if self.bitmap.is_set(seq) {
            return Ok(ChunkWriteResult::Duplicate);
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

        // Per-chunk SHA3-256 hash for incremental Merkle tree.
        // Computed once and reused for both the chunk_hashes array AND
        // the verifier check — avoids double-hashing the same data.
        let h = crate::core::pipeline::merkle::hash_chunk(data);
        self.chunk_hashes[seq as usize] = Some(h);

        // Incremental verification: compare the pre-computed hash against
        // the expected hash from the sender's ChunkHashBatch messages.
        let verification_result = if let Some(ref verifier) = self.verifier {
            match verifier.verify_chunk_hash(seq, &h) {
                Ok(()) => ChunkVerificationStatus::Verified,
                Err(ChunkVerificationError::HashMismatch { .. }) => {
                    self.failed_chunks.push(seq);
                    ChunkVerificationStatus::HashMismatch
                }
                Err(ChunkVerificationError::InvalidSequence { .. }) => {
                    // This shouldn't happen if the sender is well-behaved
                    warn!(
                        event = "invalid_chunk_sequence",
                        seq = seq,
                        total = self.total_chunks,
                        "Received chunk with invalid sequence number"
                    );
                    ChunkVerificationStatus::InvalidSequence
                }
                Err(ChunkVerificationError::HashNotYetReceived { .. }) => {
                    // Hash not yet received - accept chunk but mark for later verification
                    // This happens with incremental hash delivery when chunks arrive
                    // before their hash batch. Not an error, just a timing issue.
                    tracing::debug!(
                        event = "chunk_hash_not_yet_received",
                        seq = seq,
                        "Chunk hash not yet received - deferring verification"
                    );
                    ChunkVerificationStatus::NoVerifier
                }
            }
        } else {
            // No verifier set - accept chunk without verification
            ChunkVerificationStatus::NoVerifier
        };

        self.bitmap.set(seq);
        self.received_chunks += 1;

        // Buffer the chunk data
        self.write_buffer.insert(seq, data.to_vec());

        // Flush strategy: flush a sequential run starting at next_flush_seq,
        // or force-flush everything if buffer is at capacity.
        if seq == self.next_flush_seq || self.write_buffer.len() >= RECEIVER_WRITE_BUFFER_CHUNKS {
            self.flush_buffer().await?;
        }

        Ok(ChunkWriteResult::Written(verification_result))
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

            // Update incremental whole-file hash for sequential chunks.
            // With ordered SCTP delivery, hash_frontier always equals
            // next_flush_seq, so every chunk is hashed here and the
            // expensive full-file readback in finalize() is skipped.
            if self.next_flush_seq == self.hash_frontier {
                self.whole_file_hasher.update(&data);
                self.hash_frontier += 1;
            }

            self.next_flush_seq += 1;
        }

        // Safety guard: warn if buffer grows large (sequential gap not yet filled).
        // We do NOT force-flush out-of-order chunks — finalize() handles them.
        // Rate-limit warnings to only log when crossing a new milestone (multiple of capacity).
        let buffer_len = self.write_buffer.len();
        if buffer_len >= RECEIVER_WRITE_BUFFER_CHUNKS {
            let milestone = buffer_len / RECEIVER_WRITE_BUFFER_CHUNKS;
            if milestone > self.last_buffer_warn_milestone {
                self.last_buffer_warn_milestone = milestone;
                warn!(
                    event = "write_buffer_high_watermark",
                    buffered = buffer_len,
                    next_flush_seq = self.next_flush_seq,
                    milestone = milestone,
                    "Write buffer exceeds capacity — waiting for sequential gap to fill"
                );
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

    /// Get a clone of the chunk bitmap for persistence/resume.
    pub fn bitmap(&self) -> ChunkBitmap {
        self.bitmap.clone()
    }

    /// Finalize the receive: flush any remaining buffered chunks, then
    /// read back the full file to compute the whole-file SHA3-256 hash,
    /// and build the Merkle root from per-chunk hashes.
    ///
    /// Returns a [`FinalizedFile`] that can be committed or aborted.
    pub async fn finalize(mut self) -> Result<FinalizedFile> {
        // Flush any chunks still sitting in the write buffer.
        // BTreeMap iterates in ascending key order, so sequential chunks
        // starting at hash_frontier will be hashed in-memory during flush.
        let remaining: Vec<(u32, Vec<u8>)> = self.write_buffer.into_iter().collect();
        self.write_buffer = BTreeMap::new();
        for (seq, data) in &remaining {
            let offset = (*seq as u64) * (CHUNK_SIZE as u64);
            self.file.seek(SeekFrom::Start(offset)).await?;
            self.file.write_all(data).await?;

            // Continue incremental hash for any sequential remaining chunks
            if *seq == self.hash_frontier {
                self.whole_file_hasher.update(data);
                self.hash_frontier += 1;
            }
        }

        // Ensure all data reaches physical media
        self.file.flush().await?;
        self.file.sync_all().await?;

        // Compute whole-file SHA3-256 hash.
        // Fast path: if all chunks were hashed incrementally during sequential
        // flush (common case with ordered SCTP delivery), no file readback needed.
        let sha3_hash = if self.hash_frontier >= self.total_chunks {
            tracing::debug!(
                event = "incremental_hash_complete",
                total_chunks = self.total_chunks,
                "Whole-file SHA3-256 computed incrementally — no file readback"
            );
            std::mem::replace(&mut self.whole_file_hasher, Sha3_256::new())
                .finalize()
                .to_vec()
        } else {
            // Slow path: some chunks arrived out of order.  Read back
            // the un-hashed tail from disk to complete the hash.
            tracing::debug!(
                event = "partial_readback",
                hash_frontier = self.hash_frontier,
                total_chunks = self.total_chunks,
                "Reading back file from chunk {} to compute hash",
                self.hash_frontier
            );
            let start_offset = (self.hash_frontier as u64) * (CHUNK_SIZE as u64);
            self.file.seek(SeekFrom::Start(start_offset)).await?;
            let mut buf = vec![0u8; HASH_READ_BUFFER];
            loop {
                let n = self.file.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                self.whole_file_hasher.update(&buf[..n]);
            }
            std::mem::replace(&mut self.whole_file_hasher, Sha3_256::new())
                .finalize()
                .to_vec()
        };

        // Build Merkle root from incrementally collected chunk hashes
        let all_present = self.chunk_hashes.iter().all(|h| h.is_some());
        let computed_merkle_root = if all_present && !self.chunk_hashes.is_empty() {
            let leaves: Vec<[u8; 32]> = self.chunk_hashes.iter().map(|h| h.unwrap()).collect();
            MerkleTree::compute_root(&leaves)
        } else {
            [0u8; 32]
        };

        // File handle dropped when `self` is destructured below
        Ok(FinalizedFile {
            sha3_256: sha3_hash,
            merkle_root: computed_merkle_root,
            filename: self.filename,
            filesize: self.filesize,
            temp_path: self.temp_path,
            final_path: self.final_path,
            failed_chunks: self.failed_chunks,
        })
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
    use crate::core::pipeline::merkle::hash_chunk;
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
        let mut writer = StreamingFileWriter::new("dup_test.bin".into(), filesize, 2, save_path)
            .await
            .unwrap();

        let chunk = vec![0x42u8; CHUNK_SIZE];

        let result = writer.write_chunk(0, &chunk).await.unwrap();
        assert!(matches!(
            result,
            ChunkWriteResult::Written(ChunkVerificationStatus::NoVerifier)
        ));
        assert_eq!(writer.received_chunks(), 1);

        // Duplicate — should be skipped
        let result = writer.write_chunk(0, &chunk).await.unwrap();
        assert!(matches!(result, ChunkWriteResult::Duplicate));
        assert_eq!(writer.received_chunks(), 1); // NOT 2

        writer.write_chunk(1, &chunk).await.unwrap();
        assert_eq!(writer.received_chunks(), 2);
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_streaming_writer_out_of_bounds() {
        let dir = test_dir("streaming_oob");
        let save_path = dir.join("oob_test.bin");

        let filesize = CHUNK_SIZE as u64;
        let mut writer = StreamingFileWriter::new("oob_test.bin".into(), filesize, 1, save_path)
            .await
            .unwrap();

        // seq beyond total_chunks
        let result = writer.write_chunk(5, &[0u8; 100]).await;
        assert!(result.is_err());
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
        let chunk1 = vec![0xBBu8; CHUNK_SIZE / 2];

        writer.write_chunk(0, &chunk0).await.unwrap();
        writer.write_chunk(1, &chunk1).await.unwrap();

        let finalized = writer.finalize().await.unwrap();
        assert_eq!(finalized.filesize, filesize);

        let path = finalized.commit().await.unwrap();
        let content = std::fs::read(&path).unwrap();
        assert_eq!(content.len(), filesize as usize);

        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_incremental_verification_success() {
        let dir = test_dir("incremental_verify");
        let save_path = dir.join("verify_test.bin");

        let chunk0 = vec![0xAAu8; CHUNK_SIZE];
        let chunk1 = vec![0xBBu8; CHUNK_SIZE];
        let chunk2 = vec![0xCCu8; CHUNK_SIZE];

        // Compute expected hashes
        let h0 = hash_chunk(&chunk0);
        let h1 = hash_chunk(&chunk1);
        let h2 = hash_chunk(&chunk2);

        // Create verifier
        let verifier = ChunkHashVerifier::new(vec![h0, h1, h2]);

        let filesize = (CHUNK_SIZE * 3) as u64;
        let mut writer = StreamingFileWriter::new("verify_test.bin".into(), filesize, 3, save_path)
            .await
            .unwrap();

        writer.set_verifier(verifier);

        // Write correct chunks
        let result = writer.write_chunk(0, &chunk0).await.unwrap();
        assert!(matches!(
            result,
            ChunkWriteResult::Written(ChunkVerificationStatus::Verified)
        ));

        let result = writer.write_chunk(1, &chunk1).await.unwrap();
        assert!(matches!(
            result,
            ChunkWriteResult::Written(ChunkVerificationStatus::Verified)
        ));

        let result = writer.write_chunk(2, &chunk2).await.unwrap();
        assert!(matches!(
            result,
            ChunkWriteResult::Written(ChunkVerificationStatus::Verified)
        ));

        // No failed chunks
        assert!(writer.failed_chunks.is_empty());

        let finalized = writer.finalize().await.unwrap();
        assert!(finalized.failed_chunks.is_empty());

        finalized.commit().await.unwrap();
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_incremental_verification_failure() {
        let dir = test_dir("incremental_verify_fail");
        let save_path = dir.join("verify_fail_test.bin");

        let chunk0 = vec![0xAAu8; CHUNK_SIZE];
        let chunk1_good = vec![0xBBu8; CHUNK_SIZE];
        let chunk1_bad = vec![0xDDu8; CHUNK_SIZE]; // Corrupted
        let chunk2 = vec![0xCCu8; CHUNK_SIZE];

        // Compute expected hashes (using good chunks)
        let h0 = hash_chunk(&chunk0);
        let h1 = hash_chunk(&chunk1_good);
        let h2 = hash_chunk(&chunk2);

        let verifier = ChunkHashVerifier::new(vec![h0, h1, h2]);

        let filesize = (CHUNK_SIZE * 3) as u64;
        let mut writer =
            StreamingFileWriter::new("verify_fail_test.bin".into(), filesize, 3, save_path)
                .await
                .unwrap();

        writer.set_verifier(verifier);

        // Write correct chunk 0
        let result = writer.write_chunk(0, &chunk0).await.unwrap();
        assert!(matches!(
            result,
            ChunkWriteResult::Written(ChunkVerificationStatus::Verified)
        ));

        // Write corrupted chunk 1
        let result = writer.write_chunk(1, &chunk1_bad).await.unwrap();
        assert!(matches!(
            result,
            ChunkWriteResult::Written(ChunkVerificationStatus::HashMismatch)
        ));

        // Write correct chunk 2
        let result = writer.write_chunk(2, &chunk2).await.unwrap();
        assert!(matches!(
            result,
            ChunkWriteResult::Written(ChunkVerificationStatus::Verified)
        ));

        // Chunk 1 should be in failed list
        assert_eq!(writer.failed_chunks, &[1]);

        let finalized = writer.finalize().await.unwrap();
        assert_eq!(finalized.failed_chunks, vec![1]);

        finalized.abort().await;
        cleanup(&dir);
    }
}
