//! Streaming file receiver with bounded memory usage.
//!
//! Writes received chunks directly to a temporary file on disk via
//! positional seek+write, avoiding the previous full-file in-memory buffer
//! that was vulnerable to DoS.
//!
//! # Memory model
//!
//! Per-file memory usage is O(total_chunks × 33 bytes) — one `Option<[u8;32]>`
//! per chunk for hashes plus a small [`ChunkBitmap`].  File data lives on disk.
//!
//! # Incremental Integrity Verification
//!
//! When a [`ChunkHashVerifier`] is set, each incoming chunk is verified against
//! its expected hash before being written.  Mismatches are tracked for
//! retransmission requests.
//!
//! # Concurrency
//!
//! Each [`StreamingFileWriter`] is independent — multiple instances run in
//! parallel for different file IDs without shared-state contention.

use crate::core::config::{CHUNK_SIZE, HASH_READ_BUFFER, RECEIVER_WRITE_BUFFER_CHUNKS};
use crate::core::pipeline::chunk::ChunkBitmap;
use crate::core::pipeline::merkle::{ChunkHashVerifier, ChunkVerificationError, MerkleTree};
use anyhow::{anyhow, Result};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};
use tracing::warn;

// ── Public result types ────────────────────────────────────────────────────────

/// Outcome of a single [`StreamingFileWriter::write_chunk`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkWriteResult {
    Written(ChunkVerificationStatus),
    Duplicate,
}

/// Per-chunk verification outcome reported inside [`ChunkWriteResult::Written`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkVerificationStatus {
    /// Hash matched the sender's expected hash.
    Verified,
    /// Hash did not match — corruption detected.
    HashMismatch,
    /// Sequence number was out of the verifier's range.
    InvalidSequence,
    /// No verifier set; chunk accepted unconditionally.
    NoVerifier,
}

// ── StreamingFileWriter ────────────────────────────────────────────────────────

/// Streams received file chunks to a sparse temporary file.
pub struct StreamingFileWriter {
    file: fs::File,
    temp_path: PathBuf,
    final_path: PathBuf,
    filesize: u64,
    total_chunks: u32,
    received_chunks: u32,
    /// Per-chunk SHA3-256 hashes, populated as chunks arrive.
    chunk_hashes: Vec<Option<[u8; 32]>>,
    bitmap: ChunkBitmap,
    filename: String,
    /// In-memory write buffer: seq → data.
    write_buffer: BTreeMap<u32, Vec<u8>>,
    /// Next sequential chunk expected for contiguous flushing.
    next_flush_seq: u32,
    verifier: Option<ChunkHashVerifier>,
    failed_chunks: Vec<u32>,
    /// Incremental whole-file hasher — updated for sequentially flushed chunks.
    whole_file_hasher: Sha3_256,
    /// How far the incremental hasher has reached (in chunk units).
    hash_frontier: u32,
    /// Last milestone at which a high-watermark warning was emitted.
    last_buffer_warn_milestone: usize,
}

impl StreamingFileWriter {
    // ── Constructors ───────────────────────────────────────────────────────────

    /// Create a new writer backed by a fresh sparse temp file.
    pub async fn new(
        filename: String,
        filesize: u64,
        total_chunks: u32,
        save_path: PathBuf,
    ) -> Result<Self> {
        let temp_path = temp_path_for(&save_path);

        if let Some(parent) = temp_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let file = fs::OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)
            .await?;

        file.set_len(filesize).await?;

        Ok(Self::from_parts(
            file,
            temp_path,
            save_path,
            filename,
            filesize,
            total_chunks,
            ChunkBitmap::new(total_chunks),
            /*frontier*/ 0,
            /*received*/ 0,
        ))
    }

    /// Resume a writer from an existing temp file, skipping already-received chunks.
    ///
    /// Falls back to [`Self::new`] if the temp file is absent.
    pub async fn resume(
        filename: String,
        filesize: u64,
        total_chunks: u32,
        save_path: PathBuf,
        bitmap: ChunkBitmap,
    ) -> Result<Self> {
        let temp_path = temp_path_for(&save_path);

        if !temp_path.exists() {
            return Self::new(filename, filesize, total_chunks, save_path).await;
        }

        let file = fs::OpenOptions::new()
            .write(true)
            .read(true)
            .open(&temp_path)
            .await?;

        let received_chunks = (0..total_chunks).filter(|&i| bitmap.is_set(i)).count() as u32;

        // Contiguous prefix: how many chunks from 0 are already present.
        let frontier = (0..total_chunks).take_while(|&i| bitmap.is_set(i)).count() as u32;

        tracing::info!(
            event = "streaming_writer_resumed",
            filename = %filename,
            received_chunks,
            total_chunks,
            frontier,
            "Resumed streaming writer from existing temp file"
        );

        Ok(Self::from_parts(
            file,
            temp_path,
            save_path,
            filename,
            filesize,
            total_chunks,
            bitmap,
            frontier,
            received_chunks,
        ))
    }

    /// Shared field initialisation for both constructors.
    fn from_parts(
        file: fs::File,
        temp_path: PathBuf,
        final_path: PathBuf,
        filename: String,
        filesize: u64,
        total_chunks: u32,
        bitmap: ChunkBitmap,
        frontier: u32,
        received_chunks: u32,
    ) -> Self {
        Self {
            file,
            temp_path,
            final_path,
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
            whole_file_hasher: Sha3_256::new(),
            hash_frontier: 0,
            last_buffer_warn_milestone: 0,
        }
    }

    // ── Verifier management ────────────────────────────────────────────────────

    /// Attach a chunk hash verifier (called when the sender's MerkleTree message arrives).
    pub fn set_verifier(&mut self, verifier: ChunkHashVerifier) {
        self.verifier = Some(verifier);
    }

    /// Feed incremental chunk hashes into the verifier, creating one if needed.
    pub fn add_chunk_hashes(&mut self, start_index: u32, hashes: Vec<[u8; 32]>) {
        let verifier = self
            .verifier
            .get_or_insert_with(|| ChunkHashVerifier::with_capacity(self.total_chunks as usize));
        verifier.add_hashes(start_index, hashes);
    }

    // ── Chunk ingestion ────────────────────────────────────────────────────────

    /// Accept, verify, buffer, and conditionally flush one chunk.
    ///
    /// Duplicates are silently dropped.  A hash mismatch is recorded in
    /// `failed_chunks` but does not prevent the chunk from being buffered
    /// (to allow a retransmitted chunk to overwrite it later).
    ///
    /// # Errors
    ///
    /// Returns `Err` if `seq >= total_chunks` or the chunk data would extend
    /// past the declared file size.
    pub async fn write_chunk(&mut self, seq: u32, data: &[u8]) -> Result<ChunkWriteResult> {
        if seq >= self.total_chunks {
            return Err(anyhow!(
                "Chunk seq {seq} >= total_chunks {}",
                self.total_chunks
            ));
        }

        if self.bitmap.is_set(seq) {
            return Ok(ChunkWriteResult::Duplicate);
        }

        let offset = seq as u64 * CHUNK_SIZE as u64;
        let end = offset + data.len() as u64;
        if end > self.filesize {
            return Err(anyhow!(
                "Chunk {seq} extends past file end ({end} > {})",
                self.filesize
            ));
        }

        let hash = crate::core::pipeline::merkle::hash_chunk(data);
        self.chunk_hashes[seq as usize] = Some(hash);

        let status = self.verify_chunk(seq, &hash);

        self.bitmap.set(seq);
        self.received_chunks += 1;
        self.write_buffer.insert(seq, data.to_vec());

        if seq == self.next_flush_seq || self.write_buffer.len() >= RECEIVER_WRITE_BUFFER_CHUNKS {
            self.flush_buffer().await?;
        }

        Ok(ChunkWriteResult::Written(status))
    }

    /// Verify `hash` for `seq` against the verifier, updating `failed_chunks`.
    fn verify_chunk(&mut self, seq: u32, hash: &[u8; 32]) -> ChunkVerificationStatus {
        let Some(ref verifier) = self.verifier else {
            return ChunkVerificationStatus::NoVerifier;
        };

        match verifier.verify_chunk_hash(seq, hash) {
            Ok(()) => ChunkVerificationStatus::Verified,
            Err(ChunkVerificationError::HashMismatch { .. }) => {
                self.failed_chunks.push(seq);
                ChunkVerificationStatus::HashMismatch
            }
            Err(ChunkVerificationError::InvalidSequence { .. }) => {
                warn!(
                    event = "invalid_chunk_sequence",
                    seq,
                    total = self.total_chunks,
                    "Received chunk with invalid sequence number"
                );
                ChunkVerificationStatus::InvalidSequence
            }
            Err(ChunkVerificationError::HashNotYetReceived { .. }) => {
                tracing::debug!(
                    event = "chunk_hash_not_yet_received",
                    seq,
                    "Chunk hash not yet received — deferring verification"
                );
                ChunkVerificationStatus::NoVerifier
            }
        }
    }

    // ── Flushing ───────────────────────────────────────────────────────────────

    /// Drain any sequential run from `next_flush_seq`; warn on high watermark.
    async fn flush_buffer(&mut self) -> Result<()> {
        while let Some(data) = self.write_buffer.remove(&self.next_flush_seq) {
            let offset = self.next_flush_seq as u64 * CHUNK_SIZE as u64;
            self.file.seek(SeekFrom::Start(offset)).await?;
            self.file.write_all(&data).await?;

            if self.next_flush_seq == self.hash_frontier {
                self.whole_file_hasher.update(&data);
                self.hash_frontier += 1;
            }

            self.next_flush_seq += 1;
        }

        let buf_len = self.write_buffer.len();
        if buf_len >= RECEIVER_WRITE_BUFFER_CHUNKS {
            let milestone = buf_len / RECEIVER_WRITE_BUFFER_CHUNKS;
            if milestone > self.last_buffer_warn_milestone {
                self.last_buffer_warn_milestone = milestone;
                warn!(
                    event = "write_buffer_high_watermark",
                    buffered = buf_len,
                    next_flush_seq = self.next_flush_seq,
                    milestone,
                    "Write buffer exceeds capacity — waiting for sequential gap to fill"
                );
            }
        }

        Ok(())
    }

    // ── Accessors ──────────────────────────────────────────────────────────────

    pub fn received_chunks(&self) -> u32 {
        self.received_chunks
    }
    pub fn total_chunks(&self) -> u32 {
        self.total_chunks
    }
    pub fn filename(&self) -> &str {
        &self.filename
    }
    pub fn bitmap(&self) -> ChunkBitmap {
        self.bitmap.clone()
    }

    // ── Finalization ───────────────────────────────────────────────────────────

    /// Flush remaining buffered chunks, compute the whole-file SHA3-256 hash
    /// and the Merkle root, then return a [`FinalizedFile`] for commit/abort.
    pub async fn finalize(mut self) -> Result<FinalizedFile> {
        // Drain the write buffer in order.
        let remaining: Vec<(u32, Vec<u8>)> =
            std::mem::take(&mut self.write_buffer).into_iter().collect();
        for (seq, data) in &remaining {
            self.file
                .seek(SeekFrom::Start(*seq as u64 * CHUNK_SIZE as u64))
                .await?;
            self.file.write_all(data).await?;

            if *seq == self.hash_frontier {
                self.whole_file_hasher.update(data);
                self.hash_frontier += 1;
            }
        }

        self.file.flush().await?;
        self.file.sync_all().await?;

        let sha3_hash = self.compute_whole_file_hash().await?;
        let merkle_root = self.compute_merkle_root();

        Ok(FinalizedFile {
            sha3_256: sha3_hash,
            merkle_root,
            filename: self.filename,
            filesize: self.filesize,
            temp_path: self.temp_path,
            final_path: self.final_path,
            failed_chunks: self.failed_chunks,
        })
    }

    /// Finish the whole-file hash, using disk readback only for the out-of-order tail.
    async fn compute_whole_file_hash(&mut self) -> Result<Vec<u8>> {
        if self.hash_frontier >= self.total_chunks {
            tracing::debug!(
                event = "incremental_hash_complete",
                total_chunks = self.total_chunks,
                "Whole-file SHA3-256 computed incrementally — no file readback"
            );
        } else {
            tracing::debug!(
                event = "partial_readback",
                hash_frontier = self.hash_frontier,
                total_chunks = self.total_chunks,
                "Reading back file from chunk {} to compute hash",
                self.hash_frontier
            );
            let start = self.hash_frontier as u64 * CHUNK_SIZE as u64;
            self.file.seek(SeekFrom::Start(start)).await?;
            let mut buf = vec![0u8; HASH_READ_BUFFER];
            loop {
                let n = self.file.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                self.whole_file_hasher.update(&buf[..n]);
            }
        }

        Ok(
            std::mem::replace(&mut self.whole_file_hasher, Sha3_256::new())
                .finalize()
                .to_vec(),
        )
    }

    /// Build the Merkle root from per-chunk hashes collected during reception.
    fn compute_merkle_root(&self) -> [u8; 32] {
        let leaves: Vec<[u8; 32]> = self.chunk_hashes.iter().filter_map(|h| *h).collect();

        if leaves.len() == self.chunk_hashes.len() && !leaves.is_empty() {
            MerkleTree::compute_root(&leaves)
        } else {
            [0u8; 32]
        }
    }
}

// ── FinalizedFile ──────────────────────────────────────────────────────────────

/// Holds integrity data and paths after reception is complete.
///
/// Call [`commit`](FinalizedFile::commit) to rename the temp file into place,
/// or [`abort`](FinalizedFile::abort) to delete it.
pub struct FinalizedFile {
    pub sha3_256: Vec<u8>,
    pub merkle_root: [u8; 32],
    pub filename: String,
    pub filesize: u64,
    pub failed_chunks: Vec<u32>,
    temp_path: PathBuf,
    final_path: PathBuf,
}

impl FinalizedFile {
    /// Atomically move the temp file to its final destination.
    pub async fn commit(self) -> Result<PathBuf> {
        if let Some(parent) = self.final_path.parent() {
            if !parent.exists() {
                let _ = fs::create_dir_all(parent).await;
            }
        }
        fs::rename(&self.temp_path, &self.final_path)
            .await
            .map_err(|e| {
                let tp = self.temp_path.clone();
                tokio::spawn(async move {
                    let _ = fs::remove_file(&tp).await;
                });
                anyhow!("Failed to rename temp file to final path: {e}")
            })?;
        Ok(self.final_path)
    }

    /// Delete the temp file without committing.
    pub async fn abort(self) {
        let _ = fs::remove_file(&self.temp_path).await;
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Derive the temp-file path from the final save path.
fn temp_path_for(save_path: &PathBuf) -> PathBuf {
    let mut name = save_path.as_os_str().to_owned();
    name.push(".crossdrop-tmp");
    PathBuf::from(name)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::pipeline::merkle::hash_chunk;

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("crossdrop_test").join(name);
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    fn cleanup(path: &std::path::Path) {
        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn test_streaming_writer_basic() {
        let dir = test_dir("streaming_basic");
        let save_path = dir.join("test_file.bin");

        let filesize = (CHUNK_SIZE * 3) as u64;
        let mut writer = StreamingFileWriter::new("test_file.bin".into(), filesize, 3, save_path)
            .await
            .unwrap();

        let (chunk0, chunk1, chunk2) = (
            vec![0xAAu8; CHUNK_SIZE],
            vec![0xBBu8; CHUNK_SIZE],
            vec![0xCCu8; CHUNK_SIZE],
        );

        writer.write_chunk(2, &chunk2).await.unwrap();
        writer.write_chunk(0, &chunk0).await.unwrap();
        writer.write_chunk(1, &chunk1).await.unwrap();

        assert_eq!(writer.received_chunks(), 3);
        assert_eq!(writer.total_chunks(), 3);

        let finalized = writer.finalize().await.unwrap();

        let expected_hash = {
            let mut h = Sha3_256::new();
            h.update(&chunk0);
            h.update(&chunk1);
            h.update(&chunk2);
            h.finalize().to_vec()
        };

        assert_eq!(finalized.sha3_256, expected_hash);
        assert_eq!(finalized.filename, "test_file.bin");
        assert_eq!(finalized.filesize, filesize);

        let path = finalized.commit().await.unwrap();
        assert!(path.exists());

        let mut expected = Vec::new();
        expected.extend_from_slice(&chunk0);
        expected.extend_from_slice(&chunk1);
        expected.extend_from_slice(&chunk2);
        assert_eq!(std::fs::read(&path).unwrap(), expected);

        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_streaming_writer_duplicate_chunks() {
        let dir = test_dir("streaming_dup");
        let save_path = dir.join("dup_test.bin");

        let mut writer =
            StreamingFileWriter::new("dup_test.bin".into(), (CHUNK_SIZE * 2) as u64, 2, save_path)
                .await
                .unwrap();

        let chunk = vec![0x42u8; CHUNK_SIZE];

        let r = writer.write_chunk(0, &chunk).await.unwrap();
        assert!(matches!(
            r,
            ChunkWriteResult::Written(ChunkVerificationStatus::NoVerifier)
        ));
        assert_eq!(writer.received_chunks(), 1);

        let r = writer.write_chunk(0, &chunk).await.unwrap();
        assert!(matches!(r, ChunkWriteResult::Duplicate));
        assert_eq!(writer.received_chunks(), 1);

        writer.write_chunk(1, &chunk).await.unwrap();
        assert_eq!(writer.received_chunks(), 2);
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_streaming_writer_out_of_bounds() {
        let dir = test_dir("streaming_oob");
        let save_path = dir.join("oob_test.bin");

        let mut writer =
            StreamingFileWriter::new("oob_test.bin".into(), CHUNK_SIZE as u64, 1, save_path)
                .await
                .unwrap();

        assert!(writer.write_chunk(5, &[0u8; 100]).await.is_err());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_streaming_writer_abort_cleanup() {
        let dir = test_dir("streaming_abort");
        let save_path = dir.join("abort_test.bin");

        let _writer = StreamingFileWriter::new(
            "abort_test.bin".into(),
            CHUNK_SIZE as u64,
            1,
            save_path.clone(),
        )
        .await
        .unwrap();

        assert!(temp_path_for(&save_path).exists());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_streaming_writer_last_chunk_smaller() {
        let dir = test_dir("streaming_last");
        let save_path = dir.join("partial.bin");

        let filesize = (CHUNK_SIZE + CHUNK_SIZE / 2) as u64;
        let mut writer = StreamingFileWriter::new("partial.bin".into(), filesize, 2, save_path)
            .await
            .unwrap();

        writer
            .write_chunk(0, &vec![0xAAu8; CHUNK_SIZE])
            .await
            .unwrap();
        writer
            .write_chunk(1, &vec![0xBBu8; CHUNK_SIZE / 2])
            .await
            .unwrap();

        let finalized = writer.finalize().await.unwrap();
        assert_eq!(finalized.filesize, filesize);

        let path = finalized.commit().await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap().len(), filesize as usize);
        cleanup(&dir);
    }

    #[tokio::test]
    async fn test_incremental_verification_success() {
        let dir = test_dir("incremental_verify");
        let save_path = dir.join("verify_test.bin");

        let (c0, c1, c2) = (
            vec![0xAAu8; CHUNK_SIZE],
            vec![0xBBu8; CHUNK_SIZE],
            vec![0xCCu8; CHUNK_SIZE],
        );
        let verifier =
            ChunkHashVerifier::new(vec![hash_chunk(&c0), hash_chunk(&c1), hash_chunk(&c2)]);

        let mut writer = StreamingFileWriter::new(
            "verify_test.bin".into(),
            (CHUNK_SIZE * 3) as u64,
            3,
            save_path,
        )
        .await
        .unwrap();
        writer.set_verifier(verifier);

        for (seq, chunk) in [(0, &c0), (1, &c1), (2, &c2)] {
            let r = writer.write_chunk(seq, chunk).await.unwrap();
            assert!(matches!(
                r,
                ChunkWriteResult::Written(ChunkVerificationStatus::Verified)
            ));
        }

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

        let (c0, c1_good, c1_bad, c2) = (
            vec![0xAAu8; CHUNK_SIZE],
            vec![0xBBu8; CHUNK_SIZE],
            vec![0xDDu8; CHUNK_SIZE],
            vec![0xCCu8; CHUNK_SIZE],
        );
        let verifier =
            ChunkHashVerifier::new(vec![hash_chunk(&c0), hash_chunk(&c1_good), hash_chunk(&c2)]);

        let mut writer = StreamingFileWriter::new(
            "verify_fail_test.bin".into(),
            (CHUNK_SIZE * 3) as u64,
            3,
            save_path,
        )
        .await
        .unwrap();
        writer.set_verifier(verifier);

        let r = writer.write_chunk(0, &c0).await.unwrap();
        assert!(matches!(
            r,
            ChunkWriteResult::Written(ChunkVerificationStatus::Verified)
        ));

        let r = writer.write_chunk(1, &c1_bad).await.unwrap();
        assert!(matches!(
            r,
            ChunkWriteResult::Written(ChunkVerificationStatus::HashMismatch)
        ));

        let r = writer.write_chunk(2, &c2).await.unwrap();
        assert!(matches!(
            r,
            ChunkWriteResult::Written(ChunkVerificationStatus::Verified)
        ));

        assert_eq!(writer.failed_chunks, &[1]);
        let finalized = writer.finalize().await.unwrap();
        assert_eq!(finalized.failed_chunks, vec![1]);
        finalized.abort().await;
        cleanup(&dir);
    }
}
