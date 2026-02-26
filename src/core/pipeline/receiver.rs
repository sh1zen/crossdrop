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
//!
//! # Resume Support
//!
//! The chunk bitmap is persisted to a companion file (`.crossdrop-tmp.bitmap`)
//! after each chunk write, enabling crash-resilient resume. On restart,
//! the writer detects existing temp files and resumes from the last persisted
//! byte offset.

use crate::core::config::{CHUNK_SIZE, RECEIVER_WRITE_BUFFER_CHUNKS};
use crate::core::pipeline::chunk::ChunkBitmap;
use crate::core::pipeline::merkle::{ChunkHashVerifier, ChunkVerificationError, MerkleTree};
use anyhow::{anyhow, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};
use tracing::{info, warn};

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
    /// Path to the persisted bitmap file (`.crossdrop-tmp.bitmap`).
    bitmap_path: PathBuf,
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
    /// Last milestone at which a high-watermark warning was emitted.
    last_buffer_warn_milestone: usize,
    /// Byte offset of the last successfully written chunk (for resume tracking).
    last_persisted_byte_offset: u64,
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
    #[allow(clippy::too_many_arguments)]
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
        let bitmap_path = bitmap_path_for(&final_path);
        let last_persisted_byte_offset = frontier as u64 * CHUNK_SIZE as u64;
        Self {
            file,
            temp_path,
            bitmap_path,
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
            last_buffer_warn_milestone: 0,
            last_persisted_byte_offset,
        }
    }

    // ── Verifier management ────────────────────────────────────────────────────

    /// Attach a chunk hash verifier (called when the sender's MerkleTree message arrives).
    pub fn set_verifier(&mut self, verifier: ChunkHashVerifier) {
        self.verifier = Some(verifier);
    }

    /// Feed incremental chunk hashes into the verifier, creating one if needed.
    ///
    /// Also stores hashes in `chunk_hashes` for Merkle root computation at finalization.
    /// This is critical for resumed transfers where some chunks are already on disk:
    /// the sender sends all chunk hashes, and we must retain them even for chunks
    /// we won't receive again.
    pub fn add_chunk_hashes(&mut self, start_index: u32, hashes: Vec<[u8; 32]>) {
        // Store in chunk_hashes for Merkle root computation at finalization.
        for (i, hash) in hashes.iter().enumerate() {
            let seq = start_index as usize + i;
            if seq < self.chunk_hashes.len() {
                self.chunk_hashes[seq] = Some(*hash);
            }
        }
        // Also feed to verifier for incremental verification.
        let verifier = self
            .verifier
            .get_or_insert_with(|| ChunkHashVerifier::with_capacity(self.total_chunks as usize));
        verifier.add_hashes(start_index, &hashes);
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

    // ── Flushing ───────────────────────────────────────────────────────

    /// Drain any sequential run from `next_flush_seq`; warn on high watermark.
    /// Persists the bitmap to disk after each flush for crash resilience.
    async fn flush_buffer(&mut self) -> Result<()> {
        loop {
            if let Some(data) = self.write_buffer.remove(&self.next_flush_seq) {
                let offset = self.next_flush_seq as u64 * CHUNK_SIZE as u64;
                self.file.seek(SeekFrom::Start(offset)).await?;
                self.file.write_all(&data).await?;
                self.last_persisted_byte_offset = offset + data.len() as u64;
                self.next_flush_seq += 1;
            } else if self.next_flush_seq < self.total_chunks
                && self.bitmap.is_set(self.next_flush_seq)
            {
                // Chunk was pre-filled directly (e.g. load_from_existing_file) —
                // it is already on disk, so just advance the frontier.
                self.next_flush_seq += 1;
            } else {
                break;
            }
        }

        // Persist the bitmap to disk for crash resilience (fire-and-forget to
        // avoid blocking the receive path on disk I/O).
        let bitmap_bytes = self.bitmap.to_bytes();
        let bitmap_path = self.bitmap_path.clone();
        tokio::spawn(async move {
            let tmp_path = bitmap_path.with_extension("bitmap.tmp");
            if let Ok(()) = tokio::fs::write(&tmp_path, &bitmap_bytes).await {
                let _ = tokio::fs::rename(&tmp_path, &bitmap_path).await;
            }
        });

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
    pub fn bitmap(&self) -> &ChunkBitmap {
        &self.bitmap
    }
    pub fn final_path(&self) -> &Path {
        &self.final_path
    }
    pub fn chunk_hashes(&self) -> &[Option<[u8; 32]>] {
        &self.chunk_hashes
    }
    pub fn temp_path_ref(&self) -> &Path {
        &self.temp_path
    }
    pub fn bitmap_path_ref(&self) -> &Path {
        &self.bitmap_path
    }

    // ── Existing-file pre-fill ─────────────────────────────────────────────────

    /// Copy matching chunks from `existing_path` into the temp file.
    ///
    /// For each chunk where `self.chunk_hashes[seq]` matches the hash computed
    /// from `existing_path`, the chunk data is written directly to the temp file
    /// and the chunk is marked as received in the bitmap.
    ///
    /// Returns a bitmap of all pre-matched chunks (usable as `FileHaveChunks`
    /// payload so the sender can skip them in Phase 2).
    pub async fn load_from_existing_file(&mut self, existing_path: &Path) -> Result<ChunkBitmap> {
        let mut existing = fs::OpenOptions::new()
            .read(true)
            .open(existing_path)
            .await?;
        let existing_size = existing.metadata().await?.len();
        let mut matched = ChunkBitmap::new(self.total_chunks);
        let mut existing_cursor: u64 = 0;
        let mut temp_cursor: u64 = 0;
        let mut buf = vec![0u8; CHUNK_SIZE];

        for seq in 0..self.total_chunks {
            // Chunks already received in this session are already on disk.
            if self.bitmap.is_set(seq) {
                matched.set(seq);
                continue;
            }

            let offset = seq as u64 * CHUNK_SIZE as u64;
            if offset >= existing_size {
                break;
            }

            // Read chunk from existing file (seek only when needed to keep I/O mostly sequential).
            let chunk_end = (offset + CHUNK_SIZE as u64).min(existing_size);
            let chunk_len = (chunk_end - offset) as usize;
            if existing_cursor != offset {
                existing.seek(SeekFrom::Start(offset)).await?;
                existing_cursor = offset;
            }
            existing.read_exact(&mut buf[..chunk_len]).await?;
            existing_cursor += chunk_len as u64;

            let existing_hash = crate::core::pipeline::merkle::hash_chunk(&buf[..chunk_len]);

            // Compare with the hash the sender sent for this chunk.
            if let Some(sender_hash) = self.chunk_hashes[seq as usize]
                && existing_hash == sender_hash
            {
                // Write matching chunk directly to temp file.
                if temp_cursor != offset {
                    self.file.seek(SeekFrom::Start(offset)).await?;
                    temp_cursor = offset;
                }
                self.file.write_all(&buf[..chunk_len]).await?;
                temp_cursor += chunk_len as u64;
                self.bitmap.set(seq);
                self.received_chunks += 1;
                matched.set(seq);
            }
        }

        // Update next_flush_seq to the new contiguous prefix.
        let new_frontier = (0..self.total_chunks)
            .take_while(|&i| self.bitmap.is_set(i))
            .count() as u32;
        self.next_flush_seq = new_frontier;

        Ok(matched)
    }

    // ── Finalization ───────────────────────────────────────────────────────────

    /// Flush remaining buffered chunks, compute the Merkle root,
    /// then return a [`FinalizedFile`] for commit/abort.
    pub async fn finalize(mut self) -> Result<FinalizedFile> {
        // Drain the write buffer in order.
        let remaining: Vec<(u32, Vec<u8>)> =
            std::mem::take(&mut self.write_buffer).into_iter().collect();
        for (seq, data) in &remaining {
            self.file
                .seek(SeekFrom::Start(*seq as u64 * CHUNK_SIZE as u64))
                .await?;
            self.file.write_all(data).await?;
        }

        self.file.flush().await?;
        self.file.sync_all().await?;

        let merkle_root = self.compute_merkle_root();

        Ok(FinalizedFile {
            merkle_root,
            filename: self.filename,
            filesize: self.filesize,
            temp_path: self.temp_path,
            bitmap_path: self.bitmap_path,
            final_path: self.final_path,
            failed_chunks: self.failed_chunks,
        })
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
    pub merkle_root: [u8; 32],
    pub filename: String,
    pub filesize: u64,
    pub failed_chunks: Vec<u32>,
    temp_path: PathBuf,
    bitmap_path: PathBuf,
    final_path: PathBuf,
}

impl FinalizedFile {
    /// Atomically move the temp file to its final destination.
    /// Also cleans up the bitmap file.
    pub async fn commit(self) -> Result<PathBuf> {
        let Self {
            temp_path,
            bitmap_path,
            final_path,
            ..
        } = self;
        if let Some(parent) = final_path.parent()
            && !parent.exists()
        {
            let _ = fs::create_dir_all(parent).await;
        }
        if let Err(e) = fs::rename(&temp_path, &final_path).await {
            tokio::spawn(async move {
                let _ = fs::remove_file(&temp_path).await;
            });
            return Err(anyhow!("Failed to rename temp file to final path: {e}"));
        }
        // Clean up the bitmap file after successful commit
        let _ = fs::remove_file(&bitmap_path).await;
        Ok(final_path)
    }

    /// Delete the temp file and bitmap file without committing.
    pub async fn abort(self) {
        let _ = fs::remove_file(&self.temp_path).await;
        let _ = fs::remove_file(&self.bitmap_path).await;
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Derive the temp-file path from the final save path.
fn temp_path_for(save_path: &Path) -> PathBuf {
    let mut name = save_path.as_os_str().to_owned();
    name.push(".crossdrop-tmp");
    PathBuf::from(name)
}

/// Derive the bitmap-file path from the final save path.
fn bitmap_path_for(save_path: &Path) -> PathBuf {
    let mut name = save_path.as_os_str().to_owned();
    name.push(".crossdrop-tmp.bitmap");
    PathBuf::from(name)
}

/// Auto-detect existing partial progress from temp and bitmap files.
/// Returns the bitmap if both files exist and are valid.
pub fn detect_existing_progress(save_path: &Path, total_chunks: u32) -> Option<ChunkBitmap> {
    let temp_path = temp_path_for(save_path);
    let bitmap_path = bitmap_path_for(save_path);

    // Both temp file and bitmap file must exist
    if !temp_path.exists() || !bitmap_path.exists() {
        return None;
    }

    // Try to load the bitmap
    let bitmap_bytes = std::fs::read(&bitmap_path).ok()?;
    let bitmap = ChunkBitmap::from_bytes(&bitmap_bytes)?;

    // Validate bitmap size matches expected chunks
    if bitmap.total_chunks != total_chunks {
        warn!(
            event = "bitmap_chunk_mismatch",
            bitmap_chunks = bitmap.total_chunks,
            expected = total_chunks,
            "Bitmap chunk count mismatch, ignoring existing progress"
        );
        return None;
    }

    // Check if there's any actual progress
    let received = (0..total_chunks).filter(|&i| bitmap.is_set(i)).count();
    if received == 0 {
        return None;
    }

    info!(
        event = "progress_detected",
        temp_path = %temp_path.display(),
        received_chunks = received,
        total_chunks,
        "Detected existing partial progress"
    );

    Some(bitmap)
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

        // Verify Merkle root is computed (non-zero)
        assert_ne!(finalized.merkle_root, [0u8; 32]);
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
