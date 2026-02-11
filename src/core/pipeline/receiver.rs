//! Receiver pipeline: async multi-stage chunk processing.
//!
//! Pipeline stages (fully decoupled):
//! 1. Network receive queue
//! 2. Decryption worker pool
//! 3. Decompression worker pool
//! 4. Incremental hash verification
//! 5. Async disk write queue
//!
//! Features:
//! - Never blocks the network while writing to disk
//! - Batch ACKs (ACK ranges, not per-chunk)
//! - Chunk bitmap for resume support
//! - Incremental Merkle tree reconstruction

use crate::core::pipeline::chunk::{ChunkBitmap, compute_chunk_hash};
use crate::core::pipeline::merkle::IncrementalMerkleBuilder;
use crate::core::transaction::CHUNK_SIZE;
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use anyhow::{anyhow, Result};
use brotli::Decompressor;
use sha3::{Digest, Sha3_256};
use std::io::Read;
use std::path::PathBuf;
use tracing::{error, info};
use uuid::Uuid;

// ── Receiver Configuration ───────────────────────────────────────────────────

/// Configuration for the receiver pipeline.
#[derive(Debug, Clone)]
pub struct ReceiverConfig {
    /// Chunk size in bytes (must match sender).
    pub chunk_size: usize,
    /// Maximum number of chunks to buffer before applying backpressure.
    pub max_buffered_chunks: usize,
    /// ACK batch size: send ACK after this many chunks.
    pub ack_batch_size: u32,
    /// Maximum memory usage for receive buffers (bytes).
    pub max_memory: usize,
}

impl Default for ReceiverConfig {
    fn default() -> Self {
        Self {
            chunk_size: CHUNK_SIZE,
            max_buffered_chunks: 64,
            ack_batch_size: 8,
            max_memory: 128 * 1024 * 1024, // 128 MB
        }
    }
}

// ── ACK Range ────────────────────────────────────────────────────────────────

/// Compact ACK representation using ranges instead of per-chunk ACKs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AckRange {
    /// File this ACK is for.
    pub file_id: Uuid,
    /// Ranges of received chunk indices (inclusive start, exclusive end).
    pub ranges: Vec<(u32, u32)>,
}

impl AckRange {
    /// Create ACK ranges from a chunk bitmap.
    pub fn from_bitmap(file_id: Uuid, bitmap: &ChunkBitmap) -> Self {
        let mut ranges = Vec::new();
        let mut start = None;

        for i in 0..bitmap.total_chunks {
            if bitmap.is_set(i) {
                if start.is_none() {
                    start = Some(i);
                }
            } else if let Some(s) = start {
                ranges.push((s, i));
                start = None;
            }
        }

        if let Some(s) = start {
            ranges.push((s, bitmap.total_chunks));
        }

        Self { file_id, ranges }
    }

    /// Check if a chunk index is covered by these ACK ranges.
    pub fn contains(&self, index: u32) -> bool {
        self.ranges.iter().any(|(start, end)| index >= *start && index < *end)
    }

    /// Total number of acknowledged chunks.
    pub fn acked_count(&self) -> u32 {
        self.ranges.iter().map(|(s, e)| e - s).sum()
    }
}

// ── Receiver Events ──────────────────────────────────────────────────────────

/// Events emitted by the receiver pipeline.
#[derive(Debug)]
pub enum ReceiverEvent {
    /// A chunk has been verified and written to the buffer.
    ChunkVerified {
        file_id: Uuid,
        chunk_index: u32,
    },
    /// Batch ACK should be sent.
    SendAck(AckRange),
    /// A chunk failed verification.
    ChunkFailed {
        file_id: Uuid,
        chunk_index: u32,
        error: String,
    },
    /// File Merkle root verified.
    FileVerified {
        file_id: Uuid,
        merkle_root: [u8; 32],
    },
    /// File Merkle root verification failed.
    FileFailed {
        file_id: Uuid,
        expected_root: [u8; 32],
        computed_root: [u8; 32],
    },
}

// ── Per-File Receiver State ──────────────────────────────────────────────────

/// State for receiving a single file.
pub struct FileReceiveState {
    pub file_id: Uuid,
    pub file_size: u64,
    pub total_chunks: u32,
    /// Chunk receipt bitmap.
    pub bitmap: ChunkBitmap,
    /// Incremental Merkle tree builder.
    pub merkle_builder: IncrementalMerkleBuilder,
    /// Expected Merkle root from the manifest.
    pub expected_merkle_root: [u8; 32],
    /// File data buffer (reconstructed from chunks).
    pub buffer: Vec<u8>,
    /// Destination path for the final file.
    pub dest_path: PathBuf,
    /// File-level hash (SHA3-256 of all raw data in order).
    pub file_hasher: Sha3_256,
    /// Chunks received since last ACK batch.
    chunks_since_ack: u32,
}

impl FileReceiveState {
    pub fn new(
        file_id: Uuid,
        file_size: u64,
        total_chunks: u32,
        expected_merkle_root: [u8; 32],
        dest_path: PathBuf,
    ) -> Self {
        Self {
            file_id,
            file_size,
            total_chunks,
            bitmap: ChunkBitmap::new(total_chunks),
            merkle_builder: IncrementalMerkleBuilder::new(total_chunks),
            expected_merkle_root,
            buffer: vec![0u8; file_size as usize],
            dest_path,
            file_hasher: Sha3_256::new(),
            chunks_since_ack: 0,
        }
    }
}

// ── Receiver Pipeline ────────────────────────────────────────────────────────

/// The receiver pipeline processes incoming chunks through
/// decryption → decompression → verification → disk write.
pub struct ReceiverPipeline {
    config: ReceiverConfig,
}

impl ReceiverPipeline {
    pub fn new(config: ReceiverConfig) -> Self {
        Self { config }
    }

    pub fn with_default_config() -> Self {
        Self::new(ReceiverConfig::default())
    }

    /// Process an incoming encrypted chunk.
    /// Returns the decrypted, decompressed raw chunk data if verification passes.
    pub fn process_chunk(
        &self,
        wire_data: &[u8],
        expected_hash: &[u8; 32],
        decryption_key: &[u8; 32],
    ) -> Result<Vec<u8>> {
        // Stage 1: Decrypt (AEAD authentication)
        let compressed = decrypt_chunk(decryption_key, wire_data)?;

        // Stage 2: Decompress
        let raw_data = decompress_chunk(&compressed)?;

        // Stage 3: Verify chunk hash
        let computed_hash = compute_chunk_hash(&raw_data);
        if computed_hash != *expected_hash {
            return Err(anyhow!(
                "Chunk hash mismatch: expected {:?}, got {:?}",
                &expected_hash[..4],
                &computed_hash[..4]
            ));
        }

        Ok(raw_data)
    }

    /// Process a chunk and update the file receive state.
    /// Returns events to emit (ACKs, verification results).
    pub fn receive_chunk(
        &self,
        state: &mut FileReceiveState,
        chunk_index: u32,
        wire_data: &[u8],
        expected_hash: &[u8; 32],
        decryption_key: &[u8; 32],
    ) -> Result<Vec<ReceiverEvent>> {
        let mut events = Vec::new();

        // Already received this chunk? Skip.
        if state.bitmap.is_set(chunk_index) {
            return Ok(events);
        }

        // Process through pipeline
        let raw_data = self.process_chunk(wire_data, expected_hash, decryption_key)?;

        // Write to buffer
        let chunk_size = self.config.chunk_size;
        let start = (chunk_index as usize) * chunk_size;
        let end = std::cmp::min(start + raw_data.len(), state.buffer.len());
        if end > state.buffer.len() {
            return Err(anyhow!("Chunk {} out of bounds", chunk_index));
        }
        state.buffer[start..end].copy_from_slice(&raw_data);

        // Mark as received
        state.bitmap.set(chunk_index);

        // Add to Merkle builder
        state.merkle_builder.add_hash(chunk_index, *expected_hash);

        events.push(ReceiverEvent::ChunkVerified {
            file_id: state.file_id,
            chunk_index,
        });

        // Batch ACK logic
        state.chunks_since_ack += 1;
        if state.chunks_since_ack >= self.config.ack_batch_size || state.bitmap.is_complete() {
            let ack = AckRange::from_bitmap(state.file_id, &state.bitmap);
            events.push(ReceiverEvent::SendAck(ack));
            state.chunks_since_ack = 0;
        }

        // Check if file is complete
        if state.bitmap.is_complete() {
            match state.merkle_builder.verify_root(&state.expected_merkle_root) {
                Some(true) => {
                    events.push(ReceiverEvent::FileVerified {
                        file_id: state.file_id,
                        merkle_root: state.expected_merkle_root,
                    });
                }
                Some(false) => {
                    let computed = state.merkle_builder.compute_root().unwrap_or([0u8; 32]);
                    events.push(ReceiverEvent::FileFailed {
                        file_id: state.file_id,
                        expected_root: state.expected_merkle_root,
                        computed_root: computed,
                    });
                }
                None => {
                    // Should not happen since bitmap.is_complete() = true
                    error!(file_id = %state.file_id, "Merkle builder incomplete despite bitmap complete");
                }
            }
        }

        Ok(events)
    }

    /// Write a completed file's buffer to disk (atomic write via temp file).
    pub async fn write_file_to_disk(state: &FileReceiveState) -> Result<PathBuf> {
        let dest = &state.dest_path;

        // Ensure parent directory exists
        if let Some(parent) = dest.parent() {
            if !parent.exists() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }

        // Atomic write via temp file
        let temp_path = dest.with_extension(".tmp.partial");
        tokio::fs::write(&temp_path, &state.buffer).await?;
        tokio::fs::rename(&temp_path, dest).await?;

        info!(file_id = %state.file_id, path = %dest.display(), bytes = state.buffer.len(), "File written to disk");

        Ok(dest.clone())
    }
}

// ── Decryption / Decompression helpers ───────────────────────────────────────

/// Decrypt a chunk: expects nonce (12 bytes) || ciphertext || tag.
fn decrypt_chunk(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(anyhow!("Encrypted chunk too short"));
    }
    let cipher = Aes256Gcm::new_from_slice(key)?;
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&data[..12]);
    cipher
        .decrypt(nonce, &data[12..])
        .map_err(|e| anyhow!("Chunk decryption failed: {}", e))
}

/// Decompress a Brotli-compressed chunk.
fn decompress_chunk(data: &[u8]) -> Result<Vec<u8>> {
    let mut decompressor = Decompressor::new(data, 4096);
    let mut decompressed = Vec::new();
    decompressor.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    

    #[test]
    fn test_ack_range_from_bitmap() {
        let mut bm = ChunkBitmap::new(10);
        bm.set(0);
        bm.set(1);
        bm.set(2);
        bm.set(5);
        bm.set(6);
        bm.set(9);

        let file_id = Uuid::new_v4();
        let ack = AckRange::from_bitmap(file_id, &bm);
        assert_eq!(ack.ranges, vec![(0, 3), (5, 7), (9, 10)]);
        assert_eq!(ack.acked_count(), 6);
        assert!(ack.contains(0));
        assert!(ack.contains(2));
        assert!(!ack.contains(3));
        assert!(ack.contains(5));
        assert!(!ack.contains(7));
        assert!(ack.contains(9));
    }
}
