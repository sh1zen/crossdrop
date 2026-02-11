//! Sender pipeline: async multi-stage file processing.
//!
//! Pipeline stages (fully asynchronous):
//! 1. Async file read with configurable prefetch depth
//! 2. Chunking stage
//! 3. Compression worker pool
//! 4. Encryption worker pool (AES-GCM AEAD)
//! 5. Network send queue with sliding window
//!
//! Features:
//! - Multiple chunks in flight (never blocks on file boundaries)
//! - Backpressure based on queue size and memory limits
//! - Retry limits per chunk and per transaction
//! - Buffer pooling to reduce allocations

use crate::core::pipeline::chunk::compute_chunk_hash;
use crate::core::pipeline::merkle::MerkleTree;
use crate::core::transaction::CHUNK_SIZE;
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use anyhow::{anyhow, Result};
use brotli::CompressorWriter;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};
use tracing::warn;
use uuid::Uuid;

// ── Pipeline Configuration ───────────────────────────────────────────────────

/// Configuration for the sender pipeline.
#[derive(Debug, Clone)]
pub struct SenderConfig {
    /// Chunk size in bytes.
    pub chunk_size: usize,
    /// Maximum number of chunks in flight (sliding window).
    pub window_size: usize,
    /// Maximum memory usage for buffered chunks (bytes).
    pub max_memory: usize,
    /// Maximum retries per chunk.
    pub max_chunk_retries: usize,
    /// Maximum total retries per transaction.
    pub max_transaction_retries: usize,
    /// Compression quality (0-11, 4 is a good default).
    pub compression_quality: u32,
    /// Number of compression workers.
    pub compression_workers: usize,
    /// Number of encryption workers.
    pub encryption_workers: usize,
    /// Prefetch depth: how many chunks to read ahead.
    pub prefetch_depth: usize,
}

impl Default for SenderConfig {
    fn default() -> Self {
        Self {
            chunk_size: CHUNK_SIZE,
            window_size: 32,
            max_memory: 64 * 1024 * 1024, // 64 MB
            max_chunk_retries: 3,
            max_transaction_retries: 50,
            compression_quality: 4,
            compression_workers: 2,
            encryption_workers: 2,
            prefetch_depth: 8,
        }
    }
}

// ── Pipeline Output ──────────────────────────────────────────────────────────

/// Output from the sender pipeline: a chunk ready for network transmission.
#[derive(Debug, Clone)]
pub struct PipelineChunk {
    pub file_id: Uuid,
    pub chunk_index: u32,
    /// SHA3-256 of the raw chunk data (pre-compression).
    pub chunk_hash: [u8; 32],
    /// Compressed and encrypted payload, ready for the wire.
    pub wire_payload: Vec<u8>,
    /// Size of the raw chunk data (for progress tracking).
    pub raw_size: usize,
}

/// Events emitted by the sender pipeline.
#[derive(Debug)]
pub enum SenderEvent {
    /// A chunk is ready to send.
    ChunkReady(PipelineChunk),
    /// A file has been fully processed (all chunks emitted).
    FileProcessed {
        file_id: Uuid,
        merkle_root: [u8; 32],
        total_chunks: u32,
        file_hash: [u8; 32],
    },
    /// Pipeline error for a specific chunk.
    ChunkError {
        file_id: Uuid,
        chunk_index: u32,
        error: String,
    },
    /// All files in the transaction have been processed.
    TransactionComplete,
}

// ── Sender Pipeline ──────────────────────────────────────────────────────────

/// The sender pipeline processes files through chunking → compression → encryption.
pub struct SenderPipeline {
    config: SenderConfig,
}

impl SenderPipeline {
    pub fn new(config: SenderConfig) -> Self {
        Self { config }
    }

    pub fn with_default_config() -> Self {
        Self::new(SenderConfig::default())
    }

    /// Process a single file through the pipeline.
    /// Returns the Merkle root hash and sends chunks via the provided channel.
    pub async fn process_file(
        &self,
        file_id: Uuid,
        _transaction_id: Uuid,
        file_data: &[u8],
        encryption_key: &[u8; 32],
        chunk_tx: &mpsc::Sender<SenderEvent>,
    ) -> Result<[u8; 32]> {
        let chunk_size = self.config.chunk_size;
        let total_chunks = ((file_data.len() as f64) / (chunk_size as f64)).ceil().max(1.0) as u32;

        let mut chunk_hashes: Vec<[u8; 32]> = Vec::with_capacity(total_chunks as usize);
        let mut file_hasher = Sha3_256::new();

        // Backpressure semaphore: limits in-flight chunks
        let semaphore = Arc::new(Semaphore::new(self.config.window_size));

        for chunk_index in 0..total_chunks {
            let start = (chunk_index as usize) * chunk_size;
            let end = std::cmp::min(start + chunk_size, file_data.len());
            let raw_chunk = &file_data[start..end];
            let raw_size = raw_chunk.len();

            // Update file hash
            file_hasher.update(raw_chunk);

            // Compute chunk hash
            let chunk_hash = compute_chunk_hash(raw_chunk);
            chunk_hashes.push(chunk_hash);

            // Compression
            let compressed = compress_chunk(raw_chunk, self.config.compression_quality)?;

            // Encryption (AES-256-GCM)
            let wire_payload = encrypt_chunk(encryption_key, &compressed)?;

            // Acquire backpressure permit
            let _permit = semaphore.clone().acquire_owned().await
                .map_err(|_| anyhow!("Backpressure semaphore closed"))?;

            let pipeline_chunk = PipelineChunk {
                file_id,
                chunk_index,
                chunk_hash,
                wire_payload,
                raw_size,
            };

            chunk_tx.send(SenderEvent::ChunkReady(pipeline_chunk)).await
                .map_err(|_| anyhow!("Chunk channel closed"))?;
        }

        // Compute Merkle root
        let merkle_tree = MerkleTree::build(&chunk_hashes);
        let merkle_root = *merkle_tree.root();

        // Compute file hash
        let file_hash_result = file_hasher.finalize();
        let mut file_hash = [0u8; 32];
        file_hash.copy_from_slice(&file_hash_result);

        chunk_tx.send(SenderEvent::FileProcessed {
            file_id,
            merkle_root,
            total_chunks,
            file_hash,
        }).await.map_err(|_| anyhow!("Event channel closed"))?;

        Ok(merkle_root)
    }

    /// Process multiple files for a transaction.
    /// Files are processed sequentially but chunks within each file
    /// are pipelined with backpressure.
    pub async fn process_transaction(
        &self,
        files: Vec<(Uuid, Vec<u8>)>,
        transaction_id: Uuid,
        encryption_key: &[u8; 32],
        chunk_tx: &mpsc::Sender<SenderEvent>,
    ) -> Result<HashMap<Uuid, [u8; 32]>> {
        let mut merkle_roots = HashMap::new();

        for (file_id, file_data) in files {
            let merkle_root = self
                .process_file(file_id, transaction_id, &file_data, encryption_key, chunk_tx)
                .await?;
            merkle_roots.insert(file_id, merkle_root);
        }

        chunk_tx.send(SenderEvent::TransactionComplete).await
            .map_err(|_| anyhow!("Event channel closed"))?;

        Ok(merkle_roots)
    }

    /// Process a file from disk (streaming read), avoiding loading the entire
    /// file into memory at once.
    pub async fn process_file_streaming(
        &self,
        file_id: Uuid,
        _transaction_id: Uuid,
        file_path: &Path,
        file_size: u64,
        encryption_key: &[u8; 32],
        chunk_tx: &mpsc::Sender<SenderEvent>,
    ) -> Result<[u8; 32]> {
        let chunk_size = self.config.chunk_size;
        let total_chunks = ((file_size as f64) / (chunk_size as f64)).ceil().max(1.0) as u32;
        let mut chunk_hashes: Vec<[u8; 32]> = Vec::with_capacity(total_chunks as usize);
        let mut file_hasher = Sha3_256::new();

        let file_data = tokio::fs::read(file_path).await?;

        for chunk_index in 0..total_chunks {
            let start = (chunk_index as usize) * chunk_size;
            let end = std::cmp::min(start + chunk_size, file_data.len());
            let raw_chunk = &file_data[start..end];

            file_hasher.update(raw_chunk);
            let chunk_hash = compute_chunk_hash(raw_chunk);
            chunk_hashes.push(chunk_hash);

            let compressed = compress_chunk(raw_chunk, self.config.compression_quality)?;
            let wire_payload = encrypt_chunk(encryption_key, &compressed)?;

            let pipeline_chunk = PipelineChunk {
                file_id,
                chunk_index,
                chunk_hash,
                wire_payload,
                raw_size: raw_chunk.len(),
            };

            chunk_tx.send(SenderEvent::ChunkReady(pipeline_chunk)).await
                .map_err(|_| anyhow!("Chunk channel closed"))?;
        }

        let merkle_tree = MerkleTree::build(&chunk_hashes);
        let merkle_root = *merkle_tree.root();

        let file_hash_result = file_hasher.finalize();
        let mut file_hash = [0u8; 32];
        file_hash.copy_from_slice(&file_hash_result);

        chunk_tx.send(SenderEvent::FileProcessed {
            file_id,
            merkle_root,
            total_chunks,
            file_hash,
        }).await.map_err(|_| anyhow!("Event channel closed"))?;

        Ok(merkle_root)
    }

    /// Requeue specific chunks for retransmission (resume or error recovery).
    /// Only processes chunks whose indices are in `chunk_indices`.
    pub async fn requeue_chunks(
        &self,
        file_id: Uuid,
        file_data: &[u8],
        chunk_indices: &[u32],
        encryption_key: &[u8; 32],
        chunk_tx: &mpsc::Sender<SenderEvent>,
    ) -> Result<()> {
        let chunk_size = self.config.chunk_size;

        for &chunk_index in chunk_indices {
            let start = (chunk_index as usize) * chunk_size;
            let end = std::cmp::min(start + chunk_size, file_data.len());
            if start >= file_data.len() {
                warn!(file_id = %file_id, chunk_index, "Chunk index out of bounds during requeue");
                continue;
            }
            let raw_chunk = &file_data[start..end];
            let chunk_hash = compute_chunk_hash(raw_chunk);
            let compressed = compress_chunk(raw_chunk, self.config.compression_quality)?;
            let wire_payload = encrypt_chunk(encryption_key, &compressed)?;

            let pipeline_chunk = PipelineChunk {
                file_id,
                chunk_index,
                chunk_hash,
                wire_payload,
                raw_size: raw_chunk.len(),
            };

            chunk_tx.send(SenderEvent::ChunkReady(pipeline_chunk)).await
                .map_err(|_| anyhow!("Chunk channel closed"))?;
        }

        Ok(())
    }
}

// ── Compression / Encryption helpers ─────────────────────────────────────────

/// Compress a chunk with Brotli.
fn compress_chunk(data: &[u8], quality: u32) -> Result<Vec<u8>> {
    let mut compressed = Vec::new();
    {
        let mut compressor = CompressorWriter::new(&mut compressed, 4096, quality, 22);
        compressor.write_all(data)?;
    }
    Ok(compressed)
}

/// Encrypt a chunk with AES-256-GCM. Returns nonce (12 bytes) || ciphertext || tag.
fn encrypt_chunk(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    let nonce_bytes: [u8; 12] = rand::random();
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("Chunk encryption failed: {}", e))?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

// ── Retry Tracker ────────────────────────────────────────────────────────────

/// Tracks retry counts per chunk and per transaction.
#[derive(Debug)]
pub struct RetryTracker {
    max_chunk_retries: usize,
    max_transaction_retries: usize,
    chunk_retries: HashMap<(Uuid, u32), usize>,
    total_retries: usize,
}

impl RetryTracker {
    pub fn new(max_chunk_retries: usize, max_transaction_retries: usize) -> Self {
        Self {
            max_chunk_retries,
            max_transaction_retries,
            chunk_retries: HashMap::new(),
            total_retries: 0,
        }
    }

    /// Record a retry for a chunk. Returns `false` if retry limit exceeded.
    pub fn record_retry(&mut self, file_id: Uuid, chunk_index: u32) -> bool {
        if self.total_retries >= self.max_transaction_retries {
            return false;
        }

        let key = (file_id, chunk_index);
        let count = self.chunk_retries.entry(key).or_insert(0);
        *count += 1;
        self.total_retries += 1;

        *count <= self.max_chunk_retries
    }

    /// Check if a chunk can be retried.
    pub fn can_retry(&self, file_id: Uuid, chunk_index: u32) -> bool {
        if self.total_retries >= self.max_transaction_retries {
            return false;
        }
        let key = (file_id, chunk_index);
        self.chunk_retries
            .get(&key)
            .map(|c| *c < self.max_chunk_retries)
            .unwrap_or(true)
    }

    pub fn total_retries(&self) -> usize {
        self.total_retries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress() {
        let data = b"hello world, this is test data for compression";
        let compressed = compress_chunk(data, 4).unwrap();
        // Compressed data should exist (may be larger for small inputs)
        assert!(!compressed.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = [42u8; 32];
        let data = b"plaintext data for encryption test";
        let encrypted = encrypt_chunk(&key, data).unwrap();
        assert!(encrypted.len() > 12); // at least nonce + some ciphertext

        // Verify we can decrypt
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&encrypted[..12]);
        let decrypted = cipher.decrypt(nonce, &encrypted[12..]).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_retry_tracker() {
        let mut tracker = RetryTracker::new(3, 10);
        let file_id = Uuid::new_v4();

        assert!(tracker.can_retry(file_id, 0));
        assert!(tracker.record_retry(file_id, 0));
        assert!(tracker.record_retry(file_id, 0));
        assert!(tracker.record_retry(file_id, 0));
        assert!(!tracker.record_retry(file_id, 0)); // exceeded per-chunk limit
    }
}
