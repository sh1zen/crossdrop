//! Chunk data structures and integrity verification.
//!
//! Each chunk includes:
//! - file_id: identifies the file within the manifest
//! - chunk_index: incremental index within the file
//! - data: the actual bytes (post-compression, post-encryption payload)
//! - chunk_hash: SHA3-256 hash of the raw (pre-compression) chunk data
//!
//! The receiver verifies AEAD authentication, chunk hash, and incrementally
//! reconstructs the Merkle tree.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

/// Metadata for a chunk (sent as part of the binary frame).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMeta {
    /// File this chunk belongs to.
    pub file_id: Uuid,
    /// Zero-based index within the file.
    pub chunk_index: u32,
    /// SHA3-256 hash of the raw (uncompressed, unencrypted) chunk data.
    pub chunk_hash: [u8; 32],
    /// Transaction ID for authorization.
    pub transaction_id: Uuid,
}

/// A complete chunk with data ready for transmission or reception.
#[derive(Debug, Clone)]
pub struct ChunkData {
    pub meta: ChunkMeta,
    /// Raw chunk data (before compression/encryption on sender,
    /// after decryption/decompression on receiver).
    pub data: Vec<u8>,
}

/// A wire-format chunk (post-pipeline: compressed and encrypted).
#[derive(Debug, Clone)]
pub struct WireChunk {
    pub file_id: Uuid,
    pub chunk_index: u32,
    pub chunk_hash: [u8; 32],
    /// Encrypted, compressed payload.
    pub payload: Vec<u8>,
}

impl ChunkData {
    /// Create a new chunk from raw data, computing the hash.
    pub fn new(file_id: Uuid, chunk_index: u32, transaction_id: Uuid, data: Vec<u8>) -> Self {
        let chunk_hash = compute_chunk_hash(&data);
        Self {
            meta: ChunkMeta {
                file_id,
                chunk_index,
                chunk_hash,
                transaction_id,
            },
            data,
        }
    }

    /// Verify that the data matches the chunk hash.
    pub fn verify_hash(&self) -> bool {
        let computed = compute_chunk_hash(&self.data);
        computed == self.meta.chunk_hash
    }
}

/// Compute SHA3-256 hash of chunk data.
pub fn compute_chunk_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Chunk bitmap for tracking received chunks (used for resume).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkBitmap {
    /// Number of total chunks.
    pub total_chunks: u32,
    /// Bit vector: bit i is set if chunk i has been received and verified.
    bits: Vec<u64>,
}

impl ChunkBitmap {
    pub fn new(total_chunks: u32) -> Self {
        let words = ((total_chunks as usize) + 63) / 64;
        Self {
            total_chunks,
            bits: vec![0u64; words],
        }
    }

    /// Mark a chunk as received.
    pub fn set(&mut self, index: u32) {
        if index < self.total_chunks {
            let word = (index / 64) as usize;
            let bit = index % 64;
            self.bits[word] |= 1u64 << bit;
        }
    }

    /// Check if a chunk has been received.
    pub fn is_set(&self, index: u32) -> bool {
        if index >= self.total_chunks {
            return false;
        }
        let word = (index / 64) as usize;
        let bit = index % 64;
        (self.bits[word] >> bit) & 1 == 1
    }

    /// Count of received chunks.
    pub fn received_count(&self) -> u32 {
        self.bits.iter().map(|w| w.count_ones()).sum()
    }

    /// Check if all chunks have been received.
    pub fn is_complete(&self) -> bool {
        self.received_count() == self.total_chunks
    }

    /// Get list of missing chunk indices.
    pub fn missing_chunks(&self) -> Vec<u32> {
        (0..self.total_chunks)
            .filter(|i| !self.is_set(*i))
            .collect()
    }

    /// Encode as a compact byte representation for wire transfer.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + self.bits.len() * 8);
        bytes.extend_from_slice(&self.total_chunks.to_be_bytes());
        for word in &self.bits {
            bytes.extend_from_slice(&word.to_be_bytes());
        }
        bytes
    }

    /// Decode from wire format.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let total_chunks = u32::from_be_bytes(data[0..4].try_into().ok()?);
        let expected_words = ((total_chunks as usize) + 63) / 64;
        if data.len() < 4 + expected_words * 8 {
            return None;
        }
        let mut bits = Vec::with_capacity(expected_words);
        for i in 0..expected_words {
            let offset = 4 + i * 8;
            bits.push(u64::from_be_bytes(data[offset..offset + 8].try_into().ok()?));
        }
        Some(Self { total_chunks, bits })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_hash() {
        let data = b"hello world";
        let h1 = compute_chunk_hash(data);
        let h2 = compute_chunk_hash(data);
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn test_chunk_verify() {
        let chunk = ChunkData::new(Uuid::new_v4(), 0, Uuid::new_v4(), b"test data".to_vec());
        assert!(chunk.verify_hash());
    }

    #[test]
    fn test_bitmap() {
        let mut bm = ChunkBitmap::new(100);
        assert_eq!(bm.received_count(), 0);
        assert!(!bm.is_complete());

        bm.set(0);
        bm.set(50);
        bm.set(99);
        assert_eq!(bm.received_count(), 3);
        assert!(bm.is_set(0));
        assert!(bm.is_set(50));
        assert!(!bm.is_set(1));

        let missing = bm.missing_chunks();
        assert_eq!(missing.len(), 97);
    }

    #[test]
    fn test_bitmap_serialization() {
        let mut bm = ChunkBitmap::new(200);
        bm.set(0);
        bm.set(63);
        bm.set(64);
        bm.set(199);

        let bytes = bm.to_bytes();
        let bm2 = ChunkBitmap::from_bytes(&bytes).unwrap();
        assert_eq!(bm2.total_chunks, 200);
        assert!(bm2.is_set(0));
        assert!(bm2.is_set(63));
        assert!(bm2.is_set(64));
        assert!(bm2.is_set(199));
        assert!(!bm2.is_set(1));
        assert_eq!(bm2.received_count(), 4);
    }
}
