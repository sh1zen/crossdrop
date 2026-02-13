//! Chunk bitmap for tracking received chunks (used for resume).

use serde::{Deserialize, Serialize};

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

    /// Returns an iterator over missing chunk indices (chunks not yet received).
    /// Used by the sender to determine which chunks to send during resume.
    pub fn missing_chunks(&self) -> impl Iterator<Item = u32> + '_ {
        (0..self.total_chunks).filter(move |&i| !self.is_set(i))
    }

    /// Returns the number of missing chunks.
    pub fn missing_count(&self) -> u32 {
        (0..self.total_chunks).filter(|&i| !self.is_set(i)).count() as u32
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
            bits.push(u64::from_be_bytes(
                data[offset..offset + 8].try_into().ok()?,
            ));
        }
        Some(Self { total_chunks, bits })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitmap() {
        let mut bm = ChunkBitmap::new(100);

        bm.set(0);
        bm.set(50);
        bm.set(99);
        assert!(bm.is_set(0));
        assert!(bm.is_set(50));
        assert!(!bm.is_set(1));
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
    }
}
