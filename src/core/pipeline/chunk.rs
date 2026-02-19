//! Chunk bitmap for tracking received chunks (used for resume).

use serde::{Deserialize, Serialize};

const WORD_BITS: u32 = 64;

/// Bit-vector tracking which chunks have been received.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkBitmap {
    pub total_chunks: u32,
    bits: Vec<u64>,
}

impl ChunkBitmap {
    pub fn new(total_chunks: u32) -> Self {
        let words = words_needed(total_chunks);
        Self {
            total_chunks,
            bits: vec![0u64; words],
        }
    }

    /// Mark chunk `index` as received.
    pub fn set(&mut self, index: u32) {
        if let Some((word, bit)) = self.location(index) {
            self.bits[word] |= 1u64 << bit;
        }
    }

    /// Return `true` if chunk `index` has been received.
    pub fn is_set(&self, index: u32) -> bool {
        self.location(index)
            .map(|(word, bit)| (self.bits[word] >> bit) & 1 == 1)
            .unwrap_or(false)
    }

    /// Iterator over indices of chunks not yet received.
    pub fn missing_chunks(&self) -> impl Iterator<Item = u32> + '_ {
        (0..self.total_chunks).filter(|&i| !self.is_set(i))
    }

    /// Number of chunks not yet received.
    pub fn missing_count(&self) -> u32 {
        self.missing_chunks().count() as u32
    }

    /// Encode to a compact wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.bits.len() * 8);
        out.extend_from_slice(&self.total_chunks.to_be_bytes());
        for &word in &self.bits {
            out.extend_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Decode from wire format.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let total_chunks = u32::from_be_bytes(data.get(..4)?.try_into().ok()?);
        let expected_words = words_needed(total_chunks);
        let required_len = 4 + expected_words * 8;
        if data.len() < required_len {
            return None;
        }
        let bits = (0..expected_words)
            .map(|i| {
                let off = 4 + i * 8;
                Some(u64::from_be_bytes(data[off..off + 8].try_into().ok()?))
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self { total_chunks, bits })
    }

    /// Return `(word_index, bit_index)` for `index`, or `None` if out of range.
    #[inline]
    fn location(&self, index: u32) -> Option<(usize, u32)> {
        (index < self.total_chunks).then(|| ((index / WORD_BITS) as usize, index % WORD_BITS))
    }
}

#[inline]
fn words_needed(total_chunks: u32) -> usize {
    ((total_chunks as usize) + 63) / 64
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
        for i in [0, 63, 64, 199] {
            bm.set(i);
        }
        let bm2 = ChunkBitmap::from_bytes(&bm.to_bytes()).unwrap();
        assert_eq!(bm2.total_chunks, 200);
        for i in [0u32, 63, 64, 199] {
            assert!(bm2.is_set(i));
        }
        assert!(!bm2.is_set(1));
    }
}
