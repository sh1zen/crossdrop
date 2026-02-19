//! Merkle tree for file integrity verification with incremental computation.
//!
//! Used by the sender to compute the Merkle root as chunks are processed,
//! and by the receiver to verify file integrity.
//!
//! # Incremental Verification Flow
//!
//! 1. Sender computes chunk hashes incrementally while reading the file
//! 2. Sender sends the MerkleTree message (all chunk hashes + root) BEFORE chunks
//! 3. Receiver stores expected chunk hashes
//! 4. As each chunk arrives, receiver verifies its hash against the expected hash
//! 5. If any chunk fails verification, receiver requests retransmission
//! 6. Security is guaranteed by the Merkle root (sender cannot tamper with chunks)

use sha3::{Digest, Sha3_256};

// ── Hashing Functions ──────────────────────────────────────────────────────────

/// Hash a chunk of data using SHA3-256.
pub fn hash_chunk(data: &[u8]) -> [u8; 32] {
    finalize(Sha3_256::new().chain_update(data))
}

/// Hash two Merkle nodes together.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    finalize(Sha3_256::new().chain_update(left).chain_update(right))
}

/// Finalize a SHA3-256 hasher into a fixed-size array.
#[inline]
fn finalize(hasher: Sha3_256) -> [u8; 32] {
    hasher.finalize().into()
}

// ── Merkle Tree ────────────────────────────────────────────────────────────────

/// A Merkle tree built from chunk hashes.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    root: [u8; 32],
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// Build a Merkle tree from an ordered list of chunk hashes.
    pub fn build(chunk_hashes: &[[u8; 32]]) -> Self {
        Self {
            root: Self::compute_root(chunk_hashes),
            leaves: chunk_hashes.to_vec(),
        }
    }

    /// Return the Merkle root.
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Return all leaf hashes.
    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    /// Compute the Merkle root from a slice of leaf hashes.
    pub fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        match leaves {
            [] => [0u8; 32],
            [single] => *single,
            _ => {
                let mut level = leaves.to_vec();
                while level.len() > 1 {
                    level = level
                        .chunks(2)
                        .map(|pair| match pair {
                            [l, r] => hash_pair(l, r),
                            [l] => hash_pair(l, l), // odd node: promote by pairing with itself
                            _ => unreachable!(),
                        })
                        .collect();
                }
                level[0]
            }
        }
    }
}

// ── Incremental Builder ────────────────────────────────────────────────────────

/// Incrementally accumulates leaf hashes and produces a [`MerkleTree`].
///
/// Used by the sender to build the tree as chunks are read from disk.
#[derive(Debug, Clone, Default)]
pub struct IncrementalMerkleBuilder {
    leaves: Vec<[u8; 32]>,
}

impl IncrementalMerkleBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            leaves: Vec::with_capacity(capacity),
        }
    }

    /// Append a leaf hash.
    pub fn add_leaf(&mut self, hash: [u8; 32]) {
        self.leaves.push(hash);
    }

    /// Consume the builder and produce a [`MerkleTree`].
    pub fn build(self) -> MerkleTree {
        MerkleTree::build(&self.leaves)
    }
}

// ── Chunk Hash Verifier ────────────────────────────────────────────────────────

/// Holds expected per-chunk hashes and verifies incoming chunks against them.
///
/// Created from the sender's `MerkleTree` message; used by the receiver
/// to check each chunk as it arrives.
#[derive(Debug, Clone)]
pub struct ChunkHashVerifier {
    /// `None` means the hash for that slot has not yet been received.
    chunk_hashes: Vec<Option<[u8; 32]>>,
}

impl ChunkHashVerifier {
    /// Create a verifier pre-populated with all chunk hashes.
    pub fn new(chunk_hashes: Vec<[u8; 32]>) -> Self {
        Self {
            chunk_hashes: chunk_hashes.into_iter().map(Some).collect(),
        }
    }

    /// Create a verifier with capacity for `total_chunks`, all slots empty.
    pub fn with_capacity(total_chunks: usize) -> Self {
        Self {
            chunk_hashes: vec![None; total_chunks],
        }
    }

    /// Fill hash slots starting at `start_index`.
    pub fn add_hashes(&mut self, start_index: u32, hashes: Vec<[u8; 32]>) {
        let start = start_index as usize;
        for (i, hash) in hashes.into_iter().enumerate() {
            if let Some(slot) = self.chunk_hashes.get_mut(start + i) {
                *slot = Some(hash);
            }
        }
    }

    /// Return the expected hash for `seq`, if present.
    pub fn get_chunk_hash(&self, seq: u32) -> Option<&[u8; 32]> {
        self.chunk_hashes.get(seq as usize)?.as_ref()
    }

    /// Total number of chunk slots.
    pub fn total_chunks(&self) -> u32 {
        self.chunk_hashes.len() as u32
    }

    /// Verify a pre-computed chunk hash against the stored expectation.
    pub fn verify_chunk_hash(
        &self,
        seq: u32,
        computed: &[u8; 32],
    ) -> Result<(), ChunkVerificationError> {
        let total = self.total_chunks();
        let slot = self
            .chunk_hashes
            .get(seq as usize)
            .ok_or(ChunkVerificationError::InvalidSequence { seq, total })?;

        let expected = slot
            .as_ref()
            .ok_or(ChunkVerificationError::HashNotYetReceived { seq })?;

        if computed == expected {
            Ok(())
        } else {
            Err(ChunkVerificationError::HashMismatch { seq })
        }
    }
}

// ── Errors ─────────────────────────────────────────────────────────────────────

/// Errors that can occur during chunk verification.
#[derive(Debug, Clone)]
pub enum ChunkVerificationError {
    /// The chunk sequence number is out of range.
    InvalidSequence { seq: u32, total: u32 },
    /// The chunk hash doesn't match the expected hash.
    HashMismatch { seq: u32 },
    /// The hash for this chunk has not yet been received.
    HashNotYetReceived { seq: u32 },
}

impl std::fmt::Display for ChunkVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSequence { seq, total } => {
                write!(f, "Invalid chunk sequence {seq} (total: {total})")
            }
            Self::HashMismatch { seq } => write!(f, "Chunk {seq} hash mismatch"),
            Self::HashNotYetReceived { seq } => write!(f, "Chunk {seq} hash not yet received"),
        }
    }
}

impl std::error::Error for ChunkVerificationError {}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_chunk() {
        let hash = [42u8; 32];
        let tree = MerkleTree::build(&[hash]);
        assert_eq!(*tree.root(), hash);
    }

    #[test]
    fn test_two_chunks() {
        let (h1, h2) = ([1u8; 32], [2u8; 32]);
        assert_eq!(*MerkleTree::build(&[h1, h2]).root(), hash_pair(&h1, &h2));
    }

    #[test]
    fn test_odd_chunks() {
        let (h1, h2, h3) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let root = hash_pair(&hash_pair(&h1, &h2), &hash_pair(&h3, &h3));
        assert_eq!(*MerkleTree::build(&[h1, h2, h3]).root(), root);
    }

    #[test]
    fn test_empty() {
        assert_eq!(*MerkleTree::build(&[]).root(), [0u8; 32]);
    }

    #[test]
    fn test_incremental_builder() {
        let (h1, h2, h3) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let mut builder = IncrementalMerkleBuilder::with_capacity(3);
        builder.add_leaf(h1);
        builder.add_leaf(h2);
        builder.add_leaf(h3);
        assert_eq!(
            builder.build().root(),
            MerkleTree::build(&[h1, h2, h3]).root()
        );
    }

    #[test]
    fn test_merkle_tree_leaves() {
        let (h1, h2) = ([1u8; 32], [2u8; 32]);
        assert_eq!(MerkleTree::build(&[h1, h2]).leaves(), &[h1, h2]);
    }

    #[test]
    fn test_chunk_hash_verifier() {
        let (h1, h2) = ([1u8; 32], [2u8; 32]);
        let v = ChunkHashVerifier::new(vec![h1, h2]);
        assert!(v.verify_chunk_hash(0, &h1).is_ok());
        assert!(v.verify_chunk_hash(1, &h2).is_ok());
        assert!(v.verify_chunk_hash(0, &h2).is_err());
    }

    #[test]
    fn test_chunk_hash_verifier_incremental() {
        let mut v = ChunkHashVerifier::with_capacity(2);
        assert!(matches!(
            v.verify_chunk_hash(0, &[0u8; 32]),
            Err(ChunkVerificationError::HashNotYetReceived { .. })
        ));
        let (h1, h2) = ([1u8; 32], [2u8; 32]);
        v.add_hashes(0, vec![h1]);
        v.add_hashes(1, vec![h2]);
        assert!(v.verify_chunk_hash(0, &h1).is_ok());
        assert!(v.verify_chunk_hash(1, &h2).is_ok());
    }
}
