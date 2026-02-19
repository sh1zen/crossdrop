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

// ── Merkle Tree ────────────────────────────────────────────────────────────────

/// A Merkle tree built from chunk hashes.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// The computed Merkle root.
    root: [u8; 32],
    /// All leaf hashes (chunk hashes).
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// Build a Merkle tree from an ordered list of chunk hashes.
    pub fn build(chunk_hashes: &[[u8; 32]]) -> Self {
        let root = Self::compute_root(chunk_hashes);
        Self {
            root,
            leaves: chunk_hashes.to_vec(),
        }
    }

    /// Get the Merkle root.
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Get all leaf hashes.
    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    /// Compute the Merkle root from a list of leaf hashes.
    pub fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        match leaves.len() {
            0 => [0u8; 32],
            1 => leaves[0],
            _ => Self::compute_root_recursive(leaves),
        }
    }

    /// Recursive root computation for 2+ leaves.
    fn compute_root_recursive(leaves: &[[u8; 32]]) -> [u8; 32] {
        let mut current_level = leaves.to_vec();

        while current_level.len() > 1 {
            current_level = Self::build_next_level(&current_level);
        }

        current_level[0]
    }

    /// Build the next level of the Merkle tree.
    fn build_next_level(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
        let mut next_level = Vec::with_capacity((level.len() + 1) / 2);

        for pair in level.chunks(2) {
            let hash = if pair.len() == 2 {
                hash_pair(&pair[0], &pair[1])
            } else {
                // Odd node: hash with itself
                hash_pair(&pair[0], &pair[0])
            };
            next_level.push(hash);
        }

        next_level
    }
}

// ── Incremental Builder ────────────────────────────────────────────────────────

/// Incremental Merkle tree builder.
///
/// Allows adding leaves one at a time and computing the root at any point.
/// Used by the sender to compute the Merkle root as chunks are processed.
#[derive(Debug, Clone, Default)]
pub struct IncrementalMerkleBuilder {
    leaves: Vec<[u8; 32]>,
}

impl IncrementalMerkleBuilder {
    /// Create a new incremental Merkle builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            leaves: Vec::with_capacity(capacity),
        }
    }

    /// Add a leaf hash to the tree.
    pub fn add_leaf(&mut self, hash: [u8; 32]) {
        self.leaves.push(hash);
    }

    /// Convert into a MerkleTree.
    pub fn build(self) -> MerkleTree {
        MerkleTree::build(&self.leaves)
    }
}

// ── Chunk Hash Verifier ────────────────────────────────────────────────────────

/// Expected chunk hashes for verification.
///
/// Created from the sender's MerkleTree message, used by the receiver
/// to verify each chunk as it arrives.
#[derive(Debug, Clone)]
pub struct ChunkHashVerifier {
    chunk_hashes: Vec<[u8; 32]>,
}

impl ChunkHashVerifier {
    /// Create a new verifier from chunk hashes received from the sender.
    pub fn new(chunk_hashes: Vec<[u8; 32]>) -> Self {
        Self { chunk_hashes }
    }

    /// Create a new verifier with pre-allocated capacity for incremental hash addition.
    pub fn with_capacity(total_chunks: usize) -> Self {
        Self {
            chunk_hashes: vec![[0u8; 32]; total_chunks],
        }
    }

    /// Add chunk hashes starting at a specific index.
    pub fn add_hashes(&mut self, start_index: u32, hashes: Vec<[u8; 32]>) {
        let start = start_index as usize;
        for (i, hash) in hashes.into_iter().enumerate() {
            if let Some(slot) = self.chunk_hashes.get_mut(start + i) {
                *slot = hash;
            }
        }
    }

    /// Get the expected hash for a specific chunk.
    pub fn get_chunk_hash(&self, seq: u32) -> Option<&[u8; 32]> {
        self.chunk_hashes.get(seq as usize)
    }

    /// Get total number of chunks.
    pub fn total_chunks(&self) -> u32 {
        self.chunk_hashes.len() as u32
    }

    /// Verify a pre-computed chunk hash against the expected hash.
    pub fn verify_chunk_hash(
        &self,
        seq: u32,
        computed: &[u8; 32],
    ) -> Result<(), ChunkVerificationError> {
        let expected = self
            .get_chunk_hash(seq)
            .ok_or_else(|| ChunkVerificationError::InvalidSequence {
                seq,
                total: self.total_chunks(),
            })?;

        // Check if hash has been set (for incremental verification)
        if expected == &[0u8; 32] {
            return Err(ChunkVerificationError::HashNotYetReceived { seq });
        }

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
    /// The chunk hash hasn't been received yet (incremental verification).
    HashNotYetReceived { seq: u32 },
}

impl std::fmt::Display for ChunkVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSequence { seq, total } => {
                write!(f, "Invalid chunk sequence {} (total: {})", seq, total)
            }
            Self::HashMismatch { seq } => {
                write!(f, "Chunk {} hash mismatch", seq)
            }
            Self::HashNotYetReceived { seq } => {
                write!(f, "Chunk {} hash not yet received", seq)
            }
        }
    }
}

impl std::error::Error for ChunkVerificationError {}

// ── Hashing Functions ──────────────────────────────────────────────────────────

/// Hash a chunk of data.
pub fn hash_chunk(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    finalize_hash(hasher)
}

/// Hash two nodes together for Merkle tree construction.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(left);
    hasher.update(right);
    finalize_hash(hasher)
}

/// Finalize a SHA3-256 hasher into a 32-byte array.
fn finalize_hash(hasher: Sha3_256) -> [u8; 32] {
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

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
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let tree = MerkleTree::build(&[h1, h2]);
        let expected = hash_pair(&h1, &h2);
        assert_eq!(*tree.root(), expected);
    }

    #[test]
    fn test_odd_chunks() {
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let h3 = [3u8; 32];
        let tree = MerkleTree::build(&[h1, h2, h3]);
        let left = hash_pair(&h1, &h2);
        let right = hash_pair(&h3, &h3);
        let root = hash_pair(&left, &right);
        assert_eq!(*tree.root(), root);
    }

    #[test]
    fn test_empty() {
        let tree = MerkleTree::build(&[]);
        assert_eq!(*tree.root(), [0u8; 32]);
    }

    #[test]
    fn test_incremental_builder() {
        let mut builder = IncrementalMerkleBuilder::with_capacity(3);

        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let h3 = [3u8; 32];

        builder.add_leaf(h1);
        builder.add_leaf(h2);
        builder.add_leaf(h3);

        let tree = builder.build();
        let expected_tree = MerkleTree::build(&[h1, h2, h3]);

        assert_eq!(*tree.root(), *expected_tree.root());
    }

    #[test]
    fn test_merkle_tree_leaves() {
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let tree = MerkleTree::build(&[h1, h2]);

        assert_eq!(tree.leaves(), &[h1, h2]);
    }

    #[test]
    fn test_chunk_hash_verifier() {
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let verifier = ChunkHashVerifier::new(vec![h1, h2]);

        assert!(verifier.verify_chunk_hash(0, &h1).is_ok());
        assert!(verifier.verify_chunk_hash(1, &h2).is_ok());
        assert!(verifier.verify_chunk_hash(0, &h2).is_err());
    }

    #[test]
    fn test_chunk_hash_verifier_incremental() {
        let mut verifier = ChunkHashVerifier::with_capacity(2);

        // Initially, hashes are zero
        assert!(matches!(
            verifier.verify_chunk_hash(0, &[0u8; 32]),
            Err(ChunkVerificationError::HashNotYetReceived { .. })
        ));

        // Add hashes
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        verifier.add_hashes(0, vec![h1]);
        verifier.add_hashes(1, vec![h2]);

        assert!(verifier.verify_chunk_hash(0, &h1).is_ok());
        assert!(verifier.verify_chunk_hash(1, &h2).is_ok());
    }
}
