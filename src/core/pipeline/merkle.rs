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

/// A Merkle tree built from chunk hashes.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// The computed Merkle root.
    root: [u8; 32],
    /// All leaf hashes (chunk hashes).
    leaves: Vec<[u8; 32]>,
}

/// Incremental Merkle tree builder.
///
/// Allows adding leaves one at a time and computing the root at any point.
/// Used by the sender to compute the Merkle root as chunks are processed.
#[derive(Debug, Clone)]
pub struct IncrementalMerkleBuilder {
    /// Leaf hashes collected so far.
    leaves: Vec<[u8; 32]>,
}

/// Expected chunk hashes for verification.
///
/// Created from the sender's MerkleTree message, used by the receiver
/// to verify each chunk as it arrives.
#[derive(Debug, Clone)]
pub struct ChunkHashVerifier {
    /// Expected hash for each chunk (indexed by chunk sequence number).
    chunk_hashes: Vec<[u8; 32]>,
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
        if leaves.is_empty() {
            return [0u8; 32];
        }
        if leaves.len() == 1 {
            return leaves[0];
        }

        let mut current_level: Vec<[u8; 32]> = leaves.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);

            for pair in current_level.chunks(2) {
                if pair.len() == 2 {
                    next_level.push(hash_pair(&pair[0], &pair[1]));
                } else {
                    // Odd node: promote it directly (hash with itself).
                    next_level.push(hash_pair(&pair[0], &pair[0]));
                }
            }

            current_level = next_level;
        }

        current_level[0]
    }
}

impl ChunkHashVerifier {
    /// Create a new verifier from chunk hashes received from the sender.
    pub fn new(chunk_hashes: Vec<[u8; 32]>) -> Self {
        Self { chunk_hashes }
    }

    /// Create a new verifier with pre-allocated capacity for incremental hash addition.
    /// Used when chunk hashes are sent in batches during transfer.
    pub fn with_capacity(total_chunks: usize) -> Self {
        Self {
            chunk_hashes: vec![[0u8; 32]; total_chunks],
        }
    }

    /// Add chunk hashes starting at a specific index.
    /// Used for incremental hash delivery during transfer.
    pub fn add_hashes(&mut self, start_index: u32, hashes: Vec<[u8; 32]>) {
        let start = start_index as usize;
        for (i, hash) in hashes.into_iter().enumerate() {
            if start + i < self.chunk_hashes.len() {
                self.chunk_hashes[start + i] = hash;
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
    /// This avoids double-hashing when the caller has already computed the
    /// SHA3-256 hash (e.g. in [`StreamingFileWriter::write_chunk`]).
    pub fn verify_chunk_hash(
        &self,
        seq: u32,
        computed: &[u8; 32],
    ) -> Result<(), ChunkVerificationError> {
        let expected =
            self.get_chunk_hash(seq)
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
            Self::HashMismatch { seq, .. } => {
                write!(f, "Chunk {} hash mismatch", seq)
            }
            Self::HashNotYetReceived { seq } => {
                write!(f, "Chunk {} hash not yet received", seq)
            }
        }
    }
}

impl std::error::Error for ChunkVerificationError {}

impl IncrementalMerkleBuilder {
    /// Create a new incremental Merkle builder.
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
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

impl Default for IncrementalMerkleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash a chunk of data.
pub fn hash_chunk(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Hash two nodes together for Merkle tree construction.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(left);
    hasher.update(right);
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

        assert_eq!(tree.leaves().len(), 2);
        assert_eq!(tree.leaves()[0], h1);
        assert_eq!(tree.leaves()[1], h2);
    }

    #[test]
    fn test_chunk_hash_verifier() {
        let data1 = b"chunk one data";
        let data2 = b"chunk two data";
        let h1 = hash_chunk(data1);
        let h2 = hash_chunk(data2);

        let verifier = ChunkHashVerifier::new(vec![h1, h2]);

        // verify_chunk_hash (pre-computed hash)
        assert!(verifier.verify_chunk_hash(0, &h1).is_ok());
        assert!(verifier.verify_chunk_hash(1, &h2).is_ok());
        assert!(verifier.verify_chunk_hash(0, &h2).is_err()); // wrong hash
    }
}
