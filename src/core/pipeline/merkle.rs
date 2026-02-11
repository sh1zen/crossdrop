//! Merkle tree for file integrity verification.
//!
//! The sender computes Merkle roots for each file in the manifest.
//! The receiver incrementally reconstructs the tree and validates
//! the final root against the manifest.

use sha3::{Digest, Sha3_256};
use serde::{Deserialize, Serialize};

/// A Merkle tree built from chunk hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    /// Leaf hashes (one per chunk, in order).
    leaves: Vec<[u8; 32]>,
    /// The computed Merkle root.
    root: [u8; 32],
}

impl MerkleTree {
    /// Build a Merkle tree from an ordered list of chunk hashes.
    pub fn build(chunk_hashes: &[[u8; 32]]) -> Self {
        if chunk_hashes.is_empty() {
            return Self {
                leaves: Vec::new(),
                root: [0u8; 32],
            };
        }

        let leaves: Vec<[u8; 32]> = chunk_hashes.to_vec();
        let root = Self::compute_root(&leaves);

        Self { leaves, root }
    }

    /// Get the Merkle root.
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Get the number of leaves (chunks).
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Compute the Merkle root from a list of leaf hashes.
    fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
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

/// Incremental Merkle tree builder for the receiver.
/// Collects chunk hashes as they arrive and can verify the final root.
#[derive(Debug, Clone)]
pub struct IncrementalMerkleBuilder {
    /// Expected total number of chunks.
    total_chunks: u32,
    /// Collected chunk hashes, indexed by chunk_index.
    hashes: Vec<Option<[u8; 32]>>,
    /// Number of hashes collected so far.
    collected: u32,
}

impl IncrementalMerkleBuilder {
    pub fn new(total_chunks: u32) -> Self {
        Self {
            total_chunks,
            hashes: vec![None; total_chunks as usize],
            collected: 0,
        }
    }

    /// Add a chunk hash at the given index.
    /// Returns `true` if the hash was newly added.
    pub fn add_hash(&mut self, index: u32, hash: [u8; 32]) -> bool {
        if index >= self.total_chunks {
            return false;
        }
        if self.hashes[index as usize].is_none() {
            self.hashes[index as usize] = Some(hash);
            self.collected += 1;
            true
        } else {
            false
        }
    }

    /// Check if all hashes have been collected.
    pub fn is_complete(&self) -> bool {
        self.collected == self.total_chunks
    }

    /// Compute the Merkle root from collected hashes.
    /// Returns `None` if not all hashes have been collected.
    pub fn compute_root(&self) -> Option<[u8; 32]> {
        if !self.is_complete() {
            return None;
        }

        let leaves: Vec<[u8; 32]> = self
            .hashes
            .iter()
            .map(|h| h.expect("all hashes should be present"))
            .collect();

        Some(MerkleTree::compute_root(&leaves))
    }

    /// Verify the final Merkle root against an expected value.
    pub fn verify_root(&self, expected: &[u8; 32]) -> Option<bool> {
        self.compute_root().map(|root| root == *expected)
    }

    /// Number of hashes collected.
    pub fn collected_count(&self) -> u32 {
        self.collected
    }
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

/// Compute the Merkle root for a file given its raw bytes and chunk size.
pub fn compute_file_merkle_root(file_data: &[u8], chunk_size: usize) -> [u8; 32] {
    if file_data.is_empty() {
        return [0u8; 32];
    }

    let chunk_hashes: Vec<[u8; 32]> = file_data
        .chunks(chunk_size)
        .map(|chunk| {
            let mut hasher = Sha3_256::new();
            hasher.update(chunk);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        })
        .collect();

    let tree = MerkleTree::build(&chunk_hashes);
    *tree.root()
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
        let right = hash_pair(&h3, &h3); // odd, hashed with itself
        let root = hash_pair(&left, &right);
        assert_eq!(*tree.root(), root);
    }

    #[test]
    fn test_incremental_builder() {
        let hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let tree = MerkleTree::build(&hashes);

        let mut builder = IncrementalMerkleBuilder::new(4);
        assert!(!builder.is_complete());

        // Add in random order
        builder.add_hash(2, hashes[2]);
        builder.add_hash(0, hashes[0]);
        builder.add_hash(3, hashes[3]);
        assert!(!builder.is_complete());

        builder.add_hash(1, hashes[1]);
        assert!(builder.is_complete());

        assert_eq!(builder.verify_root(tree.root()), Some(true));
    }

    #[test]
    fn test_file_merkle_root() {
        let data = vec![0u8; 1024];
        let root = compute_file_merkle_root(&data, 256);
        assert_ne!(root, [0u8; 32]);

        // Same data should produce same root
        let root2 = compute_file_merkle_root(&data, 256);
        assert_eq!(root, root2);
    }

    #[test]
    fn test_empty() {
        let tree = MerkleTree::build(&[]);
        assert_eq!(*tree.root(), [0u8; 32]);
    }
}
