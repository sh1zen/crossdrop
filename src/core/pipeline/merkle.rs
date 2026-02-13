//! Merkle tree for file integrity verification.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

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
}
