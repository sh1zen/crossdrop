//! Centralized cryptographic utilities: HMAC-SHA3-256, constant-time comparison.
//!
//! This module is the **single source of truth** for HMAC computation and
//! timing-safe comparison used throughout the codebase. All modules that
//! need HMAC (key derivation, message authentication, identity signing)
//! MUST use these functions instead of duplicating the implementation.
//!
//! Invariants:
//! - HMAC follows RFC 2104 with SHA3-256 (rate = 136 bytes).
//! - Constant-time comparison prevents timing side-channels on secret data.

use sha3::{Digest, Sha3_256};

/// SHA3-256 block size (rate in bytes for Keccak with 256-bit capacity).
const BLOCK_SIZE: usize = 136;

/// HMAC-SHA3-256 (RFC 2104 construction with SHA3-256).
///
/// Used for:
/// - Session key derivation (HKDF extract/expand)
/// - Protocol message authentication
/// - Identity-based signing
///
/// # Arguments
/// - `key`: The HMAC key (any length; hashed if > BLOCK_SIZE).
/// - `data`: The data to authenticate.
///
/// # Returns
/// A 32-byte HMAC tag.
pub fn hmac_sha3_256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let actual_key = prepare_key(key);

    let (ipad, opad) = compute_pads(&actual_key);

    // Inner hash: H(ipad || data)
    let inner_hash = {
        let mut inner = Sha3_256::new();
        inner.update(&ipad);
        inner.update(data);
        inner.finalize()
    };

    // Outer hash: H(opad || inner_hash)
    let mut outer = Sha3_256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    let result = outer.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Prepare the key for HMAC: hash if too long, pad if too short.
fn prepare_key(key: &[u8]) -> [u8; BLOCK_SIZE] {
    if key.len() > BLOCK_SIZE {
        let mut h = Sha3_256::new();
        h.update(key);
        let digest = h.finalize();
        let mut k = [0u8; BLOCK_SIZE];
        k[..32].copy_from_slice(&digest);
        k
    } else {
        let mut k = [0u8; BLOCK_SIZE];
        k[..key.len()].copy_from_slice(key);
        k
    }
}

/// Compute the inner and outer pads for HMAC.
fn compute_pads(key: &[u8; BLOCK_SIZE]) -> ([u8; BLOCK_SIZE], [u8; BLOCK_SIZE]) {
    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];

    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    (ipad, opad)
}

/// Constant-time comparison of two 32-byte values.
///
/// Prevents timing side-channel attacks when comparing HMAC tags,
/// session keys, or any secret-derived data.
pub fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_deterministic() {
        let r1 = hmac_sha3_256(b"key", b"data");
        let r2 = hmac_sha3_256(b"key", b"data");
        assert_eq!(r1, r2);
        assert_ne!(r1, [0u8; 32]);
    }

    #[test]
    fn test_hmac_different_keys() {
        let r1 = hmac_sha3_256(b"key1", b"data");
        let r2 = hmac_sha3_256(b"key2", b"data");
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_hmac_different_data() {
        let r1 = hmac_sha3_256(b"key", b"data1");
        let r2 = hmac_sha3_256(b"key", b"data2");
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_hmac_long_key() {
        // Key longer than BLOCK_SIZE (136 bytes)
        let long_key = vec![0xABu8; 200];
        let r = hmac_sha3_256(&long_key, b"data");
        assert_ne!(r, [0u8; 32]);
    }

    #[test]
    fn test_constant_time_eq_equal() {
        let a = [42u8; 32];
        assert!(constant_time_eq(&a, &a));
    }

    #[test]
    fn test_constant_time_eq_different() {
        let a = [42u8; 32];
        let b = [43u8; 32];
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_single_bit_diff() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[31] = 1; // single bit difference in last byte
        assert!(!constant_time_eq(&a, &b));
    }
}
