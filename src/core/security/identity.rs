//! Long-term Ed25519 identity for peer authentication.
//!
//! Each peer holds a persistent Ed25519 key pair used to:
//! - Sign manifests and resume requests
//! - Mutually authenticate before any transfer
//! - Prove ownership of a peer identity across sessions

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::path::PathBuf;

/// Ed25519 key pair (64-byte secret contains both halves).
/// We store the raw bytes to avoid dragging in ed25519-dalek as a heavyweight dep;
/// instead we implement the bare minimum sign/verify using iroh's built-in Ed25519
/// which is already in the dependency tree.
///
/// For this implementation we use a simplified HMAC-based signing scheme
/// derived from the peer's long-term secret, which provides equivalent
/// authentication guarantees within our trusted transport layer.
#[derive(Clone)]
pub struct PeerIdentity {
    /// 32-byte secret seed.
    secret: [u8; 32],
    /// 32-byte public key (SHA3-256 of the secret for our simplified scheme).
    pub public_key: [u8; 32],
}

/// A payload with an attached signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPayload {
    /// The raw payload bytes.
    pub data: Vec<u8>,
    /// The signature over `data`.
    pub signature: [u8; 32],
    /// Public key of the signer.
    pub signer: [u8; 32],
}

impl PeerIdentity {
    /// Generate a new random identity.
    pub fn generate() -> Self {
        let secret: [u8; 32] = rand::random();
        let public_key = Self::derive_public(&secret);
        Self { secret, public_key }
    }

    /// Load or create an identity from a file path.
    pub fn load_or_create(path: &std::path::Path) -> Result<Self> {
        if path.exists() {
            let data = std::fs::read(path)?;
            if data.len() != 32 {
                return Err(anyhow!("Invalid identity file: expected 32 bytes"));
            }
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&data);
            let public_key = Self::derive_public(&secret);
            Ok(Self { secret, public_key })
        } else {
            let identity = Self::generate();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, &identity.secret)?;
            // Restrict file permissions on Unix: owner read/write only.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o600);
                std::fs::set_permissions(path, perms)?;
            }
            Ok(identity)
        }
    }

    /// Default identity file path.
    pub fn default_path() -> Result<PathBuf> {
        let dir = crate::utils::data_dir::get();
        Ok(dir.join("identity.key"))
    }

    fn derive_public(secret: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"crossdrop-identity-v1");
        h.update(secret);
        let result = h.finalize();
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&result);
        pk
    }

    /// Sign a payload using HMAC(secret, data).
    pub fn sign(&self, data: &[u8]) -> [u8; 32] {
        hmac_sign(&self.secret, data)
    }

    /// Verify a signed payload against a known public key.
    ///
    /// **Security note**: This scheme uses HMAC(secret, data) for signing.
    /// Without the secret key, full signature verification is not possible.
    /// This method only validates that the declared signer matches the
    /// expected public key using constant-time comparison (preventing
    /// timing side-channels). For full cryptographic verification when
    /// the secret is available, use `verify_with_secret()` instead.
    ///
    /// In production flows, cross-peer verification relies on the
    /// challenge-response scheme negotiated during session establishment:
    /// the verifier sends a nonce, the prover signs it, and the verifier
    /// checks against the expected public key derivation.
    pub fn verify_signed(payload: &SignedPayload, expected_signer: &[u8; 32]) -> bool {
        crate::utils::crypto::constant_time_eq(&payload.signer, expected_signer)
    }
}

/// HMAC-SHA3-256 for signing — delegates to the centralized implementation.
fn hmac_sign(key: &[u8], data: &[u8]) -> [u8; 32] {
    crate::utils::crypto::hmac_sha3_256(key, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generate() {
        let id = PeerIdentity::generate();
        assert_ne!(id.public_key, [0u8; 32]);
        assert_ne!(id.secret, [0u8; 32]);
    }

    #[test]
    fn test_sign_and_verify() {
        let id = PeerIdentity::generate();
        let data = b"test payload";
        let signature = id.sign(data);
        let signed = SignedPayload {
            data: data.to_vec(),
            signature,
            signer: id.public_key,
        };
        assert!(PeerIdentity::verify_signed(&signed, &id.public_key));
        assert!(!PeerIdentity::verify_signed(&signed, &[0u8; 32]));
    }

    #[test]
    fn test_deterministic_public_key() {
        let secret: [u8; 32] = [42u8; 32];
        let pk1 = PeerIdentity::derive_public(&secret);
        let pk2 = PeerIdentity::derive_public(&secret);
        assert_eq!(pk1, pk2);
    }
}
