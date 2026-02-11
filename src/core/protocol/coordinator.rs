//! Transfer coordinator: orchestrates secure, resumable file transfers.
//!
//! The coordinator ties together:
//! - Security (identity, sessions, replay guards)
//! - Pipeline (sender/receiver chunking, compression, encryption)
//! - Protocol (manifest, authenticated messages)
//! - Transaction lifecycle (state machine, persistence)
//!
//! It acts as the central authority that validates all operations against
//! the manifest and security constraints.

use crate::core::pipeline::chunk::ChunkBitmap;
use crate::core::pipeline::sender::{RetryTracker, SenderConfig};
use crate::core::protocol::manifest::{SecureManifest, SecureManifestEntry};
use crate::core::security::identity::PeerIdentity;
use crate::core::security::replay::{ReplayGuard, TransactionReplayState};
use crate::core::security::session::SecureSession;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info};
use uuid::Uuid;

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum retries per chunk.
pub const MAX_CHUNK_RETRIES: usize = 3;

/// Maximum total retries per transaction.
pub const MAX_TRANSACTION_RETRIES: usize = 100;

/// Default transaction timeout.
pub const DEFAULT_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(24 * 3600);

// ── Transfer State ───────────────────────────────────────────────────────────

/// The state of a secure transfer from the coordinator's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecureTransferState {
    /// Manifest created, waiting for receiver ACK.
    AwaitingAck,
    /// Receiver ACKed, actively transferring.
    Active,
    /// Transfer paused, eligible for resume.
    Resumable,
    /// Transfer completed successfully.
    Completed,
    /// Transfer failed.
    Failed,
    /// Transfer cancelled.
    Cancelled,
    /// Transfer expired.
    Expired,
}

/// Per-file transfer tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTransferState {
    pub file_id: Uuid,
    /// Chunk completion bitmap.
    pub bitmap: ChunkBitmap,
    /// Whether the file is fully transferred and verified.
    pub completed: bool,
    /// Merkle root verified?
    pub merkle_verified: bool,
}

/// Resume request from the receiver (signed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureResumeRequest {
    /// Transaction to resume.
    pub transaction_id: Uuid,
    /// Per-file bitmaps of missing chunks.
    pub missing_chunks: HashMap<Uuid, Vec<u32>>,
    /// HMAC(session_key, transaction_id || missing_chunks_digest)
    pub hmac: [u8; 32],
    /// Signature by the receiver.
    pub receiver_signature: [u8; 32],
    /// Receiver's public key.
    pub receiver_public_key: [u8; 32],
}

/// Persistent snapshot of a secure transfer for resume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureTransferSnapshot {
    pub transaction_id: Uuid,
    pub state: SecureTransferState,
    pub manifest: SecureManifest,
    pub file_states: HashMap<Uuid, FileTransferState>,
    pub replay_state: TransactionReplayState,
    pub expiration_time: u64,
}

// ── Transfer Coordinator ─────────────────────────────────────────────────────

/// Central coordinator for a single secure transfer.
pub struct TransferCoordinator {
    /// Our identity.
    identity: PeerIdentity,
    /// Replay guard (shared across transactions).
    replay_guard: ReplayGuard,
    /// Active transfer sessions.
    transfers: HashMap<Uuid, TransferContext>,
    /// Sender pipeline configuration.
    sender_config: SenderConfig,
}

/// Context for a single active transfer.
struct TransferContext {
    state: SecureTransferState,
    manifest: SecureManifest,
    session: SecureSession,
    file_states: HashMap<Uuid, FileTransferState>,
    retry_tracker: RetryTracker,
    /// Whether we are the sender or receiver.
    is_sender: bool,
}

impl TransferCoordinator {
    pub fn new(identity: PeerIdentity) -> Self {
        Self {
            identity,
            replay_guard: ReplayGuard::new(),
            transfers: HashMap::new(),
            sender_config: SenderConfig::default(),
        }
    }

    pub fn identity(&self) -> &PeerIdentity {
        &self.identity
    }

    // ── Transaction Lifecycle ────────────────────────────────────────────

    /// Start a new outbound transfer (sender side).
    /// Creates the secure manifest and registers the transaction.
    pub fn start_transfer(
        &mut self,
        transaction_id: Uuid,
        receiver_id: [u8; 32],
        files: Vec<SecureManifestEntry>,
        parent_dir: Option<String>,
        session_key: [u8; 32],
    ) -> Result<SecureManifest> {
        // Create secure manifest
        let manifest = SecureManifest::create(
            transaction_id,
            receiver_id,
            files,
            parent_dir,
            &self.identity,
            DEFAULT_TRANSACTION_TIMEOUT,
        );

        // Create session
        let session = SecureSession::new(
            transaction_id,
            session_key,
            self.identity.public_key,
            receiver_id,
        )
        .with_expiration(manifest.expiration_time);

        // Register replay guard
        self.replay_guard
            .register_transaction(transaction_id, manifest.expiration_time);

        // Initialize per-file state
        let mut file_states = HashMap::new();
        for file in &manifest.files {
            file_states.insert(
                file.file_id,
                FileTransferState {
                    file_id: file.file_id,
                    bitmap: ChunkBitmap::new(file.total_chunks),
                    completed: false,
                    merkle_verified: false,
                },
            );
        }

        let context = TransferContext {
            state: SecureTransferState::AwaitingAck,
            manifest: manifest.clone(),
            session,
            file_states,
            retry_tracker: RetryTracker::new(MAX_CHUNK_RETRIES, MAX_TRANSACTION_RETRIES),
            is_sender: true,
        };

        self.transfers.insert(transaction_id, context);

        info!(
            transaction_id = %transaction_id,
            files = manifest.file_count(),
            total_size = manifest.total_size(),
            "Secure transfer started"
        );

        Ok(manifest)
    }

    /// Accept an incoming transfer (receiver side).
    /// Validates the manifest and registers the transaction.
    pub fn accept_transfer(
        &mut self,
        manifest: &SecureManifest,
        session_key: [u8; 32],
    ) -> Result<()> {
        // Validate manifest
        crate::core::protocol::manifest::validate_manifest(manifest)?;

        let transaction_id = manifest.transaction_id;

        // Create session
        let session = SecureSession::new(
            transaction_id,
            session_key,
            self.identity.public_key,
            manifest.sender_id,
        )
        .with_expiration(manifest.expiration_time);

        // Register replay guard
        self.replay_guard
            .register_transaction(transaction_id, manifest.expiration_time);

        // Initialize per-file state
        let mut file_states = HashMap::new();
        for file in &manifest.files {
            file_states.insert(
                file.file_id,
                FileTransferState {
                    file_id: file.file_id,
                    bitmap: ChunkBitmap::new(file.total_chunks),
                    completed: false,
                    merkle_verified: false,
                },
            );
        }

        let context = TransferContext {
            state: SecureTransferState::Active,
            manifest: manifest.clone(),
            session,
            file_states,
            retry_tracker: RetryTracker::new(MAX_CHUNK_RETRIES, MAX_TRANSACTION_RETRIES),
            is_sender: false,
        };

        self.transfers.insert(transaction_id, context);

        info!(
            transaction_id = %transaction_id,
            files = manifest.file_count(),
            "Secure transfer accepted"
        );

        Ok(())
    }

    /// Activate a transfer (after receiver ACK).
    pub fn activate_transfer(&mut self, transaction_id: &Uuid) -> Result<()> {
        let ctx = self
            .transfers
            .get_mut(transaction_id)
            .ok_or_else(|| anyhow!("Unknown transaction: {}", transaction_id))?;

        if ctx.state != SecureTransferState::AwaitingAck {
            return Err(anyhow!(
                "Cannot activate transfer in state {:?}",
                ctx.state
            ));
        }

        ctx.state = SecureTransferState::Active;
        info!(transaction_id = %transaction_id, "Transfer activated");
        Ok(())
    }

    // ── Manifest Authorization ───────────────────────────────────────────

    /// Validate that a file_id is within the manifest for a transaction.
    pub fn validate_file_request(
        &self,
        transaction_id: &Uuid,
        file_id: &Uuid,
    ) -> Result<()> {
        let ctx = self
            .transfers
            .get(transaction_id)
            .ok_or_else(|| anyhow!("Unknown transaction: {}", transaction_id))?;

        if !ctx.manifest.contains_file(file_id) {
            return Err(anyhow!(
                "File {} not in manifest for transaction {}",
                file_id,
                transaction_id
            ));
        }

        Ok(())
    }

    /// Validate that a chunk request is within manifest bounds.
    pub fn validate_chunk_request(
        &self,
        transaction_id: &Uuid,
        file_id: &Uuid,
        chunk_indices: &[u32],
    ) -> Result<()> {
        let ctx = self
            .transfers
            .get(transaction_id)
            .ok_or_else(|| anyhow!("Unknown transaction: {}", transaction_id))?;

        if !ctx.manifest.validate_chunk_request(file_id, chunk_indices) {
            return Err(anyhow!(
                "Invalid chunk request for file {} in transaction {}",
                file_id,
                transaction_id
            ));
        }

        Ok(())
    }

    // ── Replay Protection ────────────────────────────────────────────────

    /// Get the next outgoing counter for a transaction's messages.
    pub fn next_counter(&mut self, transaction_id: &Uuid) -> Option<u64> {
        self.replay_guard.next_outgoing_counter(transaction_id)
    }

    /// Validate an incoming message counter.
    pub fn validate_counter(
        &mut self,
        transaction_id: &Uuid,
        counter: u64,
    ) -> Result<()> {
        self.replay_guard
            .validate_incoming(transaction_id, counter)
            .map_err(|e| anyhow!("Replay check failed: {}", e))
    }

    // ── Chunk Tracking ───────────────────────────────────────────────────

    /// Mark a chunk as completed (sender or receiver).
    pub fn mark_chunk_completed(
        &mut self,
        transaction_id: &Uuid,
        file_id: &Uuid,
        chunk_index: u32,
    ) -> Result<()> {
        let ctx = self
            .transfers
            .get_mut(transaction_id)
            .ok_or_else(|| anyhow!("Unknown transaction: {}", transaction_id))?;

        let file_state = ctx
            .file_states
            .get_mut(file_id)
            .ok_or_else(|| anyhow!("Unknown file: {}", file_id))?;

        file_state.bitmap.set(chunk_index);

        // Check if file is complete
        if file_state.bitmap.is_complete() {
            file_state.completed = true;
            debug!(
                transaction_id = %transaction_id,
                file_id = %file_id,
                "File transfer complete"
            );
        }

        Ok(())
    }

    /// Mark a file's Merkle root as verified.
    pub fn mark_merkle_verified(
        &mut self,
        transaction_id: &Uuid,
        file_id: &Uuid,
    ) -> Result<()> {
        let ctx = self
            .transfers
            .get_mut(transaction_id)
            .ok_or_else(|| anyhow!("Unknown transaction: {}", transaction_id))?;

        let file_state = ctx
            .file_states
            .get_mut(file_id)
            .ok_or_else(|| anyhow!("Unknown file: {}", file_id))?;

        file_state.merkle_verified = true;
        Ok(())
    }

    /// Check if all files in a transaction are completed and verified.
    pub fn is_transfer_complete(&self, transaction_id: &Uuid) -> bool {
        self.transfers
            .get(transaction_id)
            .is_some_and(|ctx| {
                ctx.file_states
                    .values()
                    .all(|f| f.completed && f.merkle_verified)
            })
    }

    /// Complete a transfer.
    pub fn complete_transfer(&mut self, transaction_id: &Uuid) -> Result<()> {
        let ctx = self
            .transfers
            .get_mut(transaction_id)
            .ok_or_else(|| anyhow!("Unknown transaction: {}", transaction_id))?;

        ctx.state = SecureTransferState::Completed;
        info!(transaction_id = %transaction_id, "Transfer completed");
        Ok(())
    }

    // ── Resume ───────────────────────────────────────────────────────────

    /// Pause a transfer (move to Resumable state).
    pub fn pause_transfer(&mut self, transaction_id: &Uuid) -> Result<SecureTransferSnapshot> {
        let ctx = self
            .transfers
            .get_mut(transaction_id)
            .ok_or_else(|| anyhow!("Unknown transaction: {}", transaction_id))?;

        ctx.state = SecureTransferState::Resumable;

        let replay_state = self
            .replay_guard
            .get_state(transaction_id)
            .cloned()
            .unwrap_or_else(|| TransactionReplayState::new(ctx.manifest.expiration_time));

        let snapshot = SecureTransferSnapshot {
            transaction_id: *transaction_id,
            state: SecureTransferState::Resumable,
            manifest: ctx.manifest.clone(),
            file_states: ctx.file_states.clone(),
            replay_state,
            expiration_time: ctx.manifest.expiration_time,
        };

        info!(transaction_id = %transaction_id, "Transfer paused, saved snapshot");
        Ok(snapshot)
    }

    /// Validate and accept a resume request (sender side).
    pub fn validate_resume_request(
        &mut self,
        request: &SecureResumeRequest,
    ) -> Result<Vec<(Uuid, Vec<u32>)>> {
        let txn_id = request.transaction_id;
        let ctx = self
            .transfers
            .get(&txn_id)
            .ok_or_else(|| anyhow!("Unknown transaction for resume: {}", txn_id))?;

        // Check expiration
        if ctx.manifest.is_expired() {
            return Err(anyhow!("Transaction {} has expired", txn_id));
        }

        // Verify receiver identity matches manifest
        if request.receiver_public_key != ctx.manifest.receiver_id {
            return Err(anyhow!("Receiver identity mismatch for resume request"));
        }

        // Validate all requested chunks are within the manifest
        let mut chunks_to_send = Vec::new();
        for (file_id, missing) in &request.missing_chunks {
            if !ctx.manifest.contains_file(file_id) {
                return Err(anyhow!(
                    "Resume request references file {} outside manifest",
                    file_id
                ));
            }
            if !ctx.manifest.validate_chunk_request(file_id, missing) {
                return Err(anyhow!(
                    "Resume request references chunks outside manifest bounds for file {}",
                    file_id
                ));
            }
            chunks_to_send.push((*file_id, missing.clone()));
        }

        // Reactivate the transfer
        if let Some(ctx_mut) = self.transfers.get_mut(&txn_id) {
            ctx_mut.state = SecureTransferState::Active;
        }

        info!(
            transaction_id = %txn_id,
            files = chunks_to_send.len(),
            "Resume request validated"
        );

        Ok(chunks_to_send)
    }

    /// Restore a transfer from a persistent snapshot.
    pub fn restore_transfer(
        &mut self,
        snapshot: SecureTransferSnapshot,
        session_key: [u8; 32],
    ) -> Result<()> {
        let txn_id = snapshot.transaction_id;

        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        if now >= snapshot.expiration_time {
            return Err(anyhow!("Snapshot for transaction {} has expired", txn_id));
        }

        // Recreate session
        let mut session = SecureSession::new(
            txn_id,
            session_key,
            self.identity.public_key,
            snapshot.manifest.sender_id,
        )
        .with_expiration(snapshot.expiration_time);

        session.nonce_seed = snapshot.manifest.nonce_seed;

        // Restore replay guard
        self.replay_guard
            .restore_state(txn_id, snapshot.replay_state);

        let context = TransferContext {
            state: SecureTransferState::Resumable,
            manifest: snapshot.manifest,
            session,
            file_states: snapshot.file_states,
            retry_tracker: RetryTracker::new(MAX_CHUNK_RETRIES, MAX_TRANSACTION_RETRIES),
            is_sender: false, // will be clarified by resume protocol
        };

        self.transfers.insert(txn_id, context);

        info!(transaction_id = %txn_id, "Transfer restored from snapshot");
        Ok(())
    }

    // ── Retry Tracking ───────────────────────────────────────────────────

    /// Record a retry for a chunk. Returns false if limit exceeded.
    pub fn record_retry(
        &mut self,
        transaction_id: &Uuid,
        file_id: Uuid,
        chunk_index: u32,
    ) -> bool {
        self.transfers
            .get_mut(transaction_id)
            .is_some_and(|ctx| ctx.retry_tracker.record_retry(file_id, chunk_index))
    }

    // ── State Queries ────────────────────────────────────────────────────

    /// Get the current state of a transfer.
    pub fn transfer_state(&self, transaction_id: &Uuid) -> Option<SecureTransferState> {
        self.transfers.get(transaction_id).map(|ctx| ctx.state)
    }

    /// Get the manifest for a transfer.
    pub fn manifest(&self, transaction_id: &Uuid) -> Option<&SecureManifest> {
        self.transfers.get(transaction_id).map(|ctx| &ctx.manifest)
    }

    /// Get the session key for a transfer.
    pub fn session_key(&self, transaction_id: &Uuid) -> Option<[u8; 32]> {
        self.transfers
            .get(transaction_id)
            .and_then(|ctx| ctx.session.key().copied())
    }

    /// Get missing chunks for a file in a transaction.
    pub fn missing_chunks(&self, transaction_id: &Uuid, file_id: &Uuid) -> Option<Vec<u32>> {
        self.transfers.get(transaction_id).and_then(|ctx| {
            ctx.file_states
                .get(file_id)
                .map(|fs| fs.bitmap.missing_chunks())
        })
    }

    /// Fail a transfer.
    pub fn fail_transfer(&mut self, transaction_id: &Uuid, reason: &str) {
        if let Some(ctx) = self.transfers.get_mut(transaction_id) {
            ctx.state = SecureTransferState::Failed;
            error!(transaction_id = %transaction_id, reason = reason, "Transfer failed");
        }
    }

    /// Cancel a transfer.
    pub fn cancel_transfer(&mut self, transaction_id: &Uuid) {
        if let Some(ctx) = self.transfers.get_mut(transaction_id) {
            ctx.state = SecureTransferState::Cancelled;
            info!(transaction_id = %transaction_id, "Transfer cancelled");
        }
        self.replay_guard.remove_transaction(transaction_id);
    }

    /// Remove a completed or failed transfer.
    pub fn remove_transfer(&mut self, transaction_id: &Uuid) {
        self.transfers.remove(transaction_id);
        self.replay_guard.remove_transaction(transaction_id);
    }

    /// Prune expired transactions.
    pub fn prune_expired(&mut self) {
        let expired: Vec<Uuid> = self
            .transfers
            .iter()
            .filter(|(_, ctx)| ctx.manifest.is_expired())
            .map(|(id, _)| *id)
            .collect();

        for id in expired {
            info!(transaction_id = %id, "Pruning expired transfer");
            self.transfers.remove(&id);
        }

        self.replay_guard.prune_expired();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity() -> PeerIdentity {
        PeerIdentity::generate()
    }

    fn test_manifest_entry() -> SecureManifestEntry {
        SecureManifestEntry {
            file_id: Uuid::new_v4(),
            relative_path: "test.txt".to_string(),
            file_size: 49152, // exactly 1 chunk at 48KB
            total_chunks: 1,
            merkle_root: [0u8; 32],
        }
    }

    #[test]
    fn test_start_and_activate() {
        let identity = test_identity();
        let mut coordinator = TransferCoordinator::new(identity);
        let txn_id = Uuid::new_v4();
        let receiver_id = [42u8; 32];
        let session_key = [1u8; 32];

        let _manifest = coordinator
            .start_transfer(txn_id, receiver_id, vec![test_manifest_entry()], None, session_key)
            .unwrap();

        assert_eq!(coordinator.transfer_state(&txn_id), Some(SecureTransferState::AwaitingAck));

        coordinator.activate_transfer(&txn_id).unwrap();
        assert_eq!(coordinator.transfer_state(&txn_id), Some(SecureTransferState::Active));
    }

    #[test]
    fn test_validate_file_request() {
        let identity = test_identity();
        let mut coordinator = TransferCoordinator::new(identity);
        let txn_id = Uuid::new_v4();
        let entry = test_manifest_entry();
        let file_id = entry.file_id;

        coordinator
            .start_transfer(txn_id, [0u8; 32], vec![entry], None, [1u8; 32])
            .unwrap();

        assert!(coordinator.validate_file_request(&txn_id, &file_id).is_ok());
        assert!(coordinator.validate_file_request(&txn_id, &Uuid::new_v4()).is_err());
    }

    #[test]
    fn test_counter_tracking() {
        let identity = test_identity();
        let mut coordinator = TransferCoordinator::new(identity);
        let txn_id = Uuid::new_v4();

        coordinator
            .start_transfer(txn_id, [0u8; 32], vec![test_manifest_entry()], None, [1u8; 32])
            .unwrap();

        assert_eq!(coordinator.next_counter(&txn_id), Some(1));
        assert_eq!(coordinator.next_counter(&txn_id), Some(2));

        assert!(coordinator.validate_counter(&txn_id, 1).is_ok());
        assert!(coordinator.validate_counter(&txn_id, 2).is_ok());
        assert!(coordinator.validate_counter(&txn_id, 2).is_err()); // replay
    }

    #[test]
    fn test_pause_and_restore() {
        let identity = test_identity();
        let mut coordinator = TransferCoordinator::new(identity.clone());
        let txn_id = Uuid::new_v4();

        coordinator
            .start_transfer(txn_id, [0u8; 32], vec![test_manifest_entry()], None, [1u8; 32])
            .unwrap();
        coordinator.activate_transfer(&txn_id).unwrap();

        let snapshot = coordinator.pause_transfer(&txn_id).unwrap();
        assert_eq!(snapshot.state, SecureTransferState::Resumable);

        // Create a new coordinator and restore
        let mut coordinator2 = TransferCoordinator::new(identity);
        coordinator2.restore_transfer(snapshot, [1u8; 32]).unwrap();
        assert_eq!(coordinator2.transfer_state(&txn_id), Some(SecureTransferState::Resumable));
    }
}
