//! TransferEngine: sole coordinator of all file transfer logic.
//!
//! This is the single source of truth for:
//! - Transaction lifecycle management
//! - Transfer progress tracking
//! - Data statistics (bytes, messages, files, metadata, remote exploration)
//! - ACK / resume / cancellation logic
//! - Max concurrent transaction enforcement
//!
//! **Architecture rule**: No transfer logic may exist outside this module.
//! The UI layer reads state and dispatches commands; the transport layer
//! sends/receives raw frames. All coordination happens here.

use crate::core::config::{CHUNK_SIZE, MAX_CONCURRENT_TRANSACTIONS, MAX_TRANSACTION_RETRIES, TRANSACTION_TIMEOUT};
use crate::core::initializer::AppEvent;
use crate::core::persistence::Persistence;
use crate::core::protocol::coordinator::TransferCoordinator;
use crate::core::security::identity::PeerIdentity;
use crate::core::security::replay::ReplayGuard;
use crate::core::transaction::{
    ResumeInfo, Transaction, TransactionDirection, TransactionManifest,
    TransactionManager, TransactionState,
};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// ── Engine Actions ───────────────────────────────────────────────────────────

/// Actions the engine instructs the caller (UIExecuter) to execute.
/// This keeps the engine free of async/network concerns — it is a pure
/// state machine that returns declarative side-effects.
#[derive(Debug, Clone)]
pub enum EngineAction {
    /// Send a TransactionRequest to the peer.
    SendTransactionRequest {
        peer_id: String,
        transaction_id: Uuid,
        display_name: String,
        manifest: TransactionManifest,
        total_size: u64,
        /// Source path for computing Merkle roots before sending.
        source_path: Option<String>,
    },
    /// Send a TransactionResponse (accept / reject).
    SendTransactionResponse {
        peer_id: String,
        transaction_id: Uuid,
        accepted: bool,
        dest_path: Option<String>,
        reason: Option<String>,
    },
    /// Pre-register file destinations on the transport layer so incoming
    /// Metadata frames can find the correct save path.
    PrepareReceive {
        peer_id: String,
        files: Vec<(Uuid, PathBuf)>,
    },
    /// Start sending a single file (outbound).
    SendFileData {
        peer_id: String,
        file_path: String,
        file_id: Uuid,
        filename: String,
    },
    /// Start sending a folder's files (outbound).
    SendFolderData {
        peer_id: String,
        folder_path: String,
        file_entries: Vec<(Uuid, String)>, // (file_id, relative_path)
    },
    /// Notify peer of transaction completion.
    SendTransactionComplete {
        peer_id: String,
        transaction_id: Uuid,
    },
    /// Accept a resume request from the peer.
    AcceptResume {
        peer_id: String,
        transaction_id: Uuid,
    },
    /// Send a resume request to the peer (receiver side, on reconnect).
    SendResumeRequest {
        peer_id: String,
        transaction_id: Uuid,
        resume_info: crate::core::transaction::ResumeInfo,
    },
    /// Re-send only the missing files/chunks for a resumed outbound transfer.
    ResendFiles {
        peer_id: String,
        transaction_id: Uuid,
    },
    /// Handle a remote fetch (sender side).
    HandleRemoteFetch {
        peer_id: String,
        path: String,
        is_folder: bool,
    },
}

// ── Engine Outcome ───────────────────────────────────────────────────────────

/// Result of any engine operation.
pub struct EngineOutcome {
    /// Network actions the caller must execute.
    pub actions: Vec<EngineAction>,
    /// Optional status message for the UI.
    pub status: Option<String>,
}

impl EngineOutcome {
    pub fn empty() -> Self {
        Self {
            actions: Vec::new(),
            status: None,
        }
    }

    pub fn with_status(status: impl Into<String>) -> Self {
        Self {
            actions: Vec::new(),
            status: Some(status.into()),
        }
    }
}

// ── Pending Incoming Transaction ─────────────────────────────────────────────

/// A pending incoming transaction awaiting user approval.
pub struct PendingIncoming {
    pub peer_id: String,
    pub transaction_id: Uuid,
    pub display_name: String,
    pub manifest: TransactionManifest,
    pub total_size: u64,
    pub save_path_input: String,
    pub button_focus: usize,
    pub path_editing: bool,
}

// ── Data Statistics ──────────────────────────────────────────────────────────

/// Comprehensive statistics tracking ALL data sent and received,
/// including file transfers, metadata, chat, and remote exploration.
/// Statistics are collected at the lowest possible level — immediately
/// before sending and immediately after receiving.
#[derive(Debug, Default, Clone)]
pub struct DataStats {
    /// Raw bytes sent on the wire (post-compression, post-encryption).
    pub bytes_sent: u64,
    /// Raw bytes received on the wire (post-compression, post-encryption).
    pub bytes_received: u64,
    /// Pre-compression bytes sent (original payload size).
    pub raw_bytes_sent: u64,
    /// Pre-compression bytes received (original payload size).
    pub raw_bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub files_sent: u64,
    pub files_received: u64,
    /// Metadata and control-channel overhead.
    pub metadata_bytes: u64,
    /// Remote filesystem exploration traffic.
    pub remote_exploration_bytes: u64,
}

// ── Transfer History Record ──────────────────────────────────────────────────

/// One entry per Transaction — never per individual file.
#[derive(Clone, Debug)]
pub struct TransferRecord {
    pub direction: TransactionDirection,
    pub peer_id: String,
    pub display_name: String,
    pub total_size: u64,
    pub file_count: u32,
    pub timestamp: Instant,
}

// ── TransferEngine ───────────────────────────────────────────────────────────

pub struct TransferEngine {
    /// All active and historical transactions.
    transactions: TransactionManager,
    /// Comprehensive data statistics.
    stats: DataStats,
    /// Pending incoming transfer awaiting user decision.
    pending_incoming: Option<PendingIncoming>,
    /// Transfer history: one entry per Transaction, never per file.
    transfer_history: Vec<TransferRecord>,
    /// Maps outbound transaction_id to the local source path (for sending after acceptance).
    source_paths: HashMap<Uuid, String>,
    /// Secure transfer coordinator for authentication, replay protection, and manifest enforcement.
    coordinator: Option<TransferCoordinator>,
    /// Our peer identity (long-term key pair for signing manifests and resume requests).
    identity: Option<PeerIdentity>,
    /// Replay protection: monotonic counters per transaction.
    replay_guard: ReplayGuard,
}

impl TransferEngine {
    pub fn new() -> Self {
        // Try to load or create the peer identity
        let identity = PeerIdentity::default_path()
            .ok()
            .and_then(|path| PeerIdentity::load_or_create(&path).ok());

        let coordinator = identity
            .as_ref()
            .map(|id| TransferCoordinator::new(id.clone()));

        Self {
            transactions: TransactionManager::new(),
            stats: DataStats::default(),
            pending_incoming: None,
            transfer_history: Vec::new(),
            source_paths: HashMap::new(),
            coordinator,
            identity,
            replay_guard: ReplayGuard::new(),
        }
    }

    /// Access the transfer coordinator (for secure operations).
    pub fn coordinator(&self) -> Option<&TransferCoordinator> {
        self.coordinator.as_ref()
    }

    /// Access the transfer coordinator mutably.
    pub fn coordinator_mut(&mut self) -> Option<&mut TransferCoordinator> {
        self.coordinator.as_mut()
    }

    /// Access our peer identity.
    pub fn identity(&self) -> Option<&PeerIdentity> {
        self.identity.as_ref()
    }

    // ── Queries (read-only, for UI rendering) ────────────────────────────

    pub fn transactions(&self) -> &TransactionManager {
        &self.transactions
    }

    pub fn stats(&self) -> &DataStats {
        &self.stats
    }

    pub fn pending_incoming(&self) -> Option<&PendingIncoming> {
        self.pending_incoming.as_ref()
    }

    pub fn pending_incoming_mut(&mut self) -> Option<&mut PendingIncoming> {
        self.pending_incoming.as_mut()
    }

    pub fn has_pending_incoming(&self) -> bool {
        self.pending_incoming.is_some()
    }

    pub fn transfer_history(&self) -> &[TransferRecord] {
        &self.transfer_history
    }

    pub fn can_start_transfer(&self) -> bool {
        self.transactions.active_count() < MAX_CONCURRENT_TRANSACTIONS
    }

    // ── Manifest Security ────────────────────────────────────────────────

    /// Sign a transaction manifest with our peer identity.
    /// Sets sender_id, nonce_seed, expiration_time, and computes the HMAC signature.
    pub fn sign_manifest(&self, manifest: &mut TransactionManifest) {
        if let Some(ref identity) = self.identity {
            manifest.sender_id = Some(identity.public_key);
            manifest.nonce_seed = Some(rand::random());
            manifest.expiration_time = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    + TRANSACTION_TIMEOUT.as_secs(),
            );
            let content = Transaction::manifest_content_bytes(manifest);
            manifest.signature = Some(identity.sign(&content));
        }
    }

    /// Validate a manifest's signature against the declared sender_id.
    /// Returns true if the signature is valid or if no signature is present
    /// (backward compatibility during upgrade window).
    pub fn validate_manifest_signature(&self, manifest: &TransactionManifest) -> bool {
        match (
            &manifest.sender_id,
            &manifest.signature,
        ) {
            (Some(sender_id), Some(signature)) => {
                // Check expiration
                if let Some(exp) = manifest.expiration_time {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if now >= exp {
                        warn!(event = "manifest_expired", "Received expired manifest");
                        return false;
                    }
                }
                // Verify signature: reconstruct SignedPayload and validate signer
                let content = Transaction::manifest_content_bytes(manifest);
                let signed = crate::core::security::identity::SignedPayload {
                    data: content,
                    signature: *signature,
                    signer: *sender_id,
                };
                PeerIdentity::verify_signed(&signed, sender_id)
            }
            // No security fields present — accept (will be required in future)
            _ => true,
        }
    }

    /// Register a transaction with the replay guard.
    fn register_replay_guard(&mut self, transaction_id: Uuid) {
        let expiration = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + TRANSACTION_TIMEOUT.as_secs();
        self.replay_guard.register_transaction(transaction_id, expiration);
    }

    /// Get the identity's public key (for wire messages).
    pub fn identity_public_key(&self) -> Option<[u8; 32]> {
        self.identity.as_ref().map(|id| id.public_key)
    }

    // ── Initiating Outbound Transfers ────────────────────────────────────

    /// Initiate a single-file send. Creates Transaction, returns action to
    /// send TransactionRequest to peer.
    pub fn initiate_file_send(
        &mut self,
        peer_id: &str,
        filename: &str,
        filesize: u64,
        file_path: &str,
    ) -> Result<EngineOutcome> {
        if !self.can_start_transfer() {
            warn!(event = "transfer_limit_reached", active = self.transactions.active_count(), limit = MAX_CONCURRENT_TRANSACTIONS, "File send blocked: concurrent transaction limit");
            return Err(anyhow!(
                "Maximum concurrent transactions ({}) reached",
                MAX_CONCURRENT_TRANSACTIONS
            ));
        }

        let txn = Transaction::new_outbound(
            peer_id.to_string(),
            filename.to_string(),
            None,
            vec![(filename.to_string(), filesize)],
        );
        let mut manifest = txn.build_manifest();
        let txn_id = txn.id;
        let total_size = txn.total_size;

        // Sign the manifest with our identity
        self.sign_manifest(&mut manifest);

        // Register with replay guard
        self.register_replay_guard(txn_id);

        self.source_paths.insert(txn_id, file_path.to_string());
        self.transactions.insert(txn);

        // Persist immediately so transfer survives a crash
        self.persist_active_transaction(&txn_id);

        info!(event = "transfer_initiated", transaction_id = %txn_id, direction = "outbound", kind = "file", filename = %filename, filesize, "Outbound file transfer initiated");

        Ok(EngineOutcome {
            actions: vec![EngineAction::SendTransactionRequest {
                peer_id: peer_id.to_string(),
                transaction_id: txn_id,
                display_name: filename.to_string(),
                manifest,
                total_size,
                source_path: Some(file_path.to_string()),
            }],
            status: Some(format!("Sending {}...", filename)),
        })
    }

    /// Initiate a folder send. Creates Transaction, returns action to
    /// send TransactionRequest to peer.
    pub fn initiate_folder_send(
        &mut self,
        peer_id: &str,
        dirname: &str,
        files: Vec<(String, u64)>,
        folder_path: &str,
    ) -> Result<EngineOutcome> {
        if !self.can_start_transfer() {
            warn!(event = "transfer_limit_reached", active = self.transactions.active_count(), limit = MAX_CONCURRENT_TRANSACTIONS, "Folder send blocked: concurrent transaction limit");
            return Err(anyhow!(
                "Maximum concurrent transactions ({}) reached",
                MAX_CONCURRENT_TRANSACTIONS
            ));
        }

        if files.is_empty() {
            warn!(event = "empty_folder_send", dirname = %dirname, "Attempted to send empty folder");
            return Err(anyhow!("Folder is empty"));
        }

        let txn = Transaction::new_outbound(
            peer_id.to_string(),
            dirname.to_string(),
            Some(dirname.to_string()),
            files,
        );
        let mut manifest = txn.build_manifest();
        let txn_id = txn.id;
        let total_size = txn.total_size;
        let files_len = txn.file_order.len();

        // Sign the manifest with our identity
        self.sign_manifest(&mut manifest);

        // Register with replay guard
        self.register_replay_guard(txn_id);

        self.source_paths.insert(txn_id, folder_path.to_string());
        self.transactions.insert(txn);

        // Persist immediately so transfer survives a crash
        self.persist_active_transaction(&txn_id);

        info!(event = "transfer_initiated", transaction_id = %txn_id, direction = "outbound", kind = "folder", dirname = %dirname, file_count = files_len, total_size, "Outbound folder transfer initiated");

        Ok(EngineOutcome {
            actions: vec![EngineAction::SendTransactionRequest {
                peer_id: peer_id.to_string(),
                transaction_id: txn_id,
                display_name: dirname.to_string(),
                manifest,
                total_size,
                source_path: Some(folder_path.to_string()),
            }],
            status: Some(format!("Sending folder {}...", dirname)),
        })
    }

    // ── Accepting / Rejecting Incoming Transfers ─────────────────────────

    /// Accept the current pending incoming transfer.
    pub fn accept_incoming(&mut self, dest_path: String) -> Result<EngineOutcome> {
        let pending = self
            .pending_incoming
            .take()
            .ok_or_else(|| anyhow!("No pending incoming transaction"))?;

        info!(event = "transfer_accepted", transaction_id = %pending.transaction_id, display_name = %pending.display_name, dest = %dest_path, "Incoming transfer accepted");

        let mut txn = Transaction::new_inbound(
            pending.transaction_id,
            pending.peer_id.clone(),
            pending.display_name.clone(),
            pending.manifest.parent_dir.clone(),
            pending.total_size,
            &pending.manifest,
        );
        txn.dest_path = Some(PathBuf::from(&dest_path));
        txn.activate();

        // Compute file → dest_path mapping for PrepareReceive
        let files: Vec<(Uuid, PathBuf)> = txn
            .file_order
            .iter()
            .filter_map(|fid| {
                txn.files
                    .get(fid)
                    .map(|_f| (*fid, PathBuf::from(&dest_path)))
            })
            .collect();

        let peer_id = pending.peer_id.clone();
        let txn_id = pending.transaction_id;
        let display_name = pending.display_name.clone();

        self.transactions.insert(txn);

        // Persist immediately so the inbound transaction survives a crash
        // even before any chunks arrive.
        self.persist_active_transaction(&txn_id);

        Ok(EngineOutcome {
            actions: vec![
                EngineAction::PrepareReceive {
                    peer_id: peer_id.clone(),
                    files,
                },
                EngineAction::SendTransactionResponse {
                    peer_id,
                    transaction_id: txn_id,
                    accepted: true,
                    dest_path: Some(dest_path),
                    reason: None,
                },
            ],
            status: Some(format!("Downloading: {}", display_name)),
        })
    }

    /// Reject the current pending incoming transfer.
    pub fn reject_incoming(&mut self) -> Result<EngineOutcome> {
        let pending = self
            .pending_incoming
            .take()
            .ok_or_else(|| anyhow!("No pending incoming transaction"))?;

        info!(event = "transfer_rejected", transaction_id = %pending.transaction_id, display_name = %pending.display_name, "Incoming transfer rejected by user");

        let display_name = pending.display_name.clone();

        // Create and immediately reject a transaction for history
        let mut txn = Transaction::new_inbound(
            pending.transaction_id,
            pending.peer_id.clone(),
            pending.display_name.clone(),
            pending.manifest.parent_dir.clone(),
            pending.total_size,
            &pending.manifest,
        );
        txn.reject(Some("User declined".to_string()));
        self.transactions.insert(txn);
        self.archive_transaction(pending.transaction_id);

        Ok(EngineOutcome {
            actions: vec![EngineAction::SendTransactionResponse {
                peer_id: pending.peer_id,
                transaction_id: pending.transaction_id,
                accepted: false,
                dest_path: None,
                reason: Some("User declined".to_string()),
            }],
            status: Some(format!("Rejected transfer: {}", display_name)),
        })
    }

    // ── Processing Network Events ────────────────────────────────────────

    /// Process an AppEvent and return the resulting actions + status.
    /// This is the main entry point for the event loop — ALL transfer-related
    /// events MUST be routed through here.
    pub fn process_event(&mut self, event: &AppEvent) -> EngineOutcome {
        match event {
            AppEvent::PeerDisconnected { peer_id, .. } => {
                info!(event = "peer_transfers_interrupted", peer = %peer_id, "Interrupting transfers for disconnected peer");

                // Step 1: Active → Interrupted for all non-terminal transactions.
                self.transactions.interrupt_peer(peer_id);

                // Step 2: Collect Interrupted transactions to persist as Resumable.
                // Skip already-Resumable/terminal to stay idempotent when
                // duplicate disconnects arrive.
                let txn_ids: Vec<Uuid> = self
                    .transactions
                    .active
                    .iter()
                    .filter(|(_, t)| {
                        t.peer_id == *peer_id
                            && t.state == TransactionState::Interrupted
                    })
                    .map(|(id, _)| *id)
                    .collect();

                // Transition each to Resumable and persist
                if !txn_ids.is_empty() {
                    let mut persistence = Persistence::load().unwrap_or_default();
                    self.persist_transactions_as_resumable(&txn_ids, &mut persistence);

                    if let Err(e) = persistence.save() {
                        error!(event = "persistence_save_failure", error = %e, "Failed to persist transaction state on disconnect");
                    } else {
                        info!(event = "transactions_persisted", count = txn_ids.len(), "Persisted {} transactions for peer {}", txn_ids.len(), peer_id);
                    }
                }

                // NOTE: Do NOT remove source_paths — they are needed for resume
                // Clean up pending incoming if from this peer
                if let Some(ref p) = self.pending_incoming {
                    if p.peer_id == *peer_id {
                        self.pending_incoming = None;
                    }
                }
                EngineOutcome::empty()
            }

            AppEvent::ChatReceived { message, .. } => {
                self.stats.messages_received += 1;
                // Raw message size (pre-compression)
                self.stats.raw_bytes_received += message.len() as u64;
                // Wire bytes are not tracked per-message; use raw as estimate
                self.stats.bytes_received += message.len() as u64;
                EngineOutcome::empty()
            }

            // ── File-level progress (from transport) ─────────────────────

            AppEvent::FileProgress {
                file_id,
                received_chunks,
                total_chunks: _,
                wire_bytes,
                ..
            } => {
                if let Some(txn) = self.transactions.find_by_file_mut(file_id) {
                    let old = txn
                        .files
                        .get(file_id)
                        .map(|f| f.transferred_chunks)
                        .unwrap_or(0);
                    let delta = received_chunks.saturating_sub(old);
                    // Track raw bytes (pre-compression estimate)
                    self.stats.raw_bytes_received += delta as u64 * CHUNK_SIZE as u64;
                    // Track wire bytes (post-compression/encryption) — lowest level
                    self.stats.bytes_received += *wire_bytes;
                    txn.update_file_progress(*file_id, *received_chunks);

                    // Persist transaction state every 20 chunks so it
                    // survives a sudden process kill.  The snapshot
                    // includes dest_path and per-file progress.
                    if received_chunks % 20 == 0 {
                        let txn_id = txn.id;
                        self.persist_active_transaction(&txn_id);
                    }
                }
                EngineOutcome::empty()
            }

            AppEvent::SendProgress {
                file_id,
                sent_chunks,
                wire_bytes,
                ..
            } => {
                if let Some(txn) = self.transactions.find_by_file_mut(file_id) {
                    let old = txn
                        .files
                        .get(file_id)
                        .map(|f| f.transferred_chunks)
                        .unwrap_or(0);
                    let delta = sent_chunks.saturating_sub(old);
                    // Track raw bytes (pre-compression)
                    self.stats.raw_bytes_sent += delta as u64 * CHUNK_SIZE as u64;
                    // Track wire bytes (post-compression/encryption) — lowest level
                    self.stats.bytes_sent += *wire_bytes;
                    txn.update_file_progress(*file_id, *sent_chunks);

                    // Persist transaction state periodically so outbound
                    // transfers survive a sudden process kill.
                    if sent_chunks % 20 == 0 {
                        let txn_id = txn.id;
                        self.persist_active_transaction(&txn_id);
                    }
                }
                EngineOutcome::empty()
            }

            AppEvent::SendComplete {
                file_id, success, ..
            } => {
                if let Some(txn) = self.transactions.find_by_file_mut(file_id) {
                    if *success {
                        txn.complete_file(*file_id, true);
                        self.stats.files_sent += 1;
                        debug!(event = "file_sent", file_id = %file_id, transaction_id = %txn.id, "File sent successfully");
                    } else {
                        // Mark the file as done (unverified) so the
                        // transaction can still conclude instead of
                        // hanging forever waiting for this file.
                        txn.complete_file(*file_id, false);
                        warn!(event = "file_send_failed", file_id = %file_id, transaction_id = %txn.id, "File send failed, marking as done (unverified)");
                    }
                    let txn_id = txn.id;
                    let peer_id = txn.peer_id.clone();
                    if txn.check_completion() {
                        let txn_display = txn.display_name.clone();
                        info!(event = "transfer_complete", transaction_id = %txn_id, direction = "outbound", name = %txn_display, "Outbound transfer complete");
                        self.archive_transaction(txn_id);
                        self.source_paths.remove(&txn_id);
                        return EngineOutcome {
                            actions: vec![EngineAction::SendTransactionComplete {
                                peer_id,
                                transaction_id: txn_id,
                            }],
                            status: Some(format!("Transfer complete: {}", txn_display)),
                        };
                    }
                }
                if *success {
                    EngineOutcome::with_status("Sent successfully")
                } else {
                    EngineOutcome::with_status("Transfer failed: verification error")
                }
            }

            AppEvent::FileComplete {
                file_id,
                filename,
                merkle_root,
                ..
            } => {
                if let Some(txn) = self.transactions.find_by_file_mut(file_id) {
                    // Verify Merkle root against the manifest if available
                    if let Some(file_entry) = txn.files.get(file_id) {
                        if let Some(expected_root) = &file_entry.merkle_root {
                            if expected_root != merkle_root {
                                warn!(
                                    event = "merkle_root_mismatch",
                                    file_id = %file_id,
                                    transaction_id = %txn.id,
                                    "Merkle root mismatch for file — data integrity violation"
                                );
                            } else {
                                debug!(
                                    event = "merkle_root_verified",
                                    file_id = %file_id,
                                    transaction_id = %txn.id,
                                    "Merkle root verified for file"
                                );
                            }
                        } else {
                            // Store the computed Merkle root for future reference
                            // (manifest didn't include one, but we computed it on receive)
                        }
                    }

                    txn.complete_file(*file_id, true);
                    // Store the received Merkle root in the transaction file entry
                    if let Some(tf) = txn.files.get_mut(file_id) {
                        tf.merkle_root = Some(*merkle_root);
                    }
                    self.stats.files_received += 1;
                    debug!(event = "file_received", file_id = %file_id, transaction_id = %txn.id, filename = %filename, "File received successfully");
                    let txn_id = txn.id;
                    if txn.check_completion() {
                        let display_name = txn.display_name.clone();
                        info!(event = "transfer_complete", transaction_id = %txn_id, direction = "inbound", name = %display_name, "Inbound transfer complete");
                        // Clean up replay guard for completed transaction
                        self.replay_guard.remove_transaction(&txn_id);
                        self.archive_transaction(txn_id);
                        return EngineOutcome::with_status(format!(
                            "Transfer complete: {}",
                            display_name
                        ));
                    }
                }
                EngineOutcome::with_status(format!("Received: {}", filename))
            }

            // ── Transaction-level events ─────────────────────────────────

            AppEvent::TransactionRequested {
                peer_id,
                transaction_id,
                display_name,
                manifest,
                total_size,
            } => {
                // Validate manifest signature
                if !self.validate_manifest_signature(manifest) {
                    warn!(event = "manifest_signature_invalid", transaction_id = %transaction_id, "Rejecting transfer with invalid manifest signature");
                    return EngineOutcome {
                        actions: vec![EngineAction::SendTransactionResponse {
                            peer_id: peer_id.clone(),
                            transaction_id: *transaction_id,
                            accepted: false,
                            dest_path: None,
                            reason: Some("Invalid manifest signature".to_string()),
                        }],
                        status: Some("Transfer rejected: invalid manifest signature".to_string()),
                    };
                }

                // Check capacity
                if !self.can_start_transfer() {
                    return EngineOutcome {
                        actions: vec![EngineAction::SendTransactionResponse {
                            peer_id: peer_id.clone(),
                            transaction_id: *transaction_id,
                            accepted: false,
                            dest_path: None,
                            reason: Some("Maximum concurrent transfers reached".to_string()),
                        }],
                        status: Some(
                            "Transfer request rejected: too many active transfers".to_string(),
                        ),
                    };
                }

                // Register with replay guard (receiver side)
                self.register_replay_guard(*transaction_id);

                let save_dir = std::env::current_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| ".".to_string());

                self.pending_incoming = Some(PendingIncoming {
                    peer_id: peer_id.clone(),
                    transaction_id: *transaction_id,
                    display_name: display_name.clone(),
                    manifest: manifest.clone(),
                    total_size: *total_size,
                    save_path_input: save_dir,
                    button_focus: 0,
                    path_editing: false,
                });

                info!(event = "transfer_requested", transaction_id = %transaction_id, display_name = %display_name, total_size, file_count = manifest.files.len(), "Incoming transfer request received");

                self.stats.metadata_bytes += 256; // estimate
                EngineOutcome::with_status(format!("Transfer request: {}", display_name))
            }

            AppEvent::TransactionAccepted {
                transaction_id,
                dest_path,
            } => {
                // Our outbound transaction was accepted — activate and start sending
                if let Some(txn) = self.transactions.get_active_mut(transaction_id) {
                    info!(event = "transfer_peer_accepted", transaction_id = %transaction_id, display_name = %txn.display_name, "Peer accepted transfer");
                    txn.activate();
                    if let Some(dp) = dest_path {
                        txn.dest_path = Some(PathBuf::from(dp));
                    }
                    let display = txn.display_name.clone();
                    let txn_peer_id = txn.peer_id.clone();

                    // Build actions to start sending data
                    let source_path = match self.source_paths.get(transaction_id).cloned() {
                        Some(p) => p,
                        None => {
                            error!(event = "source_path_missing", transaction_id = %transaction_id, "TransactionAccepted: no source_path for transaction");
                            tracing::error!(
                                "TransactionAccepted: no source_path for txn {}",
                                transaction_id
                            );
                            return EngineOutcome::with_status(
                                "Internal error: source path not found",
                            );
                        }
                    };

                    let actions = if txn.parent_dir.is_some() {
                        // Folder transfer
                        let file_entries: Vec<(Uuid, String)> = txn
                            .file_order
                            .iter()
                            .filter_map(|fid| {
                                txn.files
                                    .get(fid)
                                    .map(|f| (*fid, f.relative_path.clone()))
                            })
                            .collect();
                        vec![EngineAction::SendFolderData {
                            peer_id: txn_peer_id,
                            folder_path: source_path,
                            file_entries,
                        }]
                    } else {
                        // Single file transfer
                        let first_file = txn.file_order.first().copied().unwrap_or(Uuid::nil());
                        let filename = txn
                            .files
                            .get(&first_file)
                            .map(|f| f.relative_path.clone())
                            .unwrap_or_default();
                        vec![EngineAction::SendFileData {
                            peer_id: txn_peer_id,
                            file_path: source_path,
                            file_id: first_file,
                            filename,
                        }]
                    };

                    // Persist immediately so outbound transfer survives a crash
                    self.persist_active_transaction(transaction_id);

                    return EngineOutcome {
                        actions,
                        status: Some(format!("Sending: {}", display)),
                    };
                }
                EngineOutcome::empty()
            }

            AppEvent::TransactionRejected {
                transaction_id,
                reason,
            } => {
                info!(event = "transfer_peer_rejected", transaction_id = %transaction_id, reason = ?reason, "Peer rejected transfer");
                if let Some(txn) = self.transactions.get_active_mut(transaction_id) {
                    txn.reject(reason.clone());
                }
                self.archive_transaction(*transaction_id);
                self.source_paths.remove(transaction_id);
                EngineOutcome::with_status(format!(
                    "Transfer rejected: {}",
                    reason.as_deref().unwrap_or("no reason")
                ))
            }

            AppEvent::TransactionCompleted {
                transaction_id,
            } => {
                if let Some(txn) = self.transactions.get_active_mut(transaction_id) {
                    let file_ids: Vec<Uuid> = txn.file_order.clone();
                    for fid in file_ids {
                        txn.complete_file(fid, true);
                    }
                    txn.check_completion();
                }
                let display = self
                    .transactions
                    .get(transaction_id)
                    .map(|t| t.display_name.clone())
                    .unwrap_or_default();
                self.archive_transaction(*transaction_id);
                EngineOutcome::with_status(format!("Transfer complete: {}", display))
            }

            AppEvent::TransactionCancelled {
                transaction_id,
                reason,
                ..
            } => {
                warn!(event = "transfer_cancelled", transaction_id = %transaction_id, reason = ?reason, "Transfer cancelled");
                if let Some(txn) = self.transactions.get_active_mut(transaction_id) {
                    txn.cancel();
                }
                self.archive_transaction(*transaction_id);
                self.source_paths.remove(transaction_id);
                EngineOutcome::with_status(format!(
                    "Transfer cancelled: {}",
                    reason.as_deref().unwrap_or("no reason")
                ))
            }

            AppEvent::TransactionResumeRequested {
                peer_id,
                resume_info,
            } => {
                let txn_id = resume_info.transaction_id;
                info!(event = "transfer_resume_requested", transaction_id = %txn_id, completed_files = resume_info.completed_files.len(), "Resume requested by peer");

                // Try to reload from persistence if not in active memory
                if self.transactions.get(&txn_id).is_none() {
                    match Persistence::load() {
                        Ok(persistence) => {
                            if let Some(snap) = persistence.transactions.get(&txn_id) {
                                // Restore source_path so we know where to read files from
                                if let Some(ref src) = snap.source_path {
                                    self.source_paths.insert(txn_id, src.clone());
                                }
                                let restored = Transaction::from_snapshot(snap);
                                info!(event = "transaction_restored", transaction_id = %txn_id, "Restored transaction from persistence for resume");
                                self.transactions.insert(restored);
                            }
                        }
                        Err(e) => {
                            error!(event = "persistence_load_failure_on_resume", transaction_id = %txn_id, error = %e, "Failed to load persistence for resume request — cannot restore transaction");
                        }
                    }
                }

                if let Some(txn) = self.transactions.get_active_mut(&txn_id) {
                    // Centralized validation of resume request preconditions
                    if let Err(reason) = txn.validate_resume_request(
                        resume_info,
                        MAX_TRANSACTION_RETRIES as u32,
                    ) {
                        warn!(
                            event = "resume_rejected",
                            transaction_id = %txn_id,
                            state = ?txn.state,
                            reason = reason,
                            "Resume request rejected"
                        );
                        return EngineOutcome::with_status("Resume unavailable".to_string());
                    }

                    // All validations passed — apply resume info and re-send
                    txn.apply_resume_info(resume_info);

                    // Build actions: accept the resume AND re-send missing files
                    let actions = vec![
                        EngineAction::AcceptResume {
                            peer_id: peer_id.clone(),
                            transaction_id: txn_id,
                        },
                        EngineAction::ResendFiles {
                            peer_id: peer_id.clone(),
                            transaction_id: txn_id,
                        },
                    ];

                    // Clean persisted state now that we're resuming
                    if let Ok(mut p) = Persistence::load() {
                        let _ = p.remove_transaction(&txn_id);
                    }

                    EngineOutcome {
                        actions,
                        status: Some("Resuming transfer".to_string()),
                    }
                } else {
                    warn!(event = "resume_rejected_unknown", transaction_id = %txn_id, "Resume rejected: transaction not found");
                    EngineOutcome::with_status(format!("Resume rejected: unknown transaction {}", txn_id))
                }
            }

            AppEvent::TransactionResumeAccepted {
                transaction_id, ..
            } => {
                if let Some(txn) = self.transactions.get_active_mut(transaction_id) {
                    txn.activate();
                    let peer_id = txn.peer_id.clone();
                    let txn_id = *transaction_id;

                    // Clean persisted state now that resume is accepted
                    if let Ok(mut p) = Persistence::load() {
                        let _ = p.remove_transaction(&txn_id);
                    }

                    info!(event = "resume_accepted", transaction_id = %txn_id, peer = %peer_id, "Resume accepted, transfer reactivated");

                    // For inbound transactions (we are receiver), the sender will
                    // re-send the missing chunks. We MUST re-register file
                    // destinations on the new WebRTC connection so incoming
                    // Metadata/chunk frames can find the correct save path.
                    if txn.direction == TransactionDirection::Inbound {
                        let files = Self::incomplete_file_destinations(txn);
                        if !files.is_empty() {
                            return EngineOutcome {
                                actions: vec![EngineAction::PrepareReceive {
                                    peer_id,
                                    files,
                                }],
                                status: Some("Resume accepted".to_string()),
                            };
                        }
                    }
                    // For outbound, the sender already handles ResendFiles in the
                    // TransactionResumeRequested handler.
                }
                EngineOutcome::with_status("Resume accepted")
            }

            // ── Remote fetch requests ────────────────────────────────────

            AppEvent::RemoteFetchRequest {
                peer_id,
                path,
                is_folder,
            } => {
                self.stats.remote_exploration_bytes += path.len() as u64;
                EngineOutcome {
                    actions: vec![EngineAction::HandleRemoteFetch {
                        peer_id: peer_id.clone(),
                        path: path.clone(),
                        is_folder: *is_folder,
                    }],
                    status: None,
                }
            }

            AppEvent::LsResponse { .. } => {
                self.stats.remote_exploration_bytes += 256;
                EngineOutcome::empty()
            }

            // All other events are not transfer-related; return empty.
            _ => EngineOutcome::empty(),
        }
    }

    // ── Resume on reconnect ────────────────────────────────────────────

    /// Called when a peer reconnects. Checks for resumable transactions and
    /// returns actions to send resume requests (receiver side) or prepare
    /// for incoming resume requests (sender side).
    ///
    /// IMPORTANT: This also handles **Active** transactions for the peer.
    /// When the peer reconnects faster than the heartbeat can detect the
    /// disconnect (common because heartbeat debouncing takes 30+ seconds),
    /// PeerDisconnected is never fired and transactions remain Active on a
    /// dead connection.  We catch that here: any Active transaction for a
    /// reconecting peer is transitioned to Resumable, persisted, and then
    /// the normal resume flow kicks in.
    pub fn handle_peer_reconnected(&mut self, peer_id: &str) -> EngineOutcome {
        let mut actions = Vec::new();

        // 0. Transition any ACTIVE transactions for this peer to Resumable.
        //    A peer that just reconnected means the old connection is dead.
        //    Transactions stuck in Active are zombies — running on a dead
        //    WebRTC data channel.  Transition them so they can be resumed.
        //
        //    EXCEPTION: skip transactions that were resumed very recently
        //    (within the last 30 s).  A `TransactionResumeRequested` control
        //    message can arrive via the data channel BEFORE this `PeerConnected`
        //    event is processed.  In that case the transaction has already been
        //    activated by the resume handler and is actively transferring on the
        //    NEW connection — transitioning it back to Resumable would stall it.
        let recently_resumed_cutoff = std::time::Duration::from_secs(30);
        let active_txn_ids: Vec<Uuid> = self
            .transactions
            .active
            .iter()
            .filter(|(_, t)| {
                t.peer_id == peer_id
                    && t.state == TransactionState::Active
                    && !t.resumed_at.map_or(false, |at| at.elapsed() < recently_resumed_cutoff)
            })
            .map(|(id, _)| *id)
            .collect();

        if !active_txn_ids.is_empty() {
            let mut persistence = Persistence::load().unwrap_or_default();

            self.persist_transactions_as_resumable(&active_txn_ids, &mut persistence);

            for txn_id in &active_txn_ids {
                if let Some(txn) = self.transactions.get(txn_id) {
                    info!(
                        event = "active_to_resumable_on_reconnect",
                        transaction_id = %txn_id,
                        direction = ?txn.direction,
                        "Active transaction transitioned to Resumable (peer reconnected before heartbeat detected disconnect)"
                    );
                }
            }

            if let Err(e) = persistence.save() {
                error!(event = "persistence_save_failure", error = %e, "Failed to persist transactions on reconnect");
            }
        }

        // 1. Check in-memory active transactions in Resumable/Interrupted state
        //    (includes the ones we just transitioned above)
        let resumable_inbound: Vec<(Uuid, ResumeInfo)> = self
            .transactions
            .active
            .values()
            .filter(|t| {
                t.peer_id == peer_id
                    && (t.state == TransactionState::Resumable
                        || t.state == TransactionState::Interrupted)
                    && t.direction == TransactionDirection::Inbound
            })
            .map(|t| (t.id, t.build_resume_info()))
            .collect();

        // 2. Also try to restore from persistence for transactions not in memory.
        //    Include `Active` state: after a crash, periodic persistence saves
        //    snapshots in Active state.  These MUST be restored and resumed.
        //    Exclude `Pending` (transfer not yet accepted by peer) and terminal
        //    states (Completed, Rejected, Cancelled).
        let persistence_result = Persistence::load();
        if let Err(ref e) = persistence_result {
            error!(event = "persistence_load_failure_on_reconnect", peer = %peer_id, error = %e, "Failed to load persistence during reconnect — resume from disk impossible");
        }
        if let Ok(persistence) = persistence_result {
            for (txn_id, snap) in &persistence.transactions {
                if snap.peer_id == peer_id
                    && !self.transactions.active.contains_key(txn_id)
                    && (snap.state == TransactionState::Resumable
                        || snap.state == TransactionState::Interrupted
                        || snap.state == TransactionState::Active)
                {
                    // Restore source_path so outbound resumes can find files
                    if let Some(ref src) = snap.source_path {
                        self.source_paths.insert(*txn_id, src.clone());
                    }

                    let restored = Transaction::from_snapshot(snap);
                    let direction = restored.direction;
                    let resume_info = restored.build_resume_info();
                    let rid = restored.id;
                    self.transactions.insert(restored);

                    if direction == TransactionDirection::Inbound {
                        info!(event = "transaction_restored_for_resume", transaction_id = %rid, "Restored inbound transaction from persistence for resume");

                        // Pre-register file destinations on the NEW connection
                        // BEFORE sending the resume request.  This guarantees
                        // destinations are ready before the sender responds with
                        // data (PrepareReceive is awaited, not spawned).
                        if let Some(txn) = self.transactions.get(&rid) {
                            let files = Self::incomplete_file_destinations(txn);
                            if !files.is_empty() {
                                actions.push(EngineAction::PrepareReceive {
                                    peer_id: peer_id.to_string(),
                                    files,
                                });
                            }
                        }

                        actions.push(EngineAction::SendResumeRequest {
                            peer_id: peer_id.to_string(),
                            transaction_id: rid,
                            resume_info,
                        });
                    } else {
                        // Outbound: restore into memory so that when the
                        // receiver sends a resume request we can respond.
                        // Do NOT proactively send data — the receiver must
                        // drive the resume flow (it needs to register file
                        // destinations on the new connection first).
                        info!(event = "transaction_restored_for_resume", transaction_id = %rid, "Restored outbound transaction from persistence, awaiting receiver resume request");
                    }
                }
            }
        }

        // 3. Send resume requests for in-memory inbound resumable transactions.
        //    Pre-register file destinations FIRST so incoming data from the
        //    sender finds the correct save path on the new WebRTC connection.
        for (txn_id, resume_info) in resumable_inbound {
            // Register file destinations on the new connection
            if let Some(txn) = self.transactions.get(&txn_id) {
                let files = Self::incomplete_file_destinations(txn);
                if !files.is_empty() {
                    actions.push(EngineAction::PrepareReceive {
                        peer_id: peer_id.to_string(),
                        files,
                    });
                }
            }

            info!(event = "resume_request_queued", transaction_id = %txn_id, peer = %peer_id, "Queueing resume request for reconnected peer");
            actions.push(EngineAction::SendResumeRequest {
                peer_id: peer_id.to_string(),
                transaction_id: txn_id,
                resume_info,
            });
        }

        // 4. Outbound Resumable transactions: do NOT proactively re-send.
        //    The receiver must drive the resume flow by sending a resume
        //    request.  Proactive sending was racy: the sender would
        //    activate() the txn and start sending data before the receiver
        //    had registered file destinations on the new WebRTC connection,
        //    AND the sender would reject the receiver's subsequent resume
        //    request because the txn was already Active.
        //    Instead, the sender keeps the txn in Resumable state and waits.
        //    When the receiver's SendResumeRequest arrives, the sender
        //    responds with AcceptResume + ResendFiles — the correct flow.

        if actions.is_empty() {
            // Log WHY we found nothing — helps debug "not trying to resume"
            let all_for_peer: Vec<_> = self.transactions.active.values()
                .filter(|t| t.peer_id == peer_id)
                .map(|t| format!("{}({:?}/{:?})", &t.id.to_string()[..8], t.state, t.direction))
                .collect();
            if all_for_peer.is_empty() {
                info!(event = "resume_no_transactions", peer = %peer_id, "No transactions found for peer (none in memory)");
                // Also check persistence
                if let Ok(persistence) = Persistence::load() {
                    let persisted: Vec<_> = persistence.transactions.keys()
                        .filter(|_| true) // show all
                        .map(|id| id.to_string()[..8].to_string())
                        .collect();
                    if !persisted.is_empty() {
                        info!(event = "resume_persisted_available", count = persisted.len(), ids = ?persisted, "Persisted transactions exist but none matched this peer");
                    }
                }
            } else {
                info!(event = "resume_no_actions", peer = %peer_id, transactions = ?all_for_peer, "Transactions found for peer but none generated resume actions");
            }
            EngineOutcome::empty()
        } else {
            let count = actions.len();
            info!(event = "resume_on_reconnect", peer = %peer_id, count, "Initiating {} resume(s) for reconnected peer", count);
            EngineOutcome {
                actions,
                status: Some(format!("Resuming {} transfer(s)", count)),
            }
        }
    }

    // ── Statistics tracking ──────────────────────────────────────────────

    /// Record that a chat message was sent.
    pub fn record_message_sent(&mut self, bytes: u64) {
        self.stats.messages_sent += 1;
        self.stats.bytes_sent += bytes;
        self.stats.raw_bytes_sent += bytes;
    }

    /// Get the source path for an outbound transaction.
    pub fn source_path(&self, transaction_id: &Uuid) -> Option<&str> {
        self.source_paths.get(transaction_id).map(|s| s.as_str())
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// Build the list of `(file_id, dest_path)` pairs for incomplete files
    /// in a transaction.  Used to register file destinations on a (new)
    /// WebRTC connection before receiving data.
    ///
    /// Returns an empty vec if the transaction has no dest_path or all
    /// files are already completed.
    fn incomplete_file_destinations(txn: &Transaction) -> Vec<(Uuid, PathBuf)> {
        let dest = match txn.dest_path.as_ref() {
            Some(d) => d,
            None => return Vec::new(),
        };
        txn.file_order
            .iter()
            .filter_map(|fid| {
                txn.files.get(fid).and_then(|f| {
                    if !f.completed {
                        Some((*fid, dest.clone()))
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    /// Transition a set of transactions to `Resumable`, build snapshots,
    /// and persist them atomically.
    ///
    /// This is the shared logic for both `PeerDisconnected` and
    /// `handle_peer_reconnected` (Step 0).  Extracts the repeated
    /// pattern of: transition → snapshot → coordinator pause → persist.
    fn persist_transactions_as_resumable(
        &mut self,
        txn_ids: &[Uuid],
        persistence: &mut Persistence,
    ) {
        for txn_id in txn_ids {
            if let Some(txn) = self.transactions.get_active_mut(txn_id) {
                txn.make_resumable();

                let src = self.source_paths.get(txn_id).map(|s| s.as_str());
                let mut snapshot = txn.to_snapshot_with_source(src);

                if let Some(coord) = self.coordinator.as_mut() {
                    if let Ok(secure_snap) = coord.pause_transfer(txn_id) {
                        snapshot.expiration_time = Some(secure_snap.expiration_time);
                        snapshot.last_counter =
                            Some(secure_snap.replay_state.last_seen_counter);
                    }
                }

                debug!(
                    event = "transaction_persisted",
                    transaction_id = %txn_id,
                    direction = ?txn.direction,
                    state = ?txn.state,
                    "Transaction state persisted for resume"
                );
                persistence.transactions.insert(*txn_id, snapshot);
            }
        }
    }

    /// Persist a single active transaction to disk so it survives a crash.
    /// Called periodically during progress updates and when transactions
    /// become Active.  This is the **critical** mechanism that allows
    /// resume after a sudden process kill.
    fn persist_active_transaction(&self, txn_id: &Uuid) {
        if let Some(txn) = self.transactions.get(txn_id) {
            let src = self.source_paths.get(txn_id).map(|s| s.as_str());
            let snapshot = txn.to_snapshot_with_source(src);
            let mut p = match Persistence::load() {
                Ok(p) => p,
                Err(e) => {
                    warn!(event = "persistence_load_failure_on_persist", transaction_id = %txn_id, error = %e, "Failed to load persistence, starting fresh to avoid data loss");
                    Persistence::default()
                }
            };
            p.transactions.insert(*txn_id, snapshot);
            if let Err(e) = p.save() {
                warn!(event = "persist_active_failure", transaction_id = %txn_id, error = %e, "Failed to persist active transaction");
            }
        }
    }

    /// Move a transaction from active to history and persist.
    fn archive_transaction(&mut self, txn_id: Uuid) {
        if let Some(txn) = self.transactions.get(&txn_id) {
            self.transfer_history.push(TransferRecord {
                direction: txn.direction,
                peer_id: txn.peer_id.clone(),
                display_name: txn.display_name.clone(),
                total_size: txn.total_size,
                file_count: txn.total_file_count(),
                timestamp: Instant::now(),
            });
        }
        self.transactions.archive(&txn_id);

        // Clean up replay guard entry for this transaction
        self.replay_guard.remove_transaction(&txn_id);

        // Persist removal — use unwrap_or_default to handle corrupted files
        let mut p = Persistence::load().unwrap_or_default();
        let _ = p.remove_transaction(&txn_id);
    }
}

impl Default for TransferEngine {
    fn default() -> Self {
        Self::new()
    }
}
