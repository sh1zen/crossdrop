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

use crate::core::initializer::AppEvent;
use crate::core::persistence::Persistence;
use crate::core::protocol::coordinator::TransferCoordinator;
use crate::core::security::identity::PeerIdentity;
use crate::core::transaction::{
    ManifestEntry, ResumeInfo, Transaction, TransactionDirection, TransactionManifest,
    TransactionManager, TransactionState, CHUNK_SIZE,
};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of simultaneously active (non-terminal) transactions.
pub const MAX_CONCURRENT_TRANSACTIONS: usize = 3;

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
    /// Handle a remote fetch (legacy path — sender side).
    HandleRemoteFetch {
        peer_id: String,
        path: String,
        is_folder: bool,
    },
    /// Accept a legacy file offer (wrap in transaction).
    AcceptLegacyFileOffer {
        peer_id: String,
        file_id: Uuid,
        dest_path: String,
    },
    /// Reject a legacy file offer.
    RejectLegacyFileOffer {
        peer_id: String,
        file_id: Uuid,
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
    /// Whether this originated from a legacy FileOffer (not Transaction protocol).
    pub is_legacy_file: bool,
    /// For legacy file offers, the original file_id from the sender.
    pub legacy_file_id: Option<Uuid>,
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
    #[allow(dead_code)]
    coordinator: Option<TransferCoordinator>,
    /// Our peer identity (long-term Ed25519 key pair).
    #[allow(dead_code)]
    identity: Option<PeerIdentity>,
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
        }
    }

    /// Access the transfer coordinator (for secure operations).
    #[allow(dead_code)]
    pub fn coordinator(&self) -> Option<&TransferCoordinator> {
        self.coordinator.as_ref()
    }

    /// Access the transfer coordinator mutably.
    #[allow(dead_code)]
    pub fn coordinator_mut(&mut self) -> Option<&mut TransferCoordinator> {
        self.coordinator.as_mut()
    }

    /// Access our peer identity.
    #[allow(dead_code)]
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
        let manifest = txn.build_manifest();
        let txn_id = txn.id;
        let total_size = txn.total_size;

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
        let manifest = txn.build_manifest();
        let txn_id = txn.id;
        let total_size = txn.total_size;
        let files_len = txn.file_order.len();

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

        // Handle legacy file offer acceptance
        if pending.is_legacy_file {
            if let Some(legacy_file_id) = pending.legacy_file_id {
                return Ok(EngineOutcome {
                    actions: vec![EngineAction::AcceptLegacyFileOffer {
                        peer_id: pending.peer_id.clone(),
                        file_id: legacy_file_id,
                        dest_path: dest_path.clone(),
                    }],
                    status: Some(format!("Downloading: {}", pending.display_name)),
                });
            }
        }

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

        // Handle legacy file offer rejection
        if pending.is_legacy_file {
            if let Some(legacy_file_id) = pending.legacy_file_id {
                return Ok(EngineOutcome {
                    actions: vec![EngineAction::RejectLegacyFileOffer {
                        peer_id: pending.peer_id.clone(),
                        file_id: legacy_file_id,
                    }],
                    status: Some(format!("Rejected: {}", display_name)),
                });
            }
        }

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

                // Collect transaction IDs that need persistence before mutating.
                // Only consider Active or Interrupted — skip already-Resumable/terminal
                // to stay idempotent when duplicate disconnects arrive.
                let txn_ids: Vec<Uuid> = self
                    .transactions
                    .active
                    .iter()
                    .filter(|(_, t)| {
                        t.peer_id == *peer_id
                            && (t.state == TransactionState::Active
                                || t.state == TransactionState::Interrupted)
                    })
                    .map(|(id, _)| *id)
                    .collect();

                // Transition each to Resumable and persist
                if !txn_ids.is_empty() {
                    let mut persistence = Persistence::load().unwrap_or_default();

                    for txn_id in &txn_ids {
                        if let Some(txn) = self.transactions.get_active_mut(txn_id) {
                            // Transition Active → Resumable (persisted)
                            txn.make_resumable();

                            // Build snapshot with source_path so outbound transfers
                            // can be resumed even after a process restart.
                            let src = self.source_paths.get(txn_id).map(|s| s.as_str());
                            let mut snapshot = txn.to_snapshot_with_source(src);

                            // Populate expiration / counter from coordinator if available
                            if let Some(coord) = self.coordinator.as_mut() {
                                if let Ok(secure_snap) = coord.pause_transfer(txn_id) {
                                    snapshot.expiration_time = Some(secure_snap.expiration_time);
                                    snapshot.last_counter = Some(secure_snap.replay_state.last_seen_counter);
                                    persistence.secure_transfers.insert(*txn_id, secure_snap);
                                }
                            }

                            debug!(event = "transaction_persisted", transaction_id = %txn_id, direction = ?txn.direction, state = ?txn.state, "Transaction state persisted for resume");
                            persistence.transactions.insert(*txn_id, snapshot);
                        }
                    }

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
                } else {
                    // Legacy transfer without engine transaction — still count bytes
                    self.stats.raw_bytes_received += CHUNK_SIZE as u64;
                    self.stats.bytes_received += *wire_bytes;
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
                } else {
                    // Legacy transfer without engine transaction
                    self.stats.raw_bytes_sent += CHUNK_SIZE as u64;
                    self.stats.bytes_sent += *wire_bytes;
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
                } else if *success {
                    // Legacy transfer — still count
                    self.stats.files_sent += 1;
                }
                if *success {
                    EngineOutcome::with_status("File sent successfully")
                } else {
                    EngineOutcome::with_status("File transfer failed (hash mismatch)")
                }
            }

            AppEvent::FileComplete {
                file_id,
                filename,
                path,
                ..
            } => {
                if let Some(txn) = self.transactions.find_by_file_mut(file_id) {
                    txn.complete_file(*file_id, true);
                    self.stats.files_received += 1;
                    debug!(event = "file_received", file_id = %file_id, transaction_id = %txn.id, filename = %filename, "File received successfully");
                    let txn_id = txn.id;
                    if txn.check_completion() {
                        let display_name = txn.display_name.clone();
                        info!(event = "transfer_complete", transaction_id = %txn_id, direction = "inbound", name = %display_name, "Inbound transfer complete");
                        self.archive_transaction(txn_id);
                        return EngineOutcome::with_status(format!(
                            "Transfer complete: {}",
                            display_name
                        ));
                    }
                } else {
                    // Legacy transfer without engine transaction
                    self.stats.files_received += 1;
                }
                EngineOutcome::with_status(format!("File saved: {} -> {}", filename, path))
            }

            AppEvent::FileRejected {
                file_id, reason, ..
            } => {
                if let Some(txn) = self.transactions.find_by_file_mut(file_id) {
                    let txn_id = txn.id;
                    warn!(event = "file_rejected", file_id = %file_id, transaction_id = %txn_id, reason = ?reason, "File transfer rejected");
                    txn.reject(reason.clone());
                    self.archive_transaction(txn_id);
                }
                let reason_str = reason.as_deref().unwrap_or("unknown reason");
                EngineOutcome::with_status(format!("Transfer rejected: {}", reason_str))
            }

            // ── Legacy file/folder offers (wrap in Transaction) ──────────

            AppEvent::FileOffered {
                peer_id,
                file_id,
                filename,
                filesize,
                total_size,
            } => {
                // Check if this file belongs to an existing accepted transaction.
                if self.transactions.transaction_id_for_file(file_id).is_some() {
                    // Already tracked — auto-accept via transport layer
                    return EngineOutcome::empty();
                }

                // Unsolicited file offer — create ad-hoc pending transaction.
                let save_dir = std::env::current_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| ".".to_string());

                // Only show popup if we don't already have one
                if self.pending_incoming.is_some() {
                    // Queue it — for now just accept (auto-accept unsolicited per spec)
                    return EngineOutcome::empty();
                }

                let txn_id = Uuid::new_v4();
                let manifest = TransactionManifest {
                    files: vec![ManifestEntry {
                        file_id: *file_id,
                        relative_path: filename.clone(),
                        filesize: *filesize,
                        merkle_root: None,
                        total_chunks: None,
                    }],
                    parent_dir: None,
                };

                self.pending_incoming = Some(PendingIncoming {
                    peer_id: peer_id.clone(),
                    transaction_id: txn_id,
                    display_name: filename.clone(),
                    manifest,
                    total_size: *total_size,
                    save_path_input: save_dir,
                    button_focus: 0,
                    path_editing: false,
                    is_legacy_file: true,
                    legacy_file_id: Some(*file_id),
                });

                EngineOutcome::with_status(format!("File offered: {}", filename))
            }

            AppEvent::FolderOffered { .. } => {
                // Legacy folder offer — auto-accept and track
                self.stats.metadata_bytes += 128; // estimate for folder metadata
                EngineOutcome::empty() // Folders are auto-accepted via legacy path
            }

            AppEvent::FolderComplete { .. } => {
                self.stats.metadata_bytes += 64;
                EngineOutcome::empty()
            }

            // ── Transaction-level events ─────────────────────────────────

            AppEvent::TransactionRequested {
                peer_id,
                transaction_id,
                display_name,
                manifest,
                total_size,
            } => {
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
                    is_legacy_file: false,
                    legacy_file_id: None,
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
                        status: Some(format!("Transfer accepted, sending: {}", display)),
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
                    // Validate: must be in a resumable state OR Active (Active
                    // means the peer reconnected before we realised the old
                    // connection was dead — Step 0 in handle_peer_reconnected
                    // should have transitioned it, but if it didn't, or if the
                    // request races with Step 0, we accept it anyway).
                    if txn.state != TransactionState::Resumable
                        && txn.state != TransactionState::Interrupted
                        && txn.state != TransactionState::Active
                    {
                        warn!(event = "resume_rejected_state", transaction_id = %txn_id, state = ?txn.state, "Resume rejected: invalid transaction state");
                        return EngineOutcome::with_status(format!(
                            "Resume rejected: transaction {} in {:?} state",
                            txn_id, txn.state
                        ));
                    }

                    // Validate: must be an outbound transaction (we are the sender)
                    if txn.direction != TransactionDirection::Outbound {
                        warn!(event = "resume_rejected_direction", transaction_id = %txn_id, "Resume rejected: not an outbound transaction");
                        return EngineOutcome::with_status("Resume rejected: wrong direction".to_string());
                    }

                    // Validate: retry limit
                    if txn.resume_count >= safety::MAX_TRANSACTION_RETRIES as u32 {
                        warn!(event = "resume_rejected_retries", transaction_id = %txn_id, count = txn.resume_count, "Resume rejected: retry limit exceeded");
                        return EngineOutcome::with_status("Resume rejected: retry limit exceeded".to_string());
                    }

                    // Validate: requested files must be in the manifest
                    for file_id in &resume_info.completed_files {
                        if !txn.files.contains_key(file_id) {
                            warn!(event = "resume_rejected_file", transaction_id = %txn_id, file_id = %file_id, "Resume rejected: unknown file_id");
                            return EngineOutcome::with_status("Resume rejected: unknown file in request".to_string());
                        }
                    }
                    for file_id in resume_info.partial_offsets.keys() {
                        if !txn.files.contains_key(file_id) {
                            warn!(event = "resume_rejected_file", transaction_id = %txn_id, file_id = %file_id, "Resume rejected: unknown file_id in partial offsets");
                            return EngineOutcome::with_status("Resume rejected: unknown file in request".to_string());
                        }
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
                        if let Some(ref dest) = txn.dest_path {
                            let files: Vec<(Uuid, PathBuf)> = txn
                                .file_order
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
                                .collect();
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
        let active_txn_ids: Vec<Uuid> = self
            .transactions
            .active
            .iter()
            .filter(|(_, t)| {
                t.peer_id == peer_id && t.state == TransactionState::Active
            })
            .map(|(id, _)| *id)
            .collect();

        if !active_txn_ids.is_empty() {
            let mut persistence = Persistence::load().unwrap_or_default();

            for txn_id in &active_txn_ids {
                if let Some(txn) = self.transactions.get_active_mut(txn_id) {
                    txn.make_resumable();

                    let src = self.source_paths.get(txn_id).map(|s| s.as_str());
                    let mut snapshot = txn.to_snapshot_with_source(src);

                    if let Some(coord) = self.coordinator.as_mut() {
                        if let Ok(secure_snap) = coord.pause_transfer(txn_id) {
                            snapshot.expiration_time = Some(secure_snap.expiration_time);
                            snapshot.last_counter = Some(secure_snap.replay_state.last_seen_counter);
                            persistence.secure_transfers.insert(*txn_id, secure_snap);
                        }
                    }

                    info!(
                        event = "active_to_resumable_on_reconnect",
                        transaction_id = %txn_id,
                        direction = ?txn.direction,
                        "Active transaction transitioned to Resumable (peer reconnected before heartbeat detected disconnect)"
                    );
                    persistence.transactions.insert(*txn_id, snapshot);
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
                            if let Some(ref dest) = txn.dest_path {
                                let files: Vec<(Uuid, std::path::PathBuf)> = txn
                                    .file_order
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
                                    .collect();
                                if !files.is_empty() {
                                    actions.push(EngineAction::PrepareReceive {
                                        peer_id: peer_id.to_string(),
                                        files,
                                    });
                                }
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
                if let Some(ref dest) = txn.dest_path {
                    let files: Vec<(Uuid, std::path::PathBuf)> = txn
                        .file_order
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
                        .collect();
                    if !files.is_empty() {
                        actions.push(EngineAction::PrepareReceive {
                            peer_id: peer_id.to_string(),
                            files,
                        });
                    }
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

// ── Abuse & Safety Controls ─────────────────────────────────────────────────

/// Constants for abuse prevention.
#[allow(dead_code)]
pub mod safety {
    use std::time::Duration;

    /// Maximum retries per chunk before giving up.
    pub const MAX_CHUNK_RETRIES: usize = 3;
    /// Maximum total retries per transaction.
    pub const MAX_TRANSACTION_RETRIES: usize = 100;
    /// Transaction timeout (after which it expires).
    pub const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(24 * 3600);
    /// Maximum memory budget for buffered chunks (128 MB).
    pub const MAX_MEMORY_BUDGET: usize = 128 * 1024 * 1024;
    /// Maximum concurrent chunks in pipeline.
    pub const MAX_PIPELINE_DEPTH: usize = 64;
}
