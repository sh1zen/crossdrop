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
use crate::core::transaction::{
    ManifestEntry, Transaction, TransactionDirection, TransactionManifest,
    TransactionManager, TransactionState,
};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;
use uuid::Uuid;

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of simultaneously active (non-terminal) transactions.
pub const MAX_CONCURRENT_TRANSACTIONS: usize = 3;

/// Chunk size in bytes (must match transport layer).
pub const CHUNK_SIZE: u64 = 48 * 1024;

// ── Engine Actions ───────────────────────────────────────────────────────────

/// Actions the engine instructs the caller (UIExecuter) to execute.
/// This keeps the engine free of async/network concerns — it is a pure
/// state machine that returns declarative side-effects.
#[derive(Debug, Clone)]
#[allow(dead_code)]
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
    /// Notify peer of transaction cancellation.
    SendTransactionCancel {
        peer_id: String,
        transaction_id: Uuid,
        reason: Option<String>,
    },
    /// Accept a resume request from the peer.
    AcceptResume {
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

#[allow(dead_code)]
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

    pub fn with_action(action: EngineAction) -> Self {
        Self {
            actions: vec![action],
            status: None,
        }
    }

    pub fn with_action_and_status(action: EngineAction, status: impl Into<String>) -> Self {
        Self {
            actions: vec![action],
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
#[derive(Debug, Default, Clone)]
pub struct DataStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
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
#[allow(dead_code)]
pub struct TransferRecord {
    pub transaction_id: Uuid,
    pub direction: TransactionDirection,
    pub peer_id: String,
    pub display_name: String,
    pub total_size: u64,
    pub file_count: u32,
    pub timestamp: Instant,
    pub state: TransactionState,
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
}

#[allow(dead_code)]
impl TransferEngine {
    pub fn new() -> Self {
        Self {
            transactions: TransactionManager::new(),
            stats: DataStats::default(),
            pending_incoming: None,
            transfer_history: Vec::new(),
            source_paths: HashMap::new(),
        }
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

    pub fn active_count(&self) -> usize {
        self.transactions.active_count()
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
            return Err(anyhow!(
                "Maximum concurrent transactions ({}) reached",
                MAX_CONCURRENT_TRANSACTIONS
            ));
        }

        if files.is_empty() {
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

        self.source_paths.insert(txn_id, folder_path.to_string());
        self.transactions.insert(txn);

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

    /// Cancel an active transaction.
    pub fn cancel_transaction(&mut self, txn_id: Uuid) -> EngineOutcome {
        if let Some(txn) = self.transactions.get_active_mut(&txn_id) {
            let peer_id = txn.peer_id.clone();
            txn.cancel();
            self.archive_transaction(txn_id);

            EngineOutcome {
                actions: vec![EngineAction::SendTransactionCancel {
                    peer_id,
                    transaction_id: txn_id,
                    reason: Some("Cancelled by user".to_string()),
                }],
                status: Some("Transfer cancelled".to_string()),
            }
        } else {
            EngineOutcome::with_status("Transaction not found")
        }
    }

    // ── Processing Network Events ────────────────────────────────────────

    /// Process an AppEvent and return the resulting actions + status.
    /// This is the main entry point for the event loop — ALL transfer-related
    /// events MUST be routed through here.
    pub fn process_event(&mut self, event: &AppEvent) -> EngineOutcome {
        match event {
            AppEvent::PeerDisconnected { peer_id } => {
                self.transactions.interrupt_peer(peer_id);
                // Clean up pending incoming if from this peer
                if let Some(ref p) = self.pending_incoming {
                    if p.peer_id == *peer_id {
                        self.pending_incoming = None;
                    }
                }
                // Clean up source paths for this peer's transactions
                let to_remove: Vec<Uuid> = self
                    .transactions
                    .active
                    .iter()
                    .filter(|(_, t)| t.peer_id == *peer_id)
                    .map(|(id, _)| *id)
                    .collect();
                for id in to_remove {
                    self.source_paths.remove(&id);
                }
                EngineOutcome::empty()
            }

            AppEvent::ChatReceived { message, .. } => {
                self.stats.messages_received += 1;
                self.stats.bytes_received += message.len() as u64;
                EngineOutcome::empty()
            }

            // ── File-level progress (from transport) ─────────────────────

            AppEvent::FileProgress {
                file_id,
                received_chunks,
                total_chunks: _,
                ..
            } => {
                if let Some(txn) = self.transactions.find_by_file_mut(file_id) {
                    let old = txn
                        .files
                        .get(file_id)
                        .map(|f| f.transferred_chunks)
                        .unwrap_or(0);
                    let delta = received_chunks.saturating_sub(old);
                    self.stats.bytes_received += delta as u64 * CHUNK_SIZE;
                    txn.update_file_progress(*file_id, *received_chunks);
                }
                EngineOutcome::empty()
            }

            AppEvent::SendProgress {
                file_id,
                sent_chunks,
                ..
            } => {
                if let Some(txn) = self.transactions.find_by_file_mut(file_id) {
                    let old = txn
                        .files
                        .get(file_id)
                        .map(|f| f.transferred_chunks)
                        .unwrap_or(0);
                    let delta = sent_chunks.saturating_sub(old);
                    self.stats.bytes_sent += delta as u64 * CHUNK_SIZE;
                    txn.update_file_progress(*file_id, *sent_chunks);
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
                    }
                    let txn_id = txn.id;
                    let peer_id = txn.peer_id.clone();
                    if txn.check_completion() {
                        let display = txn.display_name.clone();
                        self.archive_transaction(txn_id);
                        self.source_paths.remove(&txn_id);
                        return EngineOutcome {
                            actions: vec![EngineAction::SendTransactionComplete {
                                peer_id,
                                transaction_id: txn_id,
                            }],
                            status: Some(format!("Transfer complete: {}", display)),
                        };
                    }
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
                    let txn_id = txn.id;
                    if txn.check_completion() {
                        let display = txn.display_name.clone();
                        self.archive_transaction(txn_id);
                        return EngineOutcome::with_status(format!(
                            "Transfer complete: {}",
                            display
                        ));
                    }
                } else {
                    // File not tracked by any transaction — legacy/ad-hoc
                    self.stats.files_received += 1;
                }
                EngineOutcome::with_status(format!("File saved: {} -> {}", filename, path))
            }

            AppEvent::FileRejected {
                file_id, reason, ..
            } => {
                if let Some(txn) = self.transactions.find_by_file_mut(file_id) {
                    let txn_id = txn.id;
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

                self.stats.metadata_bytes += 256; // estimate
                EngineOutcome::with_status(format!("Transfer request: {}", display_name))
            }

            AppEvent::TransactionAccepted {
                peer_id: _,
                transaction_id,
                dest_path,
            } => {
                // Our outbound transaction was accepted — activate and start sending
                if let Some(txn) = self.transactions.get_active_mut(transaction_id) {
                    txn.activate();
                    if let Some(dp) = dest_path {
                        txn.dest_path = Some(PathBuf::from(dp));
                    }
                    let display = txn.display_name.clone();
                    let txn_peer_id = txn.peer_id.clone();

                    // Build actions to start sending data
                    let source_path = self
                        .source_paths
                        .get(transaction_id)
                        .cloned()
                        .unwrap_or_default();

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

                    return EngineOutcome {
                        actions,
                        status: Some(format!("Transfer accepted, sending: {}", display)),
                    };
                }
                EngineOutcome::empty()
            }

            AppEvent::TransactionRejected {
                peer_id: _,
                transaction_id,
                reason,
            } => {
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
                peer_id: _,
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
                if let Some(txn) = self.transactions.get_active_mut(&txn_id) {
                    txn.apply_resume_info(resume_info);
                }
                EngineOutcome {
                    actions: vec![EngineAction::AcceptResume {
                        peer_id: peer_id.clone(),
                        transaction_id: txn_id,
                    }],
                    status: Some("Resuming transfer".to_string()),
                }
            }

            AppEvent::TransactionResumeAccepted {
                transaction_id, ..
            } => {
                if let Some(txn) = self.transactions.get_active_mut(transaction_id) {
                    txn.activate();
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

    // ── Statistics tracking ──────────────────────────────────────────────

    /// Record that a chat message was sent.
    pub fn record_message_sent(&mut self, bytes: u64) {
        self.stats.messages_sent += 1;
        self.stats.bytes_sent += bytes;
    }

    /// Record remote exploration traffic.
    pub fn record_remote_exploration(&mut self, bytes: u64) {
        self.stats.remote_exploration_bytes += bytes;
    }

    /// Record metadata/control channel overhead.
    pub fn record_metadata(&mut self, bytes: u64) {
        self.stats.metadata_bytes += bytes;
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// Move a transaction from active to history and persist.
    fn archive_transaction(&mut self, txn_id: Uuid) {
        if let Some(txn) = self.transactions.get(&txn_id) {
            self.transfer_history.push(TransferRecord {
                transaction_id: txn.id,
                direction: txn.direction,
                peer_id: txn.peer_id.clone(),
                display_name: txn.display_name.clone(),
                total_size: txn.total_size,
                file_count: txn.total_file_count(),
                timestamp: Instant::now(),
                state: txn.state,
            });
        }
        self.transactions.archive(&txn_id);

        // Persist removal
        if let Ok(mut p) = Persistence::load() {
            let _ = p.remove_transaction(&txn_id);
        }
    }
}

impl Default for TransferEngine {
    fn default() -> Self {
        Self::new()
    }
}
