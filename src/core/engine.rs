//! TransferEngine: sole coordinator of all file transfer logic.
//!
//! Single source of truth for transaction lifecycle, progress tracking,
//! statistics, ACK / resume / cancellation, and concurrency limits.
//!
//! **Architecture rule**: No transfer logic may exist outside this module.
//! The UI layer reads state and dispatches commands; the transport layer
//! sends/receives raw frames. All coordination happens here.

use crate::core::config::{
    CHUNK_SIZE, MAX_CONCURRENT_TRANSACTIONS, MAX_FILE_RETRANSMISSIONS, MAX_TRANSACTION_RETRIES,
    TRANSACTION_TIMEOUT,
};
use crate::core::initializer::AppEvent;
use crate::core::persistence::{Persistence, TransferRecordSnapshot, TransferStatus};
use crate::core::security::identity::PeerIdentity;
use crate::core::security::replay::ReplayGuard;
use crate::core::transaction::{
    ResumeInfo, Transaction, TransactionDirection, TransactionManager, TransactionManifest,
    TransactionState,
};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// ── Engine Actions ───────────────────────────────────────────────────────────

/// Declarative side-effects returned to the caller (UIExecuter).
/// Keeps the engine free of async/network concerns — it is a pure state machine.
#[derive(Debug, Clone)]
pub enum EngineAction {
    SendTransactionRequest {
        peer_id: String,
        transaction_id: Uuid,
        display_name: String,
        manifest: TransactionManifest,
        total_size: u64,
    },
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
        resume_bitmaps: Vec<(Uuid, crate::core::pipeline::chunk::ChunkBitmap)>,
    },
    SendFileData {
        peer_id: String,
        file_path: String,
        file_id: Uuid,
        filename: String,
    },
    SendFolderData {
        peer_id: String,
        folder_path: String,
        file_entries: Vec<(Uuid, String)>,
    },
    SendTransactionComplete {
        peer_id: String,
        transaction_id: Uuid,
    },
    AcceptResume {
        peer_id: String,
        transaction_id: Uuid,
    },
    SendResumeRequest {
        peer_id: String,
        transaction_id: Uuid,
        resume_info: ResumeInfo,
    },
    RejectResume {
        peer_id: String,
        transaction_id: Uuid,
        reason: String,
    },
    ResendFiles {
        peer_id: String,
        transaction_id: Uuid,
    },
    HandleRemoteFetch {
        peer_id: String,
        path: String,
        is_folder: bool,
    },
    CancelTransaction {
        peer_id: String,
        transaction_id: Uuid,
    },
    RetransmitChunks {
        peer_id: String,
        file_id: Uuid,
        chunk_indices: Vec<u32>,
    },
    TransactionCompleteAck {
        peer_id: String,
        transaction_id: Uuid,
    },
}

// ── Engine Outcome ───────────────────────────────────────────────────────────

pub struct EngineOutcome {
    pub actions: Vec<EngineAction>,
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

    fn with_action(action: EngineAction, status: impl Into<String>) -> Self {
        Self {
            actions: vec![action],
            status: Some(status.into()),
        }
    }

    fn with_actions(actions: Vec<EngineAction>, status: impl Into<String>) -> Self {
        Self {
            actions,
            status: Some(status.into()),
        }
    }
}

// ── Pending Incoming Transaction ─────────────────────────────────────────────

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

/// Comprehensive statistics tracking ALL data sent/received.
#[derive(Debug, Default, Clone)]
pub struct DataStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// Pre-compression bytes received (original payload size).
    pub raw_bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub files_sent: u64,
    pub files_received: u64,
    pub folders_sent: u64,
    pub folders_received: u64,
    pub metadata_bytes: u64,
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
    pub timestamp: String,
    pub status: TransferStatus,
}

// ── TransferEngine ───────────────────────────────────────────────────────────

pub struct TransferEngine {
    transactions: TransactionManager,
    stats: DataStats,
    pending_incoming: Option<PendingIncoming>,
    transfer_history: Vec<TransferRecord>,
    source_paths: HashMap<Uuid, String>,
    identity: Option<PeerIdentity>,
    replay_guard: ReplayGuard,
    peer_file_stats: HashMap<String, (u64, u64)>,
}

impl TransferEngine {
    // ── Construction ─────────────────────────────────────────────────────

    pub fn new() -> Self {
        let identity = PeerIdentity::default_path()
            .ok()
            .and_then(|p| PeerIdentity::load_or_create(&p).ok());

        let (transfer_history, transactions, source_paths, stats) =
            Self::restore_from_persistence();

        Self {
            transactions,
            stats,
            pending_incoming: None,
            transfer_history,
            source_paths,
            identity,
            replay_guard: ReplayGuard::new(),
            peer_file_stats: HashMap::new(),
        }
    }

    /// Load persisted state, returning (history, manager, source_paths, stats).
    fn restore_from_persistence() -> (
        Vec<TransferRecord>,
        TransactionManager,
        HashMap<Uuid, String>,
        DataStats,
    ) {
        let mut p = match Persistence::load() {
            Ok(p) => p,
            Err(_) => {
                return (
                    Vec::new(),
                    TransactionManager::new(),
                    HashMap::new(),
                    DataStats::default(),
                );
            }
        };

        let mut history: Vec<TransferRecord> = p
            .transfer_history
            .iter()
            .map(TransferRecord::from_snapshot)
            .collect();

        let mut manager = TransactionManager::new();
        let mut source_paths = HashMap::new();
        let mut expired_ids = Vec::new();

        for (id, snap) in &p.transactions {
            if snap.direction != TransactionDirection::Outbound
                || !matches!(
                    snap.state,
                    TransactionState::Resumable | TransactionState::Interrupted
                )
            {
                continue;
            }

            if snap.is_expired() {
                warn!(
                    event = "transaction_expired",
                    transaction_id = %id,
                    "Transaction expired, moving to history"
                );
                expired_ids.push(*id);
                history.push(TransferRecord {
                    direction: snap.direction,
                    peer_id: snap.peer_id.clone(),
                    display_name: snap.display_name.clone(),
                    total_size: snap.total_size,
                    file_count: snap.files.len() as u32,
                    timestamp: crate::ui::helpers::format_absolute_timestamp_now(),
                    status: TransferStatus::Expired,
                });
                continue;
            }

            if let Some(src) = &snap.source_path {
                source_paths.insert(*id, src.clone());
            }
            manager.insert(Transaction::from_snapshot(snap));
            info!(
                event = "transaction_restored_from_persistence",
                transaction_id = %id,
                state = ?snap.state,
                peer_id = %snap.peer_id,
            );
        }

        // Purge expired snapshots and update persisted history
        if !expired_ids.is_empty() {
            for id in &expired_ids {
                p.transactions.remove(id);
            }
            p.transfer_history = history
                .iter()
                .map(TransferRecordSnapshot::from_record)
                .collect();
            let _ = p.save();
        }

        if !manager.active.is_empty() {
            info!(
                event = "persistence_restore_complete",
                count = manager.active.len(),
                "Restored {} resumable outbound transaction(s)",
                manager.active.len()
            );
        }

        let stats = DataStats {
            files_sent: p.transfer_stats.files_sent,
            files_received: p.transfer_stats.files_received,
            folders_sent: p.transfer_stats.folders_sent,
            folders_received: p.transfer_stats.folders_received,
            messages_sent: p.transfer_stats.messages_sent,
            messages_received: p.transfer_stats.messages_received,
            ..DataStats::default()
        };

        (history, manager, source_paths, stats)
    }

    // ── Queries ───────────────────────────────────────────────────────────

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

    pub fn get_source_path(&self, txn_id: &Uuid) -> Option<&String> {
        self.source_paths.get(txn_id)
    }

    pub fn find_transaction_by_file_mut(&mut self, file_id: &Uuid) -> Option<&mut Transaction> {
        self.transactions.find_by_file_mut(file_id)
    }

    // ── Active transfer control ───────────────────────────────────────────

    pub fn cancel_active_transfer(&mut self, transaction_id: &Uuid) -> EngineOutcome {
        let Some(txn) = self.transactions.get_active_mut(transaction_id) else {
            return EngineOutcome::empty();
        };
        let peer_id = txn.peer_id.clone();
        let display_name = txn.display_name.clone();
        txn.cancel();
        info!(event = "transfer_cancelled_by_user", transaction_id = %transaction_id, name = %display_name);
        self.archive_transaction_with_status(*transaction_id, TransferStatus::Cancelled);
        self.source_paths.remove(transaction_id);
        EngineOutcome::with_action(
            EngineAction::CancelTransaction {
                peer_id,
                transaction_id: *transaction_id,
            },
            format!("Cancelled: {}", display_name),
        )
    }

    // ── Manifest signing & validation ─────────────────────────────────────

    pub fn sign_manifest(&self, manifest: &mut TransactionManifest) {
        let Some(ref identity) = self.identity else {
            return;
        };
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

    pub fn validate_manifest_signature(&self, manifest: &TransactionManifest) -> bool {
        match (&manifest.sender_id, &manifest.signature) {
            (Some(sender_id), Some(signature)) => {
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
                let content = Transaction::manifest_content_bytes(manifest);
                let signed = crate::core::security::identity::SignedPayload {
                    data: content,
                    signature: *signature,
                    signer: *sender_id,
                };
                PeerIdentity::verify_signed(&signed, sender_id)
            }
            // No security fields — accept (backward compat)
            _ => true,
        }
    }

    fn register_replay_guard(&mut self, transaction_id: Uuid) {
        let expiration = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + TRANSACTION_TIMEOUT.as_secs();
        self.replay_guard
            .register_transaction(transaction_id, expiration);
    }

    // ── Initiating outbound transfers ─────────────────────────────────────

    pub fn initiate_file_send(
        &mut self,
        peer_id: &str,
        filename: &str,
        filesize: u64,
        file_path: &str,
    ) -> Result<EngineOutcome> {
        self.check_transfer_capacity("File send")?;

        let mut txn = Transaction::new_outbound(
            peer_id.to_owned(),
            filename.to_owned(),
            None,
            vec![(filename.to_owned(), filesize)],
        );
        // Set full_path on the single file for crash-resilient resume
        if let Some(file_id) = txn.file_order.first() {
            if let Some(tf) = txn.files.get_mut(file_id) {
                tf.full_path = Some(file_path.to_owned());
            }
        }
        let txn_id = txn.id;
        let total_size = txn.total_size;
        let mut manifest = txn.build_manifest();
        self.sign_manifest(&mut manifest);
        self.register_replay_guard(txn_id);
        self.source_paths.insert(txn_id, file_path.to_owned());
        self.transactions.insert(txn);
        self.persist_active_transaction(&txn_id);

        info!(event = "transfer_initiated", transaction_id = %txn_id, kind = "file", filename, filesize);
        Ok(EngineOutcome::with_action(
            EngineAction::SendTransactionRequest {
                peer_id: peer_id.to_owned(),
                transaction_id: txn_id,
                display_name: filename.to_owned(),
                manifest,
                total_size,
            },
            format!("Sending {}...", filename),
        ))
    }

    pub fn initiate_folder_send(
        &mut self,
        peer_id: &str,
        dirname: &str,
        files: Vec<(String, u64)>,
        folder_path: &str,
    ) -> Result<EngineOutcome> {
        self.check_transfer_capacity("Folder send")?;
        if files.is_empty() {
            warn!(event = "empty_folder_send", dirname);
            return Err(anyhow!("Folder is empty"));
        }

        // Build a map of relative_path -> full_path for setting full_path on each file
        let full_paths: HashMap<String, String> = files
            .iter()
            .map(|(rel_path, _)| {
                let full = std::path::Path::new(folder_path)
                    .join(rel_path)
                    .to_string_lossy()
                    .to_string();
                (rel_path.clone(), full)
            })
            .collect();

        let mut txn = Transaction::new_outbound(
            peer_id.to_owned(),
            dirname.to_owned(),
            Some(dirname.to_owned()),
            files,
        );

        // Set full_path on each file for crash-resilient resume
        for file_id in &txn.file_order {
            if let Some(tf) = txn.files.get_mut(file_id) {
                if let Some(full) = full_paths.get(&tf.relative_path) {
                    tf.full_path = Some(full.clone());
                }
            }
        }

        let txn_id = txn.id;
        let total_size = txn.total_size;
        let files_len = txn.file_order.len();
        let mut manifest = txn.build_manifest();
        self.sign_manifest(&mut manifest);
        self.register_replay_guard(txn_id);
        self.source_paths.insert(txn_id, folder_path.to_owned());
        self.transactions.insert(txn);
        self.persist_active_transaction(&txn_id);

        info!(event = "transfer_initiated", transaction_id = %txn_id, kind = "folder", dirname, file_count = files_len, total_size);
        Ok(EngineOutcome::with_action(
            EngineAction::SendTransactionRequest {
                peer_id: peer_id.to_owned(),
                transaction_id: txn_id,
                display_name: dirname.to_owned(),
                manifest,
                total_size,
            },
            format!("Sending folder {}...", dirname),
        ))
    }

    fn check_transfer_capacity(&self, label: &str) -> Result<()> {
        if self.can_start_transfer() {
            Ok(())
        } else {
            warn!(
                event = "transfer_limit_reached",
                active = self.transactions.active_count(),
                limit = MAX_CONCURRENT_TRANSACTIONS,
                "{} blocked: concurrent transaction limit",
                label
            );
            Err(anyhow!(
                "Maximum concurrent transactions ({}) reached",
                MAX_CONCURRENT_TRANSACTIONS
            ))
        }
    }

    // ── Accepting / Rejecting Incoming Transfers ──────────────────────────

    pub fn accept_incoming(&mut self, dest_path: String) -> Result<EngineOutcome> {
        let pending = self
            .pending_incoming
            .take()
            .ok_or_else(|| anyhow!("No pending incoming transaction"))?;

        info!(
            event = "transfer_accepted",
            transaction_id = %pending.transaction_id,
            display_name = %pending.display_name,
            dest = %dest_path
        );

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

        let files: Vec<(Uuid, PathBuf)> = txn
            .file_order
            .iter()
            .map(|fid| (*fid, PathBuf::from(&dest_path)))
            .collect();

        let peer_id = pending.peer_id;
        let txn_id = pending.transaction_id;
        let display_name = pending.display_name;

        self.transactions.insert(txn);
        self.persist_active_transaction(&txn_id);

        Ok(EngineOutcome::with_actions(
            vec![
                EngineAction::PrepareReceive {
                    peer_id: peer_id.clone(),
                    files,
                    resume_bitmaps: Vec::new(),
                },
                EngineAction::SendTransactionResponse {
                    peer_id,
                    transaction_id: txn_id,
                    accepted: true,
                    dest_path: Some(dest_path),
                    reason: None,
                },
            ],
            format!("Downloading: {}", display_name),
        ))
    }

    pub fn reject_incoming(&mut self) -> Result<EngineOutcome> {
        let pending = self
            .pending_incoming
            .take()
            .ok_or_else(|| anyhow!("No pending incoming transaction"))?;

        info!(
            event = "transfer_rejected",
            transaction_id = %pending.transaction_id,
            display_name = %pending.display_name
        );

        let display_name = pending.display_name.clone();
        let mut txn = Transaction::new_inbound(
            pending.transaction_id,
            pending.peer_id.clone(),
            pending.display_name.clone(),
            pending.manifest.parent_dir.clone(),
            pending.total_size,
            &pending.manifest,
        );
        txn.reject(Some("User declined".to_owned()));
        self.transactions.insert(txn);
        self.archive_transaction_with_status(pending.transaction_id, TransferStatus::Declined);

        Ok(EngineOutcome::with_action(
            EngineAction::SendTransactionResponse {
                peer_id: pending.peer_id,
                transaction_id: pending.transaction_id,
                accepted: false,
                dest_path: None,
                reason: Some("User declined".to_owned()),
            },
            format!("Rejected transfer: {}", display_name),
        ))
    }

    // ── Event processing ──────────────────────────────────────────────────

    pub fn process_event(&mut self, event: &AppEvent) -> EngineOutcome {
        match event {
            AppEvent::ChunkRetransmitRequested {
                peer_id,
                file_id,
                chunk_indices,
            } => self.handle_chunk_retransmit(peer_id, file_id, chunk_indices),

            AppEvent::TransactionCompleteAcked {
                peer_id,
                transaction_id,
            } => {
                info!(event = "transaction_complete_ack_received", transaction_id = %transaction_id);
                let display = self
                    .transactions
                    .get(transaction_id)
                    .map(|t| t.display_name.clone())
                    .unwrap_or_default();
                self.archive_transaction_with_status(*transaction_id, TransferStatus::Ok);
                self.source_paths.remove(transaction_id);
                EngineOutcome::with_action(
                    EngineAction::TransactionCompleteAck {
                        peer_id: peer_id.clone(),
                        transaction_id: *transaction_id,
                    },
                    format!("Transfer complete: {}", display),
                )
            }

            AppEvent::FileReceivedAck { file_id } => {
                debug!(event = "file_received_ack", file_id = %file_id);
                EngineOutcome::empty()
            }

            AppEvent::PeerDisconnected { peer_id, .. } => self.handle_peer_disconnected(peer_id),

            AppEvent::ChatReceived { message, .. } => {
                self.stats.messages_received += 1;
                self.stats.raw_bytes_received += message.len() as u64;
                self.stats.bytes_received += message.len() as u64;
                self.persist_transfer_stats();
                EngineOutcome::empty()
            }

            AppEvent::FileProgress {
                file_id,
                received_chunks,
                wire_bytes,
                chunk_bitmap_bytes,
                ..
            } => {
                if let Some(txn) = self.transactions.find_by_file_mut(file_id) {
                    let old = txn
                        .files
                        .get(file_id)
                        .map(|f| f.transferred_chunks)
                        .unwrap_or(0);
                    let delta = received_chunks.saturating_sub(old);
                    self.stats.raw_bytes_received += delta as u64 * CHUNK_SIZE as u64;
                    self.stats.bytes_received += wire_bytes;
                    txn.update_file_progress_with_bitmap(
                        *file_id,
                        *received_chunks,
                        chunk_bitmap_bytes.as_deref(),
                    );
                    if received_chunks % 10 == 0 {
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
                    self.stats.bytes_sent += wire_bytes;
                    txn.update_file_progress_sent(*file_id, *sent_chunks);
                    if sent_chunks % 10 == 0 {
                        let txn_id = txn.id;
                        self.persist_active_transaction(&txn_id);
                    }
                }
                EngineOutcome::empty()
            }

            AppEvent::SendComplete {
                file_id, success, ..
            } => self.handle_send_complete(file_id, *success),

            AppEvent::FileComplete {
                file_id,
                filename,
                merkle_root,
                ..
            } => self.handle_file_complete(file_id, filename, merkle_root),

            AppEvent::TransactionRequested {
                peer_id,
                transaction_id,
                display_name,
                manifest,
                total_size,
            } => self.handle_transaction_requested(
                peer_id,
                transaction_id,
                display_name,
                manifest,
                *total_size,
            ),

            AppEvent::TransactionAccepted {
                transaction_id,
                dest_path,
            } => self.handle_transaction_accepted(transaction_id, dest_path.as_deref()),

            AppEvent::TransactionRejected {
                transaction_id,
                reason,
            } => {
                info!(event = "transfer_peer_rejected", transaction_id = %transaction_id, reason = ?reason);
                if let Some(txn) = self.transactions.get_active_mut(transaction_id) {
                    txn.reject(reason.clone());
                }
                self.archive_transaction_with_status(*transaction_id, TransferStatus::Declined);
                self.source_paths.remove(transaction_id);
                EngineOutcome::with_status(format!(
                    "Transfer rejected: {}",
                    reason.as_deref().unwrap_or("no reason")
                ))
            }

            AppEvent::TransactionCompleted { transaction_id } => {
                if let Some(txn) = self.transactions.get_active_mut(transaction_id) {
                    let ids: Vec<_> = txn.file_order.clone();
                    for fid in ids {
                        txn.complete_file(fid, true);
                    }
                    txn.check_completion();
                }
                let display = self
                    .transactions
                    .get(transaction_id)
                    .map(|t| t.display_name.clone())
                    .unwrap_or_default();
                self.archive_transaction_with_status(*transaction_id, TransferStatus::Ok);
                EngineOutcome::with_status(format!("Transfer complete: {}", display))
            }

            AppEvent::TransactionCancelled {
                transaction_id,
                reason,
                ..
            } => {
                warn!(event = "transfer_cancelled", transaction_id = %transaction_id, reason = ?reason);
                if let Some(txn) = self.transactions.get_active_mut(transaction_id) {
                    txn.cancel();
                }
                self.archive_transaction_with_status(*transaction_id, TransferStatus::Cancelled);
                self.source_paths.remove(transaction_id);
                EngineOutcome::with_status(format!(
                    "Transfer cancelled: {}",
                    reason.as_deref().unwrap_or("no reason")
                ))
            }

            AppEvent::TransactionResumeRequested {
                peer_id,
                resume_info,
            } => self.handle_resume_requested(peer_id, resume_info),

            AppEvent::TransactionResumeAccepted { transaction_id, .. } => {
                self.handle_resume_accepted(transaction_id)
            }

            AppEvent::TransactionResumeRejected {
                transaction_id,
                reason,
            } => {
                warn!(event = "resume_rejected_by_sender", transaction_id = %transaction_id, reason = ?reason);
                if let Some(txn) = self.transactions.get_active_mut(transaction_id) {
                    txn.cancel();
                }
                self.archive_transaction_with_status(
                    *transaction_id,
                    TransferStatus::ResumeDeclined,
                );
                EngineOutcome::with_status(format!(
                    "Resume declined: {}",
                    reason.as_deref().unwrap_or("unknown")
                ))
            }

            AppEvent::RemoteFetchRequest {
                peer_id,
                path,
                is_folder,
            } => {
                self.stats.remote_exploration_bytes += path.len() as u64;
                EngineOutcome::with_action(
                    EngineAction::HandleRemoteFetch {
                        peer_id: peer_id.clone(),
                        path: path.clone(),
                        is_folder: *is_folder,
                    },
                    "",
                )
            }

            AppEvent::LsResponse { .. } => {
                self.stats.remote_exploration_bytes += 256;
                EngineOutcome::empty()
            }

            _ => EngineOutcome::empty(),
        }
    }

    // ── Event sub-handlers ────────────────────────────────────────────────

    fn handle_chunk_retransmit(
        &mut self,
        peer_id: &str,
        file_id: &Uuid,
        chunk_indices: &[u32],
    ) -> EngineOutcome {
        let Some(txn) = self.transactions.find_by_file_mut(file_id) else {
            return EngineOutcome::empty();
        };
        let Some(tf) = txn.files.get_mut(file_id) else {
            return EngineOutcome::empty();
        };

        tf.retransmit_count += 1;
        if tf.retransmit_count > MAX_FILE_RETRANSMISSIONS {
            warn!(event = "retransmit_limit_exceeded", file_id = %file_id, "File failed too many times");
            tf.completed = true;
            tf.verified = Some(false);
            EngineOutcome::empty()
        } else {
            info!(
                event = "retransmit_chunks",
                file_id = %file_id,
                count = tf.retransmit_count,
                chunks = ?chunk_indices
            );
            let status = format!(
                "Retransmitting {} chunks for file {} (attempt {})",
                chunk_indices.len(),
                file_id,
                tf.retransmit_count
            );
            EngineOutcome::with_action(
                EngineAction::RetransmitChunks {
                    peer_id: peer_id.to_owned(),
                    file_id: *file_id,
                    chunk_indices: chunk_indices.to_vec(),
                },
                status,
            )
        }
    }

    fn handle_peer_disconnected(&mut self, peer_id: &str) -> EngineOutcome {
        info!(event = "peer_transfers_interrupted", peer = %peer_id);
        self.transactions.interrupt_peer(peer_id);

        let txn_ids: Vec<Uuid> = self
            .transactions
            .active
            .iter()
            .filter(|(_, t)| t.peer_id == peer_id && t.state == TransactionState::Interrupted)
            .map(|(id, _)| *id)
            .collect();

        if !txn_ids.is_empty() {
            let mut persistence = Persistence::load().unwrap_or_default();
            self.persist_transactions_as_resumable(&txn_ids, &mut persistence);
            match persistence.save() {
                Err(e) => error!(event = "persistence_save_failure", error = %e),
                Ok(_) => info!(event = "transactions_persisted", count = txn_ids.len()),
            }
        }

        if self
            .pending_incoming
            .as_ref()
            .map_or(false, |p| p.peer_id == peer_id)
        {
            self.pending_incoming = None;
        }
        EngineOutcome::empty()
    }

    fn handle_send_complete(&mut self, file_id: &Uuid, success: bool) -> EngineOutcome {
        let Some(txn) = self.transactions.find_by_file_mut(file_id) else {
            return if success {
                EngineOutcome::with_status("Sent successfully")
            } else {
                EngineOutcome::with_status("Transfer failed: verification error")
            };
        };

        if success {
            txn.complete_file(*file_id, true);
            self.stats.files_sent += 1;
            self.peer_file_stats
                .entry(txn.peer_id.clone())
                .or_default()
                .0 += 1;
            debug!(event = "file_sent", file_id = %file_id, transaction_id = %txn.id);
        } else {
            if let Some(tf) = txn.files.get_mut(file_id) {
                tf.completed = true;
                tf.verified = Some(false);
            }
            warn!(event = "file_send_failed", file_id = %file_id, transaction_id = %txn.id);
        }

        let all_done = txn.files.values().all(|f| f.completed);
        if !all_done {
            return if success {
                EngineOutcome::with_status("Sent successfully")
            } else {
                EngineOutcome::with_status("Transfer failed: verification error")
            };
        }

        let txn_id = txn.id;
        let peer_id = txn.peer_id.clone();
        let is_folder = txn.parent_dir.is_some();
        let display_name = txn.display_name.clone();
        info!(event = "transfer_complete", transaction_id = %txn_id, direction = "outbound", name = %display_name);

        if is_folder {
            self.stats.folders_sent += 1;
        }
        self.persist_transfer_stats();
        self.archive_transaction_with_status(txn_id, TransferStatus::Ok);
        self.source_paths.remove(&txn_id);

        EngineOutcome::with_action(
            EngineAction::SendTransactionComplete {
                peer_id,
                transaction_id: txn_id,
            },
            format!("Transfer complete: {}", display_name),
        )
    }

    fn handle_file_complete(
        &mut self,
        file_id: &Uuid,
        filename: &str,
        merkle_root: &[u8; 32],
    ) -> EngineOutcome {
        let Some(txn) = self.transactions.find_by_file_mut(file_id) else {
            return EngineOutcome::with_status(format!("Received: {}", filename));
        };

        // Verify Merkle root if manifest provided one
        if let Some(expected) = txn.files.get(file_id).and_then(|f| f.merkle_root) {
            if expected != *merkle_root {
                warn!(event = "merkle_root_mismatch", file_id = %file_id, transaction_id = %txn.id);
            } else {
                debug!(event = "merkle_root_verified", file_id = %file_id, transaction_id = %txn.id);
            }
        }

        txn.complete_file(*file_id, true);
        if let Some(tf) = txn.files.get_mut(file_id) {
            tf.merkle_root = Some(*merkle_root);
        }
        self.stats.files_received += 1;
        self.peer_file_stats
            .entry(txn.peer_id.clone())
            .or_default()
            .1 += 1;
        debug!(event = "file_received", file_id = %file_id, transaction_id = %txn.id, filename);

        let txn_id = txn.id;
        let is_folder = txn.parent_dir.is_some();
        let complete = txn.check_completion();

        if complete {
            let display_name = self
                .transactions
                .get(&txn_id)
                .map(|t| t.display_name.clone())
                .unwrap_or_default();
            info!(event = "transfer_complete", transaction_id = %txn_id, direction = "inbound", name = %display_name);
            if is_folder {
                self.stats.folders_received += 1;
            }
            self.persist_transfer_stats();
            self.replay_guard.remove_transaction(&txn_id);
            self.archive_transaction_with_status(txn_id, TransferStatus::Ok);
            EngineOutcome::with_status(format!("Transfer complete: {}", display_name))
        } else {
            EngineOutcome::with_status(format!("Received: {}", filename))
        }
    }

    fn handle_transaction_requested(
        &mut self,
        peer_id: &str,
        transaction_id: &Uuid,
        display_name: &str,
        manifest: &TransactionManifest,
        total_size: u64,
    ) -> EngineOutcome {
        if !self.validate_manifest_signature(manifest) {
            warn!(event = "manifest_signature_invalid", transaction_id = %transaction_id);
            return EngineOutcome::with_action(
                EngineAction::SendTransactionResponse {
                    peer_id: peer_id.to_owned(),
                    transaction_id: *transaction_id,
                    accepted: false,
                    dest_path: None,
                    reason: Some("Invalid manifest signature".to_owned()),
                },
                "Transfer rejected: invalid manifest signature",
            );
        }

        if !self.can_start_transfer() {
            return EngineOutcome::with_action(
                EngineAction::SendTransactionResponse {
                    peer_id: peer_id.to_owned(),
                    transaction_id: *transaction_id,
                    accepted: false,
                    dest_path: None,
                    reason: Some("Maximum concurrent transfers reached".to_owned()),
                },
                "Transfer request rejected: too many active transfers",
            );
        }

        self.register_replay_guard(*transaction_id);

        let save_dir = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| ".".to_owned());

        self.pending_incoming = Some(PendingIncoming {
            peer_id: peer_id.to_owned(),
            transaction_id: *transaction_id,
            display_name: display_name.to_owned(),
            manifest: manifest.clone(),
            total_size,
            save_path_input: save_dir,
            button_focus: 0,
            path_editing: false,
        });

        info!(
            event = "transfer_requested",
            transaction_id = %transaction_id,
            display_name,
            total_size,
            file_count = manifest.files.len()
        );
        self.stats.metadata_bytes += 256;
        EngineOutcome::with_status(format!("Transfer request: {}", display_name))
    }

    fn handle_transaction_accepted(
        &mut self,
        transaction_id: &Uuid,
        dest_path: Option<&str>,
    ) -> EngineOutcome {
        let Some(txn) = self.transactions.get_active_mut(transaction_id) else {
            return EngineOutcome::empty();
        };

        info!(event = "transfer_peer_accepted", transaction_id = %transaction_id, display_name = %txn.display_name);
        txn.activate();
        if let Some(dp) = dest_path {
            txn.dest_path = Some(PathBuf::from(dp));
        }
        let display = txn.display_name.clone();
        let peer_id = txn.peer_id.clone();
        let is_folder = txn.parent_dir.is_some();

        let source_path = match self.source_paths.get(transaction_id).cloned() {
            Some(p) => p,
            None => {
                error!(event = "source_path_missing", transaction_id = %transaction_id);
                return EngineOutcome::with_status("Internal error: source path not found");
            }
        };

        let txn = self.transactions.get_active_mut(transaction_id).unwrap();
        let actions = if is_folder {
            let file_entries: Vec<(Uuid, String)> = txn
                .file_order
                .iter()
                .filter_map(|fid| txn.files.get(fid).map(|f| (*fid, f.relative_path.clone())))
                .collect();
            vec![EngineAction::SendFolderData {
                peer_id,
                folder_path: source_path,
                file_entries,
            }]
        } else {
            let first = txn.file_order.first().copied().unwrap_or(Uuid::nil());
            let filename = txn
                .files
                .get(&first)
                .map(|f| f.relative_path.clone())
                .unwrap_or_default();
            vec![EngineAction::SendFileData {
                peer_id,
                file_path: source_path,
                file_id: first,
                filename,
            }]
        };

        self.persist_active_transaction(transaction_id);
        EngineOutcome::with_actions(actions, format!("Sending: {}", display))
    }

    fn handle_resume_requested(
        &mut self,
        peer_id: &str,
        resume_info: &ResumeInfo,
    ) -> EngineOutcome {
        let txn_id = resume_info.transaction_id;
        info!(
            event = "transfer_resume_requested",
            transaction_id = %txn_id,
            completed_files = resume_info.completed_files.len()
        );

        // Restore from persistence if not already in memory
        if self.transactions.get(&txn_id).is_none() {
            match Persistence::load() {
                Ok(p) => {
                    if let Some(snap) = p.transactions.get(&txn_id) {
                        if let Some(ref src) = snap.source_path {
                            self.source_paths.insert(txn_id, src.clone());
                        }
                        let restored = Transaction::from_snapshot(snap);
                        info!(event = "transaction_restored", transaction_id = %txn_id);
                        self.transactions.insert(restored);
                    }
                }
                Err(e) => {
                    error!(event = "persistence_load_failure_on_resume", transaction_id = %txn_id, error = %e)
                }
            }
        }

        let Some(txn) = self.transactions.get_active_mut(&txn_id) else {
            warn!(event = "resume_rejected_unknown", transaction_id = %txn_id);
            return EngineOutcome::with_action(
                EngineAction::RejectResume {
                    peer_id: peer_id.to_owned(),
                    transaction_id: txn_id,
                    reason: "Transaction not found".to_owned(),
                },
                format!("Resume rejected: unknown transaction {}", txn_id),
            );
        };

        if let Err(reason) =
            txn.validate_resume_request(resume_info, MAX_TRANSACTION_RETRIES as u32)
        {
            warn!(
                event = "resume_rejected",
                transaction_id = %txn_id,
                state = ?txn.state,
                reason = reason.as_str()
            );
            return EngineOutcome::with_action(
                EngineAction::RejectResume {
                    peer_id: peer_id.to_owned(),
                    transaction_id: txn_id,
                    reason: reason.to_string(),
                },
                "Resume rejected",
            );
        }

        txn.apply_resume_info(resume_info);

        // Clean persisted state — we are resuming now
        if let Ok(mut p) = Persistence::load() {
            let _ = p.remove_transaction(&txn_id);
        }

        EngineOutcome::with_actions(
            vec![
                EngineAction::AcceptResume {
                    peer_id: peer_id.to_owned(),
                    transaction_id: txn_id,
                },
                EngineAction::ResendFiles {
                    peer_id: peer_id.to_owned(),
                    transaction_id: txn_id,
                },
            ],
            "Resuming transfer",
        )
    }

    fn handle_resume_accepted(&mut self, transaction_id: &Uuid) -> EngineOutcome {
        let Some(txn) = self.transactions.get_active_mut(transaction_id) else {
            return EngineOutcome::with_status("Resume accepted");
        };
        txn.activate();
        let peer_id = txn.peer_id.clone();
        let txn_id = *transaction_id;
        let is_inbound = txn.direction == TransactionDirection::Inbound;

        if let Ok(mut p) = Persistence::load() {
            let _ = p.remove_transaction(&txn_id);
        }
        info!(event = "resume_accepted", transaction_id = %txn_id, peer = %peer_id);

        if is_inbound {
            let txn = self.transactions.get_active_mut(&txn_id).unwrap();
            let files = Self::incomplete_file_destinations(txn);
            let bitmaps = Self::incomplete_file_bitmaps(txn);
            if !files.is_empty() {
                return EngineOutcome::with_action(
                    EngineAction::PrepareReceive {
                        peer_id,
                        files,
                        resume_bitmaps: bitmaps,
                    },
                    "Resume accepted",
                );
            }
        }
        EngineOutcome::with_status("Resume accepted")
    }

    // ── Reconnect handling ────────────────────────────────────────────────

    pub fn handle_peer_reconnected(&mut self, peer_id: &str) -> EngineOutcome {
        let mut actions = Vec::new();

        // Step 0: Transition zombie Active transactions to Resumable.
        let recently_resumed = std::time::Duration::from_secs(30);
        let active_ids: Vec<Uuid> = self
            .transactions
            .active
            .iter()
            .filter(|(_, t)| {
                t.peer_id == peer_id
                    && t.state == TransactionState::Active
                    && !t
                        .resumed_at
                        .map_or(false, |at| at.elapsed() < recently_resumed)
            })
            .map(|(id, _)| *id)
            .collect();

        if !active_ids.is_empty() {
            let mut persistence = Persistence::load().unwrap_or_default();
            self.persist_transactions_as_resumable(&active_ids, &mut persistence);
            for id in &active_ids {
                if let Some(txn) = self.transactions.get(&id) {
                    info!(
                        event = "active_to_resumable_on_reconnect",
                        transaction_id = %id,
                        direction = ?txn.direction
                    );
                }
            }
            if let Err(e) = persistence.save() {
                error!(event = "persistence_save_failure", error = %e);
            }
        }

        // Step 1: Collect in-memory inbound Resumable/Interrupted for this peer.
        let resumable_inbound: Vec<(Uuid, ResumeInfo)> = self
            .transactions
            .active
            .values()
            .filter(|t| {
                t.peer_id == peer_id
                    && matches!(
                        t.state,
                        TransactionState::Resumable | TransactionState::Interrupted
                    )
                    && t.direction == TransactionDirection::Inbound
            })
            .map(|t| (t.id, t.build_resume_info()))
            .collect();

        // Step 2: Restore from persistence (not yet in memory).
        match Persistence::load() {
            Err(ref e) => {
                error!(event = "persistence_load_failure_on_reconnect", peer = %peer_id, error = %e)
            }
            Ok(persistence) => {
                for (txn_id, snap) in &persistence.transactions {
                    if snap.peer_id != peer_id
                        || self.transactions.active.contains_key(txn_id)
                        || !matches!(
                            snap.state,
                            TransactionState::Resumable
                                | TransactionState::Interrupted
                                | TransactionState::Active
                        )
                    {
                        continue;
                    }

                    if let Some(ref src) = snap.source_path {
                        self.source_paths.insert(*txn_id, src.clone());
                    }

                    let restored = Transaction::from_snapshot(snap);
                    let direction = restored.direction;
                    let resume_info = restored.build_resume_info();
                    let rid = restored.id;
                    self.transactions.insert(restored);

                    if direction == TransactionDirection::Inbound {
                        info!(event = "transaction_restored_for_resume", transaction_id = %rid);
                        if let Some(txn) = self.transactions.get(&rid) {
                            let files = Self::incomplete_file_destinations(txn);
                            let bitmaps = Self::incomplete_file_bitmaps(txn);
                            if !files.is_empty() {
                                actions.push(EngineAction::PrepareReceive {
                                    peer_id: peer_id.to_owned(),
                                    files,
                                    resume_bitmaps: bitmaps,
                                });
                            }
                        }
                        actions.push(EngineAction::SendResumeRequest {
                            peer_id: peer_id.to_owned(),
                            transaction_id: rid,
                            resume_info,
                        });
                    } else {
                        info!(
                            event = "transaction_restored_for_resume",
                            transaction_id = %rid,
                            "Outbound restored, awaiting receiver resume request"
                        );
                    }
                }
            }
        }

        // Step 3: Send resume requests for in-memory inbound transactions.
        for (txn_id, resume_info) in resumable_inbound {
            if let Some(txn) = self.transactions.get(&txn_id) {
                let files = Self::incomplete_file_destinations(txn);
                let bitmaps = Self::incomplete_file_bitmaps(txn);
                if !files.is_empty() {
                    actions.push(EngineAction::PrepareReceive {
                        peer_id: peer_id.to_owned(),
                        files,
                        resume_bitmaps: bitmaps,
                    });
                }
            }
            info!(event = "resume_request_queued", transaction_id = %txn_id, peer = %peer_id);
            actions.push(EngineAction::SendResumeRequest {
                peer_id: peer_id.to_owned(),
                transaction_id: txn_id,
                resume_info,
            });
        }

        // Step 4: Outbound resumable transactions wait for receiver to drive resume.

        if actions.is_empty() {
            self.log_no_resume_actions(peer_id);
            EngineOutcome::empty()
        } else {
            let count = actions.len();
            info!(event = "resume_on_reconnect", peer = %peer_id, count);
            EngineOutcome::with_actions(actions, format!("Resuming {} transfer(s)", count))
        }
    }

    fn log_no_resume_actions(&self, peer_id: &str) {
        let for_peer: Vec<_> = self
            .transactions
            .active
            .values()
            .filter(|t| t.peer_id == peer_id)
            .map(|t| {
                format!(
                    "{}({:?}/{:?})",
                    &t.id.to_string()[..8],
                    t.state,
                    t.direction
                )
            })
            .collect();

        if for_peer.is_empty() {
            info!(event = "resume_no_transactions", peer = %peer_id);
            if let Ok(persistence) = Persistence::load() {
                let ids: Vec<_> = persistence
                    .transactions
                    .keys()
                    .map(|id| id.to_string()[..8].to_owned())
                    .collect();
                if !ids.is_empty() {
                    info!(event = "resume_persisted_available", count = ids.len(), ids = ?ids);
                }
            }
        } else {
            info!(event = "resume_no_actions", peer = %peer_id, transactions = ?for_peer);
        }
    }

    // ── Statistics ────────────────────────────────────────────────────────

    pub fn record_message_sent(&mut self, bytes: u64) {
        self.stats.messages_sent += 1;
        self.stats.bytes_sent += bytes;
        self.persist_transfer_stats();
    }

    pub fn source_path(&self, transaction_id: &Uuid) -> Option<&str> {
        self.source_paths.get(transaction_id).map(String::as_str)
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    /// Collect `(file_id, dest_path)` for every incomplete file in `txn`.
    fn incomplete_file_destinations(txn: &Transaction) -> Vec<(Uuid, PathBuf)> {
        let Some(dest) = txn.dest_path.as_ref() else {
            return Vec::new();
        };
        txn.file_order
            .iter()
            .filter_map(|fid| {
                txn.files
                    .get(fid)
                    .filter(|f| !f.completed)
                    .map(|_| (*fid, dest.clone()))
            })
            .collect()
    }

    /// Collect chunk bitmaps for every incomplete file in `txn`.
    fn incomplete_file_bitmaps(
        txn: &Transaction,
    ) -> Vec<(Uuid, crate::core::pipeline::chunk::ChunkBitmap)> {
        txn.file_order
            .iter()
            .filter_map(|fid| {
                txn.files
                    .get(fid)
                    .and_then(|f| {
                        (!f.completed).then(|| f.chunk_bitmap.as_ref().map(|bm| (*fid, bm.clone())))
                    })
                    .flatten()
            })
            .collect()
    }

    /// Transition a set of transactions to `Resumable` and build their snapshots.
    fn persist_transactions_as_resumable(
        &mut self,
        txn_ids: &[Uuid],
        persistence: &mut Persistence,
    ) {
        for &txn_id in txn_ids {
            if let Some(txn) = self.transactions.get_active_mut(&txn_id) {
                txn.make_resumable();
                let src = self.source_paths.get(&txn_id).map(String::as_str);
                let snapshot = txn.to_snapshot_with_source(src);
                debug!(
                    event = "transaction_persisted",
                    transaction_id = %txn_id,
                    direction = ?txn.direction,
                    state = ?txn.state
                );
                persistence.transactions.insert(txn_id, snapshot);
            }
        }
    }

    fn persist_active_transaction(&self, txn_id: &Uuid) {
        let Some(txn) = self.transactions.get(txn_id) else {
            return;
        };
        let src = self.source_paths.get(txn_id).map(String::as_str);
        let snapshot = txn.to_snapshot_with_source(src);
        let mut p = Persistence::load().unwrap_or_default();
        p.transactions.insert(*txn_id, snapshot);
        if let Err(e) = p.save() {
            warn!(event = "persist_active_failure", transaction_id = %txn_id, error = %e);
        }
    }

    fn persist_transfer_stats(&self) {
        if let Ok(mut p) = Persistence::load() {
            let snapshot = crate::core::persistence::TransferStatsSnapshot {
                files_sent: self.stats.files_sent,
                files_received: self.stats.files_received,
                folders_sent: self.stats.folders_sent,
                folders_received: self.stats.folders_received,
                messages_sent: self.stats.messages_sent,
                messages_received: self.stats.messages_received,
            };
            if let Err(e) = p.update_transfer_stats(&snapshot) {
                warn!(event = "transfer_stats_persist_failure", error = %e);
            }
        }
    }

    fn archive_transaction_with_status(&mut self, txn_id: Uuid, status: TransferStatus) {
        if let Some(txn) = self.transactions.active.get(&txn_id) {
            let record = TransferRecord {
                direction: txn.direction,
                peer_id: txn.peer_id.clone(),
                display_name: txn.display_name.clone(),
                total_size: txn.total_size,
                file_count: txn.total_file_count(),
                timestamp: crate::ui::helpers::format_absolute_timestamp_now(),
                status: status.clone(),
            };
            let snapshot = TransferRecordSnapshot::from_record(&record);
            self.transfer_history.push(record);

            if let Ok(mut p) = Persistence::load() {
                if let Err(e) = p.push_transfer_record(snapshot) {
                    warn!(event = "history_persist_failure", error = %e);
                }
            }
        }

        self.transactions.archive(&txn_id);
        self.replay_guard.remove_transaction(&txn_id);

        let mut p = Persistence::load().unwrap_or_default();
        let _ = p.remove_transaction(&txn_id);
    }
}

impl Default for TransferEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper conversions ────────────────────────────────────────────────────────

impl TransferRecord {
    fn from_snapshot(snap: &TransferRecordSnapshot) -> Self {
        Self {
            direction: snap.direction,
            peer_id: snap.peer_id.clone(),
            display_name: snap.display_name.clone(),
            total_size: snap.total_size,
            file_count: snap.file_count,
            timestamp: snap.timestamp.clone(),
            status: snap.status.clone(),
        }
    }
}

impl TransferRecordSnapshot {
    fn from_record(rec: &TransferRecord) -> Self {
        Self {
            direction: rec.direction,
            peer_id: rec.peer_id.clone(),
            display_name: rec.display_name.clone(),
            total_size: rec.total_size,
            file_count: rec.file_count,
            timestamp: rec.timestamp.clone(),
            status: rec.status.clone(),
        }
    }
}
