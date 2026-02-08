//! Transaction-based file transfer system.
//!
//! A Transaction represents one transfer request (file or folder), regardless of
//! the number of files involved. It owns:
//! - State management (lifecycle transitions)
//! - Progress calculation (aggregated over all files)
//! - ACK / resume / cancellation logic
//! - Control-channel coordination
//!
//! There is exactly one Transaction per transfer request.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;
use uuid::Uuid;

// ── Transaction State Machine ────────────────────────────────────────────────

/// All possible states a Transaction can be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionState {
    /// Transaction created, waiting for peer response.
    Pending,
    /// Peer accepted the transfer—files are being sent.
    Active,
    /// Transfer completed successfully.
    Completed,
    /// Transfer was rejected by the receiver.
    Rejected,
    /// Transfer was cancelled (by either side).
    Cancelled,
    /// Transfer failed with an error.
    Failed,
    /// Transfer paused / interrupted, eligible for resume.
    Interrupted,
}

impl TransactionState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TransactionState::Completed
                | TransactionState::Rejected
                | TransactionState::Cancelled
                | TransactionState::Failed
        )
    }
}

// ── Transaction Direction ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionDirection {
    /// We are sending files to a peer.
    Outbound,
    /// We are receiving files from a peer.
    Inbound,
}

// ── File entry inside a Transaction ──────────────────────────────────────────

/// Tracks progress of a single file within a Transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionFile {
    /// Unique ID for this file within the transaction.
    pub file_id: Uuid,
    /// Relative path (for folders) or filename (for single file).
    pub relative_path: String,
    /// Size of this file in bytes.
    pub filesize: u64,
    /// Number of chunks expected.
    pub total_chunks: u32,
    /// Number of chunks received/sent so far.
    pub transferred_chunks: u32,
    /// Whether this file has been fully transferred.
    pub completed: bool,
    /// Optional SHA3-256 hash once verified.
    pub verified: Option<bool>,
}

impl TransactionFile {
    pub fn new(file_id: Uuid, relative_path: String, filesize: u64) -> Self {
        let chunk_size = 48 * 1024; // matches CHUNK_SIZE in webrtc.rs
        let total_chunks = ((filesize as f64) / (chunk_size as f64)).ceil().max(1.0) as u32;
        Self {
            file_id,
            relative_path,
            filesize,
            total_chunks,
            transferred_chunks: 0,
            completed: false,
            verified: None,
        }
    }
}

// ── Transaction Manifest (sent over the wire) ────────────────────────────────

/// The file manifest sent from sender to receiver as part of the transfer request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionManifest {
    /// List of files in this transaction with relative paths and sizes.
    pub files: Vec<ManifestEntry>,
    /// Parent directory name, if this is a folder transfer.
    pub parent_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Unique ID for this file — shared between sender and receiver.
    pub file_id: Uuid,
    pub relative_path: String,
    pub filesize: u64,
}

// ── Resume info ──────────────────────────────────────────────────────────────

/// Sent by the receiver when requesting a resume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeInfo {
    /// Transaction ID to resume.
    pub transaction_id: Uuid,
    /// Files that have been fully and successfully received.
    pub completed_files: Vec<Uuid>,
    /// Per-file partial offsets (file_id -> byte offset already received).
    pub partial_offsets: HashMap<Uuid, u64>,
    /// Optional per-file checksums for partial verification.
    pub partial_checksums: HashMap<Uuid, Vec<u8>>,
}

// ── Transaction ──────────────────────────────────────────────────────────────

/// A Transaction represents a single transfer request (one or many files).
/// There is exactly one Transaction per transfer request.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Transaction {
    /// Unique transaction ID.
    pub id: Uuid,
    /// Current state of the transaction.
    pub state: TransactionState,
    /// Direction: are we sending or receiving?
    pub direction: TransactionDirection,
    /// Peer ID of the remote participant.
    pub peer_id: String,
    /// Display label (folder name or single filename).
    pub display_name: String,
    /// Parent directory name, if a folder transfer.
    pub parent_dir: Option<String>,
    /// Total aggregated size of all files (bytes).
    pub total_size: u64,
    /// Per-file tracking.
    pub files: HashMap<Uuid, TransactionFile>,
    /// Ordered list of file IDs (preserves insertion order for sending).
    pub file_order: Vec<Uuid>,
    /// Destination path (receiver side).
    pub dest_path: Option<PathBuf>,
    /// Local source path (sender side, for outbound transfers).
    pub source_path: Option<PathBuf>,
    /// When the transaction reached a terminal state (if ever).
    pub finished_at: Option<Instant>,
    /// Rejection reason (if rejected).
    pub reject_reason: Option<String>,
    /// Number of resume attempts.
    pub resume_count: u32,
}

impl Transaction {
    /// Create a new outbound transaction (sending to peer).
    pub fn new_outbound(
        peer_id: String,
        display_name: String,
        parent_dir: Option<String>,
        files: Vec<(String, u64)>, // (relative_path, filesize)
    ) -> Self {
        let id = Uuid::new_v4();
        let total_size: u64 = files.iter().map(|(_, s)| *s).sum();
        let mut file_map = HashMap::new();
        let mut file_order = Vec::new();

        for (rel_path, filesize) in files {
            let file_id = Uuid::new_v4();
            file_map.insert(
                file_id,
                TransactionFile::new(file_id, rel_path, filesize),
            );
            file_order.push(file_id);
        }

        Self {
            id,
            state: TransactionState::Pending,
            direction: TransactionDirection::Outbound,
            peer_id,
            display_name,
            parent_dir,
            total_size,
            files: file_map,
            file_order,
            dest_path: None,
            source_path: None,
            finished_at: None,
            reject_reason: None,
            resume_count: 0,
        }
    }

    /// Create a new inbound transaction (receiving from peer).
    pub fn new_inbound(
        transaction_id: Uuid,
        peer_id: String,
        display_name: String,
        parent_dir: Option<String>,
        total_size: u64,
        manifest: &TransactionManifest,
    ) -> Self {
        let mut file_map = HashMap::new();
        let mut file_order = Vec::new();

        for entry in &manifest.files {
            // Use the file_id from the manifest so sender and receiver
            // share the same identifiers for ACK / resume.
            let file_id = entry.file_id;
            file_map.insert(
                file_id,
                TransactionFile::new(file_id, entry.relative_path.clone(), entry.filesize),
            );
            file_order.push(file_id);
        }

        Self {
            id: transaction_id,
            state: TransactionState::Pending,
            direction: TransactionDirection::Inbound,
            peer_id,
            display_name,
            parent_dir,
            total_size,
            files: file_map,
            file_order,
            dest_path: None,
            source_path: None,
            finished_at: None,
            reject_reason: None,
            resume_count: 0,
        }
    }

    // ── State transitions ────────────────────────────────────────────────

    /// Transition to Active state (transfer accepted and started).
    pub fn activate(&mut self) {
        if self.state == TransactionState::Pending || self.state == TransactionState::Interrupted {
            self.state = TransactionState::Active;
        }
    }

    /// Mark the transaction as rejected.
    pub fn reject(&mut self, reason: Option<String>) {
        self.state = TransactionState::Rejected;
        self.reject_reason = reason;
        self.finished_at = Some(Instant::now());
    }

    /// Mark the transaction as cancelled.
    pub fn cancel(&mut self) {
        if !self.state.is_terminal() {
            self.state = TransactionState::Cancelled;
            self.finished_at = Some(Instant::now());
        }
    }

    /// Mark the transaction as failed.
    #[allow(dead_code)]
    pub fn fail(&mut self, reason: Option<String>) {
        if !self.state.is_terminal() {
            self.state = TransactionState::Failed;
            self.reject_reason = reason;
            self.finished_at = Some(Instant::now());
        }
    }

    /// Whether the transaction is currently active.
    #[allow(dead_code)]
    pub fn is_active(&self) -> bool {
        self.state == TransactionState::Active
    }

    /// Mark the transaction as interrupted (eligible for resume).
    pub fn interrupt(&mut self) {
        if self.state == TransactionState::Active {
            self.state = TransactionState::Interrupted;
        }
    }

    /// Check if all files are completed and transition to Completed.
    pub fn check_completion(&mut self) -> bool {
        if self.state != TransactionState::Active {
            return false;
        }
        let all_done = self.files.values().all(|f| f.completed);
        if all_done {
            self.state = TransactionState::Completed;
            self.finished_at = Some(Instant::now());
        }
        all_done
    }

    // ── File-level operations ────────────────────────────────────────────

    /// Update chunk progress for a specific file.
    pub fn update_file_progress(&mut self, file_id: Uuid, transferred_chunks: u32) {
        if let Some(file) = self.files.get_mut(&file_id) {
            file.transferred_chunks = transferred_chunks;
        }
    }

    /// Mark a file as completed within this transaction.
    pub fn complete_file(&mut self, file_id: Uuid, verified: bool) {
        if let Some(file) = self.files.get_mut(&file_id) {
            file.completed = true;
            file.verified = Some(verified);
            file.transferred_chunks = file.total_chunks;
        }
    }

    /// Overall progress as chunks: (transferred, total).
    pub fn progress_chunks(&self) -> (u32, u32) {
        let transferred: u32 = self.files.values().map(|f| f.transferred_chunks).sum();
        let total: u32 = self.files.values().map(|f| f.total_chunks).sum();
        (transferred, total)
    }

    /// Number of completed files.
    pub fn completed_file_count(&self) -> u32 {
        self.files.values().filter(|f| f.completed).count() as u32
    }

    /// Total number of files.
    pub fn total_file_count(&self) -> u32 {
        self.files.len() as u32
    }

    // ── Resume support ───────────────────────────────────────────────────

    /// Apply resume info from the receiver: mark completed files as done.
    pub fn apply_resume_info(&mut self, info: &ResumeInfo) {
        self.resume_count += 1;

        for (file_id, file) in &mut self.files {
            if info.completed_files.contains(file_id) {
                file.completed = true;
                file.transferred_chunks = file.total_chunks;
                file.verified = Some(true);
            } else if let Some(&offset) = info.partial_offsets.get(file_id) {
                let chunk_size: u64 = 48 * 1024;
                file.transferred_chunks = (offset / chunk_size) as u32;
            }
        }

        self.state = TransactionState::Active;
    }

    // ── Manifest generation ──────────────────────────────────────────────

    /// Build a manifest for this transaction (used in the transfer request).
    pub fn build_manifest(&self) -> TransactionManifest {
        let files: Vec<ManifestEntry> = self
            .file_order
            .iter()
            .filter_map(|id| self.files.get(id))
            .map(|f| ManifestEntry {
                file_id: f.file_id,
                relative_path: f.relative_path.clone(),
                filesize: f.filesize,
            })
            .collect();

        TransactionManifest {
            files,
            parent_dir: self.parent_dir.clone(),
        }
    }
}

// ── Transaction Manager ──────────────────────────────────────────────────────

/// Manages all active and historical transactions.
#[derive(Debug, Clone)]
pub struct TransactionManager {
    /// Active transactions (not yet in terminal state).
    pub active: HashMap<Uuid, Transaction>,
    /// Historical transactions (completed, rejected, failed, cancelled).
    pub history: Vec<Transaction>,
    /// Lookup: file_id -> transaction_id.
    pub file_to_transaction: HashMap<Uuid, Uuid>,
}

impl TransactionManager {
    pub fn new() -> Self {
        Self {
            active: HashMap::new(),
            history: Vec::new(),
            file_to_transaction: HashMap::new(),
        }
    }

    /// Insert a new transaction.
    pub fn insert(&mut self, txn: Transaction) {
        let txn_id = txn.id;
        for file_id in &txn.file_order {
            self.file_to_transaction.insert(*file_id, txn_id);
        }
        self.active.insert(txn_id, txn);
    }

    /// Get a transaction by ID (active or history).
    pub fn get(&self, id: &Uuid) -> Option<&Transaction> {
        self.active.get(id).or_else(|| {
            self.history.iter().find(|t| t.id == *id)
        })
    }

    /// Get a mutable reference to an active transaction.
    pub fn get_active_mut(&mut self, id: &Uuid) -> Option<&mut Transaction> {
        self.active.get_mut(id)
    }

    /// Find the transaction that owns a given file_id.
    /// Find a mutable transaction that owns a given file_id.
    pub fn find_by_file_mut(&mut self, file_id: &Uuid) -> Option<&mut Transaction> {
        if let Some(txn_id) = self.file_to_transaction.get(file_id).copied() {
            self.active.get_mut(&txn_id)
        } else {
            None
        }
    }

    /// Get the transaction ID for a file ID.
    pub fn transaction_id_for_file(&self, file_id: &Uuid) -> Option<Uuid> {
        self.file_to_transaction.get(file_id).copied()
    }

    /// Move a transaction from active to history.
    pub fn archive(&mut self, id: &Uuid) {
        if let Some(txn) = self.active.remove(id) {
            // Clean up file mappings for completed files
            for file_id in &txn.file_order {
                self.file_to_transaction.remove(file_id);
            }
            self.history.push(txn);
        }
    }

    /// Remove all transactions for a disconnected peer, marking them as interrupted.
    pub fn interrupt_peer(&mut self, peer_id: &str) {
        for txn in self.active.values_mut() {
            if txn.peer_id == peer_id && !txn.state.is_terminal() {
                txn.interrupt();
            }
        }
    }

    /// Get all rejected transactions (from history + active).
    pub fn rejected(&self) -> Vec<&Transaction> {
        let mut result: Vec<&Transaction> = self
            .active
            .values()
            .filter(|t| t.state == TransactionState::Rejected)
            .collect();
        result.extend(
            self.history
                .iter()
                .filter(|t| t.state == TransactionState::Rejected),
        );
        result
    }

    /// Total count of active (non-terminal) transactions.
    pub fn active_count(&self) -> usize {
        self.active
            .values()
            .filter(|t| !t.state.is_terminal())
            .count()
    }
}

impl Default for TransactionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Serializable Transaction State (for persistence) ─────────────────────────

/// Serializable version of a Transaction for persistence/resume across restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSnapshot {
    pub id: Uuid,
    pub state: TransactionState,
    pub direction: TransactionDirection,
    pub peer_id: String,
    pub display_name: String,
    pub parent_dir: Option<String>,
    pub total_size: u64,
    pub files: Vec<TransactionFileSnapshot>,
    pub dest_path: Option<PathBuf>,
    pub reject_reason: Option<String>,
    pub resume_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionFileSnapshot {
    pub file_id: Uuid,
    pub relative_path: String,
    pub filesize: u64,
    pub total_chunks: u32,
    pub transferred_chunks: u32,
    pub completed: bool,
    pub verified: Option<bool>,
}
