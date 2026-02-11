//! Transaction-based file transfer system.
//!
//! A Transaction represents one transfer request (file or folder), regardless of
//! the number of files involved. It owns:
//! - State management (lifecycle transitions)
//! - Progress calculation (aggregated over all files)
//! - ACK / resume / cancellation logic
//! - Control-channel coordination
//! - Secure manifest integration (cryptographic signing, Merkle roots)
//! - Chunk bitmap tracking for resume
//! - Replay protection via monotonic counters
//!
//! There is exactly one Transaction per transfer request.

use crate::core::pipeline::chunk::ChunkBitmap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;
use uuid::Uuid;

/// Canonical chunk size in bytes. Must match the constant in webrtc.rs.
/// Every module that computes total_chunks or byte offsets MUST use this.
pub const CHUNK_SIZE: usize = 48 * 1024;

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
    /// Transfer paused and persisted, eligible for resume with security state.
    Resumable,
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
    /// Chunk completion bitmap for resume support.
    #[serde(skip)]
    #[allow(dead_code)]
    pub chunk_bitmap: Option<ChunkBitmap>,
    /// Merkle root for integrity verification.
    #[serde(default)]
    pub merkle_root: Option<[u8; 32]>,
}

impl TransactionFile {
    pub fn new(file_id: Uuid, relative_path: String, filesize: u64) -> Self {
        let total_chunks = ((filesize as f64) / (CHUNK_SIZE as f64)).ceil().max(1.0) as u32;
        Self {
            file_id,
            relative_path,
            filesize,
            total_chunks,
            transferred_chunks: 0,
            completed: false,
            verified: None,
            chunk_bitmap: Some(ChunkBitmap::new(total_chunks)),
            merkle_root: None,
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
    /// Merkle root of all chunk hashes (for integrity verification).
    #[serde(default)]
    pub merkle_root: Option<[u8; 32]>,
    /// Total number of chunks.
    #[serde(default)]
    pub total_chunks: Option<u32>,
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
    /// Per-file chunk bitmaps for precise resume (serialized).
    #[serde(default)]
    pub chunk_bitmaps: HashMap<Uuid, Vec<u8>>,
    /// HMAC for resume request authentication.
    #[serde(default)]
    pub hmac: Option<[u8; 32]>,
    /// Receiver's signature on this resume request.
    #[serde(default)]
    pub receiver_signature: Option<[u8; 32]>,
}

// ── Transaction ──────────────────────────────────────────────────────────────

/// A Transaction represents a single transfer request (one or many files).
/// There is exactly one Transaction per transfer request.
#[derive(Debug, Clone)]
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
            finished_at: None,
            reject_reason: None,
            resume_count: 0,
        }
    }

    // ── State transitions ────────────────────────────────────────────────

    /// Transition to Active state (transfer accepted and started).
    pub fn activate(&mut self) {
        if self.state == TransactionState::Pending
            || self.state == TransactionState::Interrupted
            || self.state == TransactionState::Resumable
        {
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

    /// Mark the transaction as interrupted (eligible for resume).
    pub fn interrupt(&mut self) {
        if self.state == TransactionState::Active {
            self.state = TransactionState::Interrupted;
        }
    }

    /// Mark the transaction as resumable (persisted state).
    #[allow(dead_code)]
    pub fn make_resumable(&mut self) {
        if self.state == TransactionState::Active || self.state == TransactionState::Interrupted {
            self.state = TransactionState::Resumable;
        }
    }

    /// Mark a specific chunk as received for a file.
    #[allow(dead_code)]
    pub fn mark_chunk_received(&mut self, file_id: Uuid, chunk_index: u32) {
        if let Some(file) = self.files.get_mut(&file_id) {
            if let Some(ref mut bitmap) = file.chunk_bitmap {
                if !bitmap.is_set(chunk_index) {
                    bitmap.set(chunk_index);
                    file.transferred_chunks = bitmap.received_count();
                }
            }
        }
    }

    /// Get missing chunks for a file.
    #[allow(dead_code)]
    pub fn missing_chunks(&self, file_id: &Uuid) -> Vec<u32> {
        self.files
            .get(file_id)
            .and_then(|f| f.chunk_bitmap.as_ref())
            .map(|bm| bm.missing_chunks())
            .unwrap_or_default()
    }

    /// Build a resume info from the current transaction state.
    #[allow(dead_code)]
    pub fn build_resume_info(&self) -> ResumeInfo {
        let completed_files: Vec<Uuid> = self
            .files
            .values()
            .filter(|f| f.completed)
            .map(|f| f.file_id)
            .collect();

        let partial_offsets: HashMap<Uuid, u64> = self
            .files
            .values()
            .filter(|f| !f.completed)
            .map(|f| (f.file_id, f.transferred_chunks as u64 * CHUNK_SIZE as u64))
            .collect();

        let chunk_bitmaps: HashMap<Uuid, Vec<u8>> = self
            .files
            .values()
            .filter_map(|f| {
                f.chunk_bitmap
                    .as_ref()
                    .map(|bm| (f.file_id, bm.to_bytes()))
            })
            .collect();

        ResumeInfo {
            transaction_id: self.id,
            completed_files,
            partial_offsets,
            partial_checksums: HashMap::new(),
            chunk_bitmaps,
            hmac: None,
            receiver_signature: None,
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
            } else {
                // Reset progress for incomplete files — the sender will
                // re-send ALL chunks from 0 because the receiver's
                // in-memory buffer is lost on reconnect.  Keeping the
                // old transferred_chunks would cause the sender to skip
                // chunks that the receiver no longer has.
                file.transferred_chunks = 0;
            }
        }

        self.state = TransactionState::Active;
    }

    // ── Snapshot (persistence) ─────────────────────────────────────────────

    /// Create a serializable snapshot of this transaction for persistence.
    /// `source_path`: the local source path for outbound transfers.
    pub fn to_snapshot_with_source(&self, source_path: Option<&str>) -> TransactionSnapshot {
        let files: Vec<TransactionFileSnapshot> = self
            .file_order
            .iter()
            .filter_map(|id| self.files.get(id))
            .map(|f| TransactionFileSnapshot {
                file_id: f.file_id,
                relative_path: f.relative_path.clone(),
                filesize: f.filesize,
                total_chunks: f.total_chunks,
                transferred_chunks: f.transferred_chunks,
                completed: f.completed,
                verified: f.verified,
                chunk_bitmap_bytes: f.chunk_bitmap.as_ref().map(|bm| bm.to_bytes()),
                merkle_root: f.merkle_root,
            })
            .collect();

        let manifest = Some(self.build_manifest());

        TransactionSnapshot {
            id: self.id,
            state: self.state,
            direction: self.direction,
            peer_id: self.peer_id.clone(),
            display_name: self.display_name.clone(),
            parent_dir: self.parent_dir.clone(),
            total_size: self.total_size,
            files,
            dest_path: self.dest_path.clone(),
            reject_reason: self.reject_reason.clone(),
            resume_count: self.resume_count,
            expiration_time: None,
            last_counter: None,
            source_path: source_path.map(|s| s.to_string()),
            manifest,
        }
    }

    /// Create a serializable snapshot (convenience, no source_path).
    pub fn to_snapshot(&self) -> TransactionSnapshot {
        self.to_snapshot_with_source(None)
    }

    /// Restore a Transaction from a persisted snapshot.
    pub fn from_snapshot(snap: &TransactionSnapshot) -> Self {
        let mut file_map = HashMap::new();
        let mut file_order = Vec::new();

        for fs in &snap.files {
            let bitmap = fs
                .chunk_bitmap_bytes
                .as_ref()
                .and_then(|b| ChunkBitmap::from_bytes(b))
                .unwrap_or_else(|| {
                    let mut bm = ChunkBitmap::new(fs.total_chunks);
                    // Mark already-transferred chunks as received
                    for i in 0..fs.transferred_chunks {
                        bm.set(i);
                    }
                    bm
                });

            let tf = TransactionFile {
                file_id: fs.file_id,
                relative_path: fs.relative_path.clone(),
                filesize: fs.filesize,
                total_chunks: fs.total_chunks,
                transferred_chunks: fs.transferred_chunks,
                completed: fs.completed,
                verified: fs.verified,
                chunk_bitmap: Some(bitmap),
                merkle_root: fs.merkle_root,
            };
            file_map.insert(fs.file_id, tf);
            file_order.push(fs.file_id);
        }

        Self {
            id: snap.id,
            state: snap.state,
            direction: snap.direction,
            peer_id: snap.peer_id.clone(),
            display_name: snap.display_name.clone(),
            parent_dir: snap.parent_dir.clone(),
            total_size: snap.total_size,
            files: file_map,
            file_order,
            dest_path: snap.dest_path.clone(),
            finished_at: None,
            reject_reason: snap.reject_reason.clone(),
            resume_count: snap.resume_count,
        }
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
                merkle_root: f.merkle_root,
                total_chunks: Some(f.total_chunks),
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
    /// Transaction expiration time (Unix timestamp seconds).
    #[serde(default)]
    pub expiration_time: Option<u64>,
    /// Last replay counter seen.
    #[serde(default)]
    pub last_counter: Option<u64>,
    /// Source path for outbound transfers (absolute path on sender's disk).
    #[serde(default)]
    pub source_path: Option<String>,
    /// Manifest snapshot for the transaction (immutable after creation).
    #[serde(default)]
    pub manifest: Option<TransactionManifest>,
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
    /// Serialized chunk bitmap for resume.
    #[serde(default)]
    pub chunk_bitmap_bytes: Option<Vec<u8>>,
    /// Merkle root for integrity verification.
    #[serde(default)]
    pub merkle_root: Option<[u8; 32]>,
}
