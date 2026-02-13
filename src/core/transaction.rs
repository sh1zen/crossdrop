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

pub use crate::core::config::CHUNK_SIZE;
use crate::core::pipeline::chunk::ChunkBitmap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;
use uuid::Uuid;

/// Compute the total number of chunks for a file of the given size.
///
/// This is the **single source of truth** for chunk count computation.
/// All modules MUST use this instead of duplicating the formula.
///
/// Invariant: always returns at least 1 (even for zero-size files).
#[inline]
pub fn compute_total_chunks(file_size: u64) -> u32 {
    ((file_size as f64) / (CHUNK_SIZE as f64)).ceil().max(1.0) as u32
}

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
    pub chunk_bitmap: Option<ChunkBitmap>,
    /// Merkle root for integrity verification.
    #[serde(default)]
    pub merkle_root: Option<[u8; 32]>,
    /// Numero di richieste di ritrasmissione per questo file.
    pub retransmit_count: u32,
}

impl TransactionFile {
    pub fn new(file_id: Uuid, relative_path: String, filesize: u64) -> Self {
        let total_chunks = compute_total_chunks(filesize);
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
            retransmit_count: 0,
        }
    }
}

// ── Transaction Manifest (sent over the wire) ────────────────────────────────

/// The file manifest sent from sender to receiver as part of the transfer request.
///
/// Includes cryptographic security fields: the sender signs the manifest
/// content and the receiver validates the signature before ACK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionManifest {
    /// List of files in this transaction with relative paths and sizes.
    pub files: Vec<ManifestEntry>,
    /// Parent directory name, if this is a folder transfer.
    pub parent_dir: Option<String>,
    /// Sender's public key (identity).
    #[serde(default)]
    pub sender_id: Option<[u8; 32]>,
    /// HMAC signature over manifest content by the sender.
    #[serde(default)]
    pub signature: Option<[u8; 32]>,
    /// Per-session nonce seed for deterministic nonce derivation.
    #[serde(default)]
    pub nonce_seed: Option<[u8; 32]>,
    /// Manifest expiration time (Unix timestamp seconds).
    #[serde(default)]
    pub expiration_time: Option<u64>,
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
    /// Timestamp when the transaction was last activated via resume.
    /// Used to prevent `handle_peer_reconnected` from re-interrupting a
    /// transfer that was just resumed (race between data-channel resume
    /// messages and the PeerConnected event).
    pub resumed_at: Option<Instant>,
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
            file_map.insert(file_id, TransactionFile::new(file_id, rel_path, filesize));
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
            resumed_at: None,
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
            let mut tf = TransactionFile::new(file_id, entry.relative_path.clone(), entry.filesize);
            // Copy Merkle root from manifest for integrity verification on receive
            tf.merkle_root = entry.merkle_root;
            file_map.insert(file_id, tf);
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
            resumed_at: None,
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
    pub fn make_resumable(&mut self) {
        if self.state == TransactionState::Active || self.state == TransactionState::Interrupted {
            self.state = TransactionState::Resumable;
        }
    }

    /// Build a resume info from the current transaction state.
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
            .filter_map(|f| f.chunk_bitmap.as_ref().map(|bm| (f.file_id, bm.to_bytes())))
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

    /// Update chunk progress for a specific file and mark chunks as sent in bitmap.
    /// This is used by the sender to track which chunks have been sent.
    pub fn update_file_progress_sent(&mut self, file_id: Uuid, sent_chunks: u32) {
        if let Some(file) = self.files.get_mut(&file_id) {
            file.transferred_chunks = sent_chunks;
            // Mark chunks 0..sent_chunks as sent in the bitmap
            if let Some(ref mut bitmap) = file.chunk_bitmap {
                // Only mark chunks that aren't already marked
                for i in file.transferred_chunks..sent_chunks {
                    bitmap.set(i);
                }
            }
        }
    }

    /// Update chunk progress for a specific file and sync the bitmap from receiver.
    pub fn update_file_progress_with_bitmap(
        &mut self,
        file_id: Uuid,
        transferred_chunks: u32,
        bitmap_bytes: Option<&[u8]>,
    ) {
        if let Some(file) = self.files.get_mut(&file_id) {
            file.transferred_chunks = transferred_chunks;
            // Sync bitmap from receiver if provided
            if let Some(bytes) = bitmap_bytes {
                if let Some(bitmap) = ChunkBitmap::from_bytes(bytes) {
                    file.chunk_bitmap = Some(bitmap);
                }
            }
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

    /// Validate a resume request against the transaction's current state.
    ///
    /// Checks:
    /// 1. Transaction is in a resumable state (Active, Interrupted, or Resumable).
    /// 2. Transaction is outbound (we are the sender; receiver drives resume).
    /// 3. Retry limit has not been exceeded.
    /// 4. All referenced file_ids exist in the transaction manifest.
    ///
    /// Returns `Ok(())` if valid, `Err(reason)` if the request must be rejected.
    pub fn validate_resume_request(
        &self,
        resume_info: &ResumeInfo,
        max_retries: u32,
    ) -> Result<(), &'static str> {
        // State check: must be in a resumable-compatible state
        if self.state != TransactionState::Resumable
            && self.state != TransactionState::Interrupted
            && self.state != TransactionState::Active
        {
            return Err("Invalid transaction state for resume");
        }

        // Direction check: only outbound transactions accept resume requests
        if self.direction != TransactionDirection::Outbound {
            return Err("Resume rejected: wrong direction");
        }

        // Retry limit
        if self.resume_count >= max_retries {
            return Err("Resume rejected: retry limit exceeded");
        }

        // Manifest integrity: all referenced file_ids must exist
        for file_id in &resume_info.completed_files {
            if !self.files.contains_key(file_id) {
                return Err("Resume rejected: unknown file in request");
            }
        }
        for file_id in resume_info.partial_offsets.keys() {
            if !self.files.contains_key(file_id) {
                return Err("Resume rejected: unknown file in request");
            }
        }

        Ok(())
    }

    /// Apply resume info from the receiver: mark completed files as done,
    /// and preserve partial progress for incomplete files so the sender
    /// can skip already-received chunks.
    pub fn apply_resume_info(&mut self, info: &ResumeInfo) {
        self.resume_count += 1;

        for (file_id, file) in &mut self.files {
            if info.completed_files.contains(file_id) {
                file.completed = true;
                file.transferred_chunks = file.total_chunks;
                file.verified = Some(true);
            } else {
                // Reset `completed` because a prior SendComplete{success:false}
                // (fired when the connection drops mid-send) marks the file as
                // completed even though it was never fully transferred.
                file.completed = false;
                file.verified = None;

                // Restore chunk bitmap from the resume info if available.
                // This allows the sender to skip already-received chunks
                // instead of re-sending the entire file.
                if let Some(bitmap_bytes) = info.chunk_bitmaps.get(file_id) {
                    if let Some(bitmap) = ChunkBitmap::from_bytes(bitmap_bytes) {
                        // Count received chunks from the bitmap
                        let mut count = 0u32;
                        for i in 0..file.total_chunks {
                            if bitmap.is_set(i) {
                                count += 1;
                            }
                        }
                        file.transferred_chunks = count;
                        file.chunk_bitmap = Some(bitmap);
                    } else {
                        // Invalid bitmap — reset to 0
                        file.transferred_chunks = 0;
                        if let Some(ref mut bitmap) = file.chunk_bitmap {
                            *bitmap = ChunkBitmap::new(file.total_chunks);
                        }
                    }
                } else {
                    // No bitmap in resume info — reset to 0
                    file.transferred_chunks = 0;
                    if let Some(ref mut bitmap) = file.chunk_bitmap {
                        *bitmap = ChunkBitmap::new(file.total_chunks);
                    }
                }
            }
        }

        self.state = TransactionState::Active;
        self.resumed_at = Some(Instant::now());
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
                retransmit_count: f.retransmit_count,
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
            interrupted_at: if self.state == TransactionState::Resumable 
                || self.state == TransactionState::Interrupted {
                Some(std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs())
            } else {
                None
            },
            last_counter: None,
            source_path: source_path.map(|s| s.to_string()),
            manifest,
        }
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
                retransmit_count: fs.retransmit_count,
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
            resumed_at: None,
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
            sender_id: None,
            signature: None,
            nonce_seed: None,
            expiration_time: None,
        }
    }

    /// Compute the canonical bytes used for manifest signing.
    /// Covers all content except the signature itself.
    pub fn manifest_content_bytes(manifest: &TransactionManifest) -> Vec<u8> {
        let mut data = Vec::new();
        if let Some(ref pd) = manifest.parent_dir {
            data.extend_from_slice(pd.as_bytes());
        }
        if let Some(ref sender) = manifest.sender_id {
            data.extend_from_slice(sender);
        }
        if let Some(ref seed) = manifest.nonce_seed {
            data.extend_from_slice(seed);
        }
        if let Some(exp) = manifest.expiration_time {
            data.extend_from_slice(&exp.to_be_bytes());
        }
        for f in &manifest.files {
            data.extend_from_slice(f.file_id.as_bytes());
            data.extend_from_slice(f.relative_path.as_bytes());
            data.extend_from_slice(&f.filesize.to_be_bytes());
            if let Some(tc) = f.total_chunks {
                data.extend_from_slice(&tc.to_be_bytes());
            }
            if let Some(ref mr) = f.merkle_root {
                data.extend_from_slice(mr);
            }
        }
        data
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
        self.active
            .get(id)
            .or_else(|| self.history.iter().find(|t| t.id == *id))
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

    /// Count of transactions currently transferring data (state == Active).
    /// Pending, Interrupted, and Resumable transactions do NOT count,
    /// so they don't block new transfers from starting.
    pub fn active_count(&self) -> usize {
        self.active
            .values()
            .filter(|t| t.state == TransactionState::Active)
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
    /// Timestamp when the transaction became resumable (Unix timestamp seconds).
    /// Used to determine if the transaction has expired.
    #[serde(default)]
    pub interrupted_at: Option<u64>,
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

impl TransactionSnapshot {
    /// Check if this transaction has expired.
    /// A transaction is expired if:
    /// 1. It's in Resumable or Interrupted state
    /// 2. The expiration_time has passed (if set)
    /// 3. Or 24 hours have passed since interrupted_at
    pub fn is_expired(&self) -> bool {
        if self.state != TransactionState::Resumable 
            && self.state != TransactionState::Interrupted {
            return false;
        }
        
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Check explicit expiration time
        if let Some(exp) = self.expiration_time {
            if now >= exp {
                return true;
            }
        }
        
        // Check 24-hour default expiration from interrupted_at
        if let Some(interrupted) = self.interrupted_at {
            const EXPIRY_SECS: u64 = 24 * 3600; // 24 hours
            if now >= interrupted + EXPIRY_SECS {
                return true;
            }
        }
        
        false
    }
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
    /// Number of retransmission attempts for this file.
    #[serde(default)]
    pub retransmit_count: u32,
}
