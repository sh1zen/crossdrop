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

// ── Chunk count helper ───────────────────────────────────────────────────────

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
    /// Peer accepted the transfer — files are being sent.
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
    #[inline]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Rejected | Self::Cancelled | Self::Failed
        )
    }

    /// Returns true if the state allows a resume request to be accepted.
    #[inline]
    pub fn is_resumable(self) -> bool {
        matches!(self, Self::Active | Self::Interrupted | Self::Resumable)
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
    pub file_id: Uuid,
    /// Relative path (for folders) or filename (for single file).
    pub relative_path: String,
    /// Full absolute path to the source file (for outbound) or destination (for inbound).
    /// Persisted for crash-resilient resume support.
    #[serde(default)]
    pub full_path: Option<String>,
    pub filesize: u64,
    pub total_chunks: u32,
    pub transferred_chunks: u32,
    pub completed: bool,
    /// Some(true) = verified OK, Some(false) = integrity failure, None = not checked yet.
    pub verified: Option<bool>,
    /// Chunk completion bitmap for resume support.
    #[serde(skip)]
    pub chunk_bitmap: Option<ChunkBitmap>,
    /// Merkle root for integrity verification.
    #[serde(default)]
    pub merkle_root: Option<[u8; 32]>,
    pub retransmit_count: u32,
}

impl TransactionFile {
    pub fn new(file_id: Uuid, relative_path: String, filesize: u64) -> Self {
        let total_chunks = compute_total_chunks(filesize);
        Self {
            file_id,
            relative_path,
            full_path: None,
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

    /// Mark this file as fully transferred and optionally verified.
    #[inline]
    pub fn mark_complete(&mut self, verified: bool) {
        self.completed = true;
        self.verified = Some(verified);
        self.transferred_chunks = self.total_chunks;
    }

    /// Reset partial progress (used when resume info has no bitmap for this file).
    fn reset_progress(&mut self) {
        self.completed = false;
        self.verified = None;
        self.transferred_chunks = 0;
        if let Some(ref mut bm) = self.chunk_bitmap {
            *bm = ChunkBitmap::new(self.total_chunks);
        }
    }
}

// ── Transaction Manifest (sent over the wire) ────────────────────────────────

/// The file manifest sent from sender to receiver as part of the transfer request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionManifest {
    pub files: Vec<ManifestEntry>,
    pub parent_dir: Option<String>,
    #[serde(default)]
    pub sender_id: Option<[u8; 32]>,
    #[serde(default)]
    pub signature: Option<[u8; 32]>,
    #[serde(default)]
    pub nonce_seed: Option<[u8; 32]>,
    #[serde(default)]
    pub expiration_time: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub file_id: Uuid,
    pub relative_path: String,
    pub filesize: u64,
    #[serde(default)]
    pub merkle_root: Option<[u8; 32]>,
    #[serde(default)]
    pub total_chunks: Option<u32>,
}

// ── Resume info ──────────────────────────────────────────────────────────────

/// Sent by the receiver when requesting a resume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeInfo {
    pub transaction_id: Uuid,
    pub completed_files: Vec<Uuid>,
    pub partial_offsets: HashMap<Uuid, u64>,
    pub partial_checksums: HashMap<Uuid, Vec<u8>>,
    #[serde(default)]
    pub chunk_bitmaps: HashMap<Uuid, Vec<u8>>,
    #[serde(default)]
    pub hmac: Option<[u8; 32]>,
    #[serde(default)]
    pub receiver_signature: Option<[u8; 32]>,
}

// ── Resume validation error ──────────────────────────────────────────────────

/// Reason a resume request was rejected. A dedicated type avoids magic strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeRejectReason {
    InvalidState,
    WrongDirection,
    RetryLimitExceeded,
    UnknownFile,
}

impl ResumeRejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidState => "Invalid transaction state for resume",
            Self::WrongDirection => "Resume rejected: wrong direction",
            Self::RetryLimitExceeded => "Resume rejected: retry limit exceeded",
            Self::UnknownFile => "Resume rejected: unknown file in request",
        }
    }
}

impl std::fmt::Display for ResumeRejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Transaction ──────────────────────────────────────────────────────────────

/// A Transaction represents a single transfer request (one or many files).
#[derive(Debug, Clone)]
pub struct Transaction {
    pub id: Uuid,
    pub state: TransactionState,
    pub direction: TransactionDirection,
    pub peer_id: String,
    pub display_name: String,
    pub parent_dir: Option<String>,
    pub total_size: u64,
    pub files: HashMap<Uuid, TransactionFile>,
    /// Ordered list of file IDs (preserves insertion order for sending).
    pub file_order: Vec<Uuid>,
    pub dest_path: Option<PathBuf>,
    pub finished_at: Option<Instant>,
    pub reject_reason: Option<String>,
    pub resume_count: u32,
    /// Timestamp of the last resume activation. Guards against the
    /// `handle_peer_reconnected` race that could re-interrupt a live transfer.
    pub resumed_at: Option<Instant>,
}

impl Transaction {
    // ── Constructors ─────────────────────────────────────────────────────

    /// Create a new outbound transaction (we are the sender).
    pub fn new_outbound(
        peer_id: String,
        display_name: String,
        parent_dir: Option<String>,
        files: Vec<(String, u64)>,
    ) -> Self {
        let total_size = files.iter().map(|(_, s)| s).sum();
        let (file_map, file_order) = Self::build_file_map_outbound(files);
        Self::new_inner(
            Uuid::new_v4(),
            TransactionDirection::Outbound,
            peer_id,
            display_name,
            parent_dir,
            total_size,
            file_map,
            file_order,
        )
    }

    /// Create a new inbound transaction (we are the receiver).
    pub fn new_inbound(
        transaction_id: Uuid,
        peer_id: String,
        display_name: String,
        parent_dir: Option<String>,
        total_size: u64,
        manifest: &TransactionManifest,
    ) -> Self {
        let (file_map, file_order) = Self::build_file_map_inbound(manifest);
        Self::new_inner(
            transaction_id,
            TransactionDirection::Inbound,
            peer_id,
            display_name,
            parent_dir,
            total_size,
            file_map,
            file_order,
        )
    }

    fn new_inner(
        id: Uuid,
        direction: TransactionDirection,
        peer_id: String,
        display_name: String,
        parent_dir: Option<String>,
        total_size: u64,
        files: HashMap<Uuid, TransactionFile>,
        file_order: Vec<Uuid>,
    ) -> Self {
        Self {
            id,
            state: TransactionState::Pending,
            direction,
            peer_id,
            display_name,
            parent_dir,
            total_size,
            files,
            file_order,
            dest_path: None,
            finished_at: None,
            reject_reason: None,
            resume_count: 0,
            resumed_at: None,
        }
    }

    fn build_file_map_outbound(
        files: Vec<(String, u64)>,
    ) -> (HashMap<Uuid, TransactionFile>, Vec<Uuid>) {
        let mut map = HashMap::with_capacity(files.len());
        let mut order = Vec::with_capacity(files.len());
        for (rel_path, filesize) in files {
            let file_id = Uuid::new_v4();
            map.insert(file_id, TransactionFile::new(file_id, rel_path, filesize));
            order.push(file_id);
        }
        (map, order)
    }

    fn build_file_map_inbound(
        manifest: &TransactionManifest,
    ) -> (HashMap<Uuid, TransactionFile>, Vec<Uuid>) {
        let mut map = HashMap::with_capacity(manifest.files.len());
        let mut order = Vec::with_capacity(manifest.files.len());
        for entry in &manifest.files {
            let mut tf =
                TransactionFile::new(entry.file_id, entry.relative_path.clone(), entry.filesize);
            tf.merkle_root = entry.merkle_root;
            map.insert(entry.file_id, tf);
            order.push(entry.file_id);
        }
        (map, order)
    }

    // ── State transitions ────────────────────────────────────────────────

    /// Transition to Active state (accepted and started).
    pub fn activate(&mut self) {
        if matches!(
            self.state,
            TransactionState::Pending | TransactionState::Interrupted | TransactionState::Resumable
        ) {
            self.state = TransactionState::Active;
        }
    }

    pub fn reject(&mut self, reason: Option<String>) {
        self.state = TransactionState::Rejected;
        self.reject_reason = reason;
        self.finished_at = Some(Instant::now());
    }

    pub fn cancel(&mut self) {
        if !self.state.is_terminal() {
            self.state = TransactionState::Cancelled;
            self.finished_at = Some(Instant::now());
        }
    }

    pub fn interrupt(&mut self) {
        if self.state == TransactionState::Active {
            self.state = TransactionState::Interrupted;
        }
    }

    pub fn make_resumable(&mut self) {
        if matches!(
            self.state,
            TransactionState::Active | TransactionState::Interrupted
        ) {
            self.state = TransactionState::Resumable;
        }
    }

    // ── File-level operations ────────────────────────────────────────────

    /// Update sent-chunk progress and mark chunks as sent in the bitmap.
    pub fn update_file_progress_sent(&mut self, file_id: Uuid, sent_chunks: u32) {
        if let Some(f) = self.files.get_mut(&file_id) {
            let prev = f.transferred_chunks;
            f.transferred_chunks = sent_chunks;
            if let Some(ref mut bm) = f.chunk_bitmap {
                for i in prev..sent_chunks {
                    bm.set(i);
                }
            }
        }
    }

    /// Update received-chunk progress and optionally sync the bitmap from receiver.
    pub fn update_file_progress_with_bitmap(
        &mut self,
        file_id: Uuid,
        transferred_chunks: u32,
        bitmap_bytes: Option<&[u8]>,
    ) {
        if let Some(f) = self.files.get_mut(&file_id) {
            f.transferred_chunks = transferred_chunks;
            if let Some(bytes) = bitmap_bytes {
                if let Some(bm) = ChunkBitmap::from_bytes(bytes) {
                    f.chunk_bitmap = Some(bm);
                }
            }
        }
    }

    pub fn complete_file(&mut self, file_id: Uuid, verified: bool) {
        if let Some(f) = self.files.get_mut(&file_id) {
            f.mark_complete(verified);
        }
    }

    /// Check if all files are completed; if so, transition to Completed.
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

    /// Overall progress as `(transferred_chunks, total_chunks)`.
    pub fn progress_chunks(&self) -> (u32, u32) {
        self.files.values().fold((0, 0), |(t, tot), f| {
            (t + f.transferred_chunks, tot + f.total_chunks)
        })
    }

    pub fn completed_file_count(&self) -> u32 {
        self.files.values().filter(|f| f.completed).count() as u32
    }

    pub fn total_file_count(&self) -> u32 {
        self.files.len() as u32
    }

    // ── Resume support ───────────────────────────────────────────────────

    /// Build a resume-info snapshot from the current transaction state.
    pub fn build_resume_info(&self) -> ResumeInfo {
        let completed_files = self
            .files
            .values()
            .filter(|f| f.completed)
            .map(|f| f.file_id)
            .collect();

        let partial_offsets = self
            .files
            .values()
            .filter(|f| !f.completed)
            .map(|f| (f.file_id, f.transferred_chunks as u64 * CHUNK_SIZE as u64))
            .collect();

        let chunk_bitmaps = self
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

    /// Validate a resume request against the transaction's current state.
    pub fn validate_resume_request(
        &self,
        resume_info: &ResumeInfo,
        max_retries: u32,
    ) -> Result<(), ResumeRejectReason> {
        if !self.state.is_resumable() {
            return Err(ResumeRejectReason::InvalidState);
        }
        if self.direction != TransactionDirection::Outbound {
            return Err(ResumeRejectReason::WrongDirection);
        }
        if self.resume_count >= max_retries {
            return Err(ResumeRejectReason::RetryLimitExceeded);
        }
        let unknown = resume_info
            .completed_files
            .iter()
            .chain(resume_info.partial_offsets.keys())
            .any(|id| !self.files.contains_key(id));
        if unknown {
            return Err(ResumeRejectReason::UnknownFile);
        }
        Ok(())
    }

    /// Apply resume info: mark completed files and restore partial progress.
    pub fn apply_resume_info(&mut self, info: &ResumeInfo) {
        self.resume_count += 1;

        for (file_id, f) in &mut self.files {
            if info.completed_files.contains(file_id) {
                f.mark_complete(true);
            } else {
                // Reset `completed` — a prior SendComplete{success:false} on
                // connection drop can falsely mark the file as done.
                f.completed = false;
                f.verified = None;

                match info
                    .chunk_bitmaps
                    .get(file_id)
                    .and_then(|b| ChunkBitmap::from_bytes(b))
                {
                    Some(bm) => {
                        let count = (0..f.total_chunks).filter(|&i| bm.is_set(i)).count() as u32;
                        f.transferred_chunks = count;
                        f.chunk_bitmap = Some(bm);
                    }
                    None => f.reset_progress(),
                }
            }
        }

        self.state = TransactionState::Active;
        self.resumed_at = Some(Instant::now());
    }

    // ── Manifest ─────────────────────────────────────────────────────────

    /// Build a manifest for this transaction (used in the transfer request).
    pub fn build_manifest(&self) -> TransactionManifest {
        let files = self
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

    /// Compute the canonical bytes over manifest fields used for signing.
    /// Covers everything except the `signature` field itself.
    pub fn manifest_content_bytes(manifest: &TransactionManifest) -> Vec<u8> {
        // Pre-estimate capacity to reduce reallocations.
        let est = manifest.files.len() * 64;
        let mut data = Vec::with_capacity(est);

        if let Some(pd) = &manifest.parent_dir {
            data.extend_from_slice(pd.as_bytes());
        }
        if let Some(sid) = &manifest.sender_id {
            data.extend_from_slice(sid);
        }
        if let Some(seed) = &manifest.nonce_seed {
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
            if let Some(mr) = &f.merkle_root {
                data.extend_from_slice(mr);
            }
        }
        data
    }

    // ── Snapshot (persistence) ────────────────────────────────────────────

    /// Create a serializable snapshot of this transaction for persistence.
    pub fn to_snapshot_with_source(&self, source_path: Option<&str>) -> TransactionSnapshot {
        let files = self
            .file_order
            .iter()
            .filter_map(|id| self.files.get(id))
            .map(|f| TransactionFileSnapshot {
                file_id: f.file_id,
                relative_path: f.relative_path.clone(),
                full_path: f.full_path.clone(),
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

        let interrupted_at = self.state.is_resumable().then(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });

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
            interrupted_at,
            last_counter: None,
            source_path: source_path.map(str::to_owned),
            manifest: Some(self.build_manifest()),
        }
    }

    /// Restore a Transaction from a persisted snapshot.
    pub fn from_snapshot(snap: &TransactionSnapshot) -> Self {
        let mut file_map = HashMap::with_capacity(snap.files.len());
        let mut file_order = Vec::with_capacity(snap.files.len());

        for fs in &snap.files {
            let bitmap = fs
                .chunk_bitmap_bytes
                .as_deref()
                .and_then(ChunkBitmap::from_bytes)
                .unwrap_or_else(|| {
                    let mut bm = ChunkBitmap::new(fs.total_chunks);
                    for i in 0..fs.transferred_chunks {
                        bm.set(i);
                    }
                    bm
                });

            let tf = TransactionFile {
                file_id: fs.file_id,
                relative_path: fs.relative_path.clone(),
                full_path: fs.full_path.clone(),
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
}

// ── Transaction Manager ──────────────────────────────────────────────────────

/// Manages all active and historical transactions.
#[derive(Debug, Clone)]
pub struct TransactionManager {
    pub active: HashMap<Uuid, Transaction>,
    pub history: Vec<Transaction>,
    /// Reverse index: file_id → transaction_id, for O(1) lookup.
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

    pub fn insert(&mut self, txn: Transaction) {
        let txn_id = txn.id;
        for file_id in &txn.file_order {
            self.file_to_transaction.insert(*file_id, txn_id);
        }
        self.active.insert(txn_id, txn);
    }

    /// Get a transaction by ID — checks active first, then history.
    pub fn get(&self, id: &Uuid) -> Option<&Transaction> {
        self.active
            .get(id)
            .or_else(|| self.history.iter().find(|t| t.id == *id))
    }

    pub fn get_active_mut(&mut self, id: &Uuid) -> Option<&mut Transaction> {
        self.active.get_mut(id)
    }

    /// Find the active transaction that owns `file_id`.
    pub fn find_by_file_mut(&mut self, file_id: &Uuid) -> Option<&mut Transaction> {
        let txn_id = *self.file_to_transaction.get(file_id)?;
        self.active.get_mut(&txn_id)
    }

    /// Move a transaction from active into history.
    pub fn archive(&mut self, id: &Uuid) {
        if let Some(txn) = self.active.remove(id) {
            for file_id in &txn.file_order {
                self.file_to_transaction.remove(file_id);
            }
            self.history.push(txn);
        }
    }

    /// Interrupt all non-terminal transactions belonging to `peer_id`.
    pub fn interrupt_peer(&mut self, peer_id: &str) {
        for txn in self.active.values_mut() {
            if txn.peer_id == peer_id && !txn.state.is_terminal() {
                txn.interrupt();
            }
        }
    }

    pub fn rejected(&self) -> Vec<&Transaction> {
        self.active
            .values()
            .chain(self.history.iter())
            .filter(|t| t.state == TransactionState::Rejected)
            .collect()
    }

    /// Count of transactions currently in `Active` state.
    /// `Pending`, `Interrupted`, and `Resumable` do not count.
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

// ── Serializable snapshots (persistence) ─────────────────────────────────────

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
    #[serde(default)]
    pub expiration_time: Option<u64>,
    #[serde(default)]
    pub interrupted_at: Option<u64>,
    #[serde(default)]
    pub last_counter: Option<u64>,
    #[serde(default)]
    pub source_path: Option<String>,
    #[serde(default)]
    pub manifest: Option<TransactionManifest>,
}

impl TransactionSnapshot {
    const EXPIRY_SECS: u64 = 24 * 3600;

    /// Returns true if this resumable/interrupted transaction has expired.
    pub fn is_expired(&self) -> bool {
        if !matches!(
            self.state,
            TransactionState::Resumable | TransactionState::Interrupted
        ) {
            return false;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.expiration_time.map_or(false, |exp| now >= exp)
            || self
                .interrupted_at
                .map_or(false, |at| now >= at + Self::EXPIRY_SECS)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionFileSnapshot {
    pub file_id: Uuid,
    pub relative_path: String,
    /// Full absolute path to the source file (for outbound) or destination (for inbound).
    /// Persisted for crash-resilient resume support.
    #[serde(default)]
    pub full_path: Option<String>,
    pub filesize: u64,
    pub total_chunks: u32,
    pub transferred_chunks: u32,
    pub completed: bool,
    pub verified: Option<bool>,
    #[serde(default)]
    pub chunk_bitmap_bytes: Option<Vec<u8>>,
    #[serde(default)]
    pub merkle_root: Option<[u8; 32]>,
    #[serde(default)]
    pub retransmit_count: u32,
}
