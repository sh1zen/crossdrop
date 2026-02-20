//! Persistent state management for the application.
//!
//! Provides:
//! - Transfer history tracking
//! - Chat message persistence
//! - Pending message queue for offline peers
//! - User preferences (display name, theme)

use crate::core::transaction::{TransactionDirection, TransactionSnapshot};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// ── Transfer Status ──────────────────────────────────────────────────────────

/// Outcome status for a transfer record in history.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub enum TransferStatus {
    /// Transfer completed successfully.
    #[default]
    Ok,
    /// Transfer was declined/rejected by the peer.
    Declined,
    /// Transfer failed with an error.
    Error,
    /// Transfer was cancelled by the user.
    Cancelled,
    /// Resume was declined by the sender.
    ResumeDeclined,
    /// Transfer expired before it could be resumed.
    Expired,
}

impl TransferStatus {
    /// Human-readable label for the status.
    pub fn label(&self) -> &'static str {
        match self {
            TransferStatus::Ok => "✓",
            TransferStatus::Declined => "✗ declined",
            TransferStatus::Error => "⚠ error",
            TransferStatus::Cancelled => "⊘ cancelled",
            TransferStatus::ResumeDeclined => "↻✗ resume declined",
            TransferStatus::Expired => "⏱ expired",
        }
    }
}

// ── Transfer History Snapshot ────────────────────────────────────────────────

/// Persistable transfer history record.
/// One entry per completed/cancelled/rejected transaction.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransferRecord {
    pub direction: TransactionDirection,
    pub peer_id: String,
    pub display_name: String,
    pub total_size: u64,
    pub file_count: u32,
    /// Absolute timestamp formatted as "dd-mm-yyyy HH:MM".
    pub timestamp: String,
    /// Outcome status of the transfer.
    #[serde(default)]
    pub status: TransferStatus,
}

// ── Transfer Statistics Snapshot ──────────────────────────────────────────────

/// Persistable cumulative transfer statistics.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TransferStatsSnapshot {
    pub files_sent: u64,
    pub files_received: u64,
    pub folders_sent: u64,
    pub folders_received: u64,
    /// Cumulative chat messages sent (persisted across sessions).
    #[serde(default)]
    pub messages_sent: u64,
    /// Cumulative chat messages received (persisted across sessions).
    #[serde(default)]
    pub messages_received: u64,
}

// ── Chat History Snapshot ────────────────────────────────────────────────────

/// Who sent the chat message (persistable).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ChatSenderSnapshot {
    Me,
    Peer(String),
}

/// Which chat channel the message belongs to (persistable).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ChatTargetSnapshot {
    Room,
    Peer(String),
}

/// Persistable chat message record.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChatMessageSnapshot {
    pub id: String,
    pub sender: ChatSenderSnapshot,
    pub text: String,
    /// Absolute timestamp formatted at creation (e.g. "14:32").
    pub timestamp: String,
    pub target: ChatTargetSnapshot,
}

// ── Pending Message Queue ────────────────────────────────────────────────────

/// Types of messages that can be queued for offline peers.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum QueuedMessageType {
    /// Direct message (chat).
    Dm { message: String },
    /// Transaction request.
    TransactionRequest {
        transaction_id: Uuid,
        display_name: String,
        manifest: crate::core::transaction::TransactionManifest,
        total_size: u64,
    },
    /// Transaction response.
    TransactionResponse {
        transaction_id: Uuid,
        accepted: bool,
        dest_path: Option<String>,
        reject_reason: Option<String>,
    },
    /// Transaction cancel.
    TransactionCancel { transaction_id: Uuid },
}

/// A message queued for delivery to an offline peer.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QueuedMessage {
    /// Unique ID for this queued message.
    pub id: Uuid,
    /// Target peer ID.
    pub peer_id: String,
    /// The message type and payload.
    pub message_type: QueuedMessageType,
    /// Timestamp when the message was queued.
    pub queued_at: String,
}

// ── Unified Persistence ──────────────────────────────────────────────────────

/// Central persistence for all application state that must survive restarts.
///
/// Saved atomically via temp-file + rename on every mutation.
/// The application may be closed at any time — every change triggers a save.
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Persistence {
    /// Transaction-level persistence for resume support.
    #[serde(default)]
    pub transactions: HashMap<Uuid, TransactionSnapshot>,

    /// User's own display name (empty string = not set).
    #[serde(default)]
    pub display_name: Option<String>,

    /// Completed transfer history with absolute timestamps.
    #[serde(default)]
    pub transfer_history: Vec<TransferRecord>,

    /// Cumulative transfer statistics (files/folders sent/received).
    #[serde(default)]
    pub transfer_stats: TransferStatsSnapshot,

    /// Session-scoped chat message history.
    #[serde(default)]
    pub chat_history: Vec<ChatMessageSnapshot>,

    /// Messages queued for offline peers.
    #[serde(default)]
    pub pending_messages: Vec<QueuedMessage>,

    /// UI theme name (persisted across sessions).
    #[serde(default)]
    pub theme: String,

    /// Remote file system access enabled (allow peers to browse files).
    #[serde(default)]
    pub remote_access: bool,

    /// Remote key listener enabled (allow peers to send key events).
    #[serde(default)]
    pub remote_key_listener: bool,
}

impl Persistence {
    /// Load persistence state from disk, or return default if not found.
    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&path).map_err(|e| {
            warn!(
                event = "persistence_read_failure",
                path = %path.display(),
                error = %e,
                "Failed to read persistence file"
            );
            e
        })?;

        let p: Persistence = serde_json::from_str(&content).map_err(|e| {
            error!(
                event = "persistence_parse_failure",
                path = %path.display(),
                error = %e,
                "Failed to parse persistence state"
            );
            e
        })?;

        debug!(
            event = "persistence_loaded",
            transactions = p.transactions.len(),
            history = p.transfer_history.len(),
            "Persistence state loaded"
        );

        Ok(p)
    }

    /// Persist current state to disk atomically.
    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        let content = serde_json::to_string_pretty(self)?;
        crate::utils::atomic_write::atomic_write(&path, content.as_bytes())
    }

    /// Remove a completed transaction from persistence.
    pub fn remove_transaction(&mut self, id: &Uuid) -> Result<()> {
        self.transactions.remove(id);
        self.save()
    }

    /// Save the user's display name.
    pub fn save_display_name(&mut self, name: &str) -> Result<()> {
        self.display_name = if name.is_empty() {
            None
        } else {
            Some(name.to_string())
        };
        self.save()
    }

    /// Append a transfer record to history and persist.
    pub fn push_transfer_record(&mut self, record: TransferRecord) -> Result<()> {
        self.transfer_history.push(record);
        self.save()
    }

    /// Remove a transfer record from history by index and persist.
    pub fn remove_transfer_record(&mut self, index: usize) -> Result<()> {
        if index < self.transfer_history.len() {
            self.transfer_history.remove(index);
            self.save()
        } else {
            Ok(())
        }
    }

    /// Update transfer statistics and persist.
    pub fn update_transfer_stats(&mut self, stats: &TransferStatsSnapshot) -> Result<()> {
        self.transfer_stats = stats.clone();
        self.save()
    }

    /// Append a chat message to history and persist.
    pub fn push_chat_message(&mut self, msg: ChatMessageSnapshot) -> Result<()> {
        self.chat_history.push(msg);
        self.save()
    }

    /// Save the UI theme name.
    pub fn save_theme(&mut self, theme: &str) -> Result<()> {
        self.theme = theme.to_string();
        self.save()
    }

    /// Save the remote file system access setting.
    pub fn save_remote_access(&mut self, enabled: bool) -> Result<()> {
        self.remote_access = enabled;
        self.save()
    }

    /// Save the remote key listener setting.
    pub fn save_remote_key_listener(&mut self, enabled: bool) -> Result<()> {
        self.remote_key_listener = enabled;
        self.save()
    }

    /// Clear chat history for a specific target and persist.
    pub fn clear_chat_target(&mut self, target: &ChatTargetSnapshot) -> Result<()> {
        self.chat_history.retain(|m| !matches_target(&m.target, target));
        self.save()
    }

    // ── Pending Message Queue ────────────────────────────────────────────────

    /// Queue a message for an offline peer.
    pub fn queue_message(&mut self, msg: QueuedMessage) -> Result<()> {
        info!(
            event = "message_queued",
            peer_id = %msg.peer_id,
            message_id = %msg.id,
            "Message queued for offline peer"
        );
        self.pending_messages.push(msg);
        self.save()
    }

    /// Get all pending messages for a specific peer.
    pub fn get_pending_messages(&self, peer_id: &str) -> Vec<&QueuedMessage> {
        self.pending_messages
            .iter()
            .filter(|m| m.peer_id == peer_id)
            .collect()
    }

    /// Remove a delivered message from the queue.
    pub fn remove_pending_message(&mut self, id: &Uuid) -> Result<()> {
        let initial_len = self.pending_messages.len();
        self.pending_messages.retain(|m| m.id != *id);

        if self.pending_messages.len() < initial_len {
            info!(
                event = "pending_message_removed",
                message_id = %id,
                "Pending message removed after delivery"
            );
            self.save()?;
        }

        Ok(())
    }

    fn path() -> Result<PathBuf> {
        let dir = crate::utils::data_dir::get();
        Ok(dir.join("transfers.json"))
    }
}

/// Check if a chat target matches another (for filtering).
fn matches_target(a: &ChatTargetSnapshot, b: &ChatTargetSnapshot) -> bool {
    match (a, b) {
        (ChatTargetSnapshot::Room, ChatTargetSnapshot::Room) => true,
        (ChatTargetSnapshot::Peer(id_a), ChatTargetSnapshot::Peer(id_b)) => id_a == id_b,
        _ => false,
    }
}
