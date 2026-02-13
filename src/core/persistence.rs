use crate::core::transaction::{TransactionDirection, TransactionSnapshot};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, error, warn};
use uuid::Uuid;

// ── Transfer History Snapshot ────────────────────────────────────────────────

/// Persistable transfer history record.
/// One entry per completed/cancelled/rejected transaction.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransferRecordSnapshot {
    pub direction: TransactionDirection,
    pub peer_id: String,
    pub display_name: String,
    pub total_size: u64,
    pub file_count: u32,
    /// Absolute timestamp formatted as "dd-mm-yyyy HH:MM".
    pub timestamp: String,
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
    pub transfer_history: Vec<TransferRecordSnapshot>,

    /// Session-scoped chat message history.
    #[serde(default)]
    pub chat_history: Vec<ChatMessageSnapshot>,
}

impl Persistence {
    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path).map_err(|e| {
            warn!(event = "persistence_read_failure", path = %path.display(), error = %e, "Failed to read persistence file");
            e
        })?;
        let p: Persistence = serde_json::from_str(&content).map_err(|e| {
            error!(event = "persistence_parse_failure", path = %path.display(), error = %e, "Failed to parse persistence state");
            e
        })?;
        debug!(event = "persistence_loaded", transactions = p.transactions.len(), history = p.transfer_history.len(), "Persistence state loaded");
        Ok(p)
    }

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
    pub fn push_transfer_record(&mut self, record: TransferRecordSnapshot) -> Result<()> {
        self.transfer_history.push(record);
        self.save()
    }

    /// Append a chat message to history and persist.
    pub fn push_chat_message(&mut self, msg: ChatMessageSnapshot) -> Result<()> {
        self.chat_history.push(msg);
        self.save()
    }

    /// Clear chat history for a specific target and persist.
    pub fn clear_chat_target(&mut self, target: &ChatTargetSnapshot) -> Result<()> {
        self.chat_history.retain(|m| {
            match (&m.target, target) {
                (ChatTargetSnapshot::Room, ChatTargetSnapshot::Room) => false,
                (ChatTargetSnapshot::Peer(a), ChatTargetSnapshot::Peer(b)) if a == b => false,
                _ => true,
            }
        });
        self.save()
    }

    fn path() -> Result<PathBuf> {
        let dir = crate::utils::data_dir::get();
        Ok(dir.join("transfers.json"))
    }
}
