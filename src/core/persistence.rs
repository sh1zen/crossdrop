use crate::core::protocol::coordinator::SecureTransferSnapshot;
use crate::core::transaction::TransactionSnapshot;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, error, warn};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferState {
    pub file_id: Uuid,
    pub filename: String,
    pub total_chunks: u32,
    pub received_chunks: u32,
    pub dest_path: Option<PathBuf>,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Persistence {
    pub transfers: HashMap<Uuid, TransferState>,
    /// Transaction-level persistence for resume support.
    #[serde(default)]
    pub transactions: HashMap<Uuid, TransactionSnapshot>,
    /// Secure transfer snapshots for resumable transfers.
    #[serde(default)]
    pub secure_transfers: HashMap<Uuid, SecureTransferSnapshot>,
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
        debug!(event = "persistence_loaded", transactions = p.transactions.len(), transfers = p.transfers.len(), "Persistence state loaded");
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
        self.secure_transfers.remove(id);
        self.save()
    }

    /// Save a secure transfer snapshot for resume.
    #[allow(dead_code)]
    pub fn save_secure_transfer(&mut self, snapshot: SecureTransferSnapshot) -> Result<()> {
        self.secure_transfers.insert(snapshot.transaction_id, snapshot);
        self.save()
    }

    /// Load a secure transfer snapshot by transaction ID.
    #[allow(dead_code)]
    pub fn get_secure_transfer(&self, id: &Uuid) -> Option<&SecureTransferSnapshot> {
        self.secure_transfers.get(id)
    }

    /// Remove a secure transfer snapshot.
    #[allow(dead_code)]
    pub fn remove_secure_transfer(&mut self, id: &Uuid) -> Result<()> {
        self.secure_transfers.remove(id);
        self.save()
    }

    fn path() -> Result<PathBuf> {
        let dir = crate::utils::data_dir::get();
        Ok(dir.join("transfers.json"))
    }
}
