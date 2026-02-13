use crate::core::transaction::TransactionSnapshot;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, error, warn};
use uuid::Uuid;

/// Transaction-only persistence for resume support.
///
/// All file transfers are represented as transactions. There is no
/// per-file legacy state — every transfer has a transaction ID,
/// manifest, and full lifecycle.
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Persistence {
    /// Transaction-level persistence for resume support.
    #[serde(default)]
    pub transactions: HashMap<Uuid, TransactionSnapshot>,
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
        debug!(event = "persistence_loaded", transactions = p.transactions.len(), "Persistence state loaded");
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

    fn path() -> Result<PathBuf> {
        let dir = crate::utils::data_dir::get();
        Ok(dir.join("transfers.json"))
    }
}
