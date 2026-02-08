use crate::core::transaction::TransactionSnapshot;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
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
}

impl Persistence {
    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)?;
        let p = serde_json::from_str(&content)?;
        Ok(p)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Remove a completed transaction from persistence.
    pub fn remove_transaction(&mut self, id: &Uuid) -> Result<()> {
        self.transactions.remove(id);
        self.save()
    }

    fn path() -> Result<PathBuf> {
        let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("No home dir"))?;
        Ok(home.join(".crossdrop").join("transfers.json"))
    }
}
