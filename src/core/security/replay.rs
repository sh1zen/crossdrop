//! Replay protection: per-transaction registration and cleanup.

use std::collections::HashSet;
use uuid::Uuid;

/// Global replay guard tracking registered transactions.
#[derive(Debug, Clone, Default)]
pub struct ReplayGuard {
    transactions: HashSet<Uuid>,
}

impl ReplayGuard {
    /// Create a new empty replay guard.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new transaction.
    ///
    /// The `expiration_time` parameter is reserved for future use
    /// (automatic cleanup of expired transactions).
    pub fn register_transaction(&mut self, transaction_id: Uuid, _expiration_time: u64) {
        self.transactions.insert(transaction_id);
    }

    /// Remove a specific transaction.
    pub fn remove_transaction(&mut self, transaction_id: &Uuid) {
        self.transactions.remove(transaction_id);
    }
}
