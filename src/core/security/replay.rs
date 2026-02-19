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

    /// Check if a transaction is registered.
    pub fn is_registered(&self, transaction_id: &Uuid) -> bool {
        self.transactions.contains(transaction_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_remove() {
        let mut guard = ReplayGuard::new();
        let txn_id = Uuid::new_v4();

        guard.register_transaction(txn_id, u64::MAX);
        assert!(guard.is_registered(&txn_id));

        guard.remove_transaction(&txn_id);
        assert!(!guard.is_registered(&txn_id));
    }

    #[test]
    fn test_default_is_empty() {
        let guard = ReplayGuard::default();
        let txn_id = Uuid::new_v4();
        assert!(!guard.is_registered(&txn_id));
    }
}
