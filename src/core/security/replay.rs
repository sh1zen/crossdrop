//! Replay protection via monotonic counters and transaction expiration.
//!
//! Each direction of communication maintains an independent monotonic counter.
//! The guard rejects:
//! - Any message with counter ≤ last seen counter
//! - Any message for an expired transaction
//! - Any message with an invalid HMAC

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Per-transaction replay guard state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReplayState {
    /// Highest counter value seen from the remote peer.
    pub last_seen_counter: u64,
    /// Our own outgoing counter (monotonically increasing).
    pub local_counter: u64,
    /// Transaction expiration time (Unix timestamp seconds).
    pub expiration_time: u64,
}

impl TransactionReplayState {
    pub fn new(expiration_time: u64) -> Self {
        Self {
            last_seen_counter: 0,
            local_counter: 0,
            expiration_time,
        }
    }

    /// Check if the transaction has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        now >= self.expiration_time
    }

    /// Validate and accept an incoming counter value.
    /// Returns `true` if the counter is valid (strictly greater than last seen).
    pub fn accept_counter(&mut self, counter: u64) -> bool {
        if counter <= self.last_seen_counter {
            return false;
        }
        self.last_seen_counter = counter;
        true
    }

    /// Get and increment the local outgoing counter.
    pub fn next_counter(&mut self) -> u64 {
        self.local_counter += 1;
        self.local_counter
    }
}

/// Global replay guard managing per-transaction state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplayGuard {
    transactions: HashMap<Uuid, TransactionReplayState>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self {
            transactions: HashMap::new(),
        }
    }

    /// Register a new transaction with its expiration time.
    pub fn register_transaction(&mut self, transaction_id: Uuid, expiration_time: u64) {
        self.transactions.insert(
            transaction_id,
            TransactionReplayState::new(expiration_time),
        );
    }

    /// Validate an incoming message counter for a transaction.
    /// Returns an error string if validation fails.
    pub fn validate_incoming(
        &mut self,
        transaction_id: &Uuid,
        counter: u64,
    ) -> Result<(), &'static str> {
        let state = self
            .transactions
            .get_mut(transaction_id)
            .ok_or("Unknown transaction ID")?;

        if state.is_expired() {
            return Err("Transaction expired");
        }

        if !state.accept_counter(counter) {
            return Err("Counter replay detected");
        }

        Ok(())
    }

    /// Get the next outgoing counter for a transaction.
    pub fn next_outgoing_counter(&mut self, transaction_id: &Uuid) -> Option<u64> {
        self.transactions
            .get_mut(transaction_id)
            .map(|s| s.next_counter())
    }

    /// Get the last seen counter for a transaction.
    pub fn last_seen_counter(&self, transaction_id: &Uuid) -> Option<u64> {
        self.transactions
            .get(transaction_id)
            .map(|s| s.last_seen_counter)
    }

    /// Remove expired transactions.
    pub fn prune_expired(&mut self) {
        self.transactions.retain(|_, state| !state.is_expired());
    }

    /// Remove a specific transaction.
    pub fn remove_transaction(&mut self, transaction_id: &Uuid) {
        self.transactions.remove(transaction_id);
    }

    /// Check if a transaction is registered and not expired.
    pub fn is_valid_transaction(&self, transaction_id: &Uuid) -> bool {
        self.transactions
            .get(transaction_id)
            .is_some_and(|s| !s.is_expired())
    }

    /// Get persisted state for a transaction (for resume).
    pub fn get_state(&self, transaction_id: &Uuid) -> Option<&TransactionReplayState> {
        self.transactions.get(transaction_id)
    }

    /// Restore state for a transaction (from persistence).
    pub fn restore_state(&mut self, transaction_id: Uuid, state: TransactionReplayState) {
        self.transactions.insert(transaction_id, state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_monotonic() {
        let mut state = TransactionReplayState::new(u64::MAX);
        assert!(state.accept_counter(1));
        assert!(state.accept_counter(2));
        assert!(!state.accept_counter(2)); // replay
        assert!(!state.accept_counter(1)); // old counter
        assert!(state.accept_counter(3));
        assert!(state.accept_counter(100)); // gap OK
        assert!(!state.accept_counter(50)); // behind
    }

    #[test]
    fn test_expiration() {
        let state = TransactionReplayState::new(0); // expired immediately
        assert!(state.is_expired());

        let state = TransactionReplayState::new(u64::MAX);
        assert!(!state.is_expired());
    }

    #[test]
    fn test_guard_validate() {
        let mut guard = ReplayGuard::new();
        let txn_id = Uuid::new_v4();
        guard.register_transaction(txn_id, u64::MAX);

        assert!(guard.validate_incoming(&txn_id, 1).is_ok());
        assert!(guard.validate_incoming(&txn_id, 2).is_ok());
        assert!(guard.validate_incoming(&txn_id, 2).is_err()); // replay
        assert!(guard.validate_incoming(&txn_id, 3).is_ok());

        // Unknown transaction
        assert!(guard.validate_incoming(&Uuid::new_v4(), 1).is_err());
    }
}
