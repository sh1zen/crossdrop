//! Persistent peer registry: remembers known peers for auto-reconnection.
//!
//! Stores peer connection info (ticket, display name, last seen time) in
//! `<data_dir>/peers.json`. Updated on every connect/disconnect event.
//! On startup the app reads this file and attempts to reconnect to all
//! known peers.

use anyhow::Result;
use iroh::EndpointAddr;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, error, warn};

/// Information stored for each known peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    /// The peer's node ID (public key hex string).
    pub peer_id: String,
    /// The ticket used to connect the last time (contains relay + direct addrs).
    /// For inbound peers, this is a minimal ticket built from the NodeId.
    pub ticket: String,
    /// Display name the peer last advertised.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Unix timestamp (seconds) of last successful connection.
    #[serde(default)]
    pub last_connected: u64,
    /// Unix timestamp (seconds) of last disconnect.
    #[serde(default)]
    pub last_disconnected: Option<u64>,
    /// Whether the user explicitly removed this peer (should not auto-reconnect).
    #[serde(default)]
    pub removed: bool,
}

/// Persistent registry of known peers.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PeerRegistry {
    /// peer_id → PeerRecord
    pub peers: HashMap<String, PeerRecord>,
}

impl PeerRegistry {
    /// Load the registry from disk (or return an empty one).
    pub fn load() -> Self {
        let path = match Self::path() {
            Ok(p) => p,
            Err(_) => return Self::default(),
        };

        if !path.exists() {
            return Self::default();
        }

        Self::read_from_file(&path)
    }

    /// Read registry from file with error handling.
    fn read_from_file(path: &PathBuf) -> Self {
        match std::fs::read_to_string(path) {
            Ok(content) => Self::parse_content(&content),
            Err(e) => {
                warn!(
                    event = "peer_registry_read_failure",
                    error = %e,
                    "Failed to read peer registry"
                );
                Self::default()
            }
        }
    }

    /// Parse registry content with error handling.
    fn parse_content(content: &str) -> Self {
        match serde_json::from_str::<PeerRegistry>(content) {
            Ok(reg) => {
                debug!(
                    event = "peer_registry_loaded",
                    peers = reg.peers.len(),
                    "Peer registry loaded"
                );
                reg
            }
            Err(e) => {
                error!(
                    event = "peer_registry_parse_failure",
                    error = %e,
                    "Failed to parse peer registry, starting fresh"
                );
                Self::default()
            }
        }
    }

    /// Persist the registry to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        let content = serde_json::to_string_pretty(self)?;
        crate::utils::atomic_write::atomic_write(&path, content.as_bytes())
    }

    /// Record that a peer has connected.
    pub fn peer_connected(&mut self, peer_id: &str, ticket: String) {
        let now = now_unix();
        let entry = self.peers.entry(peer_id.to_string()).or_insert_with(|| {
            PeerRecord {
                peer_id: peer_id.to_string(),
                ticket: ticket.clone(),
                display_name: None,
                last_connected: now,
                last_disconnected: None,
                removed: false,
            }
        });

        entry.ticket = ticket;
        entry.last_connected = now;
        entry.removed = false;
        let _ = self.save();
    }

    /// Update the display name for a peer.
    pub fn set_display_name(&mut self, peer_id: &str, name: &str) {
        if let Some(entry) = self.peers.get_mut(peer_id) {
            entry.display_name = Some(name.to_string());
            let _ = self.save();
        }
    }

    /// Record that a peer has disconnected (connection lost — not user-initiated removal).
    pub fn peer_disconnected(&mut self, peer_id: &str) {
        if let Some(entry) = self.peers.get_mut(peer_id) {
            entry.last_disconnected = Some(now_unix());
            let _ = self.save();
        }
    }

    /// Mark a peer as explicitly removed (user clicked disconnect).
    pub fn peer_removed(&mut self, peer_id: &str) {
        if let Some(entry) = self.peers.get_mut(peer_id) {
            entry.removed = true;
            entry.last_disconnected = Some(now_unix());
            let _ = self.save();
        }
    }

    /// Returns peers eligible for auto-reconnection.
    pub fn reconnectable_peers(&self) -> Vec<&PeerRecord> {
        self.peers
            .values()
            .filter(|p| !p.removed && p.last_connected > 0)
            .collect()
    }

    /// Returns ALL saved peers (including removed ones).
    pub fn all_peers(&self) -> Vec<&PeerRecord> {
        self.peers.values().collect()
    }

    /// Remove a single peer from the registry entirely.
    pub fn remove_single(&mut self, peer_id: &str) {
        self.peers.remove(peer_id);
        let _ = self.save();
    }

    /// Clear all saved peers from the registry.
    pub fn clear(&mut self) {
        self.peers.clear();
        let _ = self.save();
    }

    /// Build a ticket string from a peer's NodeId (for inbound connections).
    pub fn ticket_from_node_id(peer_id: &str) -> Option<String> {
        use crate::core::connection::Ticket;
        let pk: iroh::PublicKey = peer_id.parse().ok()?;
        let addr = EndpointAddr::new(pk);
        let ticket = Ticket::new(addr);
        Ticket::export(ticket).ok()
    }

    fn path() -> Result<PathBuf> {
        let dir = crate::utils::data_dir::get();
        Ok(dir.join("peers.json"))
    }
}

/// Get current Unix timestamp in seconds.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
