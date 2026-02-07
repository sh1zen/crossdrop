//! [`WebRTCConnection`] struct definition and its inherent `impl`.
//!
//! All protocol logic lives in the sibling sub-modules (`sender`, `receiver`,
//! `control`).  This file is intentionally thin: it owns the struct fields and
//! the two methods that depend directly on the `peer_connection` handle.

use super::initializer::SharedReceiverState;
use super::types::{ConnectionMessage, ControlMessage, ReceiveFileState};
use crate::core::connection::crypto::SessionKeyManager;
use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock, Semaphore};
use uuid::Uuid;
use webrtc::data_channel::RTCDataChannel;
use webrtc::peer_connection::RTCPeerConnection;

// ── Struct ────────────────────────────────────────────────────────────────────

/// A WebRTC peer connection with dual encrypted data channels.
///
/// Manages the full lifecycle of a peer session:
///
/// - **Control channel** — Brotli-compressed, AES-256-GCM encrypted JSON frames.
/// - **Data channel**   — AES-256-GCM encrypted binary chunk frames (no compression).
///
/// # Thread safety
///
/// All mutable state is behind `Arc<RwLock<_>>` or `AtomicU64`.
/// The struct is `Send + Sync`.
pub struct WebRTCConnection {
    // ── WebRTC core ───────────────────────────────────────────────────────────
    pub peer_connection: Arc<RTCPeerConnection>,
    /// JSON control messages (chat, metadata, acknowledgements).
    pub control_channel: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,
    /// Binary file chunks.
    pub data_channel: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,

    // ── Application interface ─────────────────────────────────────────────────
    pub app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
    /// Notified when the peer replies to an `AreYouAwake` probe.
    pub awake_notify: Arc<tokio::sync::Notify>,

    // ── File transfer state ───────────────────────────────────────────────────
    /// Full per-file save paths keyed by `file_id` (set by PrepareReceive).
    pub accepted_destinations: Arc<RwLock<HashMap<Uuid, PathBuf>>>,
    /// Live per-file receive state (writer + pending hash).
    pub recv_state: Arc<RwLock<HashMap<Uuid, ReceiveFileState>>>,
    /// Chunks buffered before their Metadata frame arrives.
    pub pending_chunks: Arc<RwLock<HashMap<Uuid, Vec<(u32, Vec<u8>, u64)>>>>,
    /// Per-file chunk bitmaps for resume support.
    pub resume_bitmaps:
        Arc<RwLock<HashMap<Uuid, crate::core::pipeline::chunk::ChunkBitmap>>>,
    /// Limits the number of concurrently in-flight (sent but unacknowledged) files.
    pub file_ack_semaphore: Arc<Semaphore>,

    // ── Cryptography ──────────────────────────────────────────────────────────
    pub shared_key: Arc<RwLock<[u8; 32]>>,
    pub key_manager: Option<SessionKeyManager>,
    /// Ephemeral keypair held during an in-progress key rotation.
    pub pending_rotation:
        Arc<RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>>,

    // ── Counters ──────────────────────────────────────────────────────────────
    /// Monotonic outgoing chat counter (replay protection).
    pub chat_send_counter: Arc<RwLock<u64>>,
    /// Cumulative wire-level TX bytes.
    pub wire_tx: Arc<std::sync::atomic::AtomicU64>,

    // ── Cancellation ──────────────────────────────────────────────────────────
    /// Transactions that have been cancelled; checked by in-flight send tasks.
    pub cancelled_transactions: Arc<Mutex<HashSet<Uuid>>>,
}

// ── Inherent impl ─────────────────────────────────────────────────────────────

impl WebRTCConnection {
    /// Probe the peer with `AreYouAwake` and wait for `ImAwake` within the
    /// configured timeout.
    ///
    /// Call this before initiating a file transfer to verify the peer is
    /// still responsive.
    pub async fn check_peer_alive(&self) -> Result<()> {
        use crate::core::config::AWAKE_CHECK_TIMEOUT;
        use webrtc::data_channel::data_channel_state::RTCDataChannelState;

        // Fail fast if the control channel is already known to be closed.
        let cc = self.control_channel.read().await;
        match cc.as_ref() {
            Some(dc) if dc.ready_state() == RTCDataChannelState::Open => {}
            Some(_) => return Err(anyhow!("Control channel not open")),
            None => return Err(anyhow!("Control channel not available")),
        }
        drop(cc);

        self.send_control(&ControlMessage::AreYouAwake).await?;

        tokio::time::timeout(AWAKE_CHECK_TIMEOUT, self.awake_notify.notified())
            .await
            .map_err(|_| anyhow!("Peer not responding to awake check"))
    }

    /// Mark a transaction as cancelled so in-flight send tasks stop early.
    pub async fn cancel_transaction(&self, transaction_id: Uuid) {
        self.cancelled_transactions
            .lock()
            .await
            .insert(transaction_id);
    }

    /// Return true if this transaction has been cancelled.
    pub async fn is_transaction_cancelled(&self, transaction_id: Uuid) -> bool {
        self.cancelled_transactions
            .lock()
            .await
            .contains(&transaction_id)
    }

    /// Remove all in-flight receiver state for the given file IDs.
    ///
    /// Called after a transaction is cancelled (locally or by the remote peer)
    /// to prevent further chunks from being written to disk.  Any chunks that
    /// arrive after this call will find no active writer and be silently dropped.
    pub async fn cleanup_cancelled_files(&self, file_ids: &[Uuid]) {
        if file_ids.is_empty() {
            return;
        }
        let mut recv = self.recv_state.write().await;
        let mut pending = self.pending_chunks.write().await;
        let mut destinations = self.accepted_destinations.write().await;
        for fid in file_ids {
            recv.remove(fid);
            pending.remove(fid);
            destinations.remove(fid);
        }
    }

    /// Return the `IP:port` of the selected ICE candidate pair, or `None` if
    /// the connection is not yet established.
    pub async fn get_remote_ip(&self) -> Option<String> {
        use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;

        if self.peer_connection.connection_state() != RTCPeerConnectionState::Connected {
            return None;
        }

        let pair = self
            .peer_connection
            .sctp()
            .transport()
            .ice_transport()
            .get_selected_candidate_pair()
            .await?;

        (!pair.remote.address.is_empty())
            .then(|| format!("{}:{}", pair.remote.address, pair.remote.port))
    }

    /// Extract the shared receiver state Arcs so they can be passed to a
    /// replacement connection.  This ensures that file-destination registrations
    /// survive connection races during auto-reconnect.
    pub fn shared_receiver_state(&self) -> SharedReceiverState {
        SharedReceiverState {
            accepted_destinations: Arc::clone(&self.accepted_destinations),
            resume_bitmaps: Arc::clone(&self.resume_bitmaps),
        }
    }
}
