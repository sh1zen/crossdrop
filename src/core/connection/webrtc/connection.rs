//! [`WebRTCConnection`] struct definition and its inherent `impl`.
//!
//! All protocol logic lives in the sibling sub-modules (`sender`, `receiver`,
//! `control`).  This file is intentionally thin: it owns the struct fields and
//! the two methods that depend directly on the `peer_connection` handle.

use super::types::ConnectionMessage;
use super::types::ControlMessage;
use crate::core::connection::crypto::SessionKeyManager;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock, Semaphore};
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
    pub(crate) peer_connection: Arc<RTCPeerConnection>,
    /// JSON control messages (chat, metadata, acknowledgements).
    pub(crate) control_channel: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,
    /// Binary file chunks.
    pub(crate) data_channel: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,

    // ── Application interface ─────────────────────────────────────────────────
    pub(crate) app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
    /// Notified when the peer replies to an `AreYouAwake` probe.
    pub(crate) awake_notify: Arc<tokio::sync::Notify>,

    // ── File transfer state ───────────────────────────────────────────────────
    /// Accepted save directories keyed by `file_id`.
    pub(crate) accepted_destinations: Arc<RwLock<HashMap<Uuid, PathBuf>>>,
    /// Per-file chunk bitmaps for resume support.
    pub(crate) resume_bitmaps:
        Arc<RwLock<HashMap<Uuid, crate::core::pipeline::chunk::ChunkBitmap>>>,
    /// Limits the number of concurrently in-flight (sent but unacknowledged) files.
    pub(crate) file_ack_semaphore: Arc<Semaphore>,

    // ── Cryptography ──────────────────────────────────────────────────────────
    pub(crate) shared_key: Arc<RwLock<[u8; 32]>>,
    pub(crate) key_manager: Option<SessionKeyManager>,
    /// Ephemeral keypair held during an in-progress key rotation.
    pub(crate) pending_rotation:
        Arc<RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>>,

    // ── Counters ──────────────────────────────────────────────────────────────
    /// Monotonic outgoing chat counter (replay protection).
    pub(crate) chat_send_counter: Arc<RwLock<u64>>,
    /// Cumulative wire-level TX bytes.
    pub(crate) wire_tx: Arc<std::sync::atomic::AtomicU64>,
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
}
