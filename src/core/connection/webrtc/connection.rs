//! [`WebRTCConnection`] struct definition and its inherent `impl`.
//!
//! All protocol logic lives in the sibling sub-modules (`sender`, `receiver`,
//! `control`).  This file is intentionally thin: it owns the struct fields and
//! the two methods that depend directly on the `peer_connection` handle.

use super::initializer::SharedReceiverState;
use super::types::{ConnectionMessage, ControlMessage, ReceiveFileState, ReceiverDecision};
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
#[allow(clippy::type_complexity)]
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
    pub resume_bitmaps: Arc<RwLock<HashMap<Uuid, crate::core::pipeline::chunk::ChunkBitmap>>>,
    /// Limits the number of concurrently in-flight (sent but unacknowledged) files.
    pub file_ack_semaphore: Arc<Semaphore>,

    // ── Cryptography ──────────────────────────────────────────────────────────
    pub shared_key: Arc<RwLock<[u8; 32]>>,
    pub key_manager: Option<SessionKeyManager>,
    /// Ephemeral keypair held during an in-progress key rotation.
    pub pending_rotation: Arc<RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>>,

    // ── Counters ──────────────────────────────────────────────────────────────
    /// Monotonic outgoing chat counter (replay protection).
    pub chat_send_counter: Arc<RwLock<u64>>,
    /// Cumulative wire-level TX bytes.
    pub wire_tx: Arc<std::sync::atomic::AtomicU64>,

    // ── Cancellation ──────────────────────────────────────────────────────────
    /// Transactions that have been cancelled; checked by in-flight send tasks.
    pub cancelled_transactions: Arc<Mutex<HashSet<Uuid>>>,

    // ── File verification ─────────────────────────────────────────────────────
    /// One-shot channels the sender inserts while waiting for a receiver decision
    /// after sending `AllHashesSent`.  The control handler fires them when
    /// `FileSkip` or `FileHaveChunks` arrives from the remote peer.
    pub file_decision_tx: Arc<Mutex<HashMap<Uuid, tokio::sync::oneshot::Sender<ReceiverDecision>>>>,

    /// Files the receiver has pre-determined are identical to a locally-existing
    /// file (Merkle root match during PrepareReceive).  When `Metadata` arrives
    /// for one of these files, the receiver sends `FileSkip` immediately and the
    /// sender can stop early — no data is transferred.
    ///
    /// Value: `(final_path, merkle_root)` for the `FileSaved` notification.
    pub pre_skip_files: Arc<Mutex<HashMap<Uuid, (PathBuf, [u8; 32])>>>,
    /// File IDs for which we already sent `FileSkip`.
    /// Any late/stray chunk frames for these IDs should be ignored.
    pub skipped_files: Arc<Mutex<HashSet<Uuid>>>,

    /// Optional precomputed chunk hashes used to reduce sender warm-up latency.
    pub prewarmed_hashes: Arc<Mutex<HashMap<Uuid, Vec<[u8; 32]>>>>,

    /// Reverse index: file_id → transaction_id, for O(1) lookup.
    pub file_to_transaction: Arc<Mutex<HashMap<Uuid, Uuid>>>,
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

    /// Register a file that the receiver already has locally (identical Merkle root).
    ///
    /// When Metadata arrives for this file, the control handler will immediately
    /// send `FileSkip` to the sender instead of creating a writer.
    pub async fn register_pre_skip(&self, file_id: Uuid, path: PathBuf, merkle_root: [u8; 32]) {
        self.pre_skip_files
            .lock()
            .await
            .insert(file_id, (path, merkle_root));
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

        // Collect temp/bitmap paths before removing state entries.
        let mut paths_to_delete: Vec<(PathBuf, PathBuf)> = Vec::new();
        {
            let recv = self.recv_state.read().await;
            for fid in file_ids {
                if let Some(state) = recv.get(fid) {
                    paths_to_delete.push((
                        state.writer.temp_path_ref().to_path_buf(),
                        state.writer.bitmap_path_ref().to_path_buf(),
                    ));
                }
            }
        }

        let mut recv = self.recv_state.write().await;
        let mut pending = self.pending_chunks.write().await;
        let mut destinations = self.accepted_destinations.write().await;
        let mut skipped = self.skipped_files.lock().await;
        for fid in file_ids {
            recv.remove(fid);
            pending.remove(fid);
            destinations.remove(fid);
            skipped.remove(fid);
        }
        drop(recv);
        drop(pending);
        drop(destinations);
        drop(skipped);

        // Spawn async deletion of partial temp files.
        if !paths_to_delete.is_empty() {
            tokio::spawn(async move {
                for (temp, bitmap) in paths_to_delete {
                    let _ = tokio::fs::remove_file(&temp).await;
                    let _ = tokio::fs::remove_file(&bitmap).await;
                }
            });
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
