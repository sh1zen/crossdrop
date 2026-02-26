use crate::core::connection::crypto::SessionKeyManager;
use crate::core::connection::webrtc::types::FilePullRequestItem;
use crate::core::connection::webrtc::{
    AckContext, ConnectionMessage, ControlMessage, SignalingMessage, WebRTCConnection,
};
use crate::core::connection::{Iroh, Ticket};
use crate::core::transaction::{ResumeInfo, TransactionManifest};
use crate::utils::sos::SignalOfStop;
use crate::workers::args::Args;
use anyhow::{Context, Result};
use iroh::SecretKey;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// ── App Events ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum AppEvent {
    PeerConnected {
        peer_id: String,
        remote_ip: Option<String>,
    },
    PeerDisconnected {
        peer_id: String,
        /// `true` = user-initiated removal; `false` = connection lost.
        explicit: bool,
    },
    ChatReceived {
        peer_id: String,
        message: Vec<u8>,
    },
    DmReceived {
        peer_id: String,
        message: Vec<u8>,
    },
    TypingReceived {
        peer_id: String,
    },
    FileProgress {
        _peer_id: String,
        file_id: Uuid,
        _filename: String,
        received_chunks: u32,
        _total_chunks: u32,
        wire_bytes: u64,
        chunk_bitmap_bytes: Option<Vec<u8>>,
    },
    SendProgress {
        _peer_id: String,
        file_id: Uuid,
        _filename: String,
        _total_chunks: u32,
        wire_bytes: u64,
        chunks_sent: u32,
    },
    SendComplete {
        _peer_id: String,
        file_id: Uuid,
        success: bool,
    },
    FileComplete {
        _peer_id: String,
        file_id: Uuid,
        filename: String,
        _path: String,
        merkle_root: [u8; 32],
    },
    DisplayNameReceived {
        peer_id: String,
        name: String,
    },
    LsResponse {
        peer_id: String,
        path: String,
        entries: Vec<crate::workers::peer::RemoteEntry>,
    },
    RemoteAccessDisabled {
        peer_id: String,
    },
    RemoteKeyListenerDisabled {
        peer_id: String,
    },
    RemoteKeyEventReceived {
        peer_id: String,
        key: String,
    },
    RemoteFetchRequest {
        peer_id: String,
        path: String,
        is_folder: bool,
    },
    TransactionRequested {
        peer_id: String,
        transaction_id: Uuid,
        display_name: String,
        manifest: TransactionManifest,
        total_size: u64,
    },
    TransactionAccepted {
        transaction_id: Uuid,
        dest_path: Option<String>,
    },
    TransactionRejected {
        transaction_id: Uuid,
        reason: Option<String>,
    },
    TransactionCompleted {
        transaction_id: Uuid,
    },
    TransactionCancelled {
        transaction_id: Uuid,
        reason: Option<String>,
    },
    TransactionResumeRequested {
        peer_id: String,
        resume_info: ResumeInfo,
    },
    TransactionResumeAccepted {
        transaction_id: Uuid,
    },
    TransactionResumeRejected {
        transaction_id: Uuid,
        reason: Option<String>,
    },
    TransactionManifestReceived {
        peer_id: String,
        transaction_id: Uuid,
        manifest: TransactionManifest,
        total_size: u64,
    },
    FilePullRequested {
        peer_id: String,
        transaction_id: Uuid,
        file_id: Uuid,
    },
    FilePullBatchRequested {
        peer_id: String,
        transaction_id: Uuid,
        requests: Vec<FilePullRequestItem>,
    },
    ChunkRetransmitRequested {
        peer_id: String,
        file_id: Uuid,
        chunk_indices: Vec<u32>,
    },
    /// Unified acknowledgement received from peer.
    AckReceived {
        context: AckContext,
    },
    Error(String),
    Info(String),
    Connecting {
        peer_id: String,
        status: String,
    },
}

// ── Internal types ───────────────────────────────────────────────────────────

struct PeerEntry {
    connection: Arc<WebRTCConnection>,
    key_manager: SessionKeyManager,
}

#[derive(Clone)]
pub struct PeerNode {
    sos: SignalOfStop,
    _args: Args,
    iroh: Arc<Iroh>,
    peers: Arc<Mutex<HashMap<String, PeerEntry>>>,
    peer_tickets: Arc<Mutex<HashMap<String, String>>>,
    connecting: Arc<Mutex<HashSet<String>>>,
    event_tx: mpsc::UnboundedSender<AppEvent>,
    public_key: iroh::PublicKey,
    display_name_tx: Arc<tokio::sync::watch::Sender<String>>,
    display_name_rx: tokio::sync::watch::Receiver<String>,
    wire_tx: Arc<AtomicU64>,
    wire_rx: Arc<AtomicU64>,
}

// ── Utility helpers ───────────────────────────────────────────────────────────

fn short_id(id: &str) -> &str {
    let end = id.len().min(8);
    &id[..end]
}

/// Public accessor for truncated peer IDs in log messages.
pub fn short_id_pub(id: &str) -> &str {
    short_id(id)
}

// ── RAII connecting guard ─────────────────────────────────────────────────────

/// Removes `peer_id` from the `connecting` set when dropped.
struct ConnectingGuard {
    connecting: Arc<Mutex<HashSet<String>>>,
    peer_id: String,
}

impl Drop for ConnectingGuard {
    fn drop(&mut self) {
        let connecting = self.connecting.clone();
        let peer_id = std::mem::take(&mut self.peer_id);
        if let Ok(mut set) = connecting.try_lock() {
            set.remove(&peer_id);
        } else {
            tokio::spawn(async move {
                connecting.lock().await.remove(&peer_id);
            });
        }
    }
}

// ── ConnectionMessage → AppEvent mapping ─────────────────────────────────────

/// Maps a [`ConnectionMessage`] to the corresponding [`AppEvent`].
///
/// Returns `None` for `AwakeReceived`, which is handled locally in the
/// connection task rather than forwarded to the application layer.
fn map_connection_to_app_event(pid: &str, msg: ConnectionMessage) -> Option<AppEvent> {
    let peer_id = || pid.to_string();

    Some(match msg {
        ConnectionMessage::TextReceived(message) => AppEvent::ChatReceived {
            peer_id: peer_id(),
            message,
        },
        ConnectionMessage::DmReceived(message) => AppEvent::DmReceived {
            peer_id: peer_id(),
            message,
        },
        ConnectionMessage::TypingReceived => AppEvent::TypingReceived { peer_id: peer_id() },
        ConnectionMessage::FileSaved {
            file_id,
            filename,
            path,
            merkle_root,
        } => AppEvent::FileComplete {
            _peer_id: peer_id(),
            file_id,
            filename,
            _path: path,
            merkle_root,
        },
        ConnectionMessage::FileProgress {
            file_id,
            filename,
            received_chunks,
            total_chunks,
            wire_bytes,
            chunk_bitmap_bytes,
        } => AppEvent::FileProgress {
            _peer_id: peer_id(),
            file_id,
            _filename: filename,
            received_chunks,
            _total_chunks: total_chunks,
            wire_bytes,
            chunk_bitmap_bytes,
        },
        ConnectionMessage::SendProgress {
            file_id,
            filename,
            total_chunks,
            wire_bytes,
            chunks_sent,
            ..
        } => AppEvent::SendProgress {
            _peer_id: peer_id(),
            file_id,
            _filename: filename,
            _total_chunks: total_chunks,
            wire_bytes,
            chunks_sent,
        },
        ConnectionMessage::SendComplete { file_id, success } => AppEvent::SendComplete {
            _peer_id: peer_id(),
            file_id,
            success,
        },
        ConnectionMessage::DisplayNameReceived(name) => AppEvent::DisplayNameReceived {
            peer_id: peer_id(),
            name,
        },
        ConnectionMessage::Debug(s) => AppEvent::Info(s),
        ConnectionMessage::Error(s) => AppEvent::Error(s),
        ConnectionMessage::LsResponse { path, entries } => AppEvent::LsResponse {
            peer_id: peer_id(),
            path,
            entries,
        },
        ConnectionMessage::RemoteAccessDisabled => {
            AppEvent::RemoteAccessDisabled { peer_id: peer_id() }
        }
        ConnectionMessage::RemoteKeyListenerDisabled => {
            AppEvent::RemoteKeyListenerDisabled { peer_id: peer_id() }
        }
        ConnectionMessage::RemoteKeyEventReceived { key } => AppEvent::RemoteKeyEventReceived {
            peer_id: peer_id(),
            key,
        },
        ConnectionMessage::RemoteFetchRequest { path, is_folder } => AppEvent::RemoteFetchRequest {
            peer_id: peer_id(),
            path,
            is_folder,
        },
        ConnectionMessage::TransactionRequested {
            transaction_id,
            display_name,
            manifest,
            total_size,
        } => AppEvent::TransactionRequested {
            peer_id: peer_id(),
            transaction_id,
            display_name,
            manifest,
            total_size,
        },
        ConnectionMessage::TransactionAccepted {
            transaction_id,
            dest_path,
        } => AppEvent::TransactionAccepted {
            transaction_id,
            dest_path,
        },
        ConnectionMessage::TransactionRejected {
            transaction_id,
            reason,
        } => AppEvent::TransactionRejected {
            transaction_id,
            reason,
        },
        ConnectionMessage::TransactionCompleted { transaction_id } => {
            AppEvent::TransactionCompleted { transaction_id }
        }
        ConnectionMessage::TransactionCancelled {
            transaction_id,
            reason,
        } => AppEvent::TransactionCancelled {
            transaction_id,
            reason,
        },
        ConnectionMessage::TransactionResumeRequested { resume_info } => {
            AppEvent::TransactionResumeRequested {
                peer_id: peer_id(),
                resume_info,
            }
        }
        ConnectionMessage::TransactionResumeAccepted { transaction_id } => {
            AppEvent::TransactionResumeAccepted { transaction_id }
        }
        ConnectionMessage::TransactionResumeRejected {
            transaction_id,
            reason,
        } => AppEvent::TransactionResumeRejected {
            transaction_id,
            reason,
        },
        ConnectionMessage::TransactionManifestReceived {
            transaction_id,
            manifest,
            total_size,
        } => AppEvent::TransactionManifestReceived {
            peer_id: peer_id(),
            transaction_id,
            manifest,
            total_size,
        },
        ConnectionMessage::FilePullRequested {
            transaction_id,
            file_id,
        } => AppEvent::FilePullRequested {
            peer_id: peer_id(),
            transaction_id,
            file_id,
        },
        ConnectionMessage::FilePullBatchRequested {
            transaction_id,
            requests,
        } => AppEvent::FilePullBatchRequested {
            peer_id: peer_id(),
            transaction_id,
            requests,
        },
        ConnectionMessage::ChunkRetransmitRequested {
            file_id,
            chunk_indices,
        } => AppEvent::ChunkRetransmitRequested {
            peer_id: peer_id(),
            file_id,
            chunk_indices,
        },
        ConnectionMessage::AckReceived { context } => AppEvent::AckReceived { context },
        ConnectionMessage::Disconnected => AppEvent::PeerDisconnected {
            peer_id: peer_id(),
            explicit: false,
        },
        ConnectionMessage::AwakeReceived => return None,
    })
}

// ── PeerNode impl ────────────────────────────────────────────────────────────

impl PeerNode {
    pub async fn new(
        secret_key: SecretKey,
        args: Args,
        sos: SignalOfStop,
        event_tx: mpsc::UnboundedSender<AppEvent>,
        wire_tx: Arc<AtomicU64>,
        wire_rx: Arc<AtomicU64>,
    ) -> Result<Self> {
        let public_key = secret_key.public();
        let iroh = Arc::new(
            Iroh::new(
                secret_key,
                args.relay.clone(),
                args.ipv4_addr,
                args.ipv6_addr,
                args.port,
            )
            .await?,
        );

        let initial_name = args.display_name.clone().unwrap_or_default();
        let (display_name_tx, display_name_rx) = tokio::sync::watch::channel(initial_name);

        Ok(Self {
            sos,
            _args: args,
            iroh,
            peers: Arc::new(Mutex::new(HashMap::new())),
            peer_tickets: Arc::new(Mutex::new(HashMap::new())),
            connecting: Arc::new(Mutex::new(HashSet::new())),
            event_tx,
            public_key,
            display_name_tx: Arc::new(display_name_tx),
            display_name_rx,
            wire_tx,
            wire_rx,
        })
    }

    pub fn ticket(&self) -> Result<String> {
        self.iroh.ticket()
    }

    /// Own peer ID (public key formatted as string).
    pub fn peer_id(&self) -> String {
        self.public_key.to_string()
    }

    pub fn event_tx(&self) -> &mpsc::UnboundedSender<AppEvent> {
        &self.event_tx
    }

    // ── Internal: connection event relay ────────────────────────────────

    fn create_connection_tx(
        peer_id: String,
        event_tx: mpsc::UnboundedSender<AppEvent>,
        awake_notify: Arc<tokio::sync::Notify>,
    ) -> mpsc::UnboundedSender<ConnectionMessage> {
        let (conn_tx, mut conn_rx) = mpsc::unbounded_channel::<ConnectionMessage>();
        tokio::spawn(async move {
            let mut disconnect_sent = false;
            while let Some(msg) = conn_rx.recv().await {
                if matches!(msg, ConnectionMessage::AwakeReceived) {
                    awake_notify.notify_one();
                    continue;
                }

                // Deduplicate Disconnected: WebRTC can fire it multiple times.
                if matches!(msg, ConnectionMessage::Disconnected) {
                    if disconnect_sent {
                        debug!(
                            event = "duplicate_disconnect_suppressed",
                            peer = %short_id(&peer_id),
                            "Suppressing duplicate Disconnected event"
                        );
                        continue;
                    }
                    disconnect_sent = true;
                }

                if let Some(event) = map_connection_to_app_event(&peer_id, msg)
                    && event_tx.send(event).is_err()
                {
                    break;
                }
            }
        });
        conn_tx
    }

    // ── Internal: peer lookup helpers ────────────────────────────────────

    /// Clone the [`Arc<WebRTCConnection>`] for `peer_id`, or return an error.
    async fn get_connection(&self, peer_id: &str) -> Result<Arc<WebRTCConnection>> {
        self.peers
            .lock()
            .await
            .get(peer_id)
            .map(|e| e.connection.clone())
            .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))
    }

    /// Try to get the connection without holding the lock, returning `None` if absent.
    async fn try_get_connection(&self, peer_id: &str) -> Option<Arc<WebRTCConnection>> {
        self.peers
            .lock()
            .await
            .get(peer_id)
            .map(|e| e.connection.clone())
    }

    // ── Internal: display name ───────────────────────────────────────────

    async fn send_display_name_if_set(&self, conn: &WebRTCConnection) {
        let name = self.current_display_name();
        if !name.is_empty() {
            let _ = conn.send_display_name(name).await;
        }
    }

    // ── Internal: liveness + disconnect helpers ──────────────────────────

    /// Check liveness; on failure, remove peer from map and emit `PeerDisconnected`.
    async fn check_alive_or_disconnect(
        &self,
        peer_id: &str,
        conn: &WebRTCConnection,
    ) -> Result<()> {
        if let Err(e) = conn.check_peer_alive().await {
            // Remove from map first to prevent stale_disconnect_ignored guard from blocking
            self.peers.lock().await.remove(peer_id);
            let _ = self.event_tx.send(AppEvent::PeerDisconnected {
                peer_id: peer_id.to_string(),
                explicit: false,
            });
            return Err(e);
        }
        Ok(())
    }

    // ── Internal: key rotation (offerer side) ────────────────────────────

    fn spawn_key_rotation(peer_id: String, conn: Arc<WebRTCConnection>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(crate::core::connection::crypto::KEY_ROTATION_INTERVAL).await;
                match conn.initiate_key_rotation().await {
                    Ok(()) => info!(
                        event = "key_rotation_scheduled",
                        peer = %short_id(&peer_id),
                        "Hourly key rotation initiated"
                    ),
                    Err(e) => {
                        warn!(
                            event = "key_rotation_failed",
                            peer = %short_id(&peer_id),
                            error = %e,
                            "Key rotation failed"
                        );
                        break;
                    }
                }
            }
        });
    }

    // ── Connect (outbound) ───────────────────────────────────────────────

    pub async fn connect_to(&self, ticket_str: String) -> Result<()> {
        self.connect_to_inner(ticket_str, false).await
    }

    pub async fn connect_to_quiet(&self, ticket_str: String) -> Result<()> {
        self.connect_to_inner(ticket_str, true).await
    }

    async fn connect_to_inner(&self, ticket_str: String, quiet: bool) -> Result<()> {
        let ticket = Ticket::parse(ticket_str.clone())?;
        let peer_id = ticket.address.id.to_string();

        // Guard: already connected?
        if self.peers.lock().await.contains_key(&peer_id) {
            debug!(event = "connect_skipped", peer = %short_id(&peer_id), "Already connected, skipping");
            if !quiet {
                let _ = self.event_tx.send(AppEvent::Info(format!(
                    "[{}] Already connected, skipping",
                    short_id(&peer_id)
                )));
            }
            return Ok(());
        }

        // Guard: connection in progress?
        if !self.connecting.lock().await.insert(peer_id.clone()) {
            debug!(event = "connect_skipped", peer = %short_id(&peer_id), "Connection already in progress, skipping");
            return Ok(());
        }
        let _guard = ConnectingGuard {
            connecting: self.connecting.clone(),
            peer_id: peer_id.clone(),
        };

        self.connecting_notify(&peer_id, "Resolving peer via Iroh...");
        if !quiet {
            self.send_info(&peer_id, "Establishing peer connection...");
        }

        let connection = tokio::time::timeout(Duration::from_secs(30), self.iroh.connect(ticket))
            .await
            .context("Connection to peer timed out (Iroh)")?
            .context("Iroh connection failed")?;

        info!(event = "iroh_connected", peer = %short_id(&peer_id), "Iroh connection established");
        self.connecting_notify(&peer_id, "Opening handshake stream...");

        let (mut send_stream, mut recv_stream) =
            tokio::time::timeout(Duration::from_secs(15), connection.open_bi())
                .await
                .context("Opening handshake stream timed out")?
                .context("Failed to open handshake stream")?;

        self.connecting_notify(&peer_id, "Exchanging encryption key...");

        let key_manager = crate::core::connection::crypto::handshake_offerer(
            &mut send_stream,
            &mut recv_stream,
            &self.public_key,
            &connection.remote_id(),
        )
        .await
        .context("ECDH handshake failed (offerer)")?;

        let shared_key = key_manager.inner();
        self.connecting_notify(&peer_id, "ECDH handshake complete, session key derived");

        let awake_notify = Arc::new(tokio::sync::Notify::new());
        let conn_tx = Self::create_connection_tx(
            peer_id.clone(),
            self.event_tx.clone(),
            awake_notify.clone(),
        );

        self.connecting_notify(&peer_id, "Creating WebRTC offer...");

        let (webrtc_conn, offer_msg) = WebRTCConnection::create_offer(
            Some(conn_tx),
            shared_key,
            Some(key_manager.clone()),
            awake_notify,
            self.wire_tx.clone(),
            self.wire_rx.clone(),
            self._args.remote_access,
            None, // no existing connection to inherit state from
        )
        .await?;
        let webrtc_conn = Arc::new(webrtc_conn);

        let offer_data = serde_json::to_vec(&offer_msg)?;
        self.connecting_notify(
            &peer_id,
            &format!("Sending WebRTC offer ({} bytes)", offer_data.len()),
        );

        send_stream.write_all(&offer_data).await?;
        send_stream.finish()?;

        self.connecting_notify(&peer_id, "Waiting for WebRTC answer...");

        let answer_data = tokio::time::timeout(
            Duration::from_secs(30),
            recv_stream.read_to_end(1024 * 1024),
        )
        .await
        .context("Reading WebRTC answer timed out")?
        .context("Failed to read WebRTC answer")?;

        self.connecting_notify(
            &peer_id,
            &format!("Answer received ({} bytes)", answer_data.len()),
        );

        let answer_msg: SignalingMessage = serde_json::from_slice(&answer_data)?;
        webrtc_conn.set_answer(answer_msg).await?;

        self.connecting_notify(&peer_id, "WebRTC ICE connecting...");
        webrtc_conn.wait_connected().await?;

        self.connecting_notify(&peer_id, "WebRTC connected, waiting for data channels...");
        webrtc_conn.wait_data_channels_open().await?;

        // Atomic check-and-insert: if an inbound connection won the race, drop ours.
        {
            let mut peers = self.peers.lock().await;
            if let Some(winner) = peers.get(&peer_id) {
                debug!(event = "connect_race_lost", peer = %short_id(&peer_id), direction = "outbound", "Another connection completed first, dropping duplicate");
                // Merge our accepted_destinations into the winner's (in case
                // PrepareReceive registered files while we were connecting).
                let our_dests = webrtc_conn.accepted_destinations.read().await;
                if !our_dests.is_empty() {
                    let mut winner_dests = winner.connection.accepted_destinations.write().await;
                    for (k, v) in our_dests.iter() {
                        winner_dests.entry(*k).or_insert_with(|| v.clone());
                    }
                }
                // Close our WebRTC peer connection so the remote side detects
                // the dead half promptly instead of timing out.
                let pc = webrtc_conn.peer_connection.clone();
                tokio::spawn(async move {
                    let _ = pc.close().await;
                });
                return Ok(());
            }
            peers.insert(
                peer_id.clone(),
                PeerEntry {
                    connection: webrtc_conn.clone(),
                    key_manager,
                },
            );
        }

        self.connecting_notify(&peer_id, "Data channels open (control + data)");
        self.send_display_name_if_set(&webrtc_conn).await;
        Self::spawn_key_rotation(peer_id.clone(), webrtc_conn.clone());

        self.peer_tickets
            .lock()
            .await
            .insert(peer_id.clone(), ticket_str);

        info!("Peer connected: {}", peer_id);
        self.connecting_notify(&peer_id, "Peer fully connected!");
        let remote_ip = webrtc_conn.get_remote_ip().await;
        let _ = self
            .event_tx
            .send(AppEvent::PeerConnected { peer_id, remote_ip });
        Ok(())
    }

    // ── Accept (inbound) ─────────────────────────────────────────────────

    async fn handle_incoming(&self, incoming_conn: iroh::endpoint::Incoming) -> Result<()> {
        let connection = incoming_conn.accept()?.await?;
        let peer_id = connection.remote_id().to_string();

        // Evict any stale entry without calling close() to avoid spurious events.
        // Preserve the shared receiver state so that file-destination registrations
        // from PrepareReceive are visible to the replacement connection's handlers.
        let shared_rx_state = {
            let mut peers = self.peers.lock().await;
            if let Some(old) = peers.remove(&peer_id) {
                info!(event = "stale_evict", peer = %short_id(&peer_id), "Evicting stale connection for incoming reconnect (no close)");
                Some(old.connection.shared_receiver_state())
            } else {
                None
            }
        };

        self.send_info(&peer_id, "Incoming connection..");

        let (mut send_stream, mut recv_stream) =
            tokio::time::timeout(Duration::from_secs(15), connection.accept_bi())
                .await
                .context("Accepting handshake stream timed out")?
                .context("Failed to accept handshake stream")?;

        let key_manager = crate::core::connection::crypto::handshake_answerer(
            &mut send_stream,
            &mut recv_stream,
            &self.public_key,
            &connection.remote_id(),
        )
        .await
        .context("ECDH handshake failed (answerer)")?;

        let shared_key = key_manager.inner();
        self.send_info(&peer_id, "ECDH handshake complete, session key derived");

        let offer_data = tokio::time::timeout(
            Duration::from_secs(15),
            recv_stream.read_to_end(1024 * 1024),
        )
        .await
        .context("Receiving WebRTC offer timed out")?
        .context("Failed to read WebRTC offer")?;

        self.send_info(
            &peer_id,
            &format!("Offer received ({} bytes)", offer_data.len()),
        );

        let offer_msg: SignalingMessage = serde_json::from_slice(&offer_data)?;

        let awake_notify = Arc::new(tokio::sync::Notify::new());
        let conn_tx = Self::create_connection_tx(
            peer_id.clone(),
            self.event_tx.clone(),
            awake_notify.clone(),
        );

        let (webrtc_conn, answer_msg) = WebRTCConnection::accept_offer(
            offer_msg,
            Some(conn_tx),
            shared_key,
            Some(key_manager.clone()),
            awake_notify,
            self.wire_tx.clone(),
            self.wire_rx.clone(),
            self._args.remote_access,
            shared_rx_state,
        )
        .await?;
        let webrtc_conn = Arc::new(webrtc_conn);

        let answer_data = serde_json::to_vec(&answer_msg)?;
        self.send_info(
            &peer_id,
            &format!("Sending answer ({} bytes)", answer_data.len()),
        );

        send_stream.write_all(&answer_data).await?;
        send_stream.finish()?;

        webrtc_conn.wait_connected().await?;
        webrtc_conn.wait_data_channels_open().await?;

        {
            let mut peers = self.peers.lock().await;
            if let Some(old) = peers.remove(&peer_id) {
                debug!(event = "stale_evict_late", peer = %short_id(&peer_id), direction = "inbound", "Evicting stale entry during insert (no close)");
                // If the early eviction didn't capture shared state (another
                // connection snuck in between), grab it now so the new
                // connection inherits any file-destination registrations.
                let late_dests = old.connection.accepted_destinations.read().await;
                if !late_dests.is_empty() {
                    let mut new_dests = webrtc_conn.accepted_destinations.write().await;
                    for (k, v) in late_dests.iter() {
                        new_dests.entry(*k).or_insert_with(|| v.clone());
                    }
                }
            }
            peers.insert(
                peer_id.clone(),
                PeerEntry {
                    connection: webrtc_conn.clone(),
                    key_manager,
                },
            );
        }

        self.send_display_name_if_set(&webrtc_conn).await;

        if let Some(ticket) =
            crate::core::peer_registry::PeerRegistry::ticket_from_node_id(&peer_id)
        {
            self.peer_tickets
                .lock()
                .await
                .insert(peer_id.clone(), ticket);
        }

        info!(event = "peer_connected", peer = %short_id(&peer_id), direction = "inbound", "Peer connected (inbound)");
        self.send_info(&peer_id, "✓ Peer fully connected!");
        let remote_ip = webrtc_conn.get_remote_ip().await;
        let _ = self
            .event_tx
            .send(AppEvent::PeerConnected { peer_id, remote_ip });
        Ok(())
    }

    // ── Accept loop ──────────────────────────────────────────────────────

    pub async fn run_accept_loop(self) {
        loop {
            let sos = self.sos.clone();
            let iroh = self.iroh.clone();
            let result = sos
                .select(async move { iroh.wait_connection().await })
                .await;
            match result {
                Err(()) => break,
                Ok(Ok(incoming)) => {
                    let this = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = this.handle_incoming(incoming).await {
                            error!(event = "incoming_connection_error", error = %e, "Incoming connection failed");
                            // Do not send an AppEvent::Error to the UI for connection failures
                            // This prevents the user from seeing "DataChannel 'control' is permanently closed"
                            // as an application error
                        }
                    });
                }
                Ok(Err(e)) => {
                    error!(event = "accept_error", error = %e, "Accept loop error");
                    // Do not send an AppEvent::Error to the UI for accept loop errors
                }
            }
        }
    }

    // ── Chat ─────────────────────────────────────────────────────────────

    pub fn queue_message_for_peer(
        &self,
        peer_id: &str,
        msg_type: crate::core::persistence::QueuedMessageType,
    ) -> Result<()> {
        use crate::core::persistence::{Persistence, QueuedMessage};
        use chrono::Local;

        let queued_msg = QueuedMessage {
            id: Uuid::new_v4(),
            peer_id: peer_id.to_string(),
            message_type: msg_type,
            queued_at: Local::now().format("%H:%M").to_string(),
        };

        let mut persistence =
            Persistence::load().context("Failed to load persistence for message queue")?;
        persistence.queue_message(queued_msg)
    }

    pub async fn send_dm(&self, peer_id: &str, message: &str) -> Result<()> {
        match self.try_get_connection(peer_id).await {
            Some(conn) => {
                conn.check_peer_alive().await?;
                debug!("Sending DM (direct) to {}: {}", peer_id, message);
                conn.send_dm(message.as_bytes().to_vec()).await
            }
            None => {
                info!(event = "dm_queued", peer_id = %peer_id, "Peer offline, queuing DM");
                self.queue_message_for_peer(
                    peer_id,
                    crate::core::persistence::QueuedMessageType::Dm {
                        message: message.to_string(),
                    },
                )
            }
        }
    }

    pub async fn send_typing(&self, peer_id: &str) -> Result<()> {
        if let Some(conn) = self.try_get_connection(peer_id).await {
            conn.send_typing().await
        } else {
            Ok(())
        }
    }

    pub async fn broadcast_typing(&self) -> Result<()> {
        let peers = self.peers.lock().await;
        for entry in peers.values() {
            let _ = entry.connection.send_typing().await;
        }
        Ok(())
    }

    pub async fn broadcast_chat(&self, message: &str) -> Result<Vec<String>> {
        let peer_conns: Vec<(String, Arc<WebRTCConnection>)> = {
            let peers = self.peers.lock().await;
            peers
                .iter()
                .map(|(id, e)| (id.clone(), e.connection.clone()))
                .collect()
        };

        let mut sent_to = Vec::new();
        for (peer_id, conn) in &peer_conns {
            if let Err(e) = conn.check_peer_alive().await {
                warn!(event = "chat_peer_not_awake", peer = %short_id(peer_id), error = %e, "Peer not awake, skipping chat message");
                continue;
            }
            match conn.send_message(message.as_bytes().to_vec()).await {
                Ok(()) => sent_to.push(peer_id.clone()),
                Err(e) => {
                    warn!(event = "chat_send_failure", peer = %short_id(peer_id), error = %e, "Failed to send chat message")
                }
            }
        }
        debug!(
            "Broadcasting chat to {} peers: {}",
            peer_conns.len(),
            message
        );
        Ok(sent_to)
    }

    pub async fn broadcast_display_name(&self, name: String) {
        let _ = self.display_name_tx.send(name.clone());
        let peers = self.peers.lock().await;
        for (peer_id, entry) in peers.iter() {
            if let Err(e) = entry.connection.send_display_name(name.clone()).await {
                warn!(event = "display_name_send_failure", peer = %short_id(peer_id), error = %e, "Failed to send display name");
            }
        }
    }

    pub fn set_display_name(&self, name: String) {
        let _ = self.display_name_tx.send(name);
    }

    pub fn current_display_name(&self) -> String {
        self.display_name_rx.borrow().clone()
    }

    // ── File transfer ────────────────────────────────────────────────────

    pub async fn send_file_data(
        &self,
        peer_id: &str,
        file_id: Uuid,
        file_path: &str,
        filename: &str,
        transaction_id: Option<Uuid>,
    ) -> Result<()> {
        let filesize = tokio::fs::metadata(file_path).await?.len();
        let conn = self.get_connection(peer_id).await?;

        info!(
            "Sending file '{}' ({} bytes) to {} [txn file_id={}]",
            filename, filesize, peer_id, file_id
        );
        conn.send_file(
            file_id,
            std::path::PathBuf::from(file_path),
            filesize,
            filename,
            transaction_id,
        )
        .await
    }

    pub async fn send_file_data_resuming(
        &self,
        peer_id: &str,
        file_id: Uuid,
        file_path: &str,
        filename: &str,
        bitmap: crate::core::pipeline::chunk::ChunkBitmap,
        transaction_id: Option<Uuid>,
    ) -> Result<()> {
        let filesize = tokio::fs::metadata(file_path).await?.len();
        let conn = self.get_connection(peer_id).await?;

        let missing_count = bitmap.missing_count();
        info!(
            "Resuming file '{}' ({} bytes) to {} with bitmap ({} missing chunks) [txn file_id={}]",
            filename, filesize, peer_id, missing_count, file_id
        );
        conn.send_file_with_bitmap(
            file_id,
            std::path::PathBuf::from(file_path),
            filesize,
            filename,
            bitmap,
            transaction_id,
        )
        .await
    }

    // ── Transaction API ──────────────────────────────────────────────────

    pub async fn deliver_pending_messages(&self, peer_id: &str) -> Result<()> {
        use crate::core::persistence::{Persistence, QueuedMessageType};

        let mut persistence =
            Persistence::load().context("Failed to load persistence for pending messages")?;
        let pending: Vec<_> = persistence
            .get_pending_messages(peer_id)
            .into_iter()
            .cloned()
            .collect();

        if pending.is_empty() {
            return Ok(());
        }

        info!(
            event = "delivering_pending_messages",
            peer_id = %peer_id,
            count = pending.len(),
            "Delivering pending messages to reconnected peer"
        );

        let conn = self.get_connection(peer_id).await?;
        conn.wait_data_channels_open()
            .await
            .context("Data channels not ready for pending messages")?;

        for msg in pending {
            let result = match &msg.message_type {
                QueuedMessageType::Dm { message } => {
                    conn.send_dm(message.as_bytes().to_vec()).await
                }
                QueuedMessageType::TransactionRequest {
                    transaction_id,
                    display_name,
                    manifest,
                    total_size,
                } => {
                    conn.send_transaction_request(
                        *transaction_id,
                        display_name.clone(),
                        manifest.clone(),
                        *total_size,
                    )
                    .await
                }
                QueuedMessageType::TransactionResponse {
                    transaction_id,
                    accepted,
                    dest_path,
                    reject_reason,
                } => {
                    conn.send_transaction_response(
                        *transaction_id,
                        *accepted,
                        dest_path.clone(),
                        reject_reason.clone(),
                    )
                    .await
                }
                QueuedMessageType::TransactionCancel { transaction_id } => {
                    conn.send_transaction_cancel(
                        *transaction_id,
                        Some("User cancelled".to_string()),
                    )
                    .await
                }
            };

            match result {
                Ok(()) => {
                    info!(
                        event = "pending_message_delivered",
                        message_id = %msg.id,
                        peer_id = %peer_id,
                        "Pending message delivered successfully"
                    );
                    persistence.remove_pending_message(&msg.id)?;
                }
                Err(e) => {
                    warn!(
                        event = "pending_message_delivery_failed",
                        message_id = %msg.id,
                        peer_id = %peer_id,
                        error = %e,
                        "Failed to deliver pending message, will retry later"
                    );
                }
            }
        }

        Ok(())
    }

    pub async fn send_transaction_request(
        &self,
        peer_id: &str,
        transaction_id: Uuid,
        display_name: String,
        manifest: TransactionManifest,
        total_size: u64,
    ) -> Result<()> {
        let conn = self.get_connection(peer_id).await?;
        self.check_alive_or_disconnect(peer_id, &conn).await?;
        conn.send_transaction_request(transaction_id, display_name, manifest, total_size)
            .await
    }

    pub async fn respond_to_transaction(
        &self,
        peer_id: &str,
        transaction_id: Uuid,
        accepted: bool,
        dest_path: Option<String>,
        reject_reason: Option<String>,
    ) -> Result<()> {
        let conn = self.get_connection(peer_id).await?;
        conn.wait_data_channels_open()
            .await
            .context("Data channels not ready for transaction response")?;
        conn.send_transaction_response(transaction_id, accepted, dest_path, reject_reason)
            .await
    }

    pub async fn accept_transaction_resume(
        &self,
        peer_id: &str,
        transaction_id: Uuid,
    ) -> Result<()> {
        let conn = self.get_connection(peer_id).await?;
        conn.wait_data_channels_open()
            .await
            .context("Data channels not ready for resume acceptance")?;
        conn.send_transaction_resume_response(transaction_id, true)
            .await
    }

    pub async fn reject_transaction_resume(
        &self,
        peer_id: &str,
        transaction_id: Uuid,
    ) -> Result<()> {
        let conn = self.get_connection(peer_id).await?;
        conn.wait_data_channels_open()
            .await
            .context("Data channels not ready for resume rejection")?;
        conn.send_transaction_resume_response(transaction_id, false)
            .await
    }

    pub async fn send_resume_request(
        &self,
        peer_id: &str,
        _transaction_id: Uuid,
        resume_info: ResumeInfo,
    ) -> Result<()> {
        let conn = self.get_connection(peer_id).await?;
        conn.wait_data_channels_open()
            .await
            .context("Data channels not ready for resume request")?;
        conn.send_control(&ControlMessage::TransactionResumeRequest { resume_info })
            .await
    }

    pub async fn send_transaction_complete(
        &self,
        peer_id: &str,
        transaction_id: Uuid,
    ) -> Result<()> {
        let conn = self.get_connection(peer_id).await?;
        conn.wait_data_channels_open()
            .await
            .context("Data channels not ready for transaction complete")?;
        conn.send_control(&ControlMessage::TransactionComplete { transaction_id })
            .await
    }

    pub async fn send_transaction_manifest(
        &self,
        peer_id: &str,
        transaction_id: Uuid,
        manifest: TransactionManifest,
        total_size: u64,
    ) -> Result<()> {
        let conn = self.get_connection(peer_id).await?;
        conn.wait_data_channels_open()
            .await
            .context("Data channels not ready for transaction manifest")?;
        conn.send_transaction_manifest(transaction_id, manifest, total_size)
            .await
    }

    pub async fn request_file_pull_batch(
        &self,
        peer_id: &str,
        transaction_id: Uuid,
        requests: Vec<FilePullRequestItem>,
    ) -> Result<()> {
        let conn = self.get_connection(peer_id).await?;
        conn.wait_data_channels_open()
            .await
            .context("Data channels not ready for batch file pull request")?;
        conn.send_file_pull_batch_request(transaction_id, requests)
            .await
    }

    pub async fn send_file_chunks_data(
        &self,
        peer_id: &str,
        file_id: Uuid,
        file_path: &str,
        filename: &str,
        chunk_indices: Vec<u32>,
        transaction_id: Option<Uuid>,
    ) -> Result<()> {
        let filesize = tokio::fs::metadata(file_path).await?.len();
        let conn = self.get_connection(peer_id).await?;
        conn.send_file_chunks(
            file_id,
            std::path::PathBuf::from(file_path),
            filesize,
            filename,
            chunk_indices,
            transaction_id,
        )
        .await
    }

    pub async fn prewarm_file_data(
        &self,
        peer_id: &str,
        file_id: Uuid,
        file_path: &str,
    ) -> Result<()> {
        let filesize = tokio::fs::metadata(file_path).await?.len();
        let conn = self.get_connection(peer_id).await?;
        conn.prewarm_file_hashes(file_id, std::path::PathBuf::from(file_path), filesize)
            .await
    }

    /// Mark a transaction as cancelled on the connection so in-flight send tasks stop early.
    pub async fn mark_transaction_cancelled(&self, peer_id: &str, transaction_id: Uuid) {
        if let Some(conn) = self.try_get_connection(peer_id).await {
            conn.cancel_transaction(transaction_id).await;
        }
    }

    /// Remove receiver state for all files in a cancelled transfer so no further
    /// chunks are written to disk.
    pub async fn cleanup_cancelled_files(&self, peer_id: &str, file_ids: &[Uuid]) {
        if let Some(conn) = self.try_get_connection(peer_id).await {
            conn.cleanup_cancelled_files(file_ids).await;
        }
    }

    pub async fn send_transaction_cancel(&self, peer_id: &str, transaction_id: Uuid) -> Result<()> {
        match self.try_get_connection(peer_id).await {
            Some(conn) => match conn.wait_data_channels_open().await {
                Ok(()) => {
                    conn.send_transaction_cancel(transaction_id, Some("User cancelled".to_string()))
                        .await
                }
                Err(e) => {
                    warn!(
                        event = "cancel_queued_connection_not_ready",
                        transaction_id = %transaction_id,
                        peer_id = %peer_id,
                        error = %e,
                        "Peer connection not ready, queuing cancel message"
                    );
                    self.queue_message_for_peer(
                        peer_id,
                        crate::core::persistence::QueuedMessageType::TransactionCancel {
                            transaction_id,
                        },
                    )
                }
            },
            None => {
                info!(
                    event = "cancel_queued_peer_offline",
                    transaction_id = %transaction_id,
                    peer_id = %peer_id,
                    "Peer offline, queuing cancel message for later delivery"
                );
                self.queue_message_for_peer(
                    peer_id,
                    crate::core::persistence::QueuedMessageType::TransactionCancel {
                        transaction_id,
                    },
                )
            }
        }
    }

    /// Retransmit specific chunks (or the whole file if `chunk_indices` is empty).
    pub async fn retransmit_chunks(
        &self,
        engine: &mut crate::core::engine::TransferEngine,
        peer_id: &str,
        file_id: Uuid,
        chunk_indices: &[u32],
    ) -> Result<()> {
        let conn = self.get_connection(peer_id).await?;

        let (txn_id, filesize, relative_path) =
            if let Some(txn) = engine.find_transaction_by_file_mut(&file_id) {
                let tf = txn
                    .files
                    .get(&file_id)
                    .ok_or_else(|| anyhow::anyhow!("File not found in transaction: {}", file_id))?;
                (txn.id, tf.filesize, tf.relative_path.clone())
            } else {
                return Err(anyhow::anyhow!(
                    "Transaction not found for file: {}",
                    file_id
                ));
            };

        let file_path = engine
            .get_source_path(&txn_id)
            .ok_or_else(|| anyhow::anyhow!("Source path not found for transaction: {}", txn_id))?;
        let path = std::path::PathBuf::from(file_path);

        if chunk_indices.is_empty() {
            conn.send_file(file_id, path, filesize, &relative_path, Some(txn_id))
                .await
        } else {
            conn.send_file_chunks(
                file_id,
                path,
                filesize,
                &relative_path,
                chunk_indices.to_vec(),
                Some(txn_id),
            )
            .await
        }
    }

    // ── Peers ────────────────────────────────────────────────────────────

    pub async fn send_remote_key_event(&self, peer_id: &str, key: &str) -> Result<()> {
        if let Some(conn) = self.try_get_connection(peer_id).await {
            conn.send_control(&ControlMessage::RemoteKeyEvent {
                key: key.to_string(),
            })
            .await?;
        }
        Ok(())
    }

    pub async fn list_remote_directory(&self, peer_id: &str, path: String) -> Result<()> {
        if let Some(conn) = self.try_get_connection(peer_id).await {
            conn.send_control(&ControlMessage::LsRequest { path })
                .await?;
        }
        Ok(())
    }

    pub async fn fetch_remote_path(
        &self,
        peer_id: &str,
        path: String,
        is_folder: bool,
    ) -> Result<()> {
        if let Some(conn) = self.try_get_connection(peer_id).await {
            conn.send_control(&ControlMessage::FetchRequest { path, is_folder })
                .await?;
        }
        Ok(())
    }

    pub async fn fetch_remote_path_with_dest(
        &self,
        peer_id: &str,
        path: String,
        is_folder: bool,
        dest_path: String,
    ) -> Result<()> {
        let _ = self.event_tx.send(AppEvent::Info(format!(
            "REMOTE_SAVE_PATH:{}:{}",
            peer_id, dest_path
        )));
        self.fetch_remote_path(peer_id, path, is_folder).await
    }

    pub async fn get_peer_key(&self, peer_id: &str) -> Option<[u8; 32]> {
        let peers = self.peers.lock().await;
        let entry = peers.get(peer_id)?;
        Some(entry.key_manager.current_key().await)
    }

    pub async fn get_peer_ticket(&self, peer_id: &str) -> Option<String> {
        self.peer_tickets.lock().await.get(peer_id).cloned()
    }

    pub async fn is_peer_connected(&self, peer_id: &str) -> bool {
        self.peers.lock().await.contains_key(peer_id)
    }

    /// Check if a peer is still alive by sending an AreYouAwake message.
    /// Returns Ok(()) if the peer responds, Err if the peer is not connected or fails to respond.
    pub async fn check_peer_liveness(&self, peer_id: &str) -> Result<()> {
        let conn = self.get_connection(peer_id).await?;
        self.check_alive_or_disconnect(peer_id, &conn).await
    }

    pub async fn wait_for_peer(&self, peer_id: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let poll_interval = Duration::from_millis(50);
        loop {
            if self.peers.lock().await.contains_key(peer_id) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(poll_interval).await;
        }
    }

    pub async fn prepare_file_reception(
        &self,
        peer_id: &str,
        files: Vec<(Uuid, std::path::PathBuf)>,
    ) -> Result<()> {
        let conn = self.get_connection(peer_id).await?;
        for (file_id, dest_path) in files {
            conn.register_file_destination(file_id, dest_path).await;
        }
        Ok(())
    }

    /// Register files that the receiver has pre-determined are identical to a
    /// locally-existing file.  When Metadata arrives for these files, the
    /// control handler sends `FileSkip` immediately — no data is transferred.
    pub async fn register_pre_skip_files(
        &self,
        peer_id: &str,
        files: Vec<(Uuid, std::path::PathBuf, [u8; 32])>,
    ) -> anyhow::Result<()> {
        let conn = self.get_connection(peer_id).await?;
        for (file_id, path, merkle_root) in files {
            conn.register_pre_skip(file_id, path, merkle_root).await;
        }
        Ok(())
    }

    pub async fn prepare_resume_bitmaps(
        &self,
        peer_id: &str,
        bitmaps: Vec<(Uuid, crate::core::pipeline::chunk::ChunkBitmap)>,
    ) -> Result<()> {
        let conn = self.get_connection(peer_id).await?;
        for (file_id, bitmap) in bitmaps {
            conn.register_resume_bitmap(file_id, bitmap).await;
        }
        Ok(())
    }

    pub async fn remove_peer(&self, peer_id: &str) {
        if let Some(entry) = self.peers.lock().await.remove(peer_id) {
            let _ = entry.connection.close().await;
        }
        info!(event = "peer_disconnected", peer = %short_id(peer_id), explicit = true, "Peer explicitly disconnected");
        let _ = self.event_tx.send(AppEvent::PeerDisconnected {
            peer_id: peer_id.to_string(),
            explicit: true,
        });
    }

    pub async fn cleanup_peer(&self, peer_id: &str) {
        if self.peers.lock().await.remove(peer_id).is_some() {
            debug!(event = "peer_cleanup", peer = %short_id(peer_id), "Stale peer entry removed (no close)");
        }
    }

    // ── Logging helpers ──────────────────────────────────────────────────

    fn connecting_notify(&self, peer_id: &str, status: &str) {
        let _ = self.event_tx.send(AppEvent::Connecting {
            peer_id: peer_id.to_string(),
            status: status.to_string(),
        });
    }

    fn send_info(&self, peer_id: &str, msg: &str) {
        let _ = self
            .event_tx
            .send(AppEvent::Info(format!("[{}] {}", short_id(peer_id), msg)));
    }
}
