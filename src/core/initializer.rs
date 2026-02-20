use crate::core::connection::crypto::SessionKeyManager;
use crate::core::connection::webrtc::{
    ConnectionMessage, ControlMessage, SignalingMessage, WebRTCConnection,
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
        sent_chunks: u32,
        _total_chunks: u32,
        wire_bytes: u64,
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
        entries: Vec<crate::workers::app::RemoteEntry>,
    },
    RemoteAccessDisabled {
        peer_id: String,
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
    ChunkRetransmitRequested {
        peer_id: String,
        file_id: Uuid,
        chunk_indices: Vec<u32>,
    },
    TransactionCompleteAcked {
        peer_id: String,
        transaction_id: Uuid,
    },
    FileReceivedAck {
        file_id: Uuid,
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
    remote_access_tx: Arc<tokio::sync::watch::Sender<bool>>,
    remote_access_rx: tokio::sync::watch::Receiver<bool>,
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
            sent_chunks,
            total_chunks,
            wire_bytes,
        } => AppEvent::SendProgress {
            _peer_id: peer_id(),
            file_id,
            _filename: filename,
            sent_chunks,
            _total_chunks: total_chunks,
            wire_bytes,
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
        ConnectionMessage::ChunkRetransmitRequested {
            file_id,
            chunk_indices,
        } => AppEvent::ChunkRetransmitRequested {
            peer_id: peer_id(),
            file_id,
            chunk_indices,
        },
        ConnectionMessage::TransactionCompleteAcked { transaction_id } => {
            AppEvent::TransactionCompleteAcked {
                peer_id: peer_id(),
                transaction_id,
            }
        }
        ConnectionMessage::FileReceivedAck { file_id } => AppEvent::FileReceivedAck { file_id },
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

        let (remote_access_tx, remote_access_rx) = tokio::sync::watch::channel(args.remote_access);
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
            remote_access_tx: Arc::new(remote_access_tx),
            remote_access_rx,
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
        format!("{}", self.public_key)
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

                if let Some(event) = map_connection_to_app_event(&peer_id, msg) {
                    if event_tx.send(event).is_err() {
                        break;
                    }
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

    /// Check liveness; on failure, emit `PeerDisconnected` and propagate the error.
    async fn check_alive_or_disconnect(
        &self,
        peer_id: &str,
        conn: &WebRTCConnection,
    ) -> Result<()> {
        if let Err(e) = conn.check_peer_alive().await {
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
        let peer_id = format!("{}", ticket.address.id);

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
            self.remote_access_rx.clone(),
            awake_notify,
            self.wire_tx.clone(),
            self.wire_rx.clone(),
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
            if peers.contains_key(&peer_id) {
                debug!(event = "connect_race_lost", peer = %short_id(&peer_id), direction = "outbound", "Another connection completed first, dropping duplicate");
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
        let peer_id = format!("{}", connection.remote_id());

        // Evict any stale entry without calling close() to avoid spurious events.
        {
            let mut peers = self.peers.lock().await;
            if peers.remove(&peer_id).is_some() {
                info!(event = "stale_evict", peer = %short_id(&peer_id), "Evicting stale connection for incoming reconnect (no close)");
            }
        }

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
            self.remote_access_rx.clone(),
            awake_notify,
            self.wire_tx.clone(),
            self.wire_rx.clone(),
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
            if peers.remove(&peer_id).is_some() {
                debug!(event = "stale_evict_late", peer = %short_id(&peer_id), direction = "inbound", "Evicting stale entry during insert (no close)");
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
                            let _ = this
                                .event_tx
                                .send(AppEvent::Error(format!("Incoming error: {e}")));
                        }
                    });
                }
                Ok(Err(e)) => {
                    error!(event = "accept_error", error = %e, "Accept loop error");
                    let _ = self
                        .event_tx
                        .send(AppEvent::Error(format!("Accept error: {e}")));
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
    ) -> Result<()> {
        let filesize = tokio::fs::metadata(file_path).await?.len();
        let conn = self.get_connection(peer_id).await?;
        self.check_alive_or_disconnect(peer_id, &conn).await?;

        info!(
            "Sending file '{}' ({} bytes) to {} [txn file_id={}]",
            filename, filesize, peer_id, file_id
        );
        conn.send_file(
            file_id,
            std::path::PathBuf::from(file_path),
            filesize,
            filename,
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
    ) -> Result<()> {
        let filesize = tokio::fs::metadata(file_path).await?.len();
        let conn = self.get_connection(peer_id).await?;
        self.check_alive_or_disconnect(peer_id, &conn).await?;

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
        )
        .await
    }

    pub async fn send_folder_data(
        &self,
        peer_id: &str,
        folder_path: &str,
        file_entries: Vec<(Uuid, String)>,
    ) -> Result<()> {
        use crate::core::config::FILE_ACK_POLL_INTERVAL;

        let folder_root = std::path::Path::new(folder_path);

        let conn = self.get_connection(peer_id).await?;
        self.check_alive_or_disconnect(peer_id, &conn).await?;

        info!(
            "Sending folder '{}' ({} files) to {} via Transaction protocol (async streaming)",
            folder_path,
            file_entries.len(),
            peer_id
        );

        let peer_id_owned = peer_id.to_string();
        let total_files = file_entries.len();
        let semaphore = &conn.file_ack_semaphore;

        for (idx, (file_id, relative_path)) in file_entries.into_iter().enumerate() {
            // Acquire semaphore, probing liveness on each timeout.
            loop {
                match tokio::time::timeout(FILE_ACK_POLL_INTERVAL, semaphore.acquire()).await {
                    Ok(Ok(permit)) => {
                        permit.forget();
                        break;
                    }
                    Ok(Err(_)) => return Err(anyhow::anyhow!("File ACK semaphore closed")),
                    Err(_timeout) => {
                        if let Err(e) = conn.check_peer_alive().await {
                            warn!(
                                event = "folder_send_peer_offline",
                                peer = %short_id(peer_id),
                                file_idx = idx,
                                error = %e,
                                "Peer not responding while waiting for file ACKs"
                            );
                            let _ = self.event_tx.send(AppEvent::PeerDisconnected {
                                peer_id: peer_id_owned.clone(),
                                explicit: false,
                            });
                            return Err(anyhow::anyhow!(
                                "Peer not responding while waiting for file ACKs after {} files",
                                idx
                            ));
                        }
                        debug!(
                            "Peer {} still alive, waiting for file ACK permits ({}/{})",
                            short_id(peer_id),
                            idx,
                            total_files
                        );
                    }
                }
            }

            let full_path = folder_root.join(&relative_path);

            let filesize = match tokio::fs::metadata(&full_path).await {
                Ok(m) => m.len(),
                Err(e) => {
                    error!(
                        "Failed to stat file for folder transfer: {} — {}",
                        full_path.display(),
                        e
                    );
                    let _ = self.event_tx.send(AppEvent::SendComplete {
                        _peer_id: peer_id_owned.clone(),
                        file_id,
                        success: false,
                    });
                    semaphore.add_permits(1);
                    continue;
                }
            };

            debug!(
                "Sending file '{}' ({} bytes) [file_id={}]",
                relative_path, filesize, file_id
            );

            if let Err(e) = conn
                .send_file(file_id, full_path, filesize, &relative_path)
                .await
            {
                let err_str = e.to_string();
                error!(
                    "Failed to send file '{}' [file_id={}]: {}",
                    relative_path, file_id, err_str
                );
                let _ = self.event_tx.send(AppEvent::SendComplete {
                    _peer_id: peer_id_owned.clone(),
                    file_id,
                    success: false,
                });
                semaphore.add_permits(1);
                if err_str.contains("permanently closed") || err_str.contains("not available") {
                    let remaining = total_files.saturating_sub(idx + 1);
                    error!(
                        "Connection to peer lost — aborting remaining {} file(s) in folder transfer",
                        remaining
                    );
                    break;
                }
            }
        }

        Ok(())
    }

    // ── Transaction API ──────────────────────────────────────────────────

    pub async fn deliver_pending_messages(&self, peer_id: &str) -> Result<()> {
        use crate::core::persistence::{Persistence, QueuedMessageType};

        let persistence =
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

        let mut persistence = persistence;
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

    pub async fn send_transaction_complete_ack(
        &self,
        peer_id: &str,
        transaction_id: Uuid,
    ) -> Result<()> {
        let conn = self.get_connection(peer_id).await?;
        conn.send_control(&ControlMessage::TransactionCompleteAck { transaction_id })
            .await
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
            conn.send_file(file_id, path, filesize, &relative_path)
                .await
        } else {
            conn.send_file_chunks(
                file_id,
                path,
                filesize,
                &relative_path,
                chunk_indices.to_vec(),
            )
            .await
        }
    }

    // ── Peers ────────────────────────────────────────────────────────────

    pub fn update_remote_access(&self, enabled: bool) {
        let _ = self.remote_access_tx.send(enabled);
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
