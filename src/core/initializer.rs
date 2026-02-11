use crate::core::connection::crypto::SessionKeyManager;
use crate::core::connection::webrtc::{ConnectionMessage, SignalingMessage, WebRTCConnection};
use crate::core::connection::{Iroh, Ticket};
use crate::core::transaction::{ResumeInfo, TransactionManifest};
use crate::utils::sos::SignalOfStop;
use crate::workers::args::Args;
use anyhow::{Context, Result};
use iroh::SecretKey;
use std::collections::{HashMap, HashSet};
use std::path::Path;
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
    },
    PeerDisconnected {
        peer_id: String,
        /// If true, the user explicitly disconnected this peer (full removal).
        /// If false, the connection was lost (transition to offline).
        explicit: bool,
    },
    ChatReceived {
        peer_id: String,
        message: Vec<u8>,
    },
    /// Direct (1-to-1) message received from a peer.
    DmReceived {
        peer_id: String,
        message: Vec<u8>,
    },
    /// Ephemeral typing indicator from a peer.
    TypingReceived {
        peer_id: String,
    },
    FileOffered {
        peer_id: String,
        file_id: Uuid,
        filename: String,
        filesize: u64,
        total_size: u64, // Total for aggregated progress
    },
    FileProgress {
        _peer_id: String,
        file_id: Uuid,
        filename: String,
        received_chunks: u32,
        total_chunks: u32,
        /// Bytes received on the wire (post-compression/encryption).
        wire_bytes: u64,
    },
    SendProgress {
        _peer_id: String,
        file_id: Uuid,
        filename: String,
        sent_chunks: u32,
        total_chunks: u32,
        /// Bytes sent on the wire (post-compression/encryption).
        wire_bytes: u64,
    },
    SendComplete {
        peer_id: String,
        file_id: Uuid,
        success: bool,
    },
    FileComplete {
        peer_id: String,
        file_id: Uuid,
        filename: String,
        path: String,
    },
    FileRejected {
        file_id: Uuid,
        reason: Option<String>,
    },
    FolderOffered {
        peer_id: String,
        folder_id: Uuid,
        dirname: String,
        file_count: u32,
        total_size: u64,
    },
    FolderComplete {
        peer_id: String,
        folder_id: Uuid,
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
    // ── Transaction-level events ─────────────────────────────────────────
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
    /// Timestamp of the last received pong (heartbeat).
    #[allow(dead_code)]
    last_pong: Arc<Mutex<Instant>>,
}

#[derive(Clone)]
pub struct PeerNode {
    sos: SignalOfStop,
    args: Args,
    iroh: Arc<Iroh>,
    peers: Arc<Mutex<HashMap<String, PeerEntry>>>,
    /// Stores the ticket string used/generated for each peer connection.
    peer_tickets: Arc<Mutex<HashMap<String, String>>>,
    /// Guards against duplicate concurrent connection attempts to the same peer.
    connecting: Arc<Mutex<HashSet<String>>>,
    event_tx: mpsc::UnboundedSender<AppEvent>,
    public_key: iroh::PublicKey,
    remote_access_tx: Arc<tokio::sync::watch::Sender<bool>>,
    remote_access_rx: tokio::sync::watch::Receiver<bool>,
}

// ── Key derivation ───────────────────────────────────────────────────────────

fn short_id(id: &str) -> String {
    if id.len() > 8 {
        format!("{}…", &id[..8])
    } else {
        id.to_string()
    }
}

/// Public accessor for truncated peer IDs in log messages.
pub fn short_id_pub(id: &str) -> String {
    short_id(id)
}

/// RAII guard that removes a peer_id from the `connecting` set on drop.
struct ConnectingGuard {
    connecting: Arc<Mutex<HashSet<String>>>,
    peer_id: String,
}

impl Drop for ConnectingGuard {
    fn drop(&mut self) {
        let connecting = self.connecting.clone();
        let peer_id = std::mem::take(&mut self.peer_id);
        // Use try_lock to avoid blocking in the Drop impl.
        // If the lock is contended we spawn a task to clean up.
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
/// Returns `None` for `PongReceived`, which is handled separately in the
/// connection task (it updates the heartbeat timestamp rather than being
/// forwarded to the application layer).
fn map_connection_to_app_event(pid: &str, msg: ConnectionMessage) -> Option<AppEvent> {
    let event = match msg {
        ConnectionMessage::TextReceived(data) => AppEvent::ChatReceived {
            peer_id: pid.to_string(),
            message: data,
        },
        ConnectionMessage::DmReceived(data) => AppEvent::DmReceived {
            peer_id: pid.to_string(),
            message: data,
        },
        ConnectionMessage::TypingReceived => AppEvent::TypingReceived {
            peer_id: pid.to_string(),
        },
        ConnectionMessage::FileSaved { file_id, filename, path } => AppEvent::FileComplete {
            peer_id: pid.to_string(),
            file_id,
            filename,
            path,
        },
        ConnectionMessage::FileOffered {
            file_id,
            filename,
            filesize,
            total_size,
        } => AppEvent::FileOffered {
            peer_id: pid.to_string(),
            file_id,
            filename,
            filesize,
            total_size,
        },
        ConnectionMessage::FileProgress {
            file_id,
            filename,
            received_chunks,
            total_chunks,
            wire_bytes,
        } => AppEvent::FileProgress {
            _peer_id: pid.to_string(),
            file_id,
            filename,
            received_chunks,
            total_chunks,
            wire_bytes,
        },
        ConnectionMessage::SendProgress {
            file_id,
            filename,
            sent_chunks,
            total_chunks,
            wire_bytes,
        } => AppEvent::SendProgress {
            _peer_id: pid.to_string(),
            file_id,
            filename,
            sent_chunks,
            total_chunks,
            wire_bytes,
        },
        ConnectionMessage::SendComplete { file_id, success } => AppEvent::SendComplete {
            peer_id: pid.to_string(),
            file_id,
            success,
        },
        ConnectionMessage::FolderOffered {
            folder_id,
            dirname,
            file_count,
            total_size,
        } => AppEvent::FolderOffered {
            peer_id: pid.to_string(),
            folder_id,
            dirname,
            file_count,
            total_size,
        },
        ConnectionMessage::FolderComplete { folder_id } => AppEvent::FolderComplete {
            peer_id: pid.to_string(),
            folder_id,
        },
        ConnectionMessage::DisplayNameReceived(name) => AppEvent::DisplayNameReceived {
            peer_id: pid.to_string(),
            name,
        },
        ConnectionMessage::Debug(s) => AppEvent::Info(s),
        ConnectionMessage::Error(s) => AppEvent::Error(s),
        ConnectionMessage::LsResponse { path, entries } => AppEvent::LsResponse {
            peer_id: pid.to_string(),
            path,
            entries,
        },
        ConnectionMessage::RemoteAccessDisabled => AppEvent::RemoteAccessDisabled {
            peer_id: pid.to_string(),
        },
        ConnectionMessage::RemoteFetchRequest { path, is_folder } => {
            AppEvent::RemoteFetchRequest {
                peer_id: pid.to_string(),
                path,
                is_folder,
            }
        }
        ConnectionMessage::FileCompleted { file_id, filename, path } => AppEvent::FileComplete {
            peer_id: pid.to_string(),
            file_id,
            filename,
            path,
        },
        ConnectionMessage::FileRejected { file_id, reason } => AppEvent::FileRejected {
            file_id,
            reason,
        },
        // ── Transaction-level events ─────────────────────────────────────
        ConnectionMessage::TransactionRequested {
            transaction_id,
            display_name,
            manifest,
            total_size,
        } => AppEvent::TransactionRequested {
            peer_id: pid.to_string(),
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
                peer_id: pid.to_string(),
                resume_info,
            }
        }
        ConnectionMessage::TransactionResumeAccepted { transaction_id } => {
            AppEvent::TransactionResumeAccepted { transaction_id }
        }
        ConnectionMessage::Disconnected => AppEvent::PeerDisconnected {
            peer_id: pid.to_string(),
            explicit: false, // Connection lost, not user-initiated
        },
        ConnectionMessage::PongReceived => return None,
    };
    Some(event)
}

// ── PeerNode impl ────────────────────────────────────────────────────────────

impl PeerNode {
    pub async fn new(
        secret_key: SecretKey,
        args: Args,
        sos: SignalOfStop,
        event_tx: mpsc::UnboundedSender<AppEvent>,
    ) -> Result<Self> {
        let public_key = secret_key.public();
        let iroh = Arc::new(
            Iroh::new(
                secret_key.clone(),
                args.relay.clone(),
                args.ipv4_addr,
                args.ipv6_addr,
                args.port,
            )
            .await?,
        );

        let (remote_access_tx, remote_access_rx) = tokio::sync::watch::channel(args.remote_access);

        Ok(Self {
            sos,
            args,
            iroh,
            peers: Arc::new(Mutex::new(HashMap::new())),
            peer_tickets: Arc::new(Mutex::new(HashMap::new())),
            connecting: Arc::new(Mutex::new(HashSet::new())),
            event_tx,
            public_key,
            remote_access_tx: Arc::new(remote_access_tx),
            remote_access_rx,
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

    fn create_connection_tx(
        peer_id: String,
        event_tx: mpsc::UnboundedSender<AppEvent>,
        last_pong: Arc<Mutex<Instant>>,
    ) -> mpsc::UnboundedSender<ConnectionMessage> {
        let (conn_tx, mut conn_rx) = mpsc::unbounded_channel::<ConnectionMessage>();
        let pid = peer_id;
        let mut disconnect_sent = false;
        tokio::spawn(async move {
            while let Some(msg) = conn_rx.recv().await {
                // Handle PongReceived locally — not an app-level event
                if matches!(msg, ConnectionMessage::PongReceived) {
                    *last_pong.lock().await = Instant::now();
                    continue;
                }

                // Reset last_pong on ANY valid inbound message — not just Pong.
                // This prevents heartbeat timeout when the peer is actively
                // sending data (chunks, ACKs, control) but pong responses are
                // delayed due to load.
                *last_pong.lock().await = Instant::now();

                // Deduplicate Disconnected events — only forward the first one.
                // WebRTC can fire Disconnected followed by Closed in sequence,
                // or the same state multiple times. Processing duplicates
                // causes cascading state transitions in the engine.
                if matches!(msg, ConnectionMessage::Disconnected) {
                    if disconnect_sent {
                        debug!(event = "duplicate_disconnect_suppressed", peer = %pid, "Suppressing duplicate Disconnected event");
                        continue;
                    }
                    disconnect_sent = true;
                }

                if let Some(event) = map_connection_to_app_event(&pid, msg) {
                    if event_tx.send(event).is_err() {
                        break;
                    }
                }
            }
        });
        conn_tx
    }

    // ── Connect (outbound) ───────────────────────────────────────────────

    pub async fn connect_to(&self, ticket_str: String) -> Result<()> {
        let ticket = Ticket::parse(ticket_str.clone())?;
        let peer_id = format!("{}", ticket.address.id);

        // Check if already connected or already attempting to connect
        {
            let peers = self.peers.lock().await;
            if peers.contains_key(&peer_id) {
                debug!(event = "connect_skipped", peer = %short_id(&peer_id), "Already connected, skipping");
                let _ = self.event_tx.send(AppEvent::Info(format!(
                    "[{}] Already connected, skipping",
                    short_id(&peer_id)
                )));
                return Ok(());
            }
        }
        {
            let mut connecting = self.connecting.lock().await;
            if !connecting.insert(peer_id.clone()) {
                debug!(event = "connect_skipped", peer = %short_id(&peer_id), "Connection already in progress, skipping");
                return Ok(());
            }
        }

        // Ensure we remove from the connecting set when we're done (success or failure)
        let _guard = ConnectingGuard {
            connecting: self.connecting.clone(),
            peer_id: peer_id.clone(),
        };

        self.connecting_notify(&peer_id, "Resolving peer via Iroh...");
        self.send_info(&peer_id, "Establishing peer connection...");

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

        // ECDH key exchange: offerer side
        let key_manager =
            crate::core::connection::crypto::handshake_offerer(
                &mut send_stream,
                &mut recv_stream,
                &self.public_key,
                &connection.remote_id(),
            )
                .await
                .context("ECDH handshake failed (offerer)")?;

        let shared_key = key_manager.inner();

        self.connecting_notify(&peer_id, "ECDH handshake complete, session key derived");

        let last_pong = Arc::new(Mutex::new(Instant::now()));
        let conn_tx = Self::create_connection_tx(peer_id.clone(), self.event_tx.clone(), last_pong.clone());

        self.connecting_notify(&peer_id, "Creating WebRTC offer...");

        let (webrtc_conn, offer_msg) = WebRTCConnection::create_offer(
            Some(conn_tx),
            shared_key,
            Some(key_manager.clone()),
            self.remote_access_rx.clone(),
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

        self.connecting_notify(&peer_id, "Data channels open (control + data)");

        if let Some(name) = &self.args.display_name {
            let _ = webrtc_conn.send_display_name(name.clone()).await;
        }

        // Atomic check-and-insert: if another connection (inbound) won the race, drop ours
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
                    last_pong: last_pong.clone(),
                },
            );
        }

        // Spawn heartbeat monitor
        self.spawn_heartbeat(peer_id.clone(), webrtc_conn.clone(), last_pong);

        // Spawn hourly key rotation task (offerer is the rotation initiator)
        {
            let wc = webrtc_conn.clone();
            let pid = peer_id.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(crate::core::connection::crypto::KEY_ROTATION_INTERVAL).await;
                    match wc.initiate_key_rotation().await {
                        Ok(()) => info!(event = "key_rotation_scheduled", peer = %short_id(&pid), "Hourly key rotation initiated"),
                        Err(e) => {
                            warn!(event = "key_rotation_failed", peer = %short_id(&pid), error = %e, "Key rotation failed");
                            break;
                        }
                    }
                }
            });
        }

        // Store the ticket used for this outbound connection
        self.peer_tickets.lock().await.insert(peer_id.clone(), ticket_str);

        tracing::info!("Peer connected: {}", peer_id);
        self.connecting_notify(&peer_id, "Peer fully connected!");
        let _ = self.event_tx.send(AppEvent::PeerConnected { peer_id });
        Ok(())
    }

    // ── Accept (inbound) ─────────────────────────────────────────────────

    async fn handle_incoming(&self, incoming_conn: iroh::endpoint::Incoming) -> Result<()> {
        let connection = incoming_conn.accept()?.await?;
        let peer_id = format!("{}", connection.remote_id());

        // If we already have an entry for this peer, evict the stale connection.
        // This handles the case where the remote peer went offline and came back
        // before our heartbeat detected the disappearance.
        // NOTE: We do NOT call close() on the evicted connection. The old
        // heartbeat task will detect the staleness via Arc::ptr_eq and stop
        // on its own. Calling close() would trigger WebRTC state-change
        // callbacks that could cascade into spurious PeerDisconnected events.
        {
            let mut peers = self.peers.lock().await;
            if let Some(_old) = peers.remove(&peer_id) {
                info!(event = "stale_evict", peer = %short_id(&peer_id), "Evicting stale connection for incoming reconnect (no close)");
            }
        }

        self.send_info(&peer_id, "Incoming connection..");

        let (mut send_stream, mut recv_stream) =
            tokio::time::timeout(Duration::from_secs(15), connection.accept_bi())
                .await
                .context("Accepting handshake stream timed out")?
                .context("Failed to accept handshake stream")?;

        // ECDH key exchange: answerer side
        let key_manager =
            crate::core::connection::crypto::handshake_answerer(
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
        let last_pong = Arc::new(Mutex::new(Instant::now()));
        let conn_tx = Self::create_connection_tx(peer_id.clone(), self.event_tx.clone(), last_pong.clone());

        let (webrtc_conn, answer_msg) = WebRTCConnection::accept_offer(
            offer_msg,
            Some(conn_tx),
            shared_key,
            Some(key_manager.clone()),
            self.remote_access_rx.clone(),
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

        if let Some(name) = &self.args.display_name {
            let _ = webrtc_conn.send_display_name(name.clone()).await;
        }

        // Insert the new connection, evicting any stale entry that appeared in the meantime.
        // Do NOT close the old connection — let it drop naturally.
        {
            let mut peers = self.peers.lock().await;
            if let Some(_old) = peers.remove(&peer_id) {
                debug!(event = "stale_evict_late", peer = %short_id(&peer_id), direction = "inbound", "Evicting stale entry during insert (no close)");
            }
            peers.insert(
                peer_id.clone(),
                PeerEntry {
                    connection: webrtc_conn.clone(),
                    key_manager,
                    last_pong: last_pong.clone(),
                },
            );
        }

        // Spawn heartbeat monitor
        self.spawn_heartbeat(peer_id.clone(), webrtc_conn, last_pong);

        // Generate a minimal ticket from the inbound peer's NodeId for future reconnection
        if let Some(ticket) = crate::core::peer_registry::PeerRegistry::ticket_from_node_id(&peer_id) {
            self.peer_tickets.lock().await.insert(peer_id.clone(), ticket);
        }

        tracing::info!(event = "peer_connected", peer = %short_id(&peer_id), direction = "inbound", "Peer connected (inbound)");
        self.send_info(&peer_id, "✓ Peer fully connected!");
        let _ = self.event_tx.send(AppEvent::PeerConnected { peer_id });
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

    /// Send a chat message to a specific peer (room/broadcast protocol).
    #[allow(dead_code)]
    pub async fn send_chat(&self, peer_id: &str, message: &str) -> Result<()> {
        let peers = self.peers.lock().await;
        let entry = peers
            .get(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?;
        tracing::debug!("Sending DM to {}: {}", peer_id, message);
        entry
            .connection
            .send_message(message.as_bytes().to_vec())
            .await
    }

    /// Send a direct (1-to-1) message using the DM protocol.
    pub async fn send_dm(&self, peer_id: &str, message: &str) -> Result<()> {
        let peers = self.peers.lock().await;
        let entry = peers
            .get(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?;
        tracing::debug!("Sending DM (direct) to {}: {}", peer_id, message);
        entry
            .connection
            .send_dm(message.as_bytes().to_vec())
            .await
    }

    /// Send a typing indicator to a specific peer.
    pub async fn send_typing(&self, peer_id: &str) -> Result<()> {
        let peers = self.peers.lock().await;
        if let Some(entry) = peers.get(peer_id) {
            entry.connection.send_typing().await
        } else {
            Ok(())
        }
    }

    /// Broadcast a typing indicator to all connected peers.
    pub async fn broadcast_typing(&self) -> Result<()> {
        let peers = self.peers.lock().await;
        for (_, entry) in peers.iter() {
            let _ = entry.connection.send_typing().await;
        }
        Ok(())
    }

    /// Broadcast a chat message to ALL connected peers.
    pub async fn broadcast_chat(&self, message: &str) -> Result<Vec<String>> {
        let peers = self.peers.lock().await;
        let peer_count = peers.len();
        let mut sent_to = Vec::new();
        for (peer_id, entry) in peers.iter() {
            if let Err(e) = entry
                .connection
                .send_message(message.as_bytes().to_vec())
                .await
            {
                warn!(event = "chat_send_failure", peer = %short_id(peer_id), error = %e, "Failed to send chat message");
            } else {
                sent_to.push(peer_id.clone());
            }
        }
        tracing::debug!("Broadcasting chat to {} peers: {}", peer_count, message);
        Ok(sent_to)
    }

    /// Broadcast display name to all connected peers.
    pub async fn broadcast_display_name(&self, name: String) {
        let peers = self.peers.lock().await;
        for (peer_id, entry) in peers.iter() {
            if let Err(e) = entry.connection.send_display_name(name.clone()).await {
                warn!(event = "display_name_send_failure", peer = %short_id(peer_id), error = %e, "Failed to send display name");
            }
        }
    }

    // ── Files ────────────────────────────────────────────────────────────

    pub async fn offer_file(&self, peer_id: &str, file_path: &str) -> Result<bool> {
        let file_bytes = tokio::fs::read(file_path).await?;
        let filename = std::path::Path::new(file_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());

        let conn = {
            let peers = self.peers.lock().await;
            peers
                .get(peer_id)
                .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?
                .connection
                .clone()
        };

        // Ensure filename doesn't exceed reasonable length to avoid JSON encoding issues
        let safe_filename = if filename.len() > 1024 {
            format!(
                "{}...{}",
                &filename[..500],
                &filename[filename.len() - 500..]
            )
        } else {
            filename.clone()
        };

        tracing::info!(
            "Offering file '{}' to {} ({} bytes)",
            safe_filename,
            peer_id,
            file_bytes.len()
        );
        conn.send_file_with_offer(file_bytes, safe_filename).await
    }

    pub async fn respond_to_file_offer(
        &self,
        peer_id: &str,
        file_id: Uuid,
        accepted: bool,
        dest_path: Option<String>,
    ) -> Result<()> {
        let peers = self.peers.lock().await;
        peers
            .get(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?
            .connection
            .send_file_response(file_id, accepted, dest_path)
            .await
    }

    // ── Folders ──────────────────────────────────────────────────────────

    pub async fn offer_folder(&self, peer_id: &str, folder_path: &str) -> Result<bool> {
        let root = Path::new(folder_path).to_path_buf();
        let dirname = root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "folder".to_string());

        let mut files = Vec::new();
        let mut total_size: u64 = 0;
        collect_folder_files(&root, &root, &mut files, &mut total_size).await?;

        if files.is_empty() {
            return Err(anyhow::anyhow!("Folder is empty"));
        }

        let file_count = files.len() as u32;
        let conn = {
            let peers = self.peers.lock().await;
            peers
                .get(peer_id)
                .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?
                .connection
                .clone()
        };

        tracing::info!(
            "Offering folder '{}' to {} ({} files, {} bytes)",
            dirname,
            peer_id,
            file_count,
            total_size
        );
        let (folder_id, accepted) = conn.offer_folder(&dirname, file_count, total_size).await?;
        if !accepted {
            return Ok(false);
        }
        conn.send_folder_files(folder_id, files).await?;
        Ok(true)
    }

    pub async fn respond_to_folder_offer(
        &self,
        peer_id: &str,
        folder_id: Uuid,
        accepted: bool,
    ) -> Result<()> {
        let peers = self.peers.lock().await;
        peers
            .get(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?
            .connection
            .send_folder_response(folder_id, accepted)
            .await
    }

    // ── Direct file send (Transaction protocol) ─────────────────────────

    /// Send a single file directly using a Transaction file_id.
    /// No offer/response negotiation — the receiver has already accepted
    /// via TransactionResponse and registered a destination via PrepareReceive.
    pub async fn send_file_data(
        &self,
        peer_id: &str,
        file_id: Uuid,
        file_path: &str,
        filename: &str,
    ) -> Result<()> {
        let file_bytes = tokio::fs::read(file_path).await?;

        let conn = {
            let peers = self.peers.lock().await;
            peers
                .get(peer_id)
                .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?
                .connection
                .clone()
        };

        tracing::info!(
            "Sending file '{}' ({} bytes) to {} [txn file_id={}]",
            filename,
            file_bytes.len(),
            peer_id,
            file_id
        );
        conn.send_file(file_id, file_bytes, filename).await
    }

    /// Send a single file directly, resuming from a given chunk offset.
    /// Chunks before `start_chunk` are hashed but not transmitted.
    pub async fn send_file_data_resuming(
        &self,
        peer_id: &str,
        file_id: Uuid,
        file_path: &str,
        filename: &str,
        start_chunk: u32,
    ) -> Result<()> {
        let file_bytes = tokio::fs::read(file_path).await?;

        let conn = {
            let peers = self.peers.lock().await;
            peers
                .get(peer_id)
                .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?
                .connection
                .clone()
        };

        tracing::info!(
            "Resuming file '{}' ({} bytes) to {} [txn file_id={}, start_chunk={}]",
            filename,
            file_bytes.len(),
            peer_id,
            file_id,
            start_chunk,
        );
        conn.send_file_resuming(file_id, file_bytes, filename, start_chunk).await
    }

    /// Send multiple files for a folder transfer using Transaction file_ids.
    /// Uses a parallel preparation pipeline: while file N is sending,
    /// files N+1..N+k are being read from disk asynchronously.
    /// Memory is bounded by prefetching at most MAX_PREFETCH_FILES files
    /// whose cumulative size stays under MAX_PREFETCH_BYTES.
    pub async fn send_folder_data(
        &self,
        peer_id: &str,
        folder_path: &str,
        file_entries: Vec<(Uuid, String)>, // (file_id, relative_path)
    ) -> Result<()> {
        const MAX_PREFETCH_FILES: usize = 24;
        const MAX_PREFETCH_BYTES: u64 = 256 * 1024 * 1024; // 256 MB

        let root = std::path::Path::new(folder_path);
        let root_parent = root.parent().unwrap_or(root);

        let conn = {
            let peers = self.peers.lock().await;
            peers
                .get(peer_id)
                .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?
                .connection
                .clone()
        };

        tracing::info!(
            "Sending folder '{}' ({} files) to {} via Transaction protocol (parallel prep)",
            folder_path,
            file_entries.len(),
            peer_id
        );

        // Semaphore-style backpressure: the producer tracks how many bytes
        // and how many files are sitting in the channel waiting to be sent.
        // When either limit is hit the producer pauses until the consumer
        // drains enough items.
        let prefetch_bytes = Arc::new(tokio::sync::Mutex::new(0u64));
        let prefetch_notify = Arc::new(tokio::sync::Notify::new());

        // Channel capacity set to MAX_PREFETCH_FILES — the producer will
        // self-throttle via the byte counter before filling it completely
        // for large files, but the bounded channel still caps item count.
        // Option<Vec<u8>>: None = file read failed, Some = real data.
        let (prep_tx, mut prep_rx) =
            mpsc::channel::<(Uuid, String, Option<Vec<u8>>)>(MAX_PREFETCH_FILES);

        // Spawn file preparation task (producer)
        let root_parent_owned = root_parent.to_path_buf();
        let entries_for_producer = file_entries;
        let pb = prefetch_bytes.clone();
        let pn = prefetch_notify.clone();
        tokio::spawn(async move {
            for (file_id, relative_path) in entries_for_producer {
                let full_path = root_parent_owned.join(&relative_path);
                match tokio::fs::read(&full_path).await {
                    Ok(file_bytes) => {
                        let len = file_bytes.len() as u64;

                        // Wait until there is room under the byte budget
                        loop {
                            let current = *pb.lock().await;
                            // Allow at least one file through even if it
                            // alone exceeds the budget (current == 0).
                            if current == 0 || current + len <= MAX_PREFETCH_BYTES {
                                break;
                            }
                            pn.notified().await;
                        }

                        *pb.lock().await += len;

                        if prep_tx
                            .send((file_id, relative_path.clone(), Some(file_bytes)))
                            .await
                            .is_err()
                        {
                            // Consumer dropped — abort preparation
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to read file for folder transfer: {} — {}",
                            full_path.display(),
                            e
                        );
                        // Signal read failure so the consumer can emit a
                        // SendComplete{success:false} for this file_id.
                        if prep_tx
                            .send((file_id, relative_path.clone(), None))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            // Drop prep_tx to signal end of preparation
        });

        // Consumer: send files as they become available from the preparation pipeline.
        // This overlaps disk I/O (preparation of N+1) with network I/O (sending N).
        // Errors are handled per-file so one failure does not orphan the rest.
        let peer_id_owned = peer_id.to_string();
        while let Some((file_id, relative_path, file_bytes)) = prep_rx.recv().await {
            match file_bytes {
                None => {
                    // File read failed in producer — notify engine so the
                    // transaction can still conclude.
                    tracing::error!(
                        "Skipping file '{}' [file_id={}]: read failed",
                        relative_path,
                        file_id
                    );
                    let _ = self.event_tx.send(AppEvent::SendComplete {
                        peer_id: peer_id_owned.clone(),
                        file_id,
                        success: false,
                    });
                }
                Some(data) => {
                    let len = data.len() as u64;
                    tracing::debug!(
                        "Sending file '{}' ({} bytes) [file_id={}]",
                        relative_path,
                        len,
                        file_id
                    );
                    if let Err(e) = conn
                        .send_file(file_id, data, relative_path.as_str())
                        .await
                    {
                        tracing::error!(
                            "Failed to send file '{}' [file_id={}]: {}",
                            relative_path,
                            file_id,
                            e
                        );
                        // Notify engine about the failure so the transaction
                        // does not hang waiting for this file.
                        let _ = self.event_tx.send(AppEvent::SendComplete {
                            peer_id: peer_id_owned.clone(),
                            file_id,
                            success: false,
                        });
                    }

                    // Release byte budget so the producer can prefetch more
                    *prefetch_bytes.lock().await -= len;
                    prefetch_notify.notify_one();
                }
            }
        }

        Ok(())
    }

    // ── Transaction-level API ────────────────────────────────────────────

    /// Send a transaction request to a peer (new protocol).
    pub async fn send_transaction_request(
        &self,
        peer_id: &str,
        transaction_id: Uuid,
        display_name: String,
        manifest: TransactionManifest,
        total_size: u64,
    ) -> Result<()> {
        let peers = self.peers.lock().await;
        peers
            .get(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?
            .connection
            .send_transaction_request(transaction_id, display_name, manifest, total_size)
            .await
    }

    /// Respond to a transaction request (accept/reject).
    pub async fn respond_to_transaction(
        &self,
        peer_id: &str,
        transaction_id: Uuid,
        accepted: bool,
        dest_path: Option<String>,
        reject_reason: Option<String>,
    ) -> Result<()> {
        let peers = self.peers.lock().await;
        peers
            .get(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?
            .connection
            .send_transaction_response(transaction_id, accepted, dest_path, reject_reason)
            .await
    }

    /// Accept a resume request for a transaction.
    pub async fn accept_transaction_resume(
        &self,
        peer_id: &str,
        transaction_id: Uuid,
    ) -> Result<()> {
        let peers = self.peers.lock().await;
        peers
            .get(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?
            .connection
            .send_transaction_resume_response(transaction_id, true)
            .await
    }

    /// Send a resume request to the peer (receiver side, requesting retransmission).
    pub async fn send_resume_request(
        &self,
        peer_id: &str,
        _transaction_id: Uuid,
        resume_info: ResumeInfo,
    ) -> Result<()> {
        let peers = self.peers.lock().await;
        peers
            .get(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?
            .connection
            .send_control(
                &crate::core::connection::webrtc::ControlMessage::TransactionResumeRequest {
                    resume_info,
                },
            )
            .await
    }

    /// Notify the peer that a transaction has completed successfully.
    pub async fn send_transaction_complete(
        &self,
        peer_id: &str,
        transaction_id: Uuid,
    ) -> Result<()> {
        let peers = self.peers.lock().await;
        peers
            .get(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?
            .connection
            .send_control(
                &crate::core::connection::webrtc::ControlMessage::TransactionComplete {
                    transaction_id,
                },
            )
            .await
    }

    // ── Peers ────────────────────────────────────────────────────────────

    pub fn update_remote_access(&self, enabled: bool) {
        let _ = self.remote_access_tx.send(enabled);
    }

    pub async fn list_remote_directory(&self, peer_id: &str, path: String) -> Result<()> {
        let peers = self.peers.lock().await;
        if let Some(peer) = peers.get(peer_id) {
            peer.connection
                .send_control(&crate::core::connection::webrtc::ControlMessage::LsRequest { path })
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
        let peers = self.peers.lock().await;
        if let Some(peer) = peers.get(peer_id) {
            peer.connection
                .send_control(
                    &crate::core::connection::webrtc::ControlMessage::FetchRequest {
                        path,
                        is_folder,
                    },
                )
                .await?;
        }
        Ok(())
    }

    /// Like `fetch_remote_path` but also stores a destination path in the app
    /// event channel so the UI can auto-accept the incoming file to the right
    /// location.  The dest_path is carried as a special Info event.
    pub async fn fetch_remote_path_with_dest(
        &self,
        peer_id: &str,
        path: String,
        is_folder: bool,
        dest_path: String,
    ) -> Result<()> {
        // Notify the UI to store the save path for auto-accept
        let _ = self.event_tx.send(AppEvent::Info(
            format!("REMOTE_SAVE_PATH:{}:{}", peer_id, dest_path),
        ));
        self.fetch_remote_path(peer_id, path, is_folder).await
    }

    pub async fn get_peer_key(&self, peer_id: &str) -> Option<[u8; 32]> {
        let peers = self.peers.lock().await;
        if let Some(entry) = peers.get(peer_id) {
            Some(entry.key_manager.current_key().await)
        } else {
            None
        }
    }

    /// Get the ticket string stored for a peer (used for persistence).
    pub async fn get_peer_ticket(&self, peer_id: &str) -> Option<String> {
        self.peer_tickets.lock().await.get(peer_id).cloned()
    }

    /// Check if a peer currently has an active connection in the peers map.
    /// Used to detect stale disconnect events from evicted connections.
    pub async fn is_peer_connected(&self, peer_id: &str) -> bool {
        self.peers.lock().await.contains_key(peer_id)
    }

    /// Pre-register file destinations so that incoming Metadata frames can
    /// look up the correct save path. Called by the TransferEngine when
    /// accepting an incoming Transaction.
    pub async fn prepare_file_reception(
        &self,
        peer_id: &str,
        files: Vec<(Uuid, std::path::PathBuf)>,
    ) -> Result<()> {
        let peers = self.peers.lock().await;
        let entry = peers
            .get(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?;
        for (file_id, dest_path) in files {
            entry
                .connection
                .register_file_destination(file_id, dest_path)
                .await;
        }
        Ok(())
    }

    pub async fn remove_peer(&self, peer_id: &str) {
        let mut peers = self.peers.lock().await;
        if let Some(entry) = peers.remove(peer_id) {
            let _ = entry.connection.close().await;
        }
        info!(event = "peer_disconnected", peer = %short_id(peer_id), explicit = true, "Peer explicitly disconnected");
        let _ = self.event_tx.send(AppEvent::PeerDisconnected {
            peer_id: peer_id.to_string(),
            explicit: true, // User-initiated disconnect
        });
    }

    /// Remove a stale peer entry from the internal map without firing events.
    /// Called when a connection-lost event is detected so the peer slot is freed
    /// and the remote side can reconnect inbound.
    ///
    /// NOTE: We intentionally do NOT call `close()` on the connection here.
    /// The heartbeat already removed the entry (or the connection is truly
    /// dead). Calling `close()` on a dead connection is pointless, and on a
    /// live connection it would generate cascading state-change callbacks.
    /// The `WebRTCConnection` will be cleaned up when its last `Arc` ref drops.
    pub async fn cleanup_peer(&self, peer_id: &str) {
        let mut peers = self.peers.lock().await;
        if peers.remove(peer_id).is_some() {
            debug!(event = "peer_cleanup", peer = %short_id(peer_id), "Stale peer entry removed (no close)");
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    /// Spawn a background heartbeat task that periodically pings the peer
    /// and fires a disconnect event if no pong is received within the timeout.
    fn spawn_heartbeat(
        &self,
        peer_id: String,
        conn: Arc<WebRTCConnection>,
        last_pong: Arc<Mutex<Instant>>,
    ) {
        use crate::core::connection::webrtc::ControlMessage;

        const PING_INTERVAL: Duration = Duration::from_secs(10);
        const PONG_TIMEOUT: Duration = Duration::from_secs(60);
        /// Number of consecutive ping send failures before declaring offline.
        /// A single transient failure (e.g. control channel momentarily not
        /// open under heavy load) must NOT trigger disconnection.
        const MAX_CONSECUTIVE_FAILURES: u32 = 3;

        let event_tx = self.event_tx.clone();
        let peers = self.peers.clone();

        tokio::spawn(async move {
            let mut consecutive_failures: u32 = 0;

            loop {
                tokio::time::sleep(PING_INTERVAL).await;

                // Send ping — tolerate transient failures with debouncing.
                // Only declare dead after MAX_CONSECUTIVE_FAILURES in a row.
                if conn.send_control(&ControlMessage::Ping).await.is_err() {
                    consecutive_failures += 1;
                    warn!(
                        event = "heartbeat_send_failed",
                        peer = %short_id(&peer_id),
                        consecutive = consecutive_failures,
                        max = MAX_CONSECUTIVE_FAILURES,
                        "Ping send failed (transient?)"
                    );
                    if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                        info!(event = "heartbeat_dead", peer = %short_id(&peer_id), "Peer confirmed dead after {} consecutive ping failures", consecutive_failures);
                        break;
                    }
                    continue;
                } else {
                    // Ping succeeded — reset failure counter
                    if consecutive_failures > 0 {
                        debug!(event = "heartbeat_recovered", peer = %short_id(&peer_id), previous_failures = consecutive_failures, "Ping recovered after transient failures");
                    }
                    consecutive_failures = 0;
                }

                // Check if last pong is recent enough.
                // Use a generous timeout to account for load-induced delays.
                let elapsed = last_pong.lock().await.elapsed();
                if elapsed > PONG_TIMEOUT {
                    warn!(
                        event = "heartbeat_timeout",
                        peer = %short_id(&peer_id),
                        elapsed_secs = elapsed.as_secs(),
                        "No pong received within timeout, peer disappeared"
                    );
                    break;
                }
            }

            // Clean up the stale peer entry and fire disconnect.
            // IMPORTANT: only remove if the current entry is the SAME connection
            // we are monitoring (by Arc pointer identity). If the peer reconnected
            // while we were sleeping, peers[peer_id] holds the new connection — we
            // must NOT remove or close it.
            let mut should_fire_disconnect = false;
            {
                let mut peers_guard = peers.lock().await;
                if let Some(entry) = peers_guard.get(&peer_id) {
                    if Arc::ptr_eq(&entry.connection, &conn) {
                        // Same connection — safe to remove.
                        // Drop without close() — the WebRTCConnection drop will
                        // handle cleanup. Calling close() would trigger state
                        // callbacks that could cascade (though wait_connected()
                        // has replaced them, we avoid it defensively).
                        peers_guard.remove(&peer_id);
                        should_fire_disconnect = true;
                    } else {
                        // A newer connection has replaced ours — do nothing
                        info!(event = "heartbeat_stale_skip", peer = %short_id(&peer_id), "Heartbeat for stale connection, new connection exists — skipping cleanup");
                    }
                }
            }
            if should_fire_disconnect {
                let _ = event_tx.send(AppEvent::PeerDisconnected {
                    peer_id,
                    explicit: false,
                });
            }
        });
    }

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

// ── Folder collection ────────────────────────────────────────────────────────

async fn collect_folder_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<(String, Vec<u8>)>,
    total_size: &mut u64,
) -> Result<()> {
    let mut entries = tokio::fs::read_dir(current).await?;
    while let Some(entry) = entries.next_entry().await? {
        let file_type = entry.file_type().await?;
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            Box::pin(collect_folder_files(root, &path, files, total_size)).await?;
        } else if file_type.is_file() {
            let bytes = tokio::fs::read(&path).await?;
            *total_size += bytes.len() as u64;
            let root_parent = root.parent().unwrap_or(root);
            let relative = path
                .strip_prefix(root_parent)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            files.push((relative, bytes));
        }
    }
    Ok(())
}
