use crate::core::connection::webrtc::{ConnectionMessage, SignalingMessage, WebRTCConnection};
use crate::core::connection::{Iroh, Ticket};
use crate::core::transaction::{ResumeInfo, TransactionManifest};
use crate::utils::sos::SignalOfStop;
use crate::workers::args::Args;
use anyhow::{Context, Result};
use iroh::SecretKey;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

// ── App Events ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum AppEvent {
    PeerConnected {
        peer_id: String,
    },
    PeerDisconnected {
        peer_id: String,
    },
    ChatReceived {
        peer_id: String,
        message: Vec<u8>,
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
    },
    SendProgress {
        _peer_id: String,
        file_id: Uuid,
        filename: String,
        sent_chunks: u32,
        total_chunks: u32,
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
        peer_id: String,
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
        peer_id: String,
        transaction_id: Uuid,
        dest_path: Option<String>,
    },
    TransactionRejected {
        peer_id: String,
        transaction_id: Uuid,
        reason: Option<String>,
    },
    TransactionCompleted {
        peer_id: String,
        transaction_id: Uuid,
    },
    TransactionCancelled {
        peer_id: String,
        transaction_id: Uuid,
        reason: Option<String>,
    },
    TransactionResumeRequested {
        peer_id: String,
        resume_info: ResumeInfo,
    },
    TransactionResumeAccepted {
        peer_id: String,
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
    #[allow(dead_code)]
    shared_key: [u8; 32],
}

#[derive(Clone)]
pub struct PeerNode {
    sos: SignalOfStop,
    args: Args,
    iroh: Arc<Iroh>,
    peers: Arc<Mutex<HashMap<String, PeerEntry>>>,
    event_tx: mpsc::UnboundedSender<AppEvent>,
    public_key: iroh::PublicKey,
    remote_access_tx: Arc<tokio::sync::watch::Sender<bool>>,
    remote_access_rx: tokio::sync::watch::Receiver<bool>,
}

// ── Key derivation ───────────────────────────────────────────────────────────

fn derive_peer_key(
    local_pk: &iroh::PublicKey,
    remote_pk: &iroh::PublicKey,
    session_key: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    // Use both public keys to ensure the shared key is specific to these two hosts.
    // Sorting the keys ensures both peers arrive at the same shared key regardless of who dialed.
    let mut pks = [*local_pk.as_bytes(), *remote_pk.as_bytes()];
    pks.sort();
    for pk in &pks {
        hasher.update(pk);
    }
    hasher.update(session_key);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

fn short_id(id: &str) -> String {
    if id.len() > 8 {
        format!("{}…", &id[..8])
    } else {
        id.to_string()
    }
}

// ── PeerNode impl ────────────────────────────────────────────────────────────

#[allow(dead_code)]
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
            event_tx,
            public_key,
            remote_access_tx: Arc::new(remote_access_tx),
            remote_access_rx,
        })
    }

    pub fn ticket(&self) -> Result<String> {
        self.iroh.ticket()
    }

    pub fn event_tx(&self) -> &mpsc::UnboundedSender<AppEvent> {
        &self.event_tx
    }

    fn create_connection_tx(
        peer_id: String,
        event_tx: mpsc::UnboundedSender<AppEvent>,
    ) -> mpsc::UnboundedSender<ConnectionMessage> {
        let (conn_tx, mut conn_rx) = mpsc::unbounded_channel::<ConnectionMessage>();
        let pid = peer_id;
        tokio::spawn(async move {
            while let Some(msg) = conn_rx.recv().await {
                let event = match msg {
                    ConnectionMessage::TextReceived(data) => AppEvent::ChatReceived {
                        peer_id: pid.clone(),
                        message: data,
                    },
                    ConnectionMessage::FileSaved { file_id, filename, path } => AppEvent::FileComplete {
                        peer_id: pid.clone(),
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
                        peer_id: pid.clone(),
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
                    } => AppEvent::FileProgress {
                        _peer_id: pid.clone(),
                        file_id,
                        filename,
                        received_chunks,
                        total_chunks,
                    },
                    ConnectionMessage::SendProgress {
                        file_id,
                        filename,
                        sent_chunks,
                        total_chunks,
                    } => AppEvent::SendProgress {
                        _peer_id: pid.clone(),
                        file_id,
                        filename,
                        sent_chunks,
                        total_chunks,
                    },
                    ConnectionMessage::SendComplete { file_id, success } => {
                        AppEvent::SendComplete {
                            peer_id: pid.clone(),
                            file_id,
                            success,
                        }
                    }
                    ConnectionMessage::FolderOffered {
                        folder_id,
                        dirname,
                        file_count,
                        total_size,
                    } => AppEvent::FolderOffered {
                        peer_id: pid.clone(),
                        folder_id,
                        dirname,
                        file_count,
                        total_size,
                    },
                    ConnectionMessage::FolderComplete { folder_id } => AppEvent::FolderComplete {
                        peer_id: pid.clone(),
                        folder_id,
                    },
                    ConnectionMessage::DisplayNameReceived(name) => AppEvent::DisplayNameReceived {
                        peer_id: pid.clone(),
                        name,
                    },
                    ConnectionMessage::Debug(s) => AppEvent::Info(s),
                    ConnectionMessage::Error(s) => AppEvent::Error(s),
                    ConnectionMessage::LsResponse { path, entries } => AppEvent::LsResponse {
                        peer_id: pid.clone(),
                        path,
                        entries,
                    },
                    ConnectionMessage::RemoteAccessDisabled => AppEvent::RemoteAccessDisabled {
                        peer_id: pid.clone(),
                    },
                    ConnectionMessage::RemoteFetchRequest { path, is_folder } => {
                        AppEvent::RemoteFetchRequest {
                            peer_id: pid.clone(),
                            path,
                            is_folder,
                        }
                    }
                    ConnectionMessage::FileCompleted { file_id, filename, path } => {
                        AppEvent::FileComplete {
                            peer_id: pid.clone(),
                            file_id,
                            filename,
                            path,
                        }
                    }
                    ConnectionMessage::FileRejected { file_id, reason } => {
                        AppEvent::FileRejected {
                            peer_id: pid.clone(),
                            file_id,
                            reason,
                        }
                    }
                    // ── Transaction-level events ─────────────────────────────
                    ConnectionMessage::TransactionRequested {
                        transaction_id,
                        display_name,
                        manifest,
                        total_size,
                    } => AppEvent::TransactionRequested {
                        peer_id: pid.clone(),
                        transaction_id,
                        display_name,
                        manifest,
                        total_size,
                    },
                    ConnectionMessage::TransactionAccepted {
                        transaction_id,
                        dest_path,
                    } => AppEvent::TransactionAccepted {
                        peer_id: pid.clone(),
                        transaction_id,
                        dest_path,
                    },
                    ConnectionMessage::TransactionRejected {
                        transaction_id,
                        reason,
                    } => AppEvent::TransactionRejected {
                        peer_id: pid.clone(),
                        transaction_id,
                        reason,
                    },
                    ConnectionMessage::TransactionCompleted { transaction_id } => {
                        AppEvent::TransactionCompleted {
                            peer_id: pid.clone(),
                            transaction_id,
                        }
                    }
                    ConnectionMessage::TransactionCancelled {
                        transaction_id,
                        reason,
                    } => AppEvent::TransactionCancelled {
                        peer_id: pid.clone(),
                        transaction_id,
                        reason,
                    },
                    ConnectionMessage::TransactionResumeRequested { resume_info } => {
                        AppEvent::TransactionResumeRequested {
                            peer_id: pid.clone(),
                            resume_info,
                        }
                    }
                    ConnectionMessage::TransactionResumeAccepted { transaction_id } => {
                        AppEvent::TransactionResumeAccepted {
                            peer_id: pid.clone(),
                            transaction_id,
                        }
                    }
                    ConnectionMessage::Disconnected => AppEvent::PeerDisconnected {
                        peer_id: pid.clone(),
                    },
                };
                if event_tx.send(event).is_err() {
                    break;
                }
            }
        });
        conn_tx
    }

    // ── Connect (outbound) ───────────────────────────────────────────────

    pub async fn connect_to(&self, ticket_str: String) -> Result<()> {
        let ticket = Ticket::parse(ticket_str)?;
        let peer_id = format!("{}", ticket.address.id);

        {
            let peers = self.peers.lock().await;
            if peers.contains_key(&peer_id) {
                let _ = self.event_tx.send(AppEvent::Info(format!(
                    "[{}] Already connected, skipping",
                    short_id(&peer_id)
                )));
                return Ok(());
            }
        }

        self.connecting_notify(&peer_id, "Resolving peer via Iroh...");
        self.send_info(&peer_id, "Establishing peer connection...");

        let connection = tokio::time::timeout(Duration::from_secs(30), self.iroh.connect(ticket))
            .await
            .context("Connection to peer timed out (Iroh)")?
            .context("Iroh connection failed")?;

        self.connecting_notify(&peer_id, "Opening handshake stream...");

        let (mut send_stream, mut recv_stream) =
            tokio::time::timeout(Duration::from_secs(15), connection.open_bi())
                .await
                .context("Opening handshake stream timed out")?
                .context("Failed to open handshake stream")?;

        self.connecting_notify(&peer_id, "Exchanging encryption key...");

        // Generate session key, derive per-peer key
        let mut session_key = [0u8; 32];
        rand::fill(&mut session_key);
        send_stream.write_all(&session_key).await?;
        let shared_key = derive_peer_key(&self.public_key, &connection.remote_id(), &session_key);

        self.connecting_notify(&peer_id, "Session key sent, per-peer key derived");

        let conn_tx = Self::create_connection_tx(peer_id.clone(), self.event_tx.clone());

        self.connecting_notify(&peer_id, "Creating WebRTC offer...");

        let (webrtc_conn, offer_msg) = WebRTCConnection::create_offer(
            Some(conn_tx),
            shared_key,
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

        self.peers.lock().await.insert(
            peer_id.clone(),
            PeerEntry {
                connection: webrtc_conn,
                shared_key,
            },
        );

        tracing::info!("Peer connected: {}", peer_id);
        self.connecting_notify(&peer_id, "Peer fully connected!");
        self.connecting_notify(&peer_id, "Peer connected!");
        let _ = self.event_tx.send(AppEvent::PeerConnected { peer_id });
        Ok(())
    }

    // ── Accept (inbound) ─────────────────────────────────────────────────

    async fn handle_incoming(&self, incoming_conn: iroh::endpoint::Incoming) -> Result<()> {
        let connection = incoming_conn.accept()?.await?;
        let peer_id = format!("{}", connection.remote_id());

        {
            let peers = self.peers.lock().await;
            if peers.contains_key(&peer_id) {
                return Ok(());
            }
        }

        self.send_info(&peer_id, "Incoming connection..");

        let (mut send_stream, mut recv_stream) =
            tokio::time::timeout(Duration::from_secs(15), connection.accept_bi())
                .await
                .context("Accepting handshake stream timed out")?
                .context("Failed to accept handshake stream")?;

        let mut session_key = [0u8; 32];
        recv_stream.read_exact(&mut session_key).await?;
        let shared_key = derive_peer_key(&self.public_key, &connection.remote_id(), &session_key);

        self.send_info(&peer_id, "Session key received, per-peer key derived");

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
        let conn_tx = Self::create_connection_tx(peer_id.clone(), self.event_tx.clone());

        let (webrtc_conn, answer_msg) = WebRTCConnection::accept_offer(
            offer_msg,
            Some(conn_tx),
            shared_key,
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

        self.peers.lock().await.insert(
            peer_id.clone(),
            PeerEntry {
                connection: webrtc_conn,
                shared_key,
            },
        );

        tracing::info!("Peer connected: {}", peer_id);
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
                            let _ = this
                                .event_tx
                                .send(AppEvent::Error(format!("Incoming error: {e}")));
                        }
                    });
                }
                Ok(Err(e)) => {
                    let _ = self
                        .event_tx
                        .send(AppEvent::Error(format!("Accept error: {e}")));
                }
            }
        }
    }

    // ── Chat ─────────────────────────────────────────────────────────────

    /// Send a chat message to a specific peer.
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
                tracing::warn!("Failed to send chat to {}: {}", peer_id, e);
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
                tracing::warn!("Failed to send display name to {}: {}", peer_id, e);
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

    pub async fn get_peer_key(&self, peer_id: &str) -> Option<[u8; 32]> {
        self.peers
            .lock()
            .await
            .get(peer_id)
            .map(|entry| entry.shared_key)
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
        tracing::info!("Peer disconnected: {}", peer_id);
        let _ = self.event_tx.send(AppEvent::PeerDisconnected {
            peer_id: peer_id.to_string(),
        });
    }

    // ── Helpers ──────────────────────────────────────────────────────────

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
