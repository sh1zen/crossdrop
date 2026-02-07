use crate::app::Args;
use crate::core::connection::webrtc::{ConnectionMessage, SignalingMessage, WebRTCConnection};
use crate::core::connection::{Iroh, Ticket};
use crate::utils::sos::SignalOfStop;
use anyhow::Result;
use iroh::SecretKey;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

/// Events sent from PeerNode to the TUI.
#[derive(Debug, Clone)]
pub enum AppEvent {
    PeerConnected { peer_id: String },
    PeerDisconnected { peer_id: String },
    ChatReceived { peer_id: String, message: Vec<u8> },
    FileOffered { peer_id: String, file_id: Uuid, filename: String, filesize: u64 },
    FileProgress { peer_id: String, file_id: Uuid, filename: String, received_chunks: u32, total_chunks: u32 },
    SendProgress { peer_id: String, file_id: Uuid, filename: String, sent_chunks: u32, total_chunks: u32 },
    SendComplete { peer_id: String, file_id: Uuid, success: bool },
    FileComplete { peer_id: String, filename: String, path: String },
    FolderOffered { peer_id: String, folder_id: Uuid, dirname: String, file_count: u32, total_size: u64 },
    FolderComplete { peer_id: String, folder_id: Uuid },
    Error(String),
    Info(String),
}

struct PeerEntry {
    connection: Arc<WebRTCConnection>,
}

#[derive(Clone)]
pub struct PeerNode {
    sos: SignalOfStop,
    args: Args,
    iroh: Arc<Iroh>,
    peers: Arc<Mutex<HashMap<String, PeerEntry>>>,
    event_tx: mpsc::UnboundedSender<AppEvent>,
}

impl PeerNode {
    pub async fn new(
        secret_key: SecretKey,
        args: Args,
        sos: SignalOfStop,
        event_tx: mpsc::UnboundedSender<AppEvent>,
    ) -> Result<Self> {
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

        Ok(Self {
            sos,
            args,
            iroh,
            peers: Arc::new(Mutex::new(HashMap::new())),
            event_tx,
        })
    }

    pub fn ticket(&self) -> Result<String> {
        self.iroh.ticket()
    }

    pub fn event_tx(&self) -> &mpsc::UnboundedSender<AppEvent> {
        &self.event_tx
    }

    /// Create an mpsc sender that bridges ConnectionMessage -> AppEvent for a specific peer.
    fn create_connection_tx(
        peer_id: String,
        event_tx: mpsc::UnboundedSender<AppEvent>,
    ) -> mpsc::UnboundedSender<ConnectionMessage> {
        let (conn_tx, mut conn_rx) = mpsc::unbounded_channel::<ConnectionMessage>();
        let pid = peer_id.clone();
        tokio::spawn(async move {
            while let Some(msg) = conn_rx.recv().await {
                let event = match msg {
                    ConnectionMessage::TextReceived(data) => AppEvent::ChatReceived {
                        peer_id: pid.clone(),
                        message: data,
                    },
                    ConnectionMessage::FileSaved { filename, path } => AppEvent::FileComplete {
                        peer_id: pid.clone(),
                        filename,
                        path,
                    },
                    ConnectionMessage::FileOffered {
                        file_id,
                        filename,
                        filesize,
                    } => AppEvent::FileOffered {
                        peer_id: pid.clone(),
                        file_id,
                        filename,
                        filesize,
                    },
                    ConnectionMessage::FileProgress {
                        file_id,
                        filename,
                        received_chunks,
                        total_chunks,
                    } => AppEvent::FileProgress {
                        peer_id: pid.clone(),
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
                        peer_id: pid.clone(),
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
                    ConnectionMessage::Debug(s) => AppEvent::Info(s),
                    ConnectionMessage::Error(s) => AppEvent::Error(s),
                };
                if event_tx.send(event).is_err() {
                    break;
                }
            }
        });
        conn_tx
    }

    /// Connect to a remote peer via ticket string.
    pub async fn connect_to(&self, ticket_str: String) -> Result<()> {
        let ticket = Ticket::parse(ticket_str)?;
        let peer_id = format!("{}", ticket.address.id);

        // Avoid duplicate connections
        {
            let peers = self.peers.lock().await;
            if peers.contains_key(&peer_id) {
                return Ok(());
            }
        }

        let _ = self
            .event_tx
            .send(AppEvent::Info(format!("Connecting to {peer_id}...")));

        let connection = self.iroh.connect(ticket).await?;
        let (mut send_stream, mut recv_stream) = connection.open_bi().await?;

        let conn_tx = Self::create_connection_tx(peer_id.clone(), self.event_tx.clone());

        // Create WebRTC offer
        let (webrtc_conn, offer_msg) =
            WebRTCConnection::create_offer(Some(conn_tx)).await?;

        let webrtc_conn = Arc::new(webrtc_conn);

        // Send offer via iroh stream
        let offer_data = serde_json::to_vec(&offer_msg)?;
        send_stream.write_all(&offer_data).await?;
        send_stream.finish()?;

        // Receive answer
        let answer_data = recv_stream.read_to_end(1024 * 1024).await?;
        let answer_msg: SignalingMessage = serde_json::from_slice(&answer_data)?;
        webrtc_conn.set_answer(answer_msg).await?;

        // Complete handshake
        webrtc_conn.wait_connected().await?;

        self.peers.lock().await.insert(
            peer_id.clone(),
            PeerEntry {
                connection: webrtc_conn,
            },
        );

        let _ = self
            .event_tx
            .send(AppEvent::PeerConnected { peer_id });

        Ok(())
    }

    /// Handle an incoming connection.
    async fn handle_incoming(&self, incoming_conn: iroh::endpoint::Incoming) -> Result<()> {
        let connection = incoming_conn.accept()?.await?;
        let peer_id = format!("{}", connection.remote_id());

        // Avoid duplicates
        {
            let peers = self.peers.lock().await;
            if peers.contains_key(&peer_id) {
                return Ok(());
            }
        }

        // Incoming side: accept the bidirectional stream opened by caller
        let (mut send_stream, mut recv_stream) = connection.accept_bi().await?;

        // Receive offer
        let offer_data = recv_stream.read_to_end(1024 * 1024).await?;
        let offer_msg: SignalingMessage = serde_json::from_slice(&offer_data)?;

        let conn_tx = Self::create_connection_tx(peer_id.clone(), self.event_tx.clone());

        // Accept offer and produce answer
        let (webrtc_conn, answer_msg) =
            WebRTCConnection::accept_offer(offer_msg, Some(conn_tx)).await?;

        let webrtc_conn = Arc::new(webrtc_conn);

        // Send answer back
        let answer_data = serde_json::to_vec(&answer_msg)?;
        send_stream.write_all(&answer_data).await?;
        send_stream.finish()?;

        // Complete handshake
        webrtc_conn.wait_connected().await?;

        self.peers.lock().await.insert(
            peer_id.clone(),
            PeerEntry {
                connection: webrtc_conn,
            },
        );

        let _ = self
            .event_tx
            .send(AppEvent::PeerConnected { peer_id });

        Ok(())
    }

    /// Run the accept loop for incoming connections. Stops when sos is cancelled.
    pub async fn run_accept_loop(self) {
        loop {
            let sos = self.sos.clone();
            let iroh = self.iroh.clone();
            let result = sos.select(async move { iroh.wait_connection().await }).await;
            match result {
                Err(()) => break, // sos cancelled
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

    /// Send a chat message to a specific peer.
    pub async fn send_chat(&self, peer_id: &str, message: &str) -> Result<()> {
        let peers = self.peers.lock().await;
        let entry = peers
            .get(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?;
        entry
            .connection
            .send_message(message.as_bytes().to_vec())
            .await
    }

    /// Offer a file to a specific peer. Returns whether it was accepted.
    pub async fn offer_file(&self, peer_id: &str, file_path: &str) -> Result<bool> {
        let file_bytes = tokio::fs::read(file_path).await?;
        let filename = std::path::Path::new(file_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());

        let conn = {
            let peers = self.peers.lock().await;
            let entry = peers
                .get(peer_id)
                .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?;
            entry.connection.clone()
        };

        conn.send_file_with_offer(file_bytes, filename).await
    }

    /// Respond to a file offer.
    pub async fn respond_to_file_offer(
        &self,
        peer_id: &str,
        file_id: Uuid,
        accepted: bool,
        dest_path: Option<String>,
    ) -> Result<()> {
        let peers = self.peers.lock().await;
        let entry = peers
            .get(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?;
        entry
            .connection
            .send_file_response(file_id, accepted, dest_path)
            .await
    }

    /// Offer a folder to a specific peer. Returns whether it was accepted.
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
            let entry = peers
                .get(peer_id)
                .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?;
            entry.connection.clone()
        };

        let (folder_id, accepted) = conn.offer_folder(&dirname, file_count, total_size).await?;
        if !accepted {
            return Ok(false);
        }

        conn.send_folder_files(folder_id, files).await?;
        Ok(true)
    }

    /// Respond to a folder offer.
    pub async fn respond_to_folder_offer(
        &self,
        peer_id: &str,
        folder_id: Uuid,
        accepted: bool,
    ) -> Result<()> {
        let peers = self.peers.lock().await;
        let entry = peers
            .get(peer_id)
            .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_id))?;
        entry.connection.send_folder_response(folder_id, accepted).await
    }

    /// List connected peer IDs.
    pub async fn list_peers(&self) -> Vec<String> {
        let peers = self.peers.lock().await;
        peers.keys().cloned().collect()
    }

    /// Remove a peer.
    pub async fn remove_peer(&self, peer_id: &str) {
        let mut peers = self.peers.lock().await;
        if let Some(entry) = peers.remove(peer_id) {
            let _ = entry.connection.close().await;
        }
        let _ = self.event_tx.send(AppEvent::PeerDisconnected {
            peer_id: peer_id.to_string(),
        });
    }
}

/// Recursively collect all files under `current`, storing (relative_path, bytes).
/// `root` is the top-level folder (used to compute relative paths that include the folder name).
/// Skips symlinks.
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
            // Compute relative path including the folder name
            // e.g. root = /home/user/myfolder -> relative = myfolder/sub/file.txt
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
