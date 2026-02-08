use crate::core::engine::TransferEngine;
use crate::core::transaction::{TransactionManager, TransactionManifest};
use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Mode {
    Home,
    Chat,
    Send,
    Connect,
    Peers,
    Files,
    Logs,
    Id,
    Settings,
    Remote,
}

impl Mode {
    pub fn label(&self) -> &'static str {
        match self {
            Mode::Home => "Home",
            Mode::Chat => "Chat",
            Mode::Send => "Send",
            Mode::Connect => "Connect",
            Mode::Peers => "Peers",
            Mode::Files => "Files",
            Mode::Logs => "Logs",
            Mode::Id => "My ID",
            Mode::Settings => "Settings",
            Mode::Remote => "Remote Access",
        }
    }
}

/// Who a chat message targets / comes from.
#[derive(Clone, PartialEq, Debug)]
pub enum ChatTarget {
    /// "Room" — broadcast to all peers
    Room,
    /// DM with a specific peer
    Peer(String),
}

impl ChatTarget {
    pub fn label<'a>(&'a self, peer_names: &'a HashMap<String, String>) -> String {
        match self {
            ChatTarget::Room => "Room".to_string(),
            ChatTarget::Peer(id) => {
                if let Some(name) = peer_names.get(id) {
                    name.clone()
                } else if id.len() > 12 {
                    format!("{}...", &id[..12])
                } else {
                    id.clone()
                }
            }
        }
    }
}

pub struct ChatMessage {
    pub from_me: bool,
    pub peer_id: String,
    pub text: String,
    pub timestamp: Instant,
    /// Which chat this message belongs to
    pub target: ChatTarget,
}

pub struct PendingFileOffer {
    pub peer_id: String,
    pub _file_id: Uuid,
    pub _filename: String,
    pub _filesize: u64,
    pub _total_size: u64,
}

pub struct PendingFolderOffer {
    pub peer_id: String,
    pub folder_id: Uuid,
    pub dirname: String,
    pub _file_count: u32,
    pub _total_size: u64,
}

/// A legacy pending file offer for backward compatibility.
pub struct AcceptingFileOffer {
    pub peer_id: String,
    pub file_id: Uuid,
    pub filename: String,
    pub filesize: u64,
    pub _total_size: u64,
    pub save_path_input: String,
    pub is_remote: bool,
    pub remote_path: Option<String>,
}

/// A legacy pending folder offer for backward compatibility.
pub struct AcceptingFolderOffer {
    pub peer_id: String,
    pub folder_id: Uuid,
    pub dirname: String,
    pub file_count: u32,
    pub total_size: u64,
    pub is_remote: bool,
    pub remote_path: Option<String>,
}

/// A pending transaction offer that the user needs to accept/reject.
/// Now delegates to TransferEngine's PendingIncoming — kept for backward
/// compatibility with popup code.
#[allow(dead_code)]
pub struct PendingTransactionOffer {
    pub peer_id: String,
    pub transaction_id: Uuid,
    pub display_name: String,
    pub manifest: TransactionManifest,
    pub total_size: u64,
    pub save_path_input: String,
    pub button_focus: usize,
    pub path_editing: bool,
}

#[derive(Clone, Copy, PartialEq)]
pub enum FileDirection {
    Sent,
    Received,
}

#[derive(Clone)]
pub enum FileTransferStatus {
    Rejected,
}

#[derive(Clone)]
pub struct FileRecord {
    pub direction: FileDirection,
    pub peer_id: String,
    pub filename: String,
    pub filesize: u64,
    pub path: Option<String>,
    pub timestamp: Instant,
}

#[derive(Default)]
#[allow(dead_code)]
pub struct DataStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub files_sent: u64,
    pub files_received: u64,
}

/// NOTE: DataStats above is kept for backward compatibility during transition.
/// The authoritative stats are in TransferEngine.stats().

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct RemoteEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

#[allow(dead_code)]
pub struct App {
    pub mode: Mode,
    pub input: String,
    pub ticket: String,

    // Home
    pub menu_selected: usize,

    // Chat
    pub chat_history: Vec<ChatMessage>,
    /// Current active chat target (Room or specific peer DM)
    pub chat_target: ChatTarget,
    /// Index in the sidebar chat list (0 = Room, 1.. = peers)
    pub chat_sidebar_idx: usize,

    // Peers
    pub peers: Vec<String>,
    pub peer_names: HashMap<String, String>,
    pub peer_keys: HashMap<String, [u8; 32]>,
    pub selected_peer_idx: usize,

    // File offers
    pub pending_offers: Vec<PendingFileOffer>,
    pub accepting_file: Option<AcceptingFileOffer>,
    pub file_progress: HashMap<Uuid, (String, u32, u32)>,
    pub send_progress: HashMap<Uuid, (String, u32, u32)>,
    pub rejected_transfers: HashMap<Uuid, (String, Option<String>)>, // file_id -> (filename, reason)
    pub file_transfer_status: HashMap<Uuid, FileTransferStatus>, // Track status of transfers
    pub file_offer_button_focus: usize, // 0 = Accept, 1 = Reject
    pub file_path_editing: bool,

    // Folder offers
    pub pending_folder_offers: Vec<PendingFolderOffer>,
    pub accepting_folder: Option<AcceptingFolderOffer>,
    pub folder_progress: HashMap<Uuid, (u32, u32)>,
    pub folder_offer_button_focus: usize, // 0 = Accept, 1 = Reject
    /// Maps file_id to folder_id for tracking which folder a file belongs to
    pub file_to_folder: HashMap<Uuid, Uuid>,
    /// Tracks folder transactions: folder_id -> (peer_id, dirname, total_size, file_count, received_count)
    pub folder_transactions: HashMap<Uuid, (String, String, u64, u32, u32)>,

    // File history
    pub file_history: Vec<FileRecord>,

    // Data statistics
    pub stats: DataStats,

    // Connect
    pub connect_ticket_input: String,

    // Send
    pub send_file_path: String,

    // Logs
    pub log_scroll: usize,

    // Files
    pub history_scroll: usize,
    pub files_peer_idx: usize,
    pub files_search: String,

    // Settings
    pub display_name: String,
    pub remote_access: bool,

    // Remote
    pub remote_peer: Option<String>,
    pub remote_path: String,
    pub remote_entries: Vec<RemoteEntry>,
    pub remote_selected: usize,

    // Status
    pub status: String,

    // Connecting status
    pub connecting_peers: HashMap<String, String>,

    // ── Transfer Engine ──────────────────────────────────────────────────
    /// The TransferEngine owns ALL transfer state and logic.
    /// No transfer logic exists outside the engine.
    pub engine: TransferEngine,

    // ── Legacy fields (kept for transition, delegate to engine) ──────────
    /// Legacy transaction manager reference — use engine.transactions() instead.
    pub transactions: TransactionManager,
    /// Legacy pending transaction — use engine.pending_incoming() instead.
    pub pending_transaction: Option<PendingTransactionOffer>,
}

impl App {
    pub fn new(ticket: String, display_name: Option<String>) -> Self {
        Self {
            mode: Mode::Home,
            input: String::new(),
            ticket,
            menu_selected: 0,
            chat_history: Vec::new(),
            chat_target: ChatTarget::Room,
            chat_sidebar_idx: 0,
            peers: Vec::new(),
            peer_names: HashMap::new(),
            peer_keys: HashMap::new(),
            selected_peer_idx: 0,
            pending_offers: Vec::new(),
            accepting_file: None,
            file_progress: HashMap::new(),
            send_progress: HashMap::new(),
            rejected_transfers: HashMap::new(),
            file_transfer_status: HashMap::new(),
            file_offer_button_focus: 0,
            file_path_editing: false,
            pending_folder_offers: Vec::new(),
            accepting_folder: None,
            folder_progress: HashMap::new(),
            folder_offer_button_focus: 0,
            file_to_folder: HashMap::new(),
            folder_transactions: HashMap::new(),
            file_history: Vec::new(),
            stats: DataStats::default(),
            connect_ticket_input: String::new(),
            send_file_path: String::new(),
            log_scroll: 0,
            history_scroll: 0,
            files_peer_idx: 0,
            files_search: String::new(),
            display_name: display_name.unwrap_or_else(|| "Anonymous".to_string()),
            // Remote access is disabled by default per security spec.
            remote_access: false,
            remote_peer: None,
            remote_path: "/".to_string(),
            remote_entries: Vec::new(),
            remote_selected: 0,
            status: String::new(),
            connecting_peers: HashMap::new(),
            engine: TransferEngine::new(),
            transactions: TransactionManager::new(),
            pending_transaction: None,
        }
    }

    /// Peer attualmente selezionato nella vista Files
    pub fn files_peer(&self) -> Option<&String> {
        self.peers.get(self.files_peer_idx)
    }

    /// File history filtrata per peer + search
    pub fn filtered_file_history(&self) -> Vec<&FileRecord> {
        let peer = match self.files_peer() {
            Some(p) => p,
            None => return Vec::new(),
        };

        let search = self.files_search.to_lowercase();

        self.file_history
            .iter()
            .filter(|r| &r.peer_id == peer)
            .filter(|r| {
                if search.is_empty() {
                    true
                } else {
                    r.filename.to_lowercase().contains(&search)
                }
            })
            .collect()
    }

    /// Build the list of chat targets for the sidebar: Room + each peer.
    pub fn chat_targets(&self) -> Vec<ChatTarget> {
        let mut targets = vec![ChatTarget::Room];
        for p in &self.peers {
            targets.push(ChatTarget::Peer(p.clone()));
        }
        targets
    }

    pub fn selected_peer(&self) -> Option<&String> {
        self.peers.get(self.selected_peer_idx)
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
    }

    pub fn push_error(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
    }

    pub fn add_peer(&mut self, peer_id: String) {
        if !self.peers.contains(&peer_id) {
            self.peers.push(peer_id);
        }
    }

    pub fn remove_peer(&mut self, peer_id: &str) {
        self.peers.retain(|p| p != peer_id);
        if self.selected_peer_idx >= self.peers.len() && !self.peers.is_empty() {
            self.selected_peer_idx = self.peers.len() - 1;
        }
        // If DM with this peer, go back to Room
        if self.chat_target == ChatTarget::Peer(peer_id.to_string()) {
            self.chat_target = ChatTarget::Room;
            self.chat_sidebar_idx = 0;
        }
        // Clean up all peer-related data
        self.peer_names.remove(peer_id);
        self.peer_keys.remove(peer_id);

        // Clean up pending offers from this peer
        self.pending_offers.retain(|o| o.peer_id != peer_id);
        self.pending_folder_offers.retain(|o| o.peer_id != peer_id);

        // Clean up folder transactions from this peer
        self.folder_transactions.retain(|_, (pid, _, _, _, _)| pid != peer_id);

        // Clear accepting state if it's from this peer
        if let Some(ref af) = self.accepting_file {
            if af.peer_id == peer_id {
                self.accepting_file = None;
            }
        }
        if let Some(ref af) = self.accepting_folder {
            if af.peer_id == peer_id {
                self.accepting_folder = None;
            }
        }

        // If we're viewing this peer's remote filesystem, exit remote mode
        if self.mode == Mode::Remote && self.remote_peer.as_deref() == Some(peer_id) {
            self.mode = Mode::Peers;
            self.remote_peer = None;
        }
    }

    /// Count unread messages in the Room chat.
    pub fn unread_room_count(&self) -> usize {
        self.chat_history
            .iter()
            .filter(|m| !m.from_me && m.target == ChatTarget::Room)
            .count()
    }

    /// Count unread DM messages for a specific peer.
    pub fn unread_dm_count(&self, peer_id: &str) -> usize {
        self.chat_history
            .iter()
            .filter(|m| !m.from_me && m.target == ChatTarget::Peer(peer_id.to_string()))
            .count()
    }
}
