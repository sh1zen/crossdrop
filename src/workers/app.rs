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
        }
    }
}

pub struct ChatMessage {
    pub from_me: bool,
    pub peer_id: String,
    pub text: String,
    pub timestamp: Instant,
}

pub struct PendingFileOffer {
    pub peer_id: String,
    pub file_id: Uuid,
    pub filename: String,
    pub filesize: u64,
}

pub struct PendingFolderOffer {
    pub peer_id: String,
    pub folder_id: Uuid,
    pub dirname: String,
    pub file_count: u32,
    pub total_size: u64,
}

pub struct AcceptingFileOffer {
    pub peer_id: String,
    pub file_id: Uuid,
    pub filename: String,
    pub filesize: u64,
    pub save_path_input: String,
}

pub struct AcceptingFolderOffer {
    pub peer_id: String,
    pub folder_id: Uuid,
    pub dirname: String,
    pub file_count: u32,
    pub total_size: u64,
    pub save_path_input: String,
}

#[derive(Clone, Copy, PartialEq)]
pub enum FileDirection {
    Sent,
    Received,
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
pub struct DataStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub files_sent: u64,
    pub files_received: u64,
}

pub struct App {
    pub mode: Mode,
    pub input: String,
    pub ticket: String,

    // Home
    pub menu_items: Vec<Mode>,
    pub menu_selected: usize,

    // Chat
    pub chat_history: Vec<ChatMessage>,
    pub chat_peer: Option<String>,
    // Peers
    pub peers: Vec<String>,
    pub selected_peer_idx: usize,

    // File offers
    pub pending_offers: Vec<PendingFileOffer>,
    pub accepting_file: Option<AcceptingFileOffer>,
    pub file_progress: HashMap<Uuid, (String, u32, u32)>,   // file_id -> (filename, received, total)
    pub send_progress: HashMap<Uuid, (String, u32, u32)>,   // file_id -> (filename, sent, total)

    // Folder offers
    pub pending_folder_offers: Vec<PendingFolderOffer>,
    pub accepting_folder: Option<AcceptingFolderOffer>,
    pub folder_progress: HashMap<Uuid, (u32, u32)>, // (files_completed, file_count)

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

    // Status
    pub status: String,
    pub errors: Vec<String>,
}

impl App {
    pub fn new(ticket: String) -> Self {
        Self {
            mode: Mode::Home,
            input: String::new(),
            ticket,
            menu_items: vec![
                Mode::Chat,
                Mode::Send,
                Mode::Connect,
                Mode::Peers,
                Mode::Files,
                Mode::Logs,
                Mode::Id,
            ],
            menu_selected: 0,
            chat_history: Vec::new(),
            chat_peer: None,
            peers: Vec::new(),
            selected_peer_idx: 0,
            pending_offers: Vec::new(),
            accepting_file: None,
            file_progress: HashMap::new(),
            send_progress: HashMap::new(),
            pending_folder_offers: Vec::new(),
            accepting_folder: None,
            folder_progress: HashMap::new(),
            file_history: Vec::new(),
            stats: DataStats::default(),
            connect_ticket_input: String::new(),
            send_file_path: String::new(),
            log_scroll: 0,
            status: String::new(),
            errors: Vec::new(),
        }
    }

    pub fn selected_peer(&self) -> Option<&String> {
        self.peers.get(self.selected_peer_idx)
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
    }

    pub fn push_error(&mut self, msg: impl Into<String>) {
        let s = msg.into();
        self.errors.push(s.clone());
        self.status = s;
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
        if self.chat_peer.as_deref() == Some(peer_id) {
            self.chat_peer = None;
        }
    }

    /// Count messages for a given peer (for unread indicators, etc.)
    pub fn unread_count_for(&self, peer_id: &str) -> usize {
        self.chat_history
            .iter()
            .filter(|m| !m.from_me && m.peer_id == peer_id)
            .count()
    }
}
