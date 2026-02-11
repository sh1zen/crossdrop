use crate::core::engine::TransferEngine;
use crate::core::transaction::TransactionManager;
use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;

/// Connectivity state of a peer — orthogonal to identity and chat state.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum PeerStatus {
    Online,
    Offline,
}

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

// ── Logical Message Model ────────────────────────────────────────────────────

/// Unique, non-encrypted message identifier.
pub type MessageId = Uuid;

/// Who sent the message.
#[derive(Clone, Debug, PartialEq)]
pub enum MessageSender {
    Me,
    Peer(String),
}

/// A single canonical message entry.
///
/// When a message is sent to multiple peers in a room, only **one** `Message`
/// is stored.  Transport still sends individually to each peer.
#[derive(Clone, Debug)]
pub struct Message {
    /// Unique, plain-text identifier.
    pub id: MessageId,
    /// Who sent this message.
    pub sender: MessageSender,
    /// Textual content.
    pub text: String,
    /// Absolute timestamp formatted at creation (e.g. `"14:32"`).
    pub timestamp: String,
    /// Which chat context this message belongs to.
    pub target: ChatTarget,
    /// For outgoing room broadcasts: list of peer IDs the message was
    /// sent to.  Empty for incoming messages.
    #[allow(dead_code)]
    pub recipients: Vec<String>,
    /// Monotonic instant kept for internal ordering only.
    #[allow(dead_code)]
    pub created_at: Instant,
}

/// The logical message table.  Rendering consumes this — not network events.
pub struct MessageTable {
    messages: Vec<Message>,
}

impl MessageTable {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
        }
    }

    /// Insert a message, deduplicating by `id`.
    pub fn insert(&mut self, message: Message) {
        if !self.messages.iter().any(|m| m.id == message.id) {
            self.messages.push(message);
        }
    }

    /// All messages for a given chat target, in insertion order.
    pub fn messages_for(&self, target: &ChatTarget) -> Vec<&Message> {
        self.messages.iter().filter(|m| &m.target == target).collect()
    }

    /// Clear messages for a target (`/clear` command).
    pub fn clear_target(&mut self, target: &ChatTarget) {
        self.messages.retain(|m| &m.target != target);
    }

    /// Total number of messages across all targets.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.messages.len()
    }
}

// ── Unread Tracker ───────────────────────────────────────────────────────────

/// State-based unread message counters (not inferred from UI).
pub struct UnreadTracker {
    room: usize,
    peers: HashMap<String, usize>,
}

impl UnreadTracker {
    pub fn new() -> Self {
        Self {
            room: 0,
            peers: HashMap::new(),
        }
    }

    pub fn increment_room(&mut self) {
        self.room += 1;
    }

    pub fn increment_peer(&mut self, peer_id: &str) {
        *self.peers.entry(peer_id.to_string()).or_insert(0) += 1;
    }

    pub fn reset_room(&mut self) {
        self.room = 0;
    }

    pub fn reset_peer(&mut self, peer_id: &str) {
        self.peers.insert(peer_id.to_string(), 0);
    }

    pub fn room_count(&self) -> usize {
        self.room
    }

    pub fn peer_count(&self, peer_id: &str) -> usize {
        self.peers.get(peer_id).copied().unwrap_or(0)
    }

    pub fn remove_peer(&mut self, peer_id: &str) {
        self.peers.remove(peer_id);
    }
}

// ── Typing State ─────────────────────────────────────────────────────────────

/// Ephemeral peer typing indicators.
///
/// * Peer-specific — does **not** create message entries.
/// * Auto-expires after `TYPING_TIMEOUT_SECS`.
const TYPING_TIMEOUT_SECS: u64 = 3;

pub struct TypingState {
    /// peer_id → when the peer last signalled "typing".
    typing: HashMap<String, Instant>,
}

impl TypingState {
    pub fn new() -> Self {
        Self {
            typing: HashMap::new(),
        }
    }

    /// Mark `peer_id` as currently typing.
    pub fn set_typing(&mut self, peer_id: &str) {
        self.typing.insert(peer_id.to_string(), Instant::now());
    }

    /// Explicitly clear typing for `peer_id` (e.g. they sent a message).
    pub fn clear(&mut self, peer_id: &str) {
        self.typing.remove(peer_id);
    }

    /// Returns peer IDs that are currently typing (not expired).
    pub fn typing_peers(&self) -> Vec<&String> {
        self.typing
            .iter()
            .filter(|(_, instant)| instant.elapsed().as_secs() < TYPING_TIMEOUT_SECS)
            .map(|(pid, _)| pid)
            .collect()
    }

    /// Remove all data for a disconnected peer.
    pub fn remove_peer(&mut self, peer_id: &str) {
        self.typing.remove(peer_id);
    }
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

/// A pending remote file request with editable download path.
pub struct RemoteFileRequest {
    pub peer_id: String,
    pub filename: String,
    pub filesize: u64,
    pub remote_path: String,
    pub save_path_input: String,
    pub button_focus: usize,
    pub is_path_editing: bool,
}

/// A pending remote folder request with editable download path.
pub struct RemoteFolderRequest {
    pub peer_id: String,
    pub dirname: String,
    pub total_size: u64,
    pub remote_path: String,
    pub save_path_input: String,
    pub button_focus: usize,
    pub is_path_editing: bool,
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
    pub save_path_input: String,
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
pub struct DataStats {
    pub bytes_sent: u64,
    pub messages_sent: u64,
}

/// NOTE: DataStats above is kept for backward compatibility during transition.
/// The authoritative stats are in TransferEngine.stats().

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct RemoteEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

pub struct App {
    pub mode: Mode,
    pub input: String,
    pub peer_id: String,
    pub ticket: String,

    // Home
    pub menu_selected: usize,

    // Chat
    /// Logical message table — single canonical entry per message.
    pub messages: MessageTable,
    /// State-based unread counters (not inferred from UI).
    pub unread: UnreadTracker,
    /// Ephemeral typing indicators from peers.
    pub typing: TypingState,
    /// Throttle: when we last sent a typing event to peers.
    pub last_typing_sent: Option<Instant>,
    /// Current active chat target (Room or specific peer DM)
    pub chat_target: ChatTarget,
    /// Index in the sidebar chat list (0 = Room, 1.. = peers)
    pub chat_sidebar_idx: usize,

    // Peers
    pub peers: Vec<String>,
    pub peer_names: HashMap<String, String>,
    pub peer_keys: HashMap<String, [u8; 32]>,
    /// Per-peer connectivity status (Online / Offline).
    pub peer_status: HashMap<String, PeerStatus>,
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
    pub folder_path_editing: bool,
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
    pub remote_file_request: Option<RemoteFileRequest>,
    pub remote_folder_request: Option<RemoteFolderRequest>,
    /// Save paths for pending remote file requests, keyed by peer_id.
    /// When a file offer arrives from a peer in this map, auto-accept
    /// with the stored save path instead of showing a popup.
    pub pending_remote_save_paths: HashMap<String, String>,

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
}

impl App {
    pub fn new(peer_id: String, ticket: String, display_name: Option<String>) -> Self {
        Self {
            mode: Mode::Home,
            input: String::new(),
            peer_id,
            ticket,
            menu_selected: 0,
            messages: MessageTable::new(),
            unread: UnreadTracker::new(),
            typing: TypingState::new(),
            last_typing_sent: None,
            chat_target: ChatTarget::Room,
            chat_sidebar_idx: 0,
            peers: Vec::new(),
            peer_names: HashMap::new(),
            peer_keys: HashMap::new(),
            peer_status: HashMap::new(),
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
            folder_path_editing: false,
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
            remote_file_request: None,
            remote_folder_request: None,
            pending_remote_save_paths: HashMap::new(),
            status: String::new(),
            connecting_peers: HashMap::new(),
            engine: TransferEngine::new(),
            transactions: TransactionManager::new(),
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
            self.peers.push(peer_id.clone());
        }
        // Mark as online (re-connection or first connection)
        self.peer_status.insert(peer_id, PeerStatus::Online);
    }

    /// Transition a peer to offline state.
    /// Preserves identity, chat history, display name, and keys.
    /// Does NOT remove the peer from the list.
    pub fn set_peer_offline(&mut self, peer_id: &str) {
        self.peer_status.insert(peer_id.to_string(), PeerStatus::Offline);

        // Clean up ephemeral typing indicator
        self.typing.remove_peer(peer_id);

        // Clean up pending offers from this peer (they can't complete)
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

    /// Fully remove a peer from all state (used for explicit disconnect).
    pub fn remove_peer(&mut self, peer_id: &str) {
        self.peers.retain(|p| p != peer_id);
        self.peer_status.remove(peer_id);
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
        self.typing.remove_peer(peer_id);
        self.unread.remove_peer(peer_id);

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

    /// Check if a peer is currently online.
    pub fn is_peer_online(&self, peer_id: &str) -> bool {
        self.peer_status.get(peer_id).copied() == Some(PeerStatus::Online)
    }

    /// Switch the active chat target and reset unread for it.
    pub fn switch_chat_target(&mut self, target: ChatTarget) {
        self.chat_target = target.clone();
        match &target {
            ChatTarget::Room => self.unread.reset_room(),
            ChatTarget::Peer(pid) => self.unread.reset_peer(pid),
        }
    }

    /// Count unread messages in the Room chat.
    pub fn unread_room_count(&self) -> usize {
        self.unread.room_count()
    }

    /// Count unread DM messages for a specific peer.
    pub fn unread_dm_count(&self, peer_id: &str) -> usize {
        self.unread.peer_count(peer_id)
    }
}
