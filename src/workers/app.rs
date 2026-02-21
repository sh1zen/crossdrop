use crate::core::config::TYPING_TIMEOUT_SECS;
use crate::core::engine::TransferEngine;
use crate::ui::notify::NotifyManager;
use crate::utils::global_keyboard::CapturedKey;
use crate::workers::peer::PeerStatus;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
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
    KeyListener,
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
            Mode::KeyListener => "Key Listener",
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
    pub target: ChatTarget
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
        self.messages
            .iter()
            .filter(|m| &m.target == target)
            .collect()
    }

    /// Clear messages for a target (`/clear` command).
    pub fn clear_target(&mut self, target: &ChatTarget) {
        self.messages.retain(|m| &m.target != target);
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

    /// Total unread messages across room + all peer DMs.
    pub fn total(&self) -> usize {
        self.room + self.peers.values().sum::<usize>()
    }
}

// ── Typing State ─────────────────────────────────────────────────────────────

/// Ephemeral peer typing indicators.
///
/// * Peer-specific — does **not** create message entries.
/// * Auto-expires after `TYPING_TIMEOUT_SECS`.

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

/// Chat messaging state: messages, typing indicators, and unread tracking.
pub struct ChatState {
    /// Logical message table — single canonical entry per message.
    pub messages: MessageTable,
    /// State-based unread counters (not inferred from UI).
    pub unread: UnreadTracker,
    /// Ephemeral typing indicators from peers.
    pub typing: TypingState,
    /// Throttle: when we last sent a typing event to peers.
    pub last_typing_sent: Option<Instant>,
    /// Current active chat target (Room or specific peer DM)
    pub target: ChatTarget,
    /// Index in the sidebar chat list (0 = Room, 1.. = peers)
    pub sidebar_idx: usize,
}

impl ChatState {
    pub fn new() -> Self {
        Self {
            messages: MessageTable::new(),
            unread: UnreadTracker::new(),
            typing: TypingState::new(),
            last_typing_sent: None,
            target: ChatTarget::Room,
            sidebar_idx: 0,
        }
    }
}

/// Files panel UI state.
pub struct FilesPanelState {
    /// Scroll position in history list.
    pub history_scroll: usize,
    /// Search filter string.
    pub search: String,
    /// Whether search mode is active.
    pub search_mode: bool,
    /// Index of the selected active transfer (for cancel).
    pub active_transfer_idx: usize,
    /// Index of the selected history entry (for info popup).
    pub history_selected_idx: usize,
    /// Focus area: true = active transfers, false = history.
    pub focus_active: bool,
}

impl FilesPanelState {
    pub fn new() -> Self {
        Self {
            history_scroll: 0,
            search: String::new(),
            search_mode: false,
            active_transfer_idx: 0,
            history_selected_idx: 0,
            focus_active: true,
        }
    }
}

pub struct App {
    pub mode: Mode,
    pub input: String,
    pub peer_id: String,
    pub ticket: String,

    // Home
    pub menu_selected: usize,

    // Connect
    pub connect_ticket_input: String,

    // Send
    pub send_file_path: String,

    // Logs
    pub log_scroll: usize,

    // Notifications (user-facing status bar)
    pub notify: NotifyManager,

    // Key Listener
    /// Received remote key events from all peers.
    pub remote_key_events: Vec<CapturedKey>,

    // ── Transfer Engine ──────────────────────────────────────────────────
    /// The TransferEngine owns ALL transfer state and logic.
    /// No transfer logic exists outside the engine.
    pub engine: TransferEngine,

    // ── Wire-level statistics ────────────────────────────────────────────
    /// Cumulative wire-level TX/RX bytes - atomic counters for direct
    /// updates from WebRTC connections. Tracks ALL bytes crossing the network.
    pub cumulative_tx: Arc<AtomicU64>,
    pub cumulative_rx: Arc<AtomicU64>,

    // ── Aggregate sub-structs ────────────────────────────────────────────
    /// Peer-related state.
    pub peers: crate::workers::peer::PeerState,
    /// Chat messaging state.
    pub chat: ChatState,
    /// Remote file browsing state.
    pub remote: crate::workers::peer::RemoteState,
    /// Files panel UI state.
    pub files: FilesPanelState,
    /// User-configurable settings.
    pub settings: crate::workers::settings::Settings,
}

impl App {
    pub fn new(peer_id: String, ticket: String, display_name: Option<String>, cumulative_tx: Arc<AtomicU64>, cumulative_rx: Arc<AtomicU64>) -> Self {
        Self {
            mode: Mode::Home,
            input: String::new(),
            peer_id,
            ticket,
            menu_selected: 0,
            connect_ticket_input: String::new(),
            send_file_path: String::new(),
            log_scroll: 0,
            notify: NotifyManager::new(),
            remote_key_events: Vec::new(),
            engine: TransferEngine::new(),
            cumulative_tx,
            cumulative_rx,
            peers: crate::workers::peer::PeerState::new(),
            chat: ChatState::new(),
            remote: crate::workers::peer::RemoteState::new(),
            files: FilesPanelState::new(),
            settings: crate::workers::settings::Settings::new(display_name),
        }
    }

    /// Build the list of chat targets for the sidebar: Room + each peer.
    pub fn chat_targets(&self) -> Vec<ChatTarget> {
        let mut targets = vec![ChatTarget::Room];
        for p in &self.peers.list {
            targets.push(ChatTarget::Peer(p.clone()));
        }
        targets
    }

    pub fn selected_peer(&self) -> Option<&String> {
        self.peers.list.get(self.peers.selected_idx)
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.notify.info(msg);
    }

    pub fn push_error(&mut self, msg: impl Into<String>) {
        self.notify.error(msg);
    }

    pub fn add_peer(&mut self, peer_id: String) {
        if !self.peers.list.contains(&peer_id) {
            self.peers.list.push(peer_id.clone());
        }
        // Mark as online (re-connection or first connection)
        self.peers.status.insert(peer_id.clone(), PeerStatus::Online);
        // Track connection time
        self.peers.connected_at.insert(peer_id, crate::ui::helpers::format_absolute_timestamp_now());
    }

    /// Transition a peer to offline state.
    /// Preserves identity, chat history, display name, and keys.
    /// Does NOT remove the peer from the list.
    pub fn set_peer_offline(&mut self, peer_id: &str) {
        self.peers.status
            .insert(peer_id.to_string(), PeerStatus::Offline);

        // Clean up ephemeral typing indicator
        self.chat.typing.remove_peer(peer_id);

        // If we're viewing this peer's remote filesystem, exit remote mode
        if self.mode == Mode::Remote && self.remote.peer.as_deref() == Some(peer_id) {
            self.mode = Mode::Peers;
            self.remote.peer = None;
        }
    }

    /// Fully remove a peer from all state (used for explicit disconnect).
    pub fn remove_peer(&mut self, peer_id: &str) {
        self.peers.list.retain(|p| p != peer_id);
        self.peers.status.remove(peer_id);
        if self.peers.selected_idx >= self.peers.list.len() && !self.peers.list.is_empty() {
            self.peers.selected_idx = self.peers.list.len() - 1;
        }
        // If DM with this peer, go back to Room
        if self.chat.target == ChatTarget::Peer(peer_id.to_string()) {
            self.chat.target = ChatTarget::Room;
            self.chat.sidebar_idx = 0;
        }
        // Clean up all peer-related data
        self.peers.names.remove(peer_id);
        self.peers.keys.remove(peer_id);
        self.chat.typing.remove_peer(peer_id);
        self.chat.unread.remove_peer(peer_id);

        // If we're viewing this peer's remote filesystem, exit remote mode
        if self.mode == Mode::Remote && self.remote.peer.as_deref() == Some(peer_id) {
            self.mode = Mode::Peers;
            self.remote.peer = None;
        }
    }

    /// Check if a peer is currently online.
    pub fn is_peer_online(&self, peer_id: &str) -> bool {
        self.peers.status.get(peer_id).copied() == Some(PeerStatus::Online)
    }

    /// Get wire-level TX bytes (session lifetime).
    pub fn total_wire_tx(&self) -> u64 {
        self.cumulative_tx.load(Ordering::Relaxed)
    }

    /// Get wire-level RX bytes (session lifetime).
    pub fn total_wire_rx(&self) -> u64 {
        self.cumulative_rx.load(Ordering::Relaxed)
    }

    /// Switch the active chat target and reset unread for it.
    pub fn switch_chat_target(&mut self, target: ChatTarget) {
        self.chat.target = target.clone();
        match &target {
            ChatTarget::Room => self.chat.unread.reset_room(),
            ChatTarget::Peer(pid) => self.chat.unread.reset_peer(pid),
        }
    }

    /// Count unread messages in the Room chat.
    pub fn unread_room_count(&self) -> usize {
        self.chat.unread.room_count()
    }

    /// Count unread DM messages for a specific peer.
    pub fn unread_dm_count(&self, peer_id: &str) -> usize {
        self.chat.unread.peer_count(peer_id)
    }

    /// Total unread messages across all chat channels.
    pub fn total_unread(&self) -> usize {
        self.chat.unread.total()
    }
}
