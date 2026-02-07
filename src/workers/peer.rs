use std::collections::HashMap;

/// Connectivity state of a peer — orthogonal to identity and chat state.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum PeerStatus {
    Online,
    Offline,
}

/// Peer-related state: identity, connectivity, and metadata.
pub struct PeerState {
    /// List of known peer IDs.
    pub list: Vec<String>,
    /// Display names for peers (peer_id -> name).
    pub names: HashMap<String, String>,
    /// Cipher keys for peers (peer_id -> key).
    pub keys: HashMap<String, [u8; 32]>,
    /// Per-peer connectivity status (Online / Offline).
    pub status: HashMap<String, PeerStatus>,
    /// Index of selected peer in the peers panel.
    pub selected_idx: usize,
    /// Peer info popup: which peer is being viewed.
    pub info_popup: Option<String>,
    /// Per-peer statistics: (messages_sent, messages_received, files_sent, files_received).
    pub stats: HashMap<String, (u64, u64, u64, u64)>,
    /// Per-peer connection timestamps.
    pub connected_at: HashMap<String, String>,
    /// Per-peer IP addresses (remote address from WebRTC ICE connection).
    pub ips: HashMap<String, String>,
    /// Peers currently being connected (peer_id -> status message).
    pub connecting: HashMap<String, String>,
}

impl PeerState {
    pub fn new() -> Self {
        Self {
            list: Vec::new(),
            names: HashMap::new(),
            keys: HashMap::new(),
            status: HashMap::new(),
            selected_idx: 0,
            info_popup: None,
            stats: HashMap::new(),
            connected_at: HashMap::new(),
            ips: HashMap::new(),
            connecting: HashMap::new(),
        }
    }
}

/// A pending remote file/folder request with editable download path.
pub struct RemotePathRequest {
    pub peer_id: String,
    /// Name of the file or folder.
    pub name: String,
    /// Size in bytes.
    pub size: u64,
    /// Remote path being requested.
    pub remote_path: String,
    /// User-editable save path.
    pub save_path_input: String,
    /// 0 = Accept, 1 = Decline, 2 = Path input.
    pub button_focus: usize,
    /// Whether the path input field is being edited.
    pub is_path_editing: bool,
    /// True if this is a folder request, false if file.
    pub is_folder: bool,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct RemoteEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

/// Remote file browsing state.
pub struct RemoteState {
    /// Currently browsed peer.
    pub peer: Option<String>,
    /// Current remote path.
    pub path: String,
    /// Directory entries at current path.
    pub entries: Vec<RemoteEntry>,
    /// Selected entry index.
    pub selected: usize,
    /// Pending remote file/folder request popup.
    pub path_request: Option<RemotePathRequest>,
    /// Save paths for pending remote file requests, keyed by peer_id.
    /// When a file offer arrives from a peer in this map, auto-accept
    /// with the stored save path instead of showing a popup.
    pub pending_save_paths: HashMap<String, String>,
}

impl RemoteState {
    pub fn new() -> Self {
        Self {
            peer: None,
            path: "/".to_string(),
            entries: Vec::new(),
            selected: 0,
            path_request: None,
            pending_save_paths: HashMap::new(),
        }
    }
}
