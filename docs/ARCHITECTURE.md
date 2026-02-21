# Crossdrop Architecture Documentation

This document provides comprehensive documentation of the Crossdrop architecture, including module organization, data flows, and implementation details.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Module Structure](#2-module-structure)
3. [Core Module](#3-core-module)
4. [Connection Layer](#4-connection-layer)
5. [Pipeline Module](#5-pipeline-module)
6. [Security Module](#6-security-module)
7. [UI Module](#7-ui-module)
8. [Utils Module](#8-utils-module)
9. [Workers Module](#9-workers-module)
10. [Message Pipeline](#10-message-pipeline)
11. [File Transfer Pipeline](#11-file-transfer-pipeline)
12. [Transaction State Machine](#12-transaction-state-machine)
13. [WebRTC Data Flow](#13-webrtc-data-flow)
14. [Configuration Constants](#14-configuration-constants)

---

## 1. Project Overview

Crossdrop is a peer-to-peer file sharing and chat application built in Rust. It uses:
- **Iroh** for P2P discovery and signaling
- **WebRTC** for direct peer connections with data channels
- **SHA3-256** and **AES-256-GCM** for cryptographic operations
- **Ratatui** for the terminal UI

### Key Features
- Direct peer-to-peer file transfers with resume capability
- Real-time chat (broadcast and direct messages)
- Remote file system browsing
- End-to-end encryption with session key rotation
- Merkle tree integrity verification for file transfers

---

## 2. Module Structure

```
src/
├── main.rs              # Application entry point
├── core/                # Business logic and transfer coordination
│   ├── mod.rs
│   ├── config.rs        # Centralized configuration constants
│   ├── engine.rs        # TransferEngine - transfer state machine
│   ├── initializer.rs   # PeerNode - connection management
│   ├── peer_registry.rs # Saved peer persistence
│   ├── persistence.rs   # JSON-based state persistence
│   ├── transaction.rs   # Transaction data structures
│   ├── connection/      # Network layer
│   │   ├── mod.rs
│   │   ├── iroh.rs      # Iroh endpoint wrapper
│   │   ├── ticket.rs    # Connection ticket parsing
│   │   ├── crypto.rs    # ECDH key exchange
│   │   └── webrtc/      # WebRTC implementation
│   ├── pipeline/        # File transfer pipeline
│   │   ├── mod.rs
│   │   ├── chunk.rs     # Chunk bitmap for resume
│   │   ├── merkle.rs    # Merkle tree integrity
│   │   ├── receiver.rs  # Streaming file writer
│   │   └── sender.rs    # Disk reader pipeline
│   └── security/        # Authentication and replay protection
│       ├── mod.rs
│       ├── identity.rs      # Ed25519 identity
│       ├── message_auth.rs  # HMAC authentication
│       └── replay.rs        # Replay guard
├── ui/                  # Terminal UI (Ratatui)
│   ├── mod.rs
│   ├── executer.rs      # Main UI loop
│   ├── commands.rs      # UI commands
│   ├── notify.rs        # Notification manager
│   ├── traits.rs        # Component traits
│   ├── panels/          # UI panels
│   ├── popups/          # Modal dialogs
│   ├── helpers/         # Formatting utilities
│   └── widgets/         # Reusable widgets
├── utils/               # Shared utilities
│   ├── mod.rs
│   ├── crypto.rs        # HMAC-SHA3-256
│   ├── hash.rs          # Compression and key management
│   ├── data_dir.rs      # Data directory management
│   ├── clipboard.rs     # Clipboard operations
│   ├── atomic_write.rs  # Atomic file writes
│   ├── log_buffer.rs    # In-memory log buffer
│   ├── global_keyboard.rs # Global hotkeys
│   └── sos.rs           # Signal-of-stop for cancellation
└── workers/             # Application state
    ├── mod.rs
    ├── app.rs           # App struct and Mode enum
    ├── args.rs          # CLI argument parsing
    ├── peer.rs          # Peer state types
    └── settings.rs      # User settings
```

---

## 3. Core Module

### 3.1 TransferEngine ([`engine.rs`](src/core/engine.rs))

The `TransferEngine` is the **sole coordinator** of all file transfer logic. It is a pure state machine with no async/network concerns.

**Architecture Rule**: No transfer logic may exist outside this module.

```
                                    TransferEngine Architecture
                                    ==========================

    UI Layer                    Core Layer                    Transport Layer
    ========                    ==========                    ===============

    UIExecuter                  TransferEngine                WebRTCConnection
        |                           |                              |
        | initiate_file_send()      |                              |
        +-------------------------->|                              |
        |                           |                              |
        |                     EngineAction                        |
        |                           |                              |
        |                           +--- send_control() ----------->|
        |                           |                              |
```

**Key Types**:

| Type | Purpose |
|------|---------|
| `EngineAction` | Declarative side-effects returned to UIExecuter |
| `EngineOutcome` | Result containing actions and status message |
| `PendingIncoming` | Incoming transaction awaiting user acceptance |
| `DataStats` | Comprehensive transfer statistics |

**Engine Actions**:
```rust
pub enum EngineAction {
    SendTransactionRequest { ... },
    SendTransactionResponse { ... },
    PrepareReceive { ... },
    SendFileData { ... },
    SendFolderData { ... },
    SendTransactionComplete { ... },
    AcceptResume { ... },
    SendResumeRequest { ... },
    RejectResume { ... },
    ResendFiles { ... },
    HandleRemoteFetch { ... },
    CancelTransaction { ... },
    RetransmitChunks { ... },
    TransactionCompleteAck { ... },
}
```

### 3.2 PeerNode ([`initializer.rs`](src/core/initializer.rs))

`PeerNode` manages peer connections, message routing, and event dispatch.

**Responsibilities**:
- Iroh endpoint management
- WebRTC connection establishment (offerer/answerer)
- ECDH handshake coordination
- Event broadcasting to UI layer
- Message queuing for offline peers

**AppEvent Enum**:
```rust
pub enum AppEvent {
    PeerConnected { peer_id, remote_ip },
    PeerDisconnected { peer_id, explicit },
    ChatReceived { peer_id, message },
    DmReceived { peer_id, message },
    TypingReceived { peer_id },
    FileProgress { file_id, received_chunks, ... },
    SendProgress { file_id, sent_chunks, ... },
    SendComplete { file_id, success },
    FileComplete { file_id, filename, merkle_root, ... },
    TransactionRequested { ... },
    TransactionAccepted { ... },
    TransactionRejected { ... },
    // ... more variants
}
```

### 3.3 Transaction ([`transaction.rs`](src/core/transaction.rs))

Manages transaction lifecycle, state transitions, and resume capability.

**Transaction States**:
```
Pending → Active → Completed
        ↘ Rejected
        ↘ Cancelled
        ↘ Interrupted → Resumable
```

### 3.4 Persistence ([`persistence.rs`](src/core/persistence.rs))

JSON-based state persistence for:
- Transfer history
- Transaction snapshots (for resume)
- Transfer statistics
- Chat history
- Saved peers
- Queued messages

---

## 4. Connection Layer

### 4.1 Iroh ([`connection/iroh.rs`](src/core/connection/iroh.rs))

Wrapper around Iroh endpoint for P2P connectivity.

**Features**:
- Endpoint creation with port binding retry logic
- Connection establishment via tickets
- Ticket generation for incoming connections
- Relay support for NAT traversal

### 4.2 Ticket ([`connection/ticket.rs`](src/core/connection/ticket.rs))

Connection tickets are compressed, serialized endpoint addresses.

```
Ticket Format:
==============
1. JSON serialize EndpointAddr
2. Brotli compress
3. URL-safe Base64 encode
4. Prepend version byte
```

### 4.3 Crypto ([`connection/crypto.rs`](src/core/connection/crypto.rs))

ECDH key exchange and session key derivation.

**Handshake Protocol**:
```
Offerer                          Answerer
─────────                        ─────────
eph_pk_A  ──────────────────────►
eph_pk_B  ◄──────────────────────

shared_secret = X25519(eph_sk_A, eph_pk_B)
session_key = HKDF-SHA3-256(
    ikm  = shared_secret,
    salt = sort(iroh_pk_A, iroh_pk_B),
    info = b"crossdrop-session-v1"
)
```

**Key Rotation**:
- Hourly automatic rotation
- New ephemeral X25519 key pair
- Forward secrecy via previous key mixing

### 4.4 WebRTC ([`connection/webrtc/`](src/core/connection/webrtc/))

**Module Layout**:

| File | Responsibility |
|------|----------------|
| `types.rs` | Protocol enums and internal state structs |
| `helpers.rs` | Crypto, compression, path sanitization |
| `connection.rs` | `WebRTCConnection` struct |
| `data.rs` | Binary frame encode/decode |
| `control.rs` | Incoming message dispatch |
| `sender.rs` | TX operations: files, messages, control frames |
| `receiver.rs` | RX operations: finalization and hash verification |
| `initializer.rs` | Connection setup and data-channel negotiation |

**Frame Types**:
```rust
pub const FRAME_CONTROL: u8 = 0x01;  // JSON ControlMessage
pub const FRAME_CHUNK: u8 = 0x02;    // Binary file chunk
```

**ControlMessage Enum**:
```rust
pub enum ControlMessage {
    // Chat
    Text(Vec<u8>),
    DirectMessage(Vec<u8>),
    Typing,
    AuthenticatedText(Vec<u8>),
    AuthenticatedDm(Vec<u8>),
    DisplayName(String),

    // File transfer
    Metadata { file_id, total_chunks, filename, filesize },
    ChunkHashBatch { file_id, start_index, chunk_hashes },
    Hash { file_id, merkle_root },
    HashResult { file_id, ok },
    ChunkRetransmitRequest { file_id, chunk_indices },
    FileReceived { file_id },

    // Transactions
    TransactionRequest { ... },
    TransactionResponse { ... },
    TransactionComplete { ... },
    TransactionCancel { ... },
    TransactionResumeRequest { ... },
    TransactionResumeResponse { ... },
    TransactionCompleteAck { ... },

    // Remote access
    LsRequest { path },
    LsResponse { path, entries },
    FetchRequest { path, is_folder },
    RemoteAccessDisabled,
    RemoteKeyEvent { key },
    RemoteKeyListenerDisabled,

    // Key rotation
    KeyRotation { ephemeral_pub },

    // Liveness
    AreYouAwake,
    ImAwake,
}
```

---

## 5. Pipeline Module

### 5.1 Chunk Bitmap ([`pipeline/chunk.rs`](src/core/pipeline/chunk.rs))

Bit-vector tracking which chunks have been received.

```rust
pub struct ChunkBitmap {
    pub total_chunks: u32,
    bits: Vec<u64>,  // 64 bits per word
}
```

**Wire Format**:
```
[4 bytes: total_chunks][N * 8 bytes: bits]
```

### 5.2 Merkle Tree ([`pipeline/merkle.rs`](src/core/pipeline/merkle.rs))

Merkle tree for file integrity verification.

**Incremental Verification Flow**:
1. Sender computes chunk hashes while reading file
2. Sender sends `ChunkHashBatch` messages BEFORE chunks
3. Receiver stores expected chunk hashes
4. Each chunk verified against expected hash on arrival
5. Mismatches trigger retransmission requests

```rust
pub struct IncrementalMerkleBuilder {
    leaves: Vec<[u8; 32]>,
}

pub struct ChunkHashVerifier {
    chunk_hashes: Vec<Option<[u8; 32]>>,
}
```

### 5.3 Streaming File Writer ([`pipeline/receiver.rs`](src/core/pipeline/receiver.rs))

Streams received chunks directly to disk with bounded memory usage.

**Memory Model**:
```
Per-file memory: O(total_chunks × 33 bytes)
- chunk_hashes: Vec<Option<[u8; 32]>>
- bitmap: ChunkBitmap
- write_buffer: BTreeMap<u32, Vec<u8>> (bounded)
```

**Write Strategy**:
1. Chunks written to sparse temp file at correct offset
2. Sequential runs flushed immediately
3. Out-of-order chunks buffered until gap fills
4. Finalize: sync, compute Merkle root, atomic rename

### 5.4 Sender Pipeline ([`pipeline/sender.rs`](src/core/pipeline/sender.rs))

Async disk reader with read-ahead buffering.

```
┌──────────┐   prefetch_tx   ┌─────────────────────┐
│ DiskRead │ ───────────────►│ Send loop           │──► WebRTC DC
│ (async)  │   bounded chan  │ (encrypt+tx)        │
└──────────┘                 └─────────────────────┘
```

---

## 6. Security Module

### 6.1 Identity ([`security/identity.rs`](src/core/security/identity.rs))

Long-term Ed25519-style identity for peer authentication.

```rust
pub struct PeerIdentity {
    secret: [u8; 32],
    pub public_key: [u8; 32],  // SHA3-256(IDENTITY_DOMAIN || secret)
}
```

**Features**:
- Persistent key pair storage
- HMAC-based signing scheme
- Constant-time verification

### 6.2 Message Authentication ([`security/message_auth.rs`](src/core/security/message_auth.rs))

HMAC computation and verification for protocol messages.

```rust
pub struct AuthenticatedMessage {
    pub transaction_id: Uuid,
    pub counter: u64,
    pub payload: Vec<u8>,
    pub hmac: [u8; 32],  // HMAC(session_key, txn_id || counter || payload)
}
```

### 6.3 Replay Protection ([`security/replay.rs`](src/core/security/replay.rs))

Global replay guard tracking registered transactions.

```rust
pub struct ReplayGuard {
    transactions: HashSet<Uuid>,
}
```

---

## 7. UI Module

### 7.1 Component Traits ([`ui/traits.rs`](src/ui/traits.rs))

```rust
pub trait Component {
    fn render(&mut self, f: &mut Frame, app: &App, area: Rect);
    fn on_focus(&mut self, _app: &mut App) {}
    fn on_blur(&mut self, _app: &mut App) {}
}

pub trait Handler {
    fn handle_key(&mut self, app: &mut App, node: &PeerNode, key: KeyCode) -> Option<Action>;
}

pub trait Focusable {
    fn focusable_elements(&self) -> Vec<FocusableElement>;
    fn focused_index(&self) -> usize;
    fn set_focus(&mut self, index: usize);
}
```

### 7.2 Panels ([`ui/panels/`](src/ui/panels/))

| Panel | Purpose |
|-------|---------|
| `HomePanel` | Main menu navigation |
| `ChatPanel` | Room and DM messaging |
| `SendPanel` | File/folder sending |
| `ConnectPanel` | Peer connection via ticket |
| `PeersPanel` | Connected peer list |
| `FilesPanel` | Transfer history and active transfers |
| `RemotePanel` | Remote file system browsing |
| `SettingsPanel` | User settings configuration |
| `IdPanel` | Display own peer ID and ticket |
| `LogsPanel` | Application log viewer |
| `KeyListenerPanel` | Remote key event viewer |

### 7.3 Popups ([`ui/popups/`](src/ui/popups/))

| Popup | Purpose |
|-------|---------|
| `SavePathPopup` | Accept incoming transfer with path selection |
| `RemotePathPopup` | Confirm remote file fetch |
| `PeerInfoPopup` | Display peer details |
| `TransactionPopup` | Transaction offer handling |

### 7.4 Helpers ([`ui/helpers/`](src/ui/helpers/))

- `formatters.rs`: File size formatting, name truncation
- `loader.rs`: Loading animation frames
- `time.rs`: Timestamp formatting

### 7.5 Widgets ([`ui/widgets/`](src/ui/widgets/))

- `progress_bar.rs`: Custom progress bar component

---

## 8. Utils Module

### 8.1 Crypto ([`utils/crypto.rs`](src/utils/crypto.rs))

Centralized HMAC-SHA3-256 implementation.

```rust
pub fn hmac_sha3_256(key: &[u8], data: &[u8]) -> [u8; 32];
pub fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool;
```

### 8.2 Hash ([`utils/hash.rs`](src/utils/hash.rs))

- Brotli string compression/expansion
- Instance locking for single-instance enforcement
- Secret key slot management

### 8.3 Other Utilities

| Module | Purpose |
|--------|---------|
| `data_dir.rs` | Cross-platform data directory |
| `clipboard.rs` | System clipboard access |
| `atomic_write.rs` | Atomic file writes |
| `log_buffer.rs` | In-memory log ring buffer |
| `global_keyboard.rs` | Global hotkey listener |
| `sos.rs` | Signal-of-stop for graceful shutdown |

---

## 9. Workers Module

### 9.1 App ([`workers/app.rs`](src/workers/app.rs))

Main application state container.

```rust
pub struct App {
    pub mode: Mode,
    pub input: String,
    pub peer_id: String,
    pub ticket: String,
    pub engine: TransferEngine,
    pub peers: PeerState,
    pub chat: ChatState,
    pub remote: RemoteState,
    pub files: FilesPanelState,
    pub settings: Settings,
    pub notify: NotifyManager,
    // ...
}
```

**Mode Enum**:
```rust
pub enum Mode {
    Home, Chat, Send, Connect, Peers,
    Files, Logs, Id, Settings, Remote, KeyListener,
}
```

### 9.2 Chat State

```rust
pub struct ChatState {
    pub messages: MessageTable,
    pub unread: UnreadTracker,
    pub typing: TypingState,
    pub target: ChatTarget,
    // ...
}

pub enum ChatTarget {
    Room,  // Broadcast to all peers
    Peer(String),  // DM with specific peer
}
```

### 9.3 Args ([`workers/args.rs`](src/workers/args.rs))

CLI argument parsing with TOML config file support.

```rust
pub struct Args {
    pub ipv4_addr: Option<SocketAddrV4>,
    pub ipv6_addr: Option<SocketAddrV6>,
    pub port: u16,
    pub verbose: u8,
    pub relay: RelayModeOption,
    pub show_secret: bool,
    pub remote_access: bool,
    pub display_name: Option<String>,
    pub conf: Option<PathBuf>,
}
```

### 9.4 Settings ([`workers/settings.rs`](src/workers/settings.rs))

User-configurable settings with theme support.

```rust
pub struct Settings {
    pub display_name: String,
    pub remote_access: bool,
    pub remote_key_listener: bool,
    pub theme: AppTheme,
}
```

---

## 10. Message Pipeline

### 10.1 Message Sending Flow

```
                                    MESSAGE SENDING FLOW
                                    ====================

    UI Layer                    Core Layer                    Transport Layer
    ========                    ==========                    ===============

    Chat Panel                  UIExecuter                    WebRTCConnection
        |                           |                              |
        | send_message()            |                              |
        +-------------------------->|                              |
        |                           |                              |
        |                     EngineAction                        |
        |                           |                              |
        |                           +--- send_control() ----------->|
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     |  Derive HMAC    |
        |                           |                     |  (chat_hmac_key)|
        |                           |                     +--------+--------+
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     | Create AuthMsg  |
        |                           |                     | (counter + HMAC)|
        |                           |                     +--------+--------+
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     |  JSON Encode    |
        |                           |                     | ControlMessage  |
        |                           |                     +--------+--------+
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     | Brotli Compress |
        |                           |                     +--------+--------+
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     | AES-256-GCM     |
        |                           |                     | Encrypt         |
        |                           |                     +--------+--------+
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     | WebRTC Send     |
        |                           |                     | (DataChannel)   |
        |                           |                     +-----------------+
```

### 10.2 Message Receiving Flow

```
                                    MESSAGE RECEIVING FLOW
                                    ======================

    Transport Layer                    Core Layer                    UI Layer
    ===============                    ==========                    ========

    WebRTCConnection                   TransferEngine               App/Chat Panel
        |                                    |                            |
        | on_message callback                |                            |
        +------------------------------------>|                            |
        |                                    |                            |
        +--------v--------+                  |                            |
        | AES-256-GCM     |                  |                            |
        | Decrypt         |                  |                            |
        +--------+--------+                  |                            |
        |                                    |                            |
        +--------v--------+                  |                            |
        | Brotli Decompress|                 |                            |
        +--------+--------+                  |                            |
        |                                    |                            |
        +--------v--------+                  |                            |
        | Frame Type Check|                  |                            |
        +--------+--------+                  |                            |
        |                                    |                            |
        |    FRAME_CONTROL                   |                            |
        +-----------> ControlMessage         |                            |
        |                                    |                            |
        +--------v--------+                  |                            |
        | Verify HMAC      |                 |                            |
        | Check Counter    |                 |                            |
        | (Replay Protect) |                 |                            |
        +--------+--------+                  |                            |
        |                                    |                            |
        |     ConnectionMessage              |                            |
        |     .TextReceived(data)            |                            |
        +----------------------------------->|                            |
        |                                    |                            |
        |                              AppEvent                           |
        |                              .ChatReceived                   |
        |                                    +--------------------------->|
        |                                    |                            |
        |                                    |                     Update UI
        |                                    |                     (Chat Panel)
```

---

## 11. File Transfer Pipeline

### 11.1 Outbound File Transfer (Sender Side)

```
                                    OUTBOUND FILE TRANSFER
                                    ======================

    UI Layer                    Core Layer                    Transport Layer
    ========                    ==========                    ===============

    Send Panel                  TransferEngine                WebRTCConnection
        |                           |                              |
        | initiate_file_send()      |                              |
        +-------------------------->|                              |
        |                           |                              |
        |                     +-----v-----+                        |
        |                     | Create    |                        |
        |                     | Transaction|                       |
        |                     +-----+-----+                        |
        |                           |                              |
        |                     +-----v-----+                        |
        |                     | Sign      |                        |
        |                     | Manifest  |                        |
        |                     +-----+-----+                        |
        |                           |                              |
        |                     EngineAction                        |
        |                     .SendTransactionRequest              |
        |                           +-----------> ControlMessage  |
        |                           |             .TransactionRequest
        |                           |             --------------->|
        |                           |                              |
        |                           |                     Peer accepts
        |                           |                              |
        |                           |<---- TransactionAccepted ----|
        |                           |                              |
        |                     +-----v-----+                        |
        |                     | Activate  |                        |
        |                     | Transaction|                       |
        |                     +-----+-----+                        |
        |                           |                              |
        |                     EngineAction                        |
        |                     .SendFileData                       |
        |                           |                              |
        |                           +-----------> send_file() ---->|
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     | Spawn Disk      |
        |                           |                     | Reader Task     |
        |                           |                     +--------+--------+
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     | Send Metadata   |
        |                           |                     | (ControlMessage)|
        |                           |                     +--------+--------+
        |                           |                              |
        |                           |            +-----------------v-----------------+
        |                           |            |         CHUNK LOOP               |
        |                           |            |  +--------------------------+    |
        |                           |            |  | Read chunk from disk     |    |
        |                           |            |  +------------+-------------+    |
        |                           |            |               |                  |
        |                           |            |  +------------v-------------+    |
        |                           |            |  | SHA3-256 hash (per chunk)|    |
        |                           |            |  +------------+-------------+    |
        |                           |            |               |                  |
        |                           |            |  +------------v-------------+    |
        |                           |            |  | Encode chunk frame       |    |
        |                           |            |  | [FRAME_CHUNK|UUID|SEQ|DATA] |
        |                           |            |  +------------+-------------+    |
        |                           |            |               |                  |
        |                           |            |  +------------v-------------+    |
        |                           |            |  | AES-256-GCM encrypt      |    |
        |                           |            |  +------------+-------------+    |
        |                           |            |               |                  |
        |                           |            |  +------------v-------------+    |
        |                           |            |  | WebRTC send (backpressure)|   |
        |                           |            |  +------------+-------------+    |
        |                           |            |               |                  |
        |                           |            |  +------------v-------------+    |
        |                           |            |  | Progress report every    |    |
        |                           |            |  | PIPELINE_SIZE chunks     |    |
        |                           |            |  +--------------------------+    |
        |                           |            +-----------------+----------------+
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     | Send Hash       |
        |                           |                     | (SHA3-256 +     |
        |                           |                     |  Merkle Root)   |
        |                           |                     +--------+--------+
        |                           |                              |
        |                           |                     +--------v--------+
        |                           |                     | Wait HashResult |
        |                           |                     +--------+--------+
        |                           |                              |
        |                           |<---- HashResult {ok: true} ---|
        |                           |                              |
        |                     +-----v-----+                        |
        |                     | Complete  |                        |
        |                     | File      |                        |
        |                     +-----+-----+                        |
        |                           |                              |
        |                     EngineAction                        |
        |                     .SendTransactionComplete            |
        |                           +-----------> ControlMessage  |
        |                           |             .TransactionComplete
        |                           |             --------------->|
        |                           |                              |
        |                           |<---- TransactionCompleteAck -|
        |                           |                              |
        |                     +-----v-----+                        |
        |                     | Archive   |                        |
        |                     | Transaction|                       |
        |                     +-----------+                        |
```

### 11.2 Inbound File Transfer (Receiver Side)

```
                                    INBOUND FILE TRANSFER
                                    =====================

    Transport Layer                    Core Layer                    UI Layer
    ===============                    ==========                    ========

    WebRTCConnection                   TransferEngine               App/Files Panel
        |                                    |                            |
        |<--- TransactionRequest -----------|                            |
        |                                    |                            |
        |     ConnectionMessage              |                            |
        |     .TransactionRequested          |                            |
        +----------------------------------->|                            |
        |                                    |                            |
        |                              +-----v-----+                      |
        |                              | Validate   |                     |
        |                              | Manifest   |                     |
        |                              | Signature  |                     |
        |                              +-----+-----+                      |
        |                                    |                            |
        |                              +-----v-----+                      |
        |                              | Create     |                     |
        |                              | PendingIncoming                    |
        |                              +-----+-----+                      |
        |                                    |                            |
        |                              AppEvent                       |
        |                              .TransactionRequested         |
        |                                    +--------------------------->|
        |                                    |                     Show popup
        |                                    |                     (Accept/Reject)
        |                                    |                            |
        |                                    |<--- User accepts -----------|
        |                                    |                            |
        |                              +-----v-----+                      |
        |                              | Create     |                     |
        |                              | Inbound    |                     |
        |                              | Transaction|                     |
        |                              +-----+-----+                      |
        |                                    |                            |
        |                              EngineAction                      |
        |                              .PrepareReceive                   |
        |                              .SendTransactionResponse          |
        |<-----------------------------------+                            |
        |                                    |                            |
        |     TransactionResponse (accepted)|                            |
        |     ----------------------------->|                            |
        |                                    |                            |
        |     Metadata {file_id, ...}        |                            |
        |<-----------------------------------|                            |
        |                                    |                            |
        +--------v--------+                  |                            |
        | Create           |                  |                            |
        | StreamingFileWriter                 |                            |
        | (sparse temp file)                 |                            |
        +--------+--------+                  |                            |
        |                                    |                            |
        |            +-----------------------v-----------------------+    |
        |            |              CHUNK RECEPTION                 |    |
        |            |  +--------------------------+                |    |
        |            |  | Receive chunk frame      |                |    |
        |            |  +------------+-------------+                |    |
        |            |               |                              |    |
        |            |  +------------v-------------+                |    |
        |            |  | Decrypt (AES-256-GCM)    |                |    |
        |            |  +------------+-------------+                |    |
        |            |               |                              |    |
        |            |  +------------v-------------+                |    |
        |            |  | Parse: [UUID|SEQ|DATA]   |                |    |
        |            |  +------------+-------------+                |    |
        |            |               |                              |    |
        |            |  +------------v-------------+                |    |
        |            |  | Check bitmap (duplicate) |                |    |
        |            |  +------------+-------------+                |    |
        |            |               |                              |    |
        |            |  +------------v-------------+                |    |
        |            |  | SHA3-256 hash (per chunk)|                |    |
        |            |  +------------+-------------+                |    |
        |            |               |                              |    |
        |            |  +------------v-------------+                |    |
        |            |  | Buffer in memory         |                |    |
        |            |  | (BTreeMap<seq, data>)    |                |    |
        |            |  +------------+-------------+                |    |
        |            |               |                              |    |
        |            |  +------------v-------------+                |    |
        |            |  | Flush to disk when       |                |    |
        |            |  | sequential or buffer full|                |    |
        |            |  +------------+-------------+                |    |
        |            |               |                              |    |
        |            |  +------------v-------------+                |    |
        |            |  | Progress report          |                |    |
        |            |  +--------------------------+                |    |
        |            +-----------------------+-----------------------+    |
        |                                    |                            |
        |     Hash {sha3_256, merkle_root}   |                            |
        |<-----------------------------------|                            |
        |                                    |                            |
        +--------v--------+                  |                            |
        | finalize()       |                  |                            |
        | - Flush buffer   |                  |                            |
        | - Read back file |                  |                            |
        | - Compute SHA3   |                  |                            |
        | - Build Merkle   |                  |                            |
        | - Verify match   |                  |                            |
        +--------+--------+                  |                            |
        |                                    |                            |
        |     HashResult {ok: true/false}    |                            |
        |----------------------------------->|                            |
        |                                    |                            |
        |                              +-----v-----+                      |
        |                              | commit()   |                     |
        |                              | atomic rename                    |
        |                              | temp -> final                     |
        |                              +-----+-----+                      |
        |                                    |                            |
        |                              AppEvent                       |
        |                              .FileComplete                  |
        |                                    +--------------------------->|
        |                                    |                     Update UI
```

### 11.3 File Chunk Frame Format

```
                                    CHUNK FRAME FORMAT
                                    ==================

    Wire Format (after encryption envelope):
    ========================================

    +--------+--------+--------+------------------+
    | 1 byte | 16 bytes| 4 bytes|    N bytes       |
    +--------+--------+--------+------------------+
    | Frame  | File   | Chunk  |   Chunk Data     |
    | Type   | UUID   | Seq    |   (up to 48KB)   |
    +--------+--------+--------+------------------+
    | 0x02   | UUID   | BE u32 |   Raw bytes      |
    | (CHUNK)|        |        |                  |
    +--------+--------+--------+------------------+

    Encryption Envelope:
    ====================

    +--------+----------------+------------------+
    | 1 byte |   12 bytes     |   N bytes        |
    +--------+----------------+------------------+
    | Compress| Nonce         |   Ciphertext     |
    | Flag    | (random)      |   (AES-256-GCM)  |
    +--------+----------------+------------------+
    | 0x00 or|                |                  |
    | 0x01   |                |                  |
    +--------+----------------+------------------+

    Compression:
    - 0x00 = No compression (file chunks)
    - 0x01 = Brotli compressed (control messages)
```

---

## 12. Transaction State Machine

### 12.1 Transaction States

```
                                    TRANSACTION STATE MACHINE
                                    ========================

                                    +------------+
                                    |   Pending  |
                                    +-----+------+
                                          |
                     +--------------------+--------------------+
                     |                                         |
            +--------v--------+                       +--------v--------+
            | TransactionAccepted                     | TransactionRejected
            | (peer accepted) |                       | (peer declined) |
            +--------+--------+                       +--------+--------+
                     |                                         |
            +--------v--------+                       +--------v--------+
            |     Active      |                       |    Rejected     |
            | (transferring)  |                       |    (terminal)   |
            +--------+--------+                       +-----------------+
                     |
         +-----------+-----------+-----------+
         |           |           |           |
    +----v----+ +----v----+ +----v----+ +----v----+
    | Complete| | Cancel  | | Error   | | Disconnect
    | (all OK)| | (user)  | | (fail)  | | (network)
    +----+----+ +----+----+ +----+----+ +----+----+
         |           |           |           |
         |           |           |    +------v------+
         |           |           |    | Interrupted |
         |           |           |    +------+------+
         |           |           |           |
    +----v----+ +----v----+ +----v----+      |
    |Completed| |Cancelled| | Failed  | +-----v-----+
    |(terminal)| |(terminal)| |(terminal)| | Resumable |
    +---------+ +---------+ +---------+ +-----+-----+
                                              |
                                    +---------v----------+
                                    | Peer Reconnects     |
                                    +---------+----------+
                                              |
                             +------------------+------------------+
                             |                                     |
                      +------v------+                       +------v------+
                      | Resume      |                       | Resume      |
                      | (inbound)   |                       | (outbound)  |
                      +------+------+                       +------+------+
                             |                                     |
                      +------v------+                       +------v------+
                      | Send        |                       | Wait for    |
                      | ResumeRequest|                      | ResumeRequest
                      +------+------+                       +------+------+
                             |                                     |
                      +------v------+                       +------v------+
                      | ResumeAccepted|                     | Process     |
                      +------+------+                       | ResumeRequest
                             |                              +------+------+
                      +------v------+                              |
                      | Reactivate  |                       +------v------+
                      | Transaction |                       | ResendFiles |
                      +-------------+                       +-------------+
```

### 12.2 Transaction Lifecycle Events

```
                                    TRANSACTION LIFECYCLE
                                    =====================

    Outbound Transaction (Sending):
    ===============================

    1. initiate_file_send() / initiate_folder_send()
       -> State: Pending
       -> Action: SendTransactionRequest

    2. TransactionAccepted received
       -> State: Active
       -> Action: SendFileData / SendFolderData

    3. FileProgress events (during transfer)
       -> State: Active (ongoing)
       -> Persist every 10 chunks

    4. SendComplete received (per file)
       -> Mark file complete
       -> If all files done: SendTransactionComplete

    5. TransactionCompleteAcked received
       -> State: Completed
       -> Archive transaction

    -- Error Paths --

    3a. TransactionRejected received
        -> State: Rejected
        -> Archive transaction

    3b. TransactionCancelled received
        -> State: Cancelled
        -> Archive transaction

    3c. PeerDisconnected event
        -> State: Interrupted -> Resumable
        -> Persist for resume

    -- Resume Path --

    4a. PeerReconnected + Resumable transaction
        -> Wait for TransactionResumeRequested

    4b. TransactionResumeRequested received
        -> Validate resume request
        -> Action: AcceptResume + ResendFiles
        -> State: Active

    Inbound Transaction (Receiving):
    ================================

    1. TransactionRequested received
       -> State: Pending (in PendingIncoming)
       -> Show popup to user

    2. User accepts (accept_incoming)
       -> State: Active
       -> Action: PrepareReceive + SendTransactionResponse(accepted)

    3. FileProgress events (during transfer)
       -> State: Active (ongoing)
       -> Persist every 10 chunks

    4. FileComplete received (per file)
       -> Mark file complete
       -> If all files done: State = Completed

    5. TransactionComplete received
       -> Send TransactionCompleteAck
       -> Archive transaction

    -- Resume Path --

    4a. PeerDisconnected event
        -> State: Interrupted -> Resumable
        -> Persist for resume

    4b. PeerReconnected + Resumable inbound
        -> Action: PrepareReceive + SendResumeRequest

    4c. TransactionResumeAccepted received
        -> State: Active
        -> Wait for incoming chunks
```

---

## 13. WebRTC Data Flow

### 13.1 Connection Architecture

```
                                    WEBRTC CONNECTION ARCHITECTURE
                                    ==============================

    +-------------------------------------------------------------------+
    |                         WebRTCConnection                          |
    +-------------------------------------------------------------------+
    |                                                                   |
    |  +---------------------+        +---------------------+           |
    |  |   Control Channel   |        |    Data Channel     |           |
    |  |   (JSON messages)   |        |   (Binary chunks)  |           |
    |  +----------+----------+        +----------+----------+           |
    |             |                              |                       |
    |  +----------v----------+        +----------v----------+           |
    |  | ControlMessage      |        | Chunk Frames        |           |
    |  | - Text/DM           |        | - FRAME_CHUNK       |           |
    |  | - Transaction*      |        | - [UUID|SEQ|DATA]   |           |
    |  | - Metadata          |        +---------------------+           |
    |  | - Hash              |                                          |
    |  | - LsRequest/Response|                                          |
    |  | - FetchRequest      |                                          |
    |  +---------------------+                                          |
    |                                                                   |
    |  +---------------------+        +---------------------+           |
    |  | Shared Key          |        | Key Manager         |           |
    |  | (AES-256-GCM)       |        | (Session Key        |           |
    |  |                     |        |  Rotation)          |           |
    |  +---------------------+        +---------------------+           |
    |                                                                   |
    |  +---------------------+        +---------------------+           |
    |  | Receive State       |        | Accepted            |           |
    |  | HashMap<UUID,       |        | Destinations        |           |
    |  |   ReceiveFileState> |        | HashMap<UUID, Path> |           |
    |  +---------------------+        +---------------------+           |
    |                                                                   |
    |  +---------------------+        +---------------------+           |
    |  | Wire Statistics     |        | Chat Counters       |           |
    |  | (TX/RX bytes)       |        | (send/recv)         |           |
    |  +---------------------+        +---------------------+           |
    +-------------------------------------------------------------------+
                                    |
                                    v
    +-------------------------------------------------------------------+
    |                         RTCPeerConnection                        |
    +-------------------------------------------------------------------+
    |                                                                   |
    |  +---------------------+        +---------------------+           |
    |  | ICE Candidates      |        | SCTP Transport      |           |
    |  | (STUN/TURN)         |        | (Data Channels)    |           |
    |  +---------------------+        +---------------------+           |
    |                                                                   |
    +-------------------------------------------------------------------+
```

### 13.2 Encryption Pipeline

```
                                    ENCRYPTION PIPELINE
                                    ===================

    Outbound (Sending):
    ===================

    +-------------+     +-------------+     +-------------+     +-------------+
    | Plaintext   | --> | Brotli      | --> | AES-256-GCM | --> | WebRTC      |
    | (message/   |     | Compress    |     | Encrypt     |     | Send        |
    |  chunk)     |     | (optional)  |     |             |     |             |
    +-------------+     +-------------+     +-------------+     +-------------+
                            |                    |
                            v                    v
                     +-------------+     +-------------+
                     | 0x01 flag   |     | Nonce (12B) |
                     | if compressed|    | + Ciphertext|
                     +-------------+     +-------------+

    Wire Format:
    ============

    +--------+------------+------------------+
    | 1 byte |  12 bytes  |    N bytes       |
    +--------+------------+------------------+
    | Compress| Nonce      | Encrypted        |
    | Flag    | (random)   | Payload          |
    +--------+------------+------------------+

    Inbound (Receiving):
    ====================

    +-------------+     +-------------+     +-------------+     +-------------+
    | WebRTC      | --> | AES-256-GCM | --> | Brotli      | --> | Plaintext   |
    | Receive     |     | Decrypt     |     | Decompress  |     | (message/   |
    |             |     |             |     | (if flag)   |     |  chunk)     |
    +-------------+     +-------------+     +-------------+     +-------------+
```

### 13.3 Backpressure Handling

```
                                    BACKPRESSURE MECHANISM
                                    ======================

    Sender Side:
    ============

    +-------------------+
    | Check buffered_amount
    +--------+----------+
             |
    +--------v----------+     +-------------------+
    | buffered + next   | --> | Send immediately  |
    | <= HIGH_WATERMARK |     | (no wait)         |
    +--------+----------+     +-------------------+
             |
             | (else)
    +--------v----------+
    | Wait for buffer   |
    | to drain          |
    +--------+----------+
             |
    +--------v----------+
    | Poll every 10ms   |
    | (max 10 seconds)  |
    +--------+----------+
             |
    +--------v----------+     +-------------------+
    | Channel still     | --> | Proceed with send |
    | open?             |     | (timeout)         |
    +--------+----------+     +-------------------+
             |
             | (else)
    +--------v----------+
    | Return error      |
    | (channel closed)  |
    +-------------------+

    Constants:
    ==========

    DC_BUFFERED_AMOUNT_HIGH = 4MB
    - Maximum buffered data before applying backpressure

    DC_SEND_MAX_RETRIES = 10
    - Retries for transient "not open" errors

    DC_REOPEN_TIMEOUT = 10 seconds
    - Time to wait for channel to reopen
```

---

## 14. Configuration Constants

All configuration constants are centralized in [`core/config.rs`](src/core/config.rs).

### 14.1 Transfer / Chunking

| Constant | Value | Description |
|----------|-------|-------------|
| `CHUNK_SIZE` | 48 KB | Size of each file chunk |
| `PIPELINE_SIZE` | 32 | Chunks per progress report batch |
| `SENDER_READ_AHEAD_CHUNKS` | 64 | Prefetch buffer size |
| `RECEIVER_WRITE_BUFFER_CHUNKS` | 64 | In-memory write buffer capacity |
| `MAX_PENDING_FILE_ACKS` | 5 | Maximum files waiting for ACK |

### 14.2 Transactions

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_CONCURRENT_TRANSACTIONS` | 6 | Maximum simultaneous active transfers |
| `MAX_TRANSACTION_RETRIES` | 100 | Maximum total retries per transaction |
| `TRANSACTION_TIMEOUT` | 24 hours | Transaction expiration time |
| `MAX_FILE_RETRANSMISSIONS` | 3 | Retries per file before failure |

### 14.3 Safety / Abuse Prevention

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_PENDING_CHUNKS_PER_FILE` | 64 | Max buffered chunks before Metadata |
| `MAX_PENDING_FILE_IDS` | 16 | Max distinct file IDs in pending buffer |

### 14.4 Connection / Network

| Constant | Value | Description |
|----------|-------|-------------|
| `SCTP_MAX_MESSAGE_SIZE` | 1 MB | Explicit SCTP max message size |
| `CONNECTION_TIMEOUT` | 60 seconds | WebRTC peer connection timeout |
| `DATA_CHANNEL_TIMEOUT` | 30 seconds | Data channel open timeout |
| `DC_SEND_MAX_RETRIES` | 10 | Transient error retries |
| `DC_REOPEN_TIMEOUT` | 10 seconds | Channel reopen wait time |
| `DC_BACKPRESSURE_MAX_WAIT` | 10 seconds | Max wait for backpressure |
| `DC_BUFFERED_AMOUNT_HIGH` | 4 MB | Backpressure threshold |
| `ICE_GATHER_TIMEOUT` | 15 seconds | ICE candidate gathering timeout |
| `KEY_ROTATION_INTERVAL` | 1 hour | Session key rotation interval |
| `PORT_RETRY_ATTEMPTS` | 10 | Port binding retry attempts |

### 14.5 Liveness / Reconnect

| Constant | Value | Description |
|----------|-------|-------------|
| `AWAKE_CHECK_TIMEOUT` | 5 seconds | Liveness probe timeout |
| `INITIAL_CONNECT_MAX_RETRIES` | 3 | Initial connection retries |
| `INITIAL_CONNECT_RETRY_DELAYS` | [5, 15, 30] | Delays between retries (seconds) |
| `RECONNECT_MAX_RETRIES` | 5 | Reconnect attempts after drop |
| `RECONNECT_RETRY_DELAYS` | [3, 5, 10, 20, 30] | Reconnect delays (seconds) |

### 14.6 UI / Misc

| Constant | Value | Description |
|----------|-------|-------------|
| `TYPING_TIMEOUT_SECS` | 3 | Typing indicator expiration |
| `MAX_LOG_ENTRIES` | 500 | In-memory log ring buffer size |
| `TRANSACTION_EXPIRY_SECS` | 24 hours | Resumable transaction cleanup |

---

## 15. Data Structures Summary

### 15.1 Key Types

```
                                    KEY DATA STRUCTURES
                                    ===================

    Transaction:
    ============
    +-------------------+-------------------+
    | id: Uuid          | state: TransactionState
    | direction: Direction| peer_id: String   |
    | display_name: Str | parent_dir: Option|
    | total_size: u64   | dest_path: Option |
    | file_order: Vec<Uuid>| files: HashMap<Uuid, TransactionFile>
    | created_at: Instant| resumed_at: Option|
    +-------------------+-------------------+

    TransactionFile:
    ================
    +-------------------+-------------------+
    | file_id: Uuid     | relative_path: Str|
    | filesize: u64     | total_chunks: u32 |
    | transferred_chunks| completed: bool   |
    | verified: Option  | chunk_bitmap: Option
    | merkle_root: Option| retransmit_count |
    | full_path: Option |                   |
    +-------------------+-------------------+

    TransactionManifest:
    ====================
    +-------------------+-------------------+
    | files: Vec<ManifestEntry>| parent_dir: Option
    | sender_id: Option | signature: Option |
    | nonce_seed: Option| expiration_time   |
    +-------------------+-------------------+

    ResumeInfo:
    ===========
    +-------------------+-------------------+
    | transaction_id    | completed_files   |
    | partial_offsets   | partial_checksums |
    | chunk_bitmaps     | hmac: Option      |
    | receiver_signature|                   |
    +-------------------+-------------------+

    StreamingFileWriter:
    ====================
    +-------------------+-------------------+
    | file: File        | temp_path: PathBuf|
    | final_path: PathBuf| filesize: u64     |
    | total_chunks: u32 | received_chunks   |
    | chunk_hashes: Vec | bitmap: ChunkBitmap
    | write_buffer: BTreeMap| next_flush_seq |
    | verifier: Option  | failed_chunks: Vec|
    +-------------------+-------------------+

    ReceiveFileState:
    =================
    +-------------------+-------------------+
    | writer: StreamingFileWriter| pending_hash: Option
    +-------------------+-------------------+
```

---

This document provides a comprehensive reference for understanding the Crossdrop architecture. For implementation details, refer to the source code in the respective modules.