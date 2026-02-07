# Crossdrop Architecture Documentation

This document provides a high-level overview of the Crossdrop system architecture, focusing on component relationships, core logic flows, and architectural principles.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Core Module](#3-core-module)
4. [Connection Layer](#4-connection-layer)
5. [Pipeline Module](#5-pipeline-module)
6. [Security Module](#6-security-module)
7. [UI Module](#7-ui-module)
8. [Workers Module](#8-workers-module)
9. [Utils Module](#9-utils-module)
10. [Core Logic Flows](#10-core-logic-flows)

---

## 1. Project Overview

Crossdrop is a peer-to-peer file sharing and chat application built in Rust. It enables direct, secure communication between peers without requiring a central server for data transfer.

### Key Technologies

| Technology                 | Purpose                                             |
|----------------------------|-----------------------------------------------------|
| **Iroh**                   | P2P discovery, NAT traversal, and signaling         |
| **WebRTC**                 | Direct peer connections with reliable data channels |
| **SHA3-256 / AES-256-GCM** | Cryptographic operations                            |
| **X25519-Dalek**           | ECDH key exchange                                   |
| **Ratatui**                | Terminal user interface                             |
| **Tokio**                  | Async runtime                                       |
| **Brotli**                 | Control message compression                         |
| **Clap**                   | CLI argument parsing                                |
| **Tracing**                | Structured logging                                  |

### Core Features

- **Direct P2P File Transfers**: Transfer files and folders directly between peers with resume capability
- **Real-time Messaging**: Broadcast chat and direct messages between peers
- **Remote File Browsing**: Browse and fetch files from connected peers' filesystems
- **End-to-End Encryption**: Session-based encryption with automatic key rotation
- **Integrity Verification**: Merkle tree verification for all file transfers

---

## 2. System Architecture

Crossdrop follows a layered architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────────┐
│                        UI Layer (ui/)                           │
│  Panels, Popups, Widgets, Event Handling                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Application State (workers/)                 │
│  App Model, Settings, Peer State, Chat State                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Core Domain (core/)                         │
│  TransferEngine, PeerNode, Transaction, Persistence             │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   Connection    │ │    Pipeline     │ │    Security     │
│   (Iroh+WebRTC) │ │ (Chunk/Merkle)  │ │ (Identity/HMAC) │
└─────────────────┘ └─────────────────┘ └─────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Utils (utils/)                             │
│  Crypto, Atomic I/O, Logging, System Integration                │
└─────────────────────────────────────────────────────────────────┘
```

### Architectural Principles

1. **Single Source of Truth**: The `TransferEngine` is the sole coordinator of all transfer logic. No transfer state exists outside the engine.

2. **Declarative Actions**: Components return action enums rather than performing I/O directly, keeping them testable and decoupled.

3. **Defense in Depth**: Multiple security layers protect against tampering: manifest signing, chunk hashing, Merkle verification, and replay guards.

4. **Crash Resilience**: All critical state is persisted atomically; interrupted transfers resume automatically on restart.

---

## 3. Core Module

The core module contains the heart of the application's business logic.

### Module Organization

| Module                                       | Responsibility                           |
|----------------------------------------------|------------------------------------------|
| [`config`](src/core/config.rs)               | Centralized configuration constants      |
| [`engine`](src/core/engine.rs)               | Transfer state machine and coordination  |
| [`initializer`](src/core/initializer.rs)     | PeerNode orchestration and event routing |
| [`transaction`](src/core/transaction.rs)     | Transaction lifecycle management         |
| [`persistence`](src/core/persistence.rs)     | JSON-based state storage                 |
| [`peer_registry`](src/core/peer_registry.rs) | Persistent peer directory                |
| [`helpers`](src/core/helpers.rs)             | Internal helper functions                |

### TransferEngine

The `TransferEngine` is the central coordinator for all file transfer operations. It operates as a pure state machine with no direct network or async concerns.

**Key Responsibilities**:
- Processing transfer requests and responses
- Managing transaction state transitions
- Coordinating multi-file transfers
- Handling resume logic after interruptions
- Generating declarative actions for the UI layer
- Tracking comprehensive data statistics

**Design Pattern**: The engine returns `EngineAction` enums that describe what should happen, rather than performing operations directly. This keeps the engine testable and decoupled from I/O.

**Engine Actions**:
- `SendTransactionRequest` / `SendTransactionResponse`
- `PrepareReceive` / `SendFileData` / `SendFolderData`
- `SendTransactionComplete` / `CancelTransaction`
- `AcceptResume` / `SendResumeRequest` / `RejectResume`
- `RetransmitChunks` / `CleanupTransferFiles`

### PeerNode

`PeerNode` manages peer connections and serves as the bridge between the Iroh discovery layer and WebRTC data channels.

**Key Responsibilities**:
- Iroh endpoint management
- WebRTC connection establishment (offerer/answerer roles)
- ECDH handshake coordination
- Event broadcasting to the UI layer
- Message queuing for offline peers

### Transaction System

Transactions represent atomic transfer operations with well-defined lifecycle states:

```
Pending → Active → Completed
        ↘ Rejected
        ↘ Cancelled
        ↘ Interrupted → Resumable
```

The transaction system supports:
- Multi-file transfers with ordered delivery
- Resume from interruption points
- Manifest signing for sender authentication
- Progress tracking and statistics
- Chunk bitmap tracking for resume support

### Configuration Constants

Key tunable parameters defined in [`config.rs`](src/core/config.rs):

| Constant                      | Value    | Purpose                       |
|-------------------------------|----------|-------------------------------|
| `CHUNK_SIZE`                  | 56 KB    | File chunk size for transfer  |
| `PIPELINE_SIZE`               | 64       | Sliding-window pipeline depth |
| `MAX_CONCURRENT_TRANSACTIONS` | 6        | Simultaneous active transfers |
| `TRANSACTION_TIMEOUT`         | 24 hours | Transaction expiry time       |
| `KEY_ROTATION_INTERVAL`       | 1 hour   | Session key rotation          |
| `DC_BUFFERED_AMOUNT_HIGH`     | 4 MB     | Backpressure threshold        |

---

## 4. Connection Layer

The connection layer provides peer-to-peer connectivity through a hybrid Iroh + WebRTC approach.

### Design Rationale

| Technology  | Strength                            | Role in Crossdrop               |
|-------------|-------------------------------------|---------------------------------|
| **Iroh**    | NAT traversal, global peer IDs      | Initial discovery and signaling |
| **WebRTC**  | High throughput, congestion control | Data transfer once connected    |

This combination provides the best of both worlds: Iroh excels at establishing connections through difficult NATs, while WebRTC provides excellent throughput for large file transfers.

### Connection Establishment Flow

```
Offerer                              Answerer
────────                             ────────
Iroh.connect() ─────────────────────► Iroh.accept()
       │                                    │
       ▼                                    ▼
Open bi-stream ◄──────────────────────► Accept bi-stream
       │                                    │
       ▼                                    ▼
ECDH handshake (X25519) ◄─────────────► ECDH handshake
       │                                    │
       ▼                                    ▼
Send WebRTC offer ──────────────────► Receive offer
       │                                    │
       ◄────────────────────────────── Send WebRTC answer
       │                                    │
       ▼                                    ▼
ICE negotiation (STUN/TURN/relay)
       │                                    │
       ▼                                    ▼
Data channels open (control + data)
```

### WebRTC Module Organization

| Module           | Responsibility                                  |
|------------------|-------------------------------------------------|
| `connection.rs`  | WebRTC connection wrapper                       |
| `control.rs`     | Incoming message dispatch                       |
| `sender.rs`      | Outbound operations (files, messages, control)  |
| `receiver.rs`    | Inbound operations (finalization, verification) |
| `initializer.rs` | Connection setup and data channel negotiation   |
| `data.rs`        | Binary frame encoding/decoding                  |
| `helpers.rs`     | Crypto, compression, path sanitization          |
| `types.rs`       | Protocol enums and internal state               |

### Data Channels

Two separate channels prevent head-of-line blocking:

- **Control Channel**: JSON messages for chat, transactions, metadata
- **Data Channel**: Binary frames for file chunks

### Security Model

1. **ECDH Key Exchange**: X25519 ephemeral key exchange over Iroh bootstrap channel
2. **Session Key Derivation**: HKDF-SHA3-256 with peer IDs as salt
3. **AES-256-GCM Encryption**: All data channel traffic encrypted with unique nonces
4. **Key Rotation**: Hourly automatic rotation with forward secrecy

---

## 5. Pipeline Module

The pipeline module implements high-performance file transfer with integrity verification.

### Pipeline Architecture

The pipeline is asymmetric, with different stages optimized for sender and receiver roles:

**Sender Pipeline**:
```
File on Disk → Chunk Reader → Hash + Merkle → Encrypt → Send Queue → WebRTC
```

**Receiver Pipeline**:
```
WebRTC → Decrypt → Hash Verify → Write Buffer → File on Disk
```

### Module Organization

| Module                                      | Responsibility                                        |
|---------------------------------------------|-------------------------------------------------------|
| [`chunk`](src/core/pipeline/chunk.rs)       | Chunk bitmap for tracking received/missing chunks     |
| [`merkle`](src/core/pipeline/merkle.rs)     | Merkle tree construction and incremental verification |
| [`sender`](src/core/pipeline/sender.rs)     | Async sender pipeline with read-ahead buffering       |
| [`receiver`](src/core/pipeline/receiver.rs) | Async receiver pipeline with streaming writes         |

### Integrity Model

Three levels of integrity protection:

1. **Per-Chunk SHA3-256**: Each chunk hashed independently; failed chunks retransmitted individually
2. **Merkle Root**: All chunk hashes form a Merkle tree; verified at transfer end
3. **AES-GCM Authentication**: Encryption provides authentication tags for ciphertext integrity

### Resume Support

The `ChunkBitmap` tracks which chunks have been received. On interruption:
1. Receiver persists bitmap to disk
2. On reconnect, receiver sends bitmap to sender
3. Sender resumes from first missing chunk

This avoids retransmitting already-received data, critical for large files on unreliable networks.

---

## 6. Security Module

The security module provides cryptographic primitives for peer authentication and message integrity.

### Module Organization

| Module                                              | Responsibility                                         |
|-----------------------------------------------------|--------------------------------------------------------|
| [`identity`](src/core/security/identity.rs)         | Ed25519 key pair management and signature verification |
| [`message_auth`](src/core/security/message_auth.rs) | HMAC computation and verification                      |
| [`replay`](src/core/security/replay.rs)             | Monotonic counter-based replay protection              |

### Security Architecture

Crossdrop uses a layered security approach:

1. **Transport Security** (connection layer): ECDH session keys with AES-256-GCM encryption
2. **Application Security** (security module): Ed25519 identity signing, HMAC authentication, replay protection

### Identity Model

Each peer has a long-term Ed25519 key pair:
- **Public key**: Serves as the peer's unique identifier
- **Private key**: Never transmitted; used only for signing

The identity signs transfer manifests and resume requests, proving sender authenticity.

### Message Authentication

Critical protocol messages use HMAC-SHA3-256 with monotonic counters to prevent replay attacks.

---

## 7. UI Module

The UI module implements the terminal user interface using Ratatui.

### Architecture Pattern

The UI follows a Model-View-Controller inspired pattern:

- **Model** (`App`): Application state including peers, transfers, chat, settings
- **View** (Panels, Widgets): Rendering logic for each screen
- **Controller** (`UIExecuter`): Event loop bridging input, network events, and state

### Module Organization

| Module                           | Responsibility                      |
|----------------------------------|-------------------------------------|
| [`executer`](src/ui/executer.rs) | Main event loop and action dispatch |
| [`commands`](src/ui/commands.rs) | Chat command parsing                |
| [`notify`](src/ui/notify.rs)     | User notification system            |
| [`traits`](src/ui/traits.rs)     | Shared component traits             |
| [`panels`](src/ui/panels/)       | Full-screen panels for each mode    |
| [`popups`](src/ui/popups/)       | Modal dialogs                       |
| [`widgets`](src/ui/widgets/)     | Reusable UI components              |
| [`helpers`](src/ui/helpers/)     | Formatting and utility functions    |

### Navigation Model

```
Home (main menu)
 ├── Chat (room + DM messaging)
 ├── Send (initiate file/folder transfer)
 ├── Connect (enter peer ticket)
 ├── Peers (view/manage connected peers)
 ├── Files (active transfers + history)
 ├── Logs (tracing log viewer)
 ├── Id (display own peer ID / ticket)
 ├── Settings (display name, theme, remote access)
 ├── Remote (browse peer's filesystem)
 └── KeyListener (receive remote keystrokes)
```

### Event Flow

```
User Input → UIExecuter → Panel::handle_key() → Action enum
                                              │
                              ┌───────────────┼───────────────┐
                              ▼               ▼               ▼
                         SwitchMode    EngineActions    SetStatus
```

---

## 8. Workers Module

The workers module defines application state models that bridge the UI and domain logic.

### Module Organization

| Module                                | Responsibility                         |
|---------------------------------------|----------------------------------------|
| [`app`](src/workers/app.rs)           | Main application state container       |
| [`args`](src/workers/args.rs)         | CLI argument parsing and configuration |
| [`peer`](src/workers/peer.rs)         | Peer-related state                     |
| [`settings`](src/workers/settings.rs) | User-configurable settings             |

### State Architecture

```
App
├── mode: Mode (current screen)
├── engine: TransferEngine (transfer state machine)
├── notify: NotifyManager (user notifications)
└── state: State
    ├── peers: PeerState (connectivity, names)
    ├── chat: ChatState (messages, typing, unread)
    ├── remote: RemoteState (file browsing)
    ├── files: FilesPanelState (UI state)
    ├── settings: Settings (user preferences)
    └── transfer: TransferState (send panel state)
```

### Design Principles

1. **State Separation**: UI state (scroll positions, input buffers) is separate from domain state
2. **Single Source of Truth**: `App` owns all state; panels read from it
3. **Enum-Driven Modes**: `Mode` enum ensures exhaustive handling of all screens

---

## 9. Utils Module

The utils module provides cross-cutting utilities used throughout the application.

### Module Organization

| Module                                            | Responsibility                              |
|---------------------------------------------------|---------------------------------------------|
| [`atomic_write`](src/utils/atomic_write.rs)       | Atomic file writes via temp-file + rename   |
| [`clipboard`](src/utils/clipboard.rs)             | System clipboard integration                |
| [`crypto`](src/utils/crypto.rs)                   | HMAC-SHA3-256 computation                   |
| [`data_dir`](src/utils/data_dir.rs)               | Platform-specific data directory            |
| [`global_keyboard`](src/utils/global_keyboard.rs) | Global keyboard hook                        |
| [`hash`](src/utils/hash.rs)                       | Brotli compression, identity key management |
| [`log_buffer`](src/utils/log_buffer.rs)           | In-memory log ring buffer                   |
| [`sos`](src/utils/sos.rs)                         | Signal-of-stop for graceful shutdown        |

### Design Principles

- **No Business Logic**: Only infrastructure code
- **Single Responsibility**: Each module does one thing well
- **Cross-Platform**: Works on Windows, macOS, and Linux

---

## 10. Core Logic Flows

### Message Flow

```
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
    |                           |                     Derive HMAC
    |                           |                     Create AuthMsg
    |                           |                     JSON Encode
    |                           |                     Brotli Compress
    |                           |                     AES-256-GCM Encrypt
    |                           |                              |
    |                           |                     WebRTC Send
```

### File Transfer Flow (Outbound)

```
UI Layer                    Core Layer                    Transport Layer
========                    ==========                    ===============
Send Panel                  TransferEngine                WebRTCConnection
    |                           |                              |
    | initiate_file_send()      |                              |
    +-------------------------->|                              |
    |                           |                              |
    |                     Create Transaction                   |
    |                     Sign Manifest                        |
    |                           |                              |
    |                     EngineAction                        |
    |                     .SendTransactionRequest              |
    |                           +-----------> ControlMessage  |
    |                           |             --------------->|
    |                           |                              |
    |                           |                     Peer accepts
    |                           |<---- TransactionAccepted ----|
    |                           |                              |
    |                     Activate Transaction                 |
    |                           |                              |
    |                     EngineAction                        |
    |                     .SendFileData                       |
    |                           +-----------> send_file() ---->|
    |                           |                              |
    |                           |                     Spawn Disk Reader
    |                           |                     Send Metadata
    |                           |                              |
    |                           |            CHUNK LOOP        |
    |                           |            Read → Hash → Encrypt → Send
    |                           |                              |
    |                           |                     Send Hash
    |                           |                     Wait HashResult
    |                           |<---- HashResult {ok: true} ---|
    |                           |                              |
    |                     Complete File                        |
    |                           |                              |
    |                     EngineAction                        |
    |                     .SendTransactionComplete            |
    |                           +-----------> ControlMessage  |
    |                           |             --------------->|
    |                           |<---- TransactionCompleteAck -|
    |                           |                              |
    |                     Archive Transaction                  |
```

### File Transfer Flow (Inbound)

```
Transport Layer                    Core Layer                    UI Layer
==============                    ==========                    ========
WebRTCConnection                   TransferEngine               App/Files Panel
    |                                    |                            |
    |<--- TransactionRequest -----------|                            |
    |                                    |                            |
    |     ConnectionMessage              |                            |
    |     .TransactionRequested          |                            |
    +----------------------------------->|                            |
    |                                    |                            |
    |                              Validate Manifest                  |
    |                              Create PendingIncoming             |
    |                                    |                            |
    |                              AppEvent                     |
    |                              .TransactionRequested         |
    |                                    +--------------------------->|
    |                                    |                     Show popup
    |                                    |<--- User accepts -----------|
    |                                    |                            |
    |                              Create Inbound Transaction         |
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
    |     CHUNK RECEPTION                |                            |
    |     Receive → Decrypt → Verify → Write                         |
    |                                    |                            |
    |     Hash {sha3_256, merkle_root}   |                            |
    |<-----------------------------------|                            |
    |                                    |                            |
    |     finalize()                     |                            |
    |     Flush → Verify → Atomic rename |                            |
    |                                    |                            |
    |     HashResult {ok: true/false}    |                            |
    |----------------------------------->|                            |
    |                                    |                            |
    |                              commit()                          |
    |                              AppEvent                     |
    |                              .FileComplete                  |
    |                                    +--------------------------->|
    |                                    |                     Update UI
```

### Transaction State Machine

```
                                +------------+
                                |   Pending  |
                                +-----+------+
                                      |
                 +--------------------+--------------------+
                 |                                         |
        +--------v--------+                       +--------v--------+
        |   Accepted     |                       |    Rejected     |
        | (peer accepted)|                       | (peer declined) |
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
                           +--------------+--------------+
                           |                             |
                    +------v------+               +------v------+
                    | Resume      |               | Resume      |
                    | (inbound)   |               | (outbound)  |
                    +------+------+               +------+------+
                           |                             |
                    +------v------+               +------v------+
                    | Reactivate  |               | ResendFiles |
                    | Transaction |               +-------------+
                    +-------------+
```

---

This document provides a high-level reference for understanding the Crossdrop architecture. For implementation details, refer to the source code and inline documentation in each module.
