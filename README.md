# Crossdrop

A minimalistic, encrypted peer-to-peer file sharing and chat tool with a terminal UI — written in Rust.

No servers, no accounts. Just share a ticket and start transferring.

![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Rust](https://img.shields.io/badge/rust-2024-orange)

---

## Features

- **Direct P2P** — WebRTC data channels with NAT traversal (STUN/TURN)
- **End-to-end encrypted** — AES-256-GCM with per-peer ECDH-derived keys (X25519 + HKDF)
- **Compressed + encrypted pipeline** — data is Brotli-compressed before encryption, reducing wire traffic
- **File & folder transfer** — chunked pipeline with SHA3-256 integrity verification and Merkle tree roots
- **Async multi-stage pipelines** — sender and receiver each run a fully decoupled pipeline (chunk → compress → encrypt → send / receive → decrypt → decompress → verify → write) with configurable concurrency and backpressure
- **Parallel folder preparation** — disk I/O and network I/O overlap via a prefetch buffer for faster folder sends
- **Resumable transfers** — interrupted transactions resume from the last chunk via per-file bitmaps, HMAC-signed resume requests, and persistent snapshots
- **Cryptographically signed manifests** — the sender signs an immutable file manifest before any data is transferred; the receiver validates it before ACK
- **Replay protection** — monotonic counters and transaction expiration prevent replay and out-of-order attacks
- **Message authentication** — every protocol message carries an HMAC (SHA3-256) over the session key, ensuring integrity and origin
- **Long-term peer identity** — each node holds a persistent identity key (HMAC-SHA3-256 based) stored in `~/.crossdrop/identity.key`, used to sign manifests and resume requests
- **Abuse controls** — per-chunk and per-transaction retry limits, memory budgets, pipeline depth caps, and transaction timeouts
- **Forward secrecy** — ephemeral X25519 keypairs per session with hourly key rotation
- **Offline peer awareness** — peers that lose connection are shown as offline instead of being removed, preserving chat history and identity
- **Real-time chat** — broadcast room + private DMs per peer
- **Remote filesystem browse** — navigate and fetch files from a peer's machine
- **Terminal UI** — full TUI powered by Ratatui with panels, popups and progress bars
- **Compact tickets** — connection tickets use URL-safe Base64 without padding, producing shorter and URL-friendly IDs
- **Accurate wire statistics** — bytes are tracked at the lowest network level, with compression ratio displayed in the stats bar
- **Persistent identity** — secret key saved to disk, ticket stays valid across restarts
- **Cross-platform** — Windows, macOS, Linux
- **No central server** — signaling runs over Iroh; relay is only used as fallback

---

## How It Works

### Connection Flow

```
  Peer A                                          Peer B
  ──────                                          ──────
  1. Generate / load SecretKey
  2. Create Iroh endpoint (ALPN "msg/1")
  3. Generate ticket ──────── share ──────────►  Paste ticket
                                                  4. Iroh connect + open bi-stream
  5. ◄──────────── ECDH key exchange ─────────────►
     (ephemeral X25519 keypairs, HKDF-SHA3-256 derivation)
  6. ◄──────────── SDP offer / answer ────────────►
     (WebRTC signaling over the Iroh stream)
  7. ◄══════════ WebRTC Data Channels ════════════►
     (all traffic: chat, files, control)
  8. ─── hourly key rotation (in-band ECDH) ──────
     (forward secrecy via new ephemeral keypairs)
```

1. Each node creates an **Iroh endpoint** with DNS discovery and optional relay.
2. A **ticket** (Iroh address compressed with Brotli + URL-safe Base64, version-prefixed) is shared out-of-band.
3. The connecting peer resolves the ticket and opens a bidirectional Iroh stream.
4. Both peers perform an **X25519 ECDH key exchange** over the Iroh stream: each generates an ephemeral keypair, sends its public key, and computes a shared secret. The session key is derived via **HKDF-SHA3-256** with both Iroh public keys as context.
5. **WebRTC SDP offer/answer** is exchanged over the same Iroh stream to establish a direct connection.
6. Once connected, all communication flows over **encrypted WebRTC data channels**.
7. Every hour, the offerer initiates an **in-band key rotation**: a new ephemeral X25519 keypair is generated, exchanged over the encrypted data channel, and the session key is rederived with the previous key as additional input — providing **forward secrecy**.

### Wire Protocol

All data channel frames are **Brotli-compressed then AES-256-GCM encrypted**. Three frame types:

| Byte | Type | Payload |
|------|------|---------|
| `0x01` | Control | JSON — chat messages, file offers, transaction commands |
| `0x02` | Chunk | 16-byte file_id + 4-byte sequence + raw data |
| `0x03` | Ack | 16-byte file_id + 4-byte sequence |

File transfers use **48 KB chunks** with a **32-chunk sliding window** and SHA3-256 hash verification per chunk. Each file is covered by a **Merkle tree** whose root is pre-committed in the signed manifest.

Folder transfers use a **parallel prefetch buffer** (up to 24 files / 256 MB in-flight) so disk reads overlap with network sends.

### Transfer Pipeline

Sender and receiver each run a fully **async, multi-stage pipeline** with backpressure, configurable concurrency, and memory budgets:

```
  Sender                                          Receiver
  ──────                                          ────────
  File read (prefetch 8)                           Network receive queue
      │                                                │
  Chunking (48 KB)                                 Decryption (AES-256-GCM)
      │                                                │
  Compression (Brotli q4, 2 workers)               Decompression (Brotli)
      │                                                │
  Encryption (AES-256-GCM, 2 workers)              Hash verification (SHA3-256)
      │                                                │
  Network send (window=32, semaphore)              Merkle tree reconstruction
      │                                                │
  ◄── ACK ranges (batch of 8) ───────────────────  Disk write (atomic via tmp)
```

Backpressure: the sender caps in-flight data at **64 MB**, the receiver at **128 MB**. Retry limits are enforced per-chunk (max 3) and per-transaction (max 50).

### Secure Manifest Protocol

Before any file data flows, the sender builds a **SecureManifest** — an immutable, cryptographically signed document containing:

- Transaction ID, receiver ID, expiration time
- Per-file: deterministic file ID, normalized path (no traversal, no absolute paths), size, total chunks, Merkle root
- Sender signature and nonce seed for deterministic nonce derivation

The receiver **validates the manifest** (signature, expiration, path safety, duplicate entries) before sending an ACK. The sender **refuses any chunk/file request that falls outside the manifest**.

### Resume Protocol

When a transfer is interrupted:

1. The receiver persists its **per-file chunk bitmaps** and the **secure transfer snapshot** to disk.
2. On reconnect the receiver sends a **SecureResumeRequest** containing the missing chunk indices, an HMAC over the session key, and its identity signature.
3. The sender **validates the HMAC and signature** against the original manifest, then resumes only the missing chunks.
4. The coordinator enforces replay protection (monotonic counters, transaction expiration) so stale or replayed resume requests are rejected.

---

## Installation

### From source

```bash
git clone https://github.com/sh1zen/crossdrop
cd crossdrop
cargo install --path .
```

### Or directly with cargo

```bash
cargo install crossdrop
```

---

## Usage

```bash
crossdrop [OPTIONS]
```

The TUI launches with a home screen. Navigate between panels using the keyboard.

### Quick Start

1. **Peer A** — run `crossdrop`, go to **My ID** and copy the ticket
2. **Peer B** — run `crossdrop`, go to **Connect** and paste the ticket
3. Once connected, use **Send** to transfer files or **Chat** to message

### CLI Options

| Flag | Description |
|------|-------------|
| `--config <PATH>` | Path to a TOML config file |
| `-p, --port <PORT>` | UDP port to bind (0 = auto, default: 0) |
| `-v` | Verbosity: `-v` info, `-vv` debug, `-vvv` trace |
| `--relay <MODE>` | `default`, `disabled`, or a custom relay URL |
| `--display-name <NAME>` | Display name shown to peers |
| `--remote-access` | Allow peers to browse your filesystem |
| `--secret-file <PATH>` | Path to persistent secret key file |
| `--show-secret` | Print secret key to stderr on startup |
| `--ipv4-addr <ADDR>` | IPv4 socket address to bind |
| `--ipv6-addr <ADDR>` | IPv6 socket address to bind |

### Configuration File

All CLI options can also be set in a TOML file. CLI values take precedence.

```toml
port = 4200
display_name = "my-laptop"
remote_access = false
relay = "default"
verbose = 1
```

Load it with:

```bash
crossdrop --config my_config.toml
```

---

## TUI Panels

| Panel | Key | Description |
|-------|-----|-------------|
| **Home** | — | Main menu with navigation to all panels |
| **Chat** | `c` | Broadcast room + per-peer DMs with unread counters |
| **Send** | `s` | Send files or folders to a connected peer |
| **Connect** | `n` | Paste a peer's ticket to establish a connection |
| **Peers** | `p` | List connected peers (online/offline status) and access remote browse |
| **My ID** | `i` | Show and copy your connection ticket |
| **Files** | `f` | Transfer history with search and per-peer filtering |
| **Settings** | `o` | Change display name, toggle remote access |
| **Logs** | `l` | Live application logs with scroll |
| **Remote** | — | Browse a peer's filesystem (requires remote access) |

---

## Project Structure

```
crossdrop/
├── Cargo.toml                        # Crate metadata, dependencies, release profile
├── config.toml                       # Optional TOML config (CLI overrides)
├── LICENSE                           # Apache-2.0 license
├── README.md
│
├── src/
│   ├── main.rs                       # Entry point: arg parsing, tracing init, shutdown handler
│   │
│   ├── core/                         # ── Core domain: networking, security, transfer logic ──
│   │   ├── mod.rs                    # Re-exports all core sub-modules
│   │   ├── engine.rs                 # TransferEngine — sole state-machine coordinator for all transfers
│   │   ├── initializer.rs            # PeerNode — peer lifecycle, Iroh/WebRTC setup, event dispatch
│   │   ├── transaction.rs            # Transaction state machine, manifest, chunk bitmaps, resume info
│   │   ├── persistence.rs            # Atomic JSON persistence for transfers and secure snapshots
│   │   ├── peer_registry.rs          # Persistent peer registry (peers.json) for auto-reconnection
│   │   │
│   │   ├── connection/               # ── Transport layer ──
│   │   │   ├── mod.rs                # Re-exports Iroh and Ticket
│   │   │   ├── iroh.rs               # Iroh endpoint: binding, relay, DNS discovery, port retry
│   │   │   ├── ticket.rs             # Ticket: Brotli-compressed, URL-safe Base64 address encoding
│   │   │   ├── crypto.rs             # X25519 ECDH key exchange, HKDF-SHA3-256 derivation, key rotation
│   │   │   └── webrtc.rs             # WebRTC data channels, binary framing, AES-256-GCM + Brotli pipeline
│   │   │
│   │   ├── security/                 # ── Security layer ──
│   │   │   ├── mod.rs                # Re-exports identity, session, replay, message_auth
│   │   │   ├── identity.rs           # Long-term HMAC-SHA3-256 peer identity (sign/verify, persistence)
│   │   │   ├── session.rs            # Per-transaction secure session (nonce seed, key, expiration)
│   │   │   ├── replay.rs             # Monotonic counter + expiration-based replay guard
│   │   │   └── message_auth.rs       # HMAC-SHA3-256 authenticated protocol message envelope
│   │   │
│   │   ├── pipeline/                 # ── Async transfer pipeline ──
│   │   │   ├── mod.rs                # Re-exports chunk, merkle, sender, receiver
│   │   │   ├── chunk.rs              # ChunkData/WireChunk structures, SHA3-256 hashing, ChunkBitmap
│   │   │   ├── merkle.rs             # MerkleTree construction + IncrementalMerkleBuilder for receiver
│   │   │   ├── sender.rs             # Multi-stage sender: read → chunk → compress → encrypt → send
│   │   │   └── receiver.rs           # Multi-stage receiver: receive → decrypt → decompress → verify → write
│   │   │
│   │   └── protocol/                 # ── Secure transfer protocol ──
│   │       ├── mod.rs                # Re-exports manifest, coordinator
│   │       ├── manifest.rs           # SecureManifest — immutable, cryptographically signed file manifest
│   │       └── coordinator.rs        # TransferCoordinator — ties security + pipeline + transaction state
│   │
│   ├── ui/                           # ── Terminal user interface (Ratatui + Crossterm) ──
│   │   ├── mod.rs                    # Re-exports and `run()` entry point
│   │   ├── executer.rs               # UIExecuter: event loop, rendering, EngineAction dispatch
│   │   ├── traits.rs                 # Component / Handler / Focusable trait definitions
│   │   ├── commands.rs               # Chat slash-commands (/clear, /help)
│   │   │
│   │   ├── panels/                   # ── 10 TUI panels ──
│   │   │   ├── mod.rs                # Re-exports all panels
│   │   │   ├── home.rs               # Home — main menu and navigation
│   │   │   ├── chat.rs               # Chat — broadcast room + per-peer DMs
│   │   │   ├── send.rs               # Send — file/folder selection and outbound transfer
│   │   │   ├── connect.rs            # Connect — paste ticket to establish peer connection
│   │   │   ├── peers.rs              # Peers — online/offline list, disconnect, remote browse
│   │   │   ├── id.rs                 # My ID — show/copy connection ticket
│   │   │   ├── files.rs              # Files — transfer history with search and filters
│   │   │   ├── settings.rs           # Settings — display name, remote access toggle
│   │   │   ├── logs.rs               # Logs — live scrollable application log viewer
│   │   │   └── remote.rs             # Remote — browse and fetch from a peer's filesystem
│   │   │
│   │   ├── popups/                   # ── Modal dialogs ──
│   │   │   ├── mod.rs                # Re-exports SavePathPopup
│   │   │   └── save_path.rs          # Save-path popup for incoming file/folder offers
│   │   │
│   │   ├── widgets/                  # ── Custom TUI widgets ──
│   │   │   ├── mod.rs                # Re-exports progress_bar
│   │   │   └── progress_bar.rs       # Animated transfer progress bar
│   │   │
│   │   └── helpers/                  # ── UI utilities ──
│   │       ├── mod.rs                # Re-exports formatters, loader, time
│   │       ├── formatters.rs         # format_file_size, short_peer_id, truncate_filename
│   │       ├── loader.rs             # ASCII loading animation for startup
│   │       └── time.rs               # Timestamp formatting and elapsed time display
│   │
│   ├── utils/                        # ── Cross-cutting utilities ──
│   │   ├── mod.rs                    # Re-exports all utility modules
│   │   ├── clipboard.rs              # Cross-platform clipboard (clip / pbcopy / xclip)
│   │   ├── data_dir.rs               # Global data directory (~/.crossdrop/) with OnceLock init
│   │   ├── hash.rs                   # Brotli string compression, secret key I/O, instance locking
│   │   ├── log_buffer.rs             # In-memory ring buffer (500 entries) for tracing logs
│   │   └── sos.rs                    # SignalOfStop — async/sync graceful shutdown coordination
│   │
│   └── workers/                      # ── App state and CLI ──
│       ├── mod.rs                    # Re-exports app, args
│       ├── args.rs                   # CLI parsing (clap) + TOML config file merging
│       └── app.rs                    # Application state model: Mode, App, MessageTable, UnreadTracker
│
└── target/                           # Build artifacts (gitignored)
```

### Directory Purposes

| Directory | Role |
|-----------|------|
| `src/core/` | All networking, cryptography, and transfer logic. Zero UI dependencies. Contains the engine state machine, peer lifecycle, transport (Iroh + WebRTC), security primitives, async pipeline, and protocol coordination. |
| `src/core/connection/` | Transport layer: Iroh endpoint management, WebRTC data channel setup, ticket encoding, and X25519 key exchange with session key rotation. |
| `src/core/security/` | Security primitives: persistent peer identity, per-transaction sessions with nonce derivation, monotonic-counter replay protection, and HMAC-authenticated message envelopes. |
| `src/core/pipeline/` | High-performance async multi-stage pipeline for chunked file transfers. Handles chunking, Brotli compression, AES-256-GCM encryption, Merkle trees, bitmap tracking, and backpressure. |
| `src/core/protocol/` | Secure transfer protocol: cryptographically signed immutable manifests and the `TransferCoordinator` that integrates security, pipeline, and transaction state. |
| `src/ui/` | Terminal UI built with Ratatui + Crossterm. Strictly a presentation layer — reads state from the engine and dispatches `EngineAction` values. No transfer or crypto logic. |
| `src/ui/panels/` | Ten independent TUI panels, each implementing `Component` (render) and `Handler` (keyboard input) traits. |
| `src/ui/popups/` | Modal dialog overlays (e.g., save-path selection for incoming offers). |
| `src/ui/widgets/` | Reusable custom Ratatui widgets (progress bar). |
| `src/ui/helpers/` | Pure formatting functions: file sizes, timestamps, display names, loading animation. |
| `src/utils/` | Cross-cutting utilities: clipboard access, data directory management, string compression, log buffering, and shutdown signaling. |
| `src/workers/` | Application-level state model (`App`, `Mode`, `MessageTable`, `UnreadTracker`, `TypingState`) and CLI argument parsing with TOML config merging. |
| `~/.crossdrop/` | Runtime data directory (configurable via `--conf`): `secret.key`, `identity.key`, `transfers.json`, `peers.json`. |

---

## Application Working Flow

### 1. Initialization (Entry Point)

```
main.rs
  │
  ├─ Args::load()              Parse CLI (clap) + merge TOML config
  ├─ data_dir::init()          Set global data directory (~/.crossdrop/)
  ├─ tracing init              BufferLayer → LogBuffer (no stderr, TUI-safe)
  ├─ SignalOfStop::new()       Async/sync shutdown coordination
  ├─ Ctrl+C handler            Spawns task, calls sos.cancel() on signal
  └─ ui::run()                 Enters the TUI event loop
```

**`ui::run()`** performs the following bootstrap:

1. **Secret key** — `get_or_create_secret()` loads or generates a persistent `SecretKey` from `~/.crossdrop/secret.key` with PID-based file locking (up to 10 slots for multi-instance).
2. **Terminal setup** — enables raw mode, enters alternate screen, creates `Terminal<CrosstermBackend>`.
3. **PeerNode init** (async, with loading animation) — creates the Iroh endpoint (port binding with retry), sets up DNS discovery and relay, waits for the endpoint to go online.
4. **App state** — constructs `App` with default `Mode::Home`, empty message/chat tables, `TransferEngine::new()` (which loads/creates the peer identity from `identity.key`).
5. **PeerRegistry** — loads `peers.json` and spawns auto-reconnection tasks for all non-removed peers.
6. **UIExecuter** — enters the main event loop.

### 2. Main Event Loop

The `UIExecuter` runs a `tokio::select!` loop with three concurrent branches:

```
┌──────────────────────────────────────────────────────────────────┐
│                        UIExecuter Loop                           │
│                                                                  │
│  ┌─────────────┐   ┌──────────────────┐   ┌──────────────────┐  │
│  │ Terminal     │   │ AppEvent         │   │ Periodic tick    │  │
│  │ key events   │   │ channel (mpsc)   │   │ (250ms)          │  │
│  │ (crossterm)  │   │ from PeerNode    │   │                  │  │
│  └──────┬──────┘   └──────┬───────────┘   └──────┬───────────┘  │
│         │                  │                      │              │
│         ▼                  ▼                      ▼              │
│  Route to active     Process network      Render current panel   │
│  panel's Handler     events (connect,     + status bar + popups  │
│  → returns Action    chat, progress,                             │
│  → execute actions   transfer, etc.)                             │
│                      → update App state                          │
│                      → dispatch engine                           │
│                        actions                                   │
└──────────────────────────────────────────────────────────────────┘
```

### 3. Peer Connection Flow

```
  Peer A (listener)                              Peer B (connector)
  ─────────────────                              ──────────────────
  PeerNode::new()                                PeerNode::new()
    ├─ Iroh::new(secret_key)                       ├─ Iroh::new(secret_key)
    ├─ Spawn accept loop                           │
    │   └─ wait_connection()                       │
    └─ Generate ticket string                      │
         (Iroh addr → JSON → Brotli → B64)         │
                                                   │
  ◄──── ticket shared out-of-band ────────────────►│
                                                   │
                                          Ticket::parse(string)
                                          iroh.connect(ticket)
  accept_incoming()                                │
    ├─ ALPN verify ("msg/1")                       │
    ├─ Open bi-directional stream                  │
    │                                              │
    │◄─────── ECDH handshake (X25519) ────────────►│
    │  handshake_offerer / handshake_answerer       │
    │  → derive session_key via HKDF-SHA3-256      │
    │                                              │
    │◄─────── WebRTC signaling (SDP) ─────────────►│
    │  Offer / Answer / ICE candidates             │
    │  (exchanged over the encrypted Iroh stream)  │
    │                                              │
    │◄═══════ WebRTC Data Channel ════════════════►│
    │  on_open → emit PeerConnected                │
    │  on_message → route frames to AppEvent       │
    │                                              │
    └─ Spawn key rotation task (hourly)            │
       └─ new ECDH → SessionKeyManager::rotate()  │
```

### 4. File Transfer Flow (Transaction Protocol)

```
  Sender                                  Receiver
  ──────                                  ────────

  ① User selects file/folder in Send panel
     │
  ② engine.initiate_file_send() / initiate_folder_send()
     ├─ Creates Transaction (state=Pending)
     ├─ Builds TransactionManifest (file IDs, sizes, Merkle roots)
     ├─ Persists transaction to transfers.json
     └─ Returns EngineAction::SendTransactionRequest
                                          │
              ─────── TransactionRequest ──────►
                                          │
                                   ③ AppEvent::TransactionRequested
                                      └─ engine.handle_transaction_request()
                                         ├─ Creates PendingIncoming
                                         └─ Shows offer popup in UI
                                          │
                                   ④ User accepts → engine.accept_incoming()
                                      ├─ Creates Transaction (state=Active)
                                      ├─ Returns PrepareReceive + SendTransactionResponse
                                          │
              ◄─── TransactionResponse (accepted) ───
     │
  ⑤ engine.handle_transaction_accepted()
     ├─ Activates Transaction
     └─ Returns SendFileData / SendFolderData
     │
  ⑥ WebRTC send pipeline:
     │  Read file → 48KB chunks → Brotli compress → AES-256-GCM encrypt → send
     │  (sliding window=32, semaphore-based backpressure)
     │                                    │
     │                             ⑦ Receiver pipeline:
     │                                Receive → decrypt → decompress → SHA3-256 verify
     │                                → Merkle tree update → atomic disk write
     │                                → batch ACK (every 8 chunks)
     │                                    │
              ◄─────── ACK ranges ─────────
     │
  ⑧ All files transferred
     └─ SendTransactionComplete ──────────►
                                      engine.handle_transaction_completed()
                                      ├─ Verify Merkle roots
                                      ├─ Mark Transaction completed
                                      └─ Persist final state
```

### 5. State Management

The application uses a **layered state architecture** — no global mutable state, no actor model:

| Layer | State Owner | Scope |
|-------|-------------|-------|
| **App** (`workers/app.rs`) | UI-visible state: current mode, peers, messages, chat targets, typing indicators, unread counts | Entire session |
| **TransferEngine** (`core/engine.rs`) | Transaction lifecycle, data statistics, pending transfers, transfer history | Entire session |
| **TransactionManager** | Active/historical `Transaction` objects with per-file progress | Per-engine |
| **SessionKeyManager** (`connection/crypto.rs`) | Current AES-256-GCM session key per peer (behind `Arc<RwLock>`) | Per-peer connection |
| **PeerRegistry** (`core/peer_registry.rs`) | Persistent peer records for auto-reconnection (`peers.json`) | Cross-session |
| **Persistence** (`core/persistence.rs`) | Crash-safe transaction snapshots and secure transfer state (`transfers.json`) | Cross-session |

### 6. Event System

Events flow unidirectionally:

```
Transport (Iroh / WebRTC)
    │
    ▼
PeerNode (initializer.rs)                       ┌─────────────────────┐
    │  Emits AppEvent via mpsc::unbounded_channel │ 35+ event variants  │
    │                                             │ (PeerConnected,     │
    ▼                                             │  ChatReceived,      │
UIExecuter (executer.rs)                          │  FileProgress,      │
    │  Routes events to engine + App state        │  TransactionRequest,│
    │  Engine returns EngineAction(s)             │  Error, Info, …)    │
    ▼                                             └─────────────────────┘
EngineAction dispatch
    │  UIExecuter executes actions via PeerNode's async API
    ▼
PeerNode → WebRTC data channel → remote peer
```

No bidirectional event buses. The engine is a pure synchronous state machine that never performs I/O.

### 7. Error Handling Strategy

- **`anyhow::Result`** — used throughout for context-rich error propagation.
- **Tracing** — all errors are logged via `tracing::{error, warn}` with structured fields (`event = "…"`, `error = %e`), captured in the `LogBuffer` ring buffer (500 entries), and displayed in the Logs panel.
- **Graceful degradation** — transport errors (disconnects, timeouts) transition peers to offline state rather than crashing. Failed transactions are marked `Failed` or `Interrupted` and become eligible for resume.
- **Atomic persistence** — `Persistence` and `PeerRegistry` use write-to-temp + rename to prevent corruption on crash or power loss.
- **Abort resistance** — release builds use `panic = "abort"` for smaller binaries; all critical paths use `Result` rather than `unwrap`.

### 8. WebRTC Data Channel Protocol

Once the WebRTC data channel is open, all communication uses a compact binary framing:

```
┌───────────┬──────────────────────────────────────────────────┐
│ 1 byte    │ N bytes payload                                  │
│ frame_type│                                                  │
├───────────┼──────────────────────────────────────────────────┤
│ 0x01      │ Control: JSON-encoded ControlMessage             │
│           │  (chat, file offers, transaction commands,       │
│           │   display name, key rotation, remote access)     │
├───────────┼──────────────────────────────────────────────────┤
│ 0x02      │ Chunk: 16B file_id + 4B sequence + raw data     │
│           │  (48KB chunks, ~21 bytes overhead vs ~130KB      │
│           │   with JSON+Base64)                              │
├───────────┼──────────────────────────────────────────────────┤
│ 0x03      │ Ack: 16B file_id + 4B sequence                  │
│           │  (batched every 8 chunks via AckRange)           │
└───────────┴──────────────────────────────────────────────────┘

All frames are: Brotli-compressed → AES-256-GCM encrypted → sent
```

### 9. Key Rotation (Forward Secrecy)

```
Every 1 hour (offerer initiates):

  Offerer                        Answerer
  ───────                        ────────
  Generate new EphemeralKeypair
  Send KeyRotation(new_pub_key) ──────►
                                 Generate new EphemeralKeypair
                          ◄────── KeyRotation(new_pub_key)

  Both sides:
    new_shared_secret = X25519(new_sk, peer_new_pk)
    new_session_key = HKDF-SHA3-256(
        ikm  = new_shared_secret,
        salt = sort(iroh_pk_A, iroh_pk_B) || previous_key,
        info = b"crossdrop-rotation-v1"
    )
    SessionKeyManager::rotate() updates Arc<RwLock<[u8; 32]>>
```

Mixing the previous key into the salt ensures **forward secrecy**: compromising the current key does not reveal keys from earlier rotations.

---

## Technical Overview

### Technology Stack

| Category | Technology | Purpose |
|----------|-----------|---------|
| **Language** | Rust 2024 edition | Memory-safe systems programming |
| **Async runtime** | Tokio | Async I/O, task spawning, timers, channels |
| **P2P networking** | Iroh 0.96 | Endpoint discovery (DNS + pkarr), relay fallback, NAT traversal |
| **Data transport** | WebRTC (webrtc 0.17) | SCTP-based data channels for direct P2P communication |
| **Encryption** | AES-256-GCM (aes-gcm) | Authenticated encryption of all data channel frames |
| **Key exchange** | X25519 (x25519-dalek) | Ephemeral ECDH key agreement per session |
| **Hashing** | SHA3-256 (sha3) | Chunk hashing, Merkle trees, HMAC, identity derivation |
| **Compression** | Brotli (brotli) | Pre-encryption frame compression (quality 4 for data, 11 for tickets) |
| **Serialization** | Serde + serde_json, TOML | JSON for wire protocol and persistence, TOML for config |
| **TUI** | Ratatui 0.30 + Crossterm 0.29 | Terminal rendering, raw mode, alternate screen |
| **CLI** | Clap 4.5 (derive) | Argument parsing with TOML config merging |
| **Logging** | tracing + tracing-subscriber | Structured logging with in-memory ring buffer |
| **Error handling** | anyhow | Context-rich error propagation |
| **IDs** | uuid v4 | Transaction, file, and message identifiers |

### Architectural Pattern

Crossdrop follows a **layered event-driven architecture** with a strict separation of concerns:

```
┌─────────────────────────────────────────────────────┐
│  UI Layer  (panels, popups, executer)               │
│  • Reads state from engine                          │
│  • Dispatches user commands to engine               │
│  • Executes EngineActions (async network calls)     │
│  • ZERO transfer logic                              │
├─────────────────────────────────────────────────────┤
│  Core Domain  (TransferEngine + TransferCoordinator)│
│  • Pure synchronous state machine                   │
│  • Owns TransactionManager, DataStats, pending I/O  │
│  • Returns declarative EngineAction values          │
│  • Enforces max 3 concurrent transactions           │
│  • Tracks all data in statistics                    │
│  • Coordinator validates manifests, replay guards,  │
│    session auth, resume requests, retry limits      │
├─────────────────────────────────────────────────────┤
│  Pipeline Layer  (SenderPipeline / ReceiverPipeline)│
│  • Async multi-stage chunk processing               │
│  • Backpressure via semaphore + memory budgets      │
│  • Merkle tree construction + incremental verify    │
│  • Chunk bitmaps for resume tracking                │
├─────────────────────────────────────────────────────┤
│  Security Layer  (identity, session, replay, HMAC)  │
│  • Persistent peer identity for signing             │
│  • Per-transaction sessions with nonce derivation   │
│  • Monotonic-counter replay protection              │
│  • HMAC authentication on every protocol message    │
├─────────────────────────────────────────────────────┤
│  Transport Layer  (iroh + WebRTC)                   │
│  • Sends/receives raw encrypted frames              │
│  • No awareness of transaction state                │
│  • Iroh for signaling, WebRTC for data              │
└─────────────────────────────────────────────────────┘
```

Key patterns:
- **Command pattern** — the engine returns `EngineAction` values (declarative side-effects); the UI executer dispatches them asynchronously. The engine never calls async code.
- **Event sourcing (lightweight)** — all state changes flow through `AppEvent` variants emitted by the transport layer and consumed by the executer.
- **Component-trait UI** — each panel implements `Component` (render) and `Handler` (input), enabling independent development and testing.

### Key Design Decisions

- **Iroh for signaling only** — once WebRTC is established, all traffic moves to data channels.
- **No transfer logic in UI** — panels read engine state and return `EngineActions`; the executer dispatches them.
- **Compress-then-encrypt** — all frames are Brotli-compressed (quality 4) before AES-256-GCM encryption, reducing wire traffic without weakening security.
- **Per-peer encryption with forward secrecy** — each peer connection derives its own AES-256-GCM key via ephemeral ECDH; hourly key rotation ensures compromise of a session key does not expose past traffic.
- **Manifest-first transfer** — no file data is sent until the receiver has validated and ACKed a cryptographically signed manifest. The sender rejects any request that falls outside the manifest.
- **Merkle-verified integrity** — every file's Merkle root is pre-committed in the manifest. The receiver builds an incremental Merkle tree chunk-by-chunk and verifies the root on completion.
- **Bitmap-based resume** — each file tracks received chunks as a compact bit vector. Resume requests carry these bitmaps along with HMAC and identity signatures, so the sender only retransmits missing chunks.
- **Replay protection** — every protocol message carries a monotonic counter; the replay guard rejects any counter ≤ the last seen value, and expired transactions are automatically purged.
- **Abuse budgets** — retry limits per chunk (3) and per transaction (50–100), memory caps (64 MB sender, 128 MB receiver), pipeline depth limits, and 24-hour transaction timeouts prevent resource exhaustion.
- **Offline-aware peers** — connection loss marks a peer as offline (grey) instead of removing it, preserving identity, chat history, and encryption keys for potential reconnection.
- **Parallel folder I/O** — folder sends use a bounded prefetch channel so the next file is read from disk while the current one is still being transmitted.
- **Wire-level statistics** — `DataStats` tracks both raw bytes (pre-compression) and wire bytes (post-compression) to give users an accurate view of actual network usage and compression savings.
- **Remote access disabled by default** — peers cannot browse your filesystem unless you opt in with `--remote-access`.
- **Multi-instance support** — the secret key file uses file locking with up to 10 slots, allowing multiple instances to run simultaneously.
- **No fmt layer** — tracing output is captured in a ring buffer and displayed in the Logs panel instead of writing to stderr, which would corrupt the TUI.

### Build & Deployment

```bash
# Development build
cargo build

# Optimized release build (strip symbols, LTO, single codegen unit, abort on panic)
cargo build --release

# Install globally
cargo install --path .

# Run tests
cargo test

# Generate documentation
cargo doc --open
```

The release profile in `Cargo.toml` produces a compact, optimized single binary:

```toml
[profile.release]
strip = true          # Strip debug symbols
lto = true            # Link-time optimization (full)
codegen-units = 1     # Single codegen unit for maximum optimization
panic = "abort"       # Abort on panic (smaller binary, no unwinding)
```

**Deployment** is a single static binary with no external dependencies — copy the `crossdrop` executable to the target machine. All persistent state is stored in `~/.crossdrop/` (or the path specified via `--conf`).

---

## Security

- **Transport**: Brotli compression + AES-256-GCM encryption on all data channel frames
- **Key exchange**: Ephemeral X25519 ECDH per session, performed over the authenticated Iroh channel
- **Key derivation**: HKDF-SHA3-256 with both peers' Iroh public keys as context
- **Forward secrecy**: Hourly in-band key rotation using fresh ephemeral X25519 keypairs; new keys are derived with the previous key as additional HKDF input, so compromising a session key does not expose past traffic
- **Peer identity**: Persistent HMAC-SHA3-256 identity key stored in `~/.crossdrop/identity.key`, used to sign manifests and resume requests
- **Manifest signing**: Every transfer begins with a cryptographically signed, immutable manifest; the receiver validates the signature, expiration, and path safety before ACK
- **Message authentication**: Protocol messages carry HMAC-SHA3-256 over the session key with constant-time comparison, preventing tampering and forgery
- **Replay protection**: Monotonic per-transaction counters reject any message with counter ≤ last seen; expired transactions are automatically pruned
- **Integrity**: SHA3-256 hash verification per chunk + Merkle tree root verification per file, with the root pre-committed in the signed manifest
- **Path safety**: Manifest paths are normalized and validated — path traversal (`..`), absolute paths, and control characters are rejected
- **Abuse controls**: Per-chunk retry limit (3), per-transaction retry limit (50–100), memory budgets (64/128 MB), pipeline depth caps, and 24-hour transaction timeouts
- **Resume security**: Resume requests are HMAC-signed and identity-signed; the sender cross-checks against the original manifest before retransmitting
- **Nonce derivation**: Deterministic nonces derived from a per-transaction seed + monotonic counter via SHA3-256, preventing nonce reuse without shared state
- **Identity (Iroh)**: Ed25519 keypair via Iroh, stored locally in `~/.crossdrop/`
- **Ticket format**: URL-safe Base64 without padding, version-prefixed for forward compatibility
- **Remote access**: Disabled by default, opt-in via `--remote-access` flag

---

## License

[Apache-2.0](LICENSE)
