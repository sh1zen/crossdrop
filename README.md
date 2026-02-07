# Crossdrop

A minimalistic, encrypted peer-to-peer file sharing and chat tool with a terminal UI — written in Rust.

No servers, no accounts. Just share a ticket and start transferring.

![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Rust](https://img.shields.io/badge/rust-2024-orange)

---

## Features

- **Direct P2P** — WebRTC data channels with NAT traversal (STUN/TURN)
- **End-to-end encrypted** — AES-256-GCM with per-peer ECDH-derived keys (X25519 + HKDF)
- **Compressed control messages** — control frames are Brotli-compressed before encryption
- **File & folder transfer** — chunked pipeline with SHA3-256 integrity verification and Merkle tree roots
- **Resumable transfers** — interrupted transactions resume from the last chunk via per-file bitmaps
- **Cryptographically signed manifests** — the sender signs an immutable file manifest before any data is transferred
- **Replay protection** — monotonic counters and transaction expiration prevent replay attacks
- **Forward secrecy** — ephemeral X25519 keypairs per session with hourly key rotation
- **Real-time chat** — broadcast room + private DMs per peer
- **Remote filesystem browse** — navigate and fetch files from a peer's machine
- **Terminal UI** — full TUI powered by Ratatui with panels, popups and progress bars
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

### Architecture Overview

Crossdrop follows a **layered event-driven architecture** with strict separation of concerns:

```
┌─────────────────────────────────────────────────────┐
│  UI Layer  (panels, popups, executer)               │
│  • Reads state from engine                          │
│  • Dispatches user commands to engine               │
│  • ZERO transfer logic                              │
├─────────────────────────────────────────────────────┤
│  Core Domain  (TransferEngine)                      │
│  • Pure synchronous state machine                   │
│  • Returns declarative EngineAction values          │
│  • Enforces concurrency limits                      │
├─────────────────────────────────────────────────────┤
│  Pipeline Layer  (Sender / Receiver)                │
│  • Async multi-stage chunk processing               │
│  • Backpressure via buffered amount monitoring      │
│  • Merkle tree construction + incremental verify    │
├─────────────────────────────────────────────────────┤
│  Security Layer  (identity, session, replay, HMAC)  │
│  • Persistent peer identity for signing             │
│  • Per-transaction sessions with nonce derivation   │
│  • Monotonic-counter replay protection              │
├─────────────────────────────────────────────────────┤
│  Transport Layer  (Iroh + WebRTC)                   │
│  • Sends/receives raw encrypted frames              │
│  • Iroh for signaling, WebRTC for data              │
└─────────────────────────────────────────────────────┘
```

Key patterns:
- **Command pattern** — the engine returns `EngineAction` values; the UI executer dispatches them asynchronously
- **Event sourcing** — all state changes flow through `AppEvent` variants emitted by the transport layer
- **Component-trait UI** — each panel implements `Component` (render) and `Handler` (input)

### Transfer Pipeline

Sender and receiver each run a fully **async, multi-stage pipeline** with backpressure:

```
  Sender                                          Receiver
  ──────                                          ────────
  File read (prefetch)                             Network receive queue
      │                                                │
  Chunking (56 KB)                                 Decryption (AES-256-GCM)
      │                                                │
  Hash + Merkle tree                               Hash verification (SHA3-256)
      │                                                │
  Encryption (AES-256-GCM)                         Merkle tree reconstruction
      │                                                │
  Network send (windowed)                          Disk write (atomic)
      │                                                │
  ◄── ACK ranges ────────────────────────────────  File complete notification
```

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

| Flag                    | Description                                           |
|-------------------------|-------------------------------------------------------|
| `--conf <PATH>`         | Directory for persistent data (default: ~/.crossdrop) |
| `-p, --port <PORT>`     | UDP port to bind (0 = auto, default: 0)               |
| `-v`                    | Verbosity: `-v` info, `-vv` debug, `-vvv` trace       |
| `--relay <MODE>`        | `default`, `disabled`, or a custom relay URL          |
| `--display-name <NAME>` | Display name shown to peers                           |
| `--remote-access`       | Allow peers to browse your filesystem                 |
| `--show-secret`         | Print secret key to stderr on startup                 |
| `--ipv4-addr <ADDR>`    | IPv4 socket address to bind                           |
| `--ipv6-addr <ADDR>`    | IPv6 socket address to bind                           |

### Configuration File

Crossdrop supports TOML configuration files. Create a `config.toml` in the working directory:

```toml
display_name = "MyPeer"
remote_access = true
port = 11234
verbose = 1
relay = "default"
```

CLI arguments take precedence over file configuration.

---

## TUI Panels

| Panel           | Key     | Description                                                           |
|-----------------|---------|-----------------------------------------------------------------------|
| **Home**        | —       | Main menu with navigation to all panels                               |
| **Chat**        | `c`     | Broadcast room + per-peer DMs with unread counters                    |
| **Send**        | `s`     | Send files or folders to a connected peer                             |
| **Connect**     | `n`     | Paste a peer's ticket to establish a connection                       |
| **Peers**       | `p`     | List connected peers (online/offline status) and access remote browse |
| **My ID**       | `i`     | Show and copy your connection ticket                                  |
| **Files**       | `f`     | Transfer history with search and per-peer filtering                   |
| **Settings**    | `o`     | Change display name, toggle remote access                             |
| **Logs**        | `l`     | Live application logs with scroll                                     |
| **Remote**      | —       | Browse a peer's filesystem (requires remote access)                   |
| **KeyListener** | —       | Receive keystrokes from remote peers                                  |

---

## Technology Stack

| Category           | Technology                    | Purpose                                               |
|--------------------|-------------------------------|-------------------------------------------------------|
| **Language**       | Rust 2024 edition             | Memory-safe systems programming                       |
| **Async runtime**  | Tokio                         | Async I/O, task spawning, timers, channels            |
| **P2P networking** | Iroh                          | Endpoint discovery, relay fallback, NAT traversal     |
| **Data transport** | WebRTC                        | SCTP-based data channels for direct P2P               |
| **Encryption**     | AES-256-GCM                   | Authenticated encryption of all frames                |
| **Key exchange**   | X25519                        | Ephemeral ECDH key agreement per session              |
| **Hashing**        | SHA3-256                      | Chunk hashing, Merkle trees, HMAC                     |
| **Compression**    | Brotli                        | Control message compression                           |
| **TUI**            | Ratatui + Crossterm           | Terminal rendering, raw mode, alternate screen        |
| **CLI**            | Clap                          | Argument parsing with TOML config merging             |
| **Logging**        | Tracing                       | Structured logging with file persistence              |

---

## Key Design Decisions

- **Iroh for signaling only** — once WebRTC is established, all traffic moves to data channels
- **No transfer logic in UI** — panels read engine state and return `EngineActions`; the executer dispatches them
- **Control message compression** — JSON control frames are Brotli-compressed before AES-256-GCM encryption
- **Per-peer encryption with forward secrecy** — each connection derives its own key via ECDH; hourly rotation ensures forward secrecy
- **Manifest-first transfer** — no file data is sent until the receiver validates a signed manifest
- **Merkle-verified integrity** — every file's Merkle root is pre-committed in the manifest
- **Bitmap-based resume** — each file tracks received chunks; resume only transmits missing data
- **Offline-aware peers** — connection loss marks a peer as offline instead of removing it

---

## Security

- **Transport**: AES-256-GCM encryption on all data channel frames
- **Key exchange**: Ephemeral X25519 ECDH per session, performed over the authenticated Iroh channel
- **Forward secrecy**: Hourly in-band key rotation using fresh ephemeral keypairs
- **Peer identity**: Persistent Ed25519 identity key used to sign manifests and resume requests
- **Manifest signing**: Every transfer begins with a cryptographically signed manifest
- **Message authentication**: Protocol messages carry HMAC-SHA3-256 over the session key
- **Replay protection**: Monotonic per-transaction counters reject replayed messages
- **Integrity**: SHA3-256 hash verification per chunk + Merkle tree root verification per file
- **Path safety**: Manifest paths are normalized and validated against traversal attacks
- **Remote access**: Disabled by default, opt-in via `--remote-access` flag

---

## Build & Deployment

```bash
# Development build
cargo build

# Optimized release build
cargo build --release

# Install globally
cargo install --path .

# Run tests
cargo test

# Generate documentation
cargo doc --open
```

**Deployment** is a single static binary with no external dependencies. All persistent state is stored in `~/.crossdrop/` (or the path specified via `--conf`).

---

## Documentation

- [Architecture Documentation](docs/ARCHITECTURE.md) — High-level system architecture, component relationships, and core logic flows

---

## License

[Apache-2.0](LICENSE)
