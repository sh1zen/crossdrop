# Crossdrop

A minimalistic, encrypted peer-to-peer file sharing and chat tool with a terminal UI — written in Rust.

No servers, no accounts. Just share a ticket and start transferring.

![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Rust](https://img.shields.io/badge/rust-2024-orange)

---

## Features

- **Direct P2P** — WebRTC data channels with NAT traversal (STUN/TURN)
- **End-to-end encrypted** — AES-256-GCM with per-peer SHA3-256 derived keys
- **File & folder transfer** — chunked pipeline with SHA3-256 integrity verification
- **Resumable transfers** — interrupted transactions can be resumed automatically
- **Real-time chat** — broadcast room + private DMs per peer
- **Remote filesystem browse** — navigate and fetch files from a peer's machine
- **Terminal UI** — full TUI powered by Ratatui with panels, popups and progress bars
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
  5. ◄──────────── Exchange session key ──────────►
     (32-byte random, derive shared key via SHA3-256)
  6. ◄──────────── SDP offer / answer ────────────►
     (WebRTC signaling over the Iroh stream)
  7. ◄══════════ WebRTC Data Channels ════════════►
     (all traffic: chat, files, control)
```

1. Each node creates an **Iroh endpoint** with DNS discovery and optional relay.
2. A **ticket** (Iroh address compressed with Brotli + Base64) is shared out-of-band.
3. The connecting peer resolves the ticket and opens a bidirectional Iroh stream.
4. A **session key** is exchanged; both peers derive a shared **AES-256-GCM key** using `SHA3-256(sorted(pk_a, pk_b) || session_key)`.
5. **WebRTC SDP offer/answer** is exchanged over the same Iroh stream to establish a direct connection.
6. Once connected, all communication flows over **encrypted WebRTC data channels**.

### Wire Protocol

All data channel frames are AES-256-GCM encrypted. Three frame types:

| Byte | Type | Payload |
|------|------|---------|
| `0x01` | Control | JSON — chat messages, file offers, transaction commands |
| `0x02` | Chunk | 16-byte file_id + 4-byte sequence + raw data |
| `0x03` | Ack | 16-byte file_id + 4-byte sequence |

File transfers use **48 KB chunks** with a **16-chunk pipeline** and SHA3-256 hash verification on completion.

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
| **Peers** | `p` | List connected peers and access remote browse |
| **My ID** | `i` | Show and copy your connection ticket |
| **Files** | `f` | Transfer history with search and per-peer filtering |
| **Settings** | `o` | Change display name, toggle remote access |
| **Logs** | `l` | Live application logs with scroll |
| **Remote** | — | Browse a peer's filesystem (requires remote access) |

---

## Architecture

```
src/
├── main.rs                  Entry point, tracing setup, arg loading
├── core/
│   ├── engine.rs            TransferEngine — sole coordinator of all transfer logic
│   ├── initializer.rs       PeerNode — peer lifecycle, connect/accept, API
│   ├── transaction.rs       Transaction state machine, progress, manifest
│   ├── persistence.rs       On-disk state (~/.crossdrop/)
│   └── connection/
│       ├── iroh.rs           Iroh endpoint wrapper (relay, discovery, bind)
│       ├── ticket.rs         Ticket encoding (JSON → Brotli → Base64)
│       └── webrtc.rs         WebRTC data channels, framing, AES-256-GCM
├── ui/
│   ├── executer.rs          Event loop, rendering, engine action dispatch
│   ├── traits.rs            Component / Handler / Focusable traits
│   ├── panels/              10 UI panels (home, chat, send, connect, …)
│   ├── popups/              Modal dialogs (save path, transaction offers)
│   ├── widgets/             Custom widgets (progress bar)
│   └── helpers/             Formatters, loader animation, time utilities
├── utils/
│   ├── clipboard.rs         Cross-platform clipboard (clip/pbcopy/xclip)
│   ├── hash.rs              Brotli compression, secret key management
│   ├── log_buffer.rs        In-memory log ring buffer for the Logs panel
│   └── sos.rs               SignalOfStop — graceful shutdown coordination
└── workers/
    ├── args.rs              CLI parsing (clap) + TOML config merging
    └── app.rs               Application state model (modes, data structs)
```

### Transfer System

The file transfer system follows a strict three-layer architecture:

```
┌─────────────────────────────────────────────────────┐
│  UI Layer  (panels, popups, executer)               │
│  • Reads state from engine                          │
│  • Dispatches user commands to engine               │
│  • Executes EngineActions (async network calls)     │
│  • ZERO transfer logic                              │
├─────────────────────────────────────────────────────┤
│  Core Domain  (TransferEngine)                      │
│  • Pure synchronous state machine                   │
│  • Owns TransactionManager, DataStats, pending I/O  │
│  • Returns declarative EngineAction values          │
│  • Enforces max 3 concurrent transactions           │
│  • Tracks all data in statistics                    │
├─────────────────────────────────────────────────────┤
│  Transport Layer  (iroh + WebRTC)                   │
│  • Sends/receives raw encrypted frames              │
│  • No awareness of transaction state                │
│  • Iroh for signaling, WebRTC for data              │
└─────────────────────────────────────────────────────┘
```

**TransferEngine** (`core/engine.rs`) is the single source of truth for:

- Transaction lifecycle (create → negotiate → active → complete/failed)
- Transfer progress tracking (per-transaction, never per-file)
- Comprehensive data statistics (bytes, messages, files, metadata, remote exploration)
- ACK, resume and cancellation logic
- Concurrent transaction limit enforcement (max 3)

The engine never performs I/O. It processes events and returns `EngineAction` values that the UIExecuter dispatches asynchronously via the transport layer.

**Transaction** (`core/transaction.rs`) owns all transfer state: manifest, file IDs, progress chunks, direction, and resume info. Each Transaction represents a single logical transfer (one file or an entire folder) and is the atomic unit of progress reporting.

### Key Design Decisions

- **Iroh for signaling only** — once WebRTC is established, all traffic moves to data channels.
- **No transfer logic in UI** — panels read engine state and return `EngineActions`; the executer dispatches them.
- **Per-peer encryption** — each peer connection derives its own AES-256-GCM key, so multi-peer sessions are isolated.
- **Remote access disabled by default** — peers cannot browse your filesystem unless you opt in with `--remote-access`.
- **Multi-instance support** — the secret key file uses file locking with up to 10 slots, allowing multiple instances to run simultaneously.
- **No fmt layer** — tracing output is captured in a ring buffer and displayed in the Logs panel instead of writing to stderr, which would corrupt the TUI.

---

## Security

- **Transport**: AES-256-GCM encryption on all data channel frames
- **Key derivation**: SHA3-256 over sorted public keys + session key
- **Integrity**: SHA3-256 hash verification on every file transfer
- **Identity**: Ed25519 keypair via Iroh, stored locally in `~/.crossdrop/`
- **Remote access**: Disabled by default, opt-in via `--remote-access` flag

---

## License

[Apache-2.0](LICENSE)
