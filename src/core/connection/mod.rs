//! Peer-to-peer connection infrastructure for CrossDrop.
//!
//! This module provides the transport layer that enables secure, high-throughput
//! communication between peers. It combines two complementary technologies:
//!
//! - **Iroh**: For initial peer discovery, NAT traversal, and bootstrap signaling.
//!   Iroh provides a global peer ID and relay infrastructure for establishing
//!   connections even behind symmetric NATs.
//! - **WebRTC**: For the actual data transfer once peers are connected. WebRTC's
//!   SCTP-based data channels provide reliable, ordered delivery with congestion
//!   control and flow control built-in.
//!
//! # Connection Establishment Flow
//!
//! ```text
//! Offerer                              Answerer
//! ────────                             ────────
//! Iroh.connect() ─────────────────────► Iroh.accept()
//!        │                                    │
//!        ▼                                    ▼
//! Open bi-stream ◄──────────────────────► Accept bi-stream
//!        │                                    │
//!        ▼                                    ▼
//! ECDH handshake (X25519) ◄─────────────► ECDH handshake
//!        │                                    │
//!        ▼                                    ▼
//! Send WebRTC offer ──────────────────► Receive offer
//!        │                                    │
//!        ◄────────────────────────────── Send WebRTC answer
//!        │                                    │
//!        ▼                                    ▼
//! ICE negotiation (STUN/TURN/relay)
//!        │                                    │
//!        ▼                                    ▼
//! Data channels open (control + data)
//! ```
//!
//! # Security Model
//!
//! 1. **ECDH Key Exchange**: Each connection starts with X25519 ephemeral key
//!    exchange over the Iroh bootstrap channel, deriving a unique session key.
//! 2. **AES-256-GCM Encryption**: All WebRTC data channel traffic is encrypted
//!    with the session key. Each message uses a unique nonce derived from a
//!    monotonic counter.
//! 3. **Key Rotation**: Session keys are rotated hourly with forward secrecy
//!    (previous key mixed into new key derivation).
//! 4. **Manifest Signing**: Transfer manifests are signed with Ed25519 keys
//!    for sender authentication.
//!
//! # Module Layout
//!
//! | Module | Responsibility |
//! |--------|---------------|
//! | [`crypto`] | X25519 ECDH, HKDF key derivation, session key management |
//! | [`iroh`] | Iroh endpoint wrapper for peer discovery and NAT traversal |
//! | [`ticket`] | Connection ticket parsing and generation |
//! | [`webrtc`] | WebRTC data channel management, framing, and protocol handling |
//!
//! # Design Decisions
//!
//! - **Why Iroh + WebRTC?** Iroh excels at NAT traversal but has limited throughput.
//!   WebRTC provides excellent throughput but needs signaling. Combining them
//!   gives us the best of both worlds.
//! - **Why two data channels?** Separate control and data channels prevent
//!   head-of-line blocking: control messages (small, frequent) don't wait
//!   behind large file chunks.
//! - **Why custom framing?** The binary frame format minimizes overhead on
//!   the hot path (file chunks) while JSON control messages remain debuggable.

pub mod crypto;
mod iroh;
mod ticket;
pub mod webrtc;

pub use iroh::Iroh;
pub use ticket::Ticket;
