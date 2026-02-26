//! Core domain logic for CrossDrop peer-to-peer file transfer.
//!
//! This module contains the heart of the application, implementing all business logic
//! related to peer discovery, secure connections, file transfer orchestration, and
//! persistent state management. The design follows a layered architecture where:
//!
//! - **Transport Layer** ([`connection`]): Handles peer-to-peer connectivity via Iroh
//!   for NAT traversal and WebRTC for high-throughput data channels.
//! - **Transfer Layer** ([`engine`], [`transaction`], [`pipeline`]): Manages the complete
//!   lifecycle of file transfers with resume support, integrity verification, and
//!   concurrency control.
//! - **Security Layer** ([`security`]): Provides Ed25519 identity, ECDH key exchange,
//!   HMAC authentication, and replay protection.
//! - **Persistence Layer** ([`persistence`], [`peer_registry`]): Ensures crash-resilient
//!   state with atomic writes and automatic recovery.
//!
//! # Architectural Principles
//!
//! 1. **Single Source of Truth**: [`engine::TransferEngine`] is the sole coordinator
//!    of all transfer logic. No transfer state exists outside the engine.
//! 2. **Declarative Actions**: The engine returns [`engine::EngineAction`] enums rather
//!    than performing I/O directly, keeping it testable and async-agnostic.
//! 3. **Defense in Depth**: Multiple security layers (manifest signing, chunk hashing,
//!    Merkle verification, replay guards) protect against tampering.
//! 4. **Crash Resilience**: All critical state is persisted atomically; interrupted
//!    transfers resume automatically on restart.
//!
//! # Module Layout
//!
//! | Module | Responsibility |
//! |--------|---------------|
//! | [`config`] | Centralized configuration constants (chunk size, timeouts, limits) |
//! | [`connection`] | Peer connectivity: Iroh bootstrap, WebRTC data channels, encryption |
//! | [`engine`] | Transfer state machine: initiation, progress, completion, resume |
//! | [`initializer`] | [`PeerNode`] orchestration: connection acceptance, event routing |
//! | [`peer_registry`] | Persistent peer directory for auto-reconnection |
//! | [`persistence`] | JSON-based state storage with atomic writes |
//! | [`pipeline`] | Chunking, Merkle trees, sender/receiver async pipelines |
//! | [`security`] | Identity, session keys, HMAC, replay protection |
//! | [`transaction`] | Transaction model: manifest, files, progress, resume info |
//!
//! # Data Flow
//!
//! ```text
//! UI Layer (ui::)
//!     │
//!     ▼
//! TransferEngine ◄─────► TransactionManager
//!     │                       │
//!     ▼                       ▼
//! EngineAction          Transaction (state machine)
//!     │
//!     ▼
//! PeerNode ──► WebRTCConnection ──► DataChannel
//!     │
//!     ▼
//! Pipeline (chunking, encryption, Merkle)
//! ```

pub mod config;
pub mod connection;
pub mod engine;
mod helpers;
pub mod initializer;
pub mod peer_registry;
pub mod persistence;
pub mod pipeline;
pub mod security;
pub mod transaction;
