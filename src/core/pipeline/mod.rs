//! High-performance file transfer pipeline with integrity verification.
//!
//! This module implements the multi-stage data processing pipeline that sits
//! between the file system and the network layer. It handles chunking, hashing,
//! Merkle tree construction, and coordinated send/receive operations.
//!
//! # Pipeline Architecture
//!
//! The pipeline is asymmetric: the sender and receiver have different stages
//! optimized for their respective roles.
//!
//! ## Sender Pipeline
//!
//! ```text
//! File on disk
//!     │
//!     ▼
//! ┌─────────────────┐
//! │ Chunk Reader    │  Read chunks sequentially, prefetch ahead
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │ Hash + Merkle   │  SHA3-256 per chunk, incremental Merkle tree
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │ Encrypt         │  AES-256-GCM with session key + nonce
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │ Send Queue      │  Pipelined batch send with backpressure
//! └────────┬────────┘
//!          │
//!          ▼
//! WebRTC Data Channel
//! ```
//!
//! ## Receiver Pipeline
//!
//! ```text
//! WebRTC Data Channel
//!     │
//!     ▼
//! ┌─────────────────┐
//! │ Decrypt         │  AES-256-GCM, verify auth tag
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │ Hash Verify     │  Compare against expected chunk hash
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │ Write Buffer    │  Batch sequential writes for throughput
//! └────────┬────────┘
//!          │
//!          ▼
//! File on disk
//! ```
//!
//! # Key Components
//!
//! | Module | Responsibility |
//! |--------|---------------|
//! | [`chunk`] | [`ChunkBitmap`] for tracking received/missing chunks (resume support) |
//! | [`merkle`] | Merkle tree construction and incremental verification |
//! | [`sender`] | Async sender pipeline: read, hash, encrypt, send |
//! | [`receiver`] | Async receiver pipeline: receive, decrypt, verify, write |
//!
//! # Integrity Model
//!
//! The pipeline provides three levels of integrity protection:
//!
//! 1. **Per-chunk SHA3-256**: Each chunk is hashed independently. The sender
//!    transmits chunk hashes before data; the receiver verifies on receipt.
//!    Failed chunks are retransmitted individually.
//!
//! 2. **Merkle Root**: All chunk hashes form a Merkle tree. The root hash
//!    is computed incrementally during send and verified at transfer end.
//!    This prevents tampering with any subset of chunks.
//!
//! 3. **AES-GCM Authentication**: Encryption provides authentication tags
//!    that detect any modification of ciphertext in transit.
//!
//! # Resume Support
//!
//! The [`ChunkBitmap`] tracks which chunks have been successfully received.
//! On connection interruption:
//!
//! 1. Receiver persists bitmap to disk (via transaction snapshot)
//! 2. On reconnect, receiver sends bitmap to sender
//! 3. Sender resumes from first missing chunk
//!
//! This avoids retransmitting already-received data, critical for large files
//! on unreliable networks.

pub mod chunk;
pub mod merkle;
pub mod receiver;
pub mod sender;
