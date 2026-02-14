//! Centralized configuration constants for CrossDrop.
//!
//! All tunable parameters live here so they can be reviewed and adjusted
//! in a single place. Wire-format constants (frame type bytes, crypto
//! block sizes, Windows API flags) stay in their respective modules.

use std::time::Duration;

// ── Transfer / Chunking ──────────────────────────────────────────────────────

/// Default chunk size in bytes (256 KB).
/// This is the starting size for adaptive chunk sizing.
/// Every module that computes total_chunks or byte offsets MUST use this.
pub const CHUNK_SIZE: usize = 256 * 1024;

/// Minimum chunk size for adaptive sizing (64 KB).
#[allow(dead_code)]
pub const MIN_CHUNK_SIZE: usize = 64 * 1024;

/// Maximum chunk size for adaptive sizing (1 MB).
#[allow(dead_code)]
pub const MAX_CHUNK_SIZE: usize = 1024 * 1024;

/// Maximum number of simultaneously active (non-terminal) transactions.
pub const MAX_CONCURRENT_TRANSACTIONS: usize = 3;

/// Sliding-window pipeline depth for WebRTC chunk sending.
/// Larger values improve throughput by allowing early-chunk buffering.
pub const PIPELINE_SIZE: usize = 32;

/// Number of throughput samples used for adaptive chunk sizing EMA.
#[allow(dead_code)]
pub const ADAPTIVE_CHUNK_SAMPLE_WINDOW: usize = 8;

/// Throughput increase ratio (vs previous EMA) that triggers a chunk-size
/// scale-up.  1.05 = 5% improvement.
#[allow(dead_code)]
pub const ADAPTIVE_CHUNK_SCALE_UP_THRESHOLD: f64 = 1.05;

/// Throughput decrease ratio that triggers a chunk-size scale-down.
/// 0.90 = 10% degradation.
#[allow(dead_code)]
pub const ADAPTIVE_CHUNK_SCALE_DOWN_THRESHOLD: f64 = 0.90;

/// Sender read-ahead buffer: max chunks prefetched from disk and queued
/// for encryption+send.  Keeps the data channel saturated while the disk
/// reads the next batch.
pub const SENDER_READ_AHEAD_CHUNKS: usize = 64;

/// Receiver write-buffer: max chunks held in memory before flushing a
/// sequential run to disk.  Batching sequential writes reduces syscall
/// overhead and improves throughput on rotational media.
pub const RECEIVER_WRITE_BUFFER_CHUNKS: usize = 64;

// ── Safety / Abuse Prevention ────────────────────────────────────────────────

/// Maximum total retries per transaction.
pub const MAX_TRANSACTION_RETRIES: usize = 100;

/// Transaction timeout (after which it expires).
/// Also used as the default transaction lifetime and secure manifest expiry.
pub const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(24 * 3600);

/// Maximum chunks buffered per file before its Metadata frame arrives.
/// Prevents a peer from flooding pre-metadata chunks to exhaust memory.
pub const MAX_PENDING_CHUNKS_PER_FILE: usize = 64;

/// Maximum number of distinct file IDs in the pending-chunk buffer.
/// Limits memory exposure from bogus file IDs sent before Metadata.
pub const MAX_PENDING_FILE_IDS: usize = 16;

// ── Connection / Network ─────────────────────────────────────────────────────

/// WebRTC peer connection timeout.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout waiting for the data channel to open.
pub const DATA_CHANNEL_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for ICE candidate gathering.
pub const ICE_GATHER_TIMEOUT: Duration = Duration::from_secs(15);

/// Session key rotation interval (1 hour).
pub const KEY_ROTATION_INTERVAL: Duration = Duration::from_secs(3600);

/// Number of port-binding attempts when starting the Iroh endpoint.
pub const PORT_RETRY_ATTEMPTS: u16 = 10;

// ── Heartbeat / Keep-alive ───────────────────────────────────────────────────

/// Interval between heartbeat pings.
pub const PING_INTERVAL: Duration = Duration::from_secs(10);

/// Time to wait for a pong before considering the peer dead.
pub const PONG_TIMEOUT: Duration = Duration::from_secs(60);

/// Number of consecutive ping failures before declaring offline.
pub const MAX_CONSECUTIVE_PING_FAILURES: u32 = 3;

// ── Auto-reconnect ──────────────────────────────────────────────────────────

/// Maximum reconnect attempts on initial connection.
pub const INITIAL_CONNECT_MAX_RETRIES: u32 = 3;

/// Delays (in seconds) between initial reconnect attempts.
pub const INITIAL_CONNECT_RETRY_DELAYS: [u64; 3] = [5, 15, 30];

/// Maximum reconnect attempts after a connection drop.
pub const RECONNECT_MAX_RETRIES: u32 = 5;

/// Delays (in seconds) between reconnect attempts after a drop.
pub const RECONNECT_RETRY_DELAYS: [u64; 5] = [3, 5, 10, 20, 30];

// ── UI / Misc ────────────────────────────────────────────────────────────────

/// Seconds after which a peer's "typing" indicator expires.
pub const TYPING_TIMEOUT_SECS: u64 = 3;

/// Maximum log entries kept in the in-memory ring buffer.
pub const MAX_LOG_ENTRIES: usize = 500;
