//! Centralized configuration constants for CrossDrop.
//!
//! All tunable parameters live here so they can be reviewed and adjusted
//! in a single place. Wire-format constants (frame type bytes, crypto
//! block sizes, Windows API flags) stay in their respective modules.

use std::time::Duration;

// ── Transfer / Chunking ──────────────────────────────────────────────────────

/// Canonical chunk size in bytes (48 KB).
/// Safe for SCTP message size limits on WebRTC data channels.
/// Every module that computes total_chunks or byte offsets MUST use this.
pub const CHUNK_SIZE: usize = 48 * 1024;

/// Maximum number of simultaneously active (non-terminal) transactions.
pub const MAX_CONCURRENT_TRANSACTIONS: usize = 3;

/// Sliding-window pipeline depth for WebRTC chunk sending.
/// Larger values improve throughput by allowing early-chunk buffering.
pub const PIPELINE_SIZE: usize = 32;

// ── Safety / Abuse Prevention ────────────────────────────────────────────────

/// Maximum total retries per transaction.
pub const MAX_TRANSACTION_RETRIES: usize = 100;

/// Transaction timeout (after which it expires).
/// Also used as the default transaction lifetime and secure manifest expiry.
pub const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(24 * 3600);

/// Maximum retries for WebRTC chunk send operations.
pub const MAX_SEND_RETRIES: usize = 3;

// ── Connection / Network ─────────────────────────────────────────────────────

/// WebRTC peer connection timeout.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout waiting for the data channel to open.
pub const DATA_CHANNEL_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout waiting for a single chunk ACK.
pub const CHUNK_ACK_TIMEOUT: Duration = Duration::from_secs(5);

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

// ── Prefetch ─────────────────────────────────────────────────────────────────

/// Maximum number of files to prefetch ahead during folder transfer.
pub const MAX_PREFETCH_FILES: usize = 24;

/// Maximum cumulative bytes to prefetch ahead (256 MB).
pub const MAX_PREFETCH_BYTES: u64 = 256 * 1024 * 1024;

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
