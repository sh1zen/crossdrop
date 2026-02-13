//! Centralized configuration constants for CrossDrop.
//!
//! All tunable parameters live here so they can be reviewed and adjusted
//! in a single place. Wire-format constants (frame type bytes, crypto
//! block sizes, Windows API flags) stay in their respective modules.

use std::time::Duration;

// ── Transfer / Chunking ──────────────────────────────────────────────────────

/// Default chunk size in bytes (48 KB).
///
/// This is sized to fit within the default 64 KB SCTP receive buffer used by
/// webrtc-rs, accounting for:
/// - AES-256-GCM overhead: 28 bytes (12 nonce + 16 auth tag)
/// - Frame overhead: 21 bytes (1 frame type + 16 UUID + 4 seq)
/// - Envelope: 1 byte (compress flag)
/// - Safety margin: ~4 KB for additional protocol overhead
///
/// Note: While we set SCTP_MAX_MESSAGE_SIZE to 1 MB for sending, the
/// webrtc-rs library's receive-side buffer defaults to 64 KB and cannot
/// be configured via the public API.
pub const CHUNK_SIZE: usize = 48 * 1024;

/// Sliding-window pipeline depth for WebRTC chunk sending.
/// Larger values improve throughput by allowing early-chunk buffering.
/// Also controls the batch size for sending chunk hashes ahead of data.
pub const PIPELINE_SIZE: usize = 32;

/// Sender read-ahead buffer: max chunks prefetched from disk and queued
/// for encryption+send.  Keeps the data channel saturated while the disk
/// reads the next batch.
pub const SENDER_READ_AHEAD_CHUNKS: usize = 64;

/// Receiver write-buffer: max chunks held in memory before flushing a
/// sequential run to disk.  Batching sequential writes reduces syscall
/// overhead and improves throughput on rotational media.
pub const RECEIVER_WRITE_BUFFER_CHUNKS: usize = 64;

/// Read-back buffer size used when computing the whole-file SHA3-256 hash
/// during finalization (slow path only — when chunks arrived out of order).
/// 8 MB keeps memory bounded while providing good sequential-read throughput.
pub const HASH_READ_BUFFER: usize = 8 * 1024 * 1024;

/// Maximum files in-flight (sent but not yet acknowledged via FileReceived).
/// Sender pauses if this many files are pending ACK.
/// Higher values improve throughput by overlapping the next file's transfer
/// with the previous file's finalization on the receiver side.
pub const MAX_PENDING_FILE_ACKS: usize = 5;

/// AreYouAwake polling interval while sender is paused waiting for file ACKs.
pub const FILE_ACK_POLL_INTERVAL: Duration = Duration::from_secs(5);

// ── Transactions ─────────────────────────────────────────────────────────────

/// Maximum number of simultaneously active transactions (state == Active).
/// Only transactions that are actively transferring data count toward this
/// limit.  Pending, Interrupted, and Resumable transactions do NOT count.
pub const MAX_CONCURRENT_TRANSACTIONS: usize = 6;

/// Maximum total retries per transaction.
pub const MAX_TRANSACTION_RETRIES: usize = 100;

/// Transaction timeout (after which it expires).
/// Also used as the default transaction lifetime and secure manifest expiry.
pub const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(24 * 3600);

/// Maximum retransmission attempts per file within a transaction.
/// If a file's integrity check fails more than this many times, the file
/// is permanently marked as failed and the transaction proceeds.
pub const MAX_FILE_RETRANSMISSIONS: u32 = 3;

// ── Safety / Abuse Prevention ────────────────────────────────────────────────

/// Maximum chunks buffered per file before its Metadata frame arrives.
/// Prevents a peer from flooding pre-metadata chunks to exhaust memory.
pub const MAX_PENDING_CHUNKS_PER_FILE: usize = 64;

/// Maximum number of distinct file IDs in the pending-chunk buffer.
/// Limits memory exposure from bogus file IDs sent before Metadata.
pub const MAX_PENDING_FILE_IDS: usize = 16;

// ── Connection / Network ─────────────────────────────────────────────────────

/// Explicit large SCTP max message size (1 MiB).
/// Using a concrete value instead of Unbounded (0) because some WebRTC
/// implementations interpret 0 as "use default 64 KB" rather than unlimited.
pub const SCTP_MAX_MESSAGE_SIZE: u32 = 1 * 1024 * 1024;

/// Whether to allow loopback connections (same-machine testing).
pub const SCTP_USE_LOOPBACK: bool = false;

/// WebRTC peer connection timeout.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout waiting for the data channel to open.
pub const DATA_CHANNEL_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum retries when the data channel is transiently not open during a file send.
/// Prevents aborting an entire transfer on a momentary SCTP hiccup.
pub const DC_SEND_MAX_RETRIES: u32 = 10;

/// Timeout for waiting for a data channel to reopen during a send retry.
pub const DC_REOPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// High water mark for the WebRTC data channel SCTP send buffer (bytes).
/// When `buffered_amount` exceeds this value, the sender pauses chunk
/// transmission until the buffer drains below the low water mark.
/// 4 MB provides enough headroom to keep the SCTP transport saturated
/// on fast links while still protecting slow links (TURN relays, mobile).
pub const DC_BUFFERED_AMOUNT_HIGH: usize = 4 * 1024 * 1024; // 4 MB

/// Timeout for ICE candidate gathering.
pub const ICE_GATHER_TIMEOUT: Duration = Duration::from_secs(15);

/// Session key rotation interval (1 hour).
pub const KEY_ROTATION_INTERVAL: Duration = Duration::from_secs(3600);

/// Number of port-binding attempts when starting the Iroh endpoint.
pub const PORT_RETRY_ATTEMPTS: u16 = 10;

// ── Liveness / Awake Check ───────────────────────────────────────────────────

/// Timeout for "are you awake?" probe sent before communicating with a peer.
/// If the peer doesn't respond within this duration, it is considered dead.
pub const AWAKE_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

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
