//! Cross-cutting utility modules used throughout the application.
//!
//! This module provides foundational utilities that are not specific to any
//! particular domain. These are low-level helpers for file I/O, cryptography,
//! system integration, and application lifecycle.
//!
//! # Module Overview
//!
//! | Module | Responsibility |
//! |--------|---------------|
//! | [`atomic_write`] | Atomic file writes via temp-file + rename pattern |
//! | [`clipboard`] | System clipboard integration for copying peer IDs |
//! | [`crypto`] | HMAC-SHA3-256 computation, constant-time comparison |
//! | [`data_dir`] | Platform-specific data directory resolution |
//! | [`global_keyboard`] | Global keyboard hook for remote key listener feature |
//! | [`hash`] | Brotli compression, identity key management, instance locking |
//! | [`log_buffer`] | In-memory ring buffer for log viewer panel |
//! | [`sos`] | Signal-of-stop for graceful shutdown coordination |
//!
//! # Design Principles
//!
//! - **No Business Logic**: These modules contain only infrastructure code.
//! - **Single Responsibility**: Each module does one thing well.
//! - **Testable**: Pure functions with minimal dependencies.
//! - **Cross-Platform**: All modules work on Windows, macOS, and Linux.
//!
//! # Critical Utilities
//!
//! ## Atomic Writes
//!
//! [`atomic_write`] ensures crash resilience for persistent state:
//!
//! ```rust,ignore
//! atomic_write(&path, json_bytes)?;  // Never leaves partial files
//! ```
//!
//! ## Cryptographic Primitives
//!
//! [`crypto`] provides the single source of truth for HMAC:
//!
//! ```rust,ignore
//! let tag = hmac_sha3_256(&key, &data);
//! assert!(constant_time_eq(&tag, &expected));
//! ```
//!
//! ## Instance Locking
//!
//! [`hash`] enforces single-instance per identity slot:
//!
//! ```rust,ignore
//! let (secret_key, _guard) = get_or_create_secret()?;
//! // _guard releases lock on drop
//! ```

pub mod atomic_write;
pub mod clipboard;
pub mod crypto;
pub mod data_dir;
pub mod global_keyboard;
pub mod hash;
pub mod log_buffer;
pub mod sos;
