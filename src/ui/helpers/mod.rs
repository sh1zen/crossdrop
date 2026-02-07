//! UI helper utilities for formatting, loading animations, and time display.
//!
//! This module provides common utilities used across multiple UI panels,
//! centralizing formatting logic and visual consistency.
//!
//! # Components
//!
//! | Module | Responsibility |
//! |--------|---------------|
//! | [`formatters`] | File size formatting, peer ID truncation, filename display |
//! | [`loader`] | Loading spinner animation during initialization |
//! | [`time`] | Timestamp formatting for chat messages and logs |
//!
//! # Design Principles
//!
//! - **Consistent Formatting**: All user-visible numbers and identifiers go
//!   through these formatters for a consistent look across the UI.
//! - **Human-Readable Output**: File sizes use binary prefixes (KB, MB, GB),
//!   peer IDs are truncated to 8 characters, long filenames are elided.
//! - **No Business Logic**: These are pure formatting functions with no
//!   side effects or state dependencies.

pub mod formatters;
pub mod loader;
pub mod time;

pub use formatters::{direction_style, format_file_size, get_display_name, short_peer_id, truncate_filename};
pub use loader::render_loading_frame;
pub use time::{format_absolute_timestamp_now, format_timestamp_now};
