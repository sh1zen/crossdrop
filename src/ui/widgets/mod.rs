//! Reusable UI widgets for rendering common visual elements.
//!
//! This module contains small, reusable components that are used across
//! multiple panels. Each widget is self-contained and renders a specific
//! visual element.
//!
//! # Available Widgets
//!
//! | Widget | Purpose |
//! |--------|---------|
//! | [`ProgressBar`] | Visual progress indicator for file transfers |
//!
//! # Design Pattern
//!
//! Widgets follow the ratatui widget pattern:
//!
//! - They implement `Widget` or `StatefulWidget` traits
//! - They are pure renderers with no business logic
//! - They accept configuration via their constructor
//!
//! # Usage Example
//!
//! ```rust,ignore
//! let progress = ProgressBar::new()
//!     .ratio(transferred as f64 / total as f64)
//!     .label(&format!("{} / {}", format_file_size(transferred), format_file_size(total)));
//! f.render_widget(progress, area);
//! ```

pub mod progress_bar;

pub use progress_bar::ProgressBar;
