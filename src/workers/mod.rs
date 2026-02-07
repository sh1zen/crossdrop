//! Application state models and worker types.
//!
//! This module defines the core data structures that represent the application's
//! runtime state. These types bridge the gap between the UI layer and the
//! domain logic in [`core`].
//!
//! # Module Overview
//!
//! | Module | Responsibility |
//! |--------|---------------|
//! | [`app`] | Main [`App`] struct, modes, chat state, message model |
//! | [`args`] | Command-line argument parsing and configuration |
//! | [`peer`] | Peer-related state: connectivity, remote browsing |
//! | [`settings`] | User-configurable settings: display name, theme, remote access |
//!
//! # State Architecture
//!
//! The application state is organized hierarchically:
//!
//! ```text
//! App
//! ├── mode: Mode (current screen)
//! ├── engine: TransferEngine (transfer state machine)
//! ├── notify: NotifyManager (user notifications)
//! └── state: State
//!     ├── peers: PeerState (connectivity, names, keys)
//!     ├── chat: ChatState (messages, typing, unread)
//!     ├── remote: RemoteState (file browsing)
//!     ├── files: FilesPanelState (UI state for files panel)
//!     ├── settings: Settings (user preferences)
//!     ├── transfer: TransferState (UI state for send panel)
//!     └── key_listener: KeyListenerState (remote keystrokes)
//! ```
//!
//! # Design Principles
//!
//! 1. **State Separation**: UI state (scroll positions, input buffers) is
//!    separate from domain state (peers, transfers). This keeps the model
//!    clean and testable.
//!
//! 2. **Single Source of Truth**: [`App`] owns all state; panels read from
//!    it rather than maintaining their own state.
//!
//! 3. **Enum-Driven Modes**: [`Mode`] enum ensures exhaustive handling of
//!    all screens; compiler catches missing cases.
//!
//! 4. **Message Model**: Chat uses a logical [`Message`] model that deduplicates
//!    across room and DM contexts, avoiding confusion when the same message
//!    is displayed in multiple views.
//!
//! # Interaction with Core
//!
//! The [`core::engine::TransferEngine`] is embedded in [`App`] and serves as
//! the single source of truth for all transfer-related state. The UI layer
//! reads from it but never mutates it directly—instead, it dispatches
//! [`core::engine::EngineAction`] enums that the engine processes.

pub mod app;
pub mod args;
pub mod peer;
pub mod settings;
