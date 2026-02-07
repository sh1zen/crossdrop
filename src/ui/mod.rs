//! Terminal User Interface for CrossDrop.
//!
//! This module implements the interactive TUI built on [ratatui], providing a
//! full-screen terminal interface for file transfer management, peer discovery,
//! chat messaging, and remote file browsing.
//!
//! # Architecture
//!
//! The UI follows a Model-View-Controller (MVC) inspired pattern:
//!
//! - **Model** ([`workers::app::App`]): Application state including peers, transfers,
//!   chat messages, and settings. Owned by [`executer::UIExecuter`].
//! - **View** ([`panels`], [`widgets`]): Rendering logic for each screen/mode.
//!   Panels implement the [`traits::Component`] trait for consistent rendering.
//! - **Controller** ([`executer`]): Event loop that bridges user input, network
//!   events, and state mutations.
//!
//! # Module Layout
//!
//! | Module | Responsibility |
//! |--------|---------------|
//! | [`executer`] | Main event loop, action dispatch, engine coordination |
//! | [`commands`] | Chat command parsing (`/clear`, `/help`) |
//! | [`notify`] | User-facing notification system with auto-expiry |
//! | [`traits`] | Shared traits for UI components ([`Component`], [`Handler`]) |
//! | [`panels`] | Full-screen panels for each mode (Home, Chat, Send, etc.) |
//! | [`popups`] | Modal dialogs (transaction offers, remote path requests) |
//! | [`widgets`] | Reusable UI widgets (progress bars, etc.) |
//! | [`helpers`] | Formatting utilities, loading animations, time helpers |
//!
//! # Navigation Model
//!
//! The UI is organized into modes, each rendered by a dedicated panel:
//!
//! ```text
//! Home (main menu)
//!  ├── Chat (room + DM messaging)
//!  ├── Send (initiate file/folder transfer)
//!  ├── Connect (enter peer ticket)
//!  ├── Peers (view/manage connected peers)
//!  ├── Files (active transfers + history)
//!  ├── Logs (tracing log viewer)
//!  ├── Id (display own peer ID / ticket)
//!  ├── Settings (display name, theme, remote access)
//!  ├── Remote (browse peer's filesystem)
//!  └── KeyListener (receive remote keystrokes)
//! ```
//!
//! # Event Flow
//!
//! ```text
//! User Input ──────► UIExecuter::handle_key_event()
//!                          │
//!                          ▼
//!                    Panel::handle_key()
//!                          │
//!                          ▼
//!                    Action enum
//!                          │
//!            ┌─────────────┼─────────────┐
//!            ▼             ▼             ▼
//!      SwitchMode    EngineActions   SetStatus
//!            │             │
//!            ▼             ▼
//!      Panel::render   PeerNode::send_*
//! ```
//!
//! # Design Principles
//!
//! 1. **Separation of Concerns**: Panels only handle rendering and input;
//!    business logic lives in [`core::engine::TransferEngine`].
//! 2. **Action-Based Communication**: Panels return [`traits::Action`] enums
//!    rather than performing I/O directly, keeping them testable.
//! 3. **State-Driven UI**: All UI state is derived from the [`App`] model;
//!    no hidden state in panels.
//! 4. **Async-Safe**: The event loop bridges sync (keyboard) and async
//!    (network) events without blocking.

pub mod commands;
pub mod executer;
pub mod helpers;
pub mod notify;
pub mod panels;
pub mod popups;
pub mod traits;
pub mod widgets;

pub use executer::run;
