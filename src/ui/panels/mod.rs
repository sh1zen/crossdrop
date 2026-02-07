//! Full-screen UI panels for each application mode.
//!
//! Each panel corresponds to a distinct screen in the application, implementing
//! the [`traits::Component`] trait for rendering and the [`traits::Handler`]
//! trait for keyboard input handling.
//!
//! # Panel Overview
//!
//! | Panel | Mode | Purpose |
//! |-------|------|---------|
//! | [`HomePanel`] | Home | Main menu with navigation to all features |
//! | [`ChatPanel`] | Chat | Room broadcast + peer DM messaging |
//! | [`SendPanel`] | Send | Initiate file/folder transfer to a peer |
//! | [`ConnectPanel`] | Connect | Enter peer ticket to establish connection |
//! | [`PeersPanel`] | Peers | View/manage connected peers, start remote browse |
//! | [`FilesPanel`] | Files | Active transfers + transfer history |
//! | [`LogsPanel`] | Logs | Real-time tracing log viewer |
//! | [`IdPanel`] | Id | Display own peer ID and connection ticket |
//! | [`SettingsPanel`] | Settings | Configure display name, theme, remote access |
//! | [`RemotePanel`] | Remote | Browse peer's filesystem, fetch files/folders |
//! | [`KeyListenerPanel`] | KeyListener | Receive keystrokes from remote peers |
//!
//! # Panel Lifecycle
//!
//! Panels receive focus/blur callbacks when navigating between modes:
//!
//! ```text
//! on_blur(old_mode) ──► switch_mode ──► on_focus(new_mode)
//! ```
//!
//! This allows panels to initialize state when entering and clean up when leaving.
//!
//! # Action-Based Communication
//!
//! Panels don't perform I/O directly. Instead, they return [`traits::Action`]
//! enums that the [`executer::UIExecuter`] interprets and executes:
//!
//! - `SwitchMode`: Navigate to a different panel
//! - `EngineActions`: Trigger transfer operations (via [`core::engine::TransferEngine`])
//! - `ShowPopup`: Display a modal dialog
//! - `SetStatus`: Show a notification in the status bar
//!
//! This separation keeps panels testable and decoupled from async operations.

pub mod chat;
pub mod connect;
pub mod files;
pub mod home;
pub mod id;
pub mod key_listener;
pub mod logs;
pub mod peers;
pub mod remote;
pub mod send;
pub mod settings;

pub use chat::ChatPanel;
pub use connect::ConnectPanel;
pub use files::FilesPanel;
pub use home::HomePanel;
pub use id::IdPanel;
pub use key_listener::KeyListenerPanel;
pub use logs::LogsPanel;
pub use peers::PeersPanel;
pub use remote::RemotePanel;
pub use send::SendPanel;
pub use settings::SettingsPanel;
