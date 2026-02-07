//! Modal popup dialogs for user interactions.
//!
//! Popups are overlay UI components that appear above the current panel,
//! requiring user input before proceeding. They handle time-sensitive
//! interactions like accepting/rejecting transfers and choosing save paths.
//!
//! # Popup Types
//!
//! | Popup | Trigger | Purpose |
//! |-------|---------|---------|
//! | Transaction Offer | Incoming file/folder transfer request | Accept/reject with path selection |
//! | Remote Path Request | Peer requests to fetch a file/folder | Accept/reject with save path |
//! | Peer Info | User presses Enter on a peer in Peers panel | Display peer details and statistics |
//!
//! # Architecture
//!
//! Popups are managed by [`UIContext`], which tracks:
//!
//! - `active_popup`: Which popup is currently displayed
//! - `current_mode`: The mode to return to after popup closes
//!
//! The [`UIPopup`] enum defines all possible popup states:
//!
//! ```text
//! enum UIPopup {
//!     None,              // No popup active
//!     TransactionOffer,  // Incoming transfer request
//!     RemotePathRequest, // Remote fetch request
//!     PeerInfo,          // Peer information display
//! }
//! ```
//!
//! # Event Handling
//!
//! Popups intercept keyboard events before they reach the underlying panel.
//! Each popup has a dedicated key handler:
//!
//! - [`handle_transaction_offer_key`]: Tab between buttons, Enter to confirm, Esc to cancel
//! - [`handle_remote_path_request_key`]: Edit save path, Tab between fields
//!
//! # Rendering
//!
//! Popups render as centered boxes overlaying the main content. The
//! [`SavePathPopup`] widget provides shared rendering logic for path
//! selection UIs used by multiple popups.

pub mod context;
pub mod peer_info;
pub mod remote_path;
pub mod save_path;
pub mod transaction;

pub use context::{UIContext, UIPopup};
pub use peer_info::render_peer_info_popup;
pub use remote_path::handle_remote_path_request_key;
pub use save_path::SavePathPopup;
pub use transaction::handle_transaction_offer_key;
