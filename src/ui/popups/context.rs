use crate::workers::app::Mode;

/// Tracks the current UI context - which window and popup state.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UIPopup {
    None,
    TransactionOffer,
    RemotePathRequest,
    PeerInfo,
}

/// Context for the user interface: tracks current location and state.
#[derive(Debug, Clone)]
pub struct UIContext {
    /// The current mode/window of the app.
    pub current_mode: Mode,
    /// Which popup is active, if any.
    pub active_popup: UIPopup,
}

impl UIContext {
    pub fn new() -> Self {
        Self {
            current_mode: Mode::Home,
            active_popup: UIPopup::None,
        }
    }

    /// Determines if a popup is active.
    pub fn has_popup(&self) -> bool {
        self.active_popup != UIPopup::None
    }

    /// Change the mode and update the context.
    pub fn switch_mode(&mut self, new_mode: Mode) {
        self.current_mode = new_mode;
        self.active_popup = UIPopup::None;
    }
}

impl Default for UIContext {
    fn default() -> Self {
        Self::new()
    }
}
