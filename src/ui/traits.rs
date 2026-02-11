use crate::core::engine::EngineAction;
use crate::core::initializer::PeerNode;
use crate::ui::executer::UIPopup;
use crate::workers::app::{App, Mode};
use crossterm::event::KeyCode;
use ratatui::{layout::Rect, Frame};

/// Core trait for UI components that can be rendered
pub trait Component {
    fn render(&mut self, f: &mut Frame, app: &App, area: Rect);

    /// Called when this component gains focus
    fn on_focus(&mut self, _app: &mut App) {}

    /// Called when this component loses focus
    fn on_blur(&mut self, _app: &mut App) {}
}

/// Trait for components that handle keyboard input
pub trait Handler {
    fn handle_key(&mut self, app: &mut App, node: &PeerNode, key: KeyCode) -> Option<Action>;
}

/// Trait for components with multiple focusable elements
pub trait Focusable {
    fn focusable_elements(&self) -> Vec<FocusableElement>;
    fn focused_index(&self) -> usize;
    fn set_focus(&mut self, index: usize);

    fn focus_next(&mut self) {
        let elements = self.focusable_elements();
        if !elements.is_empty() {
            let current = self.focused_index();
            self.set_focus((current + 1) % elements.len());
        }
    }

    fn focus_prev(&mut self) {
        let elements = self.focusable_elements();
        if !elements.is_empty() {
            let current = self.focused_index();
            let new_idx = if current == 0 {
                elements.len() - 1
            } else {
                current - 1
            };
            self.set_focus(new_idx);
        }
    }
}

/// Actions that can be returned from handlers
#[derive(Debug, Clone)]
pub enum Action {
    SwitchMode(Mode),
    SetStatus(String),
    /// Engine actions that need async execution by the UIExecuter.
    EngineActions(Vec<EngineAction>),
    /// Show a popup (e.g. file/folder offer confirmation).
    ShowPopup(UIPopup),
    None,
}

/// Types of focusable UI elements
#[derive(Debug, Clone, PartialEq)]
pub enum FocusableElement {
    TextInput,
    Toggle,
}
