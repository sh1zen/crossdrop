use crate::core::engine::EngineAction;
use crate::ui::popups::context::UIPopup;
use crate::workers::app::App;
use crossterm::event::KeyCode;

/// Cycle a 3-button focus index forward (Tab) or backward (BackTab).
/// Buttons are indexed 0, 1, 2 in a circular sequence.
fn cycle_focus(current: usize, forward: bool) -> usize {
    if forward {
        match current {
            0 => 1,
            1 => 2,
            _ => 0,
        }
    } else {
        match current {
            0 => 2,
            1 => 0,
            _ => 1,
        }
    }
}

/// Result of handling a transaction offer key event.
pub struct TransactionOfferResult {
    /// Whether the app should quit.
    pub quit: bool,
    /// Engine actions to execute.
    pub actions: Vec<EngineAction>,
}

impl Default for TransactionOfferResult {
    fn default() -> Self {
        Self {
            quit: false,
            actions: Vec::new(),
        }
    }
}

/// Handle keyboard events for the transaction offer popup.
/// Delegates to TransferEngine for accept/reject logic.
pub async fn handle_transaction_offer_key(
    app: &mut App,
    key: KeyCode,
    active_popup: &mut UIPopup,
) -> TransactionOfferResult {
    let mut result = TransactionOfferResult::default();

    match key {
        KeyCode::Tab | KeyCode::BackTab => {
            let forward = matches!(key, KeyCode::Tab);
            if let Some(pi) = app.engine.pending_incoming_mut() {
                pi.button_focus = cycle_focus(pi.button_focus, forward);
                pi.path_editing = pi.button_focus == 2;
            }
        }
        KeyCode::Enter => {
            let is_editing = app
                .engine
                .pending_incoming()
                .map(|pi| pi.path_editing)
                .unwrap_or(false);
            if is_editing {
                if let Some(pi) = app.engine.pending_incoming_mut() {
                    pi.button_focus = 0;
                    pi.path_editing = false;
                }
                return result;
            }

            let button_focus = app
                .engine
                .pending_incoming()
                .map(|pi| pi.button_focus)
                .unwrap_or(0);
            let dest_path = app
                .engine
                .pending_incoming()
                .map(|pi| pi.save_path_input.clone())
                .unwrap_or_default();

            *active_popup = UIPopup::None;

            if button_focus == 0 {
                // Accept — delegate to engine
                match app.engine.accept_incoming(dest_path) {
                    Ok(outcome) => {
                        if let Some(status) = outcome.status {
                            app.notify.success(status);
                        }
                        result.actions = outcome.actions;
                    }
                    Err(e) => {
                        tracing::error!(event = "accept_failed", error = %e);
                        app.notify.error("Accept failed");
                    }
                }
            } else {
                // Reject — delegate to engine
                match app.engine.reject_incoming() {
                    Ok(outcome) => {
                        if let Some(status) = outcome.status {
                            app.notify.warn(status);
                        }
                        result.actions = outcome.actions;
                    }
                    Err(e) => {
                        tracing::error!(event = "reject_failed", error = %e);
                        app.notify.error("Reject failed");
                    }
                }
            }
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Char('c') | KeyCode::Char('C') => {
            let is_editing = app
                .engine
                .pending_incoming()
                .map(|pi| pi.path_editing)
                .unwrap_or(false);
            if !is_editing {
                *active_popup = UIPopup::None;
                match app.engine.reject_incoming() {
                    Ok(outcome) => {
                        if let Some(status) = outcome.status {
                            app.notify.warn(status);
                        }
                        result.actions = outcome.actions;
                    }
                    Err(e) => {
                        tracing::error!(event = "reject_failed", error = %e);
                        app.notify.error("Action failed");
                    }
                }
            }
        }
        KeyCode::Backspace => {
            if let Some(pi) = app.engine.pending_incoming_mut() {
                if pi.path_editing {
                    pi.save_path_input.pop();
                }
            }
        }
        KeyCode::Char(c) => {
            if let Some(pi) = app.engine.pending_incoming_mut() {
                if pi.path_editing {
                    pi.save_path_input.push(c);
                }
            }
        }
        KeyCode::Esc => {
            let is_editing = app
                .engine
                .pending_incoming()
                .map(|pi| pi.path_editing)
                .unwrap_or(false);
            if is_editing {
                if let Some(pi) = app.engine.pending_incoming_mut() {
                    pi.button_focus = 0;
                    pi.path_editing = false;
                }
            } else {
                *active_popup = UIPopup::None;
                match app.engine.reject_incoming() {
                    Ok(outcome) => {
                        if let Some(status) = outcome.status {
                            app.notify.warn(status);
                        }
                        result.actions = outcome.actions;
                    }
                    Err(e) => {
                        tracing::error!(event = "reject_failed", error = %e);
                        app.notify.error("Action failed");
                    }
                }
            }
        }
        _ => {}
    }

    result
}
