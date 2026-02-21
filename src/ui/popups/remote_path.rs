use crate::core::initializer::PeerNode;
use crate::ui::helpers::get_display_name;
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

/// Result of handling a remote path request key event.
pub struct RemotePathResult {
    /// Whether the app should quit.
    pub quit: bool,
}

impl Default for RemotePathResult {
    fn default() -> Self {
        Self { quit: false }
    }
}

/// Handle keyboard events for the remote path request popup (file or folder).
pub async fn handle_remote_path_request_key(
    app: &mut App,
    node: &PeerNode,
    key: KeyCode,
    active_popup: &mut UIPopup,
) -> RemotePathResult {
    match key {
        KeyCode::Tab | KeyCode::BackTab => {
            let forward = matches!(key, KeyCode::Tab);
            if let Some(req) = &mut app.remote.path_request {
                req.button_focus = cycle_focus(req.button_focus, forward);
                req.is_path_editing = req.button_focus == 2;
            }
        }
        KeyCode::Enter => {
            if let Some(req) = &mut app.remote.path_request {
                if req.is_path_editing {
                    req.button_focus = 0;
                    req.is_path_editing = false;
                    return RemotePathResult::default();
                }
            }
            let req = app.remote.path_request.take().unwrap();
            let button_focus = req.button_focus;
            *active_popup = UIPopup::None;

            if button_focus == 0 {
                let node = node.clone();
                let name = req.name.clone();
                let peer_id = req.peer_id.clone();
                let remote_path = req.remote_path.clone();
                let save_path = req.save_path_input.clone();
                let is_folder = req.is_folder;
                let peer_display = get_display_name(app, &peer_id).to_string();
                tokio::spawn(async move {
                    match node
                        .fetch_remote_path_with_dest(&peer_id, remote_path, is_folder, save_path)
                        .await
                    {
                        Ok(()) => {
                            tracing::debug!(
                                "Remote {} '{}' requested from {}",
                                if is_folder { "folder" } else { "file" },
                                name,
                                peer_display
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to request remote {} '{}' from {}: {}",
                                if is_folder { "folder" } else { "file" },
                                name,
                                peer_display,
                                e
                            );
                        }
                    }
                });
                app.notify.info(format!("Requesting: {}", req.name));
            } else {
                app.notify.warn(format!("Cancelled: {}", req.name));
            }
        }
        KeyCode::Backspace => {
            if let Some(req) = &mut app.remote.path_request {
                if req.is_path_editing {
                    req.save_path_input.pop();
                }
            }
        }
        KeyCode::Char(c) => {
            if let Some(req) = &mut app.remote.path_request {
                if req.is_path_editing {
                    req.save_path_input.push(c);
                } else if c == 'n' || c == 'N' || c == 'c' || c == 'C' {
                    let req = app.remote.path_request.take().unwrap();
                    *active_popup = UIPopup::None;
                    app.notify.warn(format!("Cancelled: {}", req.name));
                }
            }
        }
        KeyCode::Esc => {
            if let Some(req) = &mut app.remote.path_request {
                if req.is_path_editing {
                    req.button_focus = 0;
                    req.is_path_editing = false;
                    return RemotePathResult::default();
                }
            }
            let req = app.remote.path_request.take().unwrap();
            *active_popup = UIPopup::None;
            app.notify.warn(format!("Cancelled: {}", req.name));
        }
        _ => {}
    }
    RemotePathResult::default()
}
