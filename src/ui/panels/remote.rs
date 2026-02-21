use crate::core::initializer::PeerNode;
use crate::ui::helpers::{format_file_size, get_display_name};
use crate::ui::popups::UIPopup;
use crate::ui::traits::{Action, Component, Handler};
use crate::workers::app::{App, Mode};
use crate::workers::peer::RemotePathRequest;
use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

pub struct RemotePanel;

impl Default for RemotePanel {
    fn default() -> Self {
        Self::new()
    }
}

impl RemotePanel {
    pub fn new() -> Self {
        Self
    }
}

impl Component for RemotePanel {
    fn render(&mut self, f: &mut Frame, app: &App, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(1)])
            .split(area);

        let title = format!(
            " Remote Files: {} @ {} ",
            get_display_name(app, app.remote.peer.as_deref().unwrap_or("?")),
            app.remote.path
        );

        let path_widget = Paragraph::new(app.remote.path.as_str()).block(
            Block::default()
                .title(" Remote Path ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );
        f.render_widget(path_widget, chunks[0]);

        let items: Vec<ListItem> = app
            .remote.entries
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                let style = if i == app.remote.selected {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };

                let icon = if entry.is_dir { "📁" } else { "📄" };
                let size = if entry.is_dir {
                    String::new()
                } else {
                    format!(" ({})", format_file_size(entry.size))
                };

                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", icon), style),
                    Span::styled(entry.name.clone(), style),
                    Span::styled(size, Style::default().fg(Color::DarkGray)),
                ]))
            })
            .collect();

        let list = List::new(items).block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );
        f.render_widget(list, chunks[1]);
    }
}

impl Handler for RemotePanel {
    fn handle_key(&mut self, app: &mut App, node: &PeerNode, key: KeyCode) -> Option<Action> {
        match key {
            KeyCode::Esc => {
                app.remote.peer = None;
                app.remote.entries.clear();
                Some(Action::SwitchMode(Mode::Peers))
            }
            KeyCode::Up => {
                if !app.remote.entries.is_empty() {
                    if app.remote.selected == 0 {
                        app.remote.selected = app.remote.entries.len() - 1;
                    } else {
                        app.remote.selected -= 1;
                    }
                }
                Some(Action::None)
            }
            KeyCode::Down => {
                if !app.remote.entries.is_empty() {
                    app.remote.selected = (app.remote.selected + 1) % app.remote.entries.len();
                }
                Some(Action::None)
            }
            KeyCode::Enter => {
                if let Some(entry) = app.remote.entries.get(app.remote.selected).cloned() {
                    if entry.is_dir {
                        // Navigate into directory
                        let new_path = if app.remote.path.ends_with('/') {
                            format!("{}{}", app.remote.path, entry.name)
                        } else {
                            format!("{}/{}", app.remote.path, entry.name)
                        };
                        app.remote.path = new_path.clone();
                        app.remote.entries.clear();
                        app.remote.selected = 0;

                        if let Some(peer_id) = &app.remote.peer {
                            let peer_id = peer_id.clone();
                            let node = node.clone();
                            tokio::spawn(async move {
                                let _ = node.list_remote_directory(&peer_id, new_path).await;
                            });
                        }
                    } else {
                        // Show request file popup
                        if let Some(peer_id) = &app.remote.peer {
                            let remote_path = if app.remote.path.ends_with('/') {
                                format!("{}{}", app.remote.path, entry.name)
                            } else {
                                format!("{}/{}", app.remote.path, entry.name)
                            };

                            let save_dir = std::env::current_dir()
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|_| ".".to_string());
                            app.remote.path_request = Some(RemotePathRequest {
                                peer_id: peer_id.clone(),
                                name: entry.name.clone(),
                                size: entry.size,
                                remote_path,
                                save_path_input: save_dir,
                                button_focus: 0,
                                is_path_editing: false,
                                is_folder: false,
                            });
                            return Some(Action::ShowPopup(UIPopup::RemotePathRequest));
                        }
                    }
                }
                Some(Action::None)
            }
            KeyCode::Backspace => {
                // Go up one directory - allow going up beyond launch directory to root
                if app.remote.path != "/" {
                    let path = app.remote.path.trim_end_matches('/');
                    if let Some(last_slash) = path.rfind('/') {
                        app.remote.path = if last_slash == 0 {
                            "/".to_string()
                        } else {
                            path[..last_slash].to_string()
                        };
                    } else {
                        app.remote.path = "/".to_string();
                    }
                    app.remote.entries.clear();
                    app.remote.selected = 0;

                    if let Some(peer_id) = &app.remote.peer {
                        let peer_id = peer_id.clone();
                        let path = app.remote.path.clone();
                        let node = node.clone();
                        tokio::spawn(async move {
                            let _ = node.list_remote_directory(&peer_id, path).await;
                        });
                    }
                }
                Some(Action::None)
            }
            KeyCode::Char('f') | KeyCode::Char('F') => {
                // Show request folder popup
                if let Some(entry) = app.remote.entries.get(app.remote.selected).cloned() {
                    if entry.is_dir {
                        if let Some(peer_id) = &app.remote.peer {
                            let remote_path = if app.remote.path.ends_with('/') {
                                format!("{}{}", app.remote.path, entry.name)
                            } else {
                                format!("{}/{}", app.remote.path, entry.name)
                            };

                            let save_dir = std::env::current_dir()
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|_| ".".to_string());
                            app.remote.path_request = Some(RemotePathRequest {
                                peer_id: peer_id.clone(),
                                name: entry.name.clone(),
                                size: entry.size,
                                remote_path,
                                save_path_input: save_dir,
                                button_focus: 0,
                                is_path_editing: false,
                                is_folder: true,
                            });
                            return Some(Action::ShowPopup(UIPopup::RemotePathRequest));
                        }
                    }
                }
                Some(Action::None)
            }
            _ => Some(Action::None),
        }
    }
}
