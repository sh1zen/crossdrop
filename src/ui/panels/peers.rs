use crate::core::initializer::PeerNode;
use crate::ui::helpers::formatters::format_cipher_key;
use crate::ui::helpers::{get_display_name, short_peer_id};
use crate::ui::popups::UIPopup;
use crate::ui::traits::{Action, Component, Handler};
use crate::workers::app::{App, Mode};
use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};

pub struct PeersPanel {
    list_state: ListState,
}

impl Default for PeersPanel {
    fn default() -> Self {
        Self::new()
    }
}

impl PeersPanel {
    pub fn new() -> Self {
        Self {
            list_state: ListState::default(),
        }
    }
}

impl Component for PeersPanel {
    fn render(&mut self, f: &mut Frame, app: &App, area: Rect) {
        let items: Vec<ListItem> = app
            .peers.list
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let is_selected = i == app.peers.selected_idx;
                let is_online = app.is_peer_online(p);
                let display = get_display_name(app, p);
                let short = short_peer_id(p);

                // Status indicator: green circle for online, grey for offline
                let status_indicator = if is_online {
                    Span::styled("● ", Style::default().fg(Color::Green))
                } else {
                    Span::styled("● ", Style::default().fg(Color::DarkGray))
                };

                let name_style = if !is_online {
                    // Offline peers always rendered in dark grey
                    Style::default().fg(Color::DarkGray)
                } else if is_selected {
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                };

                let mut spans = vec![
                    Span::styled(
                        if is_selected { " > " } else { "   " },
                        Style::default().fg(Color::Cyan),
                    ),
                    status_indicator,
                    Span::styled(display, name_style),
                ];

                // Show peer ID if display name is different
                if app.peers.names.contains_key(p) {
                    spans.push(Span::styled(
                        format!(" ({})", short),
                        Style::default().fg(Color::DarkGray),
                    ));
                }

                // Show cipher key if available
                if let Some(key) = app.peers.keys.get(p) {
                    spans.push(Span::styled(
                        format!(" [key: {}]", format_cipher_key(key)),
                        Style::default().fg(if is_online {
                            Color::Yellow
                        } else {
                            Color::DarkGray
                        }),
                    ));
                }

                // Show offline label
                if !is_online {
                    spans.push(Span::styled(
                        " [offline]",
                        Style::default().fg(Color::DarkGray),
                    ));
                }

                ListItem::new(Line::from(spans))
            })
            .collect();

        let online_count = app.peers.list.iter().filter(|p| app.is_peer_online(p)).count();
        let total_count = app.peers.list.len();
        let peer_list = List::new(items).block(
            Block::default()
                .title(format!(" Peers ({}/{} online) ", online_count, total_count))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );

        if !app.peers.list.is_empty() {
            self.list_state.select(Some(app.peers.selected_idx));
        } else {
            self.list_state.select(None);
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(3)])
            .split(area);

        f.render_stateful_widget(peer_list, chunks[0], &mut self.list_state);

        // Hint bar at the bottom
        let hint = if app.peers.list.is_empty() {
            Paragraph::new("  No peers saved").style(Style::default().fg(Color::DarkGray))
        } else {
            Paragraph::new(Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    " Enter ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" info  "),
                Span::styled(
                    " d ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Red)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" disconnect  "),
                Span::styled(
                    " x ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" remove  "),
                Span::styled(
                    " s ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::LightMagenta)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" clear offline  "),
                Span::styled(
                    " c ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" clear all  "),
                Span::styled(
                    " e ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" explore  "),
                Span::styled(
                    " k ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Blue)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" key events  "),
            ]))
        };
        f.render_widget(hint, chunks[1]);
    }
}

impl Handler for PeersPanel {
    fn handle_key(&mut self, app: &mut App, node: &PeerNode, key: KeyCode) -> Option<Action> {
        match key {
            KeyCode::Esc => Some(Action::SwitchMode(Mode::Home)),
            KeyCode::Up => {
                if !app.peers.list.is_empty() {
                    if app.peers.selected_idx == 0 {
                        app.peers.selected_idx = app.peers.list.len() - 1;
                    } else {
                        app.peers.selected_idx -= 1;
                    }
                }
                Some(Action::None)
            }
            KeyCode::Down => {
                if !app.peers.list.is_empty() {
                    app.peers.selected_idx = (app.peers.selected_idx + 1) % app.peers.list.len();
                }
                Some(Action::None)
            }
            KeyCode::Char('d') | KeyCode::Char('D') => {
                if let Some(peer_id) = app.peers.list.get(app.peers.selected_idx) {
                    let peer_id = peer_id.clone();
                    let display_name = get_display_name(app, &peer_id);
                    if app.is_peer_online(&peer_id) {
                        // Online peer: disconnect the active connection
                        let node = node.clone();
                        let pid = peer_id.clone();
                        tokio::spawn(async move {
                            node.remove_peer(&pid).await;
                        });
                        Some(Action::SetStatus(format!(
                            "Disconnecting from {}...",
                            display_name
                        )))
                    } else {
                        // Offline peer: just remove from the list and registry
                        Some(Action::RemoveSavedPeer(peer_id))
                    }
                } else {
                    Some(Action::None)
                }
            }
            KeyCode::Char('x') | KeyCode::Char('X') => {
                // Remove a single saved peer (disconnect if online, remove from registry)
                if let Some(peer_id) = app.peers.list.get(app.peers.selected_idx) {
                    let peer_id = peer_id.clone();
                    if app.is_peer_online(&peer_id) {
                        let node = node.clone();
                        let pid = peer_id.clone();
                        tokio::spawn(async move {
                            node.remove_peer(&pid).await;
                        });
                    }
                    Some(Action::RemoveSavedPeer(peer_id))
                } else {
                    Some(Action::None)
                }
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                // Clear all saved peers
                Some(Action::ClearSavedPeers)
            }
            KeyCode::Char('s') | KeyCode::Char('S') => {
                // Clear offline peers only
                Some(Action::ClearOfflinePeers)
            }
            KeyCode::Enter => {
                // Show peer info popup
                if let Some(peer_id) = app.peers.list.get(app.peers.selected_idx) {
                    app.peers.info_popup = Some(peer_id.clone());
                    Some(Action::ShowPopup(UIPopup::PeerInfo))
                } else {
                    Some(Action::None)
                }
            }
            KeyCode::Char('e') | KeyCode::Char('E') => {
                // Explore remote file system
                if let Some(peer_id) = app.peers.list.get(app.peers.selected_idx) {
                    let peer_id = peer_id.clone();
                    app.remote.peer = Some(peer_id.clone());
                    app.remote.path = "/".to_string();
                    app.remote.entries.clear();
                    app.remote.selected = 0;

                    // Request directory listing starting from root
                    let node = node.clone();
                    tokio::spawn(async move {
                        let _ = node.list_remote_directory(&peer_id, "/".to_string()).await;
                    });

                    Some(Action::SwitchMode(Mode::Remote))
                } else {
                    Some(Action::None)
                }
            }
            KeyCode::Char('k') | KeyCode::Char('K') => {
                // View key listener events
                Some(Action::SwitchMode(Mode::KeyListener))
            }
            _ => Some(Action::None),
        }
    }
}
