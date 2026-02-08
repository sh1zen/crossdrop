use crate::core::initializer::PeerNode;
use crate::ui::helpers::{get_display_name, short_peer_id};
use crate::ui::helpers::formatters::format_cipher_key;
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
            .peers
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let is_selected = i == app.selected_peer_idx;
                let display = get_display_name(app, p);
                let short = short_peer_id(p);

                let mut spans = vec![
                    Span::styled(
                        if is_selected { " > " } else { "   " },
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(
                        display,
                        if is_selected {
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(Color::Gray)
                        },
                    ),
                ];

                // Show peer ID if display name is different
                if app.peer_names.contains_key(p) {
                    spans.push(Span::styled(
                        format!(" ({})", short),
                        Style::default().fg(Color::DarkGray),
                    ));
                }

                // Show cipher key if available
                if let Some(key) = app.peer_keys.get(p) {
                    spans.push(Span::styled(
                        format!(" [{}]", format_cipher_key(key)),
                        Style::default().fg(Color::Yellow),
                    ));
                }

                ListItem::new(Line::from(spans))
            })
            .collect();

        let peer_list = List::new(items).block(
            Block::default()
                .title(format!(" Connected Peers ({}) ", app.peers.len()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );

        if !app.peers.is_empty() {
            self.list_state.select(Some(app.selected_peer_idx));
        } else {
            self.list_state.select(None);
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(3)])
            .split(area);

        f.render_stateful_widget(peer_list, chunks[0], &mut self.list_state);

        // Hint bar at the bottom
        let hint = if app.peers.is_empty() {
            Paragraph::new("  No peers connected").style(Style::default().fg(Color::DarkGray))
        } else {
            Paragraph::new(Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    " d ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Red)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" disconnect    "),
                Span::styled(
                    " e/Enter ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" explore    "),
                Span::styled(
                    " ↑↓ ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" navigate    "),
                Span::styled(
                    " Esc ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" back"),
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
                if !app.peers.is_empty() {
                    if app.selected_peer_idx == 0 {
                        app.selected_peer_idx = app.peers.len() - 1;
                    } else {
                        app.selected_peer_idx -= 1;
                    }
                }
                Some(Action::None)
            }
            KeyCode::Down => {
                if !app.peers.is_empty() {
                    app.selected_peer_idx = (app.selected_peer_idx + 1) % app.peers.len();
                }
                Some(Action::None)
            }
            KeyCode::Char('d') | KeyCode::Char('D') => {
                if let Some(peer_id) = app.peers.get(app.selected_peer_idx) {
                    let peer_id = peer_id.clone();
                    let display_name = get_display_name(app, &peer_id);
                    let node = node.clone();
                    tokio::spawn(async move {
                        node.remove_peer(&peer_id).await;
                    });
                    Some(Action::SetStatus(format!(
                        "Disconnecting from {}...",
                        display_name
                    )))
                } else {
                    Some(Action::None)
                }
            }
            KeyCode::Char('e') | KeyCode::Char('E') | KeyCode::Enter => {
                // Explore remote file system
                if let Some(peer_id) = app.peers.get(app.selected_peer_idx) {
                    let peer_id = peer_id.clone();
                    app.remote_peer = Some(peer_id.clone());
                    app.remote_path = "/".to_string();
                    app.remote_entries.clear();
                    app.remote_selected = 0;

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
            _ => Some(Action::None),
        }
    }
}
