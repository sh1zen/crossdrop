use crate::core::initializer::PeerNode;
use crate::ui::helpers::{format_elapsed, get_display_name};
use crate::ui::traits::{Action, Component, Handler};
use crate::workers::app::{App, ChatMessage, ChatTarget, Mode};
use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};
use std::time::Instant;

pub struct ChatPanel;

impl Default for ChatPanel {
    fn default() -> Self {
        Self::new()
    }
}

impl ChatPanel {
    pub fn new() -> Self {
        Self
    }
}

impl Component for ChatPanel {
    fn render(&mut self, f: &mut Frame, app: &App, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(22), Constraint::Min(1)])
            .split(area);

        // Left panel: Room + peer DMs
        let targets = app.chat_targets();
        let sidebar_items: Vec<ListItem> = targets
            .iter()
            .enumerate()
            .map(|(i, target)| {
                let is_selected = i == app.chat_sidebar_idx;
                let (icon, label, badge_count) = match target {
                    ChatTarget::Room => {
                        let count = app.unread_room_count();
                        ("◆", "Room".to_string(), count)
                    }
                    ChatTarget::Peer(pid) => {
                        let count = app.unread_dm_count(pid);
                        let name = get_display_name(app, pid);
                        ("●", name, count)
                    }
                };

                let badge = if badge_count > 0 {
                    format!(" ({})", badge_count)
                } else {
                    String::new()
                };

                let line = Line::from(vec![
                    Span::styled(
                        if is_selected { " > " } else { "   " },
                        Style::default().fg(Color::Green),
                    ),
                    Span::styled(
                        format!("{} ", icon),
                        Style::default().fg(if matches!(target, ChatTarget::Room) {
                            Color::Yellow
                        } else {
                            Color::Cyan
                        }),
                    ),
                    Span::styled(
                        label,
                        if is_selected {
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(Color::Gray)
                        },
                    ),
                    Span::styled(badge, Style::default().fg(Color::Yellow)),
                ]);
                ListItem::new(line)
            })
            .collect();

        let sidebar = List::new(sidebar_items).block(
            Block::default()
                .title(" Chats ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(sidebar, chunks[0]);

        // Right panel: messages + input
        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(3)])
            .split(chunks[1]);

        let target_label = app.chat_target.label(&app.peer_names);

        // Filter messages for current target
        let messages: Vec<Line> = app
            .chat_history
            .iter()
            .filter(|m| m.target == app.chat_target)
            .map(|m| {
                let time_str = format_elapsed(m.timestamp);

                if m.from_me {
                    Line::from(vec![
                        Span::styled(
                            format!("[{}] ", time_str),
                            Style::default().fg(Color::Indexed(240)),
                        ),
                        Span::styled(
                            "You ",
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled("> ", Style::default().fg(Color::DarkGray)),
                        Span::raw(&m.text),
                    ])
                } else {
                    Line::from(vec![
                        Span::styled(
                            format!("[{}] ", time_str),
                            Style::default().fg(Color::Indexed(240)),
                        ),
                        Span::styled(
                            format!("{} ", get_display_name(app, &m.peer_id)),
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled("> ", Style::default().fg(Color::DarkGray)),
                        Span::raw(&m.text),
                    ])
                }
            })
            .collect();

        let visible_height = right_chunks[0].height.saturating_sub(2) as usize;
        let total_messages = messages.len();
        let scroll_offset = if total_messages > visible_height {
            (total_messages - visible_height) as u16
        } else {
            0
        };

        let title = match &app.chat_target {
            ChatTarget::Room => format!(" Room Chat ({} peers) ", app.peers.len()),
            ChatTarget::Peer(_) => format!(" DM with {} ", target_label),
        };

        let border_color = match &app.chat_target {
            ChatTarget::Room => Color::Yellow,
            ChatTarget::Peer(_) => Color::Cyan,
        };

        let msg_widget = Paragraph::new(messages)
            .block(
                Block::default()
                    .title(title)
                    .title_style(Style::default().fg(border_color))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            )
            .wrap(Wrap { trim: false })
            .scroll((scroll_offset, 0));
        f.render_widget(msg_widget, right_chunks[0]);

        let input_text = format!("{}_", app.input);
        let input_title = match &app.chat_target {
            ChatTarget::Room => " Message (broadcast) ",
            ChatTarget::Peer(_) => " Message (DM) ",
        };
        let input_widget = Paragraph::new(input_text)
            .block(
                Block::default()
                    .title(input_title)
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border_color)),
            )
            .style(Style::default().fg(Color::White));
        f.render_widget(input_widget, right_chunks[1]);
    }

    fn on_blur(&mut self, app: &mut App) {
        app.input.clear();
    }
}

impl Handler for ChatPanel {
    fn handle_key(&mut self, app: &mut App, node: &PeerNode, key: KeyCode) -> Option<Action> {
        match key {
            KeyCode::Esc => {
                app.input.clear();
                Some(Action::SwitchMode(Mode::Home))
            }
            KeyCode::Tab => {
                // Cycle through chat targets: Room -> peer1 -> peer2 -> ... -> Room
                let targets = app.chat_targets();
                if !targets.is_empty() {
                    app.chat_sidebar_idx = (app.chat_sidebar_idx + 1) % targets.len();
                    app.chat_target = targets[app.chat_sidebar_idx].clone();
                }
                Some(Action::None)
            }
            KeyCode::BackTab => {
                // Shift+Tab: cycle backwards
                let targets = app.chat_targets();
                if !targets.is_empty() {
                    if app.chat_sidebar_idx == 0 {
                        app.chat_sidebar_idx = targets.len() - 1;
                    } else {
                        app.chat_sidebar_idx -= 1;
                    }
                    app.chat_target = targets[app.chat_sidebar_idx].clone();
                }
                Some(Action::None)
            }
            KeyCode::Enter => {
                if !app.input.is_empty() {
                    if app.peers.is_empty() {
                        return Some(Action::SetStatus("No peers connected".to_string()));
                    }

                    let msg = app.input.clone();
                    let msg_len = msg.len() as u64;
                    let target = app.chat_target.clone();

                    match &target {
                        ChatTarget::Room => {
                            // Broadcast: record one message per peer
                            for peer_id in &app.peers {
                                app.chat_history.push(ChatMessage {
                                    from_me: true,
                                    peer_id: peer_id.clone(),
                                    text: msg.clone(),
                                    timestamp: Instant::now(),
                                    target: ChatTarget::Room,
                                });
                            }
                            app.stats.messages_sent += app.peers.len() as u64;
                            app.stats.bytes_sent += msg_len * app.peers.len() as u64;

                            let node = node.clone();
                            let m = msg.clone();
                            tokio::spawn(async move {
                                if let Err(e) = node.broadcast_chat(&m).await {
                                    tracing::error!("Broadcast failed: {e}");
                                }
                            });
                        }
                        ChatTarget::Peer(peer_id) => {
                            // DM: send to one peer
                            app.chat_history.push(ChatMessage {
                                from_me: true,
                                peer_id: peer_id.clone(),
                                text: msg.clone(),
                                timestamp: Instant::now(),
                                target: ChatTarget::Peer(peer_id.clone()),
                            });
                            app.stats.messages_sent += 1;
                            app.stats.bytes_sent += msg_len;

                            let node = node.clone();
                            let pid = peer_id.clone();
                            let m = msg.clone();
                            tokio::spawn(async move {
                                if let Err(e) = node.send_chat(&pid, &m).await {
                                    tracing::error!("DM failed: {e}");
                                }
                            });
                        }
                    }

                    app.input.clear();
                }
                Some(Action::None)
            }
            KeyCode::Backspace => {
                app.input.pop();
                Some(Action::None)
            }
            KeyCode::Char(c) => {
                app.input.push(c);
                Some(Action::None)
            }
            _ => Some(Action::None),
        }
    }
}
