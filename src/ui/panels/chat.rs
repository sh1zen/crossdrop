use crate::core::initializer::PeerNode;
use crate::core::persistence::{ChatSenderSnapshot, ChatTargetSnapshot};
use crate::ui::commands::{parse_command, ChatCommand, COMMAND_HELP};
use crate::ui::helpers::{format_timestamp_now, get_display_name};
use crate::ui::traits::{Action, Component, Handler};
use crate::workers::app::{App, ChatTarget, Message, MessageSender, Mode};
use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};
use std::time::Instant;
use uuid::Uuid;

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
                let is_selected = i == app.chat.sidebar_idx;
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

        // Right panel: messages + typing indicator + input
        // Determine if any peer is typing for the current target
        let typing_peers: Vec<String> = app
            .chat.typing
            .typing_peers()
            .into_iter()
            .filter(|pid| match &app.chat.target {
                ChatTarget::Room => true,
                ChatTarget::Peer(target_pid) => *pid == target_pid,
            })
            .map(|pid| get_display_name(app, pid))
            .collect();

        let has_typing = !typing_peers.is_empty();

        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(if has_typing {
                vec![
                    Constraint::Min(1),
                    Constraint::Length(1),
                    Constraint::Length(3),
                ]
            } else {
                vec![Constraint::Min(1), Constraint::Length(3)]
            })
            .split(chunks[1]);

        let target_label = app.chat.target.label(&app.peers.names);

        // Render messages from the logical message table
        let filtered: Vec<&Message> = app.chat.messages.messages_for(&app.chat.target);
        let messages: Vec<Line> = filtered
            .iter()
            .map(|m| {
                let time_str = &m.timestamp;

                match &m.sender {
                    MessageSender::Me => Line::from(vec![
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
                    ]),
                    MessageSender::Peer(pid) => Line::from(vec![
                        Span::styled(
                            format!("[{}] ", time_str),
                            Style::default().fg(Color::Indexed(240)),
                        ),
                        Span::styled(
                            format!("{} ", get_display_name(app, &pid)),
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled("> ", Style::default().fg(Color::DarkGray)),
                        Span::raw(&m.text),
                    ]),
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

        let title = match &app.chat.target {
            ChatTarget::Room => format!(" Room Chat ({} peers) ", app.peers.list.len()),
            ChatTarget::Peer(_) => format!(" DM with {} ", target_label),
        };

        let border_color = match &app.chat.target {
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

        // Typing indicator (shown only when someone is typing)
        if has_typing {
            let typing_text = if typing_peers.len() == 1 {
                format!(" {} is typing...", typing_peers[0])
            } else {
                let names = typing_peers.join(", ");
                format!(" {} are typing...", names)
            };
            let typing_widget = Paragraph::new(typing_text).style(
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            );
            f.render_widget(typing_widget, right_chunks[1]);
        }

        let input_idx = if has_typing { 2 } else { 1 };
        let input_text = format!("{}_", app.input);
        let input_title = match &app.chat.target {
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
        f.render_widget(input_widget, right_chunks[input_idx]);
    }

    fn on_focus(&mut self, app: &mut App) {
        // Reset unread for the currently active chat target
        match &app.chat.target {
            ChatTarget::Room => app.chat.unread.reset_room(),
            ChatTarget::Peer(pid) => app.chat.unread.reset_peer(&pid.clone()),
        }
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
                    app.chat.sidebar_idx = (app.chat.sidebar_idx + 1) % targets.len();
                    let new_target = targets[app.chat.sidebar_idx].clone();
                    app.switch_chat_target(new_target);
                }
                Some(Action::None)
            }
            KeyCode::BackTab => {
                // Shift+Tab: cycle backwards
                let targets = app.chat_targets();
                if !targets.is_empty() {
                    if app.chat.sidebar_idx == 0 {
                        app.chat.sidebar_idx = targets.len() - 1;
                    } else {
                        app.chat.sidebar_idx -= 1;
                    }
                    let new_target = targets[app.chat.sidebar_idx].clone();
                    app.switch_chat_target(new_target);
                }
                Some(Action::None)
            }
            KeyCode::Enter => {
                if !app.input.is_empty() {
                    let input = app.input.clone();

                    // ── Command handling ──────────────────────────────────
                    if let Some(cmd_result) = parse_command(&input) {
                        app.input.clear();
                        match cmd_result {
                            Ok(ChatCommand::Clear) => {
                                let target_snap = match &app.chat.target {
                                    ChatTarget::Room => ChatTargetSnapshot::Room,
                                    ChatTarget::Peer(pid) => ChatTargetSnapshot::Peer(pid.clone()),
                                };
                                app.chat.messages.clear_target(&app.chat.target);
                                return Some(Action::PersistClearChat(target_snap));
                            }
                            Ok(ChatCommand::Help) => {
                                // Insert an ephemeral help message (local only)
                                let help_text = COMMAND_HELP
                                    .iter()
                                    .map(|(cmd, desc)| format!("  {} — {}", cmd, desc))
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                app.chat.messages.insert(Message {
                                    id: Uuid::new_v4(),
                                    sender: MessageSender::Me,
                                    text: format!("Available commands:\n{}", help_text),
                                    timestamp: format_timestamp_now(),
                                    target: app.chat.target.clone(),
                                });
                                return Some(Action::None);
                            }
                            Err(err_msg) => {
                                return Some(Action::SetStatus(err_msg));
                            }
                        }
                    }

                    // ── Regular message send ─────────────────────────────
                    if app.peers.list.is_empty() {
                        return Some(Action::SetStatus("No peers connected".to_string()));
                    }

                    let msg = input;
                    let msg_len = msg.len() as u64;
                    let target = app.chat.target.clone();
                    let msg_id = Uuid::new_v4();
                    let timestamp = format_timestamp_now();

                    match &target {
                        ChatTarget::Room => {
                            // Single canonical message entry for all peers
                            app.chat.messages.insert(Message {
                                id: msg_id,
                                sender: MessageSender::Me,
                                text: msg.clone(),
                                timestamp: timestamp.clone(),
                                target: ChatTarget::Room,
                            });
                            let peer_count = app.peers.list.len() as u64;
                            app.engine.record_message_sent(msg_len * peer_count);

                            // Network: still sent individually to each peer
                            let node = node.clone();
                            let m = msg.clone();
                            tokio::spawn(async move {
                                if let Err(e) = node.broadcast_chat(&m).await {
                                    tracing::error!("Broadcast failed: {e}");
                                }
                            });

                            app.input.clear();
                            return Some(Action::PersistChat {
                                id: msg_id.to_string(),
                                sender: ChatSenderSnapshot::Me,
                                text: msg,
                                timestamp,
                                target: ChatTargetSnapshot::Room,
                            });
                        }
                        ChatTarget::Peer(peer_id) => {
                            // DM: one message, one peer, only in this chat view
                            app.chat.messages.insert(Message {
                                id: msg_id,
                                sender: MessageSender::Me,
                                text: msg.clone(),
                                timestamp: timestamp.clone(),
                                target: ChatTarget::Peer(peer_id.clone()),
                            });
                            app.engine.record_message_sent(msg_len);

                            // Update per-peer stats (messages sent)
                            let stats = app
                                .peers.stats
                                .entry(peer_id.clone())
                                .or_insert((0, 0, 0, 0));
                            stats.0 += 1;

                            // Use DM protocol so receiver routes to peer chat
                            let node = node.clone();
                            let pid = peer_id.clone();
                            let m = msg.clone();
                            tokio::spawn(async move {
                                if let Err(e) = node.send_dm(&pid, &m).await {
                                    tracing::error!("DM failed: {e}");
                                }
                            });

                            let target_snap = ChatTargetSnapshot::Peer(peer_id.clone());
                            app.input.clear();
                            return Some(Action::PersistChat {
                                id: msg_id.to_string(),
                                sender: ChatSenderSnapshot::Me,
                                text: msg,
                                timestamp,
                                target: target_snap,
                            });
                        }
                    }
                }
                Some(Action::None)
            }
            KeyCode::Backspace => {
                app.input.pop();
                // Still typing — send indicator
                send_typing_throttled(app, node);
                Some(Action::None)
            }
            KeyCode::Char(c) => {
                app.input.push(c);
                send_typing_throttled(app, node);
                Some(Action::None)
            }
            _ => Some(Action::None),
        }
    }
}

/// Send a typing indicator to relevant peers, throttled to at most once per 2 s.
fn send_typing_throttled(app: &mut App, node: &PeerNode) {
    let should_send = match app.chat.last_typing_sent {
        Some(last) => last.elapsed().as_secs() >= 2,
        None => true,
    };
    if !should_send || app.input.is_empty() {
        return;
    }
    app.chat.last_typing_sent = Some(Instant::now());

    let node = node.clone();
    let target = app.chat.target.clone();
    tokio::spawn(async move {
        match target {
            ChatTarget::Room => {
                let _ = node.broadcast_typing().await;
            }
            ChatTarget::Peer(pid) => {
                let _ = node.send_typing(&pid).await;
            }
        }
    });
}
