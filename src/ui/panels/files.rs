use crate::core::engine::EngineAction;
use crate::core::initializer::PeerNode;
use crate::core::transaction::{TransactionDirection, TransactionState};
use crate::ui::helpers::{format_file_size, get_display_name, truncate_filename};
use crate::ui::traits::{Action, Component, Handler};
use crate::ui::widgets::ProgressBar;
use crate::workers::app::{App, Mode};
use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

pub struct FilesPanel {
    progress_bar: ProgressBar,
}

impl Default for FilesPanel {
    fn default() -> Self {
        Self::new()
    }
}

impl FilesPanel {
    pub fn new() -> Self {
        Self {
            progress_bar: ProgressBar::new(20),
        }
    }
}

impl Component for FilesPanel {
    fn render(&mut self, f: &mut Frame, app: &App, area: Rect) {
        let has_active = app.engine.transactions().active.values()
            .any(|t| t.state == TransactionState::Active || t.state == TransactionState::Pending);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Summary
                Constraint::Length(if has_active { 6 } else { 0 }),
                Constraint::Min(1), // History
            ])
            .split(area);

        // Summary header — engine stats only
        let engine_stats = app.engine.stats();

        let summary = Paragraph::new(Line::from(vec![
            Span::styled(
                format!(" Sent: {} ", engine_stats.files_sent),
                Style::default().fg(Color::Green),
            ),
            Span::styled(" | ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("Received: {} ", engine_stats.files_received),
                Style::default().fg(Color::Cyan),
            ),
        ]))
        .block(
            Block::default()
                .title(" File Transfer Summary ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        );
        f.render_widget(summary, chunks[0]);

        // Active transfers progress — engine transactions only
        if has_active {
            let mut progress_items: Vec<ListItem> = Vec::new();

            // Collect active transfer IDs for selection tracking
            let active_ids: Vec<uuid::Uuid> = app.engine.transactions().active.values()
                .filter(|t| t.state == TransactionState::Active || t.state == TransactionState::Pending)
                .map(|t| t.id)
                .collect();
            let selected_idx = app.active_transfer_idx.min(active_ids.len().saturating_sub(1));

            for (idx, txn) in app.engine.transactions().active.values()
                .filter(|t| t.state == TransactionState::Active || t.state == TransactionState::Pending)
                .enumerate()
            {
                let (transferred, total) = txn.progress_chunks();
                let bar = self.progress_bar.render(transferred, total, Color::Magenta);
                let short_name = truncate_filename(&txn.display_name, 20);

                let is_selected = idx == selected_idx;
                let marker = if is_selected { "▶ " } else { "  " };

                let arrow = match txn.direction {
                    TransactionDirection::Outbound => "-> ",
                    TransactionDirection::Inbound => "<- ",
                };
                let arrow_color = match txn.direction {
                    TransactionDirection::Outbound => Color::Green,
                    TransactionDirection::Inbound => Color::Cyan,
                };

                let file_info = if txn.total_file_count() > 1 {
                    format!(
                        " ({}/{} files, {})",
                        txn.completed_file_count(),
                        txn.total_file_count(),
                        format_file_size(txn.total_size)
                    )
                } else {
                    format!(" ({})", format_file_size(txn.total_size))
                };

                progress_items.push(ListItem::new(Line::from(vec![
                    Span::styled(
                        marker,
                        Style::default()
                            .fg(if is_selected { Color::Yellow } else { Color::DarkGray }),
                    ),
                    Span::styled(
                        arrow,
                        Style::default()
                            .fg(arrow_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(short_name, Style::default().fg(Color::White)),
                    Span::raw(" "),
                    bar.spans[0].clone(),
                    bar.spans[1].clone(),
                    bar.spans[2].clone(),
                    bar.spans[3].clone(),
                    Span::styled(file_info, Style::default().fg(Color::DarkGray)),
                ])));
            }

            // Show rejected transactions
            for txn in app.engine.transactions().rejected() {
                let short_name = truncate_filename(&txn.display_name, 40);
                let reason_suffix = txn
                    .reject_reason
                    .as_ref()
                    .map(|r| format!(" ({})", r))
                    .unwrap_or_default();

                progress_items.push(ListItem::new(Line::from(vec![
                    Span::styled(
                        " ✗ ",
                        Style::default()
                            .fg(Color::Red)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{}{}", short_name, reason_suffix),
                        Style::default().fg(Color::DarkGray),
                    ),
                ])));
            }

            let progress_list = List::new(progress_items).block(
                Block::default()
                    .title(" Active Transfers ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            );
            f.render_widget(progress_list, chunks[1]);
        }

        // Peer Selector
        let mut peers_to_show = vec!["(None)".to_string()];
        for p in &app.peers {
            peers_to_show.push(p.clone());
        }

        // Filter by search if active
        if !app.files_search.is_empty() {
            let search = app.files_search.to_lowercase();
            peers_to_show.retain(|p| {
                if p == "(None)" {
                    return true;
                }
                let name = get_display_name(app, p).to_lowercase();
                name.contains(&search) || p.to_lowercase().contains(&search)
            });
        }

        let peer_idx = app
            .files_peer_idx
            .min(peers_to_show.len().saturating_sub(1));
        let _peer_spans: Vec<Span> = peers_to_show
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let name = if p == "(None)" {
                    p.clone()
                } else {
                    get_display_name(app, p)
                };
                if i == peer_idx {
                    Span::styled(
                        format!(" {} ", name),
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    )
                } else {
                    Span::styled(format!(" {} ", name), Style::default().fg(Color::Gray))
                }
            })
            .collect();

        // File list — Engine transfer_history only
        let engine_history = app.engine.transfer_history();
        let entries_total = engine_history.len();
        let visible_height = chunks[2].height.saturating_sub(2) as usize;
        let max_scroll = entries_total.saturating_sub(visible_height);
        let scroll = app.history_scroll.min(max_scroll);

        let mut items: Vec<ListItem> = Vec::new();

        for rec in engine_history.iter().rev().skip(scroll).take(visible_height) {
            let (arrow, color) = match rec.direction {
                TransactionDirection::Outbound => ("->", Color::Green),
                TransactionDirection::Inbound => ("<-", Color::Cyan),
            };
            let file_info = if rec.file_count > 1 {
                format!(" ({} files, {})", rec.file_count, format_file_size(rec.total_size))
            } else {
                format!(" ({})", format_file_size(rec.total_size))
            };

            items.push(ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {} ", arrow),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(rec.display_name.clone(), Style::default().fg(Color::White)),
                Span::styled(
                    file_info,
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("  {}", get_display_name(app, &rec.peer_id)),
                    Style::default().fg(Color::Yellow),
                ),
                Span::styled(
                    format!("  {}", rec.timestamp),
                    Style::default().fg(Color::Indexed(240)),
                ),
            ])));
        }

        let file_list = List::new(items).block(
            Block::default()
                .title(format!(
                    " Transfer History ({}/{}) ",
                    entries_total, entries_total
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(file_list, chunks[2]);
    }

    fn on_blur(&mut self, app: &mut App) {
        app.history_scroll = 0;
        app.files_search.clear();
    }
}

impl Handler for FilesPanel {
    fn handle_key(&mut self, app: &mut App, _node: &PeerNode, key: KeyCode) -> Option<Action> {
        match key {
            KeyCode::Esc => {
                app.history_scroll = 0;
                app.files_search.clear();
                Some(Action::SwitchMode(Mode::Home))
            }
            KeyCode::Up => {
                app.history_scroll = app.history_scroll.saturating_sub(1);
                Some(Action::None)
            }
            KeyCode::Down => {
                app.history_scroll += 1;
                Some(Action::None)
            }
            KeyCode::Left => {
                app.active_transfer_idx = app.active_transfer_idx.saturating_sub(1);
                Some(Action::None)
            }
            KeyCode::Right => {
                app.active_transfer_idx += 1;
                Some(Action::None)
            }
            KeyCode::Tab => {
                if !app.peers.is_empty() {
                    app.files_peer_idx = (app.files_peer_idx + 1) % app.peers.len();
                    app.history_scroll = 0;

                    if let Some(peer) = app.files_peer() {
                        let name = app
                            .peer_names
                            .get(peer)
                            .cloned()
                            .unwrap_or_else(|| peer.clone());
                        return Some(Action::SetStatus(format!("Files from {}", name)));
                    }
                }
                Some(Action::None)
            }
            KeyCode::Backspace => {
                if !app.files_search.is_empty() {
                    app.files_search.clear();
                    app.history_scroll = 0;
                    return Some(Action::SetStatus("Search cleared".to_string()));
                }
                Some(Action::None)
            }
            KeyCode::Enter | KeyCode::Char('x') | KeyCode::Char('X') => {
                // Cancel the selected active transfer
                let active_ids: Vec<uuid::Uuid> = app.engine.transactions().active.values()
                    .filter(|t| t.state == TransactionState::Active || t.state == TransactionState::Pending)
                    .map(|t| t.id)
                    .collect();
                if active_ids.is_empty() {
                    return Some(Action::None);
                }
                let idx = app.active_transfer_idx.min(active_ids.len().saturating_sub(1));
                let txn_id = active_ids[idx];
                let outcome = app.engine.cancel_active_transfer(&txn_id);
                if let Some(status) = outcome.status {
                    return Some(Action::SetStatus(status));
                }
                if !outcome.actions.is_empty() {
                    return Some(Action::EngineActions(outcome.actions));
                }
                Some(Action::None)
            }
            KeyCode::Char(c) => {
                app.files_search.push(c);
                app.history_scroll = 0;
                Some(Action::SetStatus(format!("Search: {}", app.files_search)))
            }
            _ => Some(Action::None),
        }
    }
}
