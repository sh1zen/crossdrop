use crate::core::initializer::PeerNode;
use crate::core::persistence::TransferStatus;
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
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph},
    Frame,
};

pub struct FilesPanel {
    progress_bar: ProgressBar,
    /// Popup showing transaction details.
    pub info_popup: Option<FilesInfoPopup>,
}

/// Popup showing detailed transaction info.
#[derive(Debug, Clone)]
pub struct FilesInfoPopup {
    pub direction: TransactionDirection,
    pub display_name: String,
    pub peer_name: String,
    pub total_size: u64,
    pub file_count: u32,
    pub timestamp: String,
    pub status: TransferStatus,
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
            info_popup: None,
        }
    }
}

impl Component for FilesPanel {
    fn render(&mut self, f: &mut Frame, app: &App, area: Rect) {
        // Include Active, Pending, Interrupted, and Resumable transfers
        let has_active =
            app.engine.transactions().active.values().any(|t| {
                t.state == TransactionState::Active
                    || t.state == TransactionState::Pending
                    || t.state == TransactionState::Interrupted
                    || t.state == TransactionState::Resumable
            });

        // Calculate how many rows we need for active transfers
        let active_count = app
            .engine
            .transactions()
            .active
            .values()
            .filter(|t| {
                t.state == TransactionState::Active
                    || t.state == TransactionState::Pending
                    || t.state == TransactionState::Interrupted
                    || t.state == TransactionState::Resumable
            })
            .count();
        let active_height = (active_count + 1).min(8) as u16; // At least 1 row, max 8

        // Always show active transfers section (even if empty)
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Summary
                Constraint::Length(active_height.max(3)), // Active transfers (always visible)
                Constraint::Min(1),    // History
            ])
            .split(area);

        // Summary header — engine stats only (combine files + folders)
        let engine_stats = app.engine.stats();
        let total_sent = engine_stats.files_sent + engine_stats.folders_sent;
        let total_received = engine_stats.files_received + engine_stats.folders_received;

        let summary = Paragraph::new(Line::from(vec![
            Span::styled(
                format!(" Sent: {} ", total_sent),
                Style::default().fg(Color::Green),
            ),
            Span::styled(" | ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("Received: {} ", total_received),
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

        // Determine focus border colors - use blue for focused area
        let active_border_color = if app.files_focus_active {
            Color::Cyan
        } else {
            Color::DarkGray
        };
        let history_border_color = if !app.files_focus_active {
            Color::Cyan
        } else {
            Color::DarkGray
        };

        // Active transfers progress — always visible
        let mut progress_items: Vec<ListItem> = Vec::new();

        if has_active {
            // Collect active transfer IDs for selection tracking (include Interrupted and Resumable)
            let active_ids: Vec<uuid::Uuid> = app
                .engine
                .transactions()
                .active
                .values()
                .filter(|t| {
                    t.state == TransactionState::Active
                        || t.state == TransactionState::Pending
                        || t.state == TransactionState::Interrupted
                        || t.state == TransactionState::Resumable
                })
                .map(|t| t.id)
                .collect();
            let selected_idx = app
                .active_transfer_idx
                .min(active_ids.len().saturating_sub(1));

            for (idx, txn) in app
                .engine
                .transactions()
                .active
                .values()
                .filter(|t| {
                    t.state == TransactionState::Active
                        || t.state == TransactionState::Pending
                        || t.state == TransactionState::Interrupted
                        || t.state == TransactionState::Resumable
                })
                .enumerate()
            {
                let (transferred, total) = txn.progress_chunks();
                let short_name = truncate_filename(&txn.display_name, 20);

                let is_selected = idx == selected_idx && app.files_focus_active;
                let marker = if is_selected { "▶ " } else { "  " };

                // State indicator for non-active transfers
                let (state_prefix, state_color) = match txn.state {
                    TransactionState::Interrupted => ("⏸ ", Color::Yellow),
                    TransactionState::Resumable => ("↻ ", Color::Magenta),
                    TransactionState::Pending => ("⏳ ", Color::Yellow),
                    _ => ("", Color::Reset),
                };

                let arrow = match txn.direction {
                    TransactionDirection::Outbound => "-> ",
                    TransactionDirection::Inbound => "<- ",
                };
                let arrow_color = match txn.direction {
                    TransactionDirection::Outbound => Color::Green,
                    TransactionDirection::Inbound => Color::Cyan,
                };

                // Use different progress bar color for interrupted/resumable
                let bar_color = match txn.state {
                    TransactionState::Interrupted => Color::Yellow,
                    TransactionState::Resumable => Color::Magenta,
                    _ => Color::Magenta,
                };
                let bar = self.progress_bar.render(transferred, total, bar_color);

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
                        Style::default().fg(if is_selected {
                            Color::Yellow
                        } else {
                            Color::DarkGray
                        }),
                    ),
                    Span::styled(
                        state_prefix,
                        Style::default().fg(state_color).add_modifier(Modifier::BOLD),
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
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{}{}", short_name, reason_suffix),
                        Style::default().fg(Color::DarkGray),
                    ),
                ])));
            }
        } else {
            // Show placeholder when no active transfers
            progress_items.push(ListItem::new(Line::from(vec![Span::styled(
                "  No active transfers",
                Style::default().fg(Color::DarkGray),
            )])));
        }

        let progress_list = List::new(progress_items).block(
            Block::default()
                .title(" Active Transfers ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(active_border_color)),
        );
        f.render_widget(progress_list, chunks[1]);

        // File list — Engine transfer_history only
        let engine_history = app.engine.transfer_history();
        let entries_total = engine_history.len();
        let visible_height = chunks[2].height.saturating_sub(2) as usize;
        let max_scroll = entries_total.saturating_sub(visible_height);
        let scroll = app.history_scroll.min(max_scroll);

        // Calculate selected index in history
        let history_selected = app
            .history_selected_idx
            .min(entries_total.saturating_sub(1));

        let mut items: Vec<ListItem> = Vec::new();

        for (i, rec) in engine_history.iter().rev().enumerate() {
            // Apply scroll
            if i < scroll {
                continue;
            }
            if items.len() >= visible_height {
                break;
            }

            let (arrow, color) = match rec.direction {
                TransactionDirection::Outbound => ("->", Color::Green),
                TransactionDirection::Inbound => ("<-", Color::Cyan),
            };
            let file_info = if rec.file_count > 1 {
                format!(
                    " ({} files, {})",
                    rec.file_count,
                    format_file_size(rec.total_size)
                )
            } else {
                format!(" ({})", format_file_size(rec.total_size))
            };

            let is_selected = i == history_selected && !app.files_focus_active;
            let marker = if is_selected { "▶ " } else { "  " };

            // Show delete indicator (×) when selected
            let delete_marker = if is_selected { " x" } else { "" };

            // Status mark with color
            let (status_label, status_color) = match &rec.status {
                TransferStatus::Ok => ("✓", Color::Green),
                TransferStatus::Declined => ("✗", Color::Red),
                TransferStatus::Error => ("⚠", Color::Red),
                TransferStatus::Cancelled => ("⊘", Color::Yellow),
                TransferStatus::ResumeDeclined => ("↻✗", Color::Magenta),
                TransferStatus::Expired => ("⏱", Color::DarkGray),
            };

            items.push(ListItem::new(Line::from(vec![
                Span::styled(
                    marker,
                    Style::default().fg(if is_selected {
                        Color::Yellow
                    } else {
                        Color::DarkGray
                    }),
                ),
                Span::styled(
                    format!("{} ", status_label),
                    Style::default().fg(status_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{} ", arrow),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(rec.display_name.clone(), Style::default().fg(Color::White)),
                Span::styled(file_info, Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("  {}", get_display_name(app, &rec.peer_id)),
                    Style::default().fg(Color::Yellow),
                ),
                Span::styled(
                    format!("  {}", rec.timestamp),
                    Style::default().fg(Color::Indexed(240)),
                ),
                Span::styled(
                    delete_marker,
                    Style::default().fg(if is_selected {
                        Color::Red
                    } else {
                        Color::DarkGray
                    }).add_modifier(Modifier::BOLD),
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
                .border_style(Style::default().fg(history_border_color)),
        );
        f.render_widget(file_list, chunks[2]);

        // Render info popup if active
        if let Some(ref popup) = self.info_popup {
            self.render_info_popup(f, popup, area);
        }
    }

    fn on_blur(&mut self, app: &mut App) {
        app.history_scroll = 0;
        app.files_search.clear();
        app.files_focus_active = true;
        self.info_popup = None;
    }
}

impl FilesPanel {
    fn render_info_popup(&self, f: &mut Frame, popup: &FilesInfoPopup, area: Rect) {
        // Calculate popup dimensions
        let popup_width = 60u16;
        let popup_height = 12u16;
        let popup_x = (area.width.saturating_sub(popup_width)) / 2;
        let popup_y = (area.height.saturating_sub(popup_height)) / 2;
        let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

        f.render_widget(Clear, popup_area);

        let direction_str = match popup.direction {
            TransactionDirection::Outbound => "Sent",
            TransactionDirection::Inbound => "Received",
        };
        let direction_color = match popup.direction {
            TransactionDirection::Outbound => Color::Green,
            TransactionDirection::Inbound => Color::Cyan,
        };

        let lines = vec![
            Line::from(vec![
                Span::styled("Direction: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    direction_str,
                    Style::default()
                        .fg(direction_color)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Name: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&popup.display_name, Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Peer: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&popup.peer_name, Style::default().fg(Color::Yellow)),
            ]),
            Line::from(vec![
                Span::styled("Size: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format_file_size(popup.total_size),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled("Files: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    popup.file_count.to_string(),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled("Time: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&popup.timestamp, Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Status: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    popup.status.label(),
                    Style::default().fg(match &popup.status {
                        TransferStatus::Ok => Color::Green,
                        TransferStatus::Declined => Color::Red,
                        TransferStatus::Error => Color::Red,
                        TransferStatus::Cancelled => Color::Yellow,
                        TransferStatus::ResumeDeclined => Color::Magenta,
                        TransferStatus::Expired => Color::DarkGray,
                    }),
                ),
            ]),
            Line::from(vec![]),
            Line::from(vec![Span::styled(
                "Press Enter or Esc to close",
                Style::default().fg(Color::DarkGray),
            )]),
        ];

        let block = Block::default()
            .title(" Transaction Details ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow));

        let paragraph = Paragraph::new(lines).block(block);
        f.render_widget(paragraph, popup_area);
    }
}

impl Handler for FilesPanel {
    fn handle_key(&mut self, app: &mut App, _node: &PeerNode, key: KeyCode) -> Option<Action> {
        // If info popup is open, handle close
        if self.info_popup.is_some() {
            return match key {
                KeyCode::Enter | KeyCode::Esc => {
                    self.info_popup = None;
                    Some(Action::None)
                }
                _ => Some(Action::None),
            };
        }

        let has_active =
            app.engine.transactions().active.values().any(|t| {
                t.state == TransactionState::Active
                    || t.state == TransactionState::Pending
                    || t.state == TransactionState::Interrupted
                    || t.state == TransactionState::Resumable
            });

        match key {
            KeyCode::Esc => {
                if app.files_search_mode {
                    // Exit search mode first
                    app.files_search_mode = false;
                    app.files_search.clear();
                    app.history_scroll = 0;
                    return Some(Action::SetStatus("Search closed".to_string()));
                }
                app.history_scroll = 0;
                app.files_search.clear();
                app.files_focus_active = true;
                Some(Action::SwitchMode(Mode::Home))
            }
            KeyCode::Tab => {
                // Toggle focus between active and history
                app.files_focus_active = !app.files_focus_active;
                None
            }
            KeyCode::Char('/') => {
                // Enter search mode
                app.files_search_mode = true;
                app.files_search.clear();
                Some(Action::SetStatus("Search: ".to_string()))
            }
            KeyCode::Up => {
                if app.files_search_mode {
                    return Some(Action::None);
                }
                if app.files_focus_active {
                    // Move selection in active transfers
                    if has_active {
                        app.active_transfer_idx = app.active_transfer_idx.saturating_sub(1);
                    }
                } else {
                    // Move selection in history
                    let history_len = app.engine.transfer_history().len();
                    if history_len > 0 {
                        app.history_selected_idx = app.history_selected_idx.saturating_sub(1);
                        // Adjust scroll if needed
                        if app.history_selected_idx < app.history_scroll {
                            app.history_scroll = app.history_selected_idx;
                        }
                    }
                }
                Some(Action::None)
            }
            KeyCode::Down => {
                if app.files_search_mode {
                    return Some(Action::None);
                }
                if app.files_focus_active {
                    // Count active transfers (include Interrupted and Resumable)
                    let active_count = app
                        .engine
                        .transactions()
                        .active
                        .values()
                        .filter(|t| {
                            t.state == TransactionState::Active
                                || t.state == TransactionState::Pending
                                || t.state == TransactionState::Interrupted
                                || t.state == TransactionState::Resumable
                        })
                        .count();
                    if active_count > 0 {
                        app.active_transfer_idx =
                            (app.active_transfer_idx + 1).min(active_count - 1);
                    }
                } else {
                    // Move selection in history
                    let history_len = app.engine.transfer_history().len();
                    if history_len > 0 {
                        app.history_selected_idx =
                            (app.history_selected_idx + 1).min(history_len - 1);
                    }
                }
                Some(Action::None)
            }
            KeyCode::Enter => {
                if app.files_search_mode {
                    // Exit search mode on Enter
                    app.files_search_mode = false;
                    return Some(Action::SetStatus(format!("Search: {}", app.files_search)));
                }
                if app.files_focus_active && has_active {
                    // Cancel the selected active transfer (include Interrupted and Resumable)
                    let active_ids: Vec<uuid::Uuid> = app
                        .engine
                        .transactions()
                        .active
                        .values()
                        .filter(|t| {
                            t.state == TransactionState::Active
                                || t.state == TransactionState::Pending
                                || t.state == TransactionState::Interrupted
                                || t.state == TransactionState::Resumable
                        })
                        .map(|t| t.id)
                        .collect();
                    if !active_ids.is_empty() {
                        let idx = app
                            .active_transfer_idx
                            .min(active_ids.len().saturating_sub(1));
                        let txn_id = active_ids[idx];
                        let outcome = app.engine.cancel_active_transfer(&txn_id);
                        if let Some(status) = outcome.status {
                            return Some(Action::SetStatus(status));
                        }
                        if !outcome.actions.is_empty() {
                            return Some(Action::EngineActions(outcome.actions));
                        }
                    }
                } else if !app.files_focus_active {
                    // Show info popup for selected history entry
                    let history = app.engine.transfer_history();
                    let history_len = history.len();
                    if history_len > 0 {
                        let idx = app.history_selected_idx.min(history_len - 1);
                        // History is displayed in reverse, so calculate actual index
                        let actual_idx = history_len - 1 - idx;
                        if let Some(rec) = history.get(actual_idx) {
                            self.info_popup = Some(FilesInfoPopup {
                                direction: rec.direction,
                                display_name: rec.display_name.clone(),
                                peer_name: get_display_name(app, &rec.peer_id),
                                total_size: rec.total_size,
                                file_count: rec.file_count,
                                timestamp: rec.timestamp.clone(),
                                status: rec.status.clone(),
                            });
                        }
                    }
                }
                Some(Action::None)
            }
            KeyCode::Char('x') | KeyCode::Char('X') => {
                if app.files_search_mode {
                    return Some(Action::None);
                }
                // Cancel the selected active transfer (same as Enter for active)
                if app.files_focus_active && has_active {
                    let active_ids: Vec<uuid::Uuid> = app
                        .engine
                        .transactions()
                        .active
                        .values()
                        .filter(|t| {
                            t.state == TransactionState::Active
                                || t.state == TransactionState::Pending
                        })
                        .map(|t| t.id)
                        .collect();
                    if !active_ids.is_empty() {
                        let idx = app
                            .active_transfer_idx
                            .min(active_ids.len().saturating_sub(1));
                        let txn_id = active_ids[idx];
                        let outcome = app.engine.cancel_active_transfer(&txn_id);
                        if let Some(status) = outcome.status {
                            return Some(Action::SetStatus(status));
                        }
                        if !outcome.actions.is_empty() {
                            return Some(Action::EngineActions(outcome.actions));
                        }
                    }
                } else if !app.files_focus_active {
                    // Delete the selected history entry
                    let history_len = app.engine.transfer_history().len();
                    if history_len > 0 {
                        let idx = app.history_selected_idx.min(history_len - 1);
                        // History is displayed in reverse, so calculate actual index
                        let actual_idx = history_len - 1 - idx;
                        if app.engine.delete_history_entry(actual_idx) {
                            // Adjust selection if needed
                            let new_len = history_len - 1;
                            if app.history_selected_idx >= new_len && new_len > 0 {
                                app.history_selected_idx = new_len - 1;
                            }
                            return Some(Action::SetStatus("History entry deleted".to_string()));
                        }
                    }
                }
                Some(Action::None)
            }
            KeyCode::Backspace => {
                if app.files_search_mode {
                    if !app.files_search.is_empty() {
                        app.files_search.pop();
                        app.history_scroll = 0;
                        return Some(Action::SetStatus(format!("Search: {}", app.files_search)));
                    }
                    return Some(Action::None);
                }
                Some(Action::None)
            }
            KeyCode::Char(c) => {
                if app.files_search_mode {
                    app.files_search.push(c);
                    app.history_scroll = 0;
                    return Some(Action::SetStatus(format!("Search: {}", app.files_search)));
                }
                Some(Action::None)
            }
            _ => Some(Action::None),
        }
    }
}
