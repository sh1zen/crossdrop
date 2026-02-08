use crate::core::initializer::PeerNode;
use crate::core::transaction::{TransactionDirection, TransactionState};
use crate::ui::helpers::{format_elapsed, format_file_size, get_display_name, truncate_filename};
use crate::ui::traits::{Action, Component, Handler};
use crate::ui::widgets::ProgressBar;
use crate::workers::app::{App, FileDirection, Mode};
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
        let engine_active = app.engine.transactions().active.values()
            .any(|t| t.state == TransactionState::Active || t.state == TransactionState::Pending);
        let has_active = engine_active
            || !app.send_progress.is_empty()
            || !app.file_progress.is_empty()
            || !app.folder_progress.is_empty()
            || !app.rejected_transfers.is_empty()
            || app.transactions.active_count() > 0;

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Summary
                Constraint::Length(if has_active {
                    2 + app.send_progress.len().max(1) as u16
                        + app.file_progress.len() as u16
                        + app.folder_progress.len() as u16
                } else {
                    0
                }),
                Constraint::Min(1), // History
            ])
            .split(area);

        // Summary header — engine stats + legacy history count
        let engine_stats = app.engine.stats();
        let sent_count = engine_stats.files_sent as usize + app
            .file_history
            .iter()
            .filter(|f| f.direction == FileDirection::Sent)
            .count();
        let recv_count = engine_stats.files_received as usize + app
            .file_history
            .iter()
            .filter(|f| f.direction == FileDirection::Received)
            .count();

        let summary = Paragraph::new(Line::from(vec![
            Span::styled(
                format!(" Sent: {} ", sent_count),
                Style::default().fg(Color::Green),
            ),
            Span::styled(" | ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("Received: {} ", recv_count),
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

        // Active transfers progress
        if has_active {
            let mut progress_items: Vec<ListItem> = Vec::new();

            // 1. Folder progress (aggregated)
            for (folder_id, (completed, total)) in &app.folder_progress {
                let bar = self.progress_bar.render(*completed, *total, Color::Yellow);

                // Find folder name from offers
                let folder_name = app
                    .pending_folder_offers
                    .iter()
                    .find(|o| o.folder_id == *folder_id)
                    .map(|o| o.dirname.as_str())
                    .or_else(|| {
                        app.accepting_folder
                            .as_ref()
                            .filter(|o| o.folder_id == *folder_id)
                            .map(|o| o.dirname.as_str())
                    })
                    .unwrap_or("Folder");

                let short_name = truncate_filename(folder_name, 20);

                progress_items.push(ListItem::new(Line::from(vec![
                    Span::styled(
                        " .. ",
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(short_name, Style::default().fg(Color::White)),
                    Span::raw(" "),
                    bar.spans[0].clone(),
                    bar.spans[1].clone(),
                    bar.spans[2].clone(),
                    bar.spans[3].clone(),
                    Span::styled(
                        format!(" ({}/{})", completed, total),
                        Style::default().fg(Color::DarkGray),
                    ),
                ])));
            }

            // 2. Individual file send progress - aggregated by parent directory
            let send_items: Vec<_> = app.send_progress.values().collect();
            
            // Group files by parent directory
            let mut grouped_sends: std::collections::HashMap<&str, Vec<_>> = std::collections::HashMap::new();
            for (filename, sent, total) in send_items.iter() {
                let parent_dir = filename.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");
                grouped_sends.entry(parent_dir).or_insert_with(Vec::new).push((filename.as_str(), *sent, *total));
            }

            // Show aggregated or individual entries
            for (parent_dir, files) in grouped_sends.iter() {
                if files.len() > 1 && !parent_dir.is_empty() {
                    // Multiple files in same directory - show aggregated
                    let total_sent: u32 = files.iter().map(|(_, sent, _)| *sent).sum();
                    let total_bytes: u32 = files.iter().map(|(_, _, total)| *total).sum();
                    let bar = self.progress_bar.render(total_sent, total_bytes, Color::Cyan);
                    let short_name = truncate_filename(parent_dir, 20);

                    progress_items.push(ListItem::new(Line::from(vec![
                        Span::styled(
                            " -> ",
                            Style::default()
                                .fg(Color::Green)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(short_name, Style::default().fg(Color::White)),
                        Span::raw(" "),
                        bar.spans[0].clone(),
                        bar.spans[1].clone(),
                        bar.spans[2].clone(),
                        bar.spans[3].clone(),
                        Span::styled(
                            format!(" ({} files)", files.len()),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ])));
                } else {
                    // Single file or no parent directory - show individually
                    for (filename, sent, total) in files {
                        let bar = self.progress_bar.render(*sent, *total, Color::Cyan);
                        let short_name = truncate_filename(filename, 20);

                        progress_items.push(ListItem::new(Line::from(vec![
                            Span::styled(
                                " -> ",
                                Style::default()
                                    .fg(Color::Green)
                                    .add_modifier(Modifier::BOLD),
                            ),
                            Span::styled(short_name, Style::default().fg(Color::White)),
                            Span::raw(" "),
                            bar.spans[0].clone(),
                            bar.spans[1].clone(),
                            bar.spans[2].clone(),
                            bar.spans[3].clone(),
                        ])));
                    }
                }
            }

            // 3. Individual file receive progress - aggregated by parent directory
            // Filter out files that are part of active folder transfers
            let recv_items: Vec<_> = app.file_progress
                .iter()
                .filter(|(file_id, _)| !app.file_to_folder.contains_key(file_id))
                .map(|(_, v)| v)
                .collect();
            
            // Group files by parent directory
            let mut grouped_receives: std::collections::HashMap<&str, Vec<_>> = std::collections::HashMap::new();
            for (filename, recv, total) in recv_items.iter() {
                let parent_dir = filename.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");
                grouped_receives.entry(parent_dir).or_insert_with(Vec::new).push((filename.as_str(), *recv, *total));
            }

            // Show aggregated or individual entries
            for (parent_dir, files) in grouped_receives.iter() {
                if files.len() > 1 && !parent_dir.is_empty() {
                    // Multiple files in same directory - show aggregated
                    let total_recv: u32 = files.iter().map(|(_, recv, _)| *recv).sum();
                    let total_bytes: u32 = files.iter().map(|(_, _, total)| *total).sum();
                    let bar = self.progress_bar.render(total_recv, total_bytes, Color::Cyan);
                    let short_name = truncate_filename(parent_dir, 20);

                    progress_items.push(ListItem::new(Line::from(vec![
                        Span::styled(
                            " <- ",
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(short_name, Style::default().fg(Color::White)),
                        Span::raw(" "),
                        bar.spans[0].clone(),
                        bar.spans[1].clone(),
                        bar.spans[2].clone(),
                        bar.spans[3].clone(),
                        Span::styled(
                            format!(" ({} files)", files.len()),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ])));
                } else {
                    // Single file or no parent directory - show individually
                    for (filename, recv, total) in files {
                        let bar = self.progress_bar.render(*recv, *total, Color::Cyan);
                        let short_name = truncate_filename(filename, 20);

                        progress_items.push(ListItem::new(Line::from(vec![
                            Span::styled(
                                " <- ",
                                Style::default()
                                    .fg(Color::Cyan)
                                    .add_modifier(Modifier::BOLD),
                            ),
                            Span::styled(short_name, Style::default().fg(Color::White)),
                            Span::raw(" "),
                            bar.spans[0].clone(),
                            bar.spans[1].clone(),
                            bar.spans[2].clone(),
                            bar.spans[3].clone(),
                        ])));
                    }
                }
            }

            // 4. Show rejected transfers
            for (filename, reason) in app.rejected_transfers.values() {
                let reason_suffix = reason
                    .as_ref()
                    .map(|r| format!(" ({})", r))
                    .unwrap_or_default();
                let short_name = truncate_filename(&format!("{}{}", filename, reason_suffix), 50);

                progress_items.push(ListItem::new(Line::from(vec![
                    Span::styled(
                        " ✗ ",
                        Style::default()
                            .fg(Color::Red)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(short_name, Style::default().fg(Color::DarkGray)),
                ])));
            }

            // 5. Engine Transaction-level progress entries (single row per transaction)
            for txn in app.engine.transactions().active.values() {
                if txn.state != TransactionState::Active && txn.state != TransactionState::Pending {
                    continue;
                }
                let (transferred, total) = txn.progress_chunks();
                let bar = self.progress_bar.render(transferred, total, Color::Magenta);
                let short_name = truncate_filename(&txn.display_name, 20);

                let arrow = match txn.direction {
                    TransactionDirection::Outbound => " -> ",
                    TransactionDirection::Inbound => " <- ",
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

            // 6. Legacy transaction entries (backward compat — from app.transactions)
            for txn in app.transactions.active.values() {
                if txn.state != TransactionState::Active && txn.state != TransactionState::Pending {
                    continue;
                }
                let (transferred, total) = txn.progress_chunks();
                let bar = self.progress_bar.render(transferred, total, Color::Magenta);
                let short_name = truncate_filename(&txn.display_name, 20);

                let arrow = match txn.direction {
                    TransactionDirection::Outbound => " -> ",
                    TransactionDirection::Inbound => " <- ",
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
            for txn in app.transactions.rejected() {
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

        // File list — Engine transfer_history first, then legacy file_history
        let engine_history = app.engine.transfer_history();
        let legacy_len = app.file_history.len();
        let entries_total = engine_history.len() + legacy_len;
        let visible_height = chunks[2].height.saturating_sub(2) as usize;
        let max_scroll = entries_total.saturating_sub(visible_height);
        let scroll = app.history_scroll.min(max_scroll);

        // Build combined items: engine TransferRecords first (newest on top), then legacy
        let mut items: Vec<ListItem> = Vec::new();

        // Engine transfer history (one row per Transaction)
        for rec in engine_history.iter().rev().skip(scroll).take(visible_height) {
            let (arrow, color) = match rec.direction {
                TransactionDirection::Outbound => ("->", Color::Green),
                TransactionDirection::Inbound => ("<-", Color::Cyan),
            };
            let time_str = format!("{} ago", format_elapsed(rec.timestamp));
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
                    format!("  {}", time_str),
                    Style::default().fg(Color::Indexed(240)),
                ),
            ])));
        }

        // Legacy file_history entries
        let remaining = visible_height.saturating_sub(items.len());
        let legacy_skip = scroll.saturating_sub(engine_history.len());
        let legacy_items: Vec<ListItem> = app
            .file_history
            .iter()
            .rev()
            .skip(legacy_skip)
            .take(remaining)
            .map(|rec| {
                let (arrow, color) = match rec.direction {
                    FileDirection::Sent => ("->", Color::Green),
                    FileDirection::Received => ("<-", Color::Cyan),
                };

                let time_str = format!("{} ago", format_elapsed(rec.timestamp));

                let path_info = rec
                    .path
                    .as_ref()
                    .map(|p| format!(" -> {}", p))
                    .unwrap_or_default();

                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!(" {} ", arrow),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(&rec.filename, Style::default().fg(Color::White)),
                    Span::styled(
                        format!(" ({})", format_file_size(rec.filesize)),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!("  {}", get_display_name(app, &rec.peer_id)),
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::styled(path_info, Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("  {}", time_str),
                        Style::default().fg(Color::Indexed(240)),
                    ),
                ]))
            })
            .collect();
        items.extend(legacy_items);

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
            KeyCode::Enter => {
                let (filename, path, direction) = {
                    let files = app.filtered_file_history();
                    if let Some(record) = files.get(app.history_scroll) {
                        (
                            record.filename.clone(),
                            record.path.clone(),
                            record.direction,
                        )
                    } else {
                        return Some(Action::None);
                    }
                };

                match direction {
                    FileDirection::Received => {
                        if let Some(path) = path {
                            let _ = opener::open(path);
                            Some(Action::SetStatus(format!("Opening {}", filename)))
                        } else {
                            Some(Action::SetStatus("No local path for this file".to_string()))
                        }
                    }
                    FileDirection::Sent => {
                        Some(Action::SetStatus("Cannot open sent file".to_string()))
                    }
                }
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
