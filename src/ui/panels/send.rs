use crate::core::initializer::PeerNode;
use crate::core::transaction::{TransactionDirection, TransactionState};
use crate::ui::helpers::{direction_style, format_file_size, get_display_name, truncate_filename};
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

pub struct SendPanel {
    progress_bar: ProgressBar,
}

impl Default for SendPanel {
    fn default() -> Self {
        Self::new()
    }
}

impl SendPanel {
    pub fn new() -> Self {
        Self {
            progress_bar: ProgressBar::new(20),
        }
    }
}

impl Component for SendPanel {
    fn on_focus(&mut self, app: &mut App, node: &PeerNode) {
        // Check liveness of the currently selected peer when entering the send panel
        if let Some(peer_id) = app.selected_peer().cloned() {
            if app.is_peer_online(&peer_id) {
                let node = node.clone();
                let pid = peer_id.clone();
                tokio::spawn(async move {
                    if let Err(e) = node.check_peer_liveness(&pid).await {
                        tracing::debug!(
                            event = "send_panel_liveness_check_failed",
                            peer = %pid,
                            error = %e,
                            "Peer failed liveness check on send panel focus"
                        );
                    }
                });
            }
        }
    }

    fn render(&mut self, f: &mut Frame, app: &App, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(22), Constraint::Min(1)])
            .split(area);

        // Left panel: peer list
        let peer_items: Vec<ListItem> = app
            .state.peers.list
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let is_selected = i == app.state.peers.selected_idx;
                let line = Line::from(vec![
                    Span::styled(
                        if is_selected { " > " } else { "   " },
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::styled(
                        get_display_name(app, p),
                        if is_selected {
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(Color::Gray)
                        },
                    ),
                ]);
                ListItem::new(line)
            })
            .collect();

        let peer_list = List::new(peer_items).block(
            Block::default()
                .title(format!(" Peers ({}) ", app.state.peers.list.len()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        );
        f.render_widget(peer_list, chunks[0]);

        // Right panel: file path input + progress
        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(1)])
            .split(chunks[1]);

        // File path input
        let file_text = format!("{}_", app.state.transfer.send_file_path);
        let file_widget = Paragraph::new(file_text)
            .block(
                Block::default()
                    .title(" File/Folder Path ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(app.state.settings.theme.accent())),
            )
            .style(Style::default().fg(Color::White));
        f.render_widget(file_widget, right_chunks[0]);

        // Active transfers / progress — Transaction-level only.
        // One progress row per Transaction, never per individual file.
        let mut progress_items: Vec<ListItem> = Vec::new();

        // Transaction-level progress (from engine — authoritative)
        for txn in app.engine.transactions().active.values() {
            // Show Active and Pending transactions
            if txn.state.is_terminal() {
                continue;
            }
            let (transferred, total) = txn.progress_chunks();

            let (bar_color, state_info) = match txn.state {
                TransactionState::Pending => (Color::Yellow, " [waiting]"),
                TransactionState::Interrupted => (Color::Red, " [interrupted]"),
                _ => (Color::Magenta, ""),
            };

            let bar = self.progress_bar.render(transferred, total, bar_color);
            let short_name = truncate_filename(&txn.display_name, 20);

            let (_, arrow_color) = direction_style(txn.direction);
            let arrow = match txn.direction {
                TransactionDirection::Outbound => " -> ",
                TransactionDirection::Inbound => " <- ",
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
                Span::styled(state_info, Style::default().fg(Color::Yellow)),
            ])));
        }

        let progress_list = List::new(progress_items).block(
            Block::default()
                .title(" Active Transfers ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(progress_list, right_chunks[1]);
    }

    fn on_blur(&mut self, app: &mut App) {
        app.state.transfer.send_file_path.clear();
    }
}

impl Handler for SendPanel {
    fn handle_key(&mut self, app: &mut App, node: &PeerNode, key: KeyCode) -> Option<Action> {
        match key {
            KeyCode::Esc => {
                app.state.transfer.send_file_path.clear();
                Some(Action::SwitchMode(Mode::Home))
            }
            KeyCode::Up => {
                if !app.state.peers.list.is_empty() {
                    if app.state.peers.selected_idx == 0 {
                        app.state.peers.selected_idx = app.state.peers.list.len() - 1;
                    } else {
                        app.state.peers.selected_idx -= 1;
                    }
                }
                Some(Action::None)
            }
            KeyCode::Down => {
                if !app.state.peers.list.is_empty() {
                    app.state.peers.selected_idx = (app.state.peers.selected_idx + 1) % app.state.peers.list.len();
                }
                Some(Action::None)
            }
            KeyCode::Tab => {
                if !app.state.peers.list.is_empty() {
                    app.state.peers.selected_idx = (app.state.peers.selected_idx + 1) % app.state.peers.list.len();
                }
                Some(Action::None)
            }
            KeyCode::Enter => {
                if app.state.transfer.send_file_path.is_empty() {
                    return Some(Action::SetStatus(
                        "Enter a file/folder path first".to_string(),
                    ));
                }

                if let Some(peer_id) = app.selected_peer().cloned() {
                    // Verify peer is actually connected before initiating transfer
                    let peer_id_for_check = peer_id.clone();
                    let is_connected = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(async {
                            node.is_peer_connected(&peer_id_for_check).await
                        })
                    });
                    
                    if !is_connected {
                        return Some(Action::SetStatus(
                            format!("Peer {} is not connected", get_display_name(app, &peer_id))
                        ));
                    }
                    // Clean up the path: trim whitespace and strip surrounding quotes
                    let path = app.state.transfer.send_file_path.trim().to_string();
                    let path = path
                        .strip_prefix('"')
                        .and_then(|p| p.strip_suffix('"'))
                        .or_else(|| path.strip_prefix('\'').and_then(|p| p.strip_suffix('\'')))
                        .unwrap_or(&path)
                        .to_string();

                    let is_dir = std::fs::metadata(&path)
                        .map(|m| m.is_dir())
                        .unwrap_or(false);

                    if is_dir {
                        let dirname = std::path::Path::new(&path)
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| path.clone());

                        app.state.transfer.send_file_path.clear();

                        // Collect files synchronously for engine
                        let root = std::path::Path::new(&path).to_path_buf();
                        let mut files_data = Vec::new();
                        let mut total_size: u64 = 0;

                        fn collect_files_sync(
                            root: &std::path::Path,
                            current: &std::path::Path,
                            files: &mut Vec<(String, u64)>,
                            total: &mut u64,
                        ) {
                            if let Ok(entries) = std::fs::read_dir(current) {
                                for entry in entries.flatten() {
                                    if let Ok(ft) = entry.file_type() {
                                        if ft.is_symlink() {
                                            continue;
                                        }
                                        let p = entry.path();
                                        if ft.is_dir() {
                                            collect_files_sync(root, &p, files, total);
                                        } else if ft.is_file() {
                                            if let Ok(meta) = std::fs::metadata(&p) {
                                                let size = meta.len();
                                                *total += size;
                                                let relative = p
                                                    .strip_prefix(root)
                                                    .unwrap_or(&p)
                                                    .to_string_lossy()
                                                    .replace('\\', "/");
                                                files.push((relative, size));
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        collect_files_sync(&root, &root, &mut files_data, &mut total_size);

                        if files_data.is_empty() {
                            return Some(Action::SetStatus("Folder is empty".to_string()));
                        }

                        // Delegate to TransferEngine — no transfer logic in UI
                        match app
                            .engine
                            .initiate_folder_send(&peer_id, &dirname, files_data, &path)
                        {
                            Ok(outcome) => {
                                let status = outcome
                                    .status
                                    .unwrap_or_else(|| format!("Sending folder {}...", dirname));
                                // Return engine actions for async execution by UIExecuter
                                if outcome.actions.is_empty() {
                                    Some(Action::SetStatus(status))
                                } else {
                                    // Return both status and actions — executer will handle
                                    app.set_status(status);
                                    Some(Action::EngineActions(outcome.actions))
                                }
                            }
                            Err(e) => Some(Action::SetStatus(format!("Error: {}", e))),
                        }
                    } else {
                        let filename = std::path::Path::new(&path)
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| path.clone());
                        let filesize = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

                        // Delegate to TransferEngine — no transfer logic in UI
                        match app
                            .engine
                            .initiate_file_send(&peer_id, &filename, filesize, &path)
                        {
                            Ok(outcome) => {
                                app.state.transfer.send_file_path.clear();
                                let status = outcome
                                    .status
                                    .unwrap_or_else(|| format!("Sending {}...", filename));
                                // Return engine actions for async execution by UIExecuter
                                if outcome.actions.is_empty() {
                                    Some(Action::SetStatus(status))
                                } else {
                                    app.set_status(status);
                                    Some(Action::EngineActions(outcome.actions))
                                }
                            }
                            Err(e) => Some(Action::SetStatus(format!("Error: {}", e))),
                        }
                    }
                } else {
                    Some(Action::SetStatus("No peer selected".to_string()))
                }
            }
            KeyCode::Backspace => {
                app.state.transfer.send_file_path.pop();
                Some(Action::None)
            }
            KeyCode::Char(c) => {
                app.state.transfer.send_file_path.push(c);
                Some(Action::None)
            }
            _ => Some(Action::None),
        }
    }
}
