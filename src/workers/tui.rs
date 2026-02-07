use crate::app::Args;
use crate::core::initializer::{AppEvent, PeerNode};
use crate::utils::clipboard::copy_to_clipboard;
use crate::utils::hash::get_or_create_secret;
use crate::utils::log_buffer::LogBuffer;
use crate::utils::sos::SignalOfStop;
use crate::workers::app::{
    AcceptingFileOffer, AcceptingFolderOffer, App, ChatMessage, FileDirection, FileRecord, Mode,
    PendingFileOffer, PendingFolderOffer,
};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use std::io::stdout;
use std::time::Instant;
use tokio::sync::mpsc;

pub async fn run(args: Args, sos: SignalOfStop, log_buffer: LogBuffer) -> anyhow::Result<()> {
    // Acquire secret key with per-instance locking
    let (secret_key, _instance_guard) = get_or_create_secret(args.secret_file.as_deref())?;

    if args.show_secret {
        let secret_hex = hex::encode(secret_key.to_bytes());
        eprintln!("Using secret key: {secret_hex}");
    }

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<AppEvent>();

    let node = PeerNode::new(secret_key, args, sos.clone(), event_tx).await?;

    let ticket = node.ticket()?;
    // Print ticket to stderr before TUI takes the terminal
    eprintln!("Your ticket: {ticket}");

    // Spawn accept loop
    let node_clone = node.clone();
    tokio::spawn(async move {
        node_clone.run_accept_loop().await;
    });

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    // Drain any queued events
    while event::poll(std::time::Duration::from_millis(0))? {
        let _ = event::read()?;
    }

    let mut app = App::new(ticket);
    let mut list_state = ListState::default();
    list_state.select(Some(0));

    let should_quit = loop {
        // Render
        terminal.draw(|f| render(f, &mut app, &mut list_state, &log_buffer))?;

        // Poll crossterm events with 50ms timeout
        if event::poll(std::time::Duration::from_millis(50))?
            && let Event::Key(key) = event::read()?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if handle_key(&mut app, &mut list_state, &node, &log_buffer, key.code).await {
                break true;
            }
        }

        // Drain AppEvent channel
        while let Ok(ev) = event_rx.try_recv() {
            handle_app_event(&mut app, ev);
        }

        if sos.cancelled() {
            break true;
        }
    };

    // Cleanup terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if should_quit {
        sos.cancel();
    }

    Ok(())
}

fn render(f: &mut Frame, app: &mut App, list_state: &mut ListState, log_buffer: &LogBuffer) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(1),   // main
            Constraint::Length(3), // stats bar
        ])
        .split(f.area());

    // Header
    let peer_count = app.peers.len();
    let header_text = format!(
        " Crossdrop v0.3 - {} | Peers: {} ",
        app.mode.label(),
        peer_count
    );
    let header = Paragraph::new(header_text)
        .style(
            Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::NONE));
    f.render_widget(header, chunks[0]);

    // Main content
    match app.mode {
        Mode::Home => render_home(f, app, list_state, log_buffer, chunks[1]),
        Mode::Chat => render_chat(f, app, chunks[1]),
        Mode::Send => render_send(f, app, chunks[1]),
        Mode::Connect => render_connect(f, app, chunks[1]),
        Mode::Peers => render_peers(f, app, list_state, chunks[1]),
        Mode::Files => render_files(f, app, chunks[1]),
        Mode::Logs => render_logs(f, app, log_buffer, chunks[1]),
        Mode::Id => render_id(f, app, chunks[1]),
    }

    // Popup overlay priority: accepting_file > accepting_folder > pending_folder_offers > pending_offers
    if app.accepting_file.is_some() {
        render_save_path_popup(f, app);
    } else if app.accepting_folder.is_some() {
        render_folder_save_path_popup(f, app);
    } else if !app.pending_folder_offers.is_empty() {
        render_folder_offer_notification(f, app);
    } else if !app.pending_offers.is_empty() {
        render_file_offer_notification(f, app);
    }

    // Stats bar at the bottom
    render_stats_bar(f, app, chunks[2]);
}

fn render_stats_bar(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(2)])
        .split(area);

    // Help line
    let help = match app.mode {
        Mode::Home => "Up/Down: navigate | Enter: select | c: copy ticket | Esc: quit",
        Mode::Chat => "Enter: send | Tab: switch peer | Esc: back",
        Mode::Send => "Enter: send file/folder | Tab/Up/Down: peer | Esc: back",
        Mode::Connect => "Enter: connect | Esc: back",
        Mode::Peers => "Up/Down: navigate | Esc: back",
        Mode::Files => "Esc: back",
        Mode::Logs => "Up/Down: scroll | d: clear | Esc: back",
        Mode::Id => "c: copy to clipboard | Esc: back",
    };

    let help_line = if app.status.is_empty() {
        Paragraph::new(help).style(Style::default().fg(Color::DarkGray))
    } else {
        Paragraph::new(app.status.as_str()).style(Style::default().fg(Color::Yellow))
    };
    f.render_widget(help_line, chunks[0]);

    // Stats line
    let stats = &app.stats;
    let stats_spans = vec![
        Span::styled(" TX: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format_file_size(stats.bytes_sent),
            Style::default().fg(Color::Green),
        ),
        Span::styled(
            format!(" ({} msgs, {} files)", stats.messages_sent, stats.files_sent),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled("  |  RX: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format_file_size(stats.bytes_received),
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(
            format!(
                " ({} msgs, {} files)",
                stats.messages_received, stats.files_received
            ),
            Style::default().fg(Color::DarkGray),
        ),
    ];
    let stats_line = Paragraph::new(Line::from(stats_spans))
        .style(Style::default().bg(Color::Black));
    f.render_widget(stats_line, chunks[1]);
}

fn render_home(f: &mut Frame, app: &App, list_state: &mut ListState, log_buffer: &LogBuffer, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)])
        .split(area);

    // Ticket display
    let ticket_short = if app.ticket.len() > 60 {
        format!("{}...", &app.ticket[..60])
    } else {
        app.ticket.clone()
    };
    let ticket_widget = Paragraph::new(format!(" {}", ticket_short))
        .block(
            Block::default()
                .title(" Your Ticket ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        )
        .style(Style::default().fg(Color::Green));
    f.render_widget(ticket_widget, chunks[0]);

    // Menu
    let items: Vec<ListItem> = app
        .menu_items
        .iter()
        .map(|m| {
            let (icon, suffix) = match m {
                Mode::Chat => (">>", format!(" ({})", app.chat_history.len())),
                Mode::Send => ("->", String::new()),
                Mode::Connect => ("<>", String::new()),
                Mode::Peers => ("@@", format!(" ({})", app.peers.len())),
                Mode::Files => ("[]", format!(" ({})", app.file_history.len())),
                Mode::Logs => ("!!", format!(" ({})", log_buffer.len())),
                Mode::Id => ("##", String::new()),
                _ => ("  ", String::new()),
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {}  ", icon),
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw(m.label()),
                Span::styled(suffix, Style::default().fg(Color::DarkGray)),
            ]))
        })
        .collect();

    let menu = List::new(items)
        .block(
            Block::default()
                .title(" Menu ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Indexed(236))
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("  > ");

    f.render_stateful_widget(menu, chunks[1], list_state);
}

fn render_chat(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(22), Constraint::Min(1)])
        .split(area);

    // Peer list (left panel) - prettier with status indicators
    let peer_items: Vec<ListItem> = app
        .peers
        .iter()
        .map(|p| {
            let is_selected = app.chat_peer.as_deref() == Some(p);
            let msg_count = app.unread_count_for(p);
            let badge = if msg_count > 0 {
                format!(" ({})", msg_count)
            } else {
                String::new()
            };

            let line = Line::from(vec![
                Span::styled(
                    if is_selected { " * " } else { "   " },
                    Style::default().fg(Color::Green),
                ),
                Span::styled(
                    short_peer_id(p),
                    if is_selected {
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    },
                ),
                Span::styled(badge, Style::default().fg(Color::Yellow)),
            ]);
            ListItem::new(line)
        })
        .collect();

    let peer_list = List::new(peer_items).block(
        Block::default()
            .title(" Peers ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(peer_list, chunks[0]);

    // Chat area (right panel)
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(chunks[1]);

    // Messages
    let peer_label = app
        .chat_peer
        .as_ref()
        .map(|p| short_peer_id(p))
        .unwrap_or_else(|| "no peer selected".to_string());

    let messages: Vec<Line> = app
        .chat_history
        .iter()
        .filter(|m| {
            app.chat_peer.as_deref() == Some(&m.peer_id)
        })
        .map(|m| {
            let elapsed = m.timestamp.elapsed().as_secs();
            let time_str = if elapsed < 60 {
                format!("{}s", elapsed)
            } else if elapsed < 3600 {
                format!("{}m", elapsed / 60)
            } else {
                format!("{}h", elapsed / 3600)
            };

            if m.from_me {
                Line::from(vec![
                    Span::styled(
                        format!("[{}] ", time_str),
                        Style::default().fg(Color::Indexed(240)),
                    ),
                    Span::styled("You ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
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
                        format!("{} ", short_peer_id(&m.peer_id)),
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("> ", Style::default().fg(Color::DarkGray)),
                    Span::raw(&m.text),
                ])
            }
        })
        .collect();

    // Auto-scroll: if messages exceed visible area, only show the last N lines
    let visible_height = right_chunks[0].height.saturating_sub(2) as usize; // subtract borders
    let total_messages = messages.len();
    let scroll_offset = if total_messages > visible_height {
        (total_messages - visible_height) as u16
    } else {
        0
    };

    let title_style = if app.chat_peer.is_some() {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let msg_widget = Paragraph::new(messages)
        .block(
            Block::default()
                .title(format!(" Chat with {} ", peer_label))
                .title_style(title_style)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .wrap(Wrap { trim: false })
        .scroll((scroll_offset, 0));
    f.render_widget(msg_widget, right_chunks[0]);

    // Input field with cursor indicator
    let input_text = format!("{}_", app.input);
    let input_widget = Paragraph::new(input_text)
        .block(
            Block::default()
                .title(" Message ")
                .borders(Borders::ALL)
                .border_style(
                    if app.chat_peer.is_some() {
                        Style::default().fg(Color::Cyan)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    },
                ),
        )
        .style(Style::default().fg(Color::White));
    f.render_widget(input_widget, right_chunks[1]);
}

fn render_send(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(22), Constraint::Min(1)])
        .split(area);

    // Left panel: peer list (like Chat mode)
    let peer_items: Vec<ListItem> = app
        .peers
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let is_selected = i == app.selected_peer_idx;
            let line = Line::from(vec![
                Span::styled(
                    if is_selected { " > " } else { "   " },
                    Style::default().fg(Color::Yellow),
                ),
                Span::styled(
                    short_peer_id(p),
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
            .title(format!(" Peers ({}) ", app.peers.len()))
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
    let file_text = format!("{}_", app.send_file_path);
    let file_widget = Paragraph::new(file_text)
        .block(
            Block::default()
                .title(" File/Folder Path ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .style(Style::default().fg(Color::White));
    f.render_widget(file_widget, right_chunks[0]);

    // Active transfers / progress (both sending and receiving)
    let mut progress_items: Vec<ListItem> = Vec::new();

    for (filename, sent, total) in app.send_progress.values() {
        let pct = if *total > 0 {
            (*sent as f64 / *total as f64 * 100.0) as u16
        } else {
            0
        };
        let bar_width = 20;
        let filled = (bar_width as f64 * pct as f64 / 100.0) as usize;
        let empty = bar_width - filled;
        let bar = format!("[{}{}] {}%", "#".repeat(filled), "-".repeat(empty), pct);
        let short_name = truncate_filename(filename, 20);

        progress_items.push(ListItem::new(Line::from(vec![
            Span::styled(" -> ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::styled(short_name, Style::default().fg(Color::White)),
            Span::raw(" "),
            Span::styled(bar, Style::default().fg(if pct >= 100 { Color::Green } else { Color::Cyan })),
            Span::styled(format!(" ({}/{})", sent, total), Style::default().fg(Color::DarkGray)),
        ])));
    }

    for (filename, recv, total) in app.file_progress.values() {
        let pct = if *total > 0 {
            (*recv as f64 / *total as f64 * 100.0) as u16
        } else {
            0
        };
        let bar_width = 20;
        let filled = (bar_width as f64 * pct as f64 / 100.0) as usize;
        let empty = bar_width - filled;
        let bar = format!("[{}{}] {}%", "#".repeat(filled), "-".repeat(empty), pct);
        let short_name = truncate_filename(filename, 20);

        progress_items.push(ListItem::new(Line::from(vec![
            Span::styled(" <- ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled(short_name, Style::default().fg(Color::White)),
            Span::raw(" "),
            Span::styled(bar, Style::default().fg(if pct >= 100 { Color::Green } else { Color::Cyan })),
            Span::styled(format!(" ({}/{})", recv, total), Style::default().fg(Color::DarkGray)),
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

fn render_connect(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(area);

    let help = Paragraph::new(" Paste a peer's ticket and press Enter to connect.")
        .block(Block::default().borders(Borders::NONE))
        .style(Style::default().fg(Color::Gray));
    f.render_widget(help, chunks[0]);

    let input_text = format!("{}_", app.connect_ticket_input);
    let input_widget = Paragraph::new(input_text)
        .block(
            Block::default()
                .title(" Peer Ticket ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .style(Style::default().fg(Color::White));
    f.render_widget(input_widget, chunks[1]);
}

fn render_peers(f: &mut Frame, app: &App, _list_state: &mut ListState, area: Rect) {
    let items: Vec<ListItem> = app
        .peers
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let is_selected = i == app.selected_peer_idx;
            ListItem::new(Line::from(vec![
                Span::styled(
                    if is_selected { " > " } else { "   " },
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled(
                    p.as_str(),
                    if is_selected {
                        Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Gray)
                    },
                ),
            ]))
        })
        .collect();

    let peer_list = List::new(items).block(
        Block::default()
            .title(format!(" Connected Peers ({}) ", app.peers.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );

    let mut peers_list_state = ListState::default();
    if !app.peers.is_empty() {
        peers_list_state.select(Some(app.selected_peer_idx));
    }
    f.render_stateful_widget(peer_list, area, &mut peers_list_state);
}

fn render_files(f: &mut Frame, app: &App, area: Rect) {
    let has_active = !app.send_progress.is_empty() || !app.file_progress.is_empty();

    let chunks = if has_active {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(2 + app.send_progress.len().max(1) as u16 + app.file_progress.len() as u16),
                Constraint::Min(1),
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Length(0), Constraint::Min(1)])
            .split(area)
    };

    // Summary header
    let sent_count = app
        .file_history
        .iter()
        .filter(|f| f.direction == FileDirection::Sent)
        .count();
    let recv_count = app
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

        for (filename, sent, total) in app.send_progress.values() {
            let pct = if *total > 0 {
                (*sent as f64 / *total as f64 * 100.0) as u16
            } else {
                0
            };
            let bar_width = 20;
            let filled = (bar_width as f64 * pct as f64 / 100.0) as usize;
            let empty = bar_width - filled;
            let bar = format!("[{}{}] {}%", "#".repeat(filled), "-".repeat(empty), pct);
            let short_name = truncate_filename(filename, 20);

            progress_items.push(ListItem::new(Line::from(vec![
                Span::styled(" -> ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Span::styled(short_name, Style::default().fg(Color::White)),
                Span::raw(" "),
                Span::styled(bar, Style::default().fg(Color::Cyan)),
            ])));
        }

        for (filename, recv, total) in app.file_progress.values() {
            let pct = if *total > 0 {
                (*recv as f64 / *total as f64 * 100.0) as u16
            } else {
                0
            };
            let bar_width = 20;
            let filled = (bar_width as f64 * pct as f64 / 100.0) as usize;
            let empty = bar_width - filled;
            let bar = format!("[{}{}] {}%", "#".repeat(filled), "-".repeat(empty), pct);
            let short_name = truncate_filename(filename, 20);

            progress_items.push(ListItem::new(Line::from(vec![
                Span::styled(" <- ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled(short_name, Style::default().fg(Color::White)),
                Span::raw(" "),
                Span::styled(bar, Style::default().fg(Color::Cyan)),
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

    // File list
    let items: Vec<ListItem> = app
        .file_history
        .iter()
        .rev()
        .map(|rec| {
            let (arrow, color) = match rec.direction {
                FileDirection::Sent => ("->", Color::Green),
                FileDirection::Received => ("<-", Color::Cyan),
            };

            let elapsed = rec.timestamp.elapsed().as_secs();
            let time_str = if elapsed < 60 {
                format!("{}s ago", elapsed)
            } else if elapsed < 3600 {
                format!("{}m ago", elapsed / 60)
            } else {
                format!("{}h ago", elapsed / 3600)
            };

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
                    format!("  {}", short_peer_id(&rec.peer_id)),
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

    let file_list = List::new(items).block(
        Block::default()
            .title(" Transfer History ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(file_list, chunks[2]);
}

fn render_id(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(area);

    let ticket_widget = Paragraph::new(app.ticket.as_str())
        .block(
            Block::default()
                .title(" Your Full Ticket ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        )
        .wrap(Wrap { trim: false })
        .style(Style::default().fg(Color::Green));
    f.render_widget(ticket_widget, chunks[0]);

    let hint = Paragraph::new(Line::from(vec![
        Span::raw("  Press "),
        Span::styled(
            " c ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" to copy ticket to clipboard"),
    ]))
    .block(Block::default().borders(Borders::NONE));
    f.render_widget(hint, chunks[1]);
}

fn render_logs(f: &mut Frame, app: &App, log_buffer: &LogBuffer, area: Rect) {
    let entries = log_buffer.entries();
    let total = entries.len();

    let visible_height = area.height.saturating_sub(2) as usize; // subtract borders

    // Clamp scroll offset
    let max_scroll = total.saturating_sub(visible_height);
    let scroll = app.log_scroll.min(max_scroll);

    let items: Vec<ListItem> = entries
        .iter()
        .skip(scroll)
        .take(visible_height)
        .map(|entry| {
            let level_color = match entry.level {
                tracing::Level::ERROR => Color::Red,
                tracing::Level::WARN => Color::Yellow,
                tracing::Level::INFO => Color::Green,
                tracing::Level::DEBUG => Color::DarkGray,
                tracing::Level::TRACE => Color::Indexed(240),
            };
            let level_str = match entry.level {
                tracing::Level::ERROR => "ERROR",
                tracing::Level::WARN => " WARN",
                tracing::Level::INFO => " INFO",
                tracing::Level::DEBUG => "DEBUG",
                tracing::Level::TRACE => "TRACE",
            };

            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {} ", entry.timestamp),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("{} ", level_str),
                    Style::default().fg(level_color).add_modifier(Modifier::BOLD),
                ),
                Span::raw(&entry.message),
            ]))
        })
        .collect();

    let title = format!(" Logs ({}) ", total);
    let log_list = List::new(items).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    f.render_widget(log_list, area);
}

fn render_file_offer_notification(f: &mut Frame, app: &App) {
    if let Some(offer) = app.pending_offers.first() {
        let area = f.area();
        let popup_area = Rect {
            x: area.width / 4,
            y: area.height / 3,
            width: area.width / 2,
            height: 7,
        };

        let size_str = format_file_size(offer.filesize);
        let text = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  From: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    short_peer_id(&offer.peer_id),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::styled("  File: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    &offer.filename,
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!(" ({})", size_str), Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    " y ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" accept    "),
                Span::styled(
                    " n ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Red)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" reject"),
            ]),
        ];

        let popup = Paragraph::new(text)
            .block(
                Block::default()
                    .title(" File Offer ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow)),
            )
            .wrap(Wrap { trim: false });

        // Clear background
        f.render_widget(ratatui::widgets::Clear, popup_area);
        f.render_widget(popup, popup_area);
    }
}

fn render_folder_offer_notification(f: &mut Frame, app: &App) {
    if let Some(offer) = app.pending_folder_offers.first() {
        let area = f.area();
        let popup_area = Rect {
            x: area.width / 4,
            y: area.height / 3,
            width: area.width / 2,
            height: 8,
        };

        let size_str = format_file_size(offer.total_size);
        let text = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  From: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    short_peer_id(&offer.peer_id),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Folder: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    &offer.dirname,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    format!("{} files, {}", offer.file_count, size_str),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    " y ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" accept    "),
                Span::styled(
                    " n ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Red)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" reject"),
            ]),
        ];

        let popup = Paragraph::new(text)
            .block(
                Block::default()
                    .title(" Folder Offer ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Magenta)),
            )
            .wrap(Wrap { trim: false });

        // Clear background
        f.render_widget(ratatui::widgets::Clear, popup_area);
        f.render_widget(popup, popup_area);
    }
}

fn render_save_path_popup(f: &mut Frame, app: &App) {
    if let Some(af) = &app.accepting_file {
        let area = f.area();
        let popup_area = Rect {
            x: area.width / 6,
            y: area.height / 3,
            width: area.width * 2 / 3,
            height: 9,
        };

        let size_str = format_file_size(af.filesize);
        let path_display = format!("{}|", af.save_path_input);
        let text = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  From: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    short_peer_id(&af.peer_id),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::styled("  File: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    &af.filename,
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!(" ({})", size_str), Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(vec![
                Span::styled("  Save to: ", Style::default().fg(Color::DarkGray)),
                Span::styled(path_display, Style::default().fg(Color::Cyan)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    " Enter ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" save    "),
                Span::styled(
                    " Esc ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Red)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" reject"),
            ]),
        ];

        let popup = Paragraph::new(text)
            .block(
                Block::default()
                    .title(" Save File As ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Green)),
            )
            .wrap(Wrap { trim: false });

        f.render_widget(ratatui::widgets::Clear, popup_area);
        f.render_widget(popup, popup_area);
    }
}

fn render_folder_save_path_popup(f: &mut Frame, app: &App) {
    if let Some(af) = &app.accepting_folder {
        let area = f.area();
        let popup_area = Rect {
            x: area.width / 6,
            y: area.height / 3,
            width: area.width * 2 / 3,
            height: 10,
        };

        let size_str = format_file_size(af.total_size);
        let path_display = format!("{}|", af.save_path_input);
        let text = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  From: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    short_peer_id(&af.peer_id),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Folder: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    &af.dirname,
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    format!("{} files, {}", af.file_count, size_str),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Save to: ", Style::default().fg(Color::DarkGray)),
                Span::styled(path_display, Style::default().fg(Color::Cyan)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    " Enter ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" save    "),
                Span::styled(
                    " Esc ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Red)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" reject"),
            ]),
        ];

        let popup = Paragraph::new(text)
            .block(
                Block::default()
                    .title(" Save Folder To ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Magenta)),
            )
            .wrap(Wrap { trim: false });

        f.render_widget(ratatui::widgets::Clear, popup_area);
        f.render_widget(popup, popup_area);
    }
}

/// Handle keyboard input. Returns true if the app should quit.
async fn handle_key(
    app: &mut App,
    list_state: &mut ListState,
    node: &PeerNode,
    log_buffer: &LogBuffer,
    key: KeyCode,
) -> bool {
    // Save-path input for accepting a file offer
    if app.accepting_file.is_some() {
        match key {
            KeyCode::Enter => {
                let af = app.accepting_file.take().unwrap();
                let dest_path = af.save_path_input.clone();
                app.set_status(format!(
                    "Accepted file: {} -> saving to {}/",
                    af.filename, dest_path
                ));
                let node = node.clone();
                tokio::spawn(async move {
                    let _ = node
                        .respond_to_file_offer(&af.peer_id, af.file_id, true, Some(dest_path))
                        .await;
                });
                return false;
            }
            KeyCode::Esc => {
                let af = app.accepting_file.take().unwrap();
                let node = node.clone();
                tokio::spawn(async move {
                    let _ = node
                        .respond_to_file_offer(&af.peer_id, af.file_id, false, None)
                        .await;
                });
                app.set_status(format!("Rejected file: {}", af.filename));
                return false;
            }
            KeyCode::Backspace => {
                if let Some(af) = &mut app.accepting_file {
                    af.save_path_input.pop();
                }
                return false;
            }
            KeyCode::Char(c) => {
                if let Some(af) = &mut app.accepting_file {
                    af.save_path_input.push(c);
                }
                return false;
            }
            _ => return false,
        }
    }

    // Save-path input for accepting a folder offer
    if app.accepting_folder.is_some() {
        match key {
            KeyCode::Enter => {
                let af = app.accepting_folder.take().unwrap();
                let save_dir = af.save_path_input.clone();
                app.folder_progress.insert(af.folder_id, (0, af.file_count));
                app.set_status(format!(
                    "Accepted folder: {} ({} files) -> saving to {}/",
                    af.dirname, af.file_count, save_dir
                ));
                let node = node.clone();
                tokio::spawn(async move {
                    let _ = node
                        .respond_to_folder_offer(&af.peer_id, af.folder_id, true)
                        .await;
                });
                return false;
            }
            KeyCode::Esc => {
                let af = app.accepting_folder.take().unwrap();
                let node = node.clone();
                tokio::spawn(async move {
                    let _ = node
                        .respond_to_folder_offer(&af.peer_id, af.folder_id, false)
                        .await;
                });
                app.set_status(format!("Rejected folder: {}", af.dirname));
                return false;
            }
            KeyCode::Backspace => {
                if let Some(af) = &mut app.accepting_folder {
                    af.save_path_input.pop();
                }
                return false;
            }
            KeyCode::Char(c) => {
                if let Some(af) = &mut app.accepting_folder {
                    af.save_path_input.push(c);
                }
                return false;
            }
            _ => return false,
        }
    }

    // Folder offer prompt takes priority over file offers
    if !app.pending_folder_offers.is_empty() {
        match key {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                let offer = app.pending_folder_offers.remove(0);
                let save_dir = std::env::current_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| ".".to_string());
                app.accepting_folder = Some(AcceptingFolderOffer {
                    peer_id: offer.peer_id,
                    folder_id: offer.folder_id,
                    dirname: offer.dirname,
                    file_count: offer.file_count,
                    total_size: offer.total_size,
                    save_path_input: save_dir,
                });
                return false;
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                let offer = app.pending_folder_offers.remove(0);
                let node = node.clone();
                tokio::spawn(async move {
                    let _ = node
                        .respond_to_folder_offer(&offer.peer_id, offer.folder_id, false)
                        .await;
                });
                app.set_status(format!("Rejected folder: {}", offer.dirname));
                return false;
            }
            _ => return false,
        }
    }

    // File offer prompt takes priority
    if !app.pending_offers.is_empty() {
        match key {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                let offer = app.pending_offers.remove(0);
                let save_dir = std::env::current_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| ".".to_string());
                app.accepting_file = Some(AcceptingFileOffer {
                    peer_id: offer.peer_id,
                    file_id: offer.file_id,
                    filename: offer.filename,
                    filesize: offer.filesize,
                    save_path_input: save_dir,
                });
                return false;
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                let offer = app.pending_offers.remove(0);
                let node = node.clone();
                tokio::spawn(async move {
                    let _ = node
                        .respond_to_file_offer(&offer.peer_id, offer.file_id, false, None)
                        .await;
                });
                app.set_status(format!("Rejected file: {}", offer.filename));
                return false;
            }
            _ => return false,
        }
    }

    match app.mode {
        Mode::Home => match key {
            KeyCode::Esc => return true,
            KeyCode::Up => {
                let max = app.menu_items.len();
                let sel = list_state.selected().unwrap_or(0);
                let new_sel = if sel == 0 { max - 1 } else { sel - 1 };
                list_state.select(Some(new_sel));
                app.menu_selected = new_sel;
            }
            KeyCode::Down => {
                let max = app.menu_items.len();
                let sel = list_state.selected().unwrap_or(0);
                let new_sel = if sel + 1 >= max { 0 } else { sel + 1 };
                list_state.select(Some(new_sel));
                app.menu_selected = new_sel;
            }
            KeyCode::Enter => {
                if let Some(&mode) = app.menu_items.get(app.menu_selected) {
                    app.mode = mode;
                    app.status.clear();
                    // Auto-select first peer for chat if available
                    if mode == Mode::Chat && app.chat_peer.is_none() && !app.peers.is_empty() {
                        app.chat_peer = Some(app.peers[0].clone());
                    }
                }
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                if copy_to_clipboard(&app.ticket) {
                    app.set_status("Ticket copied to clipboard!");
                } else {
                    app.set_status("Failed to copy to clipboard");
                }
            }
            _ => {}
        },
        Mode::Chat => match key {
            KeyCode::Esc => {
                app.mode = Mode::Home;
                app.input.clear();
                app.status.clear();
            }
            KeyCode::Tab => {
                // Cycle through peers
                if !app.peers.is_empty() {
                    let current_idx = app
                        .chat_peer
                        .as_ref()
                        .and_then(|p| app.peers.iter().position(|x| x == p))
                        .unwrap_or(0);
                    let next_idx = (current_idx + 1) % app.peers.len();
                    app.chat_peer = Some(app.peers[next_idx].clone());
                }
            }
            KeyCode::Enter => {
                if !app.input.is_empty() {
                    if let Some(peer_id) = app.chat_peer.clone() {
                        let msg = app.input.clone();
                        let msg_len = msg.len() as u64;
                        app.chat_history.push(ChatMessage {
                            from_me: true,
                            peer_id: peer_id.clone(),
                            text: msg.clone(),
                            timestamp: Instant::now(),
                        });
                        app.input.clear();

                        // Update stats
                        app.stats.messages_sent += 1;
                        app.stats.bytes_sent += msg_len;

                        let node = node.clone();
                        tokio::spawn(async move {
                            if let Err(e) = node.send_chat(&peer_id, &msg).await {
                                tracing::error!("Failed to send chat: {e}");
                            }
                        });
                    } else {
                        app.set_status("No peer selected");
                    }
                }
            }
            KeyCode::Backspace => {
                app.input.pop();
            }
            KeyCode::Char(c) => {
                app.input.push(c);
            }
            _ => {}
        },
        Mode::Send => match key {
            KeyCode::Esc => {
                app.mode = Mode::Home;
                app.send_file_path.clear();
                app.status.clear();
            }
            KeyCode::Up => {
                if !app.peers.is_empty() {
                    if app.selected_peer_idx == 0 {
                        app.selected_peer_idx = app.peers.len() - 1;
                    } else {
                        app.selected_peer_idx -= 1;
                    }
                }
            }
            KeyCode::Down => {
                if !app.peers.is_empty() {
                    app.selected_peer_idx = (app.selected_peer_idx + 1) % app.peers.len();
                }
            }
            KeyCode::Tab => {
                if !app.peers.is_empty() {
                    app.selected_peer_idx = (app.selected_peer_idx + 1) % app.peers.len();
                }
            }
            KeyCode::Enter => {
                if app.send_file_path.is_empty() {
                    app.set_status("Enter a file/folder path first");
                } else if let Some(peer_id) = app.selected_peer().cloned() {
                    // Clean up the path: trim whitespace and strip surrounding quotes
                    let path = app.send_file_path.trim().to_string();
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

                        app.set_status(format!("Sending folder {}...", dirname));
                        app.send_file_path.clear();

                        let node = node.clone();
                        tokio::spawn(async move {
                            match node.offer_folder(&peer_id, &path).await {
                                Ok(true) => tracing::info!("Folder sent successfully"),
                                Ok(false) => tracing::info!("Folder offer rejected"),
                                Err(e) => tracing::error!("Folder send error: {e}"),
                            }
                        });
                    } else {
                        let filename = std::path::Path::new(&path)
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| path.clone());

                        // Attempt to get filesize for the record
                        let filesize = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

                        app.set_status(format!("Sending {}...", filename));

                        // Record the sent file
                        app.file_history.push(FileRecord {
                            direction: FileDirection::Sent,
                            peer_id: peer_id.clone(),
                            filename: filename.clone(),
                            filesize,
                            path: Some(path.clone()),
                            timestamp: Instant::now(),
                        });

                        // Update stats
                        app.stats.files_sent += 1;
                        app.stats.bytes_sent += filesize;

                        let node = node.clone();
                        tokio::spawn(async move {
                            match node.offer_file(&peer_id, &path).await {
                                Ok(true) => tracing::info!("File sent successfully"),
                                Ok(false) => tracing::info!("File offer rejected"),
                                Err(e) => tracing::error!("File send error: {e}"),
                            }
                        });
                        app.send_file_path.clear();
                    }
                } else {
                    app.set_status("No peer selected");
                }
            }
            KeyCode::Backspace => {
                app.send_file_path.pop();
            }
            KeyCode::Char(c) => {
                app.send_file_path.push(c);
            }
            _ => {}
        },
        Mode::Connect => match key {
            KeyCode::Esc => {
                app.mode = Mode::Home;
                app.connect_ticket_input.clear();
                app.status.clear();
            }
            KeyCode::Enter => {
                if !app.connect_ticket_input.is_empty() {
                    let ticket = app.connect_ticket_input.clone();
                    app.connect_ticket_input.clear();
                    app.set_status("Connecting...");
                    let node = node.clone();
                    let etx = node.event_tx().clone();
                    tokio::spawn(async move {
                        match node.connect_to(ticket).await {
                            Ok(()) => {
                                // PeerConnected event will set "Peer connected: <id>"
                            }
                            Err(e) => {
                                tracing::error!("Connection failed: {e}");
                                let _ = etx.send(AppEvent::Error(format!(
                                    "Failed connection: {e}"
                                )));
                            }
                        }
                    });
                }
            }
            KeyCode::Backspace => {
                app.connect_ticket_input.pop();
            }
            KeyCode::Char(c) => {
                app.connect_ticket_input.push(c);
            }
            _ => {}
        },
        Mode::Peers => match key {
            KeyCode::Esc => {
                app.mode = Mode::Home;
                app.status.clear();
            }
            KeyCode::Up => {
                if !app.peers.is_empty() {
                    if app.selected_peer_idx == 0 {
                        app.selected_peer_idx = app.peers.len() - 1;
                    } else {
                        app.selected_peer_idx -= 1;
                    }
                }
            }
            KeyCode::Down => {
                if !app.peers.is_empty() {
                    app.selected_peer_idx = (app.selected_peer_idx + 1) % app.peers.len();
                }
            }
            _ => {}
        },
        Mode::Files => {
            if key == KeyCode::Esc {
                app.mode = Mode::Home;
                app.status.clear();
            }
        }
        Mode::Logs => match key {
            KeyCode::Esc => {
                app.mode = Mode::Home;
                app.log_scroll = 0;
                app.status.clear();
            }
            KeyCode::Up => {
                app.log_scroll = app.log_scroll.saturating_sub(1);
            }
            KeyCode::Down => {
                app.log_scroll += 1;
            }
            KeyCode::Char('d') | KeyCode::Char('D') => {
                log_buffer.clear();
                app.log_scroll = 0;
                app.set_status("Logs cleared");
            }
            _ => {}
        },
        Mode::Id => match key {
            KeyCode::Esc => {
                app.mode = Mode::Home;
                app.status.clear();
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                if copy_to_clipboard(&app.ticket) {
                    app.set_status("Ticket copied to clipboard!");
                } else {
                    app.set_status("Failed to copy to clipboard");
                }
            }
            _ => {}
        },
    }

    false
}

fn handle_app_event(app: &mut App, event: AppEvent) {
    match event {
        AppEvent::PeerConnected { peer_id } => {
            app.add_peer(peer_id.clone());
            app.set_status(format!("Peer connected: {}", short_peer_id(&peer_id)));
        }
        AppEvent::PeerDisconnected { peer_id } => {
            app.remove_peer(&peer_id);
            app.set_status(format!("Peer disconnected: {}", short_peer_id(&peer_id)));
        }
        AppEvent::ChatReceived { peer_id, message } => {
            let text = String::from_utf8_lossy(&message).to_string();
            let msg_len = message.len() as u64;

            app.chat_history.push(ChatMessage {
                from_me: false,
                peer_id: peer_id.clone(),
                text,
                timestamp: Instant::now(),
            });

            // Update stats
            app.stats.messages_received += 1;
            app.stats.bytes_received += msg_len;

            // Auto-select chat peer if none selected
            if app.chat_peer.is_none() {
                app.chat_peer = Some(peer_id);
            }
        }
        AppEvent::FileOffered {
            peer_id,
            file_id,
            filename,
            filesize,
        } => {
            app.pending_offers.push(PendingFileOffer {
                peer_id,
                file_id,
                filename: filename.clone(),
                filesize,
            });
            app.set_status(format!("File offer: {}", filename));
        }
        AppEvent::FileProgress {
            file_id,
            filename,
            received_chunks,
            total_chunks,
            ..
        } => {
            app.file_progress
                .insert(file_id, (filename, received_chunks, total_chunks));
        }
        AppEvent::SendProgress {
            file_id,
            filename,
            sent_chunks,
            total_chunks,
            ..
        } => {
            app.send_progress
                .insert(file_id, (filename, sent_chunks, total_chunks));
        }
        AppEvent::SendComplete {
            file_id,
            success,
            ..
        } => {
            app.send_progress.remove(&file_id);
            if success {
                app.set_status("File sent successfully");
            } else {
                app.set_status("File transfer failed (hash mismatch)");
            }
        }
        AppEvent::FileComplete {
            peer_id,
            filename,
            path,
        } => {
            // Record received file
            app.file_history.push(FileRecord {
                direction: FileDirection::Received,
                peer_id,
                filename: filename.clone(),
                filesize: 0, // will be available from the filesystem
                path: Some(path.clone()),
                timestamp: Instant::now(),
            });

            // Update stats
            app.stats.files_received += 1;
            // Try to get actual filesize from the saved path
            if let Ok(meta) = std::fs::metadata(&path) {
                app.stats.bytes_received += meta.len();
            }

            // Track folder file progress: increment completed count for any active folder
            for (_, (completed, _total)) in app.folder_progress.iter_mut() {
                *completed += 1;
            }

            app.set_status(format!("File saved: {} -> {}", filename, path));
            // Remove from progress tracking
            app.file_progress.retain(|_, (_, recv, total)| recv < total);
        }
        AppEvent::FolderOffered {
            peer_id,
            folder_id,
            dirname,
            file_count,
            total_size,
        } => {
            app.pending_folder_offers.push(PendingFolderOffer {
                peer_id,
                folder_id,
                dirname: dirname.clone(),
                file_count,
                total_size,
            });
            app.set_status(format!(
                "Folder offer: {} ({} files, {})",
                dirname,
                file_count,
                format_file_size(total_size)
            ));
        }
        AppEvent::FolderComplete {
            folder_id,
            ..
        } => {
            app.folder_progress.remove(&folder_id);
            app.set_status("Folder transfer complete".to_string());
        }
        AppEvent::Error(msg) => {
            app.push_error(msg);
        }
        AppEvent::Info(msg) => {
            app.set_status(msg);
        }
    }
}

fn short_peer_id(id: &str) -> String {
    if id.len() > 12 {
        format!("{}...", &id[..12])
    } else {
        id.to_string()
    }
}

fn truncate_filename(name: &str, max_len: usize) -> String {
    if name.len() <= max_len {
        name.to_string()
    } else {
        format!("...{}", &name[name.len() - (max_len - 3)..])
    }
}

fn format_file_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
