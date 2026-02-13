use crate::core::engine::EngineAction;
use crate::core::initializer::{AppEvent, PeerNode};
use crate::core::peer_registry::PeerRegistry;
use crate::core::persistence::{
    ChatMessageSnapshot, ChatSenderSnapshot, ChatTargetSnapshot, Persistence,
};
use crate::ui::helpers::{format_file_size, get_display_name, render_loading_frame};
use crate::ui::panels::{
    ChatPanel, ConnectPanel, FilesPanel, HomePanel, IdPanel, LogsPanel, PeersPanel, RemotePanel,
    SendPanel, SettingsPanel,
};
pub(crate) use crate::ui::popups::{
    handle_remote_path_request_key, handle_transaction_offer_key, render_peer_info_popup, SavePathPopup,
    UIContext, UIPopup,
};
use crate::ui::traits::{Action, Component, Handler};
use crate::utils::hash::get_or_create_secret;
use crate::utils::log_buffer::LogBuffer;
use crate::utils::sos::SignalOfStop;
use crate::workers::app::{App, ChatTarget, Message, MessageSender, Mode};
use crate::workers::args::Args;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::{Frame, Terminal};
use std::io::stdout;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Esecutore UI: contenitore centrale per tutta la logica dell'interfaccia
pub struct UIExecuter {
    app: App,
    terminal: Terminal<CrosstermBackend<std::io::Stdout>>,
    node: PeerNode,
    log_buffer: LogBuffer,
    context: UIContext,

    // Tutti i panel UI
    home_panel: HomePanel,
    chat_panel: ChatPanel,
    send_panel: SendPanel,
    connect_panel: ConnectPanel,
    peers_panel: PeersPanel,
    files_panel: FilesPanel,
    logs_panel: LogsPanel,
    id_panel: IdPanel,
    settings_panel: SettingsPanel,
    remote_panel: RemotePanel,

    // Popup
    save_path_popup: SavePathPopup,

    // Peer registry for auto-reconnection
    peer_registry: PeerRegistry,

    // Chat persistence
    persistence: Persistence,
}

pub async fn run(args: Args, sos: SignalOfStop, log_buffer: LogBuffer) -> anyhow::Result<()> {
    // Acquire secret key with per-instance locking
    let (secret_key, _instance_guard) = get_or_create_secret()?;

    if args.show_secret {
        let secret_hex = hex::encode(secret_key.to_bytes());
        eprintln!("Using secret key: {secret_hex}");
    }

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<AppEvent>();

    // Create shared atomic counters for wire-level TX/RX statistics
    let cumulative_tx = Arc::new(AtomicU64::new(0));
    let cumulative_rx = Arc::new(AtomicU64::new(0));

    // Setup terminal early for loading animation
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    // Show loading animation while initializing node
    let node_args = args.clone();
    let node_sos = sos.clone();
    let node_event_tx = event_tx.clone();
    let node_secret = secret_key.clone();
    let node_tx = cumulative_tx.clone();
    let node_rx = cumulative_rx.clone();

    let mut init_task = tokio::spawn(async move {
        PeerNode::new(
            node_secret,
            node_args,
            node_sos,
            node_event_tx,
            node_tx,
            node_rx,
        )
        .await
    });

    let mut frame_index = 0;
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(80));

    let node = loop {
        tokio::select! {
            result = &mut init_task => {
                match result {
                    Ok(node_result) => break node_result?,
                    Err(e) => {
                        return Err(anyhow::anyhow!("Failed to initialize node: {}", e));
                    }
                }
            }
            _ = interval.tick() => {
                frame_index += 1;
                render_loading_frame(&mut terminal, frame_index)?;
            }
        }
    };

    let ticket = node.ticket()?;

    // Spawn accept loop
    let node_clone = node.clone();
    tokio::spawn(async move {
        node_clone.run_accept_loop().await;
    });

    // Drain any queued events
    while event::poll(std::time::Duration::from_millis(0))? {
        let _ = event::read()?;
    }

    let peer_id = node.peer_id();
    let mut app = App::new(
        peer_id,
        ticket,
        args.display_name.clone(),
        cumulative_tx,
        cumulative_rx,
    );

    // Restore persisted display name and theme if no CLI override was provided
    if let Ok(p) = crate::core::persistence::Persistence::load() {
        if args.display_name.is_none() {
            if let Some(ref name) = p.display_name {
                if !name.is_empty() {
                    app.display_name = name.clone();
                    node.set_display_name(name.clone());
                }
            }
        }
        // Restore theme
        if !p.theme.is_empty() {
            app.theme = crate::workers::app::AppTheme::from_str(&p.theme);
        }
    }

    let mut executer = UIExecuter::new(app, terminal, node.clone(), log_buffer);

    // Restore chat history from persistence
    for snap in &executer.persistence.chat_history {
        let sender = match &snap.sender {
            ChatSenderSnapshot::Me => MessageSender::Me,
            ChatSenderSnapshot::Peer(id) => MessageSender::Peer(id.clone()),
        };
        let target = match &snap.target {
            ChatTargetSnapshot::Room => ChatTarget::Room,
            ChatTargetSnapshot::Peer(id) => ChatTarget::Peer(id.clone()),
        };
        executer.app.messages.insert(Message {
            id: uuid::Uuid::parse_str(&snap.id).unwrap_or_else(|_| uuid::Uuid::new_v4()),
            sender,
            text: snap.text.clone(),
            timestamp: snap.timestamp.clone(),
            target,
        });
    }

    // Seed peer list from registry so saved offline peers are visible
    for record in executer.peer_registry.all_peers() {
        if !record.removed {
            if let Some(ref name) = record.display_name {
                executer
                    .app
                    .peer_names
                    .insert(record.peer_id.clone(), name.clone());
            }
            if !executer.app.peers.contains(&record.peer_id) {
                executer.app.peers.push(record.peer_id.clone());
                executer.app.peer_status.insert(
                    record.peer_id.clone(),
                    crate::workers::app::PeerStatus::Offline,
                );
            }
        }
    }

    // Auto-reconnect to known peers from the registry
    {
        let peers_to_reconnect: Vec<_> = executer
            .peer_registry
            .reconnectable_peers()
            .into_iter()
            .map(|p| (p.peer_id.clone(), p.ticket.clone(), p.display_name.clone()))
            .collect();

        if !peers_to_reconnect.is_empty() {
            info!(
                event = "auto_reconnect_start",
                count = peers_to_reconnect.len(),
                "Attempting to reconnect to known peers"
            );
            executer.app.set_status(format!(
                "Resuming {} connection{}...",
                peers_to_reconnect.len(),
                if peers_to_reconnect.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ));
            for (peer_id, ticket, display_name) in peers_to_reconnect {
                // Pre-populate display name if we have one from last session
                if let Some(name) = &display_name {
                    executer
                        .app
                        .peer_names
                        .insert(peer_id.clone(), name.clone());
                }
                let node_clone = node.clone();
                let pid = peer_id.clone();
                tokio::spawn(async move {
                    // Wait before first attempt to let the network stack settle
                    // and give remote peers time to come online.
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

                    use crate::core::config::{
                        INITIAL_CONNECT_MAX_RETRIES as MAX_RETRIES,
                        INITIAL_CONNECT_RETRY_DELAYS as RETRY_DELAYS,
                    };

                    for attempt in 0..=MAX_RETRIES {
                        if attempt > 0 {
                            let delay = RETRY_DELAYS
                                .get((attempt - 1) as usize)
                                .copied()
                                .unwrap_or(30);
                            info!(
                                event = "auto_reconnect_retry",
                                peer = %crate::core::initializer::short_id_pub(&pid),
                                attempt,
                                delay_secs = delay,
                                "Retrying reconnection"
                            );
                            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                        }

                        info!(
                            event = "auto_reconnect_attempt",
                            peer = %crate::core::initializer::short_id_pub(&pid),
                            attempt = attempt + 1,
                            "Reconnecting to peer"
                        );

                        match node_clone.connect_to_quiet(ticket.clone()).await {
                            Ok(()) => break,
                            Err(e) => {
                                if attempt == MAX_RETRIES {
                                    warn!(
                                        event = "auto_reconnect_failed",
                                        peer = %crate::core::initializer::short_id_pub(&pid),
                                        error = %e,
                                        "Failed to reconnect after {} attempts",
                                        MAX_RETRIES + 1
                                    );
                                } else {
                                    debug!(
                                        event = "auto_reconnect_attempt_failed",
                                        peer = %crate::core::initializer::short_id_pub(&pid),
                                        error = %e,
                                        attempt = attempt + 1,
                                        "Reconnection attempt failed, will retry"
                                    );
                                }
                            }
                        }
                    }
                });
            }
        }
    }

    // Call on_focus for initial mode
    let initial_mode = executer.context.current_mode;
    executer.call_focus_change(initial_mode, true);

    // Main event loop
    let should_quit = executer.run_event_loop(&node, &mut event_rx, &sos).await?;

    // Cleanup terminal
    disable_raw_mode()?;
    execute!(executer.terminal.backend_mut(), LeaveAlternateScreen)?;
    executer.terminal.show_cursor()?;

    if should_quit {
        sos.cancel();
    }

    Ok(())
}

impl UIExecuter {
    pub fn new(
        app: App,
        terminal: Terminal<CrosstermBackend<std::io::Stdout>>,
        node: PeerNode,
        log_buffer: LogBuffer,
    ) -> Self {
        let persistence = Persistence::load().unwrap_or_default();
        Self {
            app,
            terminal,
            node,
            log_buffer,
            context: UIContext::new(),
            home_panel: HomePanel::new(),
            chat_panel: ChatPanel::new(),
            send_panel: SendPanel::new(),
            connect_panel: ConnectPanel::new(),
            peers_panel: PeersPanel::new(),
            files_panel: FilesPanel::new(),
            logs_panel: LogsPanel::new(),
            id_panel: IdPanel::new(),
            settings_panel: SettingsPanel::new(),
            remote_panel: RemotePanel::new(),
            save_path_popup: SavePathPopup::new(),
            peer_registry: PeerRegistry::load(),
            persistence,
        }
    }

    /// Chiama on_focus o on_blur per il panel corrispondente alla modalità data
    fn call_focus_change(&mut self, mode: Mode, focused: bool) {
        match mode {
            Mode::Home => {
                if focused {
                    self.home_panel.on_focus(&mut self.app)
                } else {
                    self.home_panel.on_blur(&mut self.app)
                }
            }
            Mode::Chat => {
                if focused {
                    self.chat_panel.on_focus(&mut self.app)
                } else {
                    self.chat_panel.on_blur(&mut self.app)
                }
            }
            Mode::Send => {
                if focused {
                    self.send_panel.on_focus(&mut self.app)
                } else {
                    self.send_panel.on_blur(&mut self.app)
                }
            }
            Mode::Connect => {
                if focused {
                    self.connect_panel.on_focus(&mut self.app)
                } else {
                    self.connect_panel.on_blur(&mut self.app)
                }
            }
            Mode::Peers => {
                if focused {
                    self.peers_panel.on_focus(&mut self.app)
                } else {
                    self.peers_panel.on_blur(&mut self.app)
                }
            }
            Mode::Files => {
                if focused {
                    self.files_panel.on_focus(&mut self.app)
                } else {
                    self.files_panel.on_blur(&mut self.app)
                }
            }
            Mode::Logs => {
                if focused {
                    self.logs_panel.on_focus(&mut self.app)
                } else {
                    self.logs_panel.on_blur(&mut self.app)
                }
            }
            Mode::Id => {
                if focused {
                    self.id_panel.on_focus(&mut self.app)
                } else {
                    self.id_panel.on_blur(&mut self.app)
                }
            }
            Mode::Settings => {
                if focused {
                    self.settings_panel.on_focus(&mut self.app)
                } else {
                    self.settings_panel.on_blur(&mut self.app)
                }
            }
            Mode::Remote => {
                if focused {
                    self.remote_panel.on_focus(&mut self.app)
                } else {
                    self.remote_panel.on_blur(&mut self.app)
                }
            }
        }
    }

    /// Gestisce pressione tasti per il panel con modalità data
    fn handle_panel_key(&mut self, mode: Mode, key: KeyCode) -> Option<Action> {
        match mode {
            Mode::Home => self.home_panel.handle_key(&mut self.app, &self.node, key),
            Mode::Chat => self.chat_panel.handle_key(&mut self.app, &self.node, key),
            Mode::Send => self.send_panel.handle_key(&mut self.app, &self.node, key),
            Mode::Connect => self
                .connect_panel
                .handle_key(&mut self.app, &self.node, key),
            Mode::Peers => self.peers_panel.handle_key(&mut self.app, &self.node, key),
            Mode::Files => self.files_panel.handle_key(&mut self.app, &self.node, key),
            Mode::Logs => self.logs_panel.handle_key(&mut self.app, &self.node, key),
            Mode::Id => self.id_panel.handle_key(&mut self.app, &self.node, key),
            Mode::Settings => self
                .settings_panel
                .handle_key(&mut self.app, &self.node, key),
            Mode::Remote => self.remote_panel.handle_key(&mut self.app, &self.node, key),
        }
    }

    /// Funzione per renderizzare l'intera interfaccia
    fn render_frame(&mut self) -> std::io::Result<()> {
        let context = self.context.clone();
        let app = &self.app;
        let log_buffer = &self.log_buffer;
        let save_path_popup = &self.save_path_popup;
        let home_panel = &mut self.home_panel;
        let chat_panel = &mut self.chat_panel;
        let send_panel = &mut self.send_panel;
        let connect_panel = &mut self.connect_panel;
        let peers_panel = &mut self.peers_panel;
        let files_panel = &mut self.files_panel;
        let logs_panel = &mut self.logs_panel;
        let id_panel = &mut self.id_panel;
        let settings_panel = &mut self.settings_panel;
        let remote_panel = &mut self.remote_panel;

        self.terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(1), Constraint::Length(3)])
                .split(f.area());

            match context.current_mode {
                Mode::Home => home_panel.render(f, app, chunks[0]),
                Mode::Chat => chat_panel.render(f, app, chunks[0]),
                Mode::Send => send_panel.render(f, app, chunks[0]),
                Mode::Connect => connect_panel.render(f, app, chunks[0]),
                Mode::Peers => peers_panel.render(f, app, chunks[0]),
                Mode::Files => files_panel.render(f, app, chunks[0]),
                Mode::Logs => logs_panel.render_with_buffer(f, app, log_buffer, chunks[0]),
                Mode::Id => id_panel.render(f, app, chunks[0]),
                Mode::Settings => settings_panel.render(f, app, chunks[0]),
                Mode::Remote => remote_panel.render(f, app, chunks[0]),
            }

            match context.active_popup {
                UIPopup::TransactionOffer if app.engine.has_pending_incoming() => {
                    save_path_popup.render_transaction_from_engine(f, app);
                }
                UIPopup::RemotePathRequest if app.remote_path_request.is_some() => {
                    save_path_popup.render_remote_path(f, app);
                }
                UIPopup::PeerInfo if app.peer_info_popup.is_some() => {
                    render_peer_info_popup(f, app);
                }
                _ => {}
            }

            Self::render_stats_bar_static(f, app, context.current_mode, chunks[1]);
        })?;

        Ok(())
    }

    /// Renderizza la barra di statistiche in fondo (versione statica per evitare borrow conflicts)
    fn render_stats_bar_static(f: &mut Frame, app: &App, mode: Mode, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Length(2)])
            .split(area);

        // Linea di aiuto basata sulla modalità
        let help = match mode {
            Mode::Home => "Up/Down: navigate | Enter: select ",
            Mode::Chat => "Enter: send | /help: commands | Tab/Shift+Tab: switch chat | Esc: back",
            Mode::Send => "Enter: send file/folder | Tab/Up/Down: peer | Esc: back",
            Mode::Connect => "Enter: connect | Esc: back",
            Mode::Peers => "Up/Down: navigate | d: disconnect | e/Enter: explore | Esc: back",
            Mode::Files => {
                "Left/Right: select active | x: cancel transfer | Up/Down: scroll history | Esc: back"
            }
            Mode::Logs => "Up/Down: scroll | d: clear | Esc: back",
            Mode::Id => "c: copy to clipboard | Esc: back",
            Mode::Settings => "Tab: switch focus | Enter: save | Esc: back",
            Mode::Remote => {
                "Enter: select file/folder | Backspace: up to parent | f: fetch folder | Esc: back"
            }
        };
        let help_line = if let Some(notif) = app.notify.current() {
            Paragraph::new(format!(" {} {}", notif.level.icon(), notif.message))
                .style(Style::default().fg(notif.level.color()))
        } else {
            Paragraph::new(help).style(Style::default().fg(Color::DarkGray))
        };
        f.render_widget(help_line, chunks[0]);

        // Linea di statistiche — uses DataStats for data-level bytes (file + chat)
        // and WireStats for total wire-level bytes (includes control overhead).
        let stats = app.engine.stats();
        let wire_tx = app.total_wire_tx();
        let wire_rx = app.total_wire_rx();
        let stats_spans = vec![
            Span::styled(" TX: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format_file_size(wire_tx), Style::default().fg(Color::Green)),
            Span::styled(
                format!(
                    " ({} msgs, {} files)",
                    stats.messages_sent, stats.files_sent
                ),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled("  |  RX: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format_file_size(wire_rx), Style::default().fg(Color::Cyan)),
            Span::styled(
                format!(
                    " ({} msgs, {} files)",
                    stats.messages_received, stats.files_received
                ),
                Style::default().fg(Color::DarkGray),
            ),
        ];
        let stats_line =
            Paragraph::new(Line::from(stats_spans)).style(Style::default().bg(Color::Black));
        f.render_widget(stats_line, chunks[1]);
    }

    /// Loop principale evento dell'applicazione
    async fn run_event_loop(
        &mut self,
        node: &PeerNode,
        event_rx: &mut mpsc::UnboundedReceiver<AppEvent>,
        sos: &SignalOfStop,
    ) -> anyhow::Result<bool> {
        loop {
            // Renderizza l'interfaccia
            self.render_frame()?;

            // Poll crossterm events con timeout di 50ms
            if event::poll(std::time::Duration::from_millis(50))?
                && let Event::Key(key) = event::read()?
            {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                // Gestisci tasti popup prima di tutto
                if self.context.has_popup() {
                    if self.handle_popup_event(node, key.code).await {
                        return Ok(true); // quit
                    }
                    continue;
                }

                // Gestisci tasti del panel
                let old_mode = self.context.current_mode;
                if let Some(action) = self.handle_panel_key(self.context.current_mode, key.code) {
                    match action {
                        Action::SwitchMode(new_mode) => {
                            self.call_focus_change(old_mode, false);
                            self.context.switch_mode(new_mode);
                            self.app.mode = new_mode;
                            self.call_focus_change(new_mode, true);
                        }
                        Action::SetStatus(msg) => self.app.set_status(msg),
                        Action::EngineActions(actions) => {
                            self.execute_engine_actions(node, actions).await;
                        }
                        Action::ShowPopup(popup) => {
                            self.context.active_popup = popup;
                        }
                        Action::PersistChat {
                            id,
                            sender,
                            text,
                            timestamp,
                            target,
                        } => {
                            let _ = self.persistence.push_chat_message(ChatMessageSnapshot {
                                id,
                                sender,
                                text,
                                timestamp,
                                target,
                            });
                        }
                        Action::PersistClearChat(target) => {
                            let _ = self.persistence.clear_chat_target(&target);
                        }
                        Action::RemoveSavedPeer(peer_id) => {
                            let display = crate::ui::helpers::get_display_name(&self.app, &peer_id);
                            self.app.remove_peer(&peer_id);
                            self.peer_registry.remove_single(&peer_id);
                            self.app
                                .notify
                                .warn(format!("Removed saved peer: {}", display));
                        }
                        Action::ClearSavedPeers => {
                            // Disconnect all online peers first
                            let online_peers: Vec<String> = self
                                .app
                                .peers
                                .iter()
                                .filter(|p| self.app.is_peer_online(p))
                                .cloned()
                                .collect();
                            for peer_id in &online_peers {
                                let node_c = node.clone();
                                let pid = peer_id.clone();
                                tokio::spawn(async move {
                                    node_c.remove_peer(&pid).await;
                                });
                            }
                            // Remove all peers from UI state
                            let all_peers: Vec<String> = self.app.peers.drain(..).collect();
                            for pid in &all_peers {
                                self.app.peer_status.remove(pid);
                                self.app.peer_names.remove(pid);
                                self.app.peer_keys.remove(pid);
                            }
                            self.app.selected_peer_idx = 0;
                            // Clear the registry
                            self.peer_registry.clear();
                            self.app.notify.warn("Cleared all saved peers".to_string());
                        }
                        Action::ClearOfflinePeers => {
                            // Collect offline peers
                            let offline_peers: Vec<String> = self
                                .app
                                .peers
                                .iter()
                                .filter(|p| !self.app.is_peer_online(p))
                                .cloned()
                                .collect();
                            let count = offline_peers.len();
                            // Remove offline peers from UI state and registry
                            for pid in &offline_peers {
                                self.app.peers.retain(|p| p != pid);
                                self.app.peer_status.remove(pid);
                                self.app.peer_names.remove(pid);
                                self.app.peer_keys.remove(pid);
                                self.peer_registry.remove_single(pid);
                            }
                            // Adjust selection if needed
                            if self.app.selected_peer_idx >= self.app.peers.len() {
                                self.app.selected_peer_idx = self.app.peers.len().saturating_sub(1);
                            }
                            self.app
                                .notify
                                .warn(format!("Cleared {} offline peer(s)", count));
                        }
                        Action::None => {}
                    }
                }
            }

            // Processa eventi app
            while let Ok(ev) = event_rx.try_recv() {
                self.handle_app_event(node, ev).await;
            }

            if sos.cancelled() {
                return Ok(true);
            }
        }
    }

    /// Gestisce gli eventi dei popup
    async fn handle_popup_event(&mut self, node: &PeerNode, key: KeyCode) -> bool {
        if self.context.active_popup == UIPopup::TransactionOffer
            && self.app.engine.has_pending_incoming()
        {
            let result =
                handle_transaction_offer_key(&mut self.app, key, &mut self.context.active_popup)
                    .await;
            self.execute_engine_actions(node, result.actions).await;
            result.quit
        } else if self.context.active_popup == UIPopup::RemotePathRequest
            && self.app.remote_path_request.is_some()
        {
            let result = handle_remote_path_request_key(
                &mut self.app,
                node,
                key,
                &mut self.context.active_popup,
            )
            .await;
            result.quit
        } else if self.context.active_popup == UIPopup::PeerInfo
            && self.app.peer_info_popup.is_some()
        {
            // Handle PeerInfo popup - close on Enter or Esc
            match key {
                KeyCode::Enter | KeyCode::Esc => {
                    self.app.peer_info_popup = None;
                    self.context.active_popup = UIPopup::None;
                }
                _ => {}
            }
            false
        } else {
            false
        }
    }

    /// Gestisce gli eventi dell'applicazione.
    /// Transfer-related events are delegated to the TransferEngine;
    /// non-transfer events are handled directly.
    pub async fn handle_app_event(&mut self, node: &PeerNode, event: AppEvent) {
        // Guard against stale disconnect events from evicted WebRTC connections FIRST,
        // before any engine processing. When a peer reconnects, handle_incoming evicts
        // the old connection. The old WebRTC on_peer_connection_state_change fires
        // Closed → Disconnected, which arrives here AFTER the new connection is already
        // established. We must skip the entire event (including engine processing) to
        // avoid transitioning Active transactions back to Resumable.
        if let AppEvent::PeerDisconnected {
            ref peer_id,
            explicit,
        } = event
        {
            if !explicit && node.is_peer_connected(peer_id).await {
                debug!(event = "stale_disconnect_ignored", peer = %crate::core::initializer::short_id_pub(peer_id), "Ignoring stale PeerDisconnected — peer has an active connection");
                return;
            }
        }

        // ── Route ALL transfer-related events through the engine ──────────
        let outcome = self.app.engine.process_event(&event);

        // Apply engine outcome (actions + status)
        if let Some(status) = outcome.status {
            self.app.notify.info(status);
        }
        self.execute_engine_actions(node, outcome.actions).await;

        // ── Handle non-transfer events directly ──────────────────────────
        match event {
            AppEvent::PeerConnected { peer_id, remote_ip } => {
                self.app.connecting_peers.remove(&peer_id);
                self.app.add_peer(peer_id.clone());

                if let Some(key) = node.get_peer_key(&peer_id).await {
                    self.app.peer_keys.insert(peer_id.clone(), key);
                }

                // Store the remote IP address if available
                if let Some(ip) = remote_ip {
                    self.app.peer_ips.insert(peer_id.clone(), ip);
                }

                // Persist peer for auto-reconnection
                if let Some(ticket) = node.get_peer_ticket(&peer_id).await {
                    self.peer_registry.peer_connected(&peer_id, ticket);
                }

                // Log active transaction state before resume check
                let active_count = self.app.engine.transactions().active_count();
                let total_active = self.app.engine.transactions().active.len();
                info!(
                    event = "peer_connected_resume_check",
                    peer = %crate::core::initializer::short_id_pub(&peer_id),
                    active_transactions = total_active,
                    non_terminal = active_count,
                    "Checking for resumable transactions"
                );

                // Check for resumable transactions with this peer
                let resume_outcome = self.app.engine.handle_peer_reconnected(&peer_id);
                let has_resume_actions = !resume_outcome.actions.is_empty();
                let action_count = resume_outcome.actions.len();
                if let Some(status) = resume_outcome.status {
                    self.app.notify.info(status);
                }
                if has_resume_actions {
                    info!(
                        event = "resume_actions_executing",
                        peer = %crate::core::initializer::short_id_pub(&peer_id),
                        actions = action_count,
                        "Executing resume actions"
                    );
                    self.execute_engine_actions(node, resume_outcome.actions)
                        .await;
                }

                info!(event = "peer_online", peer = %crate::core::initializer::short_id_pub(&peer_id), "Peer state: offline → online");
                if !has_resume_actions {
                    self.app.notify.success(format!(
                        "Connected: {}",
                        get_display_name(&self.app, &peer_id)
                    ));
                }

                // Deliver any pending messages queued while peer was offline
                if let Err(e) = node.deliver_pending_messages(&peer_id).await {
                    tracing::warn!(
                        event = "pending_messages_delivery_failed",
                        peer = %crate::core::initializer::short_id_pub(&peer_id),
                        error = %e,
                        "Failed to deliver pending messages"
                    );
                }
            }
            AppEvent::PeerDisconnected { peer_id, explicit } => {
                self.app.connecting_peers.remove(&peer_id);
                // Engine already interrupted and persisted transactions as Resumable;
                // no additional transaction handling needed here.

                // Clean up the stale entry from PeerNode so the peer
                // slot is freed and the remote side can reconnect inbound.
                node.cleanup_peer(&peer_id).await;

                if explicit {
                    // User explicitly disconnected — full removal
                    info!(event = "peer_removed", peer = %crate::core::initializer::short_id_pub(&peer_id), "Peer explicitly disconnected and removed");
                    self.app.remove_peer(&peer_id);
                    self.peer_registry.peer_removed(&peer_id);
                    self.app.notify.warn(format!(
                        "Disconnected: {}",
                        get_display_name(&self.app, &peer_id)
                    ));
                } else {
                    // Connection lost — transition to offline, preserve state
                    warn!(event = "peer_offline", peer = %crate::core::initializer::short_id_pub(&peer_id), "Peer state: online → offline (connection lost)");
                    self.app.set_peer_offline(&peer_id);
                    self.peer_registry.peer_disconnected(&peer_id);
                    self.app.notify.warn(format!(
                        "Connection lost: {}",
                        get_display_name(&self.app, &peer_id)
                    ));

                    // Auto-reconnect: try to re-establish connection using the
                    // saved ticket.  This is critical because without it neither
                    // side will attempt to reconnect after a mid-session
                    // disconnect and the transfer will stall forever.
                    if let Some(record) = self.peer_registry.peers.get(&peer_id) {
                        if !record.removed {
                            let ticket = record.ticket.clone();
                            let node_clone = node.clone();
                            let pid = peer_id.clone();
                            info!(event = "auto_reconnect_after_disconnect", peer = %crate::core::initializer::short_id_pub(&pid), "Spawning auto-reconnect after connection loss");
                            tokio::spawn(async move {
                                use crate::core::config::{
                                    RECONNECT_MAX_RETRIES as MAX_RETRIES,
                                    RECONNECT_RETRY_DELAYS as RETRY_DELAYS,
                                };

                                for attempt in 0..MAX_RETRIES {
                                    let delay =
                                        RETRY_DELAYS.get(attempt as usize).copied().unwrap_or(30);
                                    tokio::time::sleep(std::time::Duration::from_secs(delay)).await;

                                    // Check if already reconnected (another inbound
                                    // connection may have arrived in the meantime).
                                    if node_clone.is_peer_connected(&pid).await {
                                        info!(
                                            event = "auto_reconnect_already_connected",
                                            peer = %crate::core::initializer::short_id_pub(&pid),
                                            "Peer already reconnected, aborting auto-reconnect"
                                        );
                                        return;
                                    }

                                    info!(
                                        event = "auto_reconnect_attempt",
                                        peer = %crate::core::initializer::short_id_pub(&pid),
                                        attempt = attempt + 1,
                                        "Attempting auto-reconnect after disconnect"
                                    );

                                    match node_clone.connect_to_quiet(ticket.clone()).await {
                                        Ok(()) => {
                                            info!(
                                                event = "auto_reconnect_success",
                                                peer = %crate::core::initializer::short_id_pub(&pid),
                                                attempt = attempt + 1,
                                                "Auto-reconnect succeeded"
                                            );
                                            return;
                                        }
                                        Err(e) => {
                                            warn!(
                                                event = "auto_reconnect_attempt_failed",
                                                peer = %crate::core::initializer::short_id_pub(&pid),
                                                error = %e,
                                                attempt = attempt + 1,
                                                "Auto-reconnect attempt failed"
                                            );
                                        }
                                    }
                                }
                                warn!(
                                    event = "auto_reconnect_exhausted",
                                    peer = %crate::core::initializer::short_id_pub(&pid),
                                    "All auto-reconnect attempts failed"
                                );
                            });
                        }
                    }
                }
            }
            AppEvent::ChatReceived { peer_id, message } => {
                // Stats tracked by engine
                let text = String::from_utf8_lossy(&message).to_string();

                // Clear typing indicator — peer just sent a message
                self.app.typing.clear(&peer_id);

                // Update per-peer stats (messages received)
                let stats = self
                    .app
                    .peer_stats
                    .entry(peer_id.clone())
                    .or_insert((0, 0, 0, 0));
                stats.1 += 1;

                let msg_id = uuid::Uuid::new_v4();
                let timestamp = crate::ui::helpers::format_timestamp_now();

                // Room message
                self.app.messages.insert(Message {
                    id: msg_id,
                    sender: MessageSender::Peer(peer_id.clone()),
                    text: text.clone(),
                    timestamp: timestamp.clone(),
                    target: ChatTarget::Room,
                });

                // Persist to disk
                let _ = self.persistence.push_chat_message(ChatMessageSnapshot {
                    id: msg_id.to_string(),
                    sender: ChatSenderSnapshot::Peer(peer_id.clone()),
                    text,
                    timestamp,
                    target: ChatTargetSnapshot::Room,
                });

                // Increment unread unless the user is looking at Room right now
                let viewing_room =
                    self.app.mode == Mode::Chat && self.app.chat_target == ChatTarget::Room;
                if !viewing_room {
                    self.app.unread.increment_room();
                }
            }
            AppEvent::DmReceived { peer_id, message } => {
                let text = String::from_utf8_lossy(&message).to_string();

                // Clear typing indicator
                self.app.typing.clear(&peer_id);

                // Update per-peer stats (messages received)
                let stats = self
                    .app
                    .peer_stats
                    .entry(peer_id.clone())
                    .or_insert((0, 0, 0, 0));
                stats.1 += 1;

                let msg_id = uuid::Uuid::new_v4();
                let timestamp = crate::ui::helpers::format_timestamp_now();

                // Peer-chat isolation: DM only appears in the dedicated peer chat
                let target = ChatTarget::Peer(peer_id.clone());
                self.app.messages.insert(Message {
                    id: msg_id,
                    sender: MessageSender::Peer(peer_id.clone()),
                    text: text.clone(),
                    timestamp: timestamp.clone(),
                    target: target.clone(),
                });

                // Persist to disk
                let _ = self.persistence.push_chat_message(ChatMessageSnapshot {
                    id: msg_id.to_string(),
                    sender: ChatSenderSnapshot::Peer(peer_id.clone()),
                    text,
                    timestamp,
                    target: ChatTargetSnapshot::Peer(peer_id.clone()),
                });

                // Increment unread unless user is viewing this exact DM
                let viewing_dm = self.app.mode == Mode::Chat && self.app.chat_target == target;
                if !viewing_dm {
                    self.app.unread.increment_peer(&peer_id);
                }
            }
            AppEvent::TypingReceived { peer_id } => {
                self.app.typing.set_typing(&peer_id);
            }
            AppEvent::DisplayNameReceived { peer_id, name } => {
                self.peer_registry.set_display_name(&peer_id, &name);
                self.app.peer_names.insert(peer_id, name);
            }
            AppEvent::Error(msg) => {
                error!(event = "app_error", message = %msg, "Application error");
                self.app.push_error(msg);
            }
            AppEvent::Info(msg) => {
                if msg.starts_with("REMOTE_SAVE_PATH:") {
                    // Store save path for auto-accept: "REMOTE_SAVE_PATH:peer_id:path"
                    let rest = msg.trim_start_matches("REMOTE_SAVE_PATH:");
                    if let Some((peer_id, save_path)) = rest.split_once(':') {
                        self.app
                            .pending_remote_save_paths
                            .insert(peer_id.to_string(), save_path.to_string());
                    }
                } else {
                    self.app.set_status(msg);
                }
            }
            AppEvent::Connecting { peer_id, status } => {
                self.app.connecting_peers.insert(peer_id, status);
            }
            AppEvent::LsResponse {
                peer_id,
                path,
                entries,
            } => {
                if self.context.current_mode == Mode::Remote
                    && self.app.remote_peer.as_deref() == Some(&peer_id)
                {
                    self.app.remote_path = path;
                    self.app.remote_entries = entries;
                    if self.app.remote_selected >= self.app.remote_entries.len() {
                        self.app.remote_selected = 0;
                    }
                }
            }
            AppEvent::RemoteAccessDisabled { peer_id } => {
                if self.context.current_mode == Mode::Remote
                    && self.app.remote_peer.as_deref() == Some(&peer_id)
                {
                    self.app.notify.warn("Remote access disabled");
                    self.context.switch_mode(Mode::Peers);
                    self.app.mode = Mode::Peers;
                    self.app.remote_peer = None;
                }
            }

            // ── Transaction events handled by engine popup system ────────
            AppEvent::TransactionRequested { peer_id, .. } => {
                // Auto-accept if there's a pending remote save path for this peer
                if let Some(save_path) = self.app.pending_remote_save_paths.remove(&peer_id) {
                    if let Some(pi) = self.app.engine.pending_incoming_mut() {
                        pi.save_path_input = save_path.clone();
                    }
                    if let Ok(outcome) = self.app.engine.accept_incoming(save_path) {
                        if let Some(status) = outcome.status {
                            self.app.notify.info(status);
                        }
                        self.execute_engine_actions(node, outcome.actions).await;
                    }
                } else if self.app.engine.has_pending_incoming() {
                    self.context.active_popup = UIPopup::TransactionOffer;
                }
            }

            // ── File transfer events for per-peer stats ───────────────────────
            AppEvent::SendComplete {
                _peer_id, success, ..
            } => {
                if success {
                    // Update per-peer stats (files sent)
                    let stats = self
                        .app
                        .peer_stats
                        .entry(_peer_id.clone())
                        .or_insert((0, 0, 0, 0));
                    stats.2 += 1;
                }
            }
            AppEvent::FileComplete { _peer_id, .. } => {
                // Update per-peer stats (files received)
                let stats = self
                    .app
                    .peer_stats
                    .entry(_peer_id.clone())
                    .or_insert((0, 0, 0, 0));
                stats.3 += 1;
            }

            // Transfer events — already processed by engine.process_event() above
            _ => {
                // Already processed by engine.process_event() above
            }
        }
    }

    // ── Execute Engine Actions ───────────────────────────────────────────

    /// Execute network actions returned by the TransferEngine.
    /// This is the ONLY place where the UI layer talks to the network
    /// for transfer-related operations.
    async fn execute_engine_actions(&mut self, node: &PeerNode, actions: Vec<EngineAction>) {
        use std::collections::VecDeque;
        let mut queue: VecDeque<EngineAction> = actions.into();
        while let Some(action) = queue.pop_front() {
            match action {
                EngineAction::RetransmitChunks {
                    peer_id,
                    file_id,
                    chunk_indices,
                } => {
                    let engine = &mut self.app.engine;
                    if let Err(e) = node
                        .retransmit_chunks(engine, &peer_id, file_id, &chunk_indices)
                        .await
                    {
                        tracing::error!("Retransmit chunks error for {}: {}", file_id, e);
                        let _ = node.event_tx().send(AppEvent::Error(format!(
                            "Retransmit chunks failed ({}): {}",
                            file_id, e
                        )));
                    }
                }
                EngineAction::RejectResume {
                    peer_id,
                    transaction_id,
                    reason,
                } => {
                    let node = node.clone();
                    tokio::spawn(async move {
                        tracing::info!(
                            "Rejecting resume request for {} (reason: {})",
                            transaction_id,
                            reason
                        );
                        if let Err(e) = node
                            .reject_transaction_resume(&peer_id, transaction_id)
                            .await
                        {
                            tracing::error!(
                                "Failed to send resume rejection for {}: {}",
                                transaction_id,
                                e
                            );
                        }
                    });
                }
                EngineAction::TransactionCompleteAck {
                    peer_id,
                    transaction_id,
                } => {
                    let node = node.clone();
                    tokio::spawn(async move {
                        if let Err(e) = node
                            .send_transaction_complete_ack(&peer_id, transaction_id)
                            .await
                        {
                            tracing::error!(
                                "Failed to send TransactionCompleteAck for {}: {}",
                                transaction_id,
                                e
                            );
                        }
                    });
                }
                EngineAction::SendTransactionRequest {
                    peer_id,
                    transaction_id,
                    display_name,
                    mut manifest,
                    total_size,
                } => {
                    // Merkle roots are now computed per-file during send
                    // (in send_file_resuming) — no upfront computation needed.
                    // Sign the manifest (without merkle roots; the sender's
                    // per-file Merkle root is sent alongside the Hash message).
                    self.app.engine.sign_manifest(&mut manifest);

                    let node = node.clone();
                    let event_tx = node.event_tx().clone();
                    tokio::spawn(async move {
                        if let Err(e) = node
                            .send_transaction_request(
                                &peer_id,
                                transaction_id,
                                display_name,
                                manifest,
                                total_size,
                            )
                            .await
                        {
                            tracing::error!(
                                "Failed to send transaction request {}: {}",
                                transaction_id,
                                e
                            );
                            let _ = event_tx.send(AppEvent::Error(format!(
                                "Failed to send transfer request: {}",
                                e
                            )));
                        }
                    });
                }
                EngineAction::SendTransactionResponse {
                    peer_id,
                    transaction_id,
                    accepted,
                    dest_path,
                    reason,
                } => {
                    let node = node.clone();
                    tokio::spawn(async move {
                        if let Err(e) = node
                            .respond_to_transaction(
                                &peer_id,
                                transaction_id,
                                accepted,
                                dest_path,
                                reason,
                            )
                            .await
                        {
                            tracing::error!(
                                "Failed to send transaction response {}: {}",
                                transaction_id,
                                e
                            );
                        }
                    });
                }
                EngineAction::PrepareReceive { peer_id, files, resume_bitmaps } => {
                    // Await directly (not spawned) to guarantee destinations
                    // are registered BEFORE the TransactionResponse is sent.
                    // This prevents a race where the sender starts sending
                    // Metadata frames before we have registered where to save.
                    if let Err(e) = node.prepare_file_reception(&peer_id, files).await {
                        tracing::error!("Failed to prepare file reception for {}: {}", peer_id, e);
                    }
                    // Register resume bitmaps so the Metadata handler can
                    // open existing temp files without truncating.
                    if !resume_bitmaps.is_empty() {
                        if let Err(e) = node.prepare_resume_bitmaps(&peer_id, resume_bitmaps).await {
                            tracing::error!("Failed to register resume bitmaps for {}: {}", peer_id, e);
                        }
                    }
                }
                EngineAction::SendFileData {
                    peer_id,
                    file_path,
                    file_id,
                    filename,
                } => {
                    // Use send_file_data which sends directly with the
                    // Transaction's file_id.
                    let node = node.clone();
                    let event_tx = node.event_tx().clone();
                    tokio::spawn(async move {
                        if let Err(e) = node
                            .send_file_data(&peer_id, file_id, &file_path, &filename)
                            .await
                        {
                            tracing::error!("File send error for {}: {}", filename, e);
                            let _ = event_tx.send(AppEvent::Error(format!(
                                "File send failed ({}): {}",
                                filename, e
                            )));
                        }
                    });
                }
                EngineAction::SendFolderData {
                    peer_id,
                    folder_path,
                    file_entries,
                } => {
                    // Use send_folder_data which sends each file with the
                    // Transaction's file_ids, reading one at a time for lower
                    // peak memory usage.
                    let node = node.clone();
                    let event_tx = node.event_tx().clone();
                    tokio::spawn(async move {
                        if let Err(e) = node
                            .send_folder_data(&peer_id, &folder_path, file_entries)
                            .await
                        {
                            tracing::error!("Folder send error: {}", e);
                            let _ = event_tx
                                .send(AppEvent::Error(format!("Folder send failed: {}", e)));
                        }
                    });
                }
                EngineAction::SendTransactionComplete {
                    peer_id,
                    transaction_id,
                } => {
                    let node = node.clone();
                    tokio::spawn(async move {
                        if let Err(e) = node
                            .send_transaction_complete(&peer_id, transaction_id)
                            .await
                        {
                            tracing::error!(
                                "Failed to send completion for {}: {}",
                                transaction_id,
                                e
                            );
                        }
                    });
                }
                EngineAction::AcceptResume {
                    peer_id,
                    transaction_id,
                } => {
                    let node = node.clone();
                    tokio::spawn(async move {
                        // Wait for the peer to appear in the connection map.
                        // The resume request can arrive via the data channel
                        // before the connection setup has finished registering
                        // the peer.
                        if !node
                            .wait_for_peer(&peer_id, std::time::Duration::from_secs(5))
                            .await
                        {
                            tracing::error!(
                                "Failed to accept resume: peer {} not connected after wait",
                                peer_id
                            );
                            return;
                        }
                        if let Err(e) = node
                            .accept_transaction_resume(&peer_id, transaction_id)
                            .await
                        {
                            tracing::error!("Failed to accept resume: {}", e);
                        }
                    });
                }
                EngineAction::SendResumeRequest {
                    peer_id,
                    transaction_id,
                    resume_info,
                } => {
                    let node = node.clone();
                    tokio::spawn(async move {
                        if let Err(e) = node
                            .send_resume_request(&peer_id, transaction_id, resume_info)
                            .await
                        {
                            tracing::error!(
                                "Failed to send resume request for {}: {}",
                                transaction_id,
                                e
                            );
                        }
                    });
                }
                EngineAction::ResendFiles {
                    peer_id,
                    transaction_id,
                } => {
                    // Re-send only the incomplete files for this transaction.
                    // Uses the chunk bitmap to skip already-received chunks,
                    // handling non-contiguous gaps correctly.
                    // The receiver's StreamingFileWriter::resume() opens the
                    // existing temp file without truncating, so partial data
                    // is preserved across reconnects.
                    let txn_data: Option<(
                        Option<String>,
                        Vec<(uuid::Uuid, String, Option<crate::core::pipeline::chunk::ChunkBitmap>)>,
                        bool,
                    )> = self
                        .app
                        .engine
                        .transactions()
                        .get(&transaction_id)
                        .map(|txn| {
                            let source_path = self
                                .app
                                .engine
                                .source_path(&transaction_id)
                                .map(|s| s.to_string());
                            // Include chunk bitmap for precise resume
                            let file_entries: Vec<(
                                uuid::Uuid,
                                String,
                                Option<crate::core::pipeline::chunk::ChunkBitmap>,
                            )> = txn
                                .file_order
                                .iter()
                                .filter_map(|fid| {
                                    txn.files.get(fid).and_then(|f| {
                                        if !f.completed {
                                            Some((
                                                *fid,
                                                f.relative_path.clone(),
                                                f.chunk_bitmap.clone(),
                                            ))
                                        } else {
                                            None
                                        }
                                    })
                                })
                                .collect();
                            let is_folder = txn.parent_dir.is_some();
                            (source_path, file_entries, is_folder)
                        });

                    if let Some((Some(source_path), file_entries, is_folder)) = txn_data {
                        if file_entries.is_empty() {
                            tracing::info!(
                                "Resume: all files already complete for {}",
                                transaction_id
                            );
                        } else if is_folder {
                            // Folder resume: re-send incomplete files using their bitmaps
                            let node = node.clone();
                            let event_tx = node.event_tx().clone();
                            // Extract (file_id, path, bitmap) for folder resume
                            let folder_entries: Vec<(
                                uuid::Uuid,
                                String,
                                Option<crate::core::pipeline::chunk::ChunkBitmap>,
                            )> = file_entries;
                            tracing::info!(
                                "Resume: re-sending {} folder files for {} (with chunk bitmaps)",
                                folder_entries.len(),
                                transaction_id
                            );
                            for (fid, path, bitmap) in &folder_entries {
                                let missing = bitmap
                                    .as_ref()
                                    .map(|b| b.missing_count())
                                    .unwrap_or(0);
                                tracing::debug!(
                                    "  file {} '{}' ({} missing chunks)",
                                    fid, path, missing
                                );
                            }
                            tokio::spawn(async move {
                                if !node
                                    .wait_for_peer(&peer_id, std::time::Duration::from_secs(5))
                                    .await
                                {
                                    tracing::error!(
                                        "Resume folder send error: peer {} not connected after wait",
                                        peer_id
                                    );
                                    return;
                                }
                                // Send each file with its bitmap
                                for (file_id, rel_path, bitmap) in folder_entries {
                                    let full_path = std::path::Path::new(&source_path).join(&rel_path);
                                    let full_path_str = full_path.to_string_lossy().to_string();
                                    
                                    if let Some(bm) = bitmap {
                                        if let Err(e) = node
                                            .send_file_data_resuming(
                                                &peer_id, file_id, &full_path_str, &rel_path, bm,
                                            )
                                            .await
                                        {
                                            tracing::error!(
                                                "Resume folder file send error for {}: {}",
                                                rel_path, e
                                            );
                                            let _ = event_tx.send(AppEvent::Error(format!(
                                                "Resume folder file send failed ({}): {}",
                                                rel_path, e
                                            )));
                                            return;
                                        }
                                    } else {
                                        // No bitmap - send from beginning
                                        if let Err(e) = node
                                            .send_file_data(
                                                &peer_id, file_id, &full_path_str, &rel_path,
                                            )
                                            .await
                                        {
                                            tracing::error!(
                                                "Resume folder file send error for {}: {}",
                                                rel_path, e
                                            );
                                            let _ = event_tx.send(AppEvent::Error(format!(
                                                "Resume folder file send failed ({}): {}",
                                                rel_path, e
                                            )));
                                            return;
                                        }
                                    }
                                }
                            });
                        } else {
                            // Single file resume — use bitmap for precise resume
                            if let Some((file_id, filename, bitmap)) = file_entries.into_iter().next() {
                                let node = node.clone();
                                let event_tx = node.event_tx().clone();
                                let missing = bitmap
                                    .as_ref()
                                    .map(|b| b.missing_count())
                                    .unwrap_or(0);
                                tracing::info!(
                                    "Resume: re-sending file '{}' for {} ({} missing chunks)",
                                    filename,
                                    transaction_id,
                                    missing
                                );
                                tokio::spawn(async move {
                                    if !node
                                        .wait_for_peer(&peer_id, std::time::Duration::from_secs(5))
                                        .await
                                    {
                                        tracing::error!(
                                            "Resume file send error: peer {} not connected after wait",
                                            peer_id
                                        );
                                        return;
                                    }
                                    
                                    let result = if let Some(bm) = bitmap {
                                        node.send_file_data_resuming(
                                            &peer_id, file_id, &source_path, &filename, bm,
                                        )
                                        .await
                                    } else {
                                        // No bitmap - send from beginning
                                        node.send_file_data(
                                            &peer_id, file_id, &source_path, &filename,
                                        )
                                        .await
                                    };
                                    
                                    if let Err(e) = result {
                                        tracing::error!(
                                            "Resume file send error for {}: {}",
                                            filename,
                                            e
                                        );
                                        let _ = event_tx.send(AppEvent::Error(format!(
                                            "Resume file send failed ({}): {}",
                                            filename, e
                                        )));
                                    }
                                });
                            }
                        }
                    } else {
                        tracing::warn!("Resume: no source path for transaction {}", transaction_id);
                    }
                }
                EngineAction::CancelTransaction {
                    peer_id,
                    transaction_id,
                } => {
                    let node = node.clone();
                    tokio::spawn(async move {
                        if let Err(e) = node.send_transaction_cancel(&peer_id, transaction_id).await
                        {
                            tracing::error!("Failed to send cancel for {}: {}", transaction_id, e);
                        }
                    });
                }
                EngineAction::HandleRemoteFetch {
                    peer_id,
                    path,
                    is_folder,
                } => {
                    if is_folder {
                        // Collect folder metadata (paths + sizes) without reading contents
                        match collect_folder_metadata(&path).await {
                            Ok((dirname, files)) => {
                                if files.is_empty() {
                                    tracing::warn!("Remote fetch: folder '{}' is empty", path);
                                } else {
                                    match self
                                        .app
                                        .engine
                                        .initiate_folder_send(&peer_id, &dirname, files, &path)
                                    {
                                        Ok(outcome) => {
                                            if let Some(status) = outcome.status {
                                                self.app.notify.info(status);
                                            }
                                            for a in outcome.actions {
                                                queue.push_back(a);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::error!(
                                                "Remote fetch: failed to initiate folder send for '{}': {}",
                                                path,
                                                e
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Remote fetch: failed to read folder metadata for '{}': {}",
                                    path,
                                    e
                                );
                            }
                        }
                    } else {
                        match tokio::fs::metadata(&path).await {
                            Ok(meta) => {
                                let filesize = meta.len();
                                let filename = std::path::Path::new(&path)
                                    .file_name()
                                    .map(|n| n.to_string_lossy().to_string())
                                    .unwrap_or_else(|| "file".to_string());
                                match self
                                    .app
                                    .engine
                                    .initiate_file_send(&peer_id, &filename, filesize, &path)
                                {
                                    Ok(outcome) => {
                                        if let Some(status) = outcome.status {
                                            self.app.notify.info(status);
                                        }
                                        for a in outcome.actions {
                                            queue.push_back(a);
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            "Remote fetch: failed to initiate file send for '{}': {}",
                                            path,
                                            e
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Remote fetch: failed to read file metadata for '{}': {}",
                                    path,
                                    e
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Collect folder file metadata (relative paths + sizes) without reading file contents.
/// Returns `(dirname, Vec<(relative_path, filesize)>)`.
async fn collect_folder_metadata(
    folder_path: &str,
) -> anyhow::Result<(String, Vec<(String, u64)>)> {
    use std::path::Path;

    let root = Path::new(folder_path).to_path_buf();
    let dirname = root
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "folder".to_string());

    let mut files = Vec::new();
    collect_folder_metadata_recursive(&root, &root, &mut files).await?;
    Ok((dirname, files))
}

/// Recursively collect (relative_path, filesize) entries for a folder.
async fn collect_folder_metadata_recursive(
    root: &std::path::Path,
    current: &std::path::Path,
    files: &mut Vec<(String, u64)>,
) -> anyhow::Result<()> {
    let mut entries = tokio::fs::read_dir(current).await?;
    while let Some(entry) = entries.next_entry().await? {
        let file_type = entry.file_type().await?;
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            Box::pin(collect_folder_metadata_recursive(root, &path, files)).await?;
        } else if file_type.is_file() {
            let meta = tokio::fs::metadata(&path).await?;
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            files.push((relative, meta.len()));
        }
    }
    Ok(())
}
