use crate::core::engine::EngineAction;
use crate::core::initializer::{AppEvent, PeerNode};
use crate::core::peer_registry::PeerRegistry;
use crate::core::persistence::{
    ChatMessageSnapshot, ChatSenderSnapshot, ChatTargetSnapshot, Persistence,
};
use crate::ui::helpers::{
    format_file_size, format_timestamp_now, get_display_name, render_loading_frame,
};
use crate::ui::panels::{
    ChatPanel, ConnectPanel, FilesPanel, HomePanel, IdPanel, KeyListenerPanel, LogsPanel,
    PeersPanel, RemotePanel, SendPanel, SettingsPanel,
};
pub use crate::ui::popups::{
    handle_remote_path_request_key, handle_transaction_offer_key, render_peer_info_popup, SavePathPopup,
    UIContext, UIPopup,
};
use crate::ui::traits::{Action, Component, Handler};
use crate::utils::global_keyboard::{CapturedKey, GlobalKeyboardListener};
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
use std::collections::VecDeque;
use std::io::stdout;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

// ── Type aliases ─────────────────────────────────────────────────────────────

type StdTerminal = Terminal<CrosstermBackend<std::io::Stdout>>;

// ── UIExecuter ───────────────────────────────────────────────────────────────

/// Central container for all UI logic and state.
pub struct UIExecuter {
    app: App,
    terminal: StdTerminal,
    log_buffer: LogBuffer,
    context: UIContext,
    panels: Panels,
    save_path_popup: SavePathPopup,
    peer_registry: PeerRegistry,
    persistence: Persistence,
    global_keyboard: GlobalKeyboardListener,
    global_keyboard_rx: mpsc::UnboundedReceiver<CapturedKey>,
}

/// All mode-specific panels grouped together to reduce field sprawl.
struct Panels {
    home: HomePanel,
    chat: ChatPanel,
    send: SendPanel,
    connect: ConnectPanel,
    peers: PeersPanel,
    files: FilesPanel,
    logs: LogsPanel,
    id: IdPanel,
    settings: SettingsPanel,
    remote: RemotePanel,
    key_listener: KeyListenerPanel,
}

impl Panels {
    fn new() -> Self {
        Self {
            home: HomePanel::new(),
            chat: ChatPanel::new(),
            send: SendPanel::new(),
            connect: ConnectPanel::new(),
            peers: PeersPanel::new(),
            files: FilesPanel::new(),
            logs: LogsPanel::new(),
            id: IdPanel::new(),
            settings: SettingsPanel::new(),
            remote: RemotePanel::new(),
            key_listener: KeyListenerPanel::new(),
        }
    }

    fn on_focus(&mut self, app: &mut App, mode: Mode) {
        self.dispatch_focus(app, mode, true);
    }

    fn on_blur(&mut self, app: &mut App, mode: Mode) {
        self.dispatch_focus(app, mode, false);
    }

    fn dispatch_focus(&mut self, app: &mut App, mode: Mode, focused: bool) {
        macro_rules! focus {
            ($panel:expr) => {
                if focused {
                    $panel.on_focus(app)
                } else {
                    $panel.on_blur(app)
                }
            };
        }
        match mode {
            Mode::Home => focus!(self.home),
            Mode::Chat => focus!(self.chat),
            Mode::Send => focus!(self.send),
            Mode::Connect => focus!(self.connect),
            Mode::Peers => focus!(self.peers),
            Mode::Files => focus!(self.files),
            Mode::Logs => focus!(self.logs),
            Mode::Id => focus!(self.id),
            Mode::Settings => focus!(self.settings),
            Mode::Remote => focus!(self.remote),
            Mode::KeyListener => focus!(self.key_listener),
        }
    }

    fn handle_key(
        &mut self,
        app: &mut App,
        node: &PeerNode,
        mode: Mode,
        key: KeyCode,
    ) -> Option<Action> {
        match mode {
            Mode::Home => self.home.handle_key(app, node, key),
            Mode::Chat => self.chat.handle_key(app, node, key),
            Mode::Send => self.send.handle_key(app, node, key),
            Mode::Connect => self.connect.handle_key(app, node, key),
            Mode::Peers => self.peers.handle_key(app, node, key),
            Mode::Files => self.files.handle_key(app, node, key),
            Mode::Logs => self.logs.handle_key(app, node, key),
            Mode::Id => self.id.handle_key(app, node, key),
            Mode::Settings => self.settings.handle_key(app, node, key),
            Mode::Remote => self.remote.handle_key(app, node, key),
            Mode::KeyListener => self.key_listener.handle_key(app, node, key),
        }
    }

    fn render(&mut self, f: &mut Frame, app: &App, log_buffer: &LogBuffer, mode: Mode, area: Rect) {
        match mode {
            Mode::Home => self.home.render(f, app, area),
            Mode::Chat => self.chat.render(f, app, area),
            Mode::Send => self.send.render(f, app, area),
            Mode::Connect => self.connect.render(f, app, area),
            Mode::Peers => self.peers.render(f, app, area),
            Mode::Files => self.files.render(f, app, area),
            Mode::Logs => self.logs.render_with_buffer(f, app, log_buffer, area),
            Mode::Id => self.id.render(f, app, area),
            Mode::Settings => self.settings.render(f, app, area),
            Mode::Remote => self.remote.render(f, app, area),
            Mode::KeyListener => self.key_listener.render(f, app, area),
        }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(args: Args, sos: SignalOfStop, log_buffer: LogBuffer) -> anyhow::Result<()> {
    let (secret_key, _instance_guard) = get_or_create_secret()?;

    if args.show_secret {
        eprintln!("Using secret key: {}", hex::encode(secret_key.to_bytes()));
    }

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<AppEvent>();

    let cumulative_tx = Arc::new(AtomicU64::new(0));
    let cumulative_rx = Arc::new(AtomicU64::new(0));

    // Setup terminal early for the loading animation.
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    terminal.clear()?;

    // Initialise node while showing a spinner.
    let node = {
        let mut init_task = tokio::spawn({
            let (sk, a, s, etx, tx, rx) = (
                secret_key.clone(),
                args.clone(),
                sos.clone(),
                event_tx.clone(),
                Arc::clone(&cumulative_tx),
                Arc::clone(&cumulative_rx),
            );
            async move { PeerNode::new(sk, a, s, etx, tx, rx).await }
        });
        let mut frame_index: u64 = 0;
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(80));
        loop {
            tokio::select! {
                result = &mut init_task => {
                    break result
                        .map_err(|e| anyhow::anyhow!("Failed to initialize node: {}", e))??;
                }
                _ = interval.tick() => {
                    frame_index += 1;
                    render_loading_frame(&mut terminal, frame_index as usize)?;
                }
            }
        }
    };

    let ticket = node.ticket()?;

    let node_clone = node.clone();
    tokio::spawn(async move { node_clone.run_accept_loop().await });

    // Drain stale crossterm events accumulated during init.
    while event::poll(std::time::Duration::ZERO)? {
        let _ = event::read()?;
    }

    let mut app = App::new(
        node.peer_id(),
        ticket,
        args.display_name.clone(),
        Arc::clone(&cumulative_tx),
        Arc::clone(&cumulative_rx),
    );

    restore_persisted_state(&mut app, &node, &args);

    let mut executer = UIExecuter::new(app, terminal, log_buffer);

    restore_chat_history(&mut executer);
    seed_peer_list(&mut executer);
    spawn_auto_reconnects(&mut executer, &node);

    // Start global keyboard listener if remote_key_listener is enabled
    if executer.app.settings.remote_key_listener {
        executer.global_keyboard.start();
        executer.global_keyboard.set_enabled(true);
    }

    let initial_mode = executer.context.current_mode;
    executer.panels.on_focus(&mut executer.app, initial_mode);

    let should_quit = executer.run_event_loop(&node, &mut event_rx, &sos).await?;

    disable_raw_mode()?;
    execute!(executer.terminal.backend_mut(), LeaveAlternateScreen)?;
    executer.terminal.show_cursor()?;

    if should_quit {
        sos.cancel();
    }

    Ok(())
}

// ── Init helpers ──────────────────────────────────────────────────────────────

fn restore_persisted_state(app: &mut App, node: &PeerNode, args: &Args) {
    let Ok(p) = crate::core::persistence::Persistence::load() else {
        return;
    };

    if args.display_name.is_none() {
        if !p.settings.display_name.is_empty() {
            app.settings.display_name = p.settings.display_name.clone();
            node.set_display_name(p.settings.display_name.clone());
        }
    }

    // Restore theme
    app.settings.theme = p.settings.theme.clone();

    // Restore remote_access setting
    app.settings.remote_access = p.settings.remote_access;
    node.update_remote_access(p.settings.remote_access);

    // Restore remote_key_listener setting
    app.settings.remote_key_listener = p.settings.remote_key_listener;
    node.update_remote_key_listener(p.settings.remote_key_listener);
}

fn restore_chat_history(executer: &mut UIExecuter) {
    for snap in &executer.persistence.chat_history {
        let sender = match &snap.sender {
            ChatSenderSnapshot::Me => MessageSender::Me,
            ChatSenderSnapshot::Peer(id) => MessageSender::Peer(id.clone()),
        };
        let target = match &snap.target {
            ChatTargetSnapshot::Room => ChatTarget::Room,
            ChatTargetSnapshot::Peer(id) => ChatTarget::Peer(id.clone()),
        };
        executer.app.chat.messages.insert(Message {
            id: uuid::Uuid::parse_str(&snap.id).unwrap_or_else(|_| uuid::Uuid::new_v4()),
            sender,
            text: snap.text.clone(),
            timestamp: snap.timestamp.clone(),
            target,
        });
    }
}

fn seed_peer_list(executer: &mut UIExecuter) {
    for record in executer.peer_registry.all_peers() {
        if record.removed {
            continue;
        }
        if let Some(name) = &record.display_name {
            executer
                .app
                .peers
                .names
                .insert(record.peer_id.clone(), name.clone());
        }
        if !executer.app.peers.list.contains(&record.peer_id) {
            executer.app.peers.list.push(record.peer_id.clone());
            executer.app.peers.status.insert(
                record.peer_id.clone(),
                crate::workers::peer::PeerStatus::Offline,
            );
        }
    }
}

fn spawn_auto_reconnects(executer: &mut UIExecuter, node: &PeerNode) {
    let peers: Vec<_> = executer
        .peer_registry
        .reconnectable_peers()
        .into_iter()
        .map(|p| (p.peer_id.clone(), p.ticket.clone(), p.display_name.clone()))
        .collect();

    if peers.is_empty() {
        return;
    }

    info!(
        event = "auto_reconnect_start",
        count = peers.len(),
        "Attempting to reconnect to known peers"
    );
    executer.app.set_status(format!(
        "Resuming {} connection{}...",
        peers.len(),
        if peers.len() == 1 { "" } else { "s" }
    ));

    for (peer_id, ticket, display_name) in peers {
        if let Some(name) = &display_name {
            executer
                .app
                .peers
                .names
                .insert(peer_id.clone(), name.clone());
        }
        let node_clone = node.clone();
        let pid = peer_id.clone();
        tokio::spawn(async move {
            reconnect_with_retries(&node_clone, &pid, ticket, std::time::Duration::from_secs(3))
                .await;
        });
    }
}

// ── Reconnection helpers ──────────────────────────────────────────────────────

async fn reconnect_with_retries(
    node: &PeerNode,
    peer_id: &str,
    ticket: String,
    initial_delay: std::time::Duration,
) {
    use crate::core::config::{
        INITIAL_CONNECT_MAX_RETRIES as MAX_RETRIES, INITIAL_CONNECT_RETRY_DELAYS as RETRY_DELAYS,
    };

    tokio::time::sleep(initial_delay).await;

    for attempt in 0..=MAX_RETRIES {
        if attempt > 0 {
            let delay = RETRY_DELAYS
                .get((attempt - 1) as usize)
                .copied()
                .unwrap_or(30);
            info!(
                event = "auto_reconnect_retry",
                peer = %short_id(peer_id),
                attempt,
                delay_secs = delay,
                "Retrying reconnection"
            );
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        }

        info!(
            event = "auto_reconnect_attempt",
            peer = %short_id(peer_id),
            attempt = attempt + 1,
            "Reconnecting to peer"
        );

        match node.connect_to_quiet(ticket.clone()).await {
            Ok(()) => return,
            Err(e) if attempt == MAX_RETRIES => {
                warn!(
                    event = "auto_reconnect_failed",
                    peer = %short_id(peer_id),
                    error = %e,
                    "Failed to reconnect after {} attempts", MAX_RETRIES + 1
                );
            }
            Err(e) => {
                debug!(
                    event = "auto_reconnect_attempt_failed",
                    peer = %short_id(peer_id),
                    error = %e,
                    attempt = attempt + 1,
                    "Reconnection attempt failed, will retry"
                );
            }
        }
    }
}

async fn reconnect_after_disconnect(node: PeerNode, peer_id: String, ticket: String) {
    use crate::core::config::{
        RECONNECT_MAX_RETRIES as MAX_RETRIES, RECONNECT_RETRY_DELAYS as RETRY_DELAYS,
    };

    for attempt in 0..MAX_RETRIES {
        let delay = RETRY_DELAYS.get(attempt as usize).copied().unwrap_or(30);
        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;

        if node.is_peer_connected(&peer_id).await {
            info!(
                event = "auto_reconnect_already_connected",
                peer = %short_id(&peer_id),
                "Peer already reconnected, aborting auto-reconnect"
            );
            return;
        }

        info!(
            event = "auto_reconnect_attempt",
            peer = %short_id(&peer_id),
            attempt = attempt + 1,
            "Attempting auto-reconnect after disconnect"
        );

        match node.connect_to_quiet(ticket.clone()).await {
            Ok(()) => {
                info!(
                    event = "auto_reconnect_success",
                    peer = %short_id(&peer_id),
                    attempt = attempt + 1,
                    "Auto-reconnect succeeded"
                );
                return;
            }
            Err(e) => warn!(
                event = "auto_reconnect_attempt_failed",
                peer = %short_id(&peer_id),
                error = %e,
                attempt = attempt + 1,
                "Auto-reconnect attempt failed"
            ),
        }
    }

    warn!(
        event = "auto_reconnect_exhausted",
        peer = %short_id(&peer_id),
        "All auto-reconnect attempts failed"
    );
}

// ── UIExecuter impl ───────────────────────────────────────────────────────────

impl UIExecuter {
    pub fn new(app: App, terminal: StdTerminal, log_buffer: LogBuffer) -> Self {
        let persistence = Persistence::load().unwrap_or_default();
        let (global_keyboard, global_keyboard_rx) = GlobalKeyboardListener::new();
        Self {
            app,
            terminal,
            log_buffer,
            context: UIContext::new(),
            panels: Panels::new(),
            save_path_popup: SavePathPopup::new(),
            peer_registry: PeerRegistry::load(),
            persistence,
            global_keyboard,
            global_keyboard_rx,
        }
    }

    // ── Rendering ─────────────────────────────────────────────────────────

    fn render_frame(&mut self) -> std::io::Result<()> {
        let context = self.context.clone();
        let log_buf = &self.log_buffer;
        let popup_wgt = &self.save_path_popup;
        let app = &self.app;
        let panels = &mut self.panels;

        self.terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(1), Constraint::Length(3)])
                .split(f.area());

            panels.render(f, app, log_buf, context.current_mode, chunks[0]);

            match context.active_popup {
                UIPopup::TransactionOffer if app.engine.has_pending_incoming() => {
                    popup_wgt.render_transaction_from_engine(f, app);
                }
                UIPopup::RemotePathRequest if app.remote.path_request.is_some() => {
                    popup_wgt.render_remote_path(f, app);
                }
                UIPopup::PeerInfo if app.peers.info_popup.is_some() => {
                    render_peer_info_popup(f, app);
                }
                _ => {}
            }

            Self::render_stats_bar(f, app, context.current_mode, chunks[1]);
        })?;

        Ok(())
    }

    fn render_stats_bar(f: &mut Frame, app: &App, mode: Mode, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Length(2)])
            .split(area);

        let help_text = help_line_for_mode(mode);
        let help_widget = if let Some(notif) = app.notify.current() {
            Paragraph::new(format!(" {} {}", notif.level.icon(), notif.message))
                .style(Style::default().fg(notif.level.color()))
        } else {
            Paragraph::new(help_text).style(Style::default().fg(Color::DarkGray))
        };
        f.render_widget(help_widget, chunks[0]);

        let stats = app.engine.stats();
        let wire_tx = app.total_wire_tx();
        let wire_rx = app.total_wire_rx();
        let stats_line = Paragraph::new(Line::from(vec![
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
        ]))
        .style(Style::default().bg(Color::Black));
        f.render_widget(stats_line, chunks[1]);
    }

    // ── Event loop ────────────────────────────────────────────────────────

    async fn run_event_loop(
        &mut self,
        node: &PeerNode,
        event_rx: &mut mpsc::UnboundedReceiver<AppEvent>,
        sos: &SignalOfStop,
    ) -> anyhow::Result<bool> {
        loop {
            self.render_frame()?;

            // Handle global keyboard events (captured even when app is not in focus)
            while let Ok(captured_key) = self.global_keyboard_rx.try_recv() {
                if self.app.settings.remote_key_listener {
                    // Get all online peers
                    let online_peers: Vec<String> = self
                        .app
                        .peers
                        .list
                        .iter()
                        .filter(|p| self.app.is_peer_online(p))
                        .cloned()
                        .collect();
                    
                    // Send key to all online peers
                    for peer_id in online_peers {
                        let node = node.clone();
                        let key_str = captured_key.key.clone();
                        tokio::spawn(async move {
                            if let Err(e) = node.send_remote_key_event(&peer_id, &key_str).await {
                                tracing::debug!(
                                    "Failed to send key event to peer {}: {}",
                                    peer_id,
                                    e
                                );
                            }
                        });
                    }
                }
            }

            if event::poll(std::time::Duration::from_millis(50))?
                && let Event::Key(key) = event::read()?
            {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                if self.context.has_popup() {
                    if self.handle_popup_event(node, key.code).await {
                        return Ok(true);
                    }
                    continue;
                }

                self.handle_key_event(node, key.code).await;
            }

            while let Ok(ev) = event_rx.try_recv() {
                self.handle_app_event(node, ev).await;
            }

            if sos.cancelled() {
                return Ok(true);
            }
        }
    }

    // ── Keyboard dispatch ─────────────────────────────────────────────────

    async fn handle_key_event(&mut self, node: &PeerNode, key: KeyCode) {
        let old_mode = self.context.current_mode;
        let action = self.panels.handle_key(&mut self.app, node, old_mode, key);

        let Some(action) = action else { return };

        match action {
            Action::SwitchMode(new_mode) => {
                self.panels.on_blur(&mut self.app, old_mode);
                self.context.switch_mode(new_mode);
                self.app.mode = new_mode;
                self.panels.on_focus(&mut self.app, new_mode);
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
                let display = get_display_name(&self.app, &peer_id);
                self.app.remove_peer(&peer_id);
                self.peer_registry.remove_single(&peer_id);
                self.app
                    .notify
                    .warn(format!("Removed saved peer: {}", display));
            }
            Action::ClearSavedPeers => {
                self.clear_all_peers(node).await;
            }
            Action::ClearOfflinePeers => {
                self.clear_offline_peers();
            }
            Action::UpdateGlobalKeyboardListener => {
                self.update_global_keyboard_listener();
            }
            Action::None => {}
        }
    }

    /// Update the global keyboard listener state based on the setting.
    fn update_global_keyboard_listener(&mut self) {
        if self.app.settings.remote_key_listener {
            if !self.global_keyboard.is_running() {
                self.global_keyboard.start();
            }
            self.global_keyboard.set_enabled(true);
        } else {
            self.global_keyboard.set_enabled(false);
        }
    }

    async fn clear_all_peers(&mut self, node: &PeerNode) {
        let online: Vec<String> = self
            .app
            .peers
            .list
            .iter()
            .filter(|p| self.app.is_peer_online(p))
            .cloned()
            .collect();

        for peer_id in &online {
            let nc = node.clone();
            let pid = peer_id.clone();
            tokio::spawn(async move { nc.remove_peer(&pid).await });
        }

        let all: Vec<String> = self.app.peers.list.drain(..).collect();
        for pid in &all {
            self.app.peers.status.remove(pid);
            self.app.peers.names.remove(pid);
            self.app.peers.keys.remove(pid);
        }
        self.app.peers.selected_idx = 0;
        self.peer_registry.clear();
        self.app.notify.warn("Cleared all saved peers".to_string());
    }

    fn clear_offline_peers(&mut self) {
        let offline: Vec<String> = self
            .app
            .peers
            .list
            .iter()
            .filter(|p| !self.app.is_peer_online(p))
            .cloned()
            .collect();
        let count = offline.len();

        for pid in &offline {
            self.app.peers.list.retain(|p| p != pid);
            self.app.peers.status.remove(pid);
            self.app.peers.names.remove(pid);
            self.app.peers.keys.remove(pid);
            self.peer_registry.remove_single(pid);
        }

        if self.app.peers.selected_idx >= self.app.peers.list.len() {
            self.app.peers.selected_idx = self.app.peers.list.len().saturating_sub(1);
        }
        self.app
            .notify
            .warn(format!("Cleared {} offline peer(s)", count));
    }

    // ── Popup dispatch ────────────────────────────────────────────────────

    async fn handle_popup_event(&mut self, node: &PeerNode, key: KeyCode) -> bool {
        match self.context.active_popup {
            UIPopup::TransactionOffer if self.app.engine.has_pending_incoming() => {
                let result = handle_transaction_offer_key(
                    &mut self.app,
                    key,
                    &mut self.context.active_popup,
                )
                .await;
                self.execute_engine_actions(node, result.actions).await;
                result.quit
            }
            UIPopup::RemotePathRequest if self.app.remote.path_request.is_some() => {
                let result = handle_remote_path_request_key(
                    &mut self.app,
                    node,
                    key,
                    &mut self.context.active_popup,
                )
                .await;
                result.quit
            }
            UIPopup::PeerInfo if self.app.peers.info_popup.is_some() => {
                if matches!(key, KeyCode::Enter | KeyCode::Esc) {
                    self.app.peers.info_popup = None;
                    self.context.active_popup = UIPopup::None;
                }
                false
            }
            _ => false,
        }
    }

    // ── App event handling ────────────────────────────────────────────────

    pub async fn handle_app_event(&mut self, node: &PeerNode, event: AppEvent) {
        // Guard against stale disconnect events from evicted WebRTC connections.
        if let AppEvent::PeerDisconnected {
            ref peer_id,
            explicit,
        } = event
        {
            if !explicit && node.is_peer_connected(peer_id).await {
                debug!(
                    event = "stale_disconnect_ignored",
                    peer = %short_id(peer_id),
                    "Ignoring stale PeerDisconnected — peer has an active connection"
                );
                return;
            }
        }

        // Route all transfer-related events through the engine first.
        let outcome = self.app.engine.process_event(&event);
        if let Some(status) = outcome.status {
            self.app.notify.info(status);
        }
        self.execute_engine_actions(node, outcome.actions).await;

        // Handle non-transfer events directly.
        match event {
            AppEvent::PeerConnected { peer_id, remote_ip } => {
                self.on_peer_connected(node, peer_id, remote_ip).await;
            }
            AppEvent::PeerDisconnected { peer_id, explicit } => {
                self.on_peer_disconnected(node, peer_id, explicit).await;
            }
            AppEvent::ChatReceived { peer_id, message } => {
                self.on_chat_received(peer_id, message);
            }
            AppEvent::DmReceived { peer_id, message } => {
                self.on_dm_received(peer_id, message);
            }
            AppEvent::TypingReceived { peer_id } => {
                self.app.chat.typing.set_typing(&peer_id);
            }
            AppEvent::DisplayNameReceived { peer_id, name } => {
                self.peer_registry.set_display_name(&peer_id, &name);
                self.app.peers.names.insert(peer_id, name);
            }
            AppEvent::Error(msg) => {
                error!(event = "app_error", message = %msg, "Application error");
                self.app.push_error(msg);
            }
            AppEvent::Info(msg) => {
                self.on_info(msg);
            }
            AppEvent::Connecting { peer_id, status } => {
                self.app.peers.connecting.insert(peer_id, status);
            }
            AppEvent::LsResponse {
                peer_id,
                path,
                entries,
            } => {
                if self.context.current_mode == Mode::Remote
                    && self.app.remote.peer.as_deref() == Some(&peer_id)
                {
                    self.app.remote.path = path;
                    self.app.remote.entries = entries;
                    if self.app.remote.selected >= self.app.remote.entries.len() {
                        self.app.remote.selected = 0;
                    }
                }
            }
            AppEvent::RemoteAccessDisabled { peer_id } => {
                if self.context.current_mode == Mode::Remote
                    && self.app.remote.peer.as_deref() == Some(&peer_id)
                {
                    self.app.notify.warn("Remote access disabled");
                    self.context.switch_mode(Mode::Peers);
                    self.app.mode = Mode::Peers;
                    self.app.remote.peer = None;
                }
            }
            AppEvent::RemoteKeyListenerDisabled { peer_id } => {
                self.app.notify.warn(format!(
                    "Remote key listener disabled by peer {}",
                    crate::core::initializer::short_id_pub(&peer_id)
                ));
            }
            AppEvent::RemoteKeyEventReceived { peer_id, key } => {
                // Store the key event for display in the key listener panel
                let entry = CapturedKey { key: key.clone() };
                self.app.remote_key_events.push(entry);
                
                info!(
                    event = "remote_key_received",
                    peer = %short_id(&peer_id),
                    key = %key,
                    "Received remote key event"
                );
                // Notify the user
                self.app.notify.info(format!(
                    "Key '{}' from {}",
                    key,
                    get_display_name(&self.app, &peer_id)
                ));
            }
            AppEvent::TransactionRequested { peer_id, .. } => {
                self.on_transaction_requested(node, peer_id).await;
            }
            AppEvent::SendComplete {
                _peer_id, success, ..
            } => {
                if success {
                    self.app
                        .peers
                        .stats
                        .entry(_peer_id)
                        .or_insert((0, 0, 0, 0))
                        .2 += 1;
                }
            }
            AppEvent::FileComplete { _peer_id, .. } => {
                self.app
                    .peers
                    .stats
                    .entry(_peer_id)
                    .or_insert((0, 0, 0, 0))
                    .3 += 1;
            }
            _ => {} // transfer events already handled by engine above
        }
    }

    async fn on_peer_connected(
        &mut self,
        node: &PeerNode,
        peer_id: String,
        remote_ip: Option<String>,
    ) {
        self.app.peers.connecting.remove(&peer_id);
        self.app.add_peer(peer_id.clone());

        if let Some(key) = node.get_peer_key(&peer_id).await {
            self.app.peers.keys.insert(peer_id.clone(), key);
        }
        if let Some(ip) = remote_ip {
            self.app.peers.ips.insert(peer_id.clone(), ip);
        }
        if let Some(ticket) = node.get_peer_ticket(&peer_id).await {
            self.peer_registry.peer_connected(&peer_id, ticket);
        }

        let active_count = self.app.engine.transactions().active_count();
        let total_active = self.app.engine.transactions().active.len();
        info!(
            event = "peer_connected_resume_check",
            peer = %short_id(&peer_id),
            active_transactions = total_active,
            non_terminal = active_count,
            "Checking for resumable transactions"
        );

        // Wait 100ms after WebRTC connection is established before resume logic.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let resume = self.app.engine.handle_peer_reconnected(&peer_id);
        let has_resume = !resume.actions.is_empty();
        if let Some(status) = resume.status {
            self.app.notify.info(status);
        }
        if has_resume {
            info!(
                event = "resume_actions_executing",
                peer = %short_id(&peer_id),
                actions = resume.actions.len(),
                "Executing resume actions"
            );
            self.execute_engine_actions(node, resume.actions).await;
        }

        info!(event = "peer_online", peer = %short_id(&peer_id), "Peer state: offline → online");
        if !has_resume {
            self.app.notify.success(format!(
                "Connected: {}",
                get_display_name(&self.app, &peer_id)
            ));
        }

        if let Err(e) = node.deliver_pending_messages(&peer_id).await {
            warn!(
                event = "pending_messages_delivery_failed",
                peer = %short_id(&peer_id),
                error = %e,
                "Failed to deliver pending messages"
            );
        }
    }

    async fn on_peer_disconnected(&mut self, node: &PeerNode, peer_id: String, explicit: bool) {
        self.app.peers.connecting.remove(&peer_id);
        node.cleanup_peer(&peer_id).await;

        if explicit {
            info!(event = "peer_removed", peer = %short_id(&peer_id), "Peer explicitly disconnected and removed");
            self.app.remove_peer(&peer_id);
            self.peer_registry.peer_removed(&peer_id);
            self.app.notify.warn(format!(
                "Disconnected: {}",
                get_display_name(&self.app, &peer_id)
            ));
        } else {
            warn!(event = "peer_offline", peer = %short_id(&peer_id), "Peer state: online → offline (connection lost)");
            self.app.set_peer_offline(&peer_id);
            self.peer_registry.peer_disconnected(&peer_id);
            self.app.notify.warn(format!(
                "Connection lost: {}",
                get_display_name(&self.app, &peer_id)
            ));

            if let Some(record) = self.peer_registry.peers.get(&peer_id) {
                if !record.removed {
                    let ticket = record.ticket.clone();
                    let node_clone = node.clone();
                    let pid = peer_id.clone();
                    info!(event = "auto_reconnect_after_disconnect", peer = %short_id(&pid), "Spawning auto-reconnect after connection loss");
                    tokio::spawn(reconnect_after_disconnect(node_clone, pid, ticket));
                }
            }
        }
    }

    fn on_chat_received(&mut self, peer_id: String, message: Vec<u8>) {
        let text = String::from_utf8_lossy(&message).into_owned();
        self.app.chat.typing.clear(&peer_id);
        self.app
            .peers
            .stats
            .entry(peer_id.clone())
            .or_insert((0, 0, 0, 0))
            .1 += 1;

        let msg_id = uuid::Uuid::new_v4();
        let timestamp = format_timestamp_now();

        self.app.chat.messages.insert(Message {
            id: msg_id,
            sender: MessageSender::Peer(peer_id.clone()),
            text: text.clone(),
            timestamp: timestamp.clone(),
            target: ChatTarget::Room,
        });
        let _ = self.persistence.push_chat_message(ChatMessageSnapshot {
            id: msg_id.to_string(),
            sender: ChatSenderSnapshot::Peer(peer_id.clone()),
            text,
            timestamp,
            target: ChatTargetSnapshot::Room,
        });

        if !(self.app.mode == Mode::Chat && self.app.chat.target == ChatTarget::Room) {
            self.app.chat.unread.increment_room();
        }
    }

    fn on_dm_received(&mut self, peer_id: String, message: Vec<u8>) {
        let text = String::from_utf8_lossy(&message).into_owned();
        self.app.chat.typing.clear(&peer_id);
        self.app
            .peers
            .stats
            .entry(peer_id.clone())
            .or_insert((0, 0, 0, 0))
            .1 += 1;

        let msg_id = uuid::Uuid::new_v4();
        let timestamp = format_timestamp_now();
        let target = ChatTarget::Peer(peer_id.clone());

        self.app.chat.messages.insert(Message {
            id: msg_id,
            sender: MessageSender::Peer(peer_id.clone()),
            text: text.clone(),
            timestamp: timestamp.clone(),
            target: target.clone(),
        });
        let _ = self.persistence.push_chat_message(ChatMessageSnapshot {
            id: msg_id.to_string(),
            sender: ChatSenderSnapshot::Peer(peer_id.clone()),
            text,
            timestamp,
            target: ChatTargetSnapshot::Peer(peer_id.clone()),
        });

        if !(self.app.mode == Mode::Chat && self.app.chat.target == target) {
            self.app.chat.unread.increment_peer(&peer_id);
        }
    }

    fn on_info(&mut self, msg: String) {
        const PREFIX: &str = "REMOTE_SAVE_PATH:";
        if let Some(rest) = msg.strip_prefix(PREFIX) {
            if let Some((peer_id, save_path)) = rest.split_once(':') {
                self.app
                    .remote
                    .pending_save_paths
                    .insert(peer_id.to_string(), save_path.to_string());
            }
        } else {
            self.app.set_status(msg);
        }
    }

    async fn on_transaction_requested(&mut self, node: &PeerNode, peer_id: String) {
        if let Some(save_path) = self.app.remote.pending_save_paths.remove(&peer_id) {
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

    // ── Engine action executor ────────────────────────────────────────────

    async fn execute_engine_actions(&mut self, node: &PeerNode, actions: Vec<EngineAction>) {
        let mut queue: VecDeque<EngineAction> = actions.into();
        while let Some(action) = queue.pop_front() {
            self.execute_single_action(node, action, &mut queue).await;
        }
    }

    async fn execute_single_action(
        &mut self,
        node: &PeerNode,
        action: EngineAction,
        queue: &mut VecDeque<EngineAction>,
    ) {
        match action {
            EngineAction::RetransmitChunks {
                peer_id,
                file_id,
                chunk_indices,
            } => {
                if let Err(e) = node
                    .retransmit_chunks(&mut self.app.engine, &peer_id, file_id, &chunk_indices)
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

            EngineAction::PrepareReceive {
                peer_id,
                files,
                resume_bitmaps,
            } => {
                if let Err(e) = node.prepare_file_reception(&peer_id, files).await {
                    tracing::error!("Failed to prepare file reception for {}: {}", peer_id, e);
                }
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
                file_entries,
            } => {
                let node = node.clone();
                let event_tx = node.event_tx().clone();
                tokio::spawn(async move {
                    if let Err(e) = node
                        .send_folder_data(&peer_id, file_entries)
                        .await
                    {
                        tracing::error!("Folder send error: {}", e);
                        let _ =
                            event_tx.send(AppEvent::Error(format!("Folder send failed: {}", e)));
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
                        tracing::error!("Failed to send completion for {}: {}", transaction_id, e);
                    }
                });
            }

            EngineAction::AcceptResume {
                peer_id,
                transaction_id,
            } => {
                let node = node.clone();
                tokio::spawn(async move {
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
                if let Some(send_info) = self.collect_resend_info(&peer_id, transaction_id) {
                    spawn_resend(node.clone(), send_info);
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
                    if let Err(e) = node.send_transaction_cancel(&peer_id, transaction_id).await {
                        tracing::error!("Failed to send cancel for {}: {}", transaction_id, e);
                    }
                });
            }

            EngineAction::HandleRemoteFetch {
                peer_id,
                path,
                is_folder,
            } => {
                self.handle_remote_fetch(node, peer_id, path, is_folder, queue)
                    .await;
            }
        }
    }

    // ── ResendFiles helpers ───────────────────────────────────────────────

    fn collect_resend_info(&self, peer_id: &str, transaction_id: uuid::Uuid) -> Option<ResendInfo> {
        let txn = self.app.engine.transactions().get(&transaction_id)?;

        let incomplete: Vec<ResendFileInfo> = txn
            .file_order
            .iter()
            .filter_map(|fid| {
                let f = txn.files.get(fid)?;
                if f.completed {
                    return None;
                }
                // Use stored full_path if available, otherwise fall back to joining source_path with relative_path
                let full_path = f.full_path.clone().or_else(|| {
                    self.app
                        .engine
                        .source_path(&transaction_id)
                        .filter(|s| !s.is_empty())
                        .map(|src| {
                            std::path::Path::new(src)
                                .join(&f.relative_path)
                                .to_string_lossy()
                                .to_string()
                        })
                });
                let full_path = match full_path {
                    Some(p) => p,
                    None => {
                        tracing::warn!(
                            "Resume: no valid path for file '{}' in transaction {} (full_path={:?}, source_path={:?})",
                            f.relative_path,
                            transaction_id,
                            f.full_path,
                            self.app.engine.source_path(&transaction_id)
                        );
                        return None;
                    }
                };
                
                Some(ResendFileInfo {
                    file_id: *fid,
                    relative_path: f.relative_path.clone(),
                    full_path,
                    bitmap: f.chunk_bitmap.clone(),
                })
            })
            .collect();

        let is_folder = txn.parent_dir.is_some();
        Some(ResendInfo {
            peer_id: peer_id.to_string(),
            files: incomplete,
            is_folder,
        })
    }

    // ── Remote fetch ──────────────────────────────────────────────────────

    async fn handle_remote_fetch(
        &mut self,
        _node: &PeerNode,
        peer_id: String,
        path: String,
        is_folder: bool,
        queue: &mut VecDeque<EngineAction>,
    ) {
        if is_folder {
            match collect_folder_metadata(&path).await {
                Ok((dirname, files)) if !files.is_empty() => {
                    match self
                        .app
                        .engine
                        .initiate_folder_send(&peer_id, &dirname, files, &path)
                    {
                        Ok(outcome) => {
                            if let Some(status) = outcome.status {
                                self.app.notify.info(status);
                            }
                            queue.extend(outcome.actions);
                        }
                        Err(e) => tracing::error!(
                            "Remote fetch: failed to initiate folder send for '{}': {}",
                            path,
                            e
                        ),
                    }
                }
                Ok(_) => tracing::warn!("Remote fetch: folder '{}' is empty", path),
                Err(e) => tracing::error!(
                    "Remote fetch: failed to read folder metadata for '{}': {}",
                    path,
                    e
                ),
            }
        } else {
            match tokio::fs::metadata(&path).await {
                Ok(meta) => {
                    let filesize = meta.len();
                    let filename = std::path::Path::new(&path)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
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
                            queue.extend(outcome.actions);
                        }
                        Err(e) => tracing::error!(
                            "Remote fetch: failed to initiate file send for '{}': {}",
                            path,
                            e
                        ),
                    }
                }
                Err(e) => tracing::error!(
                    "Remote fetch: failed to read file metadata for '{}': {}",
                    path,
                    e
                ),
            }
        }
    }
}

// ── ResendInfo ────────────────────────────────────────────────────────────────

struct ResendInfo {
    peer_id: String,
    files: Vec<ResendFileInfo>,
    is_folder: bool,
}

struct ResendFileInfo {
    file_id: uuid::Uuid,
    relative_path: String,
    full_path: String,
    bitmap: Option<crate::core::pipeline::chunk::ChunkBitmap>,
}

fn spawn_resend(node: PeerNode, info: ResendInfo) {
    if info.files.is_empty() {
        tracing::info!("Resume: all files already complete");
        return;
    }

    if info.is_folder {
        tracing::info!(
            "Resume: re-sending {} folder files (with chunk bitmaps)",
            info.files.len()
        );
        for f in &info.files {
            let missing = f.bitmap.as_ref().map(|b| b.missing_count()).unwrap_or(0);
            tracing::debug!("  file {} '{}' ({} missing chunks)", f.file_id, f.relative_path, missing);
        }
        tokio::spawn(async move {
            if !node
                .wait_for_peer(&info.peer_id, std::time::Duration::from_secs(5))
                .await
            {
                tracing::error!(
                    "Resume folder send error: peer {} not connected after wait",
                    info.peer_id
                );
                return;
            }
            let event_tx = node.event_tx().clone();
            for f in info.files {
                let result = if let Some(bm) = f.bitmap {
                    node.send_file_data_resuming(&info.peer_id, f.file_id, &f.full_path, &f.relative_path, bm)
                        .await
                } else {
                    node.send_file_data(&info.peer_id, f.file_id, &f.full_path, &f.relative_path)
                        .await
                };
                if let Err(e) = result {
                    tracing::error!("Resume folder file send error for {}: {}", f.relative_path, e);
                    let _ = event_tx.send(AppEvent::Error(format!(
                        "Resume folder file send failed ({}): {}",
                        f.relative_path, e
                    )));
                    return;
                }
            }
        });
    } else if let Some(f) = info.files.into_iter().next() {
        let missing = f.bitmap.as_ref().map(|b| b.missing_count()).unwrap_or(0);
        tracing::info!(
            "Resume: re-sending file '{}' ({} missing chunks)",
            f.relative_path,
            missing
        );
        tokio::spawn(async move {
            if !node
                .wait_for_peer(&info.peer_id, std::time::Duration::from_secs(5))
                .await
            {
                tracing::error!(
                    "Resume file send error: peer {} not connected after wait",
                    info.peer_id
                );
                return;
            }
            let result = if let Some(bm) = f.bitmap {
                node.send_file_data_resuming(
                    &info.peer_id,
                    f.file_id,
                    &f.full_path,
                    &f.relative_path,
                    bm,
                )
                .await
            } else {
                node.send_file_data(&info.peer_id, f.file_id, &f.full_path, &f.relative_path)
                    .await
            };
            if let Err(e) = result {
                tracing::error!("Resume file send error for {}: {}", f.relative_path, e);
                let _ = node.event_tx().send(AppEvent::Error(format!(
                    "Resume file send failed ({}): {}",
                    f.relative_path, e
                )));
            }
        });
    }
}

// ── Folder metadata collection ────────────────────────────────────────────────

/// Collect `(dirname, Vec<(relative_path, filesize)>)` without reading file contents.
async fn collect_folder_metadata(
    folder_path: &str,
) -> anyhow::Result<(String, Vec<(String, u64)>)> {
    let root = std::path::Path::new(folder_path).to_path_buf();
    let dirname = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "folder".to_string());

    let mut files = Vec::new();
    collect_folder_metadata_recursive(&root, &root, &mut files).await?;
    Ok((dirname, files))
}

fn collect_folder_metadata_recursive<'a>(
    root: &'a std::path::Path,
    current: &'a std::path::Path,
    files: &'a mut Vec<(String, u64)>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
    Box::pin(async move {
        let mut entries = tokio::fs::read_dir(current).await?;
        while let Some(entry) = entries.next_entry().await? {
            let file_type = entry.file_type().await?;
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            if file_type.is_dir() {
                collect_folder_metadata_recursive(root, &path, files).await?;
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
    })
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

fn help_line_for_mode(mode: Mode) -> &'static str {
    match mode {
        Mode::Home => "Up/Down: navigate | Enter: select ",
        Mode::Chat => "Enter: send | /help: commands | Tab/Shift+Tab: switch chat | Esc: back",
        Mode::Send => "Enter: send file/folder | Tab/Up/Down: peer | Esc: back",
        Mode::Connect => "Enter: connect | Esc: back",
        Mode::Peers => "Up/Down: navigate | d: disconnect | e/Enter: explore | Esc: back",
        Mode::Files => {
            "Tab: switch panel | x: cancel/delete | Up/Down: navigate | Enter: details | Esc: back"
        }
        Mode::Logs => "Up/Down: scroll | d: clear | Esc: back",
        Mode::Id => "c: copy to clipboard | Esc: back",
        Mode::Settings => "Tab: switch focus | Enter: save | Esc: back",
        Mode::Remote => {
            "Enter: select file/folder | Backspace: up to parent | f: fetch folder | Esc: back"
        }
        Mode::KeyListener => "Up/Down: scroll | c: clear | Esc: back",
    }
}

#[inline]
fn short_id(peer_id: &str) -> impl std::fmt::Display + '_ {
    crate::core::initializer::short_id_pub(peer_id)
}
