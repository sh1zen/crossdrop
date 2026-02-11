use crate::core::engine::EngineAction;
use crate::core::initializer::{AppEvent, PeerNode};
use crate::core::peer_registry::PeerRegistry;
use crate::ui::helpers::{format_file_size, get_display_name, render_loading_frame};
use crate::ui::panels::{
    ChatPanel, ConnectPanel, FilesPanel, HomePanel, IdPanel, LogsPanel, PeersPanel, RemotePanel,
    SendPanel, SettingsPanel,
};
use crate::ui::popups::SavePathPopup;
use crate::ui::traits::{Action, Component, Handler};
use crate::utils::hash::get_or_create_secret;
use crate::utils::log_buffer::LogBuffer;
use crate::utils::sos::SignalOfStop;
use crate::workers::app::{AcceptingFileOffer, AcceptingFolderOffer, App, ChatTarget, FileDirection, FileRecord, Message, MessageSender, Mode, FileTransferStatus};
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
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Traccia lo stato del context UI - in che finestra siamo e cosa stiamo facendo
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UIPopup {
    None,
    FileOffer,
    FolderOffer,
    TransactionOffer,
    RemoteFileRequest,
    RemoteFolderRequest,
}

/// Context dell'interfaccia utente: traccia locazione e stato attuale
#[derive(Debug, Clone)]
pub struct UIContext {
    /// La modalità/finestra corrente dell'app
    pub current_mode: Mode,
    /// Quale popup è attivo, se presente
    pub active_popup: UIPopup,
    /// Se siamo in modalità editing path per i file offer
    pub file_path_editing: bool,
}

impl UIContext {
    pub fn new() -> Self {
        Self {
            current_mode: Mode::Home,
            active_popup: UIPopup::None,
            file_path_editing: false,
        }
    }

    /// Determina se un popup è attivo
    pub fn has_popup(&self) -> bool {
        self.active_popup != UIPopup::None
    }

    /// Cambia la modalità e aggiorna il context
    pub fn switch_mode(&mut self, new_mode: Mode) {
        self.current_mode = new_mode;
        self.active_popup = UIPopup::None;
        self.file_path_editing = false;
    }
}

/// Cycle a 3-button focus index forward (Tab) or backward (BackTab).
/// Buttons are indexed 0, 1, 2 in a circular sequence.
fn cycle_focus(current: usize, forward: bool) -> usize {
    if forward {
        match current { 0 => 1, 1 => 2, _ => 0 }
    } else {
        match current { 0 => 2, 1 => 0, _ => 1 }
    }
}

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
}

pub async fn run(args: Args, sos: SignalOfStop, log_buffer: LogBuffer) -> anyhow::Result<()> {
    // Acquire secret key with per-instance locking
    let (secret_key, _instance_guard) = get_or_create_secret()?;

    if args.show_secret {
        let secret_hex = hex::encode(secret_key.to_bytes());
        eprintln!("Using secret key: {secret_hex}");
    }

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<AppEvent>();

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

    let mut init_task = tokio::spawn(async move {
        PeerNode::new(node_secret, node_args, node_sos, node_event_tx).await
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
    let app = App::new(peer_id, ticket, args.display_name.clone());
    let mut executer = UIExecuter::new(app, terminal, node.clone(), log_buffer);

    // Auto-reconnect to known peers from the registry
    {
        let peers_to_reconnect: Vec<_> = executer.peer_registry.reconnectable_peers()
            .into_iter()
            .map(|p| (p.peer_id.clone(), p.ticket.clone(), p.display_name.clone()))
            .collect();

        if !peers_to_reconnect.is_empty() {
            info!(event = "auto_reconnect_start", count = peers_to_reconnect.len(), "Attempting to reconnect to known peers");
            for (peer_id, ticket, display_name) in peers_to_reconnect {
                // Pre-populate display name if we have one from last session
                if let Some(name) = &display_name {
                    executer.app.peer_names.insert(peer_id.clone(), name.clone());
                }
                let node_clone = node.clone();
                let pid = peer_id.clone();
                tokio::spawn(async move {
                    // Wait before first attempt to let the network stack settle
                    // and give remote peers time to come online.
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

                    const MAX_RETRIES: u32 = 3;
                    const RETRY_DELAYS: [u64; 3] = [5, 15, 30];

                    for attempt in 0..=MAX_RETRIES {
                        if attempt > 0 {
                            let delay = RETRY_DELAYS.get((attempt - 1) as usize).copied().unwrap_or(30);
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

                        match node_clone.connect_to(ticket.clone()).await {
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
    executer.call_on_focus(initial_mode);

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
        }
    }

    /// Chiama on_focus per il panel corrispondente alla modalità data
    fn call_on_focus(&mut self, mode: Mode) {
        match mode {
            Mode::Home => self.home_panel.on_focus(&mut self.app),
            Mode::Chat => self.chat_panel.on_focus(&mut self.app),
            Mode::Send => self.send_panel.on_focus(&mut self.app),
            Mode::Connect => self.connect_panel.on_focus(&mut self.app),
            Mode::Peers => self.peers_panel.on_focus(&mut self.app),
            Mode::Files => self.files_panel.on_focus(&mut self.app),
            Mode::Logs => self.logs_panel.on_focus(&mut self.app),
            Mode::Id => self.id_panel.on_focus(&mut self.app),
            Mode::Settings => self.settings_panel.on_focus(&mut self.app),
            Mode::Remote => self.remote_panel.on_focus(&mut self.app),
        }
    }

    /// Chiama on_blur per il panel corrispondente alla modalità data
    fn call_on_blur(&mut self, mode: Mode) {
        match mode {
            Mode::Home => self.home_panel.on_blur(&mut self.app),
            Mode::Chat => self.chat_panel.on_blur(&mut self.app),
            Mode::Send => self.send_panel.on_blur(&mut self.app),
            Mode::Connect => self.connect_panel.on_blur(&mut self.app),
            Mode::Peers => self.peers_panel.on_blur(&mut self.app),
            Mode::Files => self.files_panel.on_blur(&mut self.app),
            Mode::Logs => self.logs_panel.on_blur(&mut self.app),
            Mode::Id => self.id_panel.on_blur(&mut self.app),
            Mode::Settings => self.settings_panel.on_blur(&mut self.app),
            Mode::Remote => self.remote_panel.on_blur(&mut self.app),
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
        // Clone i dati necessari prima della chiusura per evitare borrow conflicts
        let context = self.context.clone();

        // Riferimenti ai panel e dati
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
        let save_path_popup = &self.save_path_popup;
        let app = &self.app;
        let log_buffer = &self.log_buffer;

        self.terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Min(1),    // main
                    Constraint::Length(3), // stats bar
                ])
                .split(f.area());

            // Renderizza il principale basato su context
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

            // Renderizza popup overlay
            match context.active_popup {
                UIPopup::FileOffer if app.accepting_file.is_some() => {
                    save_path_popup.render_file(f, app);
                }
                UIPopup::FolderOffer if app.accepting_folder.is_some() => {
                    save_path_popup.render_folder(f, app);
                }
                UIPopup::TransactionOffer if app.engine.has_pending_incoming() => {
                    save_path_popup.render_transaction_from_engine(f, app);
                }
                UIPopup::RemoteFileRequest if app.remote_file_request.is_some() => {
                    save_path_popup.render_remote_file(f, app);
                }
                UIPopup::RemoteFolderRequest if app.remote_folder_request.is_some() => {
                    save_path_popup.render_remote_folder(f, app);
                }
                _ => {}
            }

            // Renderizza stats bar
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
            Mode::Home => "Up/Down: navigate | Enter: select | c: copy ticket | Esc: quit",
            Mode::Chat => "Enter: send | /help: commands | Tab/Shift+Tab: switch chat | Esc: back",
            Mode::Send => "Enter: send file/folder | Tab/Up/Down: peer | Esc: back",
            Mode::Connect => "Enter: connect | Esc: back",
            Mode::Peers => "Up/Down: navigate | d: disconnect | e/Enter: explore | Esc: back",
            Mode::Files => "Esc: back",
            Mode::Logs => "Up/Down: scroll | d: clear | Esc: back",
            Mode::Id => "c: copy to clipboard | Esc: back",
            Mode::Settings => "Tab: switch focus | Enter: save | Esc: back",
            Mode::Remote => {
                "Enter: select file/folder | Backspace: up to parent | f: fetch folder | Esc: back"
            }
        };
        let help_line = if app.status.is_empty() {
            Paragraph::new(help).style(Style::default().fg(Color::DarkGray))
        } else {
            Paragraph::new(app.status.as_str()).style(Style::default().fg(Color::Yellow))
        };
        f.render_widget(help_line, chunks[0]);

        // Linea di statistiche — reads from TransferEngine (authoritative)
        // Shows wire bytes (post-compression/encryption) = what crosses the network boundary
        let stats = app.engine.stats();
        let stats_spans = vec![
            Span::styled(" TX: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format_file_size(stats.bytes_sent),
                Style::default().fg(Color::Green),
            ),
            Span::styled(
                format!(
                    " ({} msgs, {} files)",
                    stats.messages_sent, stats.files_sent
                ),
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
            // Show compression ratio if meaningful data has been transferred
            if stats.raw_bytes_sent > 0 && stats.bytes_sent > 0 && stats.raw_bytes_sent != stats.bytes_sent {
                Span::styled(
                    format!(
                        "  | ratio: {:.0}%",
                        (stats.bytes_sent as f64 / stats.raw_bytes_sent as f64) * 100.0
                    ),
                    Style::default().fg(Color::Magenta),
                )
            } else {
                Span::raw("")
            },
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
                            self.call_on_blur(old_mode);
                            self.context.switch_mode(new_mode);
                            self.app.mode = new_mode;
                            self.call_on_focus(new_mode);
                        }
                        Action::SetStatus(msg) => self.app.set_status(msg),
                        Action::EngineActions(actions) => {
                            self.execute_engine_actions(node, actions).await;
                        }
                        Action::ShowPopup(popup) => {
                            self.context.active_popup = popup;
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
            self.handle_transaction_offer_key(node, key).await
        } else if self.context.active_popup == UIPopup::FileOffer && self.app.accepting_file.is_some()
        {
            self.handle_file_offer_key(node, key).await
        } else if self.context.active_popup == UIPopup::FolderOffer
            && self.app.accepting_folder.is_some()
        {
            self.handle_folder_offer_key(node, key).await
        } else if self.context.active_popup == UIPopup::RemoteFileRequest
            && self.app.remote_file_request.is_some()
        {
            self.handle_remote_file_request_key(node, key).await
        } else if self.context.active_popup == UIPopup::RemoteFolderRequest
            && self.app.remote_folder_request.is_some()
        {
            self.handle_remote_folder_request_key(node, key).await
        } else {
            false
        }
    }

    /// Gestisce i tasti per il file offer popup
    async fn handle_file_offer_key(&mut self, node: &PeerNode, key: KeyCode) -> bool {
        match key {
            KeyCode::Tab | KeyCode::BackTab => {
                let forward = matches!(key, KeyCode::Tab);
                self.app.file_offer_button_focus = cycle_focus(self.app.file_offer_button_focus, forward);
                self.app.file_path_editing = self.app.file_offer_button_focus == 2;
                self.context.file_path_editing = self.app.file_path_editing;
            }
            KeyCode::Enter => {
                if self.app.file_path_editing {
                    self.app.file_offer_button_focus = 0;
                    self.app.file_path_editing = false;
                    self.context.file_path_editing = false;
                    return false;
                }

                let af = self.app.accepting_file.take().unwrap();
                let button_focus = self.app.file_offer_button_focus;
                self.app.file_offer_button_focus = 0;
                self.app.file_path_editing = false;
                self.context.file_path_editing = false;
                self.context.active_popup = UIPopup::None;

                if button_focus == 0 {
                    // Download button
                    self.process_file_offer_accept(node, af).await;
                } else {
                    // Cancel button
                    self.process_file_offer_reject(node, af).await;
                }
            }
            KeyCode::Backspace => {
                if self.app.file_path_editing {
                    if let Some(af) = &mut self.app.accepting_file {
                        af.save_path_input.pop();
                    }
                }
            }
            KeyCode::Char(c) => {
                if self.app.file_path_editing {
                    if let Some(af) = &mut self.app.accepting_file {
                        af.save_path_input.push(c);
                    }
                } else if c == 'n' || c == 'N' || c == 'c' || c == 'C' {
                    let af = self.app.accepting_file.take().unwrap();
                    self.app.file_offer_button_focus = 0;
                    self.app.file_path_editing = false;
                    self.context.file_path_editing = false;
                    self.context.active_popup = UIPopup::None;
                    self.process_file_offer_reject(node, af).await;
                }
            }
            KeyCode::Esc => {
                if self.app.file_path_editing {
                    self.app.file_offer_button_focus = 0;
                    self.app.file_path_editing = false;
                    self.context.file_path_editing = false;
                } else {
                    let af = self.app.accepting_file.take().unwrap();
                    self.app.file_offer_button_focus = 0;
                    self.app.file_path_editing = false;
                    self.context.file_path_editing = false;
                    self.context.active_popup = UIPopup::None;
                    self.process_file_offer_reject(node, af).await;
                }
            }
            _ => {}
        }
        false
    }

    /// Gestisce i tasti per il folder offer popup
    async fn handle_folder_offer_key(&mut self, node: &PeerNode, key: KeyCode) -> bool {
        match key {
            KeyCode::Tab | KeyCode::BackTab => {
                let forward = matches!(key, KeyCode::Tab);
                self.app.folder_offer_button_focus = cycle_focus(self.app.folder_offer_button_focus, forward);
                self.app.folder_path_editing = self.app.folder_offer_button_focus == 2;
            }
            KeyCode::Enter => {
                if self.app.folder_path_editing {
                    self.app.folder_offer_button_focus = 0;
                    self.app.folder_path_editing = false;
                    return false;
                }

                let af = self.app.accepting_folder.take().unwrap();
                let button_focus = self.app.folder_offer_button_focus;
                self.app.folder_offer_button_focus = 0;
                self.app.folder_path_editing = false;
                self.context.active_popup = UIPopup::None;

                if button_focus == 0 {
                    self.process_folder_offer_accept(node, af).await;
                } else {
                    self.process_folder_offer_reject(node, af).await;
                }
            }
            KeyCode::Backspace => {
                if self.app.folder_path_editing {
                    if let Some(af) = &mut self.app.accepting_folder {
                        af.save_path_input.pop();
                    }
                }
            }
            KeyCode::Char(c) => {
                if self.app.folder_path_editing {
                    if let Some(af) = &mut self.app.accepting_folder {
                        af.save_path_input.push(c);
                    }
                } else if c == 'n' || c == 'N' || c == 'c' || c == 'C' {
                    let af = self.app.accepting_folder.take().unwrap();
                    self.app.folder_offer_button_focus = 0;
                    self.app.folder_path_editing = false;
                    self.context.active_popup = UIPopup::None;
                    self.process_folder_offer_reject(node, af).await;
                }
            }
            KeyCode::Esc => {
                if self.app.folder_path_editing {
                    self.app.folder_offer_button_focus = 0;
                    self.app.folder_path_editing = false;
                } else {
                    let af = self.app.accepting_folder.take().unwrap();
                    self.app.folder_offer_button_focus = 0;
                    self.app.folder_path_editing = false;
                    self.context.active_popup = UIPopup::None;
                    self.process_folder_offer_reject(node, af).await;
                }
            }
            _ => {}
        }
        false
    }

    // Helper methods per processare le azioni dei popup
    async fn process_file_offer_accept(&mut self, node: &PeerNode, af: AcceptingFileOffer) {
        let dest_path = af.save_path_input.clone();
        let node = node.clone();
        let filename = af.filename.clone();
        let peer_display = get_display_name(&self.app, &af.peer_id).to_string();

        if af.is_remote {
            if let Some(remote_path) = af.remote_path {
                tokio::spawn(async move {
                    match node
                        .fetch_remote_path(&af.peer_id, remote_path, false)
                        .await
                    {
                        Ok(()) => {
                            tracing::debug!(
                                "Remote file '{}' download started from {}",
                                filename,
                                peer_display
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to download remote file '{}' from {}: {}",
                                filename,
                                peer_display,
                                e
                            );
                        }
                    }
                });
            }
        } else {
            tokio::spawn(async move {
                tracing::debug!(
                    "Sending file acceptance response for {} from {}",
                    filename,
                    peer_display
                );
                match node
                    .respond_to_file_offer(&af.peer_id, af.file_id, true, Some(dest_path.clone()))
                    .await
                {
                    Ok(()) => {
                        tracing::debug!("File offer response sent successfully for '{}'", filename);
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to accept file '{}' from {} with save path '{}': {}",
                            filename,
                            peer_display,
                            dest_path,
                            e
                        );
                    }
                }
            });
        }
        self.app
            .set_status(format!("Downloading file: {}", af.filename));
    }

    async fn process_file_offer_reject(&mut self, node: &PeerNode, af: AcceptingFileOffer) {
        if !af.is_remote {
            let file_id = af.file_id;
            let node = node.clone();
            let filename = af.filename.clone();
            tokio::spawn(async move {
                let _ = node
                    .respond_to_file_offer(&af.peer_id, af.file_id, false, None)
                    .await;
            });
            
            // Track the rejection
            self.app.file_transfer_status.insert(file_id, FileTransferStatus::Rejected);
            self.app.rejected_transfers.insert(file_id, (filename.clone(), Some("User declined".to_string())));
            
            self.app
                .set_status(format!("Cancelled file: {}", af.filename));
        } else {
            self.app
                .set_status(format!("Cancelled download: {}", af.filename));
        }
    }

    async fn process_folder_offer_accept(&mut self, node: &PeerNode, af: AcceptingFolderOffer) {
        self.app
            .folder_progress
            .insert(af.folder_id, (0, af.file_count));
        let node = node.clone();
        let dirname = af.dirname.clone();

        if af.is_remote {
            if let Some(remote_path) = af.remote_path {
                let dirname_clone = dirname.clone();
                tokio::spawn(async move {
                    match node.fetch_remote_path(&af.peer_id, remote_path, true).await {
                        Ok(()) => {
                            tracing::debug!("Remote folder '{}' download started", dirname_clone);
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to download remote folder '{}': {}",
                                dirname_clone,
                                e
                            );
                        }
                    }
                });
            }
        } else {
            tokio::spawn(async move {
                let _ = node
                    .respond_to_folder_offer(&af.peer_id, af.folder_id, true)
                    .await;
            });
        }
        self.app
            .set_status(format!("Downloading folder: {}", dirname));
    }

    async fn process_folder_offer_reject(&mut self, node: &PeerNode, af: AcceptingFolderOffer) {
        if !af.is_remote {
            let node = node.clone();
            let dirname = af.dirname.clone();
            tokio::spawn(async move {
                let _ = node
                    .respond_to_folder_offer(&af.peer_id, af.folder_id, false)
                    .await;
            });
            self.app
                .set_status(format!("Cancelled folder: {}", dirname));
        } else {
            self.app
                .set_status(format!("Cancelled download: {}", af.dirname));
        }
    }

    /// Handle keyboard events for the remote file request popup.
    async fn handle_remote_file_request_key(&mut self, node: &PeerNode, key: KeyCode) -> bool {
        match key {
            KeyCode::Tab | KeyCode::BackTab => {
                let forward = matches!(key, KeyCode::Tab);
                if let Some(req) = &mut self.app.remote_file_request {
                    req.button_focus = cycle_focus(req.button_focus, forward);
                    req.is_path_editing = req.button_focus == 2;
                }
            }
            KeyCode::Enter => {
                if let Some(req) = &mut self.app.remote_file_request {
                    if req.is_path_editing {
                        req.button_focus = 0;
                        req.is_path_editing = false;
                        return false;
                    }
                }
                let req = self.app.remote_file_request.take().unwrap();
                let button_focus = req.button_focus;
                self.context.active_popup = UIPopup::None;

                if button_focus == 0 {
                    let node = node.clone();
                    let filename = req.filename.clone();
                    let peer_id = req.peer_id.clone();
                    let remote_path = req.remote_path.clone();
                    let save_path = req.save_path_input.clone();
                    let peer_display = get_display_name(&self.app, &peer_id).to_string();
                    tokio::spawn(async move {
                        match node.fetch_remote_path_with_dest(&peer_id, remote_path, false, save_path).await {
                            Ok(()) => {
                                tracing::debug!(
                                    "Remote file '{}' requested from {}",
                                    filename,
                                    peer_display
                                );
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Failed to request remote file '{}' from {}: {}",
                                    filename,
                                    peer_display,
                                    e
                                );
                            }
                        }
                    });
                    self.app.set_status(format!("Requesting file: {}", req.filename));
                } else {
                    self.app.set_status(format!("Cancelled request: {}", req.filename));
                }
            }
            KeyCode::Backspace => {
                if let Some(req) = &mut self.app.remote_file_request {
                    if req.is_path_editing {
                        req.save_path_input.pop();
                    }
                }
            }
            KeyCode::Char(c) => {
                if let Some(req) = &mut self.app.remote_file_request {
                    if req.is_path_editing {
                        req.save_path_input.push(c);
                    } else if c == 'n' || c == 'N' || c == 'c' || c == 'C' {
                        let req = self.app.remote_file_request.take().unwrap();
                        self.context.active_popup = UIPopup::None;
                        self.app.set_status(format!("Cancelled request: {}", req.filename));
                    }
                }
            }
            KeyCode::Esc => {
                if let Some(req) = &mut self.app.remote_file_request {
                    if req.is_path_editing {
                        req.button_focus = 0;
                        req.is_path_editing = false;
                        return false;
                    }
                }
                let req = self.app.remote_file_request.take().unwrap();
                self.context.active_popup = UIPopup::None;
                self.app.set_status(format!("Cancelled request: {}", req.filename));
            }
            _ => {}
        }
        false
    }

    /// Handle keyboard events for the remote folder request popup.
    async fn handle_remote_folder_request_key(&mut self, node: &PeerNode, key: KeyCode) -> bool {
        match key {
            KeyCode::Tab | KeyCode::BackTab => {
                let forward = matches!(key, KeyCode::Tab);
                if let Some(req) = &mut self.app.remote_folder_request {
                    req.button_focus = cycle_focus(req.button_focus, forward);
                    req.is_path_editing = req.button_focus == 2;
                }
            }
            KeyCode::Enter => {
                if let Some(req) = &mut self.app.remote_folder_request {
                    if req.is_path_editing {
                        req.button_focus = 0;
                        req.is_path_editing = false;
                        return false;
                    }
                }
                let req = self.app.remote_folder_request.take().unwrap();
                let button_focus = req.button_focus;
                self.context.active_popup = UIPopup::None;

                if button_focus == 0 {
                    let node = node.clone();
                    let dirname = req.dirname.clone();
                    let peer_id = req.peer_id.clone();
                    let remote_path = req.remote_path.clone();
                    let save_path = req.save_path_input.clone();
                    tokio::spawn(async move {
                        match node.fetch_remote_path_with_dest(&peer_id, remote_path, true, save_path).await {
                            Ok(()) => {
                                tracing::debug!("Remote folder '{}' requested", dirname);
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Failed to request remote folder '{}': {}",
                                    dirname,
                                    e
                                );
                            }
                        }
                    });
                    self.app.set_status(format!("Requesting folder: {}", req.dirname));
                } else {
                    self.app.set_status(format!("Cancelled request: {}", req.dirname));
                }
            }
            KeyCode::Backspace => {
                if let Some(req) = &mut self.app.remote_folder_request {
                    if req.is_path_editing {
                        req.save_path_input.pop();
                    }
                }
            }
            KeyCode::Char(c) => {
                if let Some(req) = &mut self.app.remote_folder_request {
                    if req.is_path_editing {
                        req.save_path_input.push(c);
                    } else if c == 'n' || c == 'N' || c == 'c' || c == 'C' {
                        let req = self.app.remote_folder_request.take().unwrap();
                        self.context.active_popup = UIPopup::None;
                        self.app.set_status(format!("Cancelled request: {}", req.dirname));
                    }
                }
            }
            KeyCode::Esc => {
                if let Some(req) = &mut self.app.remote_folder_request {
                    if req.is_path_editing {
                        req.button_focus = 0;
                        req.is_path_editing = false;
                        return false;
                    }
                }
                let req = self.app.remote_folder_request.take().unwrap();
                self.context.active_popup = UIPopup::None;
                self.app.set_status(format!("Cancelled request: {}", req.dirname));
            }
            _ => {}
        }
        false
    }

    /// Handle keyboard events for the transaction offer popup.
    /// Now delegates to TransferEngine for accept/reject logic.
    async fn handle_transaction_offer_key(&mut self, node: &PeerNode, key: KeyCode) -> bool {
        match key {
            KeyCode::Tab | KeyCode::BackTab => {
                let forward = matches!(key, KeyCode::Tab);
                if let Some(pi) = self.app.engine.pending_incoming_mut() {
                    pi.button_focus = cycle_focus(pi.button_focus, forward);
                    pi.path_editing = pi.button_focus == 2;
                }
            }
            KeyCode::Enter => {
                let is_editing = self
                    .app
                    .engine
                    .pending_incoming()
                    .map(|pi| pi.path_editing)
                    .unwrap_or(false);
                if is_editing {
                    if let Some(pi) = self.app.engine.pending_incoming_mut() {
                        pi.button_focus = 0;
                        pi.path_editing = false;
                    }
                    return false;
                }

                let button_focus = self
                    .app
                    .engine
                    .pending_incoming()
                    .map(|pi| pi.button_focus)
                    .unwrap_or(0);
                let dest_path = self
                    .app
                    .engine
                    .pending_incoming()
                    .map(|pi| pi.save_path_input.clone())
                    .unwrap_or_default();

                self.context.active_popup = UIPopup::None;

                if button_focus == 0 {
                    // Accept — delegate to engine
                    match self.app.engine.accept_incoming(dest_path) {
                        Ok(outcome) => {
                            if let Some(status) = outcome.status {
                                self.app.set_status(status);
                            }
                            self.execute_engine_actions(node, outcome.actions).await;
                        }
                        Err(e) => {
                            self.app.set_status(format!("Error accepting transfer: {}", e));
                        }
                    }
                } else {
                    // Reject — delegate to engine
                    match self.app.engine.reject_incoming() {
                        Ok(outcome) => {
                            if let Some(status) = outcome.status {
                                self.app.set_status(status);
                            }
                            self.execute_engine_actions(node, outcome.actions).await;
                        }
                        Err(e) => {
                            self.app.set_status(format!("Error rejecting transfer: {}", e));
                        }
                    }
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Char('c') | KeyCode::Char('C') => {
                let is_editing = self
                    .app
                    .engine
                    .pending_incoming()
                    .map(|pi| pi.path_editing)
                    .unwrap_or(false);
                if !is_editing {
                    self.context.active_popup = UIPopup::None;
                    match self.app.engine.reject_incoming() {
                        Ok(outcome) => {
                            if let Some(status) = outcome.status {
                                self.app.set_status(status);
                            }
                            self.execute_engine_actions(node, outcome.actions).await;
                        }
                        Err(e) => {
                            self.app.set_status(format!("Error: {}", e));
                        }
                    }
                }
            }
            KeyCode::Backspace => {
                if let Some(pi) = self.app.engine.pending_incoming_mut() {
                    if pi.path_editing {
                        pi.save_path_input.pop();
                    }
                }
            }
            KeyCode::Char(c) => {
                if let Some(pi) = self.app.engine.pending_incoming_mut() {
                    if pi.path_editing {
                        pi.save_path_input.push(c);
                    }
                }
            }
            KeyCode::Esc => {
                let is_editing = self
                    .app
                    .engine
                    .pending_incoming()
                    .map(|pi| pi.path_editing)
                    .unwrap_or(false);
                if is_editing {
                    if let Some(pi) = self.app.engine.pending_incoming_mut() {
                        pi.button_focus = 0;
                        pi.path_editing = false;
                    }
                } else {
                    self.context.active_popup = UIPopup::None;
                    match self.app.engine.reject_incoming() {
                        Ok(outcome) => {
                            if let Some(status) = outcome.status {
                                self.app.set_status(status);
                            }
                            self.execute_engine_actions(node, outcome.actions).await;
                        }
                        Err(e) => {
                            self.app.set_status(format!("Error: {}", e));
                        }
                    }
                }
            }
            _ => {}
        }
        false
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
        if let AppEvent::PeerDisconnected { ref peer_id, explicit } = event {
            if !explicit && node.is_peer_connected(peer_id).await {
                debug!(event = "stale_disconnect_ignored", peer = %crate::core::initializer::short_id_pub(peer_id), "Ignoring stale PeerDisconnected — peer has an active connection");
                return;
            }
        }

        // ── Route ALL transfer-related events through the engine ──────────
        let outcome = self.app.engine.process_event(&event);

        // Apply engine outcome (actions + status)
        if let Some(status) = outcome.status {
            self.app.set_status(status);
        }
        self.execute_engine_actions(node, outcome.actions).await;

        // ── Handle non-transfer events directly ──────────────────────────
        match event {
            AppEvent::PeerConnected { peer_id } => {
                self.app.connecting_peers.remove(&peer_id);
                self.app.add_peer(peer_id.clone());

                if let Some(key) = node.get_peer_key(&peer_id).await {
                    self.app.peer_keys.insert(peer_id.clone(), key);
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
                    self.app.set_status(status);
                }
                if has_resume_actions {
                    info!(
                        event = "resume_actions_executing",
                        peer = %crate::core::initializer::short_id_pub(&peer_id),
                        actions = action_count,
                        "Executing resume actions"
                    );
                    self.execute_engine_actions(node, resume_outcome.actions).await;
                }

                info!(event = "peer_online", peer = %crate::core::initializer::short_id_pub(&peer_id), "Peer state: offline → online");
                if !has_resume_actions {
                    self.app.set_status(format!(
                        "Peer connected: {}",
                        get_display_name(&self.app, &peer_id)
                    ));
                }
            }
            AppEvent::PeerDisconnected { peer_id, explicit } => {
                self.app.connecting_peers.remove(&peer_id);
                // Engine already transitioned transactions to Resumable and persisted;
                // do NOT call interrupt_peer() here as it would overwrite Resumable → Interrupted.

                // Clean up the stale entry from PeerNode so the peer
                // slot is freed and the remote side can reconnect inbound.
                node.cleanup_peer(&peer_id).await;

                if explicit {
                    // User explicitly disconnected — full removal
                    info!(event = "peer_removed", peer = %crate::core::initializer::short_id_pub(&peer_id), "Peer explicitly disconnected and removed");
                    self.app.remove_peer(&peer_id);
                    self.peer_registry.peer_removed(&peer_id);
                    self.app.set_status(format!(
                        "Peer disconnected: {}",
                        get_display_name(&self.app, &peer_id)
                    ));
                } else {
                    // Connection lost — transition to offline, preserve state
                    warn!(event = "peer_offline", peer = %crate::core::initializer::short_id_pub(&peer_id), "Peer state: online → offline (connection lost)");
                    self.app.set_peer_offline(&peer_id);
                    self.peer_registry.peer_disconnected(&peer_id);
                    self.app.set_status(format!(
                        "Peer offline: {}",
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
                                const MAX_RETRIES: u32 = 5;
                                const RETRY_DELAYS: [u64; 5] = [3, 5, 10, 20, 30];

                                for attempt in 0..MAX_RETRIES {
                                    let delay = RETRY_DELAYS.get(attempt as usize).copied().unwrap_or(30);
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

                                    match node_clone.connect_to(ticket.clone()).await {
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

                // Room message
                self.app.messages.insert(Message {
                    id: uuid::Uuid::new_v4(),
                    sender: MessageSender::Peer(peer_id.clone()),
                    text,
                    timestamp: crate::ui::helpers::format_timestamp_now(),
                    target: ChatTarget::Room,
                    recipients: vec![],
                    created_at: Instant::now(),
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

                // Peer-chat isolation: DM only appears in the dedicated peer chat
                let target = ChatTarget::Peer(peer_id.clone());
                self.app.messages.insert(Message {
                    id: uuid::Uuid::new_v4(),
                    sender: MessageSender::Peer(peer_id.clone()),
                    text,
                    timestamp: crate::ui::helpers::format_timestamp_now(),
                    target: target.clone(),
                    recipients: vec![],
                    created_at: Instant::now(),
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
                        self.app.pending_remote_save_paths.insert(
                            peer_id.to_string(),
                            save_path.to_string(),
                        );
                    }
                } else if msg.starts_with("REMOTE_FETCH_FILE:") {
                    let path = msg.trim_start_matches("REMOTE_FETCH_FILE:").to_string();
                    let node = node.clone();
                    tokio::spawn(async move {
                        let _ = node.offer_file("all", &path).await;
                    });
                } else if msg.starts_with("REMOTE_FETCH_FOLDER:") {
                    let path = msg.trim_start_matches("REMOTE_FETCH_FOLDER:").to_string();
                    let node = node.clone();
                    tokio::spawn(async move {
                        let _ = node.offer_folder("all", &path).await;
                    });
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
                    self.app.set_status("Peer does not allow remote access");
                    self.context.switch_mode(Mode::Peers);
                    self.app.mode = Mode::Peers;
                    self.app.remote_peer = None;
                }
            }

            // ── File/Folder events handled by engine popup system ────────
            AppEvent::FileOffered { peer_id, .. } => {
                // If there's a pending remote save path for this peer,
                // auto-accept instead of showing a popup.
                if let Some(save_path) = self.app.pending_remote_save_paths.remove(&peer_id) {
                    if let Some(pi) = self.app.engine.pending_incoming_mut() {
                        pi.save_path_input = save_path.clone();
                    }
                    // Auto-accept
                    if let Ok(outcome) = self.app.engine.accept_incoming(save_path) {
                        if let Some(status) = outcome.status {
                            self.app.set_status(status);
                        }
                        self.execute_engine_actions(node, outcome.actions).await;
                    }
                } else if self.app.engine.has_pending_incoming() {
                    self.context.active_popup = UIPopup::TransactionOffer;
                }
            }
            AppEvent::TransactionRequested { peer_id, .. } => {
                // Same auto-accept logic for transaction-based transfers
                if let Some(save_path) = self.app.pending_remote_save_paths.remove(&peer_id) {
                    if let Some(pi) = self.app.engine.pending_incoming_mut() {
                        pi.save_path_input = save_path.clone();
                    }
                    if let Ok(outcome) = self.app.engine.accept_incoming(save_path) {
                        if let Some(status) = outcome.status {
                            self.app.set_status(status);
                        }
                        self.execute_engine_actions(node, outcome.actions).await;
                    }
                } else if self.app.engine.has_pending_incoming() {
                    self.context.active_popup = UIPopup::TransactionOffer;
                }
            }

            // ── Legacy folder offer auto-accept ──────────────────────────
            AppEvent::FolderOffered {
                peer_id,
                folder_id,
                dirname,
                file_count,
                total_size,
            } => {
                self.app.folder_transactions.insert(
                    folder_id,
                    (peer_id.clone(), dirname.clone(), total_size, file_count, 0),
                );
                let node = node.clone();
                tokio::spawn(async move {
                    let _ = node
                        .respond_to_folder_offer(&peer_id, folder_id, true)
                        .await;
                });
                self.app.set_status(format!(
                    "Downloading folder: {} ({} files, {})",
                    dirname,
                    file_count,
                    format_file_size(total_size)
                ));
            }
            AppEvent::FolderComplete { peer_id, folder_id } => {
                self.app.folder_progress.remove(&folder_id);
                self.app.file_to_folder.retain(|_, fid| *fid != folder_id);
                if let Some((_, dirname, total_size, file_count, _)) =
                    self.app.folder_transactions.remove(&folder_id)
                {
                    self.app.file_history.push(FileRecord {
                        direction: FileDirection::Received,
                        peer_id: peer_id.clone(),
                        filename: format!("{} ({} files)", dirname, file_count),
                        filesize: total_size,
                        path: None,
                        timestamp: Instant::now(),
                    });
                }
            }

            // Transfer events already fully handled by engine
            AppEvent::SendProgress {
                _peer_id: _,
                file_id,
                filename,
                sent_chunks,
                total_chunks,
                wire_bytes: _,
            } => {
                // For legacy sends (not tracked by engine transactions),
                // update the UI send_progress so active transfers show up.
                if self.app.engine.transactions().transaction_id_for_file(&file_id).is_none() {
                    self.app.send_progress.insert(
                        file_id,
                        (filename, sent_chunks, total_chunks),
                    );
                }
            }
            AppEvent::SendComplete {
                peer_id,
                file_id,
                success,
            } => {
                // For legacy sends, record in file history and clean up progress.
                if self.app.engine.transactions().transaction_id_for_file(&file_id).is_none() {
                    if let Some((filename, _, total_chunks)) = self.app.send_progress.remove(&file_id) {
                        if success {
                            let filesize = total_chunks as u64 * crate::core::transaction::CHUNK_SIZE as u64;
                            self.app.file_history.push(FileRecord {
                                direction: FileDirection::Sent,
                                peer_id: peer_id.clone(),
                                filename,
                                filesize,
                                path: None,
                                timestamp: Instant::now(),
                            });
                        }
                    }
                }
            }
            AppEvent::FileProgress {
                _peer_id: _,
                file_id,
                filename,
                received_chunks,
                total_chunks,
                wire_bytes: _,
            } => {
                // For legacy receives (not tracked by engine transactions),
                // update the UI file_progress so active transfers show up.
                if self.app.engine.transactions().transaction_id_for_file(&file_id).is_none() {
                    self.app.file_progress.insert(
                        file_id,
                        (filename, received_chunks, total_chunks),
                    );
                }
            }
            AppEvent::FileComplete {
                peer_id,
                file_id,
                filename,
                path,
            } => {
                // For legacy receives, record in file history and clean up progress.
                if self.app.engine.transactions().transaction_id_for_file(&file_id).is_none() {
                    self.app.file_progress.remove(&file_id);
                    let filesize = std::fs::metadata(&path)
                        .map(|m| m.len())
                        .unwrap_or(0);
                    self.app.file_history.push(FileRecord {
                        direction: FileDirection::Received,
                        peer_id: peer_id.clone(),
                        filename,
                        filesize,
                        path: Some(path),
                        timestamp: Instant::now(),
                    });
                }
            }
            AppEvent::FileRejected { .. }
            | AppEvent::TransactionAccepted { .. }
            | AppEvent::TransactionRejected { .. }
            | AppEvent::TransactionCompleted { .. }
            | AppEvent::TransactionCancelled { .. }
            | AppEvent::TransactionResumeRequested { .. }
            | AppEvent::TransactionResumeAccepted { .. }
            | AppEvent::RemoteFetchRequest { .. } => {
                // Already processed by engine.process_event() above
            }
        }
    }

    // ── Execute Engine Actions ───────────────────────────────────────────

    /// Execute network actions returned by the TransferEngine.
    /// This is the ONLY place where the UI layer talks to the network
    /// for transfer-related operations.
    async fn execute_engine_actions(&mut self, node: &PeerNode, actions: Vec<EngineAction>) {
        for action in actions {
            match action {
                EngineAction::SendTransactionRequest {
                    peer_id,
                    transaction_id,
                    display_name,
                    manifest,
                    total_size,
                } => {
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
                            let _ = event_tx.send(AppEvent::Error(
                                format!("Failed to send transfer request: {}", e),
                            ));
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
                EngineAction::PrepareReceive { peer_id, files } => {
                    // Await directly (not spawned) to guarantee destinations
                    // are registered BEFORE the TransactionResponse is sent.
                    // This prevents a race where the sender starts sending
                    // Metadata frames before we have registered where to save.
                    if let Err(e) = node.prepare_file_reception(&peer_id, files).await {
                        tracing::error!(
                            "Failed to prepare file reception for {}: {}",
                            peer_id,
                            e
                        );
                    }
                }
                EngineAction::SendFileData {
                    peer_id,
                    file_path,
                    file_id,
                    filename,
                } => {
                    // Use send_file_data which sends directly with the
                    // Transaction's file_id — NOT the legacy offer_file which
                    // generates a new UUID and re-negotiates acceptance.
                    let node = node.clone();
                    let event_tx = node.event_tx().clone();
                    tokio::spawn(async move {
                        if let Err(e) = node
                            .send_file_data(&peer_id, file_id, &file_path, &filename)
                            .await
                        {
                            tracing::error!("File send error for {}: {}", filename, e);
                            let _ = event_tx.send(AppEvent::Error(
                                format!("File send failed ({}): {}", filename, e),
                            ));
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
                            let _ = event_tx.send(AppEvent::Error(
                                format!("Folder send failed: {}", e),
                            ));
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
                        if let Err(e) =
                            node.accept_transaction_resume(&peer_id, transaction_id).await
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
                    // IMPORTANT: Always send from chunk 0 (start_chunk = 0).
                    // The receiver's in-memory buffer (WebRTC ReceiveFileState)
                    // is per-connection and lost on reconnect.  If we skip
                    // chunks the receiver will have zeros for the skipped
                    // range, causing hash failures and incomplete files.
                    let txn_data: Option<(Option<String>, Vec<(uuid::Uuid, String)>, bool)> = self
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
                            let file_entries: Vec<(uuid::Uuid, String)> = txn
                                .file_order
                                .iter()
                                .filter_map(|fid| {
                                    txn.files.get(fid).and_then(|f| {
                                        if !f.completed {
                                            Some((*fid, f.relative_path.clone()))
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
                            tracing::info!("Resume: all files already complete for {}", transaction_id);
                        } else if is_folder {
                            // Folder resume: re-send incomplete files from the beginning.
                            let node = node.clone();
                            let event_tx = node.event_tx().clone();
                            tracing::info!(
                                "Resume: re-sending {} folder files for {} (from chunk 0)",
                                file_entries.len(), transaction_id
                            );
                            tokio::spawn(async move {
                                if let Err(e) = node
                                    .send_folder_data(&peer_id, &source_path, file_entries)
                                    .await
                                {
                                    tracing::error!("Resume folder send error: {}", e);
                                    let _ = event_tx.send(AppEvent::Error(
                                        format!("Resume folder send failed: {}", e),
                                    ));
                                }
                            });
                        } else {
                            // Single file resume — always from chunk 0
                            if let Some((file_id, filename)) = file_entries.into_iter().next() {
                                let node = node.clone();
                                let event_tx = node.event_tx().clone();
                                tracing::info!(
                                    "Resume: re-sending file '{}' for {} (from chunk 0)",
                                    filename, transaction_id
                                );
                                tokio::spawn(async move {
                                    if let Err(e) = node
                                        .send_file_data(&peer_id, file_id, &source_path, &filename)
                                        .await
                                    {
                                        tracing::error!("Resume file send error for {}: {}", filename, e);
                                        let _ = event_tx.send(AppEvent::Error(
                                            format!("Resume file send failed ({}): {}", filename, e),
                                        ));
                                    }
                                });
                            }
                        }
                    } else {
                        tracing::warn!("Resume: no source path for transaction {}", transaction_id);
                    }
                }
                EngineAction::HandleRemoteFetch {
                    peer_id,
                    path,
                    is_folder,
                } => {
                    let node = node.clone();
                    tokio::spawn(async move {
                        if is_folder {
                            let _ = node.offer_folder(&peer_id, &path).await;
                        } else {
                            let _ = node.offer_file(&peer_id, &path).await;
                        }
                    });
                }
                EngineAction::AcceptLegacyFileOffer {
                    peer_id,
                    file_id,
                    dest_path,
                } => {
                    let node = node.clone();
                    tokio::spawn(async move {
                        let _ = node
                            .respond_to_file_offer(&peer_id, file_id, true, Some(dest_path))
                            .await;
                    });
                }
                EngineAction::RejectLegacyFileOffer { peer_id, file_id } => {
                    let node = node.clone();
                    tokio::spawn(async move {
                        let _ = node
                            .respond_to_file_offer(&peer_id, file_id, false, None)
                            .await;
                    });
                }
            }
        }
    }
}
