use crate::core::engine::EngineAction;
use crate::core::initializer::{AppEvent, PeerNode};
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
use crate::workers::app::{AcceptingFileOffer, AcceptingFolderOffer, App, ChatMessage, ChatTarget, FileDirection, FileRecord, Mode, FileTransferStatus};
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

/// Traccia lo stato del context UI - in che finestra siamo e cosa stiamo facendo
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UIPopup {
    None,
    FileOffer,
    FolderOffer,
    TransactionOffer,
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
}

pub async fn run(args: Args, sos: SignalOfStop, log_buffer: LogBuffer) -> anyhow::Result<()> {
    // Acquire secret key with per-instance locking
    let (secret_key, _instance_guard) = get_or_create_secret(args.secret_file.as_deref())?;

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

    let app = App::new(ticket, args.display_name.clone());
    let mut executer = UIExecuter::new(app, terminal, node.clone(), log_buffer);

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
            Mode::Chat => "Enter: send | Tab/Shift+Tab: switch chat | Esc: back",
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
        } else {
            false
        }
    }

    /// Gestisce i tasti per il file offer popup
    async fn handle_file_offer_key(&mut self, node: &PeerNode, key: KeyCode) -> bool {
        match key {
            KeyCode::Tab => {
                self.app.file_offer_button_focus = (self.app.file_offer_button_focus + 1) % 2;
            }
            KeyCode::BackTab => {
                self.app.file_offer_button_focus = if self.app.file_offer_button_focus == 0 {
                    1
                } else {
                    0
                };
            }
            KeyCode::Char('e') | KeyCode::Char('E') => {
                self.context.file_path_editing = !self.context.file_path_editing;
            }
            KeyCode::Enter => {
                if self.context.file_path_editing {
                    self.context.file_path_editing = false;
                    return false;
                }

                let af = self.app.accepting_file.take().unwrap();
                let button_focus = self.app.file_offer_button_focus;
                self.app.file_offer_button_focus = 0;
                self.context.active_popup = UIPopup::None;

                if button_focus == 0 {
                    // Download button
                    self.process_file_offer_accept(node, af).await;
                } else {
                    // Cancel button
                    self.process_file_offer_reject(node, af).await;
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Char('c') | KeyCode::Char('C') => {
                if !self.context.file_path_editing {
                    let af = self.app.accepting_file.take().unwrap();
                    self.app.file_offer_button_focus = 0;
                    self.context.active_popup = UIPopup::None;
                    self.process_file_offer_reject(node, af).await;
                }
            }
            KeyCode::Backspace => {
                if self.context.file_path_editing {
                    if let Some(af) = &mut self.app.accepting_file {
                        af.save_path_input.pop();
                    }
                }
            }
            KeyCode::Char(c) => {
                if self.context.file_path_editing {
                    if let Some(af) = &mut self.app.accepting_file {
                        af.save_path_input.push(c);
                    }
                }
            }
            KeyCode::Esc => {
                if self.context.file_path_editing {
                    self.context.file_path_editing = false;
                } else {
                    let af = self.app.accepting_file.take().unwrap();
                    self.app.file_offer_button_focus = 0;
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
            KeyCode::Tab => {
                self.app.folder_offer_button_focus = (self.app.folder_offer_button_focus + 1) % 2;
            }
            KeyCode::BackTab => {
                self.app.folder_offer_button_focus = if self.app.folder_offer_button_focus == 0 {
                    1
                } else {
                    0
                };
            }
            KeyCode::Enter => {
                let af = self.app.accepting_folder.take().unwrap();
                let button_focus = self.app.folder_offer_button_focus;
                self.app.folder_offer_button_focus = 0;
                self.context.active_popup = UIPopup::None;

                if button_focus == 0 {
                    self.process_folder_offer_accept(node, af).await;
                } else {
                    self.process_folder_offer_reject(node, af).await;
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Char('c') | KeyCode::Char('C') => {
                let af = self.app.accepting_folder.take().unwrap();
                self.app.folder_offer_button_focus = 0;
                self.context.active_popup = UIPopup::None;
                self.process_folder_offer_reject(node, af).await;
            }
            KeyCode::Esc => {
                let af = self.app.accepting_folder.take().unwrap();
                self.app.folder_offer_button_focus = 0;
                self.context.active_popup = UIPopup::None;
                self.process_folder_offer_reject(node, af).await;
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

    /// Handle keyboard events for the transaction offer popup.
    /// Now delegates to TransferEngine for accept/reject logic.
    async fn handle_transaction_offer_key(&mut self, node: &PeerNode, key: KeyCode) -> bool {
        match key {
            KeyCode::Tab => {
                if let Some(pi) = self.app.engine.pending_incoming_mut() {
                    pi.button_focus = (pi.button_focus + 1) % 2;
                }
            }
            KeyCode::BackTab => {
                if let Some(pi) = self.app.engine.pending_incoming_mut() {
                    pi.button_focus = if pi.button_focus == 0 { 1 } else { 0 };
                }
            }
            KeyCode::Char('e') | KeyCode::Char('E') => {
                if let Some(pi) = self.app.engine.pending_incoming_mut() {
                    pi.path_editing = !pi.path_editing;
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

    #[allow(dead_code)]
    async fn process_transaction_accept(
        &mut self,
        node: &PeerNode,
        pt: crate::workers::app::PendingTransactionOffer,
    ) {
        // Legacy method — now handled by engine.accept_incoming()
        let dest_path = pt.save_path_input.clone();
        match self.app.engine.accept_incoming(dest_path) {
            Ok(outcome) => {
                if let Some(status) = outcome.status {
                    self.app.set_status(status);
                }
                self.execute_engine_actions(node, outcome.actions).await;
            }
            Err(e) => {
                self.app
                    .set_status(format!("Error accepting transfer: {}", e));
            }
        }
    }

    #[allow(dead_code)]
    async fn process_transaction_reject(
        &mut self,
        node: &PeerNode,
        _pt: crate::workers::app::PendingTransactionOffer,
    ) {
        // Legacy method — now handled by engine.reject_incoming()
        match self.app.engine.reject_incoming() {
            Ok(outcome) => {
                if let Some(status) = outcome.status {
                    self.app.set_status(status);
                }
                self.execute_engine_actions(node, outcome.actions).await;
            }
            Err(e) => {
                self.app
                    .set_status(format!("Error rejecting transfer: {}", e));
            }
        }
    }

    /// Gestisce gli eventi dell'applicazione.
    /// Transfer-related events are delegated to the TransferEngine;
    /// non-transfer events are handled directly.
    pub async fn handle_app_event(&mut self, node: &PeerNode, event: AppEvent) {
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

                self.app.set_status(format!(
                    "Peer connected: {}",
                    get_display_name(&self.app, &peer_id)
                ));
            }
            AppEvent::PeerDisconnected { peer_id } => {
                self.app.connecting_peers.remove(&peer_id);
                // Engine already interrupted transactions for this peer
                self.app.transactions.interrupt_peer(&peer_id);
                self.app.remove_peer(&peer_id);
                self.app.set_status(format!(
                    "Peer disconnected: {}",
                    get_display_name(&self.app, &peer_id)
                ));
            }
            AppEvent::ChatReceived { peer_id, message } => {
                // Stats tracked by engine
                let text = String::from_utf8_lossy(&message).to_string();
                self.app.chat_history.push(ChatMessage {
                    from_me: false,
                    peer_id: peer_id.clone(),
                    text,
                    timestamp: Instant::now(),
                    target: ChatTarget::Room,
                });
            }
            AppEvent::DisplayNameReceived { peer_id, name } => {
                self.app.peer_names.insert(peer_id, name);
            }
            AppEvent::Error(msg) => {
                self.app.push_error(msg);
            }
            AppEvent::Info(msg) => {
                if msg.starts_with("REMOTE_FETCH_FILE:") {
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
            AppEvent::FileOffered { .. } => {
                // Engine creates PendingIncoming — show popup
                if self.app.engine.has_pending_incoming() {
                    self.context.active_popup = UIPopup::TransactionOffer;
                }
            }
            AppEvent::TransactionRequested { .. } => {
                // Engine creates PendingIncoming — show popup
                if self.app.engine.has_pending_incoming() {
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
            AppEvent::FileProgress { .. }
            | AppEvent::SendProgress { .. }
            | AppEvent::SendComplete { .. }
            | AppEvent::FileComplete { .. }
            | AppEvent::FileRejected { .. }
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
                    let node = node.clone();
                    tokio::spawn(async move {
                        if let Err(e) = node.prepare_file_reception(&peer_id, files).await {
                            tracing::error!(
                                "Failed to prepare file reception for {}: {}",
                                peer_id,
                                e
                            );
                        }
                    });
                }
                EngineAction::SendFileData {
                    peer_id,
                    file_path,
                    file_id: _,
                    filename,
                } => {
                    let node = node.clone();
                    tokio::spawn(async move {
                        match node.offer_file(&peer_id, &file_path).await {
                            Ok(true) => tracing::info!("File sent successfully: {}", filename),
                            Ok(false) => tracing::info!("File offer rejected: {}", filename),
                            Err(e) => tracing::error!("File send error: {}", e),
                        }
                    });
                }
                EngineAction::SendFolderData {
                    peer_id,
                    folder_path,
                    file_entries: _,
                } => {
                    let node = node.clone();
                    tokio::spawn(async move {
                        match node.offer_folder(&peer_id, &folder_path).await {
                            Ok(true) => tracing::info!("Folder sent successfully"),
                            Ok(false) => tracing::info!("Folder offer rejected"),
                            Err(e) => tracing::error!("Folder send error: {}", e),
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
                            .respond_to_transaction(
                                &peer_id,
                                transaction_id,
                                true,
                                None,
                                None,
                            )
                            .await
                        {
                            tracing::error!("Failed to send completion: {}", e);
                        }
                    });
                }
                EngineAction::SendTransactionCancel {
                    peer_id,
                    transaction_id,
                    reason,
                } => {
                    let node = node.clone();
                    tokio::spawn(async move {
                        if let Err(e) = node
                            .respond_to_transaction(
                                &peer_id,
                                transaction_id,
                                false,
                                None,
                                reason,
                            )
                            .await
                        {
                            tracing::error!("Failed to send cancellation: {}", e);
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
