use crate::core::initializer::PeerNode;
use crate::ui::helpers::short_peer_id;
use crate::ui::traits::{Action, Component, Handler};
use crate::workers::app::App;
use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

pub struct ConnectPanel;

impl Default for ConnectPanel {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectPanel {
    pub fn new() -> Self {
        Self
    }
}

impl Component for ConnectPanel {
    fn render(&mut self, f: &mut Frame, app: &App, area: Rect) {
        let constraints = if app.peers.connecting.is_empty() {
            vec![
                Constraint::Min(1),
                Constraint::Length(3),
                Constraint::Min(1),
            ]
        } else {
            vec![
                Constraint::Min(1),
                Constraint::Length(3),
                Constraint::Length(1), // Spacer
                Constraint::Length(2 + app.peers.connecting.len() as u16),
                Constraint::Min(1),
            ]
        };

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
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

        if !app.peers.connecting.is_empty() {
            let mut connecting_items = Vec::new();
            for (peer_id, status) in &app.peers.connecting {
                connecting_items.push(ListItem::new(Line::from(vec![
                    Span::styled(
                        format!(" {} ", short_peer_id(peer_id)),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::raw(": "),
                    Span::styled(status, Style::default().fg(Color::Yellow)),
                ])));
            }
            let connecting_list = List::new(connecting_items).block(
                Block::default()
                    .title(" Connecting... ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow)),
            );
            f.render_widget(connecting_list, chunks[3]);
        }
    }

    fn on_focus(&mut self, app: &mut App) {
        app.connect_ticket_input.clear();
    }

    fn on_blur(&mut self, app: &mut App) {
        app.connect_ticket_input.clear();
    }
}

impl Handler for ConnectPanel {
    fn handle_key(&mut self, app: &mut App, node: &PeerNode, key: KeyCode) -> Option<Action> {
        match key {
            KeyCode::Esc => {
                app.connect_ticket_input.clear();
                Some(Action::SwitchMode(crate::workers::app::Mode::Home))
            }
            KeyCode::Enter => {
                let ticket = app.connect_ticket_input.trim().to_string();
                if !ticket.is_empty() {
                    app.connect_ticket_input.clear();
                    app.set_status("Connecting...");
                    let node = node.clone();
                    tokio::spawn(async move {
                        if let Err(e) = node.connect_to(ticket).await {
                            tracing::error!("Failed to connect: {:?}", e);
                        }
                    });
                    Some(Action::SetStatus("Connecting...".to_string()))
                } else {
                    Some(Action::None)
                }
            }
            KeyCode::Char(c) => {
                app.connect_ticket_input.push(c);
                Some(Action::None)
            }
            KeyCode::Backspace => {
                app.connect_ticket_input.pop();
                Some(Action::None)
            }
            _ => Some(Action::None),
        }
    }
}
