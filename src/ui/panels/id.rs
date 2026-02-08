use crate::core::initializer::PeerNode;
use crate::ui::traits::{Action, Component, Handler};
use crate::utils::clipboard::copy_to_clipboard;
use crate::workers::app::App;
use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

pub struct IdPanel;

impl Default for IdPanel {
    fn default() -> Self {
        Self::new()
    }
}

impl IdPanel {
    pub fn new() -> Self {
        Self
    }
}

impl Component for IdPanel {
    fn render(&mut self, f: &mut Frame, app: &App, area: Rect) {
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
}

impl Handler for IdPanel {
    fn handle_key(&mut self, app: &mut App, _node: &PeerNode, key: KeyCode) -> Option<Action> {
        match key {
            KeyCode::Esc => {
                app.status.clear();
                Some(Action::SwitchMode(crate::workers::app::Mode::Home))
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                if copy_to_clipboard(&app.ticket) {
                    Some(Action::SetStatus("Ticket copied to clipboard!".to_string()))
                } else {
                    Some(Action::SetStatus("Failed to copy to clipboard".to_string()))
                }
            }
            _ => Some(Action::None),
        }
    }
}
