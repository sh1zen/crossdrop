use crate::core::initializer::PeerNode;
use crate::ui::traits::{Action, Component, Handler};
use crate::workers::app::{App, ChatTarget, Mode};
use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState},
    Frame,
};

/// OrderView - maps all rendered elements in order for Mode-based binding
const MENU_ORDER: &[Mode] = &[
    Mode::Chat,
    Mode::Send,
    Mode::Connect,
    Mode::Peers,
    Mode::Id,
    Mode::Files,
    Mode::Settings,
    Mode::Logs,
];

impl HomePanel {
    /// Get the Mode at a specific index position
    fn index_to_mode(index: usize) -> Option<Mode> {
        MENU_ORDER.get(index).copied()
    }
}

pub struct HomePanel {
    list_state: ListState,
}

impl Default for HomePanel {
    fn default() -> Self {
        Self::new()
    }
}

impl HomePanel {
    pub fn new() -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self { list_state }
    }
}

impl Component for HomePanel {
    fn render(&mut self, f: &mut Frame, app: &App, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1)])
            .split(area);

        let items: Vec<ListItem> = MENU_ORDER
            .iter()
            .map(|mode| match mode {
                Mode::Chat => ListItem::new(Line::from(vec![
                    Span::styled(" 💬  ".to_string(), Style::default().fg(Color::Cyan)),
                    Span::raw(mode.label()),
                    Span::styled(
                        format!(" ({})", app.messages.messages_for(&crate::workers::app::ChatTarget::Room).len()),
                        Style::default().fg(Color::DarkGray),
                    ),
                ])),
                Mode::Send => ListItem::new(Line::from(vec![
                    Span::styled(" 🛜  ".to_string(), Style::default().fg(Color::Cyan)),
                    Span::raw(mode.label()),
                ])),
                Mode::Connect => ListItem::new(Line::from(vec![
                    Span::styled(" 🔗  ".to_string(), Style::default().fg(Color::Cyan)),
                    Span::raw(mode.label()),
                ])),
                Mode::Peers => ListItem::new(Line::from(vec![
                    Span::styled(" 💻  ".to_string(), Style::default().fg(Color::Cyan)),
                    Span::raw(mode.label()),
                    Span::styled(
                        format!(" ({})", app.peers.len()),
                        Style::default().fg(Color::DarkGray),
                    ),
                ])),
                Mode::Id => ListItem::new(Line::from(vec![
                    Span::styled(" 🪪  ".to_string(), Style::default().fg(Color::Cyan)),
                    Span::raw(mode.label()),
                ])),
                Mode::Files => ListItem::new(Line::from(vec![
                    Span::styled(" 📂  ".to_string(), Style::default().fg(Color::Cyan)),
                    Span::raw(mode.label()),
                    Span::styled(
                        format!(" ({})", app.file_history.len()),
                        Style::default().fg(Color::DarkGray),
                    ),
                ])),
                Mode::Settings => ListItem::new(Line::from(vec![
                    Span::styled(" 🌐  ".to_string(), Style::default().fg(Color::Cyan)),
                    Span::raw(mode.label()),
                ])),
                Mode::Logs => ListItem::new(Line::from(vec![
                    Span::styled(" 📋  ".to_string(), Style::default().fg(Color::Cyan)),
                    Span::raw(mode.label()),
                ])),
                _ => ListItem::new(Line::from(Span::raw(mode.label()))),
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

        f.render_stateful_widget(menu, chunks[0], &mut self.list_state);
    }
}

impl Handler for HomePanel {
    fn handle_key(&mut self, app: &mut App, _node: &PeerNode, key: KeyCode) -> Option<Action> {
        let sel = self.list_state.selected().unwrap_or(0);

        match key {
            KeyCode::Up => {
                let new_sel = if sel == 0 {
                    MENU_ORDER.len() - 1
                } else {
                    sel - 1
                };
                self.list_state.select(Some(new_sel));
                app.menu_selected = new_sel;
                Some(Action::None)
            }
            KeyCode::Down => {
                let new_sel = if sel + 1 >= MENU_ORDER.len() {
                    0
                } else {
                    sel + 1
                };
                self.list_state.select(Some(new_sel));
                app.menu_selected = new_sel;
                Some(Action::None)
            }
            KeyCode::Enter => {
                if let Some(mode) = Self::index_to_mode(sel) {
                    app.status.clear();
                    if mode == Mode::Chat {
                        app.chat_target = ChatTarget::Room;
                        app.chat_sidebar_idx = 0;
                    }
                    Some(Action::SwitchMode(mode))
                } else {
                    Some(Action::None)
                }
            }
            _ => Some(Action::None),
        }
    }
}
