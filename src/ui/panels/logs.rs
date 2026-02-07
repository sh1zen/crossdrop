use crate::core::initializer::PeerNode;
use crate::ui::traits::{Action, Component, Handler};
use crate::utils::log_buffer::LogBuffer;
use crate::workers::app::App;
use crossterm::event::KeyCode;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
    Frame,
};

pub struct LogsPanel {
    pub scroll: usize,
}

impl Default for LogsPanel {
    fn default() -> Self {
        Self::new()
    }
}

impl LogsPanel {
    pub fn new() -> Self {
        Self { scroll: 0 }
    }

    pub fn render_with_buffer(
        &mut self,
        f: &mut Frame,
        _app: &App,
        log_buffer: &LogBuffer,
        area: Rect,
    ) {
        let entries = log_buffer.entries();
        let total = entries.len();

        let visible_height = area.height.saturating_sub(2) as usize; // subtract borders

        // Clamp scroll offset
        let max_scroll = total.saturating_sub(visible_height);
        let scroll = self.scroll.min(max_scroll);

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
                        Style::default()
                            .fg(level_color)
                            .add_modifier(Modifier::BOLD),
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
}

impl Component for LogsPanel {
    fn render(&mut self, _f: &mut Frame, _app: &App, _area: Rect) {
        // This panel requires log_buffer, so use render_with_buffer instead
    }

    fn on_blur(&mut self, _app: &mut App) {
        self.scroll = 0;
    }
}

impl Handler for LogsPanel {
    fn handle_key(&mut self, app: &mut App, _node: &PeerNode, key: KeyCode) -> Option<Action> {
        match key {
            KeyCode::Esc => {
                self.scroll = 0;
                Some(Action::SwitchMode(crate::workers::app::Mode::Home))
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll = self.scroll.saturating_sub(1);
                Some(Action::None)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.scroll = self.scroll.saturating_add(1);
                Some(Action::None)
            }
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(10);
                Some(Action::None)
            }
            KeyCode::PageDown => {
                self.scroll = self.scroll.saturating_add(10);
                Some(Action::None)
            }
            KeyCode::Home => {
                self.scroll = 0;
                Some(Action::None)
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                // Clear logs
                app.notify.info("Logs cleared".to_string());
                Some(Action::None)
            }
            _ => Some(Action::None),
        }
    }
}
