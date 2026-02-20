use crate::core::initializer::PeerNode;
use crate::ui::traits::{Action, Component, Handler};
use crate::workers::app::{App, Mode};
use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

pub struct KeyListenerPanel {
    scroll_offset: usize,
}

impl Default for KeyListenerPanel {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyListenerPanel {
    pub fn new() -> Self {
        Self {
            scroll_offset: 0,
        }
    }
}

/// Convert a key string to its display representation.
/// Returns the actual character for printable keys, or a special representation for special keys.
fn key_to_display(key: &str) -> String {
    match key {
        "Enter" => "\n".to_string(),
        "Tab" => "\t".to_string(),
        "Space" => " ".to_string(),
        "Backspace" => "⌫".to_string(),
        "Delete" => "⌦".to_string(),
        "Esc" => "⎋".to_string(),
        "Up" => "↑".to_string(),
        "Down" => "↓".to_string(),
        "Left" => "←".to_string(),
        "Right" => "→".to_string(),
        "PageUp" => "⇞".to_string(),
        "PageDown" => "⇟".to_string(),
        "Home" => "⇱".to_string(),
        "End" => "⇲".to_string(),
        "Shift" => "⇧".to_string(),
        "Ctrl" => "⌃".to_string(),
        "Alt" => "⌥".to_string(),
        "Meta" => "◆".to_string(),
        k => k.to_string(),
    }
}

impl Component for KeyListenerPanel {
    fn render(&mut self, f: &mut Frame, app: &App, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(1)])
            .split(area);

        // Header showing status
        let status = if app.remote_key_listener {
            "● SHARING - Your keystrokes are visible to connected peers"
        } else {
            "○ NOT SHARING - Your keystrokes are private"
        };

        let status_color = if app.remote_key_listener {
            Color::Green
        } else {
            Color::DarkGray
        };

        let header = Paragraph::new(status).style(Style::default().fg(status_color)).block(
            Block::default()
                .title(" Key Listener Status ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );
        f.render_widget(header, chunks[0]);

        // Build a text stream of all received keys
        let mut text_content = String::new();

        for entry in &app.remote_key_events {
            let display_key = key_to_display(&entry.key);
            text_content.push_str(&display_key);
        }

        // Split into lines for display
        let lines: Vec<&str> = text_content.split('\n').collect();
        let total_lines = lines.len();
        
        // Apply scroll offset
        let visible_height = chunks[1].height.saturating_sub(2) as usize; // Account for borders
        let max_scroll = total_lines.saturating_sub(visible_height);
        self.scroll_offset = self.scroll_offset.min(max_scroll);
        
        let visible_lines: Vec<&str> = lines
            .iter()
            .skip(self.scroll_offset)
            .take(visible_height)
            .copied()
            .collect();

        let content = visible_lines.join("\n");

        let count = app.remote_key_events.len();
        let title = format!(" Received Key Events ({}) - Press 'c' to clear, ↑/↓ to scroll ", count);

        let text_widget = Paragraph::new(content).block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );

        f.render_widget(text_widget, chunks[1]);
    }
}

impl Handler for KeyListenerPanel {
    fn handle_key(&mut self, app: &mut App, _node: &PeerNode, key: KeyCode) -> Option<Action> {
        match key {
            KeyCode::Esc => Some(Action::SwitchMode(Mode::Peers)),
            KeyCode::Up => {
                if self.scroll_offset > 0 {
                    self.scroll_offset -= 1;
                }
                Some(Action::None)
            }
            KeyCode::Down => {
                self.scroll_offset += 1;
                Some(Action::None)
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                app.remote_key_events.clear();
                self.scroll_offset = 0;
                Some(Action::SetStatus("Key events cleared".to_string()))
            }
            _ => Some(Action::None),
        }
    }
}
