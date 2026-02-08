use crate::core::initializer::PeerNode;
use crate::ui::traits::{Action, Component, Focusable, FocusableElement, Handler};
use crate::workers::app::App;
use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

#[derive(Debug, Clone, Copy, PartialEq)]
enum FocusElement {
    DisplayNameInput,   // Index 0
    RemoteAccessToggle, // Index 1
}

impl FocusElement {
    fn from_index(index: usize) -> Self {
        match index {
            0 => FocusElement::DisplayNameInput,
            1 => FocusElement::RemoteAccessToggle,
            _ => FocusElement::DisplayNameInput,
        }
    }

    fn to_index(self) -> usize {
        match self {
            FocusElement::DisplayNameInput => 0,
            FocusElement::RemoteAccessToggle => 1,
        }
    }
}

pub struct SettingsPanel {
    focused_element: FocusElement,
}

impl Default for SettingsPanel {
    fn default() -> Self {
        Self::new()
    }
}

impl SettingsPanel {
    pub fn new() -> Self {
        Self {
            focused_element: FocusElement::DisplayNameInput,
        }
    }
}

impl Component for SettingsPanel {
    fn render(&mut self, f: &mut Frame, app: &App, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(2)
            .constraints([
                Constraint::Length(3), // Display name input
                Constraint::Length(3), // Remote access toggle
                Constraint::Min(0),    // Spacer
            ])
            .split(area);

        // Display name input
        let name_focused = self.focused_element == FocusElement::DisplayNameInput;
        let name_border_color = if name_focused {
            Color::Cyan
        } else {
            Color::DarkGray
        };

        let name_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(name_border_color))
            .title(Span::styled(
                " Display Name ",
                Style::default().add_modifier(Modifier::BOLD),
            ));

        let name_text = Paragraph::new(app.input.as_str()).block(name_block);
        f.render_widget(name_text, chunks[0]);

        // Remote access toggle
        let toggle_focused = self.focused_element == FocusElement::RemoteAccessToggle;
        let toggle_border_color = if toggle_focused {
            Color::Cyan
        } else {
            Color::DarkGray
        };

        let toggle_status = if app.remote_access {
            Span::styled(" ENABLED ", Style::default().fg(Color::Green))
        } else {
            Span::styled(" DISABLED ", Style::default().fg(Color::Red))
        };

        let toggle_help = if toggle_focused {
            Span::styled(" (Press 'a' to toggle) ", Style::default().fg(Color::Gray))
        } else {
            Span::styled(" (Tab to focus) ", Style::default().fg(Color::DarkGray))
        };

        let toggle_line = Line::from(vec![
            Span::raw("Remote Access: "),
            toggle_status,
            toggle_help,
        ]);

        let toggle_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(toggle_border_color))
            .title(Span::styled(
                " Remote File System Access ",
                Style::default().add_modifier(Modifier::BOLD),
            ));

        let toggle_widget = Paragraph::new(toggle_line).block(toggle_block);
        f.render_widget(toggle_widget, chunks[1]);
    }

    fn on_focus(&mut self, app: &mut App) {
        // Initialize input with current display name
        app.input = app.display_name.clone();
        self.focused_element = FocusElement::DisplayNameInput;
    }

    fn on_blur(&mut self, app: &mut App) {
        app.input.clear();
    }
}

impl Handler for SettingsPanel {
    fn handle_key(&mut self, app: &mut App, node: &PeerNode, key: KeyCode) -> Option<Action> {
        match key {
            KeyCode::Esc => {
                app.input.clear();
                return Some(Action::SwitchMode(crate::workers::app::Mode::Home));
            }
            KeyCode::Tab => {
                self.focus_next();
            }
            KeyCode::BackTab => {
                self.focus_prev();
            }
            KeyCode::Enter => {
                // Save display name
                let name = app.input.trim().to_string();
                if !name.is_empty() && name != app.display_name {
                    app.display_name = name.clone();
                    app.set_status(format!("Display name set to: {}", name));

                    let node = node.clone();
                    tokio::spawn(async move {
                        node.broadcast_display_name(name).await;
                    });
                }
                app.input.clear();
                return Some(Action::SwitchMode(crate::workers::app::Mode::Home));
            }
            KeyCode::Char(c) => {
                match self.focused_element {
                    FocusElement::DisplayNameInput => {
                        // ALL characters (including 'a') go to input when input is focused
                        app.input.push(c);
                    }
                    FocusElement::RemoteAccessToggle => {
                        // Only 'a'/'A' toggles when focused on toggle
                        if c == 'a' || c == 'A' {
                            app.remote_access = !app.remote_access;
                            let enabled = app.remote_access;
                            let node = node.clone();
                            tokio::spawn(async move {
                                node.update_remote_access(enabled);
                            });
                            app.set_status(format!(
                                "Remote access {}",
                                if enabled { "enabled" } else { "disabled" }
                            ));
                        }
                    }
                }
            }
            KeyCode::Backspace => {
                if self.focused_element == FocusElement::DisplayNameInput {
                    app.input.pop();
                }
            }
            _ => {}
        }
        Some(Action::None)
    }
}

impl Focusable for SettingsPanel {
    fn focusable_elements(&self) -> Vec<FocusableElement> {
        vec![FocusableElement::TextInput, FocusableElement::Toggle]
    }

    fn focused_index(&self) -> usize {
        self.focused_element.to_index()
    }

    fn set_focus(&mut self, index: usize) {
        self.focused_element = FocusElement::from_index(index);
    }
}
