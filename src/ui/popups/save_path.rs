use crate::ui::helpers::format_file_size;
use crate::workers::app::App;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

enum OfferContext<'a> {
    File {
        name: &'a str,
        size_str: String,
        button_focus: usize,
        border_color: Color,
        height: u16,
        save_path: &'a str,
        is_editing: bool,
    },
    Folder {
        name: &'a str,
        size_str: String,
        file_count: u32,
        button_focus: usize,
        border_color: Color,
        height: u16,
    },
    Transaction {
        name: &'a str,
        size_str: String,
        file_count: usize,
        button_focus: usize,
        border_color: Color,
        height: u16,
        save_path: &'a str,
        is_editing: bool,
        parent_dir: Option<&'a str>,
    },
}

pub struct SavePathPopup;

impl SavePathPopup {
    pub fn new() -> Self {
        Self
    }

    pub fn render_file<'a>(&self, f: &mut Frame, app: &'a App) {
        if let Some(af) = &app.accepting_file {
            let context = OfferContext::File {
                name: &af.filename,
                size_str: format_file_size(af.filesize),
                button_focus: app.file_offer_button_focus,
                border_color: Color::Green,
                height: 10,
                save_path: &af.save_path_input,
                is_editing: app.file_path_editing,
            };
            self.render_internal(f, context);
        }
    }

    pub fn render_folder<'a>(&self, f: &mut Frame, app: &'a App) {
        if let Some(af) = &app.accepting_folder {
            let context = OfferContext::Folder {
                name: &af.dirname,
                size_str: format_file_size(af.total_size),
                file_count: af.file_count,
                button_focus: app.folder_offer_button_focus,
                border_color: Color::Magenta,
                height: 9,
            };
            self.render_internal(f, context);
        }
    }

    #[allow(dead_code)]
    pub fn render_transaction<'a>(&self, f: &mut Frame, app: &'a App) {
        if let Some(pt) = &app.pending_transaction {
            let context = OfferContext::Transaction {
                name: &pt.display_name,
                size_str: format_file_size(pt.total_size),
                file_count: pt.manifest.files.len(),
                button_focus: pt.button_focus,
                border_color: Color::Magenta,
                height: 11,
                save_path: &pt.save_path_input,
                is_editing: pt.path_editing,
                parent_dir: pt.manifest.parent_dir.as_deref(),
            };
            self.render_internal(f, context);
        }
    }

    /// Render the pending incoming transaction popup from the engine.
    pub fn render_transaction_from_engine<'a>(&self, f: &mut Frame, app: &'a App) {
        if let Some(pi) = app.engine.pending_incoming() {
            let context = OfferContext::Transaction {
                name: &pi.display_name,
                size_str: format_file_size(pi.total_size),
                file_count: pi.manifest.files.len(),
                button_focus: pi.button_focus,
                border_color: Color::Magenta,
                height: 11,
                save_path: &pi.save_path_input,
                is_editing: pi.path_editing,
                parent_dir: pi.manifest.parent_dir.as_deref(),
            };
            self.render_internal(f, context);
        }
    }

    fn render_internal<'a>(&self, f: &mut Frame, context: OfferContext<'a>) {
        let area = f.area();

        // Estrarre i valori comuni
        let (height, _button_focus, border_color, text_lines) = match context {
            OfferContext::File {
                name,
                size_str,
                button_focus,
                border_color,
                height,
                save_path,
                is_editing,
            } => (
                height,
                button_focus,
                border_color,
                Self::build_file_text(name, size_str, button_focus, save_path, is_editing),
            ),
            OfferContext::Folder {
                name,
                size_str,
                file_count,
                button_focus,
                border_color,
                height,
            } => (
                height,
                button_focus,
                border_color,
                Self::build_folder_text(name, file_count, size_str, button_focus),
            ),
            OfferContext::Transaction {
                name,
                size_str,
                file_count,
                button_focus,
                border_color,
                height,
                save_path,
                is_editing,
                parent_dir,
            } => (
                height,
                button_focus,
                border_color,
                Self::build_transaction_text(
                    name,
                    file_count,
                    size_str,
                    button_focus,
                    save_path,
                    is_editing,
                    parent_dir,
                ),
            ),
        };

        let popup_area = Rect {
            x: area.width / 4,
            y: area.height / 3,
            width: area.width / 2,
            height,
        };

        let popup = Paragraph::new(text_lines)
            .block(
                Block::default()
                    .title(" Confirm Download ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border_color)),
            )
            .wrap(Wrap { trim: false });

        f.render_widget(Clear, popup_area);
        f.render_widget(popup, popup_area);
    }

    fn build_buttons(button_focus: usize) -> Vec<Span<'static>> {
        let download_style = if button_focus == 0 {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Black).bg(Color::DarkGray)
        };
        let cancel_style = if button_focus == 1 {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Black).bg(Color::DarkGray)
        };
        vec![
            Span::raw("  "),
            Span::styled(" Download ", download_style),
            Span::raw("  "),
            Span::styled(" Cancel ", cancel_style),
        ]
    }

    fn build_file_text(name: &str, size_str: String, button_focus: usize, save_path: &str, is_editing: bool) -> Vec<Line<'static>> {
        let path_style = if is_editing {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Cyan)
        };

        let name_string = name.to_string();
        let save_path_string = save_path.to_string();
        let edit_indicator = if is_editing {
            " [EDIT]".to_string()
        } else {
            String::new()
        };

        vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  File: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    name_string,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(" ({})", size_str)),
            ]),
            Line::from(vec![
                Span::styled("  Path: ", Style::default().fg(Color::DarkGray)),
                Span::styled(save_path_string, path_style),
                Span::styled(edit_indicator, Style::default().fg(Color::Yellow)),
            ]),
            Line::from(""),
            Line::from(Self::build_buttons(button_focus)),
        ]
    }

    fn build_folder_text(
        name: &str,
        file_count: u32,
        size_str: String,
        button_focus: usize,
    ) -> Vec<Line<'static>> {
        vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  Folder: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    name.to_string(),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![Span::raw(format!(
                "{} files, {}",
                file_count, size_str
            ))]),
            Line::from(""),
            Line::from(Self::build_buttons(button_focus)),
        ]
    }

    fn build_transaction_text(
        name: &str,
        file_count: usize,
        size_str: String,
        button_focus: usize,
        save_path: &str,
        is_editing: bool,
        parent_dir: Option<&str>,
    ) -> Vec<Line<'static>> {
        let path_style = if is_editing {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Cyan)
        };

        let name_string = name.to_string();
        let save_path_string = save_path.to_string();
        let edit_indicator = if is_editing {
            " [EDIT]".to_string()
        } else {
            String::new()
        };

        let mut lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  Transfer: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    name_string,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
        ];

        if let Some(dir) = parent_dir {
            lines.push(Line::from(vec![
                Span::styled("  Folder: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    dir.to_string(),
                    Style::default().fg(Color::Yellow),
                ),
            ]));
        }

        lines.push(Line::from(vec![
            Span::styled("  Size: ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!("{} ({} files)", size_str, file_count)),
        ]));

        lines.push(Line::from(vec![
            Span::styled("  Path: ", Style::default().fg(Color::DarkGray)),
            Span::styled(save_path_string, path_style),
            Span::styled(edit_indicator, Style::default().fg(Color::Yellow)),
        ]));

        lines.push(Line::from(""));
        lines.push(Line::from(Self::build_buttons(button_focus)));

        lines
    }
}

impl Default for SavePathPopup {
    fn default() -> Self {
        Self::new()
    }
}
