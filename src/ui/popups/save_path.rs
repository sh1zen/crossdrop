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
    RemotePath {
        name: &'a str,
        size_str: String,
        remote_path: &'a str,
        save_path: &'a str,
        is_editing: bool,
        button_focus: usize,
        border_color: Color,
        height: u16,
        is_folder: bool,
    },
}

pub struct SavePathPopup;

impl SavePathPopup {
    pub fn new() -> Self {
        Self
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
                height: 12,
                save_path: &pi.save_path_input,
                is_editing: pi.path_editing,
                parent_dir: pi.manifest.parent_dir.as_deref(),
            };
            self.render_internal(f, context);
        }
    }

    pub fn render_remote_path<'a>(&self, f: &mut Frame, app: &'a App) {
        if let Some(req) = &app.remote_path_request {
            let context = OfferContext::RemotePath {
                name: &req.name,
                size_str: format_file_size(req.size),
                remote_path: &req.remote_path,
                save_path: &req.save_path_input,
                is_editing: req.is_path_editing,
                button_focus: req.button_focus,
                border_color: if req.is_folder { Color::Magenta } else { Color::Cyan },
                height: 12,
                is_folder: req.is_folder,
            };
            self.render_internal(f, context);
        }
    }

    fn render_internal<'a>(&self, f: &mut Frame, context: OfferContext<'a>) {
        let area = f.area();

        // Estrarre i valori comuni
        let (height, _button_focus, border_color, text_lines, title) = match context {
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
                " Confirm Download ",
            ),
            OfferContext::RemotePath {
                name,
                size_str,
                remote_path,
                save_path,
                is_editing,
                button_focus,
                border_color,
                height,
                is_folder,
            } => (
                height,
                button_focus,
                border_color,
                Self::build_remote_path_text(
                    name,
                    size_str,
                    remote_path,
                    save_path,
                    is_editing,
                    button_focus,
                    is_folder,
                ),
                if is_folder { " Request Folder " } else { " Request File " },
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
                    .title(title)
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border_color)),
            )
            .wrap(Wrap { trim: false });

        f.render_widget(Clear, popup_area);
        f.render_widget(popup, popup_area);
    }

    fn build_buttons(button_focus: usize) -> Vec<Span<'static>> {
        Self::build_buttons_with_labels(button_focus, " Download ", " Cancel ")
    }

    fn build_request_buttons(button_focus: usize) -> Vec<Span<'static>> {
        Self::build_buttons_with_labels(button_focus, " Request ", " Cancel ")
    }

    fn build_buttons_with_labels(
        button_focus: usize,
        accept_label: &str,
        cancel_label: &str,
    ) -> Vec<Span<'static>> {
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
            Span::styled(accept_label.to_string(), download_style),
            Span::raw("  "),
            Span::styled(cancel_label.to_string(), cancel_style),
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
        } else if button_focus == 2 {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
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
        let hint_text = if is_editing {
            "  Type to edit path \u{00b7} Enter/Esc to confirm"
        } else {
            "  Tab to navigate \u{00b7} Enter to select"
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
                Span::styled(dir.to_string(), Style::default().fg(Color::Yellow)),
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

        lines.push(Line::from(Span::styled(
            hint_text,
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Self::build_buttons(button_focus)));

        lines
    }

    fn build_remote_path_text(
        name: &str,
        size_str: String,
        remote_path: &str,
        save_path: &str,
        is_editing: bool,
        button_focus: usize,
        is_folder: bool,
    ) -> Vec<Line<'static>> {
        let path_style = if is_editing {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else if button_focus == 2 {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            Style::default().fg(Color::Cyan)
        };
        let edit_indicator = if is_editing {
            " [EDIT]".to_string()
        } else {
            String::new()
        };
        let hint_text = if is_editing {
            "  Type to edit path · Enter/Esc to confirm"
        } else {
            "  Tab to navigate · Enter to select"
        };

        let label = if is_folder { "Folder" } else { "File" };

        vec![
            Line::from(""),
            Line::from(vec![
                Span::styled(format!("  {}: ", label), Style::default().fg(Color::DarkGray)),
                Span::styled(
                    name.to_string(),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(" ({})", size_str)),
            ]),
            Line::from(vec![
                Span::styled("  Remote: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    remote_path.to_string(),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Save to: ", Style::default().fg(Color::DarkGray)),
                Span::styled(save_path.to_string(), path_style),
                Span::styled(edit_indicator, Style::default().fg(Color::Yellow)),
            ]),
            Line::from(Span::styled(
                hint_text,
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            Line::from(Self::build_request_buttons(button_focus)),
        ]
    }
}

impl Default for SavePathPopup {
    fn default() -> Self {
        Self::new()
    }
}
