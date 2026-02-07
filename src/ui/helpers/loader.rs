use ratatui::backend::Backend;
use ratatui::layout::Alignment;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::{Frame, Terminal};

const CROSSDROP_ASCII: &str = r#"
   ██████╗██████╗  ██████╗ ███████╗███████╗██████╗ ██████╗  ██████╗ ██████╗ 
  ██╔════╝██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗
  ██║     ██████╔╝██║   ██║███████╗███████╗██║  ██║██████╔╝██║   ██║██████╔╝
  ██║     ██╔══██╗██║   ██║╚════██║╚════██║██║  ██║██╔══██╗██║   ██║██╔═══╝ 
  ╚██████╗██║  ██║╚██████╔╝███████║███████║██████╔╝██║  ██║╚██████╔╝██║     
   ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝     
"#;

const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub fn render_loading_frame<B: Backend>(
    terminal: &mut Terminal<B>,
    frame_index: usize,
) -> anyhow::Result<()> {
    let spinner = SPINNER_FRAMES[frame_index % SPINNER_FRAMES.len()];

    terminal
        .draw(|f| {
            render_loading_ui(f, spinner);
        })
        .map_err(|e| anyhow::anyhow!("Terminal draw error: {:?}", e))?;

    Ok(())
}

fn render_loading_ui(f: &mut Frame, spinner: &str) {
    let area = f.area();

    // Create lines from the ASCII art
    let ascii_lines: Vec<Line> = CROSSDROP_ASCII
        .lines()
        .map(|line| {
            Line::from(Span::styled(
                line,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ))
        })
        .collect();

    // Add spinner and loading text
    let mut loading_lines = ascii_lines;
    loading_lines.push(Line::from(""));
    loading_lines.push(Line::from(vec![
        Span::styled(
            format!("{} ", spinner),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "Initializing peer node...",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::DIM),
        ),
    ]));

    let paragraph = Paragraph::new(loading_lines).alignment(Alignment::Center);

    f.render_widget(paragraph, area);
}
