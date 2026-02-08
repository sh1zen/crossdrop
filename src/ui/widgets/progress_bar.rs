use ratatui::style::Color;
use ratatui::text::{Line, Span};

/// Reusable progress bar widget
pub struct ProgressBar {
    width: usize,
}

impl ProgressBar {
    pub fn new(width: usize) -> Self {
        Self { width }
    }

    /// Renders a progress bar as a Line
    pub fn render(&self, completed: u32, total: u32, color: Color) -> Line<'static> {
        if total == 0 {
            return Line::from(vec![
                Span::raw("["),
                Span::raw("-".repeat(self.width)),
                Span::raw("] 0%"),
            ]);
        }

        let pct = ((completed as f64 / total as f64) * 100.0).min(100.0) as u16;
        let filled = ((self.width as f64 * pct as f64) / 100.0).round() as usize;
        let empty = self.width.saturating_sub(filled);

        Line::from(vec![
            Span::raw("["),
            Span::styled("#".repeat(filled), color),
            Span::raw("-".repeat(empty)),
            Span::raw(format!("] {}%", pct)),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_bar_zero_total() {
        let bar = ProgressBar::new(20);
        let line = bar.render(0, 0, Color::Green);
        // Should not panic and should show 0%
        let text = line
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect::<String>();
        assert!(text.contains("0%"));
    }

    #[test]
    fn test_progress_bar_full() {
        let bar = ProgressBar::new(10);
        let line = bar.render(100, 100, Color::Green);
        let text = line
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect::<String>();
        assert!(text.contains("100%"));
        assert!(text.contains("##########")); // All filled
    }

    #[test]
    fn test_progress_bar_half() {
        let bar = ProgressBar::new(10);
        let line = bar.render(50, 100, Color::Green);
        let text = line
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect::<String>();
        assert!(text.contains("50%"));
    }
}
