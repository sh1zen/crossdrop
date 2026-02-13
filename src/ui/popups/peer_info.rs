use crate::ui::helpers::{get_display_name, short_peer_id};
use crate::workers::app::App;
use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

/// Render the peer info popup.
pub fn render_peer_info_popup(f: &mut Frame, app: &App) {
    let peer_id = match &app.peer_info_popup {
        Some(id) => id,
        None => return,
    };

    let popup_width = 60u16;
    let popup_height = 14u16;
    let popup_x = (f.area().width.saturating_sub(popup_width)) / 2;
    let popup_y = (f.area().height.saturating_sub(popup_height)) / 2;
    let popup_area = ratatui::layout::Rect::new(popup_x, popup_y, popup_width, popup_height);

    f.render_widget(Clear, popup_area);

    let display_name = get_display_name(app, peer_id);
    let _short_id = short_peer_id(peer_id);
    let is_online = app.is_peer_online(peer_id);
    let status = if is_online { "Online" } else { "Offline" };
    let status_color = if is_online { Color::Green } else { Color::DarkGray };

    // Get cipher key
    let key_str = app
        .peer_keys
        .get(peer_id)
        .map(|k| hex::encode(k))
        .unwrap_or_else(|| "N/A".to_string());

    // Get connection time
    let connected_at = app
        .peer_connected_at
        .get(peer_id)
        .cloned()
        .unwrap_or_else(|| "N/A".to_string());

    // Get remote IP address
    let ip_str = app
        .peer_ips
        .get(peer_id)
        .cloned()
        .unwrap_or_else(|| "N/A".to_string());

    // Get per-peer stats (messages_sent, messages_received, files_sent, files_received)
    let (msg_sent, msg_recv, files_sent, files_recv) = app
        .peer_stats
        .get(peer_id)
        .cloned()
        .unwrap_or((0, 0, 0, 0));

    let lines = vec![
        Line::from(vec![
            Span::styled("Name: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&display_name, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("IP: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&ip_str, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("Status: ", Style::default().fg(Color::DarkGray)),
            Span::styled(status, Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Key: ", Style::default().fg(Color::DarkGray)),
            Span::styled(key_str, Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::styled("Connected: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&connected_at, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![]),
        Line::from(vec![
            Span::styled("Messages: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{} sent / {} recv", msg_sent, msg_recv),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("Files: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{} sent / {} recv", files_sent, files_recv),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![]),
        Line::from(vec![Span::styled(
            "Press Enter or Esc to close",
            Style::default().fg(Color::DarkGray),
        )]),
    ];

    let block = Block::default()
        .title(" Peer Details ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, popup_area);
}
