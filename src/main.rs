mod app;
mod core;
mod utils;
mod workers;

use crate::app::Args;
use crate::utils::log_buffer::{BufferLayer, LogBuffer};
use crate::utils::sos::SignalOfStop;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::load();

    // Init tracing with layered subscriber
    let filter = match args.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    let log_buffer = LogBuffer::new();

    let filter_layer = EnvFilter::new(filter);
    let buffer_layer = BufferLayer::new(log_buffer.clone());

    // Only the buffer layer captures logs — no fmt layer writing to stderr,
    // which would corrupt the Ratatui TUI. Logs are visible in the Logs menu.
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(buffer_layer)
        .init();

    let sos = SignalOfStop::new();

    // Ctrl+C handler
    let sos_clone = sos.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        sos_clone.cancel();
    });

    workers::tui::run(args, sos, log_buffer).await
}
