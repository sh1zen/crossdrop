/// Chat commands starting with `/`.
///
/// Commands are NOT sent as normal messages and are NOT persisted in message history.
/// They are parsed and executed locally before any network send.
use tracing::warn;


/// Recognised chat commands.
#[derive(Debug, Clone, PartialEq)]
pub enum ChatCommand {
    /// `/clear` — clears the current chat view (room or peer chat).
    Clear,
    /// `/help` — shows available commands inline.
    Help,
}

/// Available commands with short descriptions (for `/help` output).
pub const COMMAND_HELP: &[(&str, &str)] = &[
    ("/clear", "Clear the current chat view"),
    ("/help", "Show available commands"),
];

/// Try to parse `input` as a slash-command.
///
/// Returns `None` when the input is a regular message (doesn't start with `/`).
/// Returns `Some(Ok(cmd))` for a recognized command, or `Some(Err(msg))` for an
/// unknown command.
pub fn parse_command(input: &str) -> Option<Result<ChatCommand, String>> {
    let trimmed = input.trim();
    if !trimmed.starts_with('/') {
        return None;
    }
    let cmd = trimmed.split_whitespace().next()?;
    match cmd {
        "/clear" => Some(Ok(ChatCommand::Clear)),
        "/help" => Some(Ok(ChatCommand::Help)),
        _ => {
            warn!(event = "unknown_command", command = %cmd, "Unknown chat command");
            Some(Err(format!("Unknown command: {}", cmd)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regular_message_is_not_a_command() {
        assert!(parse_command("hello world").is_none());
        assert!(parse_command("").is_none());
    }

    #[test]
    fn clear_command() {
        assert_eq!(parse_command("/clear"), Some(Ok(ChatCommand::Clear)));
        assert_eq!(
            parse_command("/clear extra args"),
            Some(Ok(ChatCommand::Clear))
        );
    }

    #[test]
    fn help_command() {
        assert_eq!(parse_command("/help"), Some(Ok(ChatCommand::Help)));
    }

    #[test]
    fn unknown_command() {
        assert!(matches!(parse_command("/foo"), Some(Err(_))));
    }
}
