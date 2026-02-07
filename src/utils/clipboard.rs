//! Cross-platform clipboard utilities.
//!
//! Provides a single function to copy text to the system clipboard,
//! with platform-specific implementations for Windows, macOS, and Linux.

use std::io::Write;
use std::process::{Command, Stdio};

/// Copy text to the system clipboard. Cross-platform.
///
/// Returns `true` if the operation succeeded, `false` otherwise.
/// Uses platform-specific clipboard utilities:
/// - Windows: `clip`
/// - macOS: `pbcopy`
/// - Linux: `xclip`
pub fn copy_to_clipboard(text: &str) -> bool {
    execute_clipboard_command(text).is_ok()
}

/// Execute the platform-specific clipboard command.
#[cfg(windows)]
fn execute_clipboard_command(text: &str) -> std::io::Result<()> {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let mut child = Command::new("clip")
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(text.as_bytes())?;
    }
    child.wait()?;
    Ok(())
}

/// Execute the platform-specific clipboard command.
#[cfg(target_os = "macos")]
fn execute_clipboard_command(text: &str) -> std::io::Result<()> {
    let mut child = Command::new("pbcopy")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(text.as_bytes())?;
    }
    child.wait()?;
    Ok(())
}

/// Execute the platform-specific clipboard command.
#[cfg(all(not(windows), not(target_os = "macos")))]
fn execute_clipboard_command(text: &str) -> std::io::Result<()> {
    let mut child = Command::new("xclip")
        .args(["-selection", "clipboard"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(text.as_bytes())?;
    }
    child.wait()?;
    Ok(())
}
