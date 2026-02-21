use ratatui::style::Color;
use serde::{Deserialize, Serialize};

/// Available UI themes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum AppTheme {
    #[default]
    Default,
    Blue,
    Green,
    Purple,
    Red,
}

impl AppTheme {
    pub fn label(&self) -> &'static str {
        match self {
            AppTheme::Default => "Default (Cyan)",
            AppTheme::Blue => "Blue",
            AppTheme::Green => "Green",
            AppTheme::Purple => "Purple",
            AppTheme::Red => "Red",
        }
    }

    pub fn accent(&self) -> Color {
        match self {
            AppTheme::Default => Color::Cyan,
            AppTheme::Blue => Color::Blue,
            AppTheme::Green => Color::Green,
            AppTheme::Purple => Color::Magenta,
            AppTheme::Red => Color::Red,
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "blue" => AppTheme::Blue,
            "green" => AppTheme::Green,
            "purple" => AppTheme::Purple,
            "red" => AppTheme::Red,
            _ => AppTheme::Default,
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            AppTheme::Default => "default",
            AppTheme::Blue => "blue",
            AppTheme::Green => "green",
            AppTheme::Purple => "purple",
            AppTheme::Red => "red",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            AppTheme::Default => AppTheme::Blue,
            AppTheme::Blue => AppTheme::Green,
            AppTheme::Green => AppTheme::Purple,
            AppTheme::Purple => AppTheme::Red,
            AppTheme::Red => AppTheme::Default,
        }
    }
}

/// User-configurable settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Display name shown to peers.
    #[serde(default)]
    pub display_name: String,
    /// Whether remote file access is enabled.
    #[serde(default)]
    pub remote_access: bool,
    /// Whether remote key listener is enabled.
    #[serde(default)]
    pub remote_key_listener: bool,
    /// UI theme.
    #[serde(default)]
    pub theme: AppTheme,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            display_name: String::new(),
            // Remote access is disabled by default per security spec.
            remote_access: false,
            // Remote key listener is disabled by default per security spec.
            remote_key_listener: false,
            theme: AppTheme::Default,
        }
    }
}

impl Settings {
    pub fn new(display_name: Option<String>) -> Self {
        Self {
            display_name: display_name.unwrap_or_default(),
            ..Self::default()
        }
    }
}
