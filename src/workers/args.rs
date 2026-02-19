//! Command-line argument parsing and configuration.
//!
//! Supports:
//! - CLI arguments via clap
//! - TOML configuration file
//! - Merging CLI with file config (CLI takes precedence)

use clap::Parser;
use iroh::{RelayMode, RelayUrl};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::fs;
use std::net::{SocketAddrV4, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Crossdrop - P2P file sharing and chat.
#[derive(Parser, Deserialize, Clone, Debug)]
#[command(author, version, about)]
#[command(propagate_version = true)]
pub struct Args {
    /// The IPv4 address that socket will listen on.
    #[clap(long)]
    pub ipv4_addr: Option<SocketAddrV4>,

    /// The IPv6 address that socket will listen on.
    #[clap(long)]
    pub ipv6_addr: Option<SocketAddrV6>,

    /// UDP port to bind on. If taken, tries next ports. 0 = auto (OS-assigned).
    #[clap(short, long, default_value_t = 0)]
    pub port: u16,

    /// Verbosity level (-v, -vv, -vvv).
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// The relay URL to use as a home relay.
    #[clap(long, default_value_t = RelayModeOption::Default)]
    pub relay: RelayModeOption,

    /// Show the secret key on startup.
    #[clap(long)]
    pub show_secret: bool,

    /// Enable remote access.
    #[clap(long)]
    pub remote_access: bool,

    /// Display name for this peer.
    #[clap(long)]
    pub display_name: Option<String>,

    /// Directory for all persistent data (secret keys, identity, transfers, peers).
    /// Defaults to ~/.crossdrop/
    #[clap(long)]
    pub conf: Option<PathBuf>,
}

impl Args {
    /// Load Args from CLI + TOML file (if it exists).
    /// CLI values override those from the file.
    pub fn load() -> Self {
        let mut cli_args = Args::parse();

        // Resolve relative paths to absolute before any working directory change
        cli_args.conf = cli_args.conf.map(Self::resolve_path);

        let default_path = PathBuf::from("config.toml");
        if let Some(file_args) = Self::from_file(&default_path) {
            return Self::merge(file_args, cli_args);
        }

        cli_args
    }

    /// Resolve a potentially relative path to an absolute one.
    fn resolve_path(p: PathBuf) -> PathBuf {
        if p.is_absolute() {
            p
        } else {
            std::env::current_dir().unwrap_or_default().join(p)
        }
    }

    /// Load args from a TOML file.
    fn from_file(path: &Path) -> Option<Self> {
        if !path.exists() {
            return None;
        }
        let content = fs::read_to_string(path).ok()?;
        toml::from_str::<Args>(&content).ok()
    }

    /// Merge file args with CLI args (CLI takes precedence).
    fn merge(mut file: Args, cli: Args) -> Args {
        if cli.ipv4_addr.is_some() {
            file.ipv4_addr = cli.ipv4_addr;
        }
        if cli.ipv6_addr.is_some() {
            file.ipv6_addr = cli.ipv6_addr;
        }
        if cli.verbose > 0 {
            file.verbose = cli.verbose;
        }
        if cli.show_secret {
            file.show_secret = true;
        }
        if cli.port > 0 {
            file.port = cli.port;
        }
        if cli.display_name.is_some() {
            file.display_name = cli.display_name;
        }
        if cli.remote_access {
            file.remote_access = true;
        }
        if cli.conf.is_some() {
            file.conf = cli.conf;
        }
        file.relay = cli.relay;
        file
    }
}

// ── Relay Mode Option ──────────────────────────────────────────────────────────

/// Available command line options for configuring relays.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RelayModeOption {
    Disabled,
    Default,
    Custom(RelayUrl),
}

impl FromStr for RelayModeOption {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "disabled" => Ok(Self::Disabled),
            "default" => Ok(Self::Default),
            _ => Ok(Self::Custom(RelayUrl::from_str(s)?)),
        }
    }
}

impl Display for RelayModeOption {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => f.write_str("disabled"),
            Self::Default => f.write_str("default"),
            Self::Custom(url) => url.fmt(f),
        }
    }
}

impl From<RelayModeOption> for RelayMode {
    fn from(value: RelayModeOption) -> Self {
        match value {
            RelayModeOption::Disabled => RelayMode::Disabled,
            RelayModeOption::Default => RelayMode::Default,
            RelayModeOption::Custom(url) => RelayMode::Custom(url.into()),
        }
    }
}

impl Default for RelayModeOption {
    fn default() -> Self {
        Self::Default
    }
}
