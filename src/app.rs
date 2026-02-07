use clap::Parser;
use iroh::{RelayMode, RelayUrl};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::fs;
use std::net::{SocketAddrV4, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Parser, Deserialize, Clone, Debug)]
#[command(author, version, about = "Crossdrop - P2P file sharing and chat")]
#[command(propagate_version = true)]
pub struct Args {
    /// Path to a config file (TOML)
    #[clap(long)]
    pub config: Option<PathBuf>,

    /// The IPv4 address that socket will listen on.
    #[clap(long)]
    pub ipv4_addr: Option<SocketAddrV4>,

    /// The IPv6 address that socket will listen on.
    #[clap(long)]
    pub ipv6_addr: Option<SocketAddrV6>,

    /// UDP port to bind on. If taken, tries next ports. 0 = auto (OS-assigned).
    #[clap(short, long, default_value_t = 0)]
    pub port: u16,

    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// The relay URL to use as a home relay.
    #[clap(long, default_value_t = RelayModeOption::Default)]
    pub relay: RelayModeOption,

    #[clap(long)]
    pub show_secret: bool,

    /// Path to file storing persistent secret key.
    #[clap(long)]
    pub secret_file: Option<PathBuf>,
}

impl Args {
    /// Load Args from CLI + TOML file (if it exists).
    /// CLI values override those from the file.
    pub fn load() -> Self {
        let cli_args = Args::parse();

        if let Some(config_path) = &cli_args.config
            && let Some(mut file_args) = Self::from_file(config_path)
        {
            file_args = Self::merge(file_args, cli_args);
            return file_args;
        }

        let default_path = PathBuf::from("config.toml");
        if let Some(mut file_args) = Self::from_file(&default_path) {
            file_args = Self::merge(file_args, cli_args);
            return file_args;
        }

        cli_args
    }

    fn from_file(path: &Path) -> Option<Self> {
        if !path.exists() {
            return None;
        }
        let content = fs::read_to_string(path).ok()?;
        toml::from_str::<Args>(&content).ok()
    }

    fn merge(mut file: Args, cli: Args) -> Args {
        if cli.ipv4_addr.is_some() {
            file.ipv4_addr = cli.ipv4_addr;
        }
        if cli.ipv6_addr.is_some() {
            file.ipv6_addr = cli.ipv6_addr;
        }
        if cli.config.is_some() {
            file.config = cli.config;
        }
        if cli.secret_file.is_some() {
            file.secret_file = cli.secret_file;
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
        file.relay = cli.relay;
        file
    }
}

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
