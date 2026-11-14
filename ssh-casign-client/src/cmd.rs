use clap::Parser;
use std::path::PathBuf;

mod cert;

use crate::config::Config;
use crate::error::{Result, WrapErr};
pub(crate) type CmdResult = Result<Option<String>>;

#[derive(clap::Subcommand, Clone, Debug)]
enum Cmd {
    Cert(cert::Args),
}

#[derive(Parser)]
pub(crate) struct Args {
    #[clap(short('f'), long)]
    config_file: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

pub(crate) fn run_with_config(args: &Args, config: &Config) -> CmdResult {
    match &args.cmd {
        Cmd::Cert(args) => cert::run(args, config),
    }
}

fn default_config_file() -> PathBuf {
    dirs::config_dir()
        .unwrap_or(dirs::home_dir().unwrap_or_default().join(".config"))
        .join("ssh-casign-client")
        .join("config.toml")
}

fn load_config(args: &Args) -> Result<Config> {
    let config = if let Some(config_file) = &args.config_file {
        // Load indicated config file
        let config_str = std::fs::read_to_string(config_file).wrap_err_with(|| {
            format!(
                "Failed to read config file: {}",
                config_file.to_string_lossy()
            )
        })?;
        toml::from_str(&config_str).wrap_err_with(|| {
            format!(
                "Error parsing config file: {}",
                config_file.to_string_lossy()
            )
        })?
    } else {
        // Attempt to load default config file
        let config_file = default_config_file();
        match std::fs::read_to_string(&config_file).wrap_err_with(|| {
            format!(
                "Failed to read config file: {}",
                config_file.to_string_lossy()
            )
        }) {
            Ok(config_str) => toml::from_str(&config_str).wrap_err_with(|| {
                format!(
                    "Failed to parse config file: {}",
                    config_file.to_string_lossy()
                )
            })?,
            Err(err) => {
                // Fallback to default config
                tracing::debug!("Unable to open default config file: {}; ignoring", err);
                Default::default()
            }
        }
    };
    Ok(config)
}

pub(crate) fn run(args: &Args) -> CmdResult {
    let config = load_config(args)?;
    run_with_config(args, &config)
}
