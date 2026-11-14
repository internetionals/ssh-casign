use std::{path::PathBuf, process::ExitCode};

mod audit;
mod authority;
mod certificate;
mod config;
mod web;

/// Config file: first command-line argument, `SSH_CASIGN_CONFIG`, or
/// `config.toml` in the working directory.
fn config_file() -> PathBuf {
    std::env::args_os()
        .nth(1)
        .or_else(|| std::env::var_os("SSH_CASIGN_CONFIG"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"))
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config_file = config_file();
    let config = std::fs::read_to_string(&config_file)
        .map_err(|err| format!("failed to read {}: {err}", config_file.display()))?;
    let config: config::Config = toml::from_str(&config)
        .map_err(|err| format!("failed to parse {}: {err}", config_file.display()))?;
    web::main(config).await
}

#[tokio::main]
async fn main() -> ExitCode {
    // Logs go to stderr: stdout is reserved for the audit log's stdout sink.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!("{err}");
            ExitCode::FAILURE
        }
    }
}
