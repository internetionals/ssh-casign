use std::{path::PathBuf, process::ExitCode};

#[cfg(not(any(feature = "tls-native", feature = "tls-rustls")))]
compile_error!("enable a TLS feature: tls-native (default) or tls-rustls");

mod audit;
mod authority;
#[cfg(feature = "ca-azure-keyvault")]
mod azure;
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

/// The whole configuration in an environment variable, for platforms where
/// settings are easier to manage than files (e.g. Azure app settings).
const CONFIG_ENV: &str = "SSH_CASIGN_CONFIG_TOML";

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let (source, config) = match std::env::var(CONFIG_ENV) {
        Ok(config) if !config.trim().is_empty() => (CONFIG_ENV.to_string(), config),
        _ => {
            let config_file = config_file();
            let config = std::fs::read_to_string(&config_file)
                .map_err(|err| format!("failed to read {}: {err}", config_file.display()))?;
            (config_file.display().to_string(), config)
        }
    };
    let config: config::Config =
        toml::from_str(&config).map_err(|err| format!("failed to parse {source}: {err}"))?;
    web::main(config).await
}

#[tokio::main]
async fn main() -> ExitCode {
    // Logs go to stderr: stdout is reserved for the audit log's stdout sink.
    // No colors when stderr isn't a terminal (e.g. Azure Functions, Lambda).
    use std::io::IsTerminal;
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
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
