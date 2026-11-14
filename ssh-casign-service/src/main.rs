//! The ssh-casign signing service binary: where the configuration comes
//! from, logging, the TLS stack, and which CA key backends this build
//! contains (Cargo features `ca-*`). Everything else is in
//! `ssh-casign-core`.

use std::{path::PathBuf, process::ExitCode};

use ssh_casign_core::{Config, Registry};

#[cfg(not(any(feature = "tls-native", feature = "tls-rustls")))]
compile_error!("enable a TLS feature: tls-native (default) or tls-rustls");

/// The CA key backends of this build, and hints for the others.
fn registry() -> Registry {
    let mut registry = Registry::new();
    #[cfg(feature = "ca-file")]
    registry.register(ssh_casign_ca_file::PROVIDER, ssh_casign_ca_file::load);
    #[cfg(not(feature = "ca-file"))]
    registry.unavailable("file", "ca-file");
    #[cfg(feature = "ca-pkcs11")]
    registry.register(ssh_casign_ca_pkcs11::PROVIDER, ssh_casign_ca_pkcs11::load);
    #[cfg(not(feature = "ca-pkcs11"))]
    registry.unavailable("pkcs11", "ca-pkcs11");
    #[cfg(feature = "ca-vault")]
    registry.register(ssh_casign_ca_vault::PROVIDER, ssh_casign_ca_vault::load);
    #[cfg(not(feature = "ca-vault"))]
    registry.unavailable("vault", "ca-vault");
    #[cfg(feature = "ca-azure-keyvault")]
    registry.register(ssh_casign_ca_azure::PROVIDER, ssh_casign_ca_azure::load);
    #[cfg(not(feature = "ca-azure-keyvault"))]
    registry.unavailable("azure_keyvault", "ca-azure-keyvault");
    #[cfg(feature = "ca-aws-kms")]
    registry.register(ssh_casign_ca_aws::PROVIDER, ssh_casign_ca_aws::load);
    #[cfg(not(feature = "ca-aws-kms"))]
    registry.unavailable("aws_kms", "ca-aws-kms");
    #[cfg(feature = "ca-gcp-kms")]
    registry.register(ssh_casign_ca_gcp::PROVIDER, ssh_casign_ca_gcp::load);
    #[cfg(not(feature = "ca-gcp-kms"))]
    registry.unavailable("gcp_kms", "ca-gcp-kms");
    registry
}

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
    let config: Config =
        toml::from_str(&config).map_err(|err| format!("failed to parse {source}: {err}"))?;
    ssh_casign_core::serve(config, &registry()).await
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
