use std::{io::Write, process::ExitCode};

fn main() -> ExitCode {
    let _ = color_eyre::install();
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    match ssh_casign_client::run(std::env::args_os()) {
        Ok(Some(output)) => {
            let _ = std::io::stdout().write_all(output.as_bytes());
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(err) => {
            // clap errors (including --help/--version) know how to print themselves
            if let Some(clap_err) = err.downcast_ref::<clap::Error>() {
                let _ = clap_err.print();
                return if clap_err.use_stderr() {
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                };
            }
            if std::env::var_os("RUST_BACKTRACE").is_some() {
                eprintln!("Error: {err:?}");
            } else {
                eprintln!("Error: {err:#}");
            }
            ExitCode::FAILURE
        }
    }
}
