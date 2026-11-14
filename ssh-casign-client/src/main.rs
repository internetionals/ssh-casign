use std::{io::Write, process::ExitCode};

fn main() -> ExitCode {
    // initialize tracing
    tracing_subscriber::fmt::init();

    // call with cli provided args and exit with code based on result
    let args = std::env::args();
    let exit_code = match ssh_casign_client::run(args) {
        Ok(Some(output)) => {
            let _ = std::io::stdout().write_all(output.as_bytes());
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(err) => {
            print!("{}", err);
            ExitCode::FAILURE
        }
    };
    exit_code
}
