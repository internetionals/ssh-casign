use std::io::Read;

mod certificate_settings;
mod config;
mod ssh_ca;
mod web;

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    let mut config = String::new();
    std::fs::File::open("config.toml")
        .expect("config file")
        .read_to_string(&mut config)
        .expect("config data");
    web::main(&config).await;
}
