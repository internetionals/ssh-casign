mod web;
mod ssh_ca;

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    web::main().await;
}
