use crate::config::Config;

pub(crate) mod discovery;
pub(crate) mod oidc;
pub(crate) mod sign_key;
pub(crate) mod state;

pub(crate) async fn main(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let listen = config.listen.clone();
    let app_state = state::AppState::new(config).await?;

    let app = axum::Router::new()
        .route(
            &format!("/{}", ssh_casign_proto::DISCOVERY_PATH),
            axum::routing::get(discovery::discovery),
        )
        .route("/sign", axum::routing::post(sign_key::sign_key))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .map_err(|err| format!("failed to listen on {listen}: {err}"))?;
    tracing::info!("listening on {listen}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
