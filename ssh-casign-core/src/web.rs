use crate::config::Config;

pub(crate) mod discovery;
pub(crate) mod oidc;
pub(crate) mod sign_key;
pub(crate) mod state;

async fn no_store(mut response: axum::response::Response) -> axum::response::Response {
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

pub(crate) async fn main(
    config: Config,
    registry: &ssh_casign_ca::Registry,
) -> Result<(), Box<dyn std::error::Error>> {
    let listen = config.listen();
    let app_state = state::AppState::new(config, registry).await?;

    let app = axum::Router::new()
        .route(
            &format!("/{}", ssh_casign_proto::DISCOVERY_PATH),
            axum::routing::get(discovery::discovery),
        )
        .route(
            "/sign",
            // Including the token check's rejections: nothing from /sign may
            // be kept by a proxy or CDN.
            axum::routing::post(sign_key::sign_key).layer(axum::middleware::map_response(no_store)),
        )
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
