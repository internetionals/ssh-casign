use crate::config::Config;

pub(crate) mod oidc;
pub(crate) mod sign_key;
pub(crate) mod state;

pub(crate) async fn main(config: &str) {
    let config: Config = toml::from_str(config).expect("configuration");
    let app_state = state::AppState::new(config).await;

    // build our application with a route
    let app = axum::Router::new()
        .route("/sign", axum::routing::post(sign_key::sign_key))
        .with_state(app_state);

    // run our app with axum, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
