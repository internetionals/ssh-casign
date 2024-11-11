mod oidc;
mod sign_key;
mod state;

pub(crate) async fn main() {
    let oidc_issuer = "http://localhost:8080/ssh-casign";
    let ssh_ca = crate::ssh_ca::SshCa::new("ssh-ca", "ssh-ca.pub").expect("ssh-ca keys");
    let app_state = state::AppState::new(oidc_issuer, ssh_ca).await;

    // build our application with a route
    let app = axum::Router::new()
        .route("/sign", axum::routing::post(sign_key::sign_key))
        .with_state(app_state);

    // run our app with axum, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
