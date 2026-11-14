use std::sync::Arc;

use axum::{extract::State, http::header, response::IntoResponse};
use ssh_casign_proto::{AuthorityInfo, ServiceInfo};

use super::state::AppState;
use crate::{authority::SshCaProviders, config::Config};

/// Sign endpoint relative to the discovery document URL
/// (`<base>/.well-known/ssh-casign`), so it also resolves correctly when the
/// service is published under a path prefix behind a reverse proxy.
const SIGN_ENDPOINT: &str = "../sign";

pub(super) fn document(
    config: &Config,
    authorities: &SshCaProviders,
) -> Result<String, Box<dyn std::error::Error>> {
    let authorities = authorities
        .iter()
        .map(|(name, provider)| {
            Ok((
                name.to_string(),
                AuthorityInfo {
                    public_key: provider.public_key().to_openssh()?,
                    cert_types: provider.cert_types().to_vec(),
                },
            ))
        })
        .collect::<Result<_, ssh_key::Error>>()?;
    let info = ServiceInfo {
        issuer: config.oidc_provider.issuer().to_string(),
        client_id: config.oidc_provider.client_id().to_string(),
        scopes: config.oidc_provider.scopes().to_vec(),
        sign_endpoint: SIGN_ENDPOINT.to_string(),
        authorities,
    };
    Ok(serde_json::to_string_pretty(&info)?)
}

/// `GET /.well-known/ssh-casign`
pub(super) async fn discovery(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/json")],
        state.discovery_document.clone(),
    )
}
