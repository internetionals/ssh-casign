use std::sync::Arc;

use axum::{extract::State, http::header, response::IntoResponse};
use ssh_casign_proto::{AuthorityInfo, ServiceInfo};

use super::state::AppState;
use crate::config::Config;
use ssh_casign_ca::Authorities as SshCaProviders;

/// Sign endpoint relative to the discovery document URL
/// (`<base>/.well-known/ssh-casign`), so it also resolves correctly when the
/// service is published under a path prefix behind a reverse proxy.
const SIGN_ENDPOINT: &str = "../sign";
/// The KRL and its signatures, relative like the sign endpoint.
const REVOCATION_LIST: &str = "../revoked.krl";
const REVOCATION_LIST_SIGNATURES: &str = "../revoked.krl.sig";

pub(super) fn document(
    config: &Config,
    authorities: &SshCaProviders,
    trust: ssh_casign_proto::trust::SignedTrust,
) -> Result<String, Box<dyn std::error::Error>> {
    let authorities = authorities
        .iter()
        .map(|(name, provider)| {
            Ok((
                name.to_string(),
                AuthorityInfo {
                    public_key: provider.public_key().to_openssh()?,
                    cert_types: provider.cert_types().to_vec(),
                    signature_algorithms: provider
                        .signature_algorithms()
                        .iter()
                        .map(|algorithm| algorithm.to_string())
                        .collect(),
                    known_hosts_pattern: provider.known_hosts_pattern().map(str::to_string),
                    retired: provider.retired(),
                },
            ))
        })
        .collect::<Result<_, ssh_key::Error>>()?;
    let info = ServiceInfo {
        issuer: config.oidc_provider.issuer().to_string(),
        client_id: config.oidc_provider.client_id().to_string(),
        scopes: config.oidc_provider.scopes().to_vec(),
        sign_endpoint: SIGN_ENDPOINT.to_string(),
        revocation_list: Some(REVOCATION_LIST.to_string()),
        revocation_list_signatures: Some(REVOCATION_LIST_SIGNATURES.to_string()),
        trust: Some(trust),
        authorities,
    };
    Ok(serde_json::to_string_pretty(&info)?)
}

/// `GET /revoked.krl`: the KRL, with an ETag so timers can ask whether it
/// changed (`If-None-Match` gives 304).
pub(super) async fn revocation_list(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let snapshot = state.revocations.current();
    let etag = snapshot.etag();
    let cache = [
        (header::ETAG, etag.to_string()),
        (header::CACHE_CONTROL, DISCOVERY_MAX_AGE.to_string()),
    ];
    let unchanged = headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|tag| tag.trim() == etag || tag.trim() == "*");
    if unchanged {
        return (axum::http::StatusCode::NOT_MODIFIED, cache).into_response();
    }
    (
        cache,
        [(header::CONTENT_TYPE, "application/octet-stream".to_string())],
        snapshot.krl().to_vec(),
    )
        .into_response()
}

/// `GET /revoked.krl.sig`: the authorities' SSHSIG signatures over the KRL,
/// with the KRL's ETag, so a client can tell they belong together.
pub(super) async fn revocation_list_signatures(
    State(state): State<Arc<AppState>>,
) -> axum::response::Response {
    let snapshot = state.revocations.current();
    (
        [
            (header::ETAG, snapshot.etag().to_string()),
            (header::CACHE_CONTROL, DISCOVERY_MAX_AGE.to_string()),
            (header::CONTENT_TYPE, "text/plain".to_string()),
        ],
        snapshot.signatures().to_string(),
    )
        .into_response()
}

/// How long clients and caches may keep the discovery document. Short, so
/// configuration changes (new authorities, rotated keys) arrive quickly.
const DISCOVERY_MAX_AGE: &str = "max-age=300";

/// `GET /.well-known/ssh-casign`
pub(super) async fn discovery(State(state): State<Arc<AppState>>) -> axum::response::Response {
    // Built per request: the trust statement is re-signed over time.
    match document(&state.config, &state.authorities, state.trust.current()) {
        Ok(document) => (
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, DISCOVERY_MAX_AGE),
            ],
            document,
        )
            .into_response(),
        Err(err) => {
            tracing::error!("discovery document: {err}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
