//! `POST /revoke` and `GET /certificates`: revocation through the service
//! (see `ssh_casign_proto::revoke`).
//!
//! - A **key holder** revokes that key with a proof of possession, without
//!   a token.
//! - An **administrator** (a token matching `revocation.admins`) revokes
//!   anything: a serial, a key ID, a key, a certificate, or every unexpired
//!   certificate a search of the issuance index matches (an owner, a
//!   principal, a key, a client address, ...), e.g. after spotting abuse.
//! - A **signed-in user** revokes their own certificates: those the issuance
//!   index has for their token's issuer and ID.
//!
//! Every revocation is written to the store's revocations document, applied
//! at once on this instance (others follow within `reload_interval`), and
//! recorded in the audit log.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use ssh_casign_proto::{
    revoke::{
        possession_message, CertificateFilter, CertificatesResponse, IssuedCertificate, Owner,
        RevokeRequest, RevokeResponse, RevokedEntry, POSSESSION_MAX_SKEW, POSSESSION_NAMESPACE,
    },
    trust, ErrorResponse,
};

use super::{oidc, state::AppState};
use crate::{audit, certificate::key_id, index, revocation::RevokeError};

const MAX_REASON_LEN: usize = 200;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

struct Failure(StatusCode, String);

impl Failure {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self(status, message.into())
    }
}

impl From<oidc::AuthError> for Failure {
    fn from(err: oidc::AuthError) -> Self {
        let oidc::AuthError::InvalidToken(message) = err;
        Self(
            StatusCode::UNAUTHORIZED,
            format!("invalid token: {message}"),
        )
    }
}

fn respond(result: Result<Response, Failure>, request_id: &str) -> Response {
    let mut response = match result {
        Ok(response) => response,
        Err(Failure(status, message)) => {
            if status.is_server_error() {
                tracing::error!(request_id, "{status}: {message}");
            } else {
                tracing::info!(request_id, "{status}: {message}");
            }
            (status, Json(ErrorResponse { error: message })).into_response()
        }
    };
    if let Ok(value) = HeaderValue::from_str(request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

/// The caller of a token-authenticated request.
struct Caller {
    auth: oidc::Authenticated,
    oidc_id: String,
    admin: bool,
}

impl Caller {
    async fn from_headers(state: &AppState, headers: &HeaderMap) -> Result<Self, Failure> {
        let auth = oidc::optional_authentication(state, headers)
            .await?
            .ok_or_else(|| {
                Failure::new(
                    StatusCode::UNAUTHORIZED,
                    "sign in (Bearer token) or prove possession of the key",
                )
            })?;
        let oidc_id = key_id::oidc_id(&auth.claims, &auth.issuer.id_claim)
            .map_err(|err| Failure::new(StatusCode::FORBIDDEN, err.to_string()))?;
        let admin = state.config.revocation.as_ref().is_some_and(|config| {
            config
                .admins
                .iter()
                .any(|admin| admin.matches(&auth.issuer.name, &auth.claims))
        });
        Ok(Self {
            auth,
            oidc_id,
            admin,
        })
    }

    fn owner(&self) -> Owner {
        Owner {
            issuer: self.auth.issuer.issuer.clone(),
            id: self.oidc_id.clone(),
        }
    }

    fn describe(&self) -> String {
        let who = format!("{} {}", self.auth.issuer.name, self.oidc_id);
        if self.admin {
            format!("admin {who}")
        } else {
            who
        }
    }
}

fn index_store(state: &AppState) -> Result<&dyn ssh_casign_store::Store, Failure> {
    state.index.as_deref().ok_or_else(|| {
        Failure::new(
            StatusCode::NOT_IMPLEMENTED,
            "the issuance index is disabled on this service",
        )
    })
}

fn index_failure(err: ssh_casign_store::StoreError) -> Failure {
    Failure::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("issuance index: {err}"),
    )
}

async fn indexed(state: &AppState, owner: &Owner) -> Result<Vec<IssuedCertificate>, Failure> {
    index::list(index_store(state)?, owner, now())
        .await
        .map_err(index_failure)
}

async fn searched(
    state: &AppState,
    filter: &CertificateFilter,
) -> Result<Vec<IssuedCertificate>, Failure> {
    index::search(index_store(state)?, filter, now())
        .await
        .map_err(index_failure)
}

fn parse_serial(serial: &str) -> Result<u64, Failure> {
    serial.trim().parse().map_err(|_| {
        Failure::new(
            StatusCode::BAD_REQUEST,
            format!("invalid serial '{serial}'"),
        )
    })
}

/// The entry to revoke for a key holder's proof of possession.
fn possession_entry(
    state: &AppState,
    possession: &ssh_casign_proto::revoke::Possession,
    reason: Option<String>,
) -> Result<RevokedEntry, Failure> {
    let key = trust::normalize_key(&possession.public_key)
        .map_err(|err| Failure::new(StatusCode::BAD_REQUEST, err))?;
    let now = now();
    if possession.time.abs_diff(now) > POSSESSION_MAX_SKEW {
        return Err(Failure::new(
            StatusCode::FORBIDDEN,
            "the proof of possession is too old or from the future (check the clock)",
        ));
    }
    let message = possession_message(&key, &state.trust.id(), possession.time);
    let signers = trust::valid_signers(
        POSSESSION_NAMESPACE,
        message.as_bytes(),
        std::slice::from_ref(&possession.signature),
    );
    if !signers.contains(&key) {
        return Err(Failure::new(
            StatusCode::FORBIDDEN,
            "the proof of possession doesn't verify",
        ));
    }
    Ok(RevokedEntry {
        serial: None,
        authority: None,
        key_id: None,
        fingerprint: Some(
            trust::fingerprint(&key).map_err(|err| Failure::new(StatusCode::BAD_REQUEST, err))?,
        ),
        reason,
        revoked_at: now,
        revoked_by: "key holder".into(),
    })
}

/// The authority whose key signed `certificate`, and its serial.
fn certificate_target(state: &AppState, certificate: &str) -> Result<(String, u64), Failure> {
    let certificate = ssh_key::Certificate::from_openssh(certificate.trim()).map_err(|err| {
        Failure::new(
            StatusCode::BAD_REQUEST,
            format!("invalid certificate: {err}"),
        )
    })?;
    let authority = state
        .authorities
        .iter()
        .find(|(_, authority)| authority.public_key().key_data() == certificate.signature_key())
        .map(|(name, _)| name.to_string())
        .ok_or_else(|| {
            Failure::new(
                StatusCode::BAD_REQUEST,
                "the certificate wasn't signed by one of this service's authorities",
            )
        })?;
    Ok((authority, certificate.serial()))
}

/// The entries a token-authenticated request revokes.
async fn caller_entries(
    state: &AppState,
    caller: &Caller,
    request: RevokeRequest,
    reason: Option<String>,
) -> Result<Vec<RevokedEntry>, Failure> {
    let targets = [
        request.serial.is_some(),
        request.key_id.is_some(),
        request.fingerprint.is_some(),
        request.certificate.is_some(),
        request.all,
        request.matching.is_some(),
    ];
    if targets.iter().filter(|set| **set).count() != 1 {
        return Err(Failure::new(
            StatusCode::BAD_REQUEST,
            "set exactly one of serial, key_id, fingerprint, certificate, all or matching",
        ));
    }
    let entry =
        |serial: Option<u64>, authority: Option<String>, key_id, fingerprint| RevokedEntry {
            serial: serial.map(|serial| serial.to_string()),
            authority,
            key_id,
            fingerprint,
            reason: reason.clone(),
            revoked_at: now(),
            revoked_by: caller.describe(),
        };
    let admin_only = |what: &str| {
        Failure::new(
            StatusCode::FORBIDDEN,
            format!("only administrators can revoke by {what}; revoke your own certificates by serial, certificate or all"),
        )
    };
    // A serial (and authority) the caller may revoke: any for administrators,
    // otherwise one of their own certificates.
    let own = |serial: u64, authority: String| async move {
        if caller.admin {
            return Ok(entry(Some(serial), Some(authority), None, None));
        }
        let mine = indexed(state, &caller.owner()).await?;
        if mine
            .iter()
            .any(|c| c.serial == serial.to_string() && c.authority == authority)
        {
            Ok(entry(Some(serial), Some(authority), None, None))
        } else {
            Err(Failure::new(
                StatusCode::FORBIDDEN,
                format!("serial {serial} of {authority} is not one of your unexpired certificates"),
            ))
        }
    };
    if let Some(serial) = &request.serial {
        let authority = request
            .authority
            .clone()
            .ok_or_else(|| Failure::new(StatusCode::BAD_REQUEST, "a serial needs its authority"))?;
        return Ok(vec![own(parse_serial(serial)?, authority).await?]);
    }
    if let Some(certificate) = &request.certificate {
        let (authority, serial) = certificate_target(state, certificate)?;
        return Ok(vec![own(serial, authority).await?]);
    }
    if let Some(key_id) = request.key_id {
        if !caller.admin {
            return Err(admin_only("key ID"));
        }
        return Ok(vec![entry(None, request.authority, Some(key_id), None)]);
    }
    if let Some(fingerprint) = request.fingerprint {
        if !caller.admin {
            return Err(admin_only("key (prove possession of it instead)"));
        }
        return Ok(vec![entry(None, None, None, Some(fingerprint))]);
    }
    let certificates = match request.matching {
        Some(filter) => {
            if !caller.admin {
                return Err(admin_only("search"));
            }
            if filter.is_empty() {
                return Err(Failure::new(
                    StatusCode::BAD_REQUEST,
                    "an empty filter matches nothing",
                ));
            }
            searched(state, &filter).await?
        }
        None => indexed(state, &caller.owner()).await?,
    };
    Ok(certificates
        .into_iter()
        .filter_map(|certificate| {
            let serial = certificate.serial.parse().ok()?;
            Some(entry(Some(serial), Some(certificate.authority), None, None))
        })
        .collect())
}

/// `POST /revoke`
pub(super) async fn revoke(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(request): Json<RevokeRequest>,
) -> Response {
    let request_id = audit::new_request_id();
    let result = async {
        if !state.revocations.has_store() {
            return Err(Failure::new(
                StatusCode::NOT_IMPLEMENTED,
                "the revocation API needs a [store] on this service",
            ));
        }
        let reason = request
            .reason
            .as_deref()
            .map(str::trim)
            .filter(|reason| !reason.is_empty())
            .map(str::to_string);
        if reason
            .as_ref()
            .is_some_and(|reason| reason.chars().count() > MAX_REASON_LEN)
        {
            return Err(Failure::new(
                StatusCode::BAD_REQUEST,
                format!("reason is longer than {MAX_REASON_LEN} characters"),
            ));
        }
        let origin = state.origin.resolve(peer, &headers);
        let (entries, caller) = match &request.possession {
            Some(possession) => {
                let others = request.serial.is_some()
                    || request.key_id.is_some()
                    || request.fingerprint.is_some()
                    || request.certificate.is_some()
                    || request.all
                    || request.matching.is_some();
                if others {
                    return Err(Failure::new(
                        StatusCode::BAD_REQUEST,
                        "a proof of possession revokes its key; set no other target",
                    ));
                }
                (vec![possession_entry(&state, possession, reason)?], None)
            }
            None => {
                let caller = Caller::from_headers(&state, &headers).await?;
                let entries = caller_entries(&state, &caller, request, reason).await?;
                (entries, Some(caller))
            }
        };
        let (revoked, already_revoked) =
            state.revocations.revoke(entries).await.map_err(|err| {
                let status = match err {
                    RevokeError::NoStore => StatusCode::NOT_IMPLEMENTED,
                    RevokeError::Invalid(_) => StatusCode::BAD_REQUEST,
                    RevokeError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
                };
                Failure::new(status, err.to_string())
            })?;
        let requester = audit::Requester {
            request_id: &request_id,
            client_ip: origin.client_ip,
            client_port: origin.client_port,
            proxy: origin.proxy,
            correlation_id: origin.correlation_id.as_deref(),
            issuer: caller
                .as_ref()
                .map(|caller| caller.auth.issuer.issuer.as_str())
                .unwrap_or(""),
            subject: caller
                .as_ref()
                .and_then(|caller| caller.auth.claims.get("sub"))
                .and_then(|sub| sub.as_str()),
            oidc_id: caller.as_ref().map(|caller| caller.oidc_id.as_str()),
            profile: None,
            app_name: None,
        };
        for entry in &revoked {
            tracing::info!(
                request_id,
                revoked_by = entry.revoked_by,
                "revoked {entry:?}"
            );
            if let Some(log) = &state.audit {
                let event = audit::Event {
                    server_id: &state.server_id,
                    requester: &requester,
                    outcome: audit::Outcome::Revoked(entry),
                };
                // The revocation is in force; a failed record is an error to
                // look into, not a reason to report failure.
                if let Err(err) = log.record(&event).await {
                    tracing::error!(request_id, "audit log failed for a revocation: {err}");
                }
            }
        }
        Ok(Json(RevokeResponse {
            revoked,
            already_revoked,
        })
        .into_response())
    }
    .await;
    respond(result, &request_id)
}

/// `GET /certificates`: the caller's unexpired certificates, with whether
/// each is revoked. Administrators may search everyone's with the
/// [`CertificateFilter`] fields as query parameters (`?principal=root`).
pub(super) async fn certificates(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Query(filter): Query<CertificateFilter>,
) -> Response {
    let request_id = audit::new_request_id();
    let result = async {
        let caller = Caller::from_headers(&state, &headers).await?;
        let found = if filter.is_empty() {
            indexed(&state, &caller.owner()).await?
        } else if caller.admin {
            searched(&state, &filter).await?
        } else {
            return Err(Failure::new(
                StatusCode::FORBIDDEN,
                "only administrators can search the issuance index",
            ));
        };
        let snapshot = state.revocations.current();
        let certificates = found
            .into_iter()
            .map(|mut certificate| {
                certificate.revoked =
                    certificate.serial.parse().is_ok_and(|serial| {
                        snapshot.serial_revoked(&certificate.authority, serial)
                    }) || snapshot.key_id_revoked(&certificate.authority, &certificate.key_id)
                        || snapshot.fingerprint_revoked(&certificate.fingerprint);
                certificate
            })
            .collect();
        Ok(Json(CertificatesResponse { certificates }).into_response())
    }
    .await;
    respond(result, &request_id)
}
