use std::collections::HashMap;

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use ssh_key::{Certificate, PrivateKey, PublicKey};

#[derive(Debug, Deserialize)]
pub struct SignKeyClaims {
    validity: u64,
    key_id: String,
    valid_principals: Vec<String>,
    comment: Option<String>,
    critical_options: Option<HashMap<String, String>>,
    extensions: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
pub(super) struct SignKeyRequest {
    public_key: String,
}

#[derive(Serialize)]
pub(super) struct SignedKeyResponse {
    certificate: String,
}

fn sign_cert(client_public_key: PublicKey, claims: &SignKeyClaims, ca_private_key: &PrivateKey) -> Result<Certificate, Box<dyn std::error::Error>> {
    let valid_after = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let valid_before = valid_after + claims.validity;
    let mut rng = rand::thread_rng();
    let mut cb = ssh_key::certificate::Builder::new_with_random_nonce(&mut rng, client_public_key, valid_after, valid_before)?;
    cb.key_id(&claims.key_id)?;
    for principal in &claims.valid_principals {
        cb.valid_principal(principal)?;
    }
    if let Some(comment) = &claims.comment {
        cb.comment(comment)?;
    }
    if let Some(critical_options) = &claims.critical_options {
        for (name, data) in critical_options {
            cb.critical_option(name, data)?;
        }
    }
    if let Some(extensions) = &claims.extensions {
        for (name, data) in extensions {
            cb.extension(name, data)?;
        }
    }
    Ok(cb.sign(ca_private_key)?)
}

pub(super) async fn sign_key(
    claims: super::oidc::Claims<SignKeyClaims>,
    State(state): State<super::state::AppState>,
    Json(payload): Json<SignKeyRequest>,
) -> (StatusCode, Json<SignedKeyResponse>) {
    let client_public_key = ssh_key::PublicKey::from_openssh(&payload.public_key).expect("pubkey");
    let cert = sign_cert(client_public_key, &claims, &state.ssh_ca().private_key()).expect("cert");

    // state.ssh_ca.private_key
    (
        StatusCode::OK,
        SignedKeyResponse {
            certificate: cert.to_openssh().expect("ssh cert"),
        }
        .into(),
    )
}
