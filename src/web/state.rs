use std::sync::Arc;

use axum::extract::FromRef;
use oidc_jwt_validator::Validator;

use crate::ssh_ca::SshCa;

// use crate::ssh_ca::SshCa;

#[derive(Clone)]
pub(super) struct AppState {
    oidc_validator: Arc<Validator>,
    ssh_ca: Arc<crate::ssh_ca::SshCa>,
}

impl AppState {
    pub(super) async fn new(oidc_issuer: &str, ssh_ca: SshCa) -> Self {
        let http_client = reqwest::ClientBuilder::new().build().expect("http client");
        let validation_settings = oidc_jwt_validator::ValidationSettings::new();
        let validator = Validator::new(
            oidc_issuer,
            http_client,
            oidc_jwt_validator::cache::Strategy::Automatic,
            validation_settings,
        )
        .await
        .expect("oidc validator");
        Self {
            oidc_validator: Arc::new(validator),
            ssh_ca: Arc::new(ssh_ca),
        }
    }

    pub(super) fn ssh_ca(&self) -> &SshCa {
        &self.ssh_ca
    }
}

impl FromRef<AppState> for Arc<Validator> {
    fn from_ref(input: &AppState) -> Self {
        input.oidc_validator.clone()
    }
}

impl FromRef<AppState> for Arc<SshCa> {
    fn from_ref(input: &AppState) -> Self {
        input.ssh_ca.clone()
    }
}
