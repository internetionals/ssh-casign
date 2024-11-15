use std::sync::Arc;

use oidc_jwt_validator::Validator;

use crate::config::Config;
use crate::ssh_ca::SshCa;

pub(super) struct AppState {
    pub(super) config: Config,
    pub(super) oidc_validator: Validator,
    pub(super) ssh_ca: Arc<SshCa>,
}

impl AppState {
    pub(super) async fn new(config: Config, ssh_ca: Arc<SshCa>) -> Arc<Self> {
        let oidc_validator = config.oidc_provider.get_validator().await;
        Arc::new(Self {
            config,
            oidc_validator,
            ssh_ca,
        })
    }
}
