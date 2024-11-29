use std::sync::Arc;

use oidc_jwt_validator::Validator;

use crate::config::Config;
use crate::authority::SshCaProviders;

pub(super) struct AppState {
    pub(super) config: Config,
    pub(super) oidc_validator: Validator,
    pub(super) authorities: SshCaProviders,
}

impl AppState {
    pub(super) async fn new(config: Config) -> Arc<Self> {
        let oidc_validator = config.oidc_provider.get_validator().await;
        let authorities = config.authorities.load().expect("ssh-ca providers");
        Arc::new(Self {
            config,
            oidc_validator,
            authorities,
        })
    }
}
