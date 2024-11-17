use std::sync::Arc;

use oidc_jwt_validator::Validator;

use crate::config::Config;
use crate::ssh_ca::SshCaProviders;

pub(super) struct AppState {
    pub(super) config: Config,
    pub(super) oidc_validator: Validator,
    pub(super) ssh_ca_providers: SshCaProviders,
}

impl AppState {
    pub(super) async fn new(config: Config) -> Arc<Self> {
        let oidc_validator = config.oidc_provider.get_validator().await;
        let ssh_ca_providers = config.ssh_ca.load().expect("ssh-ca providers");
        Arc::new(Self {
            config,
            oidc_validator,
            ssh_ca_providers,
        })
    }
}
