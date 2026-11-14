use std::sync::Arc;

use oidc_jwt_validator::Validator;

use crate::authority::SshCaProviders;
use crate::config::Config;

pub(super) struct AppState {
    pub(super) config: Config,
    pub(super) server_id: String,
    pub(super) oidc_validator: Validator,
    pub(super) authorities: SshCaProviders,
    /// Pre-serialized discovery document (it only depends on the config).
    pub(super) discovery_document: String,
    pub(super) audit: Option<Arc<crate::audit::AuditLog>>,
}

impl AppState {
    pub(super) async fn new(config: Config) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let server_id = config.server_id()?;
        tracing::info!("server_id {server_id}");
        let authorities = config.authorities.load()?;
        for (profile, settings) in config.profiles.all() {
            for name in settings.authorities() {
                if !authorities.contains_key(name) {
                    return Err(format!("profile {profile}: unknown authority '{name}'").into());
                }
            }
        }
        let oidc_validator = config.oidc_provider.get_validator().await?;
        let discovery_document = super::discovery::document(&config, &authorities)?;
        let audit = match &config.audit {
            Some(audit) => Some(audit.open(&server_id)?),
            None => {
                tracing::warn!("no [audit] configured: issued certificates are only in this log");
                None
            }
        };
        Ok(Arc::new(Self {
            config,
            server_id,
            oidc_validator,
            authorities,
            discovery_document,
            audit,
        }))
    }
}
