use std::sync::Arc;

use crate::config::Config;
use ssh_casign_ca::{Authorities as SshCaProviders, Registry};

pub(super) struct AppState {
    pub(super) config: Config,
    pub(super) server_id: String,
    pub(super) issuers: super::oidc::Issuers,
    pub(super) authorities: SshCaProviders,
    /// The signed trust statement.
    pub(super) trust: Arc<crate::trust::Trust>,
    pub(super) audit: Option<Arc<crate::audit::AuditLog>>,
    /// Revoked certificates and keys, and the KRL.
    pub(super) revocations: Arc<crate::revocation::Revocations>,
    /// Client address and correlation ID behind proxies.
    pub(super) origin: crate::proxy::Resolver,
}

impl AppState {
    pub(super) async fn new(
        config: Config,
        registry: &Registry,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let server_id = config.server_id()?;
        tracing::info!("server_id {server_id}");
        let authorities = config.authorities.load(registry).await?;
        let issuers = super::oidc::Issuers::load(&config.oidc_provider, &config.issuers).await?;
        config.profiles.check(&issuers, &authorities)?;
        let trust = crate::trust::Trust::start(config.trust.as_ref(), &authorities).await?;
        super::discovery::document(&config, &authorities, trust.current())?;
        let revocations =
            crate::revocation::Revocations::start(config.revocation.as_ref(), &authorities).await?;
        let audit = match &config.audit {
            Some(audit) => Some(audit.open(&server_id)?),
            None => {
                tracing::warn!("no [audit] configured: issued certificates are only in this log");
                None
            }
        };
        let origin = match &config.audit {
            Some(audit) => audit.origin_resolver()?,
            None => crate::proxy::Resolver::default(),
        };
        Ok(Arc::new(Self {
            config,
            server_id,
            issuers,
            authorities,
            trust,
            audit,
            origin,
            revocations,
        }))
    }
}
