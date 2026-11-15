use std::sync::Arc;

use crate::config::Config;
use ssh_casign_ca::{Authorities as SshCaProviders, Registry};
use ssh_casign_store::Store;

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
    /// The store, when the issuance index is on.
    pub(super) index: Option<Arc<dyn Store>>,
    /// Weak and blocklisted keys.
    pub(super) key_checks: ssh_casign_ca::keycheck::KeyChecks,
    pub(super) duplicates: crate::key_checks::Duplicates,
}

impl AppState {
    pub(super) async fn new(
        config: Config,
        registry: &Registry,
        stores: &ssh_casign_store::Registry,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let server_id = config.server_id()?;
        tracing::info!("server_id {server_id}");
        let authorities = config.authorities.load(registry).await?;
        let issuers = super::oidc::Issuers::load(&config.oidc_provider, &config.issuers).await?;
        config.profiles.check(&issuers, &authorities)?;
        let default_checks = crate::key_checks::defaults();
        let key_checks_config = config.key_checks.as_ref().unwrap_or(&default_checks);
        let key_checks = key_checks_config.load()?;
        crate::key_checks::check_authorities(&key_checks, &authorities)?;
        let duplicates = key_checks_config.duplicates;
        let trust = crate::trust::Trust::start(config.trust.as_ref(), &authorities).await?;
        super::discovery::document(&config, &authorities, trust.current())?;
        let store: Option<Arc<dyn Store>> = match &config.store {
            Some(table) => {
                let store = stores.load(table.clone()).await?;
                tracing::info!("store: {}", store.describe());
                Some(Arc::from(store))
            }
            None => None,
        };
        let index = match (config.revocation.as_ref().and_then(|r| r.index), &store) {
            (Some(true), None) => {
                return Err("revocation.index needs a [store]".into());
            }
            (Some(false), _) | (None, None) => None,
            (_, Some(store)) => Some(store.clone()),
        };
        if let Some(revocation) = &config.revocation {
            for admin in &revocation.admins {
                if !issuers.contains(admin.issuer()) {
                    return Err(
                        format!("revocation.admins: unknown issuer '{}'", admin.issuer()).into(),
                    );
                }
            }
            if !revocation.admins.is_empty() && store.is_none() {
                tracing::warn!("revocation.admins without a [store]: the revocation API is off");
            }
        }
        if duplicates == crate::key_checks::Duplicates::Deny && index.is_none() {
            return Err(
                "key_checks.duplicates = \"deny\" needs the issuance index (a [store])".into(),
            );
        }
        let revocations = crate::revocation::Revocations::start(
            config.revocation.as_ref(),
            &authorities,
            store.clone(),
        )
        .await?;
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
            index,
            key_checks,
            duplicates,
        }))
    }
}
