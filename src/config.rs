use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct Config {
    pub(crate) oidc_provider: crate::web::oidc::Config,
    pub(crate) profiles: crate::certificate_settings::Profiles,
    pub(crate) ssh_ca: crate::ssh_ca::Config,
}
