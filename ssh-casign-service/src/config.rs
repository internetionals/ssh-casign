use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct Config {
    pub(crate) oidc_provider: crate::web::oidc::Config,
    pub(crate) profiles: crate::certificate::profiles::Profiles,
    pub(crate) authorities: crate::authority::Config,
}
