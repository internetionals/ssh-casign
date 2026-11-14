use color_eyre::eyre::WrapErr;
use ssh_casign_proto::{ServiceInfo, DISCOVERY_PATH};
use url::Url;

use crate::error::Result;

/// Service discovery document with the sign endpoint resolved to an absolute URL.
pub(crate) struct Service {
    pub(crate) info: ServiceInfo,
    pub(crate) sign_endpoint: Url,
    /// The KRL, if the service publishes one.
    pub(crate) revocation_list: Option<Url>,
}

/// Fetch `<base_url>/.well-known/ssh-casign`.
pub(crate) async fn discover(http: &reqwest::Client, base_url: &Url) -> Result<Service> {
    // `Url::join` replaces the last path segment unless the path ends in '/'.
    let mut base_url = base_url.clone();
    if !base_url.path().ends_with('/') {
        base_url.set_path(&format!("{}/", base_url.path()));
    }
    let discovery_url = base_url.join(DISCOVERY_PATH)?;
    let info: ServiceInfo = http
        .get(discovery_url.clone())
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .wrap_err_with(|| format!("Failed to fetch service discovery document {discovery_url}"))?
        .json()
        .await
        .wrap_err_with(|| format!("Invalid service discovery document {discovery_url}"))?;
    let sign_endpoint = discovery_url
        .join(&info.sign_endpoint)
        .wrap_err("Invalid sign_endpoint in service discovery document")?;
    let revocation_list = info
        .revocation_list
        .as_deref()
        .map(|list| discovery_url.join(list))
        .transpose()
        .wrap_err("Invalid revocation_list in service discovery document")?;
    Ok(Service {
        info,
        sign_endpoint,
        revocation_list,
    })
}
