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
    /// The authorities' signatures over the KRL.
    pub(crate) revocation_list_signatures: Option<Url>,
    /// The revocation API, when the service has a store.
    pub(crate) revoke_endpoint: Option<Url>,
    pub(crate) certificates_endpoint: Option<Url>,
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
    let resolve = |url: Option<&String>, what: &str| {
        url.map(|url| discovery_url.join(url))
            .transpose()
            .wrap_err_with(|| format!("Invalid {what} in service discovery document"))
    };
    let revocation_list_signatures = resolve(
        info.revocation_list_signatures.as_ref(),
        "revocation_list_signatures",
    )?;
    let revoke_endpoint = resolve(info.revoke_endpoint.as_ref(), "revoke_endpoint")?;
    let certificates_endpoint =
        resolve(info.certificates_endpoint.as_ref(), "certificates_endpoint")?;
    Ok(Service {
        info,
        sign_endpoint,
        revocation_list,
        revocation_list_signatures,
        revoke_endpoint,
        certificates_endpoint,
    })
}
