use color_eyre::eyre::{bail, WrapErr};
use ssh_casign_proto::{ErrorResponse, SignKeyRequest, SignedKeyResponse};
use ssh_key::Certificate;
use url::Url;

use crate::error::Result;

pub(crate) async fn sign(
    http: &reqwest::Client,
    sign_endpoint: &Url,
    token: &str,
    sign_key_request: &SignKeyRequest,
) -> Result<Certificate> {
    let response = http
        .post(sign_endpoint.clone())
        .bearer_auth(token)
        .json(sign_key_request)
        .send()
        .await
        .wrap_err_with(|| format!("Sign request to {sign_endpoint} failed"))?;

    let status = response.status();
    if !status.is_success() {
        let challenge = response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let detail = match (response.json::<ErrorResponse>().await, challenge) {
            (Ok(error), _) => error.error,
            (Err(_), Some(challenge)) => challenge,
            (Err(_), None) => status
                .canonical_reason()
                .unwrap_or("unknown error")
                .to_string(),
        };
        bail!("Sign request rejected ({status}): {detail}");
    }

    let response: SignedKeyResponse = response.json().await.wrap_err("Invalid sign response")?;
    let cert = Certificate::from_openssh(&response.certificate)
        .wrap_err("Service returned an invalid certificate")?;
    Ok(cert)
}
