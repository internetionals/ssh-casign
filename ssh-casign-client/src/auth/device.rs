//! OAuth 2.0 device authorization grant (RFC 8628).
//!
//! The user opens a URL on any device (a phone, a laptop) and enters a short
//! code; meanwhile this client polls the token endpoint until the sign-in is
//! approved, denied or expired. Works on machines without a browser.

use std::time::{Duration, Instant};

use color_eyre::eyre::{bail, WrapErr};
use serde::Deserialize;
use url::Url;

use super::{OAuthError, TokenResponse};
use crate::error::Result;

const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// RFC 8628 section 3.2: the default polling interval is 5 seconds.
fn default_interval() -> u64 {
    5
}

/// RFC 8628 section 3.5: increase the interval by 5 seconds on `slow_down`.
const SLOW_DOWN_INCREMENT: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
struct DeviceAuthorization {
    device_code: String,
    user_code: String,
    /// Some IdPs (Google) use the pre-RFC name `verification_url`.
    #[serde(alias = "verification_url")]
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[serde(default = "default_interval")]
    interval: u64,
}

pub(super) async fn sign_in(
    http: &reqwest::Client,
    device_authorization_endpoint: &Url,
    token_endpoint: &Url,
    client_id: &str,
    scopes: &[String],
) -> Result<TokenResponse> {
    let scope = scopes.join(" ");
    let response = http
        .post(device_authorization_endpoint.clone())
        .form(&[("client_id", client_id), ("scope", scope.as_str())])
        .send()
        .await
        .wrap_err_with(|| {
            format!("Device authorization request to {device_authorization_endpoint} failed")
        })?;
    if !response.status().is_success() {
        let status = response.status();
        let error = OAuthError::from_response(response).await;
        bail!("Device authorization rejected ({status}): {error}");
    }
    let authorization: DeviceAuthorization = response
        .json()
        .await
        .wrap_err("Invalid device authorization response")?;

    prompt(&authorization);

    let deadline = Instant::now() + Duration::from_secs(authorization.expires_in);
    let mut interval = Duration::from_secs(authorization.interval.max(1));
    loop {
        tokio::time::sleep(interval).await;
        if Instant::now() >= deadline {
            bail!("The sign-in code expired; run the command again");
        }
        let response = http
            .post(token_endpoint.clone())
            .form(&[
                ("grant_type", DEVICE_CODE_GRANT),
                ("device_code", authorization.device_code.as_str()),
                ("client_id", client_id),
            ])
            .send()
            .await
            .wrap_err_with(|| format!("Token request to {token_endpoint} failed"))?;
        if response.status().is_success() {
            return response.json().await.wrap_err("Invalid token response");
        }
        let error = OAuthError::from_response(response).await;
        match error.error.as_str() {
            "authorization_pending" => tracing::debug!("sign-in pending"),
            "slow_down" => {
                interval += SLOW_DOWN_INCREMENT;
                tracing::debug!("slowing down polling to {interval:?}");
            }
            "access_denied" => bail!("Sign-in was denied"),
            "expired_token" => bail!("The sign-in code expired; run the command again"),
            _ => bail!("Sign-in failed: {error}"),
        }
    }
}

/// Tell the user where to go. On stderr, so stdout stays usable for the
/// certificate.
fn prompt(authorization: &DeviceAuthorization) {
    eprintln!();
    eprintln!("To sign in, open {}", authorization.verification_uri);
    eprintln!("and enter the code: {}", authorization.user_code);
    if let Some(complete) = &authorization.verification_uri_complete {
        eprintln!();
        eprintln!("Or open this link, which includes the code:");
        eprintln!("  {complete}");
    }
    eprintln!();
    eprintln!("Waiting for sign-in...");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_authorization_parsing() {
        let rfc: DeviceAuthorization = serde_json::from_value(serde_json::json!({
            "device_code": "d", "user_code": "ABCD-EFGH",
            "verification_uri": "https://idp.example.com/device",
            "verification_uri_complete": "https://idp.example.com/device?user_code=ABCD-EFGH",
            "expires_in": 300, "interval": 10
        }))
        .unwrap();
        assert_eq!(rfc.interval, 10);
        assert!(rfc.verification_uri_complete.is_some());

        let google_style: DeviceAuthorization = serde_json::from_value(serde_json::json!({
            "device_code": "d", "user_code": "ABCD-EFGH",
            "verification_url": "https://www.google.com/device",
            "expires_in": 1800
        }))
        .unwrap();
        assert_eq!(
            google_style.verification_uri,
            "https://www.google.com/device"
        );
        assert_eq!(google_style.interval, 5);
    }
}
