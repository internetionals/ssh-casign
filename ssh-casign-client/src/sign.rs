use color_eyre::Result;
use serde::{Deserialize, Serialize};
use ssh_key::{Certificate, PublicKey};

#[derive(clap::ValueEnum, Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CertType {
    Host,
    User,
}

#[derive(Serialize)]
struct SignKeyRequest {
    public_key: String,
    cert_type: CertType,
}

#[derive(Deserialize)]
struct SignedKeyResponse {
    certificate: String,
}

pub(crate) async fn sign(
    url: String,
    _profile_name: String,
    cert_type: CertType,
    public_key: PublicKey,
) -> Result<Certificate> {
    // Prepare sign request
    let url = url.clone();
    let sign_key_request = SignKeyRequest {
        public_key: public_key.to_openssh()?,
        cert_type,
    };

    // Peform sign request
    let client = reqwest::Client::new();
    let response: SignedKeyResponse = client
        .post(url)
        .json(&sign_key_request)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    // Process sign response
    let cert = Certificate::from_openssh(&response.certificate)?;
    Ok(cert)
}
