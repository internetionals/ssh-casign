//! AWS Signature Version 4 for JSON POST requests to `/` (all KMS needs).

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::SystemTime;

use crate::{credentials::Credentials, time::amz_date};

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Headers to send with a signed request: `(name, value)`, including
/// `Authorization`. `host` is set by the HTTP client from the URL.
pub(crate) fn sign(
    credentials: &Credentials,
    region: &str,
    service: &str,
    host: &str,
    target: &str,
    body: &[u8],
    time: SystemTime,
) -> Vec<(&'static str, String)> {
    let amz_date = amz_date(time);
    let date = &amz_date[..8];
    let content_type = "application/x-amz-json-1.1";

    // Canonical headers, sorted by name.
    let mut headers = vec![
        ("content-type", content_type.to_string()),
        ("host", host.to_string()),
        ("x-amz-date", amz_date.clone()),
    ];
    if let Some(token) = &credentials.session_token {
        headers.push(("x-amz-security-token", token.clone()));
    }
    headers.push(("x-amz-target", target.to_string()));
    let signed_headers = headers
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers: String = headers
        .iter()
        .map(|(name, value)| format!("{name}:{}\n", value.trim()))
        .collect();
    let canonical_request = format!(
        "POST\n/\n\n{canonical_headers}\n{signed_headers}\n{}",
        hex(&Sha256::digest(body))
    );

    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );
    let key = hmac(
        format!("AWS4{}", credentials.secret_access_key).as_bytes(),
        date,
    );
    let key = hmac(&key, region);
    let key = hmac(&key, service);
    let key = hmac(&key, "aws4_request");
    let signature = hex(&hmac(&key, &string_to_sign));

    let mut result = vec![
        ("content-type", content_type.to_string()),
        ("x-amz-date", amz_date),
        ("x-amz-target", target.to_string()),
        (
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
                credentials.access_key_id
            ),
        ),
    ];
    if let Some(token) = &credentials.session_token {
        result.push(("x-amz-security-token", token.clone()));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::parse_iso8601;

    /// Vectors computed with botocore 1.44.3 (`SigV4Auth`) for the same
    /// request: POST https://kms.eu-west-1.amazonaws.com/ with body
    /// `{"KeyId":"alias/ssh-ca"}`, at 2026-11-14T12:00:00Z.
    #[test]
    fn matches_botocore() {
        let time = parse_iso8601("2026-11-14T12:00:00Z").unwrap();
        let body = br#"{"KeyId":"alias/ssh-ca"}"#;
        let authorization = |token: Option<&str>| {
            let credentials = Credentials {
                access_key_id: "AKIDEXAMPLE".into(),
                secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
                session_token: token.map(String::from),
                expires: None,
            };
            sign(
                &credentials,
                "eu-west-1",
                "kms",
                "kms.eu-west-1.amazonaws.com",
                "TrentService.GetPublicKey",
                body,
                time,
            )
            .into_iter()
            .find(|(name, _)| *name == "authorization")
            .unwrap()
            .1
        };
        assert_eq!(
            authorization(None),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261114/eu-west-1/kms/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date;x-amz-target, \
             Signature=dffde7a0bcca3b2aaa2ab4ba6f49801a5628b34796b432aec4e59a7c3a680dcf"
        );
        assert_eq!(
            authorization(Some("IQoJb3JpZ2luX2VjEXAMPLETOKEN")),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261114/eu-west-1/kms/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, \
             Signature=ee1cfdfb4004b5a8acc7e371c4b20bb1e2ce76ecec1f91950d7c316e99171237"
        );
    }
}
