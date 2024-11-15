use serde::Deserialize;
use std::collections::HashMap;

use crate::ssh_ca::{CertificateOptions, SignOptions};

#[derive(Deserialize)]
pub(crate) struct CertificateSettings {
    validity: u64,
    comment: Option<String>,
    critical_options: Option<HashMap<String, String>>,
    extensions: Option<HashMap<String, String>>,
}

impl CertificateSettings {
    pub(crate) fn sign_options<'a>(
        &'a self,
        claims: &'a crate::web::sign_key::SignKeyClaims,
    ) -> Result<SignOptions, Box<dyn std::error::Error>> {
        if claims.valid_principals.is_empty() {
            Err("No valid_principals in claims")?;
        }
        Ok(SignOptions {
            validity: claims.validity.unwrap_or(self.validity),
            certificate: CertificateOptions {
                key_id: claims.key_id.to_owned(),
                comment: claims
                    .comment
                    .to_owned()
                    .or_else(|| self.comment.to_owned()),
                valid_principals: claims.valid_principals.clone(),
                extensions: claims
                    .extensions
                    .to_owned()
                    .or_else(|| self.extensions.to_owned()),
                critical_options: claims
                    .critical_options
                    .to_owned()
                    .or_else(|| self.critical_options.to_owned()),
            },
        })
    }
}

#[derive(Deserialize)]
pub(crate) struct ProfileSelector {
    claim: String,
    value: String,
    settings: CertificateSettings,
}

#[derive(Deserialize)]
pub(crate) struct Profiles {
    map: Vec<ProfileSelector>,
    default: Option<CertificateSettings>,
}

impl Profiles {
    pub(crate) fn lookup(
        &self,
        claims: &crate::web::sign_key::SignKeyClaims,
    ) -> Option<&CertificateSettings> {
        for selector in &self.map {
            if let Some(value) = claims.other.get(&selector.claim) {
                if let Some(value) = value.as_str() {
                    if value == selector.value {
                        return Some(&selector.settings);
                    }
                } else if let Some(values) = value.as_array() {
                    if values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .any(|v| v == selector.value)
                    {
                        return Some(&selector.settings);
                    }
                }
            }
        }
        self.default.as_ref()
    }
}
