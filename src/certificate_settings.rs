use serde::Deserialize;
use std::{collections::HashMap, sync::Arc};

use crate::ssh_ca::CertificateOptions;

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("No valid_principals in claim")]
    NoPrincipals,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CertificateClaims {
    pub(crate) validity: Option<u64>,
    pub(crate) key_id: Option<Arc<str>>,
    pub(crate) valid_principals: Vec<Arc<str>>,
    pub(crate) comment: Option<Arc<str>>,
    pub(crate) critical_options: Option<HashMap<Arc<str>, Arc<str>>>,
    pub(crate) extensions: Option<HashMap<Arc<str>, Arc<str>>>,

    #[serde(flatten)]
    pub(crate) other: HashMap<Arc<str>, serde_json::Value>,
}

#[derive(Deserialize)]
pub(crate) struct CertificateSettings {
    ssh_ca: Arc<str>,
    validity: u64,
    comment: Option<Arc<str>>,
    critical_options: Option<HashMap<Arc<str>, Arc<str>>>,
    extensions: Option<HashMap<Arc<str>, Arc<str>>>,
}

impl CertificateSettings {
    pub(crate) fn ssh_ca(&self) -> &str {
        &self.ssh_ca
    }

    pub(crate) fn apply(
        &self,
        options: &mut CertificateOptions,
        claims: &CertificateClaims,
    ) -> Result<(), Error> {
        if claims.valid_principals.is_empty() {
            return Err(Error::NoPrincipals);
        }
        for principal in &claims.valid_principals {
            options.add_principal(principal.clone());
        }
        options.set_validity(claims.validity.unwrap_or(self.validity));
        if let Some(key_id) = claims.key_id.as_deref() {
            options.set_key_id(key_id);
        }
        if let Some(comment) = claims.comment.as_deref().or(self.comment.as_deref()) {
            options.set_comment(comment);
        }
        if let Some(extensions) = claims.extensions.as_ref().or(self.extensions.as_ref()) {
            for (extension, value) in extensions {
                options.set_extension(extension.clone(), value.clone());
            }
        }
        if let Some(critical_options) = claims
            .critical_options
            .as_ref()
            .or(self.critical_options.as_ref())
        {
            for (critical_option, value) in critical_options {
                options.set_critical_option(critical_option.clone(), value.clone());
            }
        }
        Ok(())
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
    pub(crate) fn lookup(&self, claims: &CertificateClaims) -> Option<&CertificateSettings> {
        for selector in &self.map {
            if let Some(value) = claims.other.get(selector.claim.as_str()) {
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
