use std::collections::HashMap;

use serde::Deserialize;
use url::Url;

pub use crate::token_store::TokenStore;

/// How the client signs the user in at the OpenID Connect provider.
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SignInMethod {
    /// OAuth 2.0 device authorization grant (RFC 8628): open a URL on any
    /// device and enter a code. Works on headless machines.
    #[default]
    Device,
    /// Authorization code flow with PKCE and a loopback redirect (RFC 8252):
    /// signs in through a browser on this machine.
    #[value(alias = "browser")]
    #[serde(alias = "browser")]
    AuthorizationCode,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Base URL of the ssh-casign service. Everything else is discovered from
    /// `<url>/.well-known/ssh-casign`.
    pub url: Url,
    /// Sign-in method for this profile; overrides the top-level `sign_in`.
    pub sign_in: Option<SignInMethod>,
    /// Overrides the client ID published by the service.
    pub client_id: Option<String>,
    /// Overrides the scopes published by the service.
    pub scopes: Option<Vec<String>>,
    /// Application name for this profile; overrides the top-level `app_name`.
    pub app_name: Option<String>,
    /// Refresh token storage for this profile; overrides the top-level one.
    pub token_store: Option<TokenStore>,
}

fn default_profile() -> String {
    "default".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub profiles: HashMap<String, Profile>,

    #[serde(default = "default_profile")]
    pub default_profile: String,

    /// Default sign-in method for all profiles.
    #[serde(default)]
    pub sign_in: SignInMethod,

    /// Default application name (part of the certificate's key ID).
    pub app_name: Option<String>,

    /// Where refresh tokens are stored (default: the OS credential store).
    #[serde(default)]
    pub token_store: TokenStore,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profiles: HashMap::new(),
            default_profile: default_profile(),
            sign_in: SignInMethod::default(),
            app_name: None,
            token_store: TokenStore::default(),
        }
    }
}
