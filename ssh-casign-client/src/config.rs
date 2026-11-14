use std::{collections::HashMap, path::PathBuf};

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
    /// OAuth 2.0 client credentials grant, for a confidential machine client
    /// (`client_id`, `client_secret_file`).
    ClientCredentials,
    /// A token read from `token_file` (e.g. a Kubernetes projected service
    /// account token).
    TokenFile,
    /// The GCE/GKE metadata server's identity token for `audience`.
    GcpMetadata,
    /// The Azure managed identity's token for `audience`.
    AzureManagedIdentity,
    /// The GitHub Actions OIDC token for `audience`.
    GithubActions,
}

impl SignInMethod {
    /// Signs in without a person, and without refresh tokens to cache.
    pub fn is_machine(self) -> bool {
        !matches!(self, Self::Device | Self::AuthorizationCode)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Base URL of the ssh-casign service. Everything else is discovered from
    /// `<url>/.well-known/ssh-casign`.
    pub url: Url,
    /// Sign-in method for this profile; overrides the top-level `sign_in`.
    pub sign_in: Option<SignInMethod>,
    /// Overrides the client ID published by the service. For
    /// `client-credentials` the confidential client; for
    /// `azure-managed-identity` a user-assigned identity.
    pub client_id: Option<String>,
    /// Issuer to sign in at, instead of the one the service publishes (for
    /// `client-credentials` at another IdP).
    pub issuer: Option<String>,
    /// File with the client secret for `client-credentials`
    /// (`SSH_CASIGN_CLIENT_SECRET` overrides it).
    pub client_secret_file: Option<PathBuf>,
    /// Audience to request machine tokens for (`gcp-metadata`,
    /// `azure-managed-identity`, `github-actions`, optionally
    /// `client-credentials`).
    pub audience: Option<String>,
    /// Token file for `token-file`.
    pub token_file: Option<PathBuf>,
    /// Overrides the scopes published by the service.
    pub scopes: Option<Vec<String>>,
    /// Application name for this profile; overrides the top-level `app_name`.
    pub app_name: Option<String>,
    /// Refresh token storage for this profile; overrides the top-level one.
    pub token_store: Option<TokenStore>,
    /// CA signature algorithms the servers of this profile accept, e.g.
    /// `["ssh-rsa"]` for old embedded systems.
    pub ca_signature_algorithms: Option<Vec<String>>,
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
