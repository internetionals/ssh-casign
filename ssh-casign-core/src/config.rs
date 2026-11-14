use serde::Deserialize;

const DEFAULT_LISTEN: &str = "0.0.0.0:3000";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Identifies this service instance in key IDs (`{{server_id}}`), so
    /// certificates can be traced back when several instances run side by
    /// side. Defaults to the hostname.
    server_id: Option<String>,
    /// Address to listen on (see [`Config::listen`] for platform overrides).
    listen: Option<String>,
    pub(crate) oidc_provider: crate::web::oidc::Config,
    /// Further trusted issuers, for machine identities (`[issuers.<name>]`).
    #[serde(default)]
    pub(crate) issuers: std::collections::BTreeMap<String, crate::web::oidc::IssuerConfig>,
    pub(crate) profiles: crate::certificate::profiles::Profiles,
    pub(crate) authorities: ssh_casign_ca::Config,
    /// Revoked certificates and keys; without it, the KRL is empty.
    pub(crate) revocation: Option<crate::revocation::Config>,
    /// Audit log; without it, issued certificates are only in the service log.
    pub(crate) audit: Option<crate::audit::Config>,
}

impl Config {
    /// Address to listen on: `SSH_CASIGN_LISTEN`; on Azure Functions
    /// `FUNCTIONS_CUSTOMHANDLER_PORT` (loopback only, the Functions host
    /// forwards requests); on platforms that set `PORT` (Cloud Run, ...) that
    /// port; else `listen` from the config, else `0.0.0.0:3000`.
    pub(crate) fn listen(&self) -> String {
        let env = |name| {
            std::env::var(name)
                .ok()
                .filter(|value: &String| !value.is_empty())
        };
        if let Some(listen) = env("SSH_CASIGN_LISTEN") {
            return listen;
        }
        if let Some(port) = env("FUNCTIONS_CUSTOMHANDLER_PORT") {
            return format!("127.0.0.1:{port}");
        }
        if let Some(port) = env("PORT") {
            return format!("0.0.0.0:{port}");
        }
        self.listen
            .clone()
            .unwrap_or_else(|| DEFAULT_LISTEN.to_string())
    }

    /// The configured `server_id`, else the hostname.
    pub(crate) fn server_id(&self) -> Result<String, Box<dyn std::error::Error>> {
        match &self.server_id {
            Some(server_id) if server_id.is_empty() => Err("server_id must not be empty".into()),
            Some(server_id) => Ok(server_id.clone()),
            None => hostname().ok_or_else(|| {
                "unable to determine the hostname; set server_id in the config".into()
            }),
        }
    }
}

fn hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: gethostname writes at most buf.len() bytes into buf.
    let result = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if result != 0 {
        return None;
    }
    let len = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    let hostname = String::from_utf8_lossy(&buf[..len]).into_owned();
    (!hostname.is_empty()).then_some(hostname)
}
