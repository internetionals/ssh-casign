use serde::Deserialize;

fn default_listen() -> String {
    "0.0.0.0:3000".to_string()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// Identifies this service instance in key IDs (`{{server_id}}`), so
    /// certificates can be traced back when several instances run side by
    /// side. Defaults to the hostname.
    server_id: Option<String>,
    /// Address to listen on.
    #[serde(default = "default_listen")]
    pub(crate) listen: String,
    pub(crate) oidc_provider: crate::web::oidc::Config,
    pub(crate) profiles: crate::certificate::profiles::Profiles,
    pub(crate) authorities: crate::authority::Config,
}

impl Config {
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
