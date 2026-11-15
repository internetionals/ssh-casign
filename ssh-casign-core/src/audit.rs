//! Durable audit log in Common Event Format (CEF), written to one or more
//! sinks before the response goes out.
//!
//! Sinks:
//!
//! - `file`: appended and fsynced per record. The file is opened for every
//!   record, so rotation by renaming needs no signal.
//! - `stdout`: one line per record, flushed immediately. On AWS Lambda, Azure
//!   Functions and Google Cloud Run functions, stdout is collected durably by
//!   the platform's logging (CloudWatch Logs, Azure Monitor, Cloud Logging).
//! - `syslog`: RFC 5424 over TCP (newline framing) or UDP, for SIEMs.
//!
//! An issued certificate is only returned once every `required` sink (the
//! default) has accepted its record; otherwise the request fails.

use std::{
    io::Write,
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;

const CEF_VERSION: u8 = 0;
const NETWORK_TIMEOUT: Duration = Duration::from_secs(5);

fn default_true() -> bool {
    true
}

fn default_vendor() -> String {
    "ssh-casign".to_string()
}

fn default_product() -> String {
    "ssh-casign-service".to_string()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// Also record denied requests of authenticated clients.
    #[serde(default = "default_true")]
    record_denials: bool,
    /// Take the client address from this header, e.g. `x-forwarded-for`,
    /// `forwarded` (RFC 7239), `cf-connecting-ip` or `x-real-ip`. Without
    /// it, the TCP peer address is used. See [`crate::proxy`].
    client_address_header: Option<String>,
    /// Entries at the end of `client_address_header` that proxies with
    /// unknown addresses add after the client address (e.g. 1 behind
    /// Google's external load balancer). Default 0.
    #[serde(default)]
    client_address_skip: usize,
    /// Address ranges of trusted proxies. When set, forwarding headers are
    /// only used from these peers, and these addresses are skipped in
    /// `client_address_header`. When unset, every peer is believed.
    trusted_proxies: Option<Vec<String>>,
    /// A trusted proxy's request ID to record, e.g. `cf-ray`.
    correlation_id_header: Option<String>,
    /// CEF header "Device Vendor".
    #[serde(default = "default_vendor")]
    device_vendor: String,
    /// CEF header "Device Product".
    #[serde(default = "default_product")]
    device_product: String,
    /// Where records go (`[[audit.sink]]`); at least one.
    #[serde(rename = "sink")]
    sinks: Vec<SinkConfig>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum SinkConfig {
    File(FileConfig),
    Stdout(StdoutConfig),
    Syslog(SyslogConfig),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    /// File to append to; its directory must exist.
    path: PathBuf,
    #[serde(default = "default_true")]
    required: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StdoutConfig {
    #[serde(default = "default_true")]
    required: bool,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
enum Transport {
    /// The local syslog daemon's Unix socket.
    Unix,
    Tcp,
    Udp,
}

fn default_transport() -> Transport {
    Transport::Unix
}

/// The local syslog socket: `/dev/log` on Linux, `/var/run/syslog` on macOS.
fn default_unix_socket() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/var/run/syslog")
    } else {
        PathBuf::from("/dev/log")
    }
}

fn default_facility() -> String {
    "authpriv".to_string()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyslogConfig {
    /// `unix` (default: the local syslog daemon), `tcp` or `udp`. UDP gives
    /// no delivery guarantee.
    #[serde(default = "default_transport")]
    transport: Transport,
    /// `host:port` of the receiver, for `tcp` and `udp`.
    address: Option<String>,
    /// Socket path, for `unix` (default `/dev/log`, macOS `/var/run/syslog`).
    path: Option<PathBuf>,
    /// Syslog facility name (`authpriv`, `auth`, `daemon`, `local0`..`local7`).
    #[serde(default = "default_facility")]
    facility: String,
    #[serde(default = "default_true")]
    required: bool,
}

fn facility_code(name: &str) -> Option<u8> {
    Some(match name {
        "kern" => 0,
        "user" => 1,
        "daemon" => 3,
        "auth" => 4,
        "syslog" => 5,
        "authpriv" => 10,
        _ => {
            let n: u8 = name.strip_prefix("local")?.parse().ok()?;
            if n > 7 {
                return None;
            }
            16 + n
        }
    })
}

impl Config {
    /// How request origins are determined.
    pub(crate) fn origin_resolver(&self) -> Result<crate::proxy::Resolver, String> {
        crate::proxy::Resolver::new(crate::proxy::Settings {
            header: self.client_address_header.as_deref(),
            skip: self.client_address_skip,
            trusted_proxies: self.trusted_proxies.as_deref(),
            correlation_id_header: self.correlation_id_header.as_deref(),
        })
        .map_err(|err| format!("audit: {err}"))
    }

    /// Set up all sinks, failing if a required one can't be used.
    pub(crate) fn open(
        &self,
        server_id: &str,
    ) -> Result<Arc<AuditLog>, Box<dyn std::error::Error>> {
        if self.sinks.is_empty() {
            return Err("audit: configure at least one [[audit.sink]]".into());
        }
        let mut sinks = Vec::new();
        for config in &self.sinks {
            let (sink, required) = match config {
                SinkConfig::File(config) => {
                    let sink = Sink::File {
                        path: config.path.clone(),
                    };
                    (sink, config.required)
                }
                SinkConfig::Stdout(config) => (Sink::Stdout, config.required),
                SinkConfig::Syslog(config) => {
                    let facility = facility_code(&config.facility).ok_or_else(|| {
                        format!("audit: unknown syslog facility '{}'", config.facility)
                    })?;
                    let target = config.target()?;
                    let sink = Sink::Syslog(SyslogSink {
                        target,
                        facility,
                        connection: Mutex::new(None),
                    });
                    (sink, config.required)
                }
            };
            let entry = SinkEntry { sink, required };
            if let Err(err) = entry.sink.check() {
                let message = format!("audit sink {}: {err}", entry.sink.describe());
                if entry.required {
                    return Err(message.into());
                }
                tracing::warn!("{message}");
            }
            sinks.push(entry);
        }
        Ok(Arc::new(AuditLog {
            header: CefHeader {
                vendor: self.device_vendor.clone(),
                product: self.device_product.clone(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            hostname: server_id.to_string(),
            record_denials: self.record_denials,
            sinks,
            lock: Mutex::new(()),
        }))
    }
}

impl SyslogConfig {
    fn target(&self) -> Result<SyslogTarget, String> {
        match (self.transport, &self.address, &self.path) {
            (Transport::Unix, None, path) => {
                if !cfg!(unix) {
                    return Err("audit: syslog over a Unix socket needs a Unix-like system".into());
                }
                Ok(SyslogTarget::Unix(
                    path.clone().unwrap_or_else(default_unix_socket),
                ))
            }
            (Transport::Unix, Some(_), _) => {
                Err("audit: syslog `address` is for tcp/udp; use `path` for unix".into())
            }
            (_, None, _) => Err("audit: syslog over tcp/udp needs an `address`".into()),
            (_, Some(_), Some(_)) => Err("audit: syslog `path` is only for unix".into()),
            (transport, Some(address), None) => {
                let address = address
                    .to_socket_addrs()
                    .map_err(|err| format!("audit: syslog address {address}: {err}"))?
                    .next()
                    .ok_or_else(|| format!("audit: syslog address {address} doesn't resolve"))?;
                Ok(match transport {
                    Transport::Tcp => SyslogTarget::Tcp(address),
                    _ => SyslogTarget::Udp(address),
                })
            }
        }
    }
}

#[derive(Debug)]
enum SyslogTarget {
    Unix(PathBuf),
    Tcp(SocketAddr),
    Udp(SocketAddr),
}

struct SyslogSink {
    target: SyslogTarget,
    facility: u8,
    /// Kept open between records (TCP); reopened after an error.
    connection: Mutex<Option<TcpStream>>,
}

enum Sink {
    File { path: PathBuf },
    Stdout,
    Syslog(SyslogSink),
}

struct SinkEntry {
    sink: Sink,
    required: bool,
}

impl Sink {
    fn describe(&self) -> String {
        match self {
            Sink::File { path } => format!("file {}", path.display()),
            Sink::Stdout => "stdout".to_string(),
            Sink::Syslog(syslog) => match &syslog.target {
                SyslogTarget::Unix(path) => format!("syslog unix {}", path.display()),
                SyslogTarget::Tcp(address) => format!("syslog tcp {address}"),
                SyslogTarget::Udp(address) => format!("syslog udp {address}"),
            },
        }
    }

    /// Startup check: can records be written at all?
    fn check(&self) -> std::io::Result<()> {
        match self {
            Sink::File { path } => open_append(path).map(drop),
            Sink::Stdout => Ok(()),
            Sink::Syslog(syslog) => match &syslog.target {
                SyslogTarget::Tcp(address) => {
                    let stream = TcpStream::connect_timeout(address, NETWORK_TIMEOUT)?;
                    *syslog.connection.lock().unwrap_or_else(|e| e.into_inner()) = Some(stream);
                    Ok(())
                }
                SyslogTarget::Udp(_) => Ok(()),
                SyslogTarget::Unix(path) => std::fs::metadata(path).map(drop),
            },
        }
    }

    fn write(&self, cef: &str, severity: SyslogSeverity, hostname: &str) -> std::io::Result<()> {
        match self {
            Sink::File { path } => {
                let mut file = open_append(path)?;
                file.write_all(format!("{cef}\n").as_bytes())?;
                file.sync_data()
            }
            Sink::Stdout => {
                let mut stdout = std::io::stdout().lock();
                stdout.write_all(format!("{cef}\n").as_bytes())?;
                stdout.flush()
            }
            Sink::Syslog(syslog) => {
                let pri = syslog.facility * 8 + severity as u8;
                match &syslog.target {
                    SyslogTarget::Unix(path) => {
                        // Local daemons expect the traditional format and add
                        // timestamp and hostname themselves.
                        let message = format!("<{pri}>ssh-casign[{}]: {cef}", std::process::id());
                        send_unix(path, &message)
                    }
                    SyslogTarget::Udp(address) => {
                        let message = rfc5424(pri, hostname, cef);
                        let socket = UdpSocket::bind(if address.is_ipv4() {
                            "0.0.0.0:0"
                        } else {
                            "[::]:0"
                        })?;
                        socket.send_to(message.as_bytes(), address).map(drop)
                    }
                    SyslogTarget::Tcp(address) => {
                        let message = format!("{}\n", rfc5424(pri, hostname, cef));
                        let mut connection =
                            syslog.connection.lock().unwrap_or_else(|e| e.into_inner());
                        // One retry on a fresh connection: the receiver may have
                        // closed an idle one.
                        for attempt in 0..2 {
                            if connection.is_none() {
                                let stream = TcpStream::connect_timeout(address, NETWORK_TIMEOUT)?;
                                stream.set_write_timeout(Some(NETWORK_TIMEOUT))?;
                                *connection = Some(stream);
                            }
                            let stream = connection.as_mut().expect("connected above");
                            match stream
                                .write_all(message.as_bytes())
                                .and_then(|()| stream.flush())
                            {
                                Ok(()) => return Ok(()),
                                Err(err) => {
                                    *connection = None;
                                    if attempt == 1 {
                                        return Err(err);
                                    }
                                }
                            }
                        }
                        unreachable!("loop returns")
                    }
                }
            }
        }
    }
}

/// RFC 5424 message (for the network transports).
fn rfc5424(pri: u8, hostname: &str, cef: &str) -> String {
    format!(
        "<{pri}>1 {} {} ssh-casign - audit - {cef}",
        now_rfc3339(),
        syslog_field(hostname)
    )
}

/// Send to the local syslog socket: a datagram socket on most systems, a
/// stream socket (newline framed) on some.
#[cfg(unix)]
fn send_unix(path: &std::path::Path, message: &str) -> std::io::Result<()> {
    use std::os::unix::net::{UnixDatagram, UnixStream};
    match UnixDatagram::unbound()?.send_to(message.as_bytes(), path) {
        Err(err) if err.raw_os_error() == Some(libc::EPROTOTYPE) => {
            let mut stream = UnixStream::connect(path)?;
            stream.write_all(format!("{message}\n").as_bytes())?;
            stream.flush()
        }
        result => result.map(drop),
    }
}

#[cfg(not(unix))]
fn send_unix(_path: &std::path::Path, _message: &str) -> std::io::Result<()> {
    Err(std::io::Error::other("Unix sockets are not available"))
}
fn open_append(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o640);
    options.open(path)
}

/// RFC 5424 header fields are printable ASCII without spaces.
fn syslog_field(value: &str) -> String {
    let field: String = value
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(255)
        .collect();
    if field.is_empty() {
        "-".to_string()
    } else {
        field
    }
}

#[derive(Clone, Copy)]
enum SyslogSeverity {
    Warning = 4,
    Notice = 5,
}

struct CefHeader {
    vendor: String,
    product: String,
    version: String,
}

pub(crate) struct AuditLog {
    header: CefHeader,
    /// Hostname in syslog messages: the server ID.
    hostname: String,
    record_denials: bool,
    sinks: Vec<SinkEntry>,
    /// Serializes records from this process.
    lock: Mutex<()>,
}

impl AuditLog {
    pub(crate) fn records_denials(&self) -> bool {
        self.record_denials
    }

    /// Write the event to every sink. Fails if a required sink fails.
    pub(crate) async fn record(self: &Arc<Self>, event: &Event<'_>) -> std::io::Result<()> {
        let cef = event.to_cef(&self.header);
        let severity = match event.outcome {
            Outcome::Issued(_) => SyslogSeverity::Notice,
            Outcome::Denied { .. } => SyslogSeverity::Warning,
            Outcome::Revoked(_) => SyslogSeverity::Notice,
        };
        let log = self.clone();
        tokio::task::spawn_blocking(move || log.write_all(&cef, severity))
            .await
            .map_err(std::io::Error::other)?
    }

    fn write_all(&self, cef: &str, severity: SyslogSeverity) -> std::io::Result<()> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut failure = None;
        for entry in &self.sinks {
            if let Err(err) = entry.sink.write(cef, severity, &self.hostname) {
                let message = format!("audit sink {}: {err}", entry.sink.describe());
                if entry.required {
                    tracing::error!("{message}");
                    failure.get_or_insert(std::io::Error::new(err.kind(), message));
                } else {
                    tracing::warn!("{message}");
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

/// Who made a recorded request.
pub(crate) struct Requester<'a> {
    pub(crate) request_id: &'a str,
    pub(crate) client_ip: IpAddr,
    /// TCP port, when the address is the TCP peer.
    pub(crate) client_port: Option<u16>,
    /// The proxy that delivered the request, when the client address came
    /// from a header.
    pub(crate) proxy: Option<SocketAddr>,
    /// The proxy's request ID (`correlation_id_header`).
    pub(crate) correlation_id: Option<&'a str>,
    pub(crate) issuer: &'a str,
    /// The token's `sub`.
    pub(crate) subject: Option<&'a str>,
    pub(crate) oidc_id: Option<&'a str>,
    pub(crate) profile: Option<&'a str>,
    pub(crate) app_name: Option<&'a str>,
}

/// What was issued.
pub(crate) struct Issued<'a> {
    pub(crate) serial: u64,
    pub(crate) key_id: &'a str,
    pub(crate) authority: &'a str,
    pub(crate) cert_type: &'a str,
    pub(crate) principals: &'a [String],
    pub(crate) valid_after: u64,
    pub(crate) valid_before: u64,
    pub(crate) extensions: Vec<(&'a str, &'a str)>,
    pub(crate) critical_options: Vec<(&'a str, &'a str)>,
    pub(crate) public_key_fingerprint: String,
    /// The client key's type, e.g. `ssh-ed25519`.
    pub(crate) key_type: &'a str,
    /// The CA signature algorithm, e.g. `rsa-sha2-512`.
    pub(crate) signature_algorithm: &'a str,
    /// The certificate itself (OpenSSH format), e.g. for revocation lists.
    pub(crate) certificate: &'a str,
}

pub(crate) enum Outcome<'a> {
    Issued(Issued<'a>),
    Denied {
        status: u16,
        reason: &'a str,
    },
    /// A certificate or key revoked through the API.
    Revoked(&'a ssh_casign_proto::revoke::RevokedEntry),
}

pub(crate) struct Event<'a> {
    pub(crate) server_id: &'a str,
    pub(crate) requester: &'a Requester<'a>,
    pub(crate) outcome: Outcome<'a>,
}

/// Escape a CEF header field: backslash and pipe; no line breaks.
fn cef_header(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            '\r' | '\n' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// Escape a CEF extension value: backslash, equals sign and line breaks.
fn cef_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

fn join_options(options: &[(&str, &str)]) -> String {
    options
        .iter()
        .map(|(name, value)| {
            if value.is_empty() {
                name.to_string()
            } else {
                format!("{name}={value}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

impl Event<'_> {
    fn to_cef(&self, header: &CefHeader) -> String {
        let (class, name, severity) = match self.outcome {
            Outcome::Issued(_) => ("certificate-issued", "SSH certificate issued", 3),
            Outcome::Denied { .. } => ("certificate-denied", "SSH certificate request denied", 6),
            Outcome::Revoked(_) => ("certificate-revoked", "SSH certificate or key revoked", 5),
        };
        let requester = self.requester;
        let mut extensions: Vec<(&str, String)> = vec![
            ("rt", now_millis().to_string()),
            ("dvchost", self.server_id.to_string()),
            ("externalId", requester.request_id.to_string()),
            ("src", requester.client_ip.to_string()),
        ];
        if let Some(port) = requester.client_port {
            extensions.push(("spt", port.to_string()));
        }
        if let Some(proxy) = requester.proxy {
            extensions.push(("proxyAddress", proxy.ip().to_string()));
            extensions.push(("proxyPort", proxy.port().to_string()));
        }
        if let Some(correlation_id) = requester.correlation_id {
            extensions.push(("flexString2Label", "correlationId".to_string()));
            extensions.push(("flexString2", correlation_id.to_string()));
        }
        if let Some(oidc_id) = requester.oidc_id {
            extensions.push(("suser", oidc_id.to_string()));
        }
        if let Some(subject) = requester.subject {
            extensions.push(("suid", subject.to_string()));
        }
        if let Some(app_name) = requester.app_name {
            extensions.push(("requestClientApplication", app_name.to_string()));
        }
        extensions.push(("cs5Label", "issuer".to_string()));
        extensions.push(("cs5", requester.issuer.to_string()));
        if let Some(profile) = requester.profile {
            extensions.push(("cs1Label", "profile".to_string()));
            extensions.push(("cs1", profile.to_string()));
        }
        match &self.outcome {
            Outcome::Issued(issued) => {
                extensions.extend([
                    ("act", "issued".to_string()),
                    ("outcome", "success".to_string()),
                    ("flexString1Label", "serial".to_string()),
                    ("flexString1", issued.serial.to_string()),
                    ("cs2Label", "keyId".to_string()),
                    ("cs2", issued.key_id.to_string()),
                    ("cs3Label", "principals".to_string()),
                    ("cs3", issued.principals.join(",")),
                    ("cs4Label", "authority".to_string()),
                    ("cs4", issued.authority.to_string()),
                    ("cs6Label", "publicKeyFingerprint".to_string()),
                    ("cs6", issued.public_key_fingerprint.clone()),
                    ("start", (issued.valid_after * 1000).to_string()),
                    (
                        "end",
                        (issued.valid_before.saturating_mul(1000)).to_string(),
                    ),
                    ("sshCertType", issued.cert_type.to_string()),
                    ("sshKeyType", issued.key_type.to_string()),
                    (
                        "sshCaSignatureAlgorithm",
                        issued.signature_algorithm.to_string(),
                    ),
                    ("sshExtensions", join_options(&issued.extensions)),
                    ("sshCriticalOptions", join_options(&issued.critical_options)),
                    ("sshCertificate", issued.certificate.to_string()),
                ]);
            }
            Outcome::Denied { status, reason } => {
                extensions.extend([
                    ("act", "denied".to_string()),
                    ("outcome", "failure".to_string()),
                    ("reason", reason.to_string()),
                    ("cn1Label", "httpStatus".to_string()),
                    ("cn1", status.to_string()),
                ]);
            }
            Outcome::Revoked(entry) => {
                extensions.extend([
                    ("act", "revoked".to_string()),
                    ("outcome", "success".to_string()),
                    ("duser", entry.revoked_by.clone()),
                ]);
                let optional = [
                    ("flexString1Label", "serial", &entry.serial),
                    ("cs4Label", "authority", &entry.authority),
                    ("cs2Label", "keyId", &entry.key_id),
                    ("cs6Label", "publicKeyFingerprint", &entry.fingerprint),
                ];
                for (label_key, label, value) in optional {
                    if let Some(value) = value {
                        let value_key = label_key.trim_end_matches("Label");
                        extensions.push((label_key, label.to_string()));
                        extensions.push((value_key, value.clone()));
                    }
                }
                if let Some(reason) = &entry.reason {
                    extensions.push(("reason", reason.clone()));
                }
            }
        }
        let extensions = extensions
            .iter()
            .map(|(key, value)| format!("{key}={}", cef_value(value)))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "CEF:{CEF_VERSION}|{}|{}|{}|{class}|{name}|{severity}|{extensions}",
            cef_header(&header.vendor),
            cef_header(&header.product),
            cef_header(&header.version),
        )
    }
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// Current time as RFC 3339 in UTC with milliseconds.
fn now_rfc3339() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_rfc3339(now.as_secs(), now.subsec_millis())
}

/// RFC 3339 in UTC for Unix time `secs` (civil-from-days, H. Hinnant).
fn format_rfc3339(secs: u64, millis: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

/// Random request ID (128 bits, hex).
pub(crate) fn new_request_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339() {
        assert_eq!(format_rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(format_rfc3339(951_782_400, 5), "2000-02-29T00:00:00.005Z");
        assert_eq!(
            format_rfc3339(1_794_668_826, 123),
            "2026-11-14T15:07:06.123Z"
        );
        assert_eq!(
            format_rfc3339(4_102_444_799, 999),
            "2099-12-31T23:59:59.999Z"
        );
    }

    #[test]
    fn cef_escaping() {
        assert_eq!(cef_header(r"a|b\c"), r"a\|b\\c");
        assert_eq!(cef_value("a=b\\c\nd|e"), r"a\=b\\c\nd|e");
    }

    fn requester() -> Requester<'static> {
        Requester {
            request_id: "r1",
            client_ip: "192.0.2.7".parse().unwrap(),
            client_port: Some(5000),
            proxy: None,
            correlation_id: None,
            issuer: "https://idp.example.com",
            subject: Some("123"),
            oidc_id: Some("alice@example.com"),
            profile: Some("default"),
            app_name: Some("laptop"),
        }
    }

    fn header() -> CefHeader {
        CefHeader {
            vendor: "ssh-casign".into(),
            product: "ssh-casign-service".into(),
            version: "0.1.0".into(),
        }
    }

    /// Minimal CEF extension parser for the tests: split on unescaped " key=".
    fn parse_extensions(extensions: &str) -> std::collections::BTreeMap<String, String> {
        let mut fields = std::collections::BTreeMap::new();
        let mut key = String::new();
        let mut value = String::new();
        let mut in_key = true;
        let mut chars = extensions.chars().peekable();
        while let Some(c) = chars.next() {
            if in_key {
                if c == '=' {
                    in_key = false;
                } else {
                    key.push(c);
                }
                continue;
            }
            match c {
                '\\' => match chars.next() {
                    Some('n') => value.push('\n'),
                    Some('r') => value.push('\r'),
                    Some(other) => value.push(other),
                    None => {}
                },
                ' ' => {
                    // A space starts a new key if a "key=" follows.
                    let rest: String = chars.clone().collect();
                    let next_key: String = rest
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric())
                        .collect();
                    if !next_key.is_empty() && rest[next_key.len()..].starts_with('=') {
                        fields.insert(std::mem::take(&mut key), std::mem::take(&mut value));
                        in_key = true;
                    } else {
                        value.push(' ');
                    }
                }
                c => value.push(c),
            }
        }
        fields.insert(key, value);
        fields
    }

    #[test]
    fn issued_event_as_cef() {
        let requester = requester();
        let principals = vec!["alice".to_string(), "deploy".to_string()];
        let event = Event {
            server_id: "ca1",
            requester: &requester,
            outcome: Outcome::Issued(Issued {
                serial: u64::MAX,
                key_id: "ca1:default:alice@example.com:laptop",
                authority: "default",
                cert_type: "user",
                principals: &principals,
                valid_after: 1_800_000_000,
                valid_before: 1_800_003_600,
                extensions: vec![("permit-pty", "")],
                critical_options: vec![("source-address", "10.0.0.0/8")],
                public_key_fingerprint: "SHA256:abc".into(),
                key_type: "ssh-ed25519",
                signature_algorithm: "ssh-rsa",
                certificate: "ssh-ed25519-cert-v01@openssh.com AAAA= comment",
            }),
        };
        let cef = event.to_cef(&header());
        let parts: Vec<&str> = cef.splitn(8, '|').collect();
        assert_eq!(
            parts[..7],
            [
                "CEF:0",
                "ssh-casign",
                "ssh-casign-service",
                "0.1.0",
                "certificate-issued",
                "SSH certificate issued",
                "3"
            ]
        );
        let fields = parse_extensions(parts[7]);
        assert_eq!(fields["act"], "issued");
        assert_eq!(fields["src"], "192.0.2.7");
        assert_eq!(fields["spt"], "5000");
        assert_eq!(fields["suser"], "alice@example.com");
        assert_eq!(fields["suid"], "123");
        assert_eq!(fields["dvchost"], "ca1");
        assert_eq!(fields["externalId"], "r1");
        assert_eq!(fields["flexString1"], u64::MAX.to_string());
        assert_eq!(fields["cs2"], "ca1:default:alice@example.com:laptop");
        assert_eq!(fields["cs3"], "alice,deploy");
        assert_eq!(fields["start"], "1800000000000");
        assert_eq!(fields["sshCriticalOptions"], "source-address=10.0.0.0/8");
        assert_eq!(fields["sshCaSignatureAlgorithm"], "ssh-rsa");
        assert_eq!(
            fields["sshCertificate"],
            "ssh-ed25519-cert-v01@openssh.com AAAA= comment"
        );
        assert!(!cef.contains('\n'));
    }

    #[test]
    fn proxy_fields_in_cef() {
        let proxied = Requester {
            client_port: None,
            proxy: Some("[2400:cb00::1]:443".parse().unwrap()),
            correlation_id: Some("8f1c2a3b4c5d6e7f-AMS"),
            ..requester()
        };
        let event = Event {
            server_id: "ca1",
            requester: &proxied,
            outcome: Outcome::Denied {
                status: 403,
                reason: "no",
            },
        };
        let cef = event.to_cef(&header());
        let fields = parse_extensions(cef.splitn(8, '|').nth(7).unwrap());
        assert_eq!(fields["src"], "192.0.2.7");
        assert!(!fields.contains_key("spt"));
        assert_eq!(fields["proxyAddress"], "2400:cb00::1");
        assert_eq!(fields["proxyPort"], "443");
        assert_eq!(fields["flexString2Label"], "correlationId");
        assert_eq!(fields["flexString2"], "8f1c2a3b4c5d6e7f-AMS");
        // Not present for direct requests.
        let plain = Event {
            requester: &requester(),
            ..event
        }
        .to_cef(&header());
        assert!(!plain.contains("proxyAddress") && !plain.contains("flexString2"));
    }

    #[test]
    fn denied_event_as_cef() {
        let requester = requester();
        let event = Event {
            server_id: "ca|1",
            requester: &requester,
            outcome: Outcome::Denied {
                status: 403,
                reason: "principal 'root' is not in allowed_principals\nof the token",
            },
        };
        let cef = event.to_cef(&header());
        assert!(cef.starts_with("CEF:0|ssh-casign|ssh-casign-service|0.1.0|certificate-denied|SSH certificate request denied|6|"));
        let fields = parse_extensions(cef.splitn(8, '|').nth(7).unwrap());
        assert_eq!(fields["act"], "denied");
        assert_eq!(fields["outcome"], "failure");
        assert_eq!(fields["cn1"], "403");
        assert_eq!(
            fields["reason"],
            "principal 'root' is not in allowed_principals\nof the token"
        );
        assert_eq!(fields["dvchost"], "ca|1");
        assert!(!fields.contains_key("flexString1"));
        assert!(!cef.contains('\n'));
    }

    fn config(toml: &str) -> Config {
        toml::from_str(toml).unwrap()
    }

    #[tokio::test]
    async fn file_sink_appends_lines() {
        let dir = std::env::temp_dir().join(format!("ssh-casign-audit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.cef");
        let log = config(&format!(
            "[[sink]]\ntype = \"file\"\npath = {:?}\n",
            path.to_str().unwrap()
        ))
        .open("ca1")
        .unwrap();
        let requester = requester();
        for reason in ["first", "second"] {
            log.record(&Event {
                server_id: "ca1",
                requester: &requester,
                outcome: Outcome::Denied {
                    status: 403,
                    reason,
                },
            })
            .await
            .unwrap();
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().all(|line| line.starts_with("CEF:0|")));
        assert!(lines[1].contains("reason=second"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o640
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn config_checks() {
        assert!(config("sink = []\n").open("ca1").is_err());
        assert!(
            config("[[sink]]\ntype = \"file\"\npath = \"/nonexistent-dir/a.cef\"\n")
                .open("ca1")
                .is_err()
        );
        // Not required: a broken sink only warns.
        assert!(config(
            "[[sink]]\ntype = \"file\"\npath = \"/nonexistent-dir/a.cef\"\nrequired = false\n"
        )
        .open("ca1")
        .is_ok());
        assert!(config("[[sink]]\ntype = \"syslog\"\naddress = \"127.0.0.1:514\"\ntransport = \"udp\"\nfacility = \"local9\"\n")
            .open("ca1")
            .is_err());
        assert!(toml::from_str::<Config>("[[sink]]\ntype = \"stdout\"\nbogus = 1\n").is_err());
    }

    fn denied<'a>(requester: &'a Requester<'a>) -> Event<'a> {
        Event {
            server_id: "ca1",
            requester,
            outcome: Outcome::Denied {
                status: 403,
                reason: "test",
            },
        }
    }

    #[tokio::test]
    async fn syslog_tcp_sink() {
        use std::io::{BufRead, BufReader};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let log = config(&format!(
            "[[sink]]\ntype = \"syslog\"\naddress = \"{address}\"\ntransport = \"tcp\"\nfacility = \"local4\"\n"
        ))
        .open("ca1")
        .unwrap();
        // The startup check opened the connection the records go over.
        let (stream, _) = listener.accept().unwrap();
        let requester = requester();
        log.record(&denied(&requester)).await.unwrap();
        log.record(&denied(&requester)).await.unwrap();
        let mut lines = BufReader::new(stream).lines();
        for _ in 0..2 {
            let line = lines.next().unwrap().unwrap();
            // local4 (20) * 8 + warning (4) = 164; newline framing
            assert!(line.starts_with("<164>1 "), "{line}");
            assert!(line.contains(" ca1 ssh-casign - audit - CEF:0|"), "{line}");
        }
    }

    #[tokio::test]
    async fn syslog_udp_sink() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let address = socket.local_addr().unwrap();
        let log = config(&format!(
            "[[sink]]\ntype = \"syslog\"\naddress = \"{address}\"\ntransport = \"udp\"\n"
        ))
        .open("ca1")
        .unwrap();
        let requester = requester();
        log.record(&denied(&requester)).await.unwrap();
        let mut buf = [0u8; 8192];
        let n = socket.recv(&mut buf).unwrap();
        let datagram = std::str::from_utf8(&buf[..n]).unwrap();
        // authpriv (10) * 8 + warning (4) = 84; one message per datagram
        assert!(datagram.starts_with("<84>1 "), "{datagram}");
        assert!(
            datagram.contains(" ca1 ssh-casign - audit - CEF:0|"),
            "{datagram}"
        );
    }

    #[test]
    fn required_tcp_sink_must_be_reachable_at_startup() {
        // Bind and drop to get a port nobody listens on.
        let address = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        assert!(config(&format!(
            "[[sink]]\ntype = \"syslog\"\ntransport = \"tcp\"\naddress = \"{address}\"\n"
        ))
        .open("ca1")
        .is_err());
    }

    #[test]
    fn syslog_target_validation() {
        let target = |toml: &str| {
            toml::from_str::<SyslogConfig>(toml)
                .unwrap()
                .target()
                .map(|target| format!("{target:?}"))
        };
        #[cfg(unix)]
        assert!(target("").unwrap().contains(if cfg!(target_os = "macos") {
            "/var/run/syslog"
        } else {
            "/dev/log"
        }));
        assert!(
            target("address = \"127.0.0.1:514\"").is_err(),
            "unix with address"
        );
        assert!(
            target("transport = \"tcp\"").is_err(),
            "tcp without address"
        );
        assert!(target("transport = \"udp\"\naddress = \"127.0.0.1:514\"\npath = \"/x\"").is_err());
        assert!(target("transport = \"udp\"\naddress = \"127.0.0.1:514\"")
            .unwrap()
            .starts_with("Udp"));
    }

    /// Short socket path: Unix socket paths are limited to ~104 bytes.
    #[cfg(unix)]
    fn socket_path(name: &str) -> PathBuf {
        PathBuf::from(format!("/tmp/sca-{}-{name}.sock", std::process::id()))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn syslog_unix_datagram_sink() {
        let path = socket_path("dgram");
        let _ = std::fs::remove_file(&path);
        let socket = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let log = config(&format!(
            "[[sink]]\ntype = \"syslog\"\npath = {:?}\nfacility = \"auth\"\n",
            path.to_str().unwrap()
        ))
        .open("ca1")
        .unwrap();
        let requester = requester();
        log.record(&denied(&requester)).await.unwrap();
        let mut buf = [0u8; 8192];
        let n = socket.recv(&mut buf).unwrap();
        let message = std::str::from_utf8(&buf[..n]).unwrap();
        // auth (4) * 8 + warning (4) = 36; traditional local format
        let expected = format!("<36>ssh-casign[{}]: CEF:0|", std::process::id());
        assert!(message.starts_with(&expected), "{message}");
        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn syslog_unix_stream_fallback() {
        use std::io::{BufRead, BufReader};
        let path = socket_path("stream");
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let log = config(&format!(
            "[[sink]]\ntype = \"syslog\"\npath = {:?}\n",
            path.to_str().unwrap()
        ))
        .open("ca1")
        .unwrap();
        let reader = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream).read_line(&mut line).unwrap();
            line
        });
        let requester = requester();
        log.record(&denied(&requester)).await.unwrap();
        let line = reader.join().unwrap();
        assert!(line.starts_with("<84>ssh-casign["), "{line}");
        assert!(line.ends_with('\n'));
        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn missing_unix_socket_fails_at_startup() {
        assert!(
            config("[[sink]]\ntype = \"syslog\"\npath = \"/nonexistent/log\"\n")
                .open("ca1")
                .is_err()
        );
    }
}
