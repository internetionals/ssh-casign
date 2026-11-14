//! Authorization code flow with PKCE and a loopback redirect (RFC 6749,
//! RFC 7636, RFC 8252).
//!
//! The client listens on a random loopback port, opens the IdP's sign-in page
//! in a browser on this machine, and receives the authorization code when the
//! browser is redirected back. PKCE binds the code to this process, and
//! `state` binds the redirect to this sign-in attempt.
//!
//! The redirect URI uses the host name `localhost` rather than the IP literal
//! RFC 8252 prefers: some IdPs (Dex) only accept loopback redirects for
//! public clients in that form, and it is what Azure documents. Because the
//! browser may resolve `localhost` to either address, the client listens on
//! both `127.0.0.1` and `[::1]`.

use std::{process::Stdio, time::Duration};

use base64ct::{Base64UrlUnpadded, Encoding};
use color_eyre::eyre::{bail, eyre, WrapErr};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use url::Url;

use super::{OAuthError, TokenResponse};
use crate::error::Result;

const CALLBACK_PATH: &str = "/callback";

/// How long to wait for the user to finish signing in.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);

/// Upper bound for the callback request head; it only carries a short query.
const MAX_REQUEST_SIZE: usize = 16 * 1024;

/// Environment variable with the browser command; the URL is its argument.
const BROWSER_ENV: &str = "BROWSER";

fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    Base64UrlUnpadded::encode_string(&buf)
}

/// PKCE (RFC 7636) verifier and its S256 challenge.
struct Pkce {
    verifier: String,
    challenge: String,
}

impl Pkce {
    fn new() -> Self {
        // 32 random bytes give a 43 character verifier, the RFC's minimum length.
        let verifier = random_token(32);
        let challenge = Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes()));
        Self {
            verifier,
            challenge,
        }
    }
}

pub(super) async fn sign_in(
    http: &reqwest::Client,
    authorization_endpoint: &Url,
    token_endpoint: &Url,
    client_id: &str,
    scopes: &[String],
) -> Result<TokenResponse> {
    // RFC 8252 section 7.3: loopback redirect with an ephemeral port.
    let listener = Loopback::bind().await?;
    let redirect_uri = format!("http://localhost:{}{CALLBACK_PATH}", listener.port);

    let pkce = Pkce::new();
    let state = random_token(16);
    let mut authorization_url = authorization_endpoint.clone();
    authorization_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", &scopes.join(" "))
        .append_pair("state", &state)
        .append_pair("code_challenge", &pkce.challenge)
        .append_pair("code_challenge_method", "S256");

    eprintln!();
    eprintln!("Opening the sign-in page in your browser. If it doesn't open, visit:");
    eprintln!("  {authorization_url}");
    eprintln!();
    eprintln!("Waiting for sign-in...");
    open_browser(authorization_url.as_str());

    let code = tokio::time::timeout(SIGN_IN_TIMEOUT, receive_code(&listener, &state))
        .await
        .map_err(|_| eyre!("Timed out waiting for the sign-in to complete"))??;

    let response = http
        .post(token_endpoint.clone())
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", client_id),
            ("code_verifier", pkce.verifier.as_str()),
        ])
        .send()
        .await
        .wrap_err_with(|| format!("Token request to {token_endpoint} failed"))?;
    if !response.status().is_success() {
        let status = response.status();
        let error = OAuthError::from_response(response).await;
        bail!("Token request rejected ({status}): {error}");
    }
    response.json().await.wrap_err("Invalid token response")
}

/// Start the browser without waiting for it. Failure is not fatal: the URL has
/// been printed, so the user can open it by hand.
fn open_browser(url: &str) {
    let mut command = match std::env::var(BROWSER_ENV) {
        Ok(browser) if !browser.trim().is_empty() => std::process::Command::new(browser),
        _ if cfg!(target_os = "macos") => std::process::Command::new("open"),
        // Not `cmd /C start`: cmd would treat the `&`s in the URL as command
        // separators. The URL handler gets the URL as is.
        _ if cfg!(windows) => {
            let mut command = std::process::Command::new("rundll32.exe");
            command.arg("url.dll,FileProtocolHandler");
            command
        }
        _ => std::process::Command::new("xdg-open"),
    };
    command
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Err(err) = command.spawn() {
        tracing::debug!("failed to open a browser: {err}");
    }
}

/// Listeners on the IPv4 and (when available) IPv6 loopback address, sharing
/// one port.
struct Loopback {
    port: u16,
    v4: TcpListener,
    v6: Option<TcpListener>,
}

impl Loopback {
    async fn bind() -> Result<Self> {
        let v4 = TcpListener::bind("127.0.0.1:0")
            .await
            .wrap_err("Failed to listen for the sign-in redirect")?;
        let port = v4.local_addr()?.port();
        let v6 = match TcpListener::bind(("::1", port)).await {
            Ok(v6) => Some(v6),
            Err(err) => {
                tracing::debug!("not listening on [::1]:{port}: {err}");
                None
            }
        };
        Ok(Self { port, v4, v6 })
    }

    async fn accept(&self) -> std::io::Result<TcpStream> {
        match &self.v6 {
            Some(v6) => tokio::select! {
                result = self.v4.accept() => result.map(|(stream, _)| stream),
                result = v6.accept() => result.map(|(stream, _)| stream),
            },
            None => self.v4.accept().await.map(|(stream, _)| stream),
        }
    }
}

/// Outcome of one request to the loopback listener.
enum Callback {
    Code(String),
    Error(String),
    /// Not the callback (e.g. `/favicon.ico`), or a stale/forged redirect.
    Ignored,
}

/// Accept connections until the callback with a matching `state` arrives.
async fn receive_code(listener: &Loopback, state: &str) -> Result<String> {
    loop {
        let mut stream = listener.accept().await?;
        let callback = match read_request_target(&mut stream).await {
            Ok(target) => parse_callback(&target, state),
            Err(err) => {
                tracing::debug!("ignoring unreadable request: {err}");
                Callback::Ignored
            }
        };
        match callback {
            Callback::Code(code) => {
                respond(
                    &mut stream,
                    "200 OK",
                    "Signed in",
                    "You can close this window and return to the terminal.",
                )
                .await;
                return Ok(code);
            }
            Callback::Error(error) => {
                respond(&mut stream, "400 Bad Request", "Sign-in failed", &error).await;
                bail!("Sign-in failed: {error}");
            }
            Callback::Ignored => respond(&mut stream, "404 Not Found", "Not found", "").await,
        }
    }
}

/// Read the request head and return the request target (path and query).
async fn read_request_target(stream: &mut TcpStream) -> Result<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    while !buf.windows(4).any(|window| window == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_REQUEST_SIZE {
            bail!("request too large");
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let request_line = head.lines().next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    match (parts.next(), parts.next()) {
        (Some("GET"), Some(target)) => Ok(target.to_string()),
        _ => bail!("unexpected request: {request_line:?}"),
    }
}

fn parse_callback(target: &str, expected_state: &str) -> Callback {
    let Ok(url) = Url::parse(&format!("http://127.0.0.1{target}")) else {
        return Callback::Ignored;
    };
    if url.path() != CALLBACK_PATH {
        return Callback::Ignored;
    }
    let param = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    if param("state").as_deref() != Some(expected_state) {
        tracing::debug!("ignoring callback with unexpected state");
        return Callback::Ignored;
    }
    if let Some(error) = param("error") {
        return Callback::Error(match param("error_description") {
            Some(description) => format!("{error} ({description})"),
            None => error,
        });
    }
    match param("code") {
        Some(code) if !code.is_empty() => Callback::Code(code),
        _ => Callback::Error("no authorization code in the redirect".to_string()),
    }
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn respond(stream: &mut TcpStream, status: &str, title: &str, message: &str) {
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>ssh-casign: {title}</title></head>\
         <body style=\"font-family:sans-serif;margin:3em\"><h1>{title}</h1><p>{}</p></body></html>",
        html_escape(message)
    );
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    if let Err(err) = stream.write_all(response.as_bytes()).await {
        tracing::debug!("failed to answer the browser: {err}");
    }
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_matches_rfc7636_example() {
        // RFC 7636 appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes()));
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        let pkce = Pkce::new();
        assert_eq!(pkce.verifier.len(), 43);
    }

    #[test]
    fn callback_parsing() {
        let code = |target| match parse_callback(target, "s1") {
            Callback::Code(code) => Some(code),
            _ => None,
        };
        assert_eq!(code("/callback?code=abc&state=s1").as_deref(), Some("abc"));
        assert_eq!(code("/callback?code=abc&state=other"), None);
        assert_eq!(code("/callback?code=abc"), None);
        assert!(matches!(
            parse_callback("/favicon.ico", "s1"),
            Callback::Ignored
        ));
        assert!(matches!(
            parse_callback("/callback?error=access_denied&state=s1", "s1"),
            Callback::Error(error) if error == "access_denied"
        ));
    }
}
