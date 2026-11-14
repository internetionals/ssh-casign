//! Minimal ssh-agent client (draft-miller-ssh-agent): add an Ed25519 key
//! together with its certificate, constrained to a lifetime.
//!
//! Only what `login` needs is implemented, so the private key of an ephemeral
//! login never has to be written to disk for `ssh-add`.

use color_eyre::eyre::{bail, eyre, WrapErr};
use ssh_key::{private::Ed25519Keypair, public::KeyData, Certificate};
use zeroize::Zeroizing;

use crate::error::Result;

const SSH_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
const SSH_AGENT_CONSTRAIN_LIFETIME: u8 = 1;
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const ED25519_CERT_ALGORITHM: &str = "ssh-ed25519-cert-v01@openssh.com";

/// Upper bound for an agent reply; replies to an add are a single byte.
const MAX_REPLY_SIZE: u32 = 256 * 1024;

fn put_string(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Build the framed `SSH_AGENTC_ADD_ID_CONSTRAINED` message. It contains the
/// private key, so it is wiped when dropped.
fn add_identity_message(
    keypair: &Ed25519Keypair,
    certificate: &Certificate,
    comment: &str,
    lifetime_secs: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    match certificate.public_key() {
        KeyData::Ed25519(public) if *public == keypair.public => {}
        _ => bail!("The certificate is not for this key"),
    }
    let mut body = Zeroizing::new(vec![SSH_AGENTC_ADD_ID_CONSTRAINED]);
    put_string(&mut body, ED25519_CERT_ALGORITHM.as_bytes());
    put_string(&mut body, &certificate.to_bytes()?);
    put_string(&mut body, keypair.public.as_ref());
    put_string(&mut body, Zeroizing::new(keypair.to_bytes()).as_ref());
    put_string(&mut body, comment.as_bytes());
    body.push(SSH_AGENT_CONSTRAIN_LIFETIME);
    body.extend_from_slice(&lifetime_secs.to_be_bytes());

    let mut message = Zeroizing::new(Vec::with_capacity(body.len() + 4));
    message.extend_from_slice(&(body.len() as u32).to_be_bytes());
    message.extend_from_slice(&body);
    Ok(message)
}

/// Add the key with its certificate to the agent at `$SSH_AUTH_SOCK`; the
/// agent forgets both after `lifetime_secs`.
#[cfg(unix)]
pub(crate) fn add_certificate(
    keypair: &Ed25519Keypair,
    certificate: &Certificate,
    comment: &str,
    lifetime_secs: u32,
) -> Result<()> {
    use std::io::{Read, Write};

    let socket = std::env::var_os("SSH_AUTH_SOCK")
        .filter(|socket| !socket.is_empty())
        .ok_or_else(|| eyre!("No ssh-agent found: SSH_AUTH_SOCK is not set"))?;
    let mut stream = std::os::unix::net::UnixStream::connect(&socket).wrap_err_with(|| {
        format!(
            "Failed to connect to ssh-agent at {}",
            socket.to_string_lossy()
        )
    })?;

    let message = add_identity_message(keypair, certificate, comment, lifetime_secs)?;
    stream
        .write_all(&message)
        .wrap_err("Failed to talk to ssh-agent")?;

    let mut len = [0u8; 4];
    stream
        .read_exact(&mut len)
        .wrap_err("No reply from ssh-agent")?;
    let len = u32::from_be_bytes(len);
    if len == 0 || len > MAX_REPLY_SIZE {
        bail!("Invalid reply from ssh-agent");
    }
    let mut reply = vec![0u8; len as usize];
    stream
        .read_exact(&mut reply)
        .wrap_err("Truncated reply from ssh-agent")?;
    match reply[0] {
        SSH_AGENT_SUCCESS => Ok(()),
        SSH_AGENT_FAILURE => bail!("ssh-agent refused the key and certificate"),
        other => bail!("Unexpected reply from ssh-agent (message type {other})"),
    }
}

#[cfg(not(unix))]
pub(crate) fn add_certificate(
    _keypair: &Ed25519Keypair,
    _certificate: &Certificate,
    _comment: &str,
    _lifetime_secs: u32,
) -> Result<()> {
    bail!("Adding keys to ssh-agent is only supported on Unix-like systems")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_string(buf: &[u8]) -> (&[u8], &[u8]) {
        let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
        (&buf[4..4 + len], &buf[4 + len..])
    }

    fn certificate_for(keypair: &Ed25519Keypair) -> Certificate {
        let ca = ssh_key::PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
        let mut builder = ssh_key::certificate::Builder::new(
            vec![0; 16],
            KeyData::Ed25519(keypair.public),
            0,
            4_102_444_800, // 2100-01-01
        )
        .unwrap();
        builder.valid_principal("alice").unwrap();
        builder.sign(&ca).unwrap()
    }

    #[test]
    fn add_identity_message_layout() {
        let keypair = Ed25519Keypair::from_seed(&[1; 32]);
        let certificate = certificate_for(&keypair);
        let message = add_identity_message(&keypair, &certificate, "comment", 300).unwrap();

        let (body, rest) = read_string(&message);
        assert!(rest.is_empty());
        assert_eq!(body[0], SSH_AGENTC_ADD_ID_CONSTRAINED);
        let (algorithm, rest) = read_string(&body[1..]);
        assert_eq!(algorithm, ED25519_CERT_ALGORITHM.as_bytes());
        let (cert_blob, rest) = read_string(rest);
        assert_eq!(cert_blob, certificate.to_bytes().unwrap());
        let (public, rest) = read_string(rest);
        assert_eq!(public, keypair.public.as_ref());
        let (private, rest) = read_string(rest);
        assert_eq!(private, keypair.to_bytes());
        let (comment, rest) = read_string(rest);
        assert_eq!(comment, b"comment");
        assert_eq!(
            rest,
            [&[SSH_AGENT_CONSTRAIN_LIFETIME][..], &300u32.to_be_bytes()].concat()
        );
    }

    #[test]
    fn certificate_must_match_key() {
        let keypair = Ed25519Keypair::from_seed(&[1; 32]);
        let other = Ed25519Keypair::from_seed(&[2; 32]);
        let certificate = certificate_for(&other);
        assert!(add_identity_message(&keypair, &certificate, "", 300).is_err());
    }
}
