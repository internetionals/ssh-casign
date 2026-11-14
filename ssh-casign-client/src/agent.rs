//! Minimal ssh-agent client (draft-miller-ssh-agent): list identities, and
//! add an Ed25519 key together with its certificate, constrained to a
//! lifetime.
//!
//! Only what `login` needs is implemented, so the private key of an ephemeral
//! login never has to be written to disk for `ssh-add`.

use color_eyre::eyre::{bail, eyre, WrapErr};
use ssh_key::{private::Ed25519Keypair, public::KeyData, Certificate};
use zeroize::Zeroizing;

use crate::error::Result;

const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
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

/// An identity held by the agent: its public key or certificate blob, and
/// its comment.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) key_blob: Vec<u8>,
    pub(crate) comment: String,
}

impl Identity {
    /// The certificate, if this identity is one.
    pub(crate) fn certificate(&self) -> Option<Certificate> {
        Certificate::from_bytes(&self.key_blob).ok()
    }
}

/// Send one framed message to the agent at `$SSH_AUTH_SOCK` and return the
/// reply body.
#[cfg(unix)]
fn roundtrip(message: &[u8]) -> Result<Vec<u8>> {
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
    stream
        .write_all(message)
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
    Ok(reply)
}

#[cfg(not(unix))]
fn roundtrip(_message: &[u8]) -> Result<Vec<u8>> {
    bail!("ssh-agent is only supported on Unix-like systems")
}

/// Add the key with its certificate to the agent; the agent forgets both
/// after `lifetime_secs`.
pub(crate) fn add_certificate(
    keypair: &Ed25519Keypair,
    certificate: &Certificate,
    comment: &str,
    lifetime_secs: u32,
) -> Result<()> {
    let message = add_identity_message(keypair, certificate, comment, lifetime_secs)?;
    let reply = roundtrip(&message)?;
    match reply[0] {
        SSH_AGENT_SUCCESS => Ok(()),
        SSH_AGENT_FAILURE => bail!("ssh-agent refused the key and certificate"),
        other => bail!("Unexpected reply from ssh-agent (message type {other})"),
    }
}

/// Remove one identity (key or certificate) from the agent.
pub(crate) fn remove_identity(key_blob: &[u8]) -> Result<()> {
    let mut body = vec![SSH_AGENTC_REMOVE_IDENTITY];
    put_string(&mut body, key_blob);
    let mut message = (body.len() as u32).to_be_bytes().to_vec();
    message.extend_from_slice(&body);
    match roundtrip(&message)?[0] {
        SSH_AGENT_SUCCESS => Ok(()),
        SSH_AGENT_FAILURE => bail!("ssh-agent refused to remove the identity"),
        other => bail!("Unexpected reply from ssh-agent (message type {other})"),
    }
}

/// The identities the agent holds.
pub(crate) fn list_identities() -> Result<Vec<Identity>> {
    let reply = roundtrip(&[0, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES])?;
    parse_identities_answer(&reply)
}

fn take_u32(buf: &mut &[u8]) -> Result<u32> {
    if buf.len() < 4 {
        bail!("Truncated identities answer from ssh-agent");
    }
    let (value, rest) = buf.split_at(4);
    *buf = rest;
    Ok(u32::from_be_bytes(value.try_into().expect("4 bytes")))
}

fn take_string<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = take_u32(buf)? as usize;
    if buf.len() < len {
        bail!("Truncated identities answer from ssh-agent");
    }
    let (value, rest) = buf.split_at(len);
    *buf = rest;
    Ok(value)
}

fn parse_identities_answer(reply: &[u8]) -> Result<Vec<Identity>> {
    let Some((&message_type, mut rest)) = reply.split_first() else {
        bail!("Empty reply from ssh-agent");
    };
    if message_type != SSH_AGENT_IDENTITIES_ANSWER {
        bail!("Unexpected reply from ssh-agent (message type {message_type})");
    }
    let count = take_u32(&mut rest)?;
    let mut identities = Vec::new();
    for _ in 0..count {
        let key_blob = take_string(&mut rest)?.to_vec();
        let comment = String::from_utf8_lossy(take_string(&mut rest)?).into_owned();
        identities.push(Identity { key_blob, comment });
    }
    Ok(identities)
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
    fn identities_answer_parsing() {
        let keypair = Ed25519Keypair::from_seed(&[1; 32]);
        let certificate = certificate_for(&keypair);
        let mut reply = vec![SSH_AGENT_IDENTITIES_ANSWER];
        reply.extend_from_slice(&2u32.to_be_bytes());
        put_string(&mut reply, &certificate.to_bytes().unwrap());
        put_string(&mut reply, b"ssh-casign:laptop id");
        put_string(&mut reply, &[1, 2, 3]);
        put_string(&mut reply, b"plain key");
        let identities = parse_identities_answer(&reply).unwrap();
        assert_eq!(identities.len(), 2);
        assert_eq!(identities[0].comment, "ssh-casign:laptop id");
        assert_eq!(identities[0].certificate().unwrap(), certificate);
        assert!(identities[1].certificate().is_none());

        assert!(parse_identities_answer(&reply[..reply.len() - 3]).is_err());
        assert!(parse_identities_answer(&[SSH_AGENT_FAILURE]).is_err());
    }

    #[test]
    fn certificate_must_match_key() {
        let keypair = Ed25519Keypair::from_seed(&[1; 32]);
        let other = Ed25519Keypair::from_seed(&[2; 32]);
        let certificate = certificate_for(&other);
        assert!(add_identity_message(&keypair, &certificate, "", 300).is_err());
    }
}
