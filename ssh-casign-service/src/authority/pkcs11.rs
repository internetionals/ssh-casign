//! CA key on a PKCS#11 token: YubiKey (ykcs11), smart cards (OpenSC), SoftHSM
//! or a network HSM.
//!
//! The private key never leaves the token. Ed25519 uses `CKM_EDDSA`, ECDSA
//! `CKM_ECDSA` over a hash computed here, and RSA `CKM_RSA_PKCS` over a
//! `DigestInfo` built here, so every hash (including SHA-1 for `ssh-rsa`)
//! works with any token that does raw PKCS#1 v1.5. The algorithms offered
//! follow the token's mechanism list.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::{
        eddsa::{EddsaParams, EddsaSignatureScheme},
        Mechanism, MechanismType,
    },
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    slot::Slot,
    types::AuthPin,
};
use serde::Deserialize;
use ssh_key::public::{EcdsaPublicKey, Ed25519PublicKey, KeyData, RsaPublicKey};

use super::{encoding, signing::SignatureAlgorithm, Backend, BackendError, BoxFuture};

const PIN_ENV: &str = "SSH_CASIGN_PKCS11_PIN";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// PKCS#11 module, e.g. `/usr/lib/softhsm/libsofthsm2.so`,
    /// `opensc-pkcs11.so` or `libykcs11.so`.
    module: PathBuf,
    /// Token label; default: the only token present.
    token_label: Option<String>,
    /// Label of the key (private and public key object).
    key_label: Option<String>,
    /// ID of the key, in hex (e.g. `"01"`).
    key_id: Option<String>,
    /// File with the user PIN; default: `SSH_CASIGN_PKCS11_PIN`. Without
    /// either, no login (tokens with a PIN pad or without a PIN).
    pin_file: Option<PathBuf>,
}

fn pkcs11_err(context: &str) -> impl Fn(cryptoki::error::Error) -> String + '_ {
    move |err| format!("{context}: {err}")
}

fn hex(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim();
    if !value.len().is_multiple_of(2) {
        return Err(format!("key_id {value:?} is not hex"));
    }
    (0..value.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&value[i..i + 2], 16)
                .map_err(|_| format!("key_id {value:?} is not hex"))
        })
        .collect()
}

/// Unwrap a DER OCTET STRING if `bytes` is one; some tokens return the bare
/// point instead.
fn unwrap_octet_string(bytes: &[u8], expected_len: usize) -> Result<&[u8], String> {
    if bytes.len() == expected_len {
        return Ok(bytes);
    }
    let invalid = || "invalid CKA_EC_POINT".to_string();
    match bytes {
        [0x04, len, rest @ ..] if (*len as usize) < 0x80 && rest.len() == *len as usize => Ok(rest),
        [0x04, 0x81, len, rest @ ..] if rest.len() == *len as usize => Ok(rest),
        _ => Err(invalid()),
    }
    .and_then(|point| {
        if point.len() == expected_len {
            Ok(point)
        } else {
            Err(invalid())
        }
    })
}

/// (expected point length, curve) for a DER-encoded curve OID in CKA_EC_PARAMS.
fn ec_curve(params: &[u8]) -> Result<(usize, &'static str), String> {
    const P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    const P384: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
    const P521: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];
    match params {
        P256 => Ok((65, "nistp256")),
        P384 => Ok((97, "nistp384")),
        P521 => Ok((133, "nistp521")),
        _ => Err("unsupported EC curve (P-256, P-384 and P-521 are supported)".to_string()),
    }
}

fn is_ed25519_params(params: &[u8]) -> bool {
    // OID 1.3.101.112, or the PrintableString "edwards25519" older tokens use.
    params == [0x06, 0x03, 0x2b, 0x65, 0x70] || params == b"\x13\x0cedwards25519"
}

/// An open, logged-in session plus what is needed to open a new one.
struct Token {
    context: Pkcs11,
    slot: Slot,
    pin: Option<String>,
    session: Option<Session>,
}

impl Token {
    fn session(&mut self) -> Result<&Session, String> {
        if self.session.is_none() {
            let session = self
                .context
                .open_ro_session(self.slot)
                .map_err(pkcs11_err("open session"))?;
            if let Some(pin) = &self.pin {
                session
                    .login(UserType::User, Some(&AuthPin::new(pin.clone().into())))
                    .map_err(pkcs11_err("login"))?;
            }
            self.session = Some(session);
        }
        Ok(self.session.as_ref().expect("opened above"))
    }
}

fn find_one(session: &Session, template: &[Attribute], what: &str) -> Result<ObjectHandle, String> {
    let objects = session
        .find_objects(template)
        .map_err(pkcs11_err("find objects"))?;
    match objects.as_slice() {
        [object] => Ok(*object),
        [] => Err(format!("no {what} found")),
        _ => Err(format!(
            "{} {what}s match; add key_label or key_id",
            objects.len()
        )),
    }
}

fn attribute(
    session: &Session,
    object: ObjectHandle,
    kind: AttributeType,
) -> Result<Attribute, String> {
    session
        .get_attributes(object, &[kind])
        .map_err(pkcs11_err("read attribute"))?
        .into_iter()
        .next()
        .ok_or_else(|| format!("{kind:?} not available"))
}

fn bytes(attribute: Attribute) -> Result<Vec<u8>, String> {
    match attribute {
        Attribute::EcParams(value)
        | Attribute::EcPoint(value)
        | Attribute::Modulus(value)
        | Attribute::PublicExponent(value) => Ok(value),
        other => Err(format!("unexpected attribute {other:?}")),
    }
}

impl Config {
    pub(super) async fn load(&self) -> Result<Pkcs11Key, String> {
        let config = Config {
            module: self.module.clone(),
            token_label: self.token_label.clone(),
            key_label: self.key_label.clone(),
            key_id: self.key_id.clone(),
            pin_file: self.pin_file.clone(),
        };
        // PKCS#11 calls block; keep them off the async runtime.
        tokio::task::spawn_blocking(move || config.load_blocking())
            .await
            .map_err(|err| err.to_string())?
    }

    fn load_blocking(&self) -> Result<Pkcs11Key, String> {
        if self.key_label.is_none() && self.key_id.is_none() {
            return Err("set key_label and/or key_id".to_string());
        }
        let pin = match &self.pin_file {
            Some(file) => Some(
                std::fs::read_to_string(file)
                    .map_err(|err| format!("pin file {}: {err}", file.display()))?
                    .trim()
                    .to_string(),
            ),
            None => std::env::var(PIN_ENV).ok(),
        };

        let context = Pkcs11::new(&self.module)
            .map_err(|err| format!("load {}: {err}", self.module.display()))?;
        context
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(pkcs11_err("initialize"))?;
        let slots = context
            .get_slots_with_token()
            .map_err(pkcs11_err("list tokens"))?;
        let mut matching = Vec::new();
        for slot in slots {
            let info = context
                .get_token_info(slot)
                .map_err(pkcs11_err("token info"))?;
            let label = info.label().trim().to_string();
            if self
                .token_label
                .as_ref()
                .is_none_or(|wanted| *wanted == label)
            {
                matching.push((slot, label));
            }
        }
        let (slot, token_label) = match matching.as_slice() {
            [one] => one.clone(),
            [] => return Err("no matching PKCS#11 token".to_string()),
            _ => return Err("several tokens present; set token_label".to_string()),
        };

        let mechanisms = context
            .get_mechanism_list(slot)
            .map_err(pkcs11_err("list mechanisms"))?;

        let mut token = Token {
            context,
            slot,
            pin,
            session: None,
        };
        let session = token.session()?;
        let mut template = Vec::new();
        if let Some(label) = &self.key_label {
            template.push(Attribute::Label(label.as_bytes().to_vec()));
        }
        if let Some(id) = &self.key_id {
            template.push(Attribute::Id(hex(id)?));
        }
        let mut private_template = template.clone();
        private_template.push(Attribute::Class(ObjectClass::PRIVATE_KEY));
        let private = find_one(session, &private_template, "private key")?;
        let mut public_template = template;
        public_template.push(Attribute::Class(ObjectClass::PUBLIC_KEY));
        let public = find_one(session, &public_template, "public key")?;

        let key_type = match attribute(session, private, AttributeType::KeyType)? {
            Attribute::KeyType(key_type) => key_type,
            other => return Err(format!("unexpected attribute {other:?}")),
        };
        let has = |mechanism: MechanismType| mechanisms.contains(&mechanism);
        let (public_key, algorithms) = if key_type == KeyType::RSA {
            let n = bytes(attribute(session, public, AttributeType::Modulus)?)?;
            let e = bytes(attribute(session, public, AttributeType::PublicExponent)?)?;
            let mpint = |value: &[u8]| {
                ssh_key::Mpint::from_positive_bytes(value).map_err(|err| err.to_string())
            };
            let key = KeyData::Rsa(RsaPublicKey {
                e: mpint(&e)?,
                n: mpint(&n)?,
            });
            let algorithms = if has(MechanismType::RSA_PKCS) {
                vec![
                    SignatureAlgorithm::RsaSha512,
                    SignatureAlgorithm::RsaSha256,
                    SignatureAlgorithm::SshRsa,
                ]
            } else {
                Vec::new()
            };
            (key, algorithms)
        } else if key_type == KeyType::EC {
            let params = bytes(attribute(session, public, AttributeType::EcParams)?)?;
            let (point_len, _) = ec_curve(&params)?;
            let point = bytes(attribute(session, public, AttributeType::EcPoint)?)?;
            let point = unwrap_octet_string(&point, point_len)?;
            let key = KeyData::Ecdsa(
                EcdsaPublicKey::from_sec1_bytes(point).map_err(|err| err.to_string())?,
            );
            let algorithms = if has(MechanismType::ECDSA) {
                SignatureAlgorithm::for_key(&key)?.0
            } else {
                Vec::new()
            };
            (key, algorithms)
        } else if key_type == KeyType::EC_EDWARDS {
            let params = bytes(attribute(session, public, AttributeType::EcParams)?)?;
            if !is_ed25519_params(&params) {
                return Err("unsupported Edwards curve (only Ed25519)".to_string());
            }
            let point = bytes(attribute(session, public, AttributeType::EcPoint)?)?;
            let point: [u8; 32] = unwrap_octet_string(&point, 32)?
                .try_into()
                .expect("32 bytes");
            let algorithms = if has(MechanismType::EDDSA) {
                vec![SignatureAlgorithm::Ed25519]
            } else {
                Vec::new()
            };
            (KeyData::Ed25519(Ed25519PublicKey(point)), algorithms)
        } else {
            return Err(format!("unsupported key type {key_type}"));
        };

        let description = format!(
            "pkcs11 {} token {token_label:?} key {}",
            self.module.display(),
            self.key_label
                .as_deref()
                .map(|label| format!("{label:?}"))
                .or(self.key_id.as_ref().map(|id| format!("id {id}")))
                .unwrap_or_default()
        );
        Ok(Pkcs11Key {
            description,
            public_key,
            algorithms,
            private_template,
            token: Arc::new(Mutex::new(token)),
        })
    }
}

pub(crate) struct Pkcs11Key {
    description: String,
    public_key: KeyData,
    algorithms: Vec<SignatureAlgorithm>,
    private_template: Vec<Attribute>,
    token: Arc<Mutex<Token>>,
}

/// One signature on an open session.
fn sign_once(
    token: &mut Token,
    template: &[Attribute],
    algorithm: SignatureAlgorithm,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let session = token.session()?;
    let key = find_one(session, template, "private key")?;
    let sign = |mechanism: &Mechanism, input: &[u8]| {
        session
            .sign(mechanism, key, input)
            .map_err(pkcs11_err("sign"))
    };
    match algorithm {
        SignatureAlgorithm::Ed25519 => sign(
            &Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure)),
            data,
        ),
        SignatureAlgorithm::EcdsaP256
        | SignatureAlgorithm::EcdsaP384
        | SignatureAlgorithm::EcdsaP521 => {
            let raw = sign(&Mechanism::Ecdsa, &encoding::digest(algorithm, data))?;
            encoding::ecdsa_signature_from_raw(&raw)
        }
        SignatureAlgorithm::RsaSha512
        | SignatureAlgorithm::RsaSha256
        | SignatureAlgorithm::SshRsa => sign(
            &Mechanism::RsaPkcs,
            &encoding::rsa_digest_info(algorithm, data)?,
        ),
    }
}

impl Backend for Pkcs11Key {
    fn describe(&self) -> String {
        self.description.clone()
    }

    fn public_key(&self) -> &KeyData {
        &self.public_key
    }

    fn algorithms(&self) -> Vec<SignatureAlgorithm> {
        self.algorithms.clone()
    }

    fn sign<'a>(
        &'a self,
        algorithm: SignatureAlgorithm,
        data: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, BackendError>> {
        let token = self.token.clone();
        let template = self.private_template.clone();
        let data = data.to_vec();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let mut token = token.lock().unwrap_or_else(|e| e.into_inner());
                match sign_once(&mut token, &template, algorithm, &data) {
                    Ok(signature) => Ok(signature),
                    Err(first) => {
                        // The session may be gone (token replugged or reset):
                        // retry once on a new session.
                        tracing::warn!(
                            "PKCS#11 signing failed, retrying on a new session: {first}"
                        );
                        token.session = None;
                        sign_once(&mut token, &template, algorithm, &data)
                    }
                }
            })
            .await
            .map_err(BackendError::new)?
            .map_err(BackendError::new)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ec_point_encodings() {
        let point = [0x04; 65];
        let mut der = vec![0x04, 65];
        der.extend_from_slice(&point);
        assert_eq!(unwrap_octet_string(&point, 65).unwrap(), point);
        assert_eq!(unwrap_octet_string(&der, 65).unwrap(), point);
        let ed = [7u8; 32];
        let mut ed_der = vec![0x04, 32];
        ed_der.extend_from_slice(&ed);
        assert_eq!(unwrap_octet_string(&ed_der, 32).unwrap(), ed);
        assert!(unwrap_octet_string(&der[..60], 65).is_err());
        assert!(ec_curve(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]).is_ok());
        assert!(ec_curve(&[0x06, 0x01, 0x00]).is_err());
        assert!(is_ed25519_params(b"\x13\x0cedwards25519"));
        assert_eq!(hex("0a1B").unwrap(), [0x0a, 0x1b]);
        assert!(hex("abc").is_err());
    }

    /// Against a real PKCS#11 module (e.g. SoftHSM), when configured:
    /// `PKCS11_TEST_MODULE`, `PKCS11_TEST_TOKEN`, `SSH_CASIGN_PKCS11_PIN`,
    /// and keys labelled `test-ed25519`, `test-p256`, `test-rsa`.
    #[tokio::test]
    #[ignore = "needs a PKCS#11 module; see the doc comment"]
    async fn issues_with_a_real_token() {
        use crate::{authority::signing, certificate::options::CertificateOptions};
        let module = std::env::var("PKCS11_TEST_MODULE").expect("PKCS11_TEST_MODULE");
        let token = std::env::var("PKCS11_TEST_TOKEN").ok();
        let user = ssh_key::private::Ed25519Keypair::from_seed(&[1; 32]);
        let mut options =
            CertificateOptions::new_user(ssh_key::PublicKey::from(KeyData::Ed25519(user.public)));
        options.add_principal("alice");
        options.set_validity(3600);
        for label in ["test-ed25519", "test-p256", "test-rsa"] {
            let key = Config {
                module: module.clone().into(),
                token_label: token.clone(),
                key_label: Some(label.to_string()),
                key_id: None,
                pin_file: None,
            }
            .load()
            .await
            .unwrap_or_else(|err| panic!("{label}: {err}"));
            assert!(!key.algorithms().is_empty(), "{label}: no algorithms");
            for algorithm in key.algorithms() {
                // signing::issue verifies each signature.
                let signed = signing::issue(&key, &options, algorithm)
                    .await
                    .unwrap_or_else(|err| panic!("{label} {algorithm}: {err}"));
                println!("{label}: {algorithm} ok, {}", &signed.openssh[..40]);
            }
        }
    }
}
