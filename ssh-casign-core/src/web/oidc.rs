//! Token validation: the interactive sign-in provider (`[oidc_provider]`,
//! published in the discovery document) and further trusted issuers
//! (`[issuers.<name>]`) for machine identities: OIDC client credentials,
//! GitHub Actions, Google and Azure workload identity, Kubernetes service
//! accounts, ...
//!
//! A token is routed by its (not yet verified) `iss` claim to the issuer
//! configurations with that issuer, and accepted by the first one whose
//! validation (signature, `exp`, `nbf`, `iss`, `aud`) succeeds.

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    RequestPartsExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use oidc_jwt_validator::Validator;
use serde::Deserialize;

use super::state::AppState;
use crate::certificate::profiles::TokenClaims;

/// Name under which profile selectors refer to `[oidc_provider]`; it is
/// also what selectors without `issuer` mean.
pub(crate) const PRIMARY_ISSUER: &str = "oidc_provider";

fn default_scopes() -> Vec<String> {
    vec!["openid".to_string()]
}

fn default_id_claim() -> String {
    "sub".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// OpenID Connect issuer. Must match the `iss` claim of the tokens exactly.
    #[serde(alias = "url")]
    issuer: String,
    /// OAuth client ID that clients authenticate as. Published through the
    /// discovery document.
    client_id: String,
    /// Scopes clients should request. Published through the discovery document.
    #[serde(default = "default_scopes")]
    scopes: Vec<String>,
    /// Accepted values of the `aud` claim. Defaults to `[client_id]`, which is
    /// what ID tokens carry.
    audience: Option<Vec<String>>,
    /// Claim that identifies the user or client in the key ID (`{{oidc_id}}`).
    /// It must be unique and traceable by the IdP maintainer: `sub` (default),
    /// a UPN, a UUID or a pseudonymous ID.
    #[serde(default = "default_id_claim")]
    id_claim: String,
    /// Read certificate defaults and limits from the token's claims
    /// (`max_validity`, `allowed_principals`, ...). Default true: the IdP is
    /// the organisation's own.
    #[serde(default = "default_true")]
    token_policy: bool,
}

/// A further trusted issuer, `[issuers.<name>]`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IssuerConfig {
    /// Must match the `iss` claim exactly; `<issuer>/.well-known/openid-configuration`
    /// must be reachable (for the signing keys).
    issuer: String,
    /// Accepted values of the `aud` claim. Required: machine tokens are
    /// requested for an audience, and a token for another service must not
    /// work here.
    audience: Vec<String>,
    /// Claim that identifies the machine or workload (`{{oidc_id}}`).
    #[serde(default = "default_id_claim")]
    id_claim: String,
    /// Read certificate defaults and limits from the token's claims. Default
    /// false: tokens of third parties (GitHub, Google, ...) carry claims this
    /// service shouldn't take as policy.
    #[serde(default)]
    token_policy: bool,
}

impl Config {
    pub(crate) fn issuer(&self) -> &str {
        &self.issuer
    }

    pub(crate) fn client_id(&self) -> &str {
        &self.client_id
    }

    pub(crate) fn scopes(&self) -> &[String] {
        &self.scopes
    }
}

/// An issuer whose tokens are accepted.
pub(crate) struct TrustedIssuer {
    /// `oidc_provider`, or the name in `[issuers.<name>]`.
    pub(crate) name: String,
    /// The issuer URL (`iss`).
    pub(crate) issuer: String,
    pub(crate) id_claim: String,
    pub(crate) token_policy: bool,
    validator: Validator,
}

async fn validator(issuer: &str, audience: &[String]) -> Result<Validator, String> {
    let http_client = reqwest::ClientBuilder::new()
        .build()
        .map_err(|err| err.to_string())?;
    let mut validation_settings = oidc_jwt_validator::ValidationSettings::new();
    // Without listing them as required, `iss` and `aud` are only checked
    // when the token happens to contain them.
    validation_settings.set_required_spec_claims(&["exp", "iss", "aud"]);
    validation_settings.validate_nbf = true;
    validation_settings.set_issuer(&[issuer]);
    validation_settings.set_audience(audience);
    Validator::new(
        issuer,
        http_client,
        oidc_jwt_validator::cache::Strategy::Automatic,
        validation_settings,
    )
    .await
    .map_err(|err| format!("OpenID Connect provider {issuer}: {err}"))
}

/// All trusted issuers, `[oidc_provider]` first.
pub(crate) struct Issuers(Vec<TrustedIssuer>);

impl Issuers {
    pub(crate) async fn load(
        primary: &Config,
        extra: &BTreeMap<String, IssuerConfig>,
    ) -> Result<Self, String> {
        let audience = primary
            .audience
            .clone()
            .unwrap_or_else(|| vec![primary.client_id.clone()]);
        let mut issuers = vec![TrustedIssuer {
            name: PRIMARY_ISSUER.to_string(),
            issuer: primary.issuer.clone(),
            id_claim: primary.id_claim.clone(),
            token_policy: primary.token_policy,
            validator: validator(&primary.issuer, &audience).await?,
        }];
        for (name, config) in extra {
            if name == PRIMARY_ISSUER {
                return Err(format!(
                    "issuers.{name}: the name is reserved for [oidc_provider]"
                ));
            }
            if config.audience.is_empty() {
                return Err(format!("issuers.{name}: audience must not be empty"));
            }
            tracing::info!("trusting issuer {name} ({})", config.issuer);
            issuers.push(TrustedIssuer {
                name: name.clone(),
                issuer: config.issuer.clone(),
                id_claim: config.id_claim.clone(),
                token_policy: config.token_policy,
                validator: validator(&config.issuer, &config.audience)
                    .await
                    .map_err(|err| format!("issuers.{name}: {err}"))?,
            });
        }
        Ok(Self(issuers))
    }

    pub(crate) fn contains(&self, name: &str) -> bool {
        self.0.iter().any(|issuer| issuer.name == name)
    }

    /// Validate `token` with the issuer configurations for its `iss`.
    async fn validate(&self, token: &str) -> Result<(&TrustedIssuer, TokenClaims), String> {
        let iss = unverified_issuer(token)?;
        let mut last_error = None;
        for issuer in self.0.iter().filter(|issuer| issuer.issuer == iss) {
            match issuer.validator.validate::<TokenClaims>(token).await {
                Ok(data) => return Ok((issuer, data.claims)),
                Err(err) => last_error = Some(err.to_string()),
            }
        }
        Err(last_error.unwrap_or_else(|| format!("issuer {iss} is not trusted")))
    }
}

/// The `iss` claim of a JWT, before the signature is checked: only used to
/// pick the validator.
fn unverified_issuer(token: &str) -> Result<String, String> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| "not a JWT".to_string())?;
    let payload = Base64UrlUnpadded::decode_vec(payload.trim_end_matches('='))
        .map_err(|_| "not a JWT".to_string())?;
    #[derive(Deserialize)]
    struct Issuer {
        iss: String,
    }
    serde_json::from_slice::<Issuer>(&payload)
        .map(|claims| claims.iss)
        .map_err(|_| "token has no issuer".to_string())
}

/// A validated token: its issuer and claims.
pub(super) struct Authenticated {
    pub(super) issuer: IssuerRef,
    pub(super) claims: TokenClaims,
}

/// The parts of the [`TrustedIssuer`] a request needs.
pub(super) struct IssuerRef {
    pub(super) name: String,
    pub(super) issuer: String,
    pub(super) id_claim: String,
    pub(super) token_policy: bool,
}

pub(super) enum AuthError {
    InvalidToken(String),
}

/// Make `value` safe to use inside a quoted-string header parameter.
fn quote_header_param(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .flat_map(|c| match c {
            '"' | '\\' => vec!['\\', c],
            c => vec![c],
        })
        .collect()
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        match self {
            AuthError::InvalidToken(msg) => {
                tracing::info!("rejected token: {msg}");
                let challenge = format!(
                    r#"Bearer realm="ssh-casign", error="invalid_token", error_description="{}""#,
                    quote_header_param(&msg)
                );
                let challenge = HeaderValue::from_str(&challenge).unwrap_or_else(|_| {
                    HeaderValue::from_static(r#"Bearer realm="ssh-casign", error="invalid_token""#)
                });
                (
                    StatusCode::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, challenge)],
                )
                    .into_response()
            }
        }
    }
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for Authenticated
where
    Arc<AppState>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|err| AuthError::InvalidToken(err.to_string()))?;
        let state = Arc::<AppState>::from_ref(state);
        let (issuer, claims) = state
            .issuers
            .validate(bearer.token())
            .await
            .map_err(AuthError::InvalidToken)?;
        Ok(Authenticated {
            issuer: IssuerRef {
                name: issuer.name.clone(),
                issuer: issuer.issuer.clone(),
                id_claim: issuer.id_claim.clone(),
                token_policy: issuer.token_policy,
            },
            claims,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(payload: &str) -> String {
        format!(
            "{}.{}.sig",
            Base64UrlUnpadded::encode_string(br#"{"alg":"RS256"}"#),
            Base64UrlUnpadded::encode_string(payload.as_bytes())
        )
    }

    #[test]
    fn issuer_is_read_for_routing() {
        assert_eq!(
            unverified_issuer(&jwt(
                r#"{"iss":"https://token.actions.githubusercontent.com"}"#
            ))
            .unwrap(),
            "https://token.actions.githubusercontent.com"
        );
        assert!(unverified_issuer(&jwt(r#"{"sub":"x"}"#)).is_err());
        assert!(unverified_issuer("opaque-access-token").is_err());
        assert!(unverified_issuer("a.!!!.c").is_err());
    }
}
