//! Certificate key ID templates.
//!
//! The key ID ends up in `sshd`'s logs, so it records where a certificate came
//! from. The default template combines everything needed for an audit trail:
//!
//! ```text
//! {{server_id}}:{{profile}}:{{oidc_id}}:{{app_name}}
//! ```
//!
//! All placeholders of [`super::template`] can be used. Substituted values are
//! percent-encoded for `%`, `:`, whitespace, control characters and non-ASCII,
//! so a value can never shift the fields of the template. Literal text in the
//! template is used as is. Claims must be present and single-valued.

use serde::{Deserialize, Deserializer};

use super::{
    profiles::TokenClaims,
    template::{self, Context, Template},
};

pub(crate) const DEFAULT_TEMPLATE: &str = "{{server_id}}:{{profile}}:{{oidc_id}}:{{app_name}}";

#[derive(Clone, Debug)]
pub(crate) struct KeyIdTemplate(Template);

impl KeyIdTemplate {
    pub(crate) fn parse(source: &str) -> Result<Self, String> {
        Template::parse(source, "key ID", |_| true).map(Self)
    }

    pub(crate) fn render(&self, context: &Context<'_>) -> Result<String, Error> {
        self.0.render_escaped(context).map_err(Error)
    }
}

impl Default for KeyIdTemplate {
    fn default() -> Self {
        Self::parse(DEFAULT_TEMPLATE).expect("default key ID template is valid")
    }
}

impl<'de> Deserialize<'de> for KeyIdTemplate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let source = String::deserialize(deserializer)?;
        Self::parse(&source).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("can't build the key ID: {0}")]
pub(crate) struct Error(template::Error);

/// The identity the IdP determined, from the configured `id_claim`.
///
/// It must identify the user or client uniquely, and the IdP maintainer must
/// be able to trace it back: `sub`, a UPN, a UUID or a pseudonymous ID. An
/// empty value is treated as missing, so no certificate is issued without one.
pub(crate) fn oidc_id(claims: &TokenClaims, id_claim: &str) -> Result<String, Error> {
    let mut values = template::claim_values(claims, id_claim).map_err(Error)?;
    match values.len() {
        1 if !values[0].is_empty() => Ok(values.remove(0)),
        1 | 0 => Err(Error(template::Error::MissingClaim(id_claim.to_string()))),
        _ => Err(Error(template::Error::MultipleValues(id_claim.to_string()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(json: serde_json::Value) -> TokenClaims {
        serde_json::from_value(json).unwrap()
    }

    fn render(
        template: &str,
        claims: &TokenClaims,
        app_name: Option<&str>,
    ) -> Result<String, Error> {
        KeyIdTemplate::parse(template).unwrap().render(&Context {
            server_id: "ca1",
            profile: "ops",
            oidc_id: "alice",
            app_name,
            serial: Some(42),
            claims,
        })
    }

    #[test]
    fn default_template() {
        let claims = claims(serde_json::json!({}));
        assert_eq!(
            render(DEFAULT_TEMPLATE, &claims, Some("ansible")).unwrap(),
            "ca1:ops:alice:ansible"
        );
        assert_eq!(
            render(DEFAULT_TEMPLATE, &claims, None).unwrap(),
            "ca1:ops:alice:-"
        );
    }

    #[test]
    fn claims_serial_and_literals() {
        let claims = claims(
            serde_json::json!({ "email": "a@example.com", "uid": 1000, "groups": ["x", "y"] }),
        );
        assert_eq!(
            render("user={{claim:email}} uid={{ claim:uid }}", &claims, None).unwrap(),
            "user=a@example.com uid=1000"
        );
        assert_eq!(
            render("{{oidc_id}}#{{serial}}", &claims, None).unwrap(),
            "alice#42"
        );
        assert!(render("{{claim:nope}}", &claims, None).is_err());
        assert!(render("{{claim:groups}}", &claims, None).is_err());
    }

    #[test]
    fn values_are_escaped() {
        let claims = claims(serde_json::json!({ "sub": "auth0|a:b 100%", "name": "Zoë" }));
        assert_eq!(
            render("{{claim:sub}}/{{claim:name}}", &claims, None).unwrap(),
            "auth0|a%3Ab%20100%25/Zo%C3%AB"
        );
        assert_eq!(
            render("{{app_name}}", &claims, Some("a:b")).unwrap(),
            "a%3Ab"
        );
    }

    #[test]
    fn invalid_templates() {
        assert!(KeyIdTemplate::parse("{{server_id}").is_err());
        assert!(KeyIdTemplate::parse("{{bogus}}").is_err());
        assert!(KeyIdTemplate::parse("{{claim:}}").is_err());
        assert!(KeyIdTemplate::parse("static").is_ok());
    }

    #[test]
    fn oidc_id_from_configured_claim() {
        let claims = claims(
            serde_json::json!({ "sub": "123", "upn": "a@example.com", "empty": "", "many": ["a", "b"] }),
        );
        assert_eq!(oidc_id(&claims, "sub").unwrap(), "123");
        assert_eq!(oidc_id(&claims, "upn").unwrap(), "a@example.com");
        assert!(oidc_id(&claims, "nope").is_err());
        assert!(oidc_id(&claims, "empty").is_err());
        assert!(oidc_id(&claims, "many").is_err());
    }
}
