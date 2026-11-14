//! `{{placeholder}}` templates, used for key IDs and principals.
//!
//! | Placeholder      | Value                                                     |
//! |------------------|-----------------------------------------------------------|
//! | `{{server_id}}`  | `server_id` from the service config (default: hostname)  |
//! | `{{profile}}`    | name of the profile that matched                          |
//! | `{{oidc_id}}`    | the token claim named by `oidc_provider.id_claim` (`sub`) |
//! | `{{app_name}}`   | application name sent by the client, or `-`               |
//! | `{{serial}}`     | the certificate's serial number (decimal)                 |
//! | `{{claim:NAME}}` | a claim of the token: string, number, boolean, or a list  |
//!
//! Which placeholders a template may use depends on where it is used; that is
//! checked when the template is parsed.

use std::fmt::Write;

use super::profiles::TokenClaims;

/// Shown for an optional value that is missing.
const MISSING: &str = "-";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Placeholder {
    ServerId,
    Profile,
    OidcId,
    AppName,
    Serial,
    Claim(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Part {
    Literal(String),
    Placeholder(Placeholder),
}

#[derive(Clone, Debug)]
pub(crate) struct Template {
    source: String,
    parts: Vec<Part>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("token has no '{0}' claim")]
    MissingClaim(String),
    #[error("token claim '{0}' is not a string, number or boolean")]
    InvalidClaim(String),
    #[error("token claim '{0}' has several values, but only one can be used here")]
    MultipleValues(String),
}

/// Values available to templates.
pub(crate) struct Context<'a> {
    pub(crate) server_id: &'a str,
    pub(crate) profile: &'a str,
    pub(crate) oidc_id: &'a str,
    pub(crate) app_name: Option<&'a str>,
    pub(crate) serial: Option<u64>,
    pub(crate) claims: &'a TokenClaims,
}

impl Template {
    /// Parse `source`; `allowed` decides which placeholders may be used, and
    /// `what` names the template in error messages.
    pub(crate) fn parse(
        source: &str,
        what: &str,
        allowed: impl Fn(&Placeholder) -> bool,
    ) -> Result<Self, String> {
        let mut parts = Vec::new();
        let mut rest = source;
        while let Some(start) = rest.find("{{") {
            if start > 0 {
                parts.push(Part::Literal(rest[..start].to_string()));
            }
            let after = &rest[start + 2..];
            let end = after
                .find("}}")
                .ok_or_else(|| format!("unclosed '{{{{' in {what} template '{source}'"))?;
            let name = after[..end].trim();
            let placeholder = match name {
                "server_id" => Placeholder::ServerId,
                "profile" => Placeholder::Profile,
                "oidc_id" => Placeholder::OidcId,
                "app_name" => Placeholder::AppName,
                "serial" => Placeholder::Serial,
                _ => match name.strip_prefix("claim:") {
                    Some(claim) if !claim.is_empty() => Placeholder::Claim(claim.to_string()),
                    _ => {
                        return Err(format!(
                            "unknown placeholder '{{{{{name}}}}}' in {what} template '{source}'"
                        ))
                    }
                },
            };
            if !allowed(&placeholder) {
                return Err(format!(
                    "placeholder '{{{{{name}}}}}' can't be used in {what} template '{source}'"
                ));
            }
            parts.push(Part::Placeholder(placeholder));
            rest = &after[end + 2..];
        }
        if !rest.is_empty() {
            parts.push(Part::Literal(rest.to_string()));
        }
        Ok(Self {
            source: source.to_string(),
            parts,
        })
    }

    pub(crate) fn source(&self) -> &str {
        &self.source
    }

    /// Render to exactly one string, percent-encoding substituted values (see
    /// [`escape_into`]). Missing claims and multi-valued claims are errors.
    pub(crate) fn render_escaped(&self, context: &Context<'_>) -> Result<String, Error> {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                Part::Literal(text) => out.push_str(text),
                Part::Placeholder(placeholder) => {
                    let mut values = values(placeholder, context)?;
                    if values.len() != 1 {
                        let Placeholder::Claim(name) = placeholder else {
                            unreachable!("only claims have several values")
                        };
                        return Err(Error::MultipleValues(name.clone()));
                    }
                    escape_into(&mut out, &values.remove(0));
                }
            }
        }
        Ok(out)
    }

    /// Render to every combination of values, substituting them as is. A
    /// list claim gives one result per element; a missing or unusable claim
    /// gives no results at all.
    pub(crate) fn expand(&self, context: &Context<'_>) -> Vec<String> {
        let mut results = vec![String::new()];
        for part in &self.parts {
            match part {
                Part::Literal(text) => results.iter_mut().for_each(|result| result.push_str(text)),
                Part::Placeholder(placeholder) => {
                    let values = match values(placeholder, context) {
                        Ok(values) => values,
                        Err(err) => {
                            tracing::debug!("template '{}' expands to nothing: {err}", self.source);
                            return Vec::new();
                        }
                    };
                    results = results
                        .iter()
                        .flat_map(|result| {
                            values.iter().map(move |value| format!("{result}{value}"))
                        })
                        .collect();
                }
            }
        }
        results
    }
}

fn values(placeholder: &Placeholder, context: &Context<'_>) -> Result<Vec<String>, Error> {
    Ok(match placeholder {
        Placeholder::ServerId => vec![context.server_id.to_string()],
        Placeholder::Profile => vec![context.profile.to_string()],
        Placeholder::OidcId => vec![context.oidc_id.to_string()],
        Placeholder::AppName => vec![context.app_name.unwrap_or(MISSING).to_string()],
        Placeholder::Serial => vec![context
            .serial
            .map_or_else(|| MISSING.to_string(), |serial| serial.to_string())],
        Placeholder::Claim(name) => claim_values(context.claims, name)?,
    })
}

fn scalar(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(_) | serde_json::Value::Bool(_) => Some(value.to_string()),
        _ => None,
    }
}

/// Values of a claim: one for a scalar, one per element for a list.
pub(crate) fn claim_values(claims: &TokenClaims, name: &str) -> Result<Vec<String>, Error> {
    match claims.get(name) {
        None | Some(serde_json::Value::Null) => Err(Error::MissingClaim(name.to_string())),
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .map(|value| scalar(value).ok_or_else(|| Error::InvalidClaim(name.to_string())))
            .collect(),
        Some(value) => scalar(value)
            .map(|value| vec![value])
            .ok_or_else(|| Error::InvalidClaim(name.to_string())),
    }
}

/// Percent-encode `%`, `:`, whitespace, control characters and non-ASCII, so
/// a value can never shift the fields of a template like `a:b:c`.
fn escape_into(out: &mut String, value: &str) {
    for c in value.chars() {
        if c.is_ascii_graphic() && c != '%' && c != ':' {
            out.push(c);
        } else {
            let mut buf = [0; 4];
            for byte in c.encode_utf8(&mut buf).bytes() {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(json: serde_json::Value) -> TokenClaims {
        serde_json::from_value(json).unwrap()
    }

    fn context(claims: &TokenClaims) -> Context<'_> {
        Context {
            server_id: "ca1",
            profile: "ops",
            oidc_id: "alice",
            app_name: None,
            serial: None,
            claims,
        }
    }

    fn template(source: &str) -> Template {
        Template::parse(source, "test", |_| true).unwrap()
    }

    #[test]
    fn expand_fans_out_over_lists() {
        let claims =
            claims(serde_json::json!({ "groups": ["dev", "ops"], "user": "alice", "uid": 1000 }));
        let context = context(&claims);
        assert_eq!(template("{{claim:user}}").expand(&context), ["alice"]);
        assert_eq!(
            template("grp-{{claim:groups}}").expand(&context),
            ["grp-dev", "grp-ops"]
        );
        assert_eq!(
            template("{{claim:user}}@{{claim:groups}}").expand(&context),
            ["alice@dev", "alice@ops"]
        );
        assert_eq!(template("u{{claim:uid}}").expand(&context), ["u1000"]);
        assert_eq!(template("static").expand(&context), ["static"]);
        assert!(template("{{claim:missing}}").expand(&context).is_empty());
        assert_eq!(
            template("{{oidc_id}}-{{profile}}").expand(&context),
            ["alice-ops"]
        );
    }

    #[test]
    fn expand_does_not_escape() {
        let claims = claims(serde_json::json!({ "email": "a:b@example.com" }));
        assert_eq!(
            template("{{claim:email}}").expand(&context(&claims)),
            ["a:b@example.com"]
        );
    }

    #[test]
    fn render_escaped_needs_single_values() {
        let claims = claims(serde_json::json!({ "groups": ["dev", "ops"], "one": ["x"] }));
        let context = context(&claims);
        assert!(matches!(
            template("{{claim:groups}}").render_escaped(&context),
            Err(Error::MultipleValues(_))
        ));
        assert_eq!(
            template("{{claim:one}}").render_escaped(&context).unwrap(),
            "x"
        );
        assert!(matches!(
            template("{{claim:nope}}").render_escaped(&context),
            Err(Error::MissingClaim(_))
        ));
    }

    #[test]
    fn placeholders_can_be_restricted() {
        let no_app_name = |p: &Placeholder| *p != Placeholder::AppName;
        assert!(Template::parse("{{app_name}}", "test", no_app_name).is_err());
        assert!(Template::parse("{{claim:x}}", "test", no_app_name).is_ok());
    }
}
