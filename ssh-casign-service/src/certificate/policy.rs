//! Certificate defaults and limits.
//!
//! Every certificate value is resolved from up to three sources:
//!
//! - **Defaults**: the value the client requested, otherwise the token's value,
//!   otherwise the profile's value (client → token → profile).
//! - **Limits**: the token and the profile can both restrict values. Both sets
//!   of limits apply, so the allowed values are those allowed by both:
//!   - `min_*` / `max_*` for ranges (validity),
//!   - `required_*` / `allowed_*` for sets (principals, extensions, critical
//!     options),
//!   - `matching_*` for anchored regular expressions on text values.
//!
//! A value the client requested explicitly must satisfy the limits, or the
//! request is rejected. A default is fitted to the limits where possible
//! (ranges are clamped, disallowed set members are dropped); text defaults
//! that violate a limit are an error. Required values are always added.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer};
use ssh_key::{certificate::CertType, PublicKey};

use super::options::CertificateOptions;

/// Extensions `ssh-keygen -s` adds to user certificates by default. Used as
/// the last-resort default when no source specifies extensions.
pub(crate) const DEFAULT_USER_EXTENSIONS: &[&str] = &[
    "permit-X11-forwarding",
    "permit-agent-forwarding",
    "permit-port-forwarding",
    "permit-pty",
    "permit-user-rc",
];

/// Built-in limit on the client's application name.
pub(crate) const MAX_APP_NAME_LEN: usize = 64;

/// Anchored regular expression: the whole value must match.
#[derive(Clone, Debug)]
pub(crate) struct Pattern {
    source: String,
    regex: regex::Regex,
}

impl Pattern {
    pub(crate) fn new(source: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            source: source.to_string(),
            regex: regex::Regex::new(&format!("^(?:{source})$"))?,
        })
    }

    fn is_match(&self, value: &str) -> bool {
        self.regex.is_match(value)
    }
}

impl<'de> Deserialize<'de> for Pattern {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let source = String::deserialize(deserializer)?;
        Pattern::new(&source).map_err(serde::de::Error::custom)
    }
}

/// Defaults and limits from one source (the token's claims or a profile).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct Policy {
    /// Default validity in seconds.
    pub(crate) validity: Option<u64>,
    pub(crate) min_validity: Option<u64>,
    pub(crate) max_validity: Option<u64>,

    /// Default principals.
    #[serde(alias = "valid_principals")]
    pub(crate) principals: Option<Vec<String>>,
    pub(crate) required_principals: Option<Vec<String>>,
    pub(crate) allowed_principals: Option<Vec<String>>,
    pub(crate) matching_principals: Option<Pattern>,

    /// Default extensions (name → value, usually empty).
    pub(crate) extensions: Option<BTreeMap<String, String>>,
    pub(crate) required_extensions: Option<Vec<String>>,
    pub(crate) allowed_extensions: Option<Vec<String>>,
    /// Pattern extension names must match.
    pub(crate) matching_extensions: Option<Pattern>,

    /// Default critical options (name → value).
    pub(crate) critical_options: Option<BTreeMap<String, String>>,
    /// Critical options that are always set, with these exact values.
    pub(crate) required_critical_options: Option<BTreeMap<String, String>>,
    pub(crate) allowed_critical_options: Option<Vec<String>>,
    /// Per critical option, the pattern its value must match.
    pub(crate) matching_critical_options: Option<BTreeMap<String, Pattern>>,

    /// Pattern the client's application name must match. (The key ID itself
    /// is built from the profile's `key_id` template.)
    pub(crate) matching_app_name: Option<Pattern>,

    /// Default comment.
    pub(crate) comment: Option<String>,
    pub(crate) matching_comment: Option<Pattern>,
}

/// Values the client requested explicitly.
#[derive(Debug, Default)]
pub(crate) struct Request {
    pub(crate) validity: Option<u64>,
    pub(crate) principals: Option<Vec<String>>,
    pub(crate) extensions: Option<BTreeMap<String, String>>,
    pub(crate) critical_options: Option<BTreeMap<String, String>>,
    /// Client-chosen name of the workload (ssh, ansible, ...); part of the key ID.
    pub(crate) app_name: Option<String>,
    pub(crate) comment: Option<String>,
}

/// Certificate values after applying defaults and limits.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Resolved {
    pub(crate) validity: u64,
    pub(crate) principals: Vec<String>,
    pub(crate) extensions: BTreeMap<String, String>,
    pub(crate) critical_options: BTreeMap<String, String>,
    pub(crate) app_name: Option<String>,
    pub(crate) comment: Option<String>,
}

impl Resolved {
    pub(crate) fn into_options(
        self,
        public_key: PublicKey,
        cert_type: CertType,
        serial: u64,
        key_id: String,
    ) -> CertificateOptions {
        let mut options = CertificateOptions::new(public_key, cert_type);
        options.set_serial(serial);
        options.set_key_id(key_id);
        options.set_validity(self.validity);
        for principal in self.principals {
            options.add_principal(principal);
        }
        for (name, value) in self.extensions {
            options.set_extension(name, value);
        }
        for (name, value) in self.critical_options {
            options.set_critical_option(name, value);
        }
        if let Some(comment) = self.comment {
            options.set_comment(comment);
        }
        options
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// The client requested something the limits don't allow.
    #[error("{0}")]
    Rejected(String),
    /// The limits or defaults contradict each other; the client can't fix
    /// this by requesting something else.
    #[error("{0}")]
    Conflict(String),
    #[error("no principals for this certificate")]
    NoPrincipals,
    #[error("no validity configured")]
    NoValidity,
}

/// Where a value came from, for resolving and for error messages.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Origin {
    Requested,
    Default,
    Required,
}

/// The two sources of defaults and limits.
pub(crate) struct Policies<'a> {
    pub(crate) token: &'a Policy,
    pub(crate) profile: &'a Policy,
}

impl<'a> Policies<'a> {
    /// Each source with a name for error messages.
    fn sources(&self) -> [(&'static str, &'a Policy); 2] {
        [("token", self.token), ("profile", self.profile)]
    }

    pub(crate) fn resolve(
        &self,
        request: &Request,
        cert_type: CertType,
    ) -> Result<Resolved, Error> {
        let validity = self.resolve_validity(request.validity)?;

        let principals = self.resolve_principals(request.principals.as_ref())?;

        let default_extensions = self
            .token
            .extensions
            .clone()
            .or_else(|| self.profile.extensions.clone())
            .or_else(|| {
                (cert_type == CertType::User).then(|| {
                    DEFAULT_USER_EXTENSIONS
                        .iter()
                        .map(|name| (name.to_string(), String::new()))
                        .collect()
                })
            });
        let extensions = self.resolve_entries(
            "extension",
            request.extensions.as_ref(),
            default_extensions.as_ref(),
            |policy| names_to_entries(policy.required_extensions.as_ref()),
            |name, _| self.check_extension(name),
        )?;

        let default_critical_options = self
            .token
            .critical_options
            .as_ref()
            .or(self.profile.critical_options.as_ref());
        let critical_options = self.resolve_entries(
            "critical option",
            request.critical_options.as_ref(),
            default_critical_options,
            |policy| policy.required_critical_options.clone().unwrap_or_default(),
            |name, value| self.check_critical_option(name, value),
        )?;

        let app_name = self.resolve_text(
            "application name",
            "matching_app_name",
            request.app_name.as_ref(),
            None,
            |policy| policy.matching_app_name.as_ref(),
        )?;
        if let Some(app_name) = &app_name {
            if app_name.chars().count() > MAX_APP_NAME_LEN {
                return Err(Error::Rejected(format!(
                    "application name is longer than {MAX_APP_NAME_LEN} characters"
                )));
            }
        }
        let comment = self.resolve_text(
            "comment",
            "matching_comment",
            request.comment.as_ref(),
            self.token
                .comment
                .as_ref()
                .or(self.profile.comment.as_ref()),
            |policy| policy.matching_comment.as_ref(),
        )?;

        Ok(Resolved {
            validity,
            principals,
            extensions,
            critical_options,
            app_name,
            comment,
        })
    }

    fn resolve_validity(&self, requested: Option<u64>) -> Result<u64, Error> {
        let mut min = (1, None);
        let mut max = (u64::MAX, None);
        for (source, policy) in self.sources() {
            if let Some(value) = policy.min_validity.filter(|value| *value > min.0) {
                min = (value, Some(source));
            }
            if let Some(value) = policy.max_validity.filter(|value| *value < max.0) {
                max = (value, Some(source));
            }
        }
        let describe = |limit: &str, (value, source): (u64, Option<&str>)| match source {
            Some(source) => format!("{limit} {value}s of the {source}"),
            None => format!("the minimum of {value}s"),
        };
        if min.0 > max.0 {
            return Err(Error::Conflict(format!(
                "{} exceeds {}",
                describe("min_validity", min),
                describe("max_validity", max)
            )));
        }
        if let Some(value) = requested {
            if value < min.0 {
                return Err(Error::Rejected(format!(
                    "requested validity {value}s is below {}",
                    describe("min_validity", min)
                )));
            }
            if value > max.0 {
                return Err(Error::Rejected(format!(
                    "requested validity {value}s exceeds {}",
                    describe("max_validity", max)
                )));
            }
            return Ok(value);
        }
        let default = self
            .token
            .validity
            .or(self.profile.validity)
            .ok_or(Error::NoValidity)?;
        Ok(default.clamp(min.0, max.0))
    }

    fn resolve_principals(&self, requested: Option<&Vec<String>>) -> Result<Vec<String>, Error> {
        // Fail closed: without any principal limits, the defaults are the only
        // thing standing between a client and e.g. `root`.
        let limited = self.sources().iter().any(|(_, policy)| {
            policy.allowed_principals.is_some() || policy.matching_principals.is_some()
        });
        if requested.is_some() && !limited {
            return Err(Error::Rejected(
                "requesting principals requires allowed_principals or matching_principals \
                 in the token or profile"
                    .to_string(),
            ));
        }
        let requested = requested.map(|names| names_to_entries(Some(names)));
        let default = self
            .token
            .principals
            .as_ref()
            .or(self.profile.principals.as_ref())
            .map(|names| names_to_entries(Some(names)));
        let principals = self.resolve_entries(
            "principal",
            requested.as_ref(),
            default.as_ref(),
            |policy| names_to_entries(policy.required_principals.as_ref()),
            |name, _| self.check_principal(name),
        )?;
        if principals.is_empty() {
            return Err(Error::NoPrincipals);
        }
        Ok(principals.into_keys().collect())
    }

    /// Resolve a set of named entries (principals use empty values).
    ///
    /// Base is the request or else the default; requested entries must pass
    /// `check`, default entries that don't are dropped. Then the required
    /// entries of both sources are added; they must pass `check` too and
    /// override default entries with the same name.
    fn resolve_entries(
        &self,
        kind: &str,
        requested: Option<&BTreeMap<String, String>>,
        default: Option<&BTreeMap<String, String>>,
        required: impl Fn(&Policy) -> BTreeMap<String, String>,
        check: impl Fn(&str, &str) -> Result<(), String>,
    ) -> Result<BTreeMap<String, String>, Error> {
        let mut entries: BTreeMap<String, (String, Origin)> = BTreeMap::new();
        if let Some(requested) = requested {
            for (name, value) in requested {
                check(name, value).map_err(Error::Rejected)?;
                entries.insert(name.clone(), (value.clone(), Origin::Requested));
            }
        } else if let Some(default) = default {
            for (name, value) in default {
                match check(name, value) {
                    Ok(()) => {
                        entries.insert(name.clone(), (value.clone(), Origin::Default));
                    }
                    Err(reason) => tracing::debug!("dropping default {kind}: {reason}"),
                }
            }
        }
        for (source, policy) in self.sources() {
            for (name, value) in required(policy) {
                check(&name, &value).map_err(|reason| {
                    Error::Conflict(format!("required {kind} of the {source}: {reason}"))
                })?;
                match entries.get(&name) {
                    Some((existing, origin)) if *existing != value => {
                        let message = format!(
                            "{kind} {name}: value '{existing}' conflicts with required value \
                             '{value}' of the {source}"
                        );
                        match origin {
                            Origin::Requested => return Err(Error::Rejected(message)),
                            Origin::Required => return Err(Error::Conflict(message)),
                            Origin::Default => {}
                        }
                    }
                    _ => {}
                }
                entries.insert(name, (value, Origin::Required));
            }
        }
        Ok(entries
            .into_iter()
            .map(|(name, (value, _))| (name, value))
            .collect())
    }

    fn resolve_text(
        &self,
        kind: &str,
        limit: &str,
        requested: Option<&String>,
        default: Option<&String>,
        matching: impl Fn(&Policy) -> Option<&Pattern>,
    ) -> Result<Option<String>, Error> {
        let (value, origin) = match (requested, default) {
            (Some(value), _) => (value, Origin::Requested),
            (None, Some(value)) => (value, Origin::Default),
            (None, None) => return Ok(None),
        };
        for (source, policy) in self.sources() {
            if let Some(pattern) = matching(policy) {
                if !pattern.is_match(value) {
                    let message = format!(
                        "{kind} '{value}' does not match {limit} '{}' of the {source}",
                        pattern.source
                    );
                    return Err(match origin {
                        Origin::Requested => Error::Rejected(message),
                        _ => Error::Conflict(message),
                    });
                }
            }
        }
        Ok(Some(value.clone()))
    }

    fn check_principal(&self, principal: &str) -> Result<(), String> {
        for (source, policy) in self.sources() {
            check_allowed(
                "principal",
                principal,
                "allowed_principals",
                policy.allowed_principals.as_ref(),
                source,
            )?;
            check_matching(
                "principal",
                principal,
                "matching_principals",
                policy.matching_principals.as_ref(),
                source,
            )?;
        }
        Ok(())
    }

    fn check_extension(&self, name: &str) -> Result<(), String> {
        for (source, policy) in self.sources() {
            check_allowed(
                "extension",
                name,
                "allowed_extensions",
                policy.allowed_extensions.as_ref(),
                source,
            )?;
            check_matching(
                "extension",
                name,
                "matching_extensions",
                policy.matching_extensions.as_ref(),
                source,
            )?;
        }
        Ok(())
    }

    fn check_critical_option(&self, name: &str, value: &str) -> Result<(), String> {
        for (source, policy) in self.sources() {
            check_allowed(
                "critical option",
                name,
                "allowed_critical_options",
                policy.allowed_critical_options.as_ref(),
                source,
            )?;
            let pattern = policy
                .matching_critical_options
                .as_ref()
                .and_then(|patterns| patterns.get(name));
            check_matching(
                &format!("critical option {name} value"),
                value,
                "matching_critical_options",
                pattern,
                source,
            )?;
        }
        Ok(())
    }
}

fn names_to_entries(names: Option<&Vec<String>>) -> BTreeMap<String, String> {
    names
        .into_iter()
        .flatten()
        .map(|name| (name.clone(), String::new()))
        .collect()
}

fn check_allowed(
    kind: &str,
    value: &str,
    limit: &str,
    allowed: Option<&Vec<String>>,
    source: &str,
) -> Result<(), String> {
    match allowed {
        Some(allowed) if !allowed.iter().any(|allowed| allowed == value) => Err(format!(
            "{kind} '{value}' is not in {limit} of the {source}"
        )),
        _ => Ok(()),
    }
}

fn check_matching(
    kind: &str,
    value: &str,
    limit: &str,
    pattern: Option<&Pattern>,
    source: &str,
) -> Result<(), String> {
    match pattern {
        Some(pattern) if !pattern.is_match(value) => Err(format!(
            "{kind} '{value}' does not match {limit} '{}' of the {source}",
            pattern.source
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(json: serde_json::Value) -> Policy {
        serde_json::from_value(json).unwrap()
    }

    fn resolve(
        token: serde_json::Value,
        profile: serde_json::Value,
        request: Request,
    ) -> Result<Resolved, Error> {
        Policies {
            token: &policy(token),
            profile: &policy(profile),
        }
        .resolve(&request, CertType::User)
    }

    fn request_validity(validity: u64) -> Request {
        Request {
            validity: Some(validity),
            ..Default::default()
        }
    }

    fn base() -> serde_json::Value {
        serde_json::json!({ "principals": ["alice"], "validity": 300 })
    }

    // --- defaults: client → token → profile

    #[test]
    fn validity_defaults_in_order() {
        let profile = serde_json::json!({ "validity": 300 });
        let token = serde_json::json!({ "principals": ["alice"], "validity": 600 });
        let token_without = serde_json::json!({ "principals": ["alice"] });
        assert_eq!(
            resolve(token.clone(), profile.clone(), request_validity(60))
                .unwrap()
                .validity,
            60
        );
        assert_eq!(
            resolve(token, profile.clone(), Request::default())
                .unwrap()
                .validity,
            600
        );
        assert_eq!(
            resolve(token_without, profile, Request::default())
                .unwrap()
                .validity,
            300
        );
    }

    #[test]
    fn no_validity_anywhere_is_an_error() {
        let token = serde_json::json!({ "principals": ["alice"] });
        assert!(matches!(
            resolve(token, serde_json::json!({}), Request::default()),
            Err(Error::NoValidity)
        ));
    }

    #[test]
    fn valid_principals_claim_is_accepted() {
        let token = serde_json::json!({ "valid_principals": ["alice"], "validity": 60 });
        let resolved = resolve(token, serde_json::json!({}), Request::default()).unwrap();
        assert_eq!(resolved.principals, ["alice"]);
    }

    #[test]
    fn text_defaults_in_order() {
        let token =
            serde_json::json!({ "principals": ["a"], "validity": 1, "comment": "token comment" });
        let profile = serde_json::json!({ "comment": "profile comment" });
        let resolved = resolve(token, profile.clone(), Request::default()).unwrap();
        assert_eq!(resolved.comment.as_deref(), Some("token comment"));
        let resolved = resolve(base(), profile, Request::default()).unwrap();
        assert_eq!(resolved.comment.as_deref(), Some("profile comment"));
    }

    #[test]
    fn user_certificates_get_default_extensions() {
        let resolved = resolve(base(), serde_json::json!({}), Request::default()).unwrap();
        assert_eq!(
            resolved
                .extensions
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            DEFAULT_USER_EXTENSIONS
        );
    }

    // --- ranges

    #[test]
    fn requested_validity_must_be_within_both_limits() {
        let token = serde_json::json!({ "principals": ["alice"], "max_validity": 3600 });
        let profile =
            serde_json::json!({ "validity": 300, "min_validity": 60, "max_validity": 7200 });
        assert_eq!(
            resolve(token.clone(), profile.clone(), request_validity(3600))
                .unwrap()
                .validity,
            3600
        );
        let err = resolve(token.clone(), profile.clone(), request_validity(7200)).unwrap_err();
        assert!(
            matches!(&err, Error::Rejected(msg) if msg.contains("max_validity 3600s of the token")),
            "{err}"
        );
        let err = resolve(token, profile, request_validity(30)).unwrap_err();
        assert!(
            matches!(&err, Error::Rejected(msg) if msg.contains("min_validity 60s of the profile")),
            "{err}"
        );
    }

    #[test]
    fn default_validity_is_clamped() {
        let token = serde_json::json!({ "principals": ["alice"], "max_validity": 600 });
        let profile = serde_json::json!({ "validity": 86400 });
        assert_eq!(
            resolve(token, profile, Request::default())
                .unwrap()
                .validity,
            600
        );
    }

    #[test]
    fn contradicting_validity_limits_conflict() {
        let token = serde_json::json!({ "principals": ["alice"], "max_validity": 60 });
        let profile = serde_json::json!({ "validity": 300, "min_validity": 120 });
        assert!(matches!(
            resolve(token, profile, Request::default()),
            Err(Error::Conflict(_))
        ));
    }

    #[test]
    fn zero_validity_is_rejected() {
        assert!(matches!(
            resolve(base(), serde_json::json!({}), request_validity(0)),
            Err(Error::Rejected(_))
        ));
    }

    // --- sets

    #[test]
    fn requesting_principals_without_limits_is_rejected() {
        let request = Request {
            principals: Some(vec!["root".into()]),
            ..Default::default()
        };
        assert!(matches!(
            resolve(base(), serde_json::json!({}), request),
            Err(Error::Rejected(_))
        ));
    }

    #[test]
    fn requested_principals_must_be_allowed_by_both() {
        let token = serde_json::json!({ "principals": ["alice"], "allowed_principals": ["alice", "deploy", "root"] });
        let profile = serde_json::json!({ "validity": 60, "matching_principals": "[a-z]+" });
        let request = |principals: &[&str]| Request {
            principals: Some(principals.iter().map(|p| p.to_string()).collect()),
            ..Default::default()
        };
        let resolved = resolve(token.clone(), profile.clone(), request(&["deploy"])).unwrap();
        assert_eq!(resolved.principals, ["deploy"]);
        let err = resolve(token.clone(), profile.clone(), request(&["bob"])).unwrap_err();
        assert!(
            err.to_string().contains("allowed_principals of the token"),
            "{err}"
        );

        let profile = serde_json::json!({ "validity": 60, "matching_principals": "[a-z]+", "allowed_principals": ["alice", "deploy"] });
        let err = resolve(token, profile, request(&["root"])).unwrap_err();
        assert!(
            err.to_string()
                .contains("allowed_principals of the profile"),
            "{err}"
        );
    }

    #[test]
    fn matching_is_anchored() {
        let token = serde_json::json!({ "principals": ["alice"], "matching_principals": "ali" });
        assert!(matches!(
            resolve(
                token,
                serde_json::json!({ "validity": 60 }),
                Request::default()
            ),
            Err(Error::NoPrincipals)
        ));
    }

    #[test]
    fn disallowed_default_principals_are_dropped() {
        let token = serde_json::json!({ "principals": ["alice", "root"], "validity": 60 });
        let profile = serde_json::json!({ "matching_principals": "[a-z]+", "allowed_principals": ["alice", "bob"] });
        assert_eq!(
            resolve(token, profile, Request::default())
                .unwrap()
                .principals,
            ["alice"]
        );
    }

    #[test]
    fn required_principals_are_added() {
        let token = serde_json::json!({ "principals": ["alice"], "validity": 60 });
        let profile = serde_json::json!({ "required_principals": ["everyone"] });
        assert_eq!(
            resolve(token, profile, Request::default())
                .unwrap()
                .principals,
            ["alice", "everyone"]
        );
    }

    #[test]
    fn required_but_disallowed_principal_conflicts() {
        let token = serde_json::json!({ "principals": ["alice"], "validity": 60, "allowed_principals": ["alice"] });
        let profile = serde_json::json!({ "required_principals": ["everyone"] });
        assert!(matches!(
            resolve(token, profile, Request::default()),
            Err(Error::Conflict(_))
        ));
    }

    #[test]
    fn default_extensions_are_filtered_and_requested_ones_checked() {
        let token = serde_json::json!({ "principals": ["alice"], "validity": 60, "allowed_extensions": ["permit-pty", "permit-port-forwarding"] });
        let profile = serde_json::json!({ "required_extensions": ["permit-pty"] });
        let resolved = resolve(token.clone(), profile.clone(), Request::default()).unwrap();
        assert_eq!(
            resolved
                .extensions
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["permit-port-forwarding", "permit-pty"]
        );

        let request = Request {
            extensions: Some([("permit-agent-forwarding".to_string(), String::new())].into()),
            ..Default::default()
        };
        assert!(matches!(
            resolve(token, profile, request),
            Err(Error::Rejected(_))
        ));
    }

    #[test]
    fn requested_extensions_replace_defaults_but_keep_required() {
        let profile = serde_json::json!({ "required_extensions": ["permit-pty"] });
        let request = Request {
            extensions: Some([("permit-agent-forwarding".to_string(), String::new())].into()),
            ..Default::default()
        };
        let resolved = resolve(base(), profile, request).unwrap();
        assert_eq!(
            resolved
                .extensions
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["permit-agent-forwarding", "permit-pty"]
        );
    }

    #[test]
    fn critical_options_are_checked_by_name_and_value() {
        let token = serde_json::json!({ "principals": ["alice"], "validity": 60, "allowed_critical_options": ["source-address", "force-command"] });
        let profile = serde_json::json!({ "matching_critical_options": { "source-address": r"10\.[0-9./,]+" } });
        let request = |name: &str, value: &str| Request {
            critical_options: Some([(name.to_string(), value.to_string())].into()),
            ..Default::default()
        };
        assert!(resolve(
            token.clone(),
            profile.clone(),
            request("source-address", "10.1.0.0/16")
        )
        .is_ok());
        let err = resolve(
            token.clone(),
            profile.clone(),
            request("source-address", "0.0.0.0/0"),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("matching_critical_options"),
            "{err}"
        );
        let err = resolve(token, profile, request("verify-required", "")).unwrap_err();
        assert!(
            err.to_string()
                .contains("allowed_critical_options of the token"),
            "{err}"
        );
    }

    #[test]
    fn required_critical_options_override_defaults_but_not_requests() {
        let token = serde_json::json!({ "principals": ["alice"], "validity": 60, "critical_options": { "force-command": "/bin/sh" } });
        let profile = serde_json::json!({ "required_critical_options": { "force-command": "/usr/bin/true" } });
        let resolved = resolve(token.clone(), profile.clone(), Request::default()).unwrap();
        assert_eq!(resolved.critical_options["force-command"], "/usr/bin/true");

        let request = Request {
            critical_options: Some([("force-command".to_string(), "/bin/sh".to_string())].into()),
            ..Default::default()
        };
        assert!(matches!(
            resolve(token, profile, request),
            Err(Error::Rejected(_))
        ));
    }

    #[test]
    fn contradicting_required_critical_options_conflict() {
        let token = serde_json::json!({ "principals": ["alice"], "validity": 60, "required_critical_options": { "force-command": "a" } });
        let profile = serde_json::json!({ "required_critical_options": { "force-command": "b" } });
        assert!(matches!(
            resolve(token, profile, Request::default()),
            Err(Error::Conflict(_))
        ));
    }

    // --- text

    #[test]
    fn text_values_must_match() {
        let token = serde_json::json!({ "principals": ["alice"], "validity": 60, "comment": "alice's laptop" });
        let profile = serde_json::json!({ "matching_comment": "[a-z' ]+" });
        assert!(resolve(token.clone(), profile.clone(), Request::default()).is_ok());
        let request = Request {
            comment: Some("ALICE".into()),
            ..Default::default()
        };
        assert!(matches!(
            resolve(token, profile.clone(), request),
            Err(Error::Rejected(_))
        ));

        let token =
            serde_json::json!({ "principals": ["alice"], "validity": 60, "comment": "NOPE" });
        assert!(matches!(
            resolve(token, profile, Request::default()),
            Err(Error::Conflict(_))
        ));
    }

    #[test]
    fn app_name_is_limited_by_both_and_by_length() {
        let token = serde_json::json!({ "principals": ["alice"], "validity": 60, "matching_app_name": "[a-z-]+" });
        let request = |app_name: &str| Request {
            app_name: Some(app_name.into()),
            ..Default::default()
        };
        let resolved = resolve(token.clone(), serde_json::json!({}), request("ansible")).unwrap();
        assert_eq!(resolved.app_name.as_deref(), Some("ansible"));
        let err = resolve(token, serde_json::json!({}), request("Ansible")).unwrap_err();
        assert!(err.to_string().contains("matching_app_name"), "{err}");
        let long = "a".repeat(MAX_APP_NAME_LEN + 1);
        assert!(matches!(
            resolve(base(), serde_json::json!({}), request(&long)),
            Err(Error::Rejected(_))
        ));
        assert_eq!(
            resolve(base(), serde_json::json!({}), Request::default())
                .unwrap()
                .app_name,
            None
        );
    }
}
