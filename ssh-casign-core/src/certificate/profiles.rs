use serde::Deserialize;
use ssh_casign_proto::CertType;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use super::{
    key_id::KeyIdTemplate,
    policy::Policy,
    template::{Context, Placeholder, Template},
};

/// Claims of the token, as used for profile selection.
pub(crate) type TokenClaims = serde_json::Map<String, serde_json::Value>;

/// Name of the fallback profile.
pub(crate) const DEFAULT_PROFILE: &str = "default";

/// Profile settings: the authority to sign with, the key ID template, plus
/// the profile's defaults and limits.
#[derive(Deserialize)]
#[serde(try_from = "RawCertificateSettings")]
pub(crate) struct CertificateSettings {
    /// Authorities to sign with, in order of preference.
    ssh_ca: Vec<Arc<str>>,
    /// Certificate types this profile issues.
    cert_types: Vec<CertType>,
    key_id: KeyIdTemplate,
    policy: Policy,
    principal_templates: PrincipalTemplates,
}

/// Templates in the profile's `principals`, `required_principals` and
/// `allowed_principals`, expanded per request.
#[derive(Default)]
struct PrincipalTemplates {
    principals: Option<Vec<Template>>,
    required_principals: Option<Vec<Template>>,
    allowed_principals: Option<Vec<Template>>,
}

/// Principal templates may use claims and server-side values, but not the
/// client-chosen application name or the serial.
fn principal_placeholder_allowed(placeholder: &Placeholder) -> bool {
    !matches!(placeholder, Placeholder::AppName | Placeholder::Serial)
}

fn parse_principal_templates(
    key: &str,
    sources: Option<&Vec<String>>,
) -> Result<Option<Vec<Template>>, String> {
    sources
        .map(|sources| {
            sources
                .iter()
                .map(|source| Template::parse(source, key, principal_placeholder_allowed))
                .collect()
        })
        .transpose()
}

/// Expand templates into principals, dropping values that can't be a
/// principal (empty, or containing whitespace or control characters).
fn expand_principals(templates: &[Template], context: &Context<'_>) -> Vec<String> {
    templates
        .iter()
        .flat_map(|template| {
            template
                .expand(context)
                .into_iter()
                .filter(move |principal| {
                    let usable = !principal.is_empty()
                        && !principal
                            .chars()
                            .any(|c| c.is_whitespace() || c.is_control());
                    if !usable {
                        tracing::debug!(
                            "dropping principal {principal:?} from template '{}'",
                            template.source()
                        );
                    }
                    usable
                })
        })
        .collect()
}

/// `deny_unknown_fields` doesn't work together with `flatten`, so unknown
/// keys are collected and rejected by hand.
#[derive(Deserialize)]
struct RawCertificateSettings {
    ssh_ca: OneOrMany,
    /// Default `["user"]`.
    cert_types: Option<Vec<CertType>>,
    #[serde(default)]
    key_id: KeyIdTemplate,
    #[serde(flatten)]
    policy: Policy,
    #[serde(flatten)]
    unknown: BTreeMap<String, toml::Value>,
}

/// `ssh_ca = "name"` or `ssh_ca = ["first", "second"]`.
#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(Arc<str>),
    Many(Vec<Arc<str>>),
}

impl TryFrom<RawCertificateSettings> for CertificateSettings {
    type Error = String;

    fn try_from(raw: RawCertificateSettings) -> Result<Self, Self::Error> {
        let ssh_ca = match raw.ssh_ca {
            OneOrMany::One(name) => vec![name],
            OneOrMany::Many(names) if names.is_empty() => {
                return Err("ssh_ca must name at least one authority".to_string())
            }
            OneOrMany::Many(names) => names,
        };
        let cert_types = raw.cert_types.unwrap_or_else(|| vec![CertType::User]);
        if cert_types.is_empty() {
            return Err("cert_types must name at least one certificate type".to_string());
        }
        if !raw.unknown.is_empty() {
            let keys: Vec<_> = raw.unknown.keys().map(String::as_str).collect();
            return Err(format!("unknown profile setting(s): {}", keys.join(", ")));
        }
        let principal_templates = PrincipalTemplates {
            principals: parse_principal_templates("principals", raw.policy.principals.as_ref())?,
            required_principals: parse_principal_templates(
                "required_principals",
                raw.policy.required_principals.as_ref(),
            )?,
            allowed_principals: parse_principal_templates(
                "allowed_principals",
                raw.policy.allowed_principals.as_ref(),
            )?,
        };
        Ok(Self {
            ssh_ca,
            cert_types,
            key_id: raw.key_id,
            policy: raw.policy,
            principal_templates,
        })
    }
}

impl CertificateSettings {
    /// Authorities to sign with, in order of preference.
    pub(crate) fn authorities(&self) -> &[Arc<str>] {
        &self.ssh_ca
    }

    pub(crate) fn cert_types(&self) -> &[CertType] {
        &self.cert_types
    }

    pub(crate) fn key_id(&self) -> &KeyIdTemplate {
        &self.key_id
    }

    /// The profile's policy as configured (principal templates unexpanded).
    #[cfg(test)]
    pub(crate) fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The profile's policy for one request, with principal templates
    /// expanded from the token's claims.
    pub(crate) fn policy_for(&self, context: &Context<'_>) -> Policy {
        let templates = &self.principal_templates;
        let expand = |templates: &Option<Vec<Template>>| {
            templates
                .as_ref()
                .map(|templates| expand_principals(templates, context))
        };
        Policy {
            principals: expand(&templates.principals),
            required_principals: expand(&templates.required_principals),
            allowed_principals: expand(&templates.allowed_principals),
            ..self.policy.clone()
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfileSelector {
    /// Profile name, used in the key ID; defaults to `<claim>=<value>`.
    name: Option<String>,
    /// The issuer whose tokens this selector matches: a name from
    /// `[issuers]`; default `oidc_provider`.
    issuer: Option<String>,
    claim: String,
    value: String,
    settings: CertificateSettings,
}

pub(crate) struct ProfileSelector {
    name: String,
    issuer: String,
    claim: String,
    value: String,
    settings: CertificateSettings,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfiles {
    #[serde(default)]
    map: Vec<RawProfileSelector>,
    default: Option<CertificateSettings>,
}

#[derive(Deserialize)]
#[serde(try_from = "RawProfiles")]
pub(crate) struct Profiles {
    map: Vec<ProfileSelector>,
    default: Option<CertificateSettings>,
}

impl TryFrom<RawProfiles> for Profiles {
    type Error = String;

    fn try_from(raw: RawProfiles) -> Result<Self, Self::Error> {
        let mut names = BTreeSet::from([DEFAULT_PROFILE.to_string()]);
        let map = raw
            .map
            .into_iter()
            .map(|selector| {
                let name = selector
                    .name
                    .unwrap_or_else(|| format!("{}={}", selector.claim, selector.value));
                if !names.insert(name.clone()) {
                    return Err(format!("duplicate profile name '{name}'"));
                }
                Ok(ProfileSelector {
                    name,
                    issuer: selector
                        .issuer
                        .unwrap_or_else(|| crate::web::oidc::PRIMARY_ISSUER.to_string()),
                    claim: selector.claim,
                    value: selector.value,
                    settings: selector.settings,
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            map,
            default: raw.default,
        })
    }
}

/// The profile selected for a request.
pub(crate) struct Profile<'a> {
    pub(crate) name: &'a str,
    pub(crate) settings: &'a CertificateSettings,
}

impl ProfileSelector {
    fn matches(&self, issuer: &str, claims: &TokenClaims) -> bool {
        if self.issuer != issuer {
            return false;
        }
        match super::template::claim(claims, &self.claim) {
            Some(serde_json::Value::String(value)) => *value == self.value,
            Some(serde_json::Value::Array(values)) => values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|value| value == self.value),
            _ => false,
        }
    }
}

impl Profiles {
    /// Every profile's name and authorities (for checking the config).
    pub(crate) fn all(&self) -> impl Iterator<Item = (&str, &CertificateSettings)> {
        self.map
            .iter()
            .map(|selector| (selector.name.as_str(), &selector.settings))
            .chain(
                self.default
                    .iter()
                    .map(|settings| (DEFAULT_PROFILE, settings)),
            )
    }

    /// The first profile whose selector matches the token's issuer and
    /// claims and that issues `cert_type`; else the default profile, which
    /// only applies to tokens of `[oidc_provider]`.
    pub(crate) fn lookup(
        &self,
        issuer: &str,
        claims: &TokenClaims,
        cert_type: CertType,
    ) -> Option<Profile<'_>> {
        let issues = |settings: &CertificateSettings| settings.cert_types.contains(&cert_type);
        self.map
            .iter()
            .find(|selector| selector.matches(issuer, claims) && issues(&selector.settings))
            .map(|selector| Profile {
                name: &selector.name,
                settings: &selector.settings,
            })
            .or_else(|| {
                self.default
                    .as_ref()
                    .filter(|settings| {
                        issuer == crate::web::oidc::PRIMARY_ISSUER && issues(settings)
                    })
                    .map(|settings| Profile {
                        name: DEFAULT_PROFILE,
                        settings,
                    })
            })
    }

    /// Check the profiles against the issuers and authorities: selectors
    /// name known issuers, profiles name known authorities, and each
    /// certificate type a profile issues has an authority that signs it.
    pub(crate) fn check(
        &self,
        issuers: &crate::web::oidc::Issuers,
        authorities: &ssh_casign_ca::Authorities,
    ) -> Result<(), String> {
        for selector in &self.map {
            if !issuers.contains(&selector.issuer) {
                return Err(format!(
                    "profile {}: unknown issuer '{}' (configure [issuers.{}])",
                    selector.name, selector.issuer, selector.issuer
                ));
            }
        }
        for (profile, settings) in self.all() {
            for name in settings.authorities() {
                if !authorities.contains_key(name) {
                    return Err(format!("profile {profile}: unknown authority '{name}'"));
                }
            }
            for cert_type in settings.cert_types() {
                let signed = settings.authorities().iter().any(|name| {
                    authorities
                        .get(name)
                        .is_some_and(|authority| authority.cert_types().contains(cert_type))
                });
                if !signed {
                    return Err(format!(
                        "profile {profile}: issues {} certificates, but none of its \
                         authorities signs them (set cert_types on an authority)",
                        cert_type_name(*cert_type)
                    ));
                }
            }
        }
        Ok(())
    }
}

/// `user` or `host`, for messages.
pub(crate) fn cert_type_name(cert_type: CertType) -> &'static str {
    match cert_type {
        CertType::User => "user",
        CertType::Host => "host",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::oidc::PRIMARY_ISSUER as PRIMARY;

    fn profiles() -> Profiles {
        toml::from_str(
            r#"
            [default]
            ssh_ca = "default"
            validity = 300

            [[map]]
            claim = "roles"
            value = "ops"
            settings = { ssh_ca = "ops", max_validity = 3600, matching_principals = "[a-z]+" }
            "#,
        )
        .unwrap()
    }

    fn claims(json: serde_json::Value) -> TokenClaims {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn lookup_matches_string_and_array_claims() {
        let profiles = profiles();
        let as_string = claims(serde_json::json!({ "roles": "ops" }));
        let as_array = claims(serde_json::json!({ "roles": ["dev", "ops"] }));
        let other = claims(serde_json::json!({ "roles": ["dev"] }));
        assert_eq!(
            profiles
                .lookup(PRIMARY, &as_string, CertType::User)
                .unwrap()
                .settings
                .authorities()[0]
                .as_ref(),
            "ops"
        );
        assert_eq!(
            profiles
                .lookup(PRIMARY, &as_array, CertType::User)
                .unwrap()
                .settings
                .authorities()[0]
                .as_ref(),
            "ops"
        );
        assert_eq!(
            profiles
                .lookup(PRIMARY, &other, CertType::User)
                .unwrap()
                .settings
                .authorities()[0]
                .as_ref(),
            "default"
        );
    }

    #[test]
    fn policy_is_parsed_from_profile() {
        let profiles = profiles();
        let ops = profiles
            .lookup(
                PRIMARY,
                &claims(serde_json::json!({ "roles": "ops" })),
                CertType::User,
            )
            .unwrap();
        assert_eq!(ops.name, "roles=ops");
        assert_eq!(ops.settings.policy().max_validity, Some(3600));
        assert!(ops.settings.policy().matching_principals.is_some());
        let default = profiles
            .lookup(PRIMARY, &claims(serde_json::json!({})), CertType::User)
            .unwrap();
        assert_eq!(default.name, DEFAULT_PROFILE);
    }

    #[test]
    fn lookup_by_issuer_and_cert_type() {
        let profiles: Profiles = toml::from_str(
            r#"
            [default]
            ssh_ca = "user-ca"

            [[map]]
            name = "admin-hosts"
            claim = "roles"
            value = "ssh-admin"
            settings = { ssh_ca = "host-ca", cert_types = ["host"] }

            [[map]]
            name = "admins"
            claim = "roles"
            value = "ssh-admin"
            settings = { ssh_ca = "user-ca", cert_types = ["user"] }

            [[map]]
            name = "gce"
            issuer = "google"
            claim = "google.compute_engine.project_id"
            value = "prod"
            settings = { ssh_ca = "host-ca", cert_types = ["host"] }
            "#,
        )
        .unwrap();
        let name = |issuer, claims: serde_json::Value, cert_type| {
            profiles
                .lookup(issuer, &self::claims(claims), cert_type)
                .map(|profile| profile.name.to_string())
        };
        let admin = serde_json::json!({ "roles": ["ssh-admin"] });
        assert_eq!(
            name(PRIMARY, admin.clone(), CertType::Host).unwrap(),
            "admin-hosts"
        );
        assert_eq!(
            name(PRIMARY, admin.clone(), CertType::User).unwrap(),
            "admins"
        );
        // Only the user default for others; it doesn't issue host certificates.
        assert_eq!(
            name(PRIMARY, serde_json::json!({}), CertType::User).unwrap(),
            "default"
        );
        assert!(name(PRIMARY, serde_json::json!({}), CertType::Host).is_none());
        // Another issuer's tokens only match its own selectors, never the default.
        let gce = serde_json::json!({ "google": { "compute_engine": { "project_id": "prod" } } });
        assert_eq!(name("google", gce.clone(), CertType::Host).unwrap(), "gce");
        assert!(name("google", gce.clone(), CertType::User).is_none());
        assert!(name(PRIMARY, gce, CertType::Host).is_none());
        assert!(name("google", admin, CertType::User).is_none());
    }

    #[test]
    fn cert_types_must_not_be_empty() {
        assert!(
            toml::from_str::<Profiles>("[default]\nssh_ca = \"a\"\ncert_types = []\n").is_err()
        );
        assert!(toml::from_str::<Profiles>(
            "[default]\nssh_ca = \"a\"\ncert_types = [\"router\"]\n"
        )
        .is_err());
    }

    #[test]
    fn profile_names_must_be_unique() {
        let result: Result<Profiles, _> = toml::from_str(
            r#"
            [[map]]
            name = "ops"
            claim = "roles"
            value = "ops"
            settings = { ssh_ca = "a" }

            [[map]]
            name = "ops"
            claim = "roles"
            value = "admin"
            settings = { ssh_ca = "a" }
            "#,
        );
        assert!(result.is_err());
        let result: Result<Profiles, _> = toml::from_str(
            r#"
            [[map]]
            name = "default"
            claim = "roles"
            value = "ops"
            settings = { ssh_ca = "a" }
            "#,
        );
        assert!(result.is_err());
    }

    fn context(claims: &TokenClaims) -> Context<'_> {
        Context {
            server_id: "ca1",
            profile: "default",
            oidc_id: "alice@example.com",
            app_name: Some("ansible"),
            serial: Some(1),
            claims,
        }
    }

    #[test]
    fn principal_templates_are_expanded() {
        let profiles: Profiles = toml::from_str(
            r#"
            [default]
            ssh_ca = "a"
            principals = ["{{claim:preferred_username}}", "grp-{{claim:groups}}", "static"]
            required_principals = ["everyone"]
            allowed_principals = ["{{claim:preferred_username}}", "{{claim:preferred_username}}-admin", "grp-{{claim:groups}}", "static", "everyone"]
            "#,
        )
        .unwrap();
        let claims =
            claims(serde_json::json!({ "preferred_username": "alice", "groups": ["dev", "ops"] }));
        let settings = profiles
            .lookup(PRIMARY, &claims, CertType::User)
            .unwrap()
            .settings;
        let policy = settings.policy_for(&context(&claims));
        assert_eq!(
            policy.principals.unwrap(),
            ["alice", "grp-dev", "grp-ops", "static"]
        );
        assert_eq!(policy.required_principals.unwrap(), ["everyone"]);
        assert_eq!(
            policy.allowed_principals.unwrap()[..2],
            ["alice", "alice-admin"]
        );
    }

    #[test]
    fn missing_claims_and_unusable_values_give_no_principals() {
        let profiles: Profiles = toml::from_str(
            r#"
            [default]
            ssh_ca = "a"
            principals = ["{{claim:preferred_username}}", "grp-{{claim:groups}}"]
            "#,
        )
        .unwrap();
        let claims = claims(serde_json::json!({ "preferred_username": "alice smith" }));
        let settings = profiles
            .lookup(PRIMARY, &claims, CertType::User)
            .unwrap()
            .settings;
        assert_eq!(
            settings.policy_for(&context(&claims)).principals.unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn principal_templates_cannot_use_client_values() {
        for template in ["{{app_name}}", "{{serial}}", "{{bogus}}"] {
            let result: Result<Profiles, _> = toml::from_str(&format!(
                "[default]\nssh_ca = \"a\"\nprincipals = [\"{template}\"]\n"
            ));
            assert!(result.is_err(), "{template}");
        }
    }

    #[test]
    fn ssh_ca_one_or_many() {
        let profiles: Profiles = toml::from_str(
            r#"
            [default]
            ssh_ca = ["ed25519", "rsa"]

            [[map]]
            claim = "roles"
            value = "ops"
            settings = { ssh_ca = "ops" }
            "#,
        )
        .unwrap();
        let names: Vec<_> = profiles
            .all()
            .map(|(name, settings)| {
                (
                    name,
                    settings
                        .authorities()
                        .iter()
                        .map(|a| a.as_ref())
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        assert_eq!(
            names,
            [
                ("roles=ops", vec!["ops"]),
                ("default", vec!["ed25519", "rsa"])
            ]
        );
        assert!(toml::from_str::<Profiles>("[default]\nssh_ca = []\n").is_err());
    }

    #[test]
    fn key_id_template_is_parsed() {
        let result: Result<Profiles, _> = toml::from_str(
            r#"
            [default]
            ssh_ca = "a"
            key_id = "{{server_id}}/{{oidc_id}}"
            "#,
        );
        assert!(result.is_ok());
        let result: Result<Profiles, _> = toml::from_str(
            r#"
            [default]
            ssh_ca = "a"
            key_id = "{{bogus}}"
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn unknown_profile_keys_are_rejected() {
        let result: Result<Profiles, _> = toml::from_str(
            r#"
            [default]
            ssh_ca = "default"
            validity = 300
            certificate = { comment = "typo" }
            "#,
        );
        let err = result
            .err()
            .expect("unknown key must be rejected")
            .to_string();
        assert!(err.contains("certificate"), "{err}");
    }

    #[test]
    fn invalid_patterns_are_rejected() {
        let result: Result<Profiles, _> = toml::from_str(
            r#"
            [default]
            ssh_ca = "default"
            matching_principals = "("
            "#,
        );
        assert!(result.is_err());
    }
}
