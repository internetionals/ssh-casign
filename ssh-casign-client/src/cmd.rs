use clap::Parser;
use std::path::PathBuf;
use url::Url;

mod cert;
mod login;
mod logout;
mod request;

use crate::config::{Config, SignInMethod, TokenStore};
use crate::error::{Report, Result, WrapErr};
pub(crate) type CmdResult = Result<Option<String>>;

#[derive(clap::Subcommand, Clone, Debug)]
enum Cmd {
    /// Sign in and request a certificate for a public key
    Cert(cert::Args),
    /// Sign in and add a key with a fresh certificate to ssh-agent
    Login(login::Args),
    /// Forget the cached sign-in and remove the keys login added to ssh-agent
    Logout(logout::Args),
}

#[derive(Parser)]
#[command(version, about = "Obtain SSH certificates from an ssh-casign service")]
pub(crate) struct Args {
    /// Config file [default: <config dir>/ssh-casign-client/config.toml]
    #[arg(short = 'f', long, global = true, env = "SSH_CASIGN_CONFIG")]
    config_file: Option<PathBuf>,

    /// Profile from the config file [default: the config's default_profile]
    #[arg(short, long, global = true, env = "SSH_CASIGN_PROFILE")]
    profile: Option<String>,

    /// Service base URL; overrides the profile's URL
    #[arg(short, long, global = true, env = "SSH_CASIGN_URL")]
    url: Option<Url>,

    /// Sign-in method; overrides the config file
    #[arg(long, global = true, value_enum, env = "SSH_CASIGN_SIGN_IN")]
    sign_in: Option<SignInMethod>,

    /// Where to keep refresh tokens; overrides the config file
    #[arg(long, global = true, value_enum, env = "SSH_CASIGN_TOKEN_STORE")]
    token_store: Option<TokenStore>,

    #[command(subcommand)]
    cmd: Cmd,
}

/// The service to talk to and how to sign in, after combining command-line
/// options, the selected profile and the config file defaults.
pub(crate) struct Target {
    pub(crate) url: Url,
    pub(crate) sign_in: SignInMethod,
    pub(crate) client_id: Option<String>,
    pub(crate) scopes: Option<Vec<String>>,
    pub(crate) app_name: Option<String>,
    pub(crate) token_store: TokenStore,
}

fn resolve_target(args: &Args, config: &Config) -> Result<Target> {
    let profile_name = args.profile.as_ref().unwrap_or(&config.default_profile);
    let profile = config.profiles.get(profile_name);
    // An explicitly requested profile must exist; the default one only when
    // there is no --url to fall back on.
    if profile.is_none() && (args.profile.is_some() || args.url.is_none()) {
        return Err(Report::msg(format!(
            "Unknown profile '{profile_name}'; configure it or pass --url"
        )));
    }
    let url = match (&args.url, profile) {
        (Some(url), _) => url.clone(),
        (None, Some(profile)) => profile.url.clone(),
        (None, None) => unreachable!("checked above"),
    };
    let sign_in = args
        .sign_in
        .or(profile.and_then(|profile| profile.sign_in))
        .unwrap_or(config.sign_in);
    Ok(Target {
        url,
        sign_in,
        client_id: profile.and_then(|profile| profile.client_id.clone()),
        scopes: profile.and_then(|profile| profile.scopes.clone()),
        app_name: profile
            .and_then(|profile| profile.app_name.clone())
            .or_else(|| config.app_name.clone()),
        token_store: args
            .token_store
            .or(profile.and_then(|profile| profile.token_store))
            .unwrap_or(config.token_store),
    })
}

pub(crate) fn run_with_config(args: &Args, config: &Config) -> CmdResult {
    let target = resolve_target(args, config)?;
    match &args.cmd {
        Cmd::Cert(cert_args) => cert::run(cert_args, &target),
        Cmd::Login(login_args) => login::run(login_args, &target),
        Cmd::Logout(logout_args) => logout::run(logout_args, &target),
    }
}

fn default_config_file() -> PathBuf {
    dirs::config_dir()
        .unwrap_or(dirs::home_dir().unwrap_or_default().join(".config"))
        .join("ssh-casign-client")
        .join("config.toml")
}

fn parse_config(config_file: &std::path::Path, config_str: &str) -> Result<Config> {
    toml::from_str(config_str).wrap_err_with(|| {
        format!(
            "Failed to parse config file: {}",
            config_file.to_string_lossy()
        )
    })
}

fn load_config(args: &Args) -> Result<Config> {
    if let Some(config_file) = &args.config_file {
        // An explicitly given config file must exist
        let config_str = std::fs::read_to_string(config_file).wrap_err_with(|| {
            format!(
                "Failed to read config file: {}",
                config_file.to_string_lossy()
            )
        })?;
        return parse_config(config_file, &config_str);
    }
    // The default config file is optional
    let config_file = default_config_file();
    match std::fs::read_to_string(&config_file) {
        Ok(config_str) => parse_config(&config_file, &config_str),
        Err(err) => {
            tracing::debug!(
                "Unable to open default config file {}: {}; ignoring",
                config_file.to_string_lossy(),
                err
            );
            Ok(Config::default())
        }
    }
}

pub(crate) fn run(args: &Args) -> CmdResult {
    let config = load_config(args)?;
    run_with_config(args, &config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        toml::from_str(
            r#"
            sign_in = "authorization-code"

            [profiles.default]
            url = "https://ca.example.com/"

            [profiles.headless]
            url = "https://ca.example.com/"
            sign_in = "device"
            "#,
        )
        .unwrap()
    }

    fn args(cli: &[&str]) -> Args {
        Args::try_parse_from(["ssh-casign-client"].iter().chain(cli).chain(&["cert"])).unwrap()
    }

    #[test]
    fn sign_in_precedence() {
        let config = config();
        let resolve = |cli: &[&str]| resolve_target(&args(cli), &config).unwrap().sign_in;
        assert_eq!(resolve(&[]), SignInMethod::AuthorizationCode);
        assert_eq!(resolve(&["-p", "headless"]), SignInMethod::Device);
        assert_eq!(resolve(&["--sign-in", "device"]), SignInMethod::Device);
        assert_eq!(
            resolve(&["-p", "headless", "--sign-in", "browser"]),
            SignInMethod::AuthorizationCode
        );
    }

    #[test]
    fn default_sign_in_is_device() {
        let target = resolve_target(&args(&["-u", "https://ca.example.com"]), &Config::default());
        assert_eq!(target.unwrap().sign_in, SignInMethod::Device);
    }

    #[test]
    fn app_name_from_profile_or_config() {
        let config: Config = toml::from_str(
            r#"
            app_name = "global"

            [profiles.default]
            url = "https://ca.example.com/"

            [profiles.ansible]
            url = "https://ca.example.com/"
            app_name = "ansible"
            "#,
        )
        .unwrap();
        let resolve = |cli: &[&str]| resolve_target(&args(cli), &config).unwrap().app_name;
        assert_eq!(resolve(&[]).as_deref(), Some("global"));
        assert_eq!(resolve(&["-p", "ansible"]).as_deref(), Some("ansible"));
    }

    #[test]
    fn unknown_profile_is_an_error() {
        let config = config();
        assert!(resolve_target(&args(&["-p", "nope"]), &config).is_err());
        assert!(resolve_target(&args(&[]), &Config::default()).is_err());
    }
}
