//! `trust`: pin a service's trust statement, and the tools for signing
//! statements offline.
//!
//! - `trust pin`: fetch the statement and pin it, after checking that its
//!   signers are the expected keys (`--expect SHA256:...`, from config
//!   management) or explicitly trusting it on first use (`--tofu`).
//! - `trust show`: the pin and whether the service's statement passes.
//! - `trust statement FILE`: the canonical bytes of a TOML statement, for
//!   `ssh-keygen -Y sign -n ssh-casign-trust`.
//! - `trust sign -k KEY FILE`: the same, signed with `ssh-keygen`.
//! - `trust verify FILE SIG...`: who signed a statement, and whether that is
//!   enough.

use std::{collections::BTreeSet, io::Write, path::PathBuf, process::Stdio};

use color_eyre::eyre::{bail, eyre, WrapErr};
use ssh_casign_proto::trust::{self, SignedTrust, TRUST_NAMESPACE};

use super::request::discover_service;
use crate::{error::Result, trust_pin};

#[derive(clap::Subcommand, Clone, Debug)]
enum Action {
    /// Pin the service's trust statement
    Pin {
        /// Fingerprint of an expected signer key (repeatable); the statement's
        /// signers must be exactly these
        #[arg(long = "expect", value_name = "SHA256:...")]
        expect: Vec<String>,
        /// Pin whatever the service presents now (trust on first use)
        #[arg(long, conflicts_with = "expect")]
        tofu: bool,
        /// Replace an existing pin (to recover from lost signer keys)
        #[arg(long)]
        force: bool,
    },
    /// Show the pin and check the service's current statement
    Show,
    /// Print the canonical statement of a TOML statement file, for signing
    Statement { file: PathBuf },
    /// Sign a TOML statement file with ssh-keygen (a private key, or a FIDO
    /// or PKCS#11 key ssh-keygen can use)
    Sign {
        /// The signing key (passed to ssh-keygen -f)
        #[arg(short, long)]
        key: PathBuf,
        /// Where to write the signature [default: stdout]
        #[arg(short, long)]
        output: Option<PathBuf>,
        file: PathBuf,
    },
    /// Check signatures over a TOML statement file
    Verify {
        file: PathBuf,
        /// Signature files (several signatures per file are fine)
        signatures: Vec<PathBuf>,
    },
}

#[derive(clap::Args, Clone, Debug)]
pub(super) struct Args {
    #[command(subcommand)]
    action: Action,
}

fn statement_file(file: &PathBuf) -> Result<trust::TrustStatement> {
    let text = std::fs::read_to_string(file)
        .wrap_err_with(|| format!("Failed to read {}", file.display()))?;
    trust::statement_from_toml(&text).map_err(|err| eyre!("{}: {err}", file.display()))
}

fn describe(statement: &trust::TrustStatement) -> String {
    let mut out = format!(
        "trust statement {} version {}, expires {}\n",
        statement.id,
        statement.version,
        trust_pin::format_date(statement.expires)
    );
    out += &format!(
        "  signers ({} of {}):\n",
        statement.signers.threshold,
        statement.signers.keys.len()
    );
    for fingerprint in statement.signer_fingerprints() {
        out += &format!("    {fingerprint}\n");
    }
    out += "  authorities:\n";
    for authority in &statement.authorities {
        let types: Vec<_> = authority
            .cert_types
            .iter()
            .map(|t| match t {
                ssh_casign_proto::CertType::User => "user",
                ssh_casign_proto::CertType::Host => "host",
            })
            .collect();
        out += &format!(
            "    {} ({}{}{}) {}\n",
            authority.name,
            types.join(","),
            authority
                .known_hosts_pattern
                .as_ref()
                .map(|p| format!(", hosts {p}"))
                .unwrap_or_default(),
            if authority.retired { ", retired" } else { "" },
            trust::fingerprint(&authority.public_key).unwrap_or_default()
        );
    }
    out
}

pub(super) fn run(args: &Args, target: &super::Target) -> super::CmdResult {
    match &args.action {
        Action::Pin {
            expect,
            tofu,
            force,
        } => {
            let path = trust_pin::pin_file(target);
            if trust_pin::load(&path)?.is_some() && !force {
                bail!(
                    "a statement is already pinned in {}; it follows the service by itself \
                     (use --force to replace it)",
                    path.display()
                );
            }
            if expect.is_empty() && !tofu {
                bail!(
                    "pass --expect with the signer fingerprints, or --tofu to trust on first use"
                );
            }
            let service = discover_service(target)?;
            let signed = service
                .info
                .trust
                .as_ref()
                .ok_or_else(|| eyre!("the service publishes no trust statement"))?;
            let verified =
                trust::verify(signed, None, trust_pin::now()).map_err(|err| eyre!(err))?;
            if !expect.is_empty() {
                let expected: BTreeSet<&str> = expect.iter().map(String::as_str).collect();
                let signers = verified.statement.signer_fingerprints();
                let actual: BTreeSet<&str> = signers.iter().map(String::as_str).collect();
                if expected != actual {
                    bail!(
                        "the statement's signers are not the expected keys:\n{}",
                        describe(&verified.statement)
                    );
                }
            }
            trust_pin::save(&path, target.url.as_str(), &signed.statement)?;
            Ok(Some(format!(
                "pinned in {}\n{}",
                path.display(),
                describe(&verified.statement)
            )))
        }
        Action::Show => {
            let path = trust_pin::pin_file(target);
            let pinned = trust_pin::load(&path)?;
            let mut out = match &pinned {
                Some(statement) => format!("pinned ({}):\n{}", path.display(), describe(statement)),
                None => format!("nothing pinned ({})\n", path.display()),
            };
            let service = discover_service(target)?;
            match &service.info.trust {
                None => out += "the service publishes no trust statement\n",
                Some(signed) => match trust::verify(signed, pinned.as_ref(), trust_pin::now()) {
                    Ok(verified) if Some(&verified.statement) == pinned.as_ref() => {
                        out += "the service's statement is the pinned one\n"
                    }
                    Ok(verified) => {
                        out += &format!(
                            "the service's statement is acceptable (signed by {}):\n{}",
                            verified.signed_by.join(", "),
                            describe(&verified.statement)
                        )
                    }
                    Err(err) => {
                        out += &format!("the service's statement is NOT acceptable: {err}\n")
                    }
                },
            }
            Ok(Some(out))
        }
        Action::Statement { .. } | Action::Sign { .. } | Action::Verify { .. } => {
            unreachable!("handled by run_offline")
        }
    }
}

/// Actions that work on files only, without a service.
pub(super) fn is_offline(args: &Args) -> bool {
    matches!(
        args.action,
        Action::Statement { .. } | Action::Sign { .. } | Action::Verify { .. }
    )
}

pub(super) fn run_offline(args: &Args) -> super::CmdResult {
    match &args.action {
        Action::Statement { file } => {
            // Exactly the signed bytes: no trailing newline.
            std::io::stdout().write_all(statement_file(file)?.canonical().as_bytes())?;
            Ok(None)
        }
        Action::Sign { key, output, file } => {
            let canonical = statement_file(file)?.canonical();
            let mut child = std::process::Command::new("ssh-keygen")
                .args(["-q", "-Y", "sign", "-n", TRUST_NAMESPACE, "-f"])
                .arg(key)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .wrap_err("Failed to run ssh-keygen")?;
            child
                .stdin
                .take()
                .expect("piped")
                .write_all(canonical.as_bytes())?;
            let result = child.wait_with_output()?;
            if !result.status.success() {
                bail!("ssh-keygen -Y sign failed ({})", result.status);
            }
            let signature = String::from_utf8(result.stdout)?;
            let check = trust::valid_signers(
                TRUST_NAMESPACE,
                canonical.as_bytes(),
                std::slice::from_ref(&signature),
            );
            if check.is_empty() {
                bail!("ssh-keygen produced no valid signature");
            }
            match output {
                Some(output) => {
                    std::fs::write(output, &signature)
                        .wrap_err_with(|| format!("Failed to write {}", output.display()))?;
                    Ok(None)
                }
                None => Ok(Some(signature)),
            }
        }
        Action::Verify { file, signatures } => {
            let statement = statement_file(file)?;
            let mut armored = Vec::new();
            for path in signatures {
                let text = std::fs::read_to_string(path)
                    .wrap_err_with(|| format!("Failed to read {}", path.display()))?;
                armored.extend(trust::split_signatures(&text));
            }
            let signed = SignedTrust {
                statement: statement.canonical(),
                signatures: armored,
            };
            let mut out = describe(&statement);
            match trust::verify(&signed, None, trust_pin::now()) {
                Ok(verified) => {
                    out += &format!("valid: signed by {}\n", verified.signed_by.join(", "));
                    Ok(Some(out))
                }
                Err(err) => bail!("{out}not valid: {err}"),
            }
        }
        Action::Pin { .. } | Action::Show => unreachable!("needs a service"),
    }
}
