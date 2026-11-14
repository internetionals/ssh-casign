use std::io::Read;

use crate::sign::CertType;

#[derive(clap::Args, Clone, Debug)]
pub(super) struct Args {
    #[clap(short, long)]
    profile: Option<String>,
    #[clap(default_value = "user")]
    cert_type: CertType,

    public_key_file: Option<String>,
    certificate_file: Option<String>,
}

pub(super) fn run(args: &Args, config: &super::Config) -> super::CmdResult {
    let profile_name = args.profile.as_ref().unwrap_or(&config.default_profile);
    let Some(profile) = config.profiles.get(profile_name) else {
        return Err(color_eyre::Report::msg(format!(
            "Unknown profile: {}",
            profile_name
        )));
    };
    let public_key_data = match args.public_key_file.as_ref() {
        Some(public_key_file) => std::fs::read(public_key_file),
        None => {
            let mut public_key_data = Vec::new();
            std::io::stdin()
                .read_to_end(&mut public_key_data)
                .map(|_| public_key_data)
        }
    }?;
    let public_key = ssh_key::PublicKey::from_bytes(&public_key_data)?;

    let url = profile.url.clone();
    let profile_name = profile_name.clone();
    let cert_type = args.cert_type;
    let rt = tokio::runtime::Builder::new_current_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");
    let certificate =
        rt.block_on(
            async move { crate::sign::sign(url, profile_name, cert_type, public_key).await },
        )?;

    let cert_data = certificate.to_openssh()?;
    match &args.certificate_file {
        Some(certificate_file) => {
            std::fs::write(certificate_file, cert_data)?;
            Ok(None)
        }
        None => Ok(Some(cert_data)),
    }
}
