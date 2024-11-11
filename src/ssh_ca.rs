use std::path::Path;
use ssh_key::{PrivateKey, PublicKey};

pub(crate) struct SshCa {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl SshCa {
    pub(crate) fn new(private_key_file: &str, public_key_file: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            private_key: PrivateKey::read_openssh_file(Path::new(private_key_file))?,
            public_key: PublicKey::read_openssh_file(Path::new(public_key_file))?,
        })
    }

    pub(crate) fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    #[allow(dead_code)]
    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}
