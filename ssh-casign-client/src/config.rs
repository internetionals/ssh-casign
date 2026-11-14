use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Profile {
    pub url: String,
    // pub name: String,
}

fn default_profile() -> String {
    "default".into()
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub profiles: HashMap<String, Profile>,

    #[serde(default = "default_profile")]
    pub default_profile: String,
}
