//! The ssh-casign signing service: OpenID Connect token validation,
//! certificate policy (profiles, defaults and limits, templates), key IDs,
//! the audit log and the HTTP API.
//!
//! CA keys come from backends registered in a [`Registry`]; the binary
//! (`ssh-casign-service`) decides which backends a build contains.

mod audit;
mod certificate;
mod config;
mod proxy;
mod revocation;
mod trust;
mod web;

pub use config::Config;
pub use ssh_casign_ca::Registry;

/// Load the authorities with `registry` and serve the HTTP API until the
/// server stops.
pub async fn serve(config: Config, registry: &Registry) -> Result<(), Box<dyn std::error::Error>> {
    web::main(config, registry).await
}
