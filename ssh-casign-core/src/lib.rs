//! The ssh-casign signing service: OpenID Connect token validation,
//! certificate policy (profiles, defaults and limits, templates), key IDs,
//! the audit log and the HTTP API.
//!
//! CA keys come from backends registered in a [`Registry`], shared storage
//! (optional) from a [`StoreRegistry`]; the binary (`ssh-casign-service`)
//! decides which backends a build contains.

mod audit;
mod certificate;
mod config;
mod index;
mod key_checks;
mod proxy;
mod revocation;
mod trust;
mod web;

pub use config::Config;
pub use ssh_casign_ca::Registry;
pub use ssh_casign_store::Registry as StoreRegistry;

/// Load the authorities with `registry` (and the store, if configured, with
/// `stores`) and serve the HTTP API until the server stops.
pub async fn serve(
    config: Config,
    registry: &Registry,
    stores: &StoreRegistry,
) -> Result<(), Box<dyn std::error::Error>> {
    web::main(config, registry, stores).await
}
