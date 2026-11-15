//! Shared command-line pieces of the `rendezvous`, `relay` and `otela` binaries.

use std::path::PathBuf;

use clap::Args;
use opentela_core::{Error, Keypair, TrustPolicy};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Args)]
pub struct IdentityArgs {
    /// Ed25519 key file (create with `otela keygen`).
    #[arg(long, env = "OTELA_KEY")]
    pub key: PathBuf,
    /// Allow list: one peer id per line; must include every node, rendezvous and relay.
    #[arg(long, env = "OTELA_ALLOW")]
    pub allow: PathBuf,
}

impl IdentityArgs {
    pub fn load(&self) -> Result<(Keypair, TrustPolicy), Error> {
        Ok((
            Keypair::load(&self.key)?,
            TrustPolicy::load_allow_list(&self.allow)?,
        ))
    }
}

/// Logs to stderr; `RUST_LOG` overrides the default `info`.
pub fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
}
