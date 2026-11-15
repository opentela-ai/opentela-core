//! Always-on relay service: splices end-to-end encrypted circuits between peers that cannot reach each other.

use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;
use opentela_bin::{init_logging, IdentityArgs};
use opentela_core::{Error, RelayConfig, RelayLimits, RelayServer};

#[derive(Debug, Parser)]
#[command(about = "Relay: TCP+TLS circuits between reserved peers; sees only ciphertext")]
struct Cli {
    #[command(flatten)]
    identity: IdentityArgs,
    /// 443 is the port HPC egress most often allows.
    #[arg(long, default_value = "0.0.0.0:443")]
    listen: SocketAddr,
    #[arg(long, default_value_t = RelayLimits::default().max_reservations)]
    max_reservations: usize,
    #[arg(long, default_value_t = RelayLimits::default().max_circuits)]
    max_circuits: usize,
    #[arg(long, default_value_t = RelayLimits::default().max_circuits_per_peer)]
    max_circuits_per_peer: usize,
    #[arg(long, default_value_t = RelayLimits::default().idle_timeout.as_secs())]
    idle_timeout_secs: u64,
}

async fn run(cli: Cli) -> Result<(), Error> {
    let (keypair, trust) = cli.identity.load()?;
    let limits = RelayLimits {
        max_reservations: cli.max_reservations,
        max_circuits: cli.max_circuits,
        max_circuits_per_peer: cli.max_circuits_per_peer,
        idle_timeout: Duration::from_secs(cli.idle_timeout_secs),
        ..RelayLimits::default()
    };
    println!("relay {} on {}", keypair.peer_id(), cli.listen);
    RelayServer::bind(RelayConfig {
        keypair,
        trust,
        listen: cli.listen,
        limits,
    })?
    .run()
    .await
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    init_logging();
    run(Cli::parse()).await
}
