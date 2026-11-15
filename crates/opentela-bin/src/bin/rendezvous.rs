//! Always-on rendezvous service: peers register and exchange candidate addresses here.

use std::net::SocketAddr;

use clap::Parser;
use opentela_bin::{init_logging, IdentityArgs};
use opentela_core::{Error, RendezvousConfig, RendezvousServer};

#[derive(Debug, Parser)]
#[command(
    about = "Rendezvous: registration, address discovery and punch coordination (TCP and UDP on one port)"
)]
struct Cli {
    #[command(flatten)]
    identity: IdentityArgs,
    #[arg(long, default_value = "0.0.0.0:7400")]
    listen: SocketAddr,
    #[arg(long, default_value_t = 4096)]
    max_peers: usize,
}

async fn run(cli: Cli) -> Result<(), Error> {
    let (keypair, trust) = cli.identity.load()?;
    println!("rendezvous {} on {}", keypair.peer_id(), cli.listen);
    RendezvousServer::bind(RendezvousConfig {
        keypair,
        trust,
        listen: cli.listen,
        max_peers: cli.max_peers,
    })?
    .run()
    .await
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    init_logging();
    run(Cli::parse()).await
}
