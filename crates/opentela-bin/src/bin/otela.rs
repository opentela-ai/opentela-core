//! Node-side tool: key generation, preflight, and an iperf-style bulk test over the library's streams.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use opentela_bin::{init_logging, IdentityArgs};
use opentela_core::{Config, Error, Keypair, Node, PeerId, Step};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(about = "opentela-core node tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a key file and print its peer id.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the peer id of a key file.
    Id {
        #[arg(long)]
        key: PathBuf,
    },
    /// Report which ladder steps work from this host.
    Preflight {
        #[command(flatten)]
        node: NodeArgs,
        #[arg(long, default_value_t = 5)]
        wait_secs: u64,
        #[arg(long)]
        json: bool,
    },
    /// Run a node that accepts streams and answers channel-binding checks (probes are drained by the library).
    Listen {
        #[command(flatten)]
        node: NodeArgs,
    },
    /// Connect to a peer, check the channel binding end to end, and measure bulk throughput.
    Bench {
        #[command(flatten)]
        node: NodeArgs,
        #[arg(long)]
        peer: PeerId,
        #[arg(long, default_value_t = 1 << 30)]
        bytes: u64,
        #[arg(long, default_value_t = 4)]
        streams: usize,
        #[arg(long, default_value_t = 3)]
        repeat: usize,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LadderStep {
    Direct,
    UdpPunch,
    TcpPunch,
    Relay,
}

#[derive(Debug, Args)]
struct NodeArgs {
    #[command(flatten)]
    identity: IdentityArgs,
    #[arg(long, default_value = "0.0.0.0:0")]
    listen: SocketAddr,
    #[arg(long, value_delimiter = ',')]
    advertise: Vec<SocketAddr>,
    /// host:port, repeatable or comma-separated.
    #[arg(long, value_delimiter = ',', env = "OTELA_RENDEZVOUS")]
    rendezvous: Vec<String>,
    #[arg(long, value_delimiter = ',', env = "OTELA_RELAYS")]
    relay: Vec<String>,
    /// Ladder steps to try, in order (default: all).
    #[arg(long, value_delimiter = ',')]
    ladder: Vec<LadderStep>,
}

impl NodeArgs {
    async fn start(&self) -> Result<Node, Error> {
        let (keypair, trust) = self.identity.load()?;
        let mut config = Config::new(keypair, trust);
        config.listen = self.listen;
        config.advertise = self.advertise.clone();
        config.rendezvous = self.rendezvous.clone();
        config.relays = self.relay.clone();
        if !self.ladder.is_empty() {
            config.ladder = self
                .ladder
                .iter()
                .map(|s| match s {
                    LadderStep::Direct => Step::Direct,
                    LadderStep::UdpPunch => Step::UdpPunch,
                    LadderStep::TcpPunch => Step::TcpPunch,
                    LadderStep::Relay => Step::Relay,
                })
                .collect();
        }
        Node::start(config).await
    }
}

async fn run(cli: Cli) -> Result<(), Error> {
    match cli.command {
        Command::Keygen { out } => {
            let key = Keypair::generate();
            key.save(&out)?;
            println!("{}", key.peer_id());
        }
        Command::Id { key } => println!("{}", Keypair::load(&key)?.peer_id()),
        Command::Preflight {
            node,
            wait_secs,
            json,
        } => {
            let node = node.start().await?;
            let report = node.preflight(Duration::from_secs(wait_secs)).await;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("report serializes")
                );
            } else {
                println!("peer {} local {}", report.peer, report.local);
                for r in &report.rendezvous {
                    println!(
                        "rendezvous {}: control {:?} quic {:?} tcp_observed {:?} udp_observed {:?}",
                        r.addr, r.control, r.quic, r.tcp_observed, r.udp_observed
                    );
                    for d in &r.dial_back {
                        println!(
                            "  dial-back {:?} {} -> {}",
                            d.transport,
                            d.addr,
                            d.error.as_deref().unwrap_or("ok")
                        );
                    }
                }
                for r in &report.relays {
                    println!(
                        "relay {}: reservation {:?} loopback {:?}",
                        r.addr, r.reservation, r.loopback
                    );
                }
                for s in &report.steps {
                    println!(
                        "{:<9} {:<5} {}",
                        format!("{:?}", s.step),
                        if s.usable { "yes" } else { "no" },
                        s.detail
                    );
                }
            }
        }
        Command::Listen { node } => {
            let node = node.start().await?;
            println!("listening as {} on {}", node.peer_id(), node.local_addr());
            loop {
                let mut stream = node.accept().await?;
                tokio::spawn(async move {
                    let mut theirs = [0u8; 32];
                    let result = async {
                        stream.read_exact(&mut theirs).await?;
                        let equal = theirs == stream.channel_binding().0;
                        stream.write_u8(equal as u8).await?;
                        stream.write_all(&stream.channel_binding().0).await?;
                        stream.shutdown().await?;
                        Ok::<_, std::io::Error>(equal)
                    }
                    .await;
                    match result {
                        Ok(equal) => {
                            info!(peer = %stream.peer(), path = ?stream.path(), transport = ?stream.transport(), binding_equal = equal, "binding check")
                        }
                        Err(error) => warn!(%error, "binding check failed"),
                    }
                });
            }
        }
        Command::Bench {
            node,
            peer,
            bytes,
            streams,
            repeat,
        } => {
            let node = node.start().await?;
            // Let the rendezvous and relay sessions come up before dialing.
            node.preflight(Duration::from_secs(5)).await;
            let conn = node.connect(peer).await?;
            let mut stream = conn.open_stream().await?;
            stream.write_all(&stream.channel_binding().0).await?;
            let equal = stream.read_u8().await? == 1;
            let mut theirs = [0u8; 32];
            stream.read_exact(&mut theirs).await?;
            println!(
                "binding_equal {} (remote echo matches: {})",
                equal,
                theirs == stream.channel_binding().0
            );
            for _ in 0..repeat {
                let bps = conn.measure(bytes, streams).await?;
                println!(
                    "throughput {:.3} Gbit/s ({} bytes, {} streams)",
                    bps / 1e9,
                    bytes,
                    streams
                );
            }
            println!(
                "{}",
                serde_json::to_string(&conn.report()).expect("report serializes")
            );
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    init_logging();
    run(Cli::parse()).await
}
