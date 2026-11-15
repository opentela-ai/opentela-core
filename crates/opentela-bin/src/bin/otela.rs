//! Node-side tool: key generation, preflight, an iperf-style bulk test, and TCP port forwarding over the
//! library's streams.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use opentela_bin::{init_logging, IdentityArgs};
use opentela_core::{
    Config, Congestion, Connection, Error, Keypair, Node, PeerId, QuicTuning, Step,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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
    /// Carry local TCP ports to services on peers, and serve the services this node exposes.
    /// Each local connection becomes one stream; the peer connects it to the named target.
    Forward {
        #[command(flatten)]
        node: NodeArgs,
        /// LISTEN=PEER/TARGET, e.g. 127.0.0.1:7202=<peer id>/127.0.0.1:7202. Repeatable or comma-separated.
        #[arg(long, value_delimiter = ',')]
        local: Vec<LocalForward>,
        /// PEER/TARGET: lets that one peer reach TARGET (e.g. <peer id>/127.0.0.1:7202) through this node.
        /// Every other peer and target is refused, trusted or not.
        #[arg(long, value_delimiter = ',')]
        expose: Vec<Exposure>,
    },
}

#[derive(Debug, Clone)]
struct LocalForward {
    listen: SocketAddr,
    peer: PeerId,
    target: SocketAddr,
}

impl FromStr for LocalForward {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let (listen, rest) = s.split_once('=').ok_or("expected LISTEN=PEER/TARGET")?;
        let (peer, target) = rest.split_once('/').ok_or("expected LISTEN=PEER/TARGET")?;
        Ok(Self {
            listen: listen
                .parse()
                .map_err(|e| format!("listen {listen}: {e}"))?,
            peer: peer.parse().map_err(|e| format!("peer {peer}: {e:?}"))?,
            target: target
                .parse()
                .map_err(|e| format!("target {target}: {e}"))?,
        })
    }
}

/// One peer allowed to reach one local target.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Exposure {
    peer: PeerId,
    target: SocketAddr,
}

impl FromStr for Exposure {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let (peer, target) = s.split_once('/').ok_or("expected PEER/TARGET")?;
        Ok(Self {
            peer: peer.parse().map_err(|e| format!("peer {peer}: {e:?}"))?,
            target: target
                .parse()
                .map_err(|e| format!("target {target}: {e}"))?,
        })
    }
}

fn exposed(expose: &[Exposure], peer: PeerId, target: SocketAddr) -> bool {
    expose.iter().any(|e| e.peer == peer && e.target == target)
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CongestionArg {
    Cubic,
    Bbr,
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
    /// QUIC congestion controller (userspace; TCP paths keep the kernel's).
    #[arg(long, value_enum, default_value = "cubic")]
    congestion: CongestionArg,
    /// QUIC per-stream receive window in MiB; one stream carries at most this per RTT.
    #[arg(long, default_value_t = 2)]
    stream_window_mib: u32,
}

impl NodeArgs {
    async fn start(&self) -> Result<Node, Error> {
        let (keypair, trust) = self.identity.load()?;
        let mut config = Config::new(keypair, trust);
        config.listen = self.listen;
        config.advertise = self.advertise.clone();
        config.rendezvous = self.rendezvous.clone();
        config.relays = self.relay.clone();
        config.quic = QuicTuning {
            congestion: match self.congestion {
                CongestionArg::Cubic => Congestion::Cubic,
                CongestionArg::Bbr => Congestion::Bbr,
            },
            stream_window: self.stream_window_mib << 20,
        };
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
                            if d.reachable {
                                "reachable"
                            } else {
                                "unreachable"
                            }
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
        Command::Forward {
            node,
            local,
            expose,
        } => forward(node.start().await?, local, expose).await?,
    }
    Ok(())
}

const SPLICE_BUFFER: usize = 256 << 10;

/// One connection per peer, made on first use and remade when a stream cannot be opened on it.
type Connections = Arc<tokio::sync::Mutex<HashMap<PeerId, Arc<Connection>>>>;

async fn forward(node: Node, local: Vec<LocalForward>, expose: Vec<Exposure>) -> Result<(), Error> {
    let node = Arc::new(node);
    println!("forwarding as {} on {}", node.peer_id(), node.local_addr());
    let connections: Connections = Arc::default();
    for rule in local {
        let listener = TcpListener::bind(rule.listen).await?;
        info!(listen = %rule.listen, peer = %rule.peer, target = %rule.target, "local forward");
        let node = node.clone();
        let connections = connections.clone();
        tokio::spawn(async move {
            loop {
                let (socket, remote) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        warn!(%error, "local accept failed");
                        continue;
                    }
                };
                let node = node.clone();
                let connections = connections.clone();
                let rule = rule.clone();
                tokio::spawn(async move {
                    if let Err(error) = carry(&node, &connections, &rule, socket).await {
                        warn!(%remote, target = %rule.target, %error, "forward failed");
                    }
                });
            }
        });
    }
    loop {
        let stream = node.accept().await?;
        let expose = expose.clone();
        tokio::spawn(async move {
            let peer = stream.peer();
            if let Err(error) = deliver(stream, &expose).await {
                warn!(%peer, %error, "inbound forward failed");
            }
        });
    }
}

async fn carry(
    node: &Node,
    connections: &Connections,
    rule: &LocalForward,
    mut socket: TcpStream,
) -> Result<(), Error> {
    socket.set_nodelay(true)?;
    let mut stream = None;
    for _ in 0..2 {
        let conn = {
            let mut cached = connections.lock().await;
            match cached.get(&rule.peer) {
                Some(conn) if conn.is_alive() => conn.clone(),
                _ => {
                    let conn = Arc::new(node.connect(rule.peer).await?);
                    let report = conn.report();
                    info!(peer = %rule.peer, kind = ?report.kind, transport = ?report.transport, via = %report.via, rtt_ms = report.rtt_ms, "forward path");
                    cached.insert(rule.peer, conn.clone());
                    conn
                }
            }
        };
        match conn.open_stream().await {
            Ok(opened) => {
                stream = Some(opened);
                break;
            }
            Err(error) => {
                warn!(peer = %rule.peer, %error, "stream open failed; reconnecting");
                connections.lock().await.remove(&rule.peer);
            }
        }
    }
    let mut stream = stream.ok_or(Error::Closed)?;
    let target = rule.target.to_string();
    stream.write_u8(target.len() as u8).await?;
    stream.write_all(target.as_bytes()).await?;
    tokio::io::copy_bidirectional_with_sizes(
        &mut socket,
        &mut stream,
        SPLICE_BUFFER,
        SPLICE_BUFFER,
    )
    .await?;
    Ok(())
}

async fn deliver(mut stream: opentela_core::Stream, expose: &[Exposure]) -> Result<(), Error> {
    let len = stream.read_u8().await? as usize;
    let mut target = vec![0u8; len];
    stream.read_exact(&mut target).await?;
    let target: SocketAddr = std::str::from_utf8(&target)
        .ok()
        .and_then(|t| t.parse().ok())
        .ok_or_else(|| Error::Protocol("malformed forward target".into()))?;
    if !exposed(expose, stream.peer(), target) {
        return Err(Error::Protocol(format!(
            "target {target} is not exposed to this peer"
        )));
    }
    let mut socket = TcpStream::connect(target).await?;
    socket.set_nodelay(true)?;
    info!(peer = %stream.peer(), %target, path = ?stream.path(), transport = ?stream.transport(), "inbound forward");
    tokio::io::copy_bidirectional_with_sizes(
        &mut stream,
        &mut socket,
        SPLICE_BUFFER,
        SPLICE_BUFFER,
    )
    .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    init_logging();
    run(Cli::parse()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposure_is_per_peer() {
        let listed = Keypair::generate().peer_id();
        let other = Keypair::generate().peer_id();
        let target: SocketAddr = "127.0.0.1:7202".parse().unwrap();
        let expose = vec![format!("{listed}/{target}").parse::<Exposure>().unwrap()];
        assert!(exposed(&expose, listed, target));
        assert!(
            !exposed(&expose, other, target),
            "a trusted peer not listed for the target is refused"
        );
        assert!(!exposed(&expose, listed, "127.0.0.1:7203".parse().unwrap()));
        assert!(
            "127.0.0.1:7202".parse::<Exposure>().is_err(),
            "an exposure must name a peer"
        );
    }
}
