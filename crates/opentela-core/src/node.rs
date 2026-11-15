//! A node: one UDP+TCP port, sessions to every rendezvous and relay kept alive in the background, and the
//! accepting side of every ladder step.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::control::Control;
use crate::identity::{Keypair, PeerId, TrustPolicy};
use crate::net::{bind_tcp, bind_udp, tune};
use crate::services::{maintain, relay_session, rendezvous_quic, rendezvous_session};
use crate::stream::{Io, PathKind, Stream, Transport, HELLO_PROBE, HELLO_STREAM};
use crate::tls::{quic_identity, ChannelBinding, Tls, ALPN_PEER};
use crate::{Error, Step};

pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HELLO_TIMEOUT: Duration = Duration::from_secs(30);
const PUNCH_MEMORY: Duration = Duration::from_secs(60);
const ACCEPT_QUEUE: usize = 1024;

/// Per-step time budgets. A relay step gets `relay` per relay tried.
#[derive(Debug, Clone)]
pub struct Timeouts {
    pub direct: Duration,
    pub udp_punch: Duration,
    pub tcp_punch: Duration,
    pub relay: Duration,
    /// Rendezvous and relay requests, and their connection setup.
    pub control: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            direct: Duration::from_secs(3),
            udp_punch: Duration::from_secs(6),
            tcp_punch: Duration::from_secs(6),
            relay: Duration::from_secs(8),
            control: Duration::from_secs(5),
        }
    }
}

#[derive(Debug)]
pub struct Config {
    pub keypair: Keypair,
    pub trust: TrustPolicy,
    /// UDP (QUIC) and TCP share this port; port 0 picks a free one.
    pub listen: SocketAddr,
    /// Addresses to advertise. Empty: the local address each rendezvous connection leaves from.
    pub advertise: Vec<SocketAddr>,
    /// `host:port` of every rendezvous; names are re-resolved on each reconnect.
    pub rendezvous: Vec<String>,
    /// `host:port` of every relay to hold a reservation on (and to dial through).
    pub relays: Vec<String>,
    pub ladder: Vec<Step>,
    pub timeouts: Timeouts,
}

impl Config {
    pub fn new(keypair: Keypair, trust: TrustPolicy) -> Self {
        Self {
            keypair,
            trust,
            listen: SocketAddr::from(([0, 0, 0, 0], 0)),
            advertise: Vec::new(),
            rendezvous: Vec::new(),
            relays: Vec::new(),
            ladder: Step::ALL.to_vec(),
            timeouts: Timeouts::default(),
        }
    }
}

/// Live state of one rendezvous or relay session, as preflight reports it.
#[derive(Debug, Clone, Default)]
pub(crate) struct SlotStatus {
    pub connected: bool,
    pub handshake: Option<Duration>,
    pub error: Option<String>,
    pub tcp_observed: Option<SocketAddr>,
    pub udp_observed: Option<SocketAddr>,
    pub quic_error: Option<String>,
}

#[derive(Debug)]
pub(crate) struct Slot {
    pub addr: String,
    pub control: Mutex<Option<Control>>,
    pub status: Mutex<SlotStatus>,
}

impl Slot {
    fn new(addr: &str) -> Self {
        Self {
            addr: addr.to_string(),
            control: Mutex::default(),
            status: Mutex::default(),
        }
    }

    pub(crate) fn control(&self) -> Option<Control> {
        self.control.lock().expect("slot lock").clone()
    }

    pub(crate) fn status(&self) -> SlotStatus {
        self.status.lock().expect("slot lock").clone()
    }

    pub(crate) fn update(&self, f: impl FnOnce(&mut SlotStatus)) {
        f(&mut self.status.lock().expect("slot lock"));
    }
}

pub(crate) struct Inner {
    pub id: PeerId,
    pub tls: Tls,
    pub quic: quinn::Endpoint,
    /// Same socket as the QUIC endpoint; used to spray punch packets.
    pub udp: std::net::UdpSocket,
    pub local: SocketAddr,
    pub advertise: Vec<SocketAddr>,
    pub ladder: Vec<Step>,
    pub timeouts: Timeouts,
    pub rendezvous: Vec<Slot>,
    pub relays: Vec<Slot>,
    incoming: mpsc::Sender<Stream>,
    pub punched_by: Mutex<HashMap<PeerId, Instant>>,
    /// Peers we are currently spraying UDP for.
    pub spraying: Mutex<HashSet<PeerId>>,
}

/// A running node. Dropping it stops every background session.
pub struct Node {
    pub(crate) inner: Arc<Inner>,
    accepted: tokio::sync::Mutex<mpsc::Receiver<Stream>>,
    _tasks: JoinSet<()>,
}

impl Node {
    pub async fn start(config: Config) -> Result<Self, Error> {
        let tls = Tls::new(&config.keypair, config.trust)?;
        let (udp, tcp) = bind_pair(config.listen)?;
        let local = udp.local_addr()?;
        let quic = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(tls.quic_server(&[ALPN_PEER])),
            udp.try_clone()?,
            Arc::new(quinn::TokioRuntime),
        )?;
        let (incoming, accepted) = mpsc::channel(ACCEPT_QUEUE);
        let inner = Arc::new(Inner {
            id: config.keypair.peer_id(),
            tls,
            quic,
            udp,
            local,
            advertise: config.advertise,
            ladder: config.ladder,
            timeouts: config.timeouts,
            rendezvous: config.rendezvous.iter().map(|a| Slot::new(a)).collect(),
            relays: config.relays.iter().map(|a| Slot::new(a)).collect(),
            incoming,
            punched_by: Mutex::default(),
            spraying: Mutex::default(),
        });
        info!(peer = %inner.id, %local, "node listening");
        let mut tasks = JoinSet::new();
        let node = inner.clone();
        tasks.spawn(async move {
            loop {
                match tcp.accept().await {
                    Ok((stream, remote)) => {
                        let node = node.clone();
                        tokio::spawn(async move {
                            if let Err(error) = serve_tcp(&node, stream).await {
                                debug!(%remote, %error, "incoming TCP stream failed");
                            }
                        });
                    }
                    Err(error) => warn!(%error, "TCP accept failed"),
                }
            }
        });
        let node = inner.clone();
        tasks.spawn(async move {
            while let Some(incoming) = node.quic.accept().await {
                let node = node.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_quic(&node, incoming).await {
                        debug!(%error, "QUIC connection ended");
                    }
                });
            }
        });
        for i in 0..inner.rendezvous.len() {
            let node = inner.clone();
            tasks.spawn(async move {
                maintain("rendezvous", &node.rendezvous[i].addr, || {
                    rendezvous_session(&node, i)
                })
                .await
            });
            let node = inner.clone();
            tasks.spawn(async move {
                maintain("rendezvous QUIC", &node.rendezvous[i].addr, || {
                    rendezvous_quic(&node, i)
                })
                .await
            });
        }
        for i in 0..inner.relays.len() {
            let node = inner.clone();
            tasks.spawn(async move {
                maintain("relay", &node.relays[i].addr, || relay_session(&node, i)).await
            });
        }
        Ok(Self {
            inner,
            accepted: tokio::sync::Mutex::new(accepted),
            _tasks: tasks,
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.inner.id
    }

    /// The bound UDP/TCP address.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local
    }

    /// Next stream any peer opened to us, over any path.
    pub async fn accept(&self) -> Result<Stream, Error> {
        self.accepted.lock().await.recv().await.ok_or(Error::Closed)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.inner.quic.close(0u32.into(), b"node stopped");
    }
}

/// UDP and TCP on one port; with port 0, retries until both are free.
fn bind_pair(listen: SocketAddr) -> Result<(std::net::UdpSocket, tokio::net::TcpListener), Error> {
    let mut last = None;
    for _ in 0..16 {
        let udp = bind_udp(listen)?;
        match bind_tcp(udp.local_addr()?) {
            Ok(tcp) => return Ok((udp, tcp)),
            Err(e) if listen.port() == 0 => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.expect("loop ran"))
}

fn kind_for(inner: &Inner, peer: &PeerId) -> PathKind {
    match inner.punched_by.lock().expect("punch lock").get(peer) {
        Some(at) if at.elapsed() < PUNCH_MEMORY => PathKind::Punched,
        _ => PathKind::Direct,
    }
}

pub(crate) async fn serve_tcp(inner: &Arc<Inner>, stream: TcpStream) -> Result<(), Error> {
    tune(&stream)?;
    debug!(local = ?stream.local_addr(), remote = ?stream.peer_addr(), "TLS accept");
    let (stream, peer, binding, _) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, inner.tls.accept(stream, &[ALPN_PEER]))
            .await
            .map_err(|_| Error::Timeout("TLS handshake"))??;
    dispatch(
        inner,
        Box::new(stream),
        peer,
        binding,
        kind_for(inner, &peer),
        Transport::Tcp,
    )
    .await
}

async fn serve_quic(inner: &Arc<Inner>, incoming: quinn::Incoming) -> Result<(), Error> {
    let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming)
        .await
        .map_err(|_| Error::Timeout("QUIC handshake"))??;
    let (peer, binding) = quic_identity(&conn)?;
    let kind = kind_for(inner, &peer);
    debug!(%peer, remote = %conn.remote_address(), ?kind, "QUIC connection accepted");
    loop {
        let (send, recv) = conn.accept_bi().await?;
        let inner = inner.clone();
        tokio::spawn(async move {
            if let Err(error) = dispatch(
                &inner,
                Box::new(tokio::io::join(recv, send)),
                peer,
                binding,
                kind,
                Transport::Quic,
            )
            .await
            {
                debug!(%peer, %error, "incoming QUIC stream failed");
            }
        });
    }
}

/// Reads the opener's hello: user streams go to `accept`, probes are drained and acknowledged here.
pub(crate) async fn dispatch(
    inner: &Inner,
    mut io: Box<dyn Io>,
    peer: PeerId,
    binding: ChannelBinding,
    kind: PathKind,
    transport: Transport,
) -> Result<(), Error> {
    let hello = tokio::time::timeout(HELLO_TIMEOUT, io.read_u8())
        .await
        .map_err(|_| Error::Timeout("stream hello"))??;
    match hello {
        HELLO_STREAM => inner
            .incoming
            .send(Stream {
                io,
                peer,
                binding,
                kind,
                transport,
            })
            .await
            .map_err(|_| Error::Closed),
        HELLO_PROBE => {
            let len = io.read_u64().await?;
            let drained = tokio::io::copy(&mut (&mut io).take(len), &mut tokio::io::sink()).await?;
            if drained != len {
                return Err(Error::Protocol(format!(
                    "probe ended after {drained} of {len} bytes"
                )));
            }
            io.write_u8(1).await?;
            // The prober may already be gone once it has the ack; that is not a failed probe.
            if let Err(error) = io.shutdown().await {
                debug!(%peer, %error, "probe closed before our shutdown");
            }
            Ok(())
        }
        other => Err(Error::Protocol(format!("unknown stream hello {other}"))),
    }
}
