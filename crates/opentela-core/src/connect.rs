//! The dialing side: walk the ladder (direct, UDP punch, TCP punch, relay) until one step yields an
//! authenticated session, and open further streams over the path that worked.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tracing::{debug, info};

use crate::identity::PeerId;
use crate::net::{connect_tcp, tcp_congestion};
use crate::node::{Inner, Node};
use crate::punch::{punch_socket, sim_open, spray};
use crate::services::resolve;
use crate::stream::{
    Attempt, Outcome, PathKind, PathReport, QuicCongestion, Stream, Transport, HELLO_PROBE,
    HELLO_STREAM,
};
use crate::tls::{quic_identity, ChannelBinding, Expect, ALPN_PEER, ALPN_RELAY};
use crate::wire::{read_frame, write_frame, Msg, Record};
use crate::{Error, Step};

/// Staggered QUIC dials during a punch: each new Initial is another chance once the far NAT opens.
const PUNCH_DIAL_OFFSETS_MS: [u64; 6] = [0, 200, 500, 1000, 2000, 3500];
const PROBE_CHUNK: usize = 1 << 20;
const QUIC_GRACE: Duration = Duration::from_millis(500);

#[derive(Debug, Clone)]
enum Route {
    Quic(quinn::Connection),
    TcpDirect(SocketAddr),
    TcpPunched(usize),
    Relay(String),
}

/// A path to one peer. Open as many streams as needed; for bulk transfer, several in parallel.
pub struct Connection {
    inner: Arc<Inner>,
    peer: PeerId,
    route: Route,
    binding: ChannelBinding,
    report: Mutex<PathReport>,
    /// The TCP-path stream established by the ladder, handed out by the first `open_stream`.
    spare: Mutex<Option<Stream>>,
}

impl Node {
    /// Reaches `peer` by the first ladder step that succeeds. On failure the error lists every attempt.
    pub async fn connect(&self, peer: PeerId) -> Result<Connection, Error> {
        let inner = &self.inner;
        if !inner.tls.trust().allows(&peer) {
            return Err(Error::Untrusted(peer));
        }
        let found = lookup(inner, peer).await;
        let mut attempts = Vec::new();
        for &step in &inner.ladder {
            let started = Instant::now();
            let result = match (&found, step) {
                (Err(why), Step::Direct | Step::UdpPunch | Step::TcpPunch) => {
                    attempts.push(Attempt {
                        step,
                        outcome: Outcome::Skipped {
                            reason: why.clone(),
                        },
                    });
                    continue;
                }
                (Ok((_, record)), Step::Direct) => {
                    timed(inner.timeouts.direct, direct(inner, peer, record)).await
                }
                (Ok((rv, _)), Step::UdpPunch) => {
                    timed(inner.timeouts.udp_punch, udp_punch(inner, peer, *rv)).await
                }
                (Ok((rv, _)), Step::TcpPunch) => {
                    timed(inner.timeouts.tcp_punch, tcp_punched(inner, peer, *rv)).await
                }
                (_, Step::Relay) => {
                    let peer_relays = found
                        .as_ref()
                        .map(|(_, r)| r.relays.clone())
                        .unwrap_or_default();
                    relay(inner, peer, &peer_relays).await
                }
            };
            attempts.push(Attempt {
                step,
                outcome: Outcome::from_result(started.elapsed(), &result),
            });
            match result {
                Ok(mut established) => {
                    established.report.attempts = attempts;
                    info!(%peer, kind = ?established.report.kind, via = %established.report.via, rtt_ms = established.report.rtt_ms, "connected");
                    return Ok(Connection {
                        inner: inner.clone(),
                        peer,
                        route: established.route,
                        binding: established.binding,
                        report: Mutex::new(established.report),
                        spare: Mutex::new(established.stream),
                    });
                }
                Err(error) => debug!(%peer, ?step, %error, "ladder step failed"),
            }
        }
        Err(Error::NoPath { peer, attempts })
    }
}

impl Connection {
    pub fn peer(&self) -> PeerId {
        self.peer
    }

    /// Channel binding of the session the ladder established. For QUIC every stream shares it; on TCP paths
    /// each stream has its own, so bind authentication to [`Stream::channel_binding`].
    pub fn channel_binding(&self) -> ChannelBinding {
        self.binding
    }

    pub fn report(&self) -> PathReport {
        let mut report = self.report.lock().expect("report lock").clone();
        if let Route::Quic(conn) = &self.route {
            report.rtt_ms = conn.min_rtt().as_secs_f64() * 1e3;
        }
        report
    }

    /// False once a QUIC path has closed; TCP paths open a fresh connection per stream and report true.
    pub fn is_alive(&self) -> bool {
        match &self.route {
            Route::Quic(conn) => conn.close_reason().is_none(),
            _ => true,
        }
    }

    pub async fn open_stream(&self) -> Result<Stream, Error> {
        let mut stream = self.raw_stream().await?;
        stream.write_u8(HELLO_STREAM).await?;
        Ok(stream)
    }

    async fn raw_stream(&self) -> Result<Stream, Error> {
        if let Some(stream) = self.spare.lock().expect("spare lock").take() {
            return Ok(stream);
        }
        let inner = &self.inner;
        let established = match &self.route {
            Route::Quic(conn) => {
                let (send, recv) = conn.open_bi().await?;
                return Ok(Stream {
                    io: Box::new(tokio::io::join(recv, send)),
                    peer: self.peer,
                    binding: self.binding,
                    kind: self.report.lock().expect("report lock").kind,
                    transport: Transport::Quic,
                });
            }
            Route::TcpDirect(addr) => {
                timed(inner.timeouts.direct, direct_tcp(inner, self.peer, *addr)).await?
            }
            Route::TcpPunched(rv) => {
                timed(inner.timeouts.tcp_punch, tcp_punched(inner, self.peer, *rv)).await?
            }
            Route::Relay(addr) => {
                timed(inner.timeouts.relay, relay_via(inner, self.peer, addr)).await?
            }
        };
        Ok(established.stream.expect("TCP routes yield a stream"))
    }

    /// Sends `bytes` split over `streams` parallel probe streams and records the goodput in the report.
    /// The remote node drains probes itself; they never reach its `accept`.
    pub async fn measure(&self, bytes: u64, streams: usize) -> Result<f64, Error> {
        assert!(streams > 0, "measure needs at least one stream");
        let per_stream = bytes / streams as u64;
        let mut opened = Vec::with_capacity(streams);
        for _ in 0..streams {
            opened.push(self.raw_stream().await?);
        }
        let started = Instant::now();
        let mut sends = JoinSet::new();
        for mut stream in opened {
            sends.spawn(async move {
                let chunk = vec![0u8; PROBE_CHUNK];
                stream.write_u8(HELLO_PROBE).await?;
                stream.write_u64(per_stream).await?;
                let mut left = per_stream;
                while left > 0 {
                    let n = left.min(PROBE_CHUNK as u64) as usize;
                    stream.write_all(&chunk[..n]).await?;
                    left -= n as u64;
                }
                stream.flush().await?;
                let ack = stream.read_u8().await?;
                if ack != 1 {
                    return Err(Error::Protocol(format!("bad probe ack {ack}")));
                }
                Ok::<_, Error>(())
            });
        }
        for result in sends.join_all().await {
            result?;
        }
        let bps = (per_stream * streams as u64) as f64 * 8.0 / started.elapsed().as_secs_f64();
        self.report.lock().expect("report lock").throughput_bps = Some(bps);
        Ok(bps)
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("peer", &self.peer)
            .field("route", &self.route)
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

struct Established {
    route: Route,
    binding: ChannelBinding,
    report: PathReport,
    stream: Option<Stream>,
}

async fn timed<T>(
    limit: Duration,
    attempt: impl std::future::Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    tokio::time::timeout(limit, attempt)
        .await
        .map_err(|_| Error::Timeout("ladder step"))?
}

/// Asks every connected rendezvous; the first that knows the peer wins.
async fn lookup(inner: &Arc<Inner>, peer: PeerId) -> Result<(usize, Record), String> {
    let mut asks = JoinSet::new();
    for (i, slot) in inner.rendezvous.iter().enumerate() {
        let Some(control) = slot.control() else {
            continue;
        };
        let timeout = inner.timeouts.control;
        asks.spawn(async move {
            (
                i,
                control
                    .request(
                        Msg::Lookup {
                            target: peer,
                            punch: false,
                        },
                        timeout,
                    )
                    .await,
            )
        });
    }
    if asks.is_empty() {
        return Err("no rendezvous session is up".into());
    }
    let mut errors = Vec::new();
    while let Some(joined) = asks.join_next().await {
        match joined.expect("lookup task does not panic") {
            (i, Ok(Msg::Found { record })) => return Ok((i, record)),
            (i, Ok(other)) => errors.push(format!(
                "{}: unexpected {other:?}",
                inner.rendezvous[i].addr
            )),
            (i, Err(e)) => errors.push(format!("{}: {e}", inner.rendezvous[i].addr)),
        }
    }
    Err(errors.join("; "))
}

async fn quic_dial(
    inner: &Inner,
    peer: PeerId,
    addr: SocketAddr,
) -> Result<quinn::Connection, Error> {
    let config = inner.tls.quic_client(Expect::Peer(peer), ALPN_PEER);
    Ok(inner.quic.connect_with(config, addr, "otela")?.await?)
}

fn quic_established(
    peer: PeerId,
    conn: quinn::Connection,
    kind: PathKind,
    congestion: QuicCongestion,
) -> Result<Established, Error> {
    let (seen, binding) = quic_identity(&conn)?;
    debug_assert_eq!(seen, peer, "the verifier pinned the peer id");
    let report = PathReport {
        peer,
        kind,
        transport: Transport::Quic,
        via: conn.remote_address().to_string(),
        rtt_ms: conn.min_rtt().as_secs_f64() * 1e3,
        congestion: format!("quic:{}", congestion.as_str()),
        throughput_bps: None,
        attempts: Vec::new(),
    };
    Ok(Established {
        route: Route::Quic(conn),
        binding,
        report,
        stream: None,
    })
}

async fn tls_over_tcp(
    inner: &Inner,
    peer: PeerId,
    tcp: TcpStream,
    kind: PathKind,
    route: Route,
) -> Result<Established, Error> {
    let via = tcp.peer_addr()?.to_string();
    let congestion = tcp_congestion(&tcp);
    let started = Instant::now();
    let (tls, _, binding) = inner
        .tls
        .connect(tcp, Expect::Peer(peer), ALPN_PEER)
        .await?;
    let report = PathReport {
        peer,
        kind,
        transport: Transport::Tcp,
        via,
        rtt_ms: started.elapsed().as_secs_f64() * 1e3,
        congestion,
        throughput_bps: None,
        attempts: Vec::new(),
    };
    let stream = Stream {
        io: Box::new(tls),
        peer,
        binding,
        kind,
        transport: Transport::Tcp,
    };
    Ok(Established {
        route,
        binding,
        report,
        stream: Some(stream),
    })
}

async fn direct_tcp(inner: &Inner, peer: PeerId, addr: SocketAddr) -> Result<Established, Error> {
    let tcp = connect_tcp(None, addr, inner.timeouts.direct).await?;
    tls_over_tcp(inner, peer, tcp, PathKind::Direct, Route::TcpDirect(addr)).await
}

/// Races QUIC and TCP to every advertised address. QUIC is preferred (one handshake for all streams, keepalives
/// hold the path open), so a TCP win waits `QUIC_GRACE` for a QUIC one.
async fn direct(inner: &Arc<Inner>, peer: PeerId, record: &Record) -> Result<Established, Error> {
    let mut quic = JoinSet::new();
    let mut tcp = JoinSet::new();
    for &addr in &record.listen {
        let quic_inner = inner.clone();
        quic.spawn(async move {
            quic_established(
                peer,
                quic_dial(&quic_inner, peer, addr).await?,
                PathKind::Direct,
                quic_inner.tls.quic_congestion(),
            )
        });
        let tcp_inner = inner.clone();
        tcp.spawn(async move { direct_tcp(&tcp_inner, peer, addr).await });
    }
    if record.listen.is_empty() {
        return Err(Error::Protocol("peer advertises no address".into()));
    }
    let tcp_won = first_ok(tcp, "");
    let quic_won = first_ok(quic, "");
    tokio::pin!(tcp_won, quic_won);
    let combine = |quic: Error, tcp: Error| Error::Protocol(format!("QUIC: {quic}; TCP: {tcp}"));
    tokio::select! {
        quic = &mut quic_won => match quic {
            Ok(established) => Ok(established),
            Err(quic) => tcp_won.await.map_err(|tcp| combine(quic, tcp)),
        },
        tcp = &mut tcp_won => match tcp {
            Err(tcp) => quic_won.await.map_err(|quic| combine(quic, tcp)),
            Ok(tcp) => match tokio::time::timeout(QUIC_GRACE, &mut quic_won).await {
                Ok(Ok(quic)) => Ok(quic),
                _ => Ok(tcp),
            },
        },
    }
}

async fn first_ok(
    mut races: JoinSet<Result<Established, Error>>,
    none: &str,
) -> Result<Established, Error> {
    let mut errors = Vec::new();
    while let Some(joined) = races.join_next().await {
        match joined.expect("dial task does not panic") {
            Ok(established) => return Ok(established),
            Err(e) => errors.push(e.to_string()),
        }
    }
    Err(Error::Protocol(if errors.is_empty() {
        none.to_string()
    } else {
        errors.join("; ")
    }))
}

async fn udp_punch(inner: &Arc<Inner>, peer: PeerId, rv: usize) -> Result<Established, Error> {
    let slot = &inner.rendezvous[rv];
    let control = slot
        .control()
        .ok_or_else(|| Error::Remote(format!("rendezvous {} went away", slot.addr)))?;
    // The fresh record carries the peer's current UDP mapping.
    let Msg::Found { record } = control
        .request(
            Msg::Lookup {
                target: peer,
                punch: true,
            },
            inner.timeouts.control,
        )
        .await?
    else {
        return Err(Error::Protocol("expected found".into()));
    };
    let candidates = record.udp_candidates();
    let mut races = JoinSet::new();
    for &addr in &candidates {
        for offset in PUNCH_DIAL_OFFSETS_MS {
            let inner = inner.clone();
            races.spawn(async move {
                tokio::time::sleep(Duration::from_millis(offset)).await;
                quic_established(
                    peer,
                    quic_dial(&inner, peer, addr).await?,
                    PathKind::Punched,
                    inner.tls.quic_congestion(),
                )
            });
        }
    }
    // Our own packets open our NAT for the peer's Initials-in-reply; the dials retransmit on their own.
    tokio::select! {
        result = first_ok(races, "peer has no UDP candidate") => result,
        () = spray(inner, &candidates, inner.timeouts.udp_punch) => Err(Error::Timeout("UDP punch")),
    }
}

/// Both sides punch from fresh ports whose mappings the rendezvous observes, so every stream gets its own
/// port pair and no listener is involved.
async fn tcp_punched(inner: &Arc<Inner>, peer: PeerId, rv: usize) -> Result<Established, Error> {
    let (control, local, holder) = punch_socket(inner, rv).await?;
    let punched = async {
        match control
            .request(Msg::TcpPunch { target: peer }, inner.timeouts.tcp_punch)
            .await?
        {
            Msg::PunchAddr { addr } => sim_open(local, addr, inner.timeouts.tcp_punch).await,
            other => Err(Error::Protocol(format!(
                "expected punch address, got {other:?}"
            ))),
        }
    }
    .await;
    drop(holder);
    let tcp = punched?;
    debug!(local = ?tcp.local_addr(), remote = ?tcp.peer_addr(), "TCP punch connected");
    tls_over_tcp(inner, peer, tcp, PathKind::Punched, Route::TcpPunched(rv)).await
}

/// Tries the peer's relays first (they hold its reservation), then any of ours it did not list.
async fn relay(
    inner: &Arc<Inner>,
    peer: PeerId,
    peer_relays: &[String],
) -> Result<Established, Error> {
    let mut order: Vec<String> = peer_relays.to_vec();
    for slot in &inner.relays {
        if !order.contains(&slot.addr) {
            order.push(slot.addr.clone());
        }
    }
    if order.is_empty() {
        return Err(Error::Config("no relay configured".into()));
    }
    let mut errors = Vec::new();
    for addr in order {
        match timed(inner.timeouts.relay, relay_via(inner, peer, &addr)).await {
            Ok(established) => return Ok(established),
            Err(e) => errors.push(format!("{addr}: {e}")),
        }
    }
    Err(Error::Remote(errors.join("; ")))
}

async fn relay_via(inner: &Inner, peer: PeerId, addr: &str) -> Result<Established, Error> {
    let mut last = None;
    for remote in resolve(inner, addr).await? {
        let attempt = async {
            let tcp = connect_tcp(None, remote, inner.timeouts.control).await?;
            let congestion = tcp_congestion(&tcp);
            let (mut outer, _, _) = inner
                .tls
                .connect(tcp, Expect::AnyTrusted, ALPN_RELAY)
                .await?;
            write_frame(&mut outer, 1, Msg::Dial { target: peer }).await?;
            match read_frame(&mut outer).await?.msg {
                Msg::Spliced => {}
                Msg::Error { message } => return Err(Error::Remote(message)),
                other => return Err(Error::Protocol(format!("expected spliced, got {other:?}"))),
            }
            let started = Instant::now();
            let (tls, _, binding) = inner
                .tls
                .connect(outer, Expect::Peer(peer), ALPN_PEER)
                .await?;
            let rtt_ms = started.elapsed().as_secs_f64() * 1e3;
            let kind = PathKind::Relayed;
            let stream = Stream {
                io: Box::new(tls),
                peer,
                binding,
                kind,
                transport: Transport::Tcp,
            };
            let route = Route::Relay(addr.to_string());
            let report = PathReport {
                peer,
                kind,
                transport: Transport::Tcp,
                via: addr.to_string(),
                rtt_ms,
                congestion,
                throughput_bps: None,
                attempts: Vec::new(),
            };
            Ok(Established {
                route,
                binding,
                report,
                stream: Some(stream),
            })
        };
        match attempt.await {
            Ok(established) => return Ok(established),
            Err(e) => last = Some(e),
        }
    }
    Err(last.expect("resolve returns at least one address"))
}

/// Opens a circuit to ourselves through one relay and round-trips an empty probe: proves the reservation,
/// the circuit and the end-to-end TLS all work from this host.
pub(crate) async fn relay_loopback(inner: &Arc<Inner>, addr: &str) -> Result<Duration, Error> {
    let started = Instant::now();
    let mut stream = timed(inner.timeouts.relay, relay_via(inner, inner.id, addr))
        .await?
        .stream
        .expect("relay yields a stream");
    stream.write_u8(HELLO_PROBE).await?;
    stream.write_u64(0).await?;
    stream.flush().await?;
    let ack = stream.read_u8().await?;
    if ack != 1 {
        return Err(Error::Protocol(format!("bad probe ack {ack}")));
    }
    Ok(started.elapsed())
}
