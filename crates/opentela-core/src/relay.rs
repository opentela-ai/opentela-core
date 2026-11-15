//! Relay server. Reservations are TLS control sessions. A circuit joins two raw TCP connections whose owners
//! proved their keys in a signed preamble (`circuit.rs`); after that the relay copies bytes without decrypting
//! anything. The peers run their own TLS session end to end inside, so the relay sees ciphertext only and
//! cannot impersonate either side. Both kinds share one port, told apart by the first byte.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::server::TlsStream;
use tracing::{debug, info};

use crate::circuit::MAGIC;
use crate::control::{self, Cleanup, Sessions};
use crate::identity::{Keypair, PeerId, TrustPolicy};
use crate::net::{bind_tcp, prefer_bbr, tune};
use crate::tls::{Tls, ALPN_RELAY};
use crate::wire::{read_frame, write_frame, Msg, Purpose};
use crate::Error;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const SPLICE_BUFFER: usize = 256 << 10;

/// Bounds on what one relay holds; every limit rejects with an error frame rather than queueing.
#[derive(Debug, Clone)]
pub struct RelayLimits {
    pub max_reservations: usize,
    pub max_circuits: usize,
    pub max_circuits_per_peer: usize,
    /// A circuit with no bytes in either direction for this long is closed.
    pub idle_timeout: Duration,
    /// How long the target has to answer a circuit request.
    pub accept_timeout: Duration,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_reservations: 1024,
            max_circuits: 512,
            max_circuits_per_peer: 64,
            idle_timeout: Duration::from_secs(120),
            accept_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug)]
pub struct RelayConfig {
    pub keypair: Keypair,
    pub trust: TrustPolicy,
    pub listen: SocketAddr,
    pub limits: RelayLimits,
}

type Conn = TcpStream;

#[derive(Default)]
struct State {
    reservations: Sessions<mpsc::Sender<Msg>>,
    pending: HashMap<u64, (PeerId, oneshot::Sender<Conn>)>,
    circuits_per_peer: HashMap<PeerId, usize>,
}

struct Shared {
    tls: Tls,
    key: Keypair,
    limits: RelayLimits,
    state: Mutex<State>,
    ids: AtomicU64,
    circuits: Arc<Semaphore>,
}

pub struct RelayServer {
    shared: Arc<Shared>,
    tcp: TcpListener,
}

impl RelayServer {
    pub fn bind(config: RelayConfig) -> Result<Self, Error> {
        let tls = Tls::new(&config.keypair, config.trust)?;
        let tcp = bind_tcp(config.listen)?;
        let circuits = Arc::new(Semaphore::new(config.limits.max_circuits));
        let shared = Arc::new(Shared {
            tls,
            key: config.keypair,
            limits: config.limits,
            state: Mutex::default(),
            ids: AtomicU64::new(1),
            circuits,
        });
        Ok(Self { shared, tcp })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.tcp.local_addr()?)
    }

    /// Serves until the listener fails. Dropping the future closes every circuit.
    pub async fn run(self) -> Result<(), Error> {
        info!(addr = %self.tcp.local_addr()?, limits = ?self.shared.limits, "relay listening");
        // Connections still in their handshake or first frame; bounds slowloris-style exhaustion.
        let handshakes = Arc::new(Semaphore::new(4 * self.shared.limits.max_reservations));
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                accepted = self.tcp.accept() => {
                    let (stream, remote) = accepted?;
                    let Ok(permit) = handshakes.clone().try_acquire_owned() else {
                        debug!(%remote, "too many connections in handshake");
                        continue;
                    };
                    let shared = self.shared.clone();
                    tasks.spawn(async move {
                        if let Err(error) = connection(shared, stream, permit).await {
                            debug!(%remote, %error, "relay connection ended");
                        }
                    });
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }
}

async fn connection(
    shared: Arc<Shared>,
    mut stream: TcpStream,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<(), Error> {
    tune(&stream)?;
    prefer_bbr(&stream);
    let mut first = [0u8; 1];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut first))
        .await
        .map_err(|_| Error::Timeout("relay handshake"))??;
    if first[0] != MAGIC[0] {
        let reservation = async {
            let (mut conn, peer, _, _) = shared.tls.accept(stream, &[ALPN_RELAY]).await?;
            let frame = read_frame(&mut conn).await?;
            Ok::<_, Error>((conn, peer, frame))
        };
        let (mut conn, peer, frame) = tokio::time::timeout(HANDSHAKE_TIMEOUT, reservation)
            .await
            .map_err(|_| Error::Timeout("relay handshake"))??;
        drop(permit);
        return match frame.msg {
            Msg::Reserve => reserve(&shared, conn, peer, frame.id).await,
            other => {
                write_frame(
                    &mut conn,
                    frame.id,
                    Msg::error("TLS sessions only hold reservations"),
                )
                .await?;
                Err(Error::Protocol(format!(
                    "unexpected first frame {}",
                    other.kind()
                )))
            }
        };
    }
    let (peer, purpose) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        crate::circuit::admit(&mut stream, &shared.key, shared.tls.trust()),
    )
    .await
    .map_err(|_| Error::Timeout("circuit preamble"))??;
    drop(permit);
    match purpose {
        Purpose::Dial { target } => match circuit(&shared, &mut stream, peer, target).await {
            Ok(()) => Ok(()),
            Err(e) => {
                write_frame(&mut stream, 0, Msg::error(e.to_string()))
                    .await
                    .ok();
                Err(e)
            }
        },
        Purpose::Accept { circuit } => {
            let waiter = {
                let mut state = shared.state.lock().expect("state lock");
                match state.pending.remove(&circuit) {
                    // Only the peer the circuit was offered to may take it.
                    Some((target, waiter)) if target == peer => Some(waiter),
                    Some(entry) => {
                        state.pending.insert(circuit, entry);
                        None
                    }
                    None => None,
                }
            };
            match waiter {
                Some(waiter) => waiter
                    .send(stream)
                    .map_err(|_| Error::Remote("dialer gave up".into())),
                None => {
                    write_frame(
                        &mut stream,
                        0,
                        Msg::error(format!("no circuit {circuit} for you")),
                    )
                    .await?;
                    Err(Error::Protocol(format!(
                        "{peer} accepted unknown circuit {circuit}"
                    )))
                }
            }
        }
    }
}

async fn reserve(
    shared: &Arc<Shared>,
    mut conn: TlsStream<TcpStream>,
    peer: PeerId,
    id: u64,
) -> Result<(), Error> {
    let session = shared.ids.fetch_add(1, Ordering::Relaxed);
    let (push, pushes) = mpsc::channel(64);
    let admitted = {
        let mut state = shared.state.lock().expect("state lock");
        let full = !state.reservations.contains(&peer)
            && state.reservations.peers() >= shared.limits.max_reservations;
        if !full {
            state.reservations.insert(peer, session, push);
        }
        !full
    };
    if !admitted {
        let message = format!(
            "relay full ({} reservations)",
            shared.limits.max_reservations
        );
        write_frame(&mut conn, id, Msg::error(message.clone())).await?;
        return Err(Error::Remote(message));
    }
    let _reserved = Cleanup::new(|| {
        if shared
            .state
            .lock()
            .expect("state lock")
            .reservations
            .remove(&peer, session)
        {
            info!(%peer, "reservation ended");
        }
    });
    info!(%peer, "reserved");
    write_frame(&mut conn, id, Msg::Reserved).await?;
    let error = control::serve(conn, pushes, |msg| async move {
        Msg::error(format!("unexpected {}", msg.kind()))
    })
    .await;
    debug!(%peer, %error, "reservation session ended");
    Ok(())
}

/// Counts a circuit against both peers; released on drop.
struct CircuitSlot<'a> {
    shared: &'a Shared,
    peers: Vec<PeerId>,
    _permit: tokio::sync::SemaphorePermit<'a>,
}

impl Drop for CircuitSlot<'_> {
    fn drop(&mut self) {
        let mut state = self.shared.state.lock().expect("state lock");
        for peer in &self.peers {
            if let Some(count) = state.circuits_per_peer.get_mut(peer) {
                *count -= 1;
                if *count == 0 {
                    state.circuits_per_peer.remove(peer);
                }
            }
        }
    }
}

async fn circuit(
    shared: &Arc<Shared>,
    conn: &mut Conn,
    from: PeerId,
    target: PeerId,
) -> Result<(), Error> {
    let permit = shared.circuits.try_acquire().map_err(|_| {
        Error::Remote(format!(
            "relay at its {} circuit limit",
            shared.limits.max_circuits
        ))
    })?;
    let id = shared.ids.fetch_add(1, Ordering::Relaxed);
    let (waiter, accepted) = oneshot::channel();
    let slot = {
        let mut state = shared.state.lock().expect("state lock");
        let peers = if from == target {
            vec![from]
        } else {
            vec![from, target]
        };
        for peer in &peers {
            if state.circuits_per_peer.get(peer).copied().unwrap_or(0)
                >= shared.limits.max_circuits_per_peer
            {
                return Err(Error::Remote(format!(
                    "peer {peer} at its {} circuit limit",
                    shared.limits.max_circuits_per_peer
                )));
            }
        }
        let push = state
            .reservations
            .latest(&target)
            .cloned()
            .ok_or_else(|| Error::Remote(format!("peer {target} has no reservation here")))?;
        push.try_send(Msg::Circuit { from, circuit: id })
            .map_err(|_| Error::Remote(format!("peer {target} is not draining its reservation")))?;
        state.pending.insert(id, (target, waiter));
        for peer in &peers {
            *state.circuits_per_peer.entry(*peer).or_default() += 1;
        }
        CircuitSlot {
            shared,
            peers,
            _permit: permit,
        }
    };
    let pending = Cleanup::new(|| {
        shared.state.lock().expect("state lock").pending.remove(&id);
    });
    let accepted = tokio::time::timeout(shared.limits.accept_timeout, accepted).await;
    drop(pending);
    let mut other = match accepted {
        Err(_) => {
            return Err(Error::Remote(format!(
                "peer {target} did not accept the circuit in time"
            )))
        }
        Ok(Err(_)) => return Err(Error::Remote(format!("peer {target} dropped the circuit"))),
        Ok(Ok(other)) => other,
    };
    write_frame(conn, 0, Msg::Spliced).await?;
    write_frame(&mut other, 0, Msg::Spliced).await?;
    debug!(%from, %target, id, "circuit spliced");
    let started = Instant::now();
    // From here on the streams carry the peers' TLS; an error frame would corrupt it, so errors are only logged.
    match splice(conn, &mut other, shared.limits.idle_timeout).await {
        Ok(bytes) => {
            debug!(%from, %target, id, bytes, secs = started.elapsed().as_secs_f64(), "circuit closed")
        }
        Err(error) => {
            debug!(%from, %target, id, %error, secs = started.elapsed().as_secs_f64(), "circuit broke")
        }
    }
    drop(slot);
    Ok(())
}

/// Copies both ways until both sides finish or the circuit idles out; returns bytes moved.
async fn splice<A, B>(a: &mut A, b: &mut B, idle: Duration) -> Result<u64, Error>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let start = Instant::now();
    let last = AtomicU64::new(0);
    let (a_read, a_write) = tokio::io::split(a);
    let (b_read, b_write) = tokio::io::split(b);
    let (up, down) = tokio::try_join!(
        pump(a_read, b_write, start, &last, idle),
        pump(b_read, a_write, start, &last, idle)
    )?;
    Ok(up + down)
}

async fn pump(
    mut from: impl AsyncRead + Unpin,
    mut to: impl AsyncWrite + Unpin,
    start: Instant,
    last: &AtomicU64,
    idle: Duration,
) -> Result<u64, Error> {
    let mut buf = vec![0u8; SPLICE_BUFFER];
    let mut total = 0u64;
    loop {
        match tokio::time::timeout(idle, from.read(&mut buf)).await {
            Err(_) => {
                let quiet = start.elapsed().as_millis() as u64 - last.load(Ordering::Relaxed);
                if quiet >= idle.as_millis() as u64 {
                    return Err(Error::Timeout("circuit idle"));
                }
            }
            Ok(Ok(0)) => {
                to.shutdown().await?;
                return Ok(total);
            }
            Ok(Ok(n)) => {
                // TLS buffers records it could not send yet; without a flush the tail of a burst can sit
                // there until the idle timeout while the sender waits for a reply.
                to.write_all(&buf[..n]).await?;
                to.flush().await?;
                total += n as u64;
                last.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
            }
            // A peer that exits without TLS close_notify has still finished sending.
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                to.shutdown().await?;
                return Ok(total);
            }
            Ok(Err(e)) => return Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pump_delivers_a_burst_tail_while_the_source_stays_open() {
        let (mut source, from) = tokio::io::duplex(1 << 16);
        let (to, mut sink) = tokio::io::duplex(1 << 16);
        // Like a TLS stream, BufWriter holds written bytes until flushed.
        let to = tokio::io::BufWriter::with_capacity(1 << 20, to);
        let last = AtomicU64::new(0);
        let start = Instant::now();
        let pumping = pump(from, to, start, &last, Duration::from_secs(60));
        let check = async {
            source.write_all(b"tail of a burst").await.unwrap();
            let mut got = [0u8; 15];
            tokio::time::timeout(Duration::from_secs(2), sink.read_exact(&mut got))
                .await
                .expect("pump flushed what it read")
                .unwrap();
            assert_eq!(&got, b"tail of a burst");
        };
        tokio::select! {
            _ = pumping => panic!("pump ended while the source is open"),
            () = check => {}
        }
    }
}
