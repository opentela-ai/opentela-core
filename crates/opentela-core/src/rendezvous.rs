//! Rendezvous server: peers register their candidate addresses over TCP+TLS and learn their public (observed)
//! TCP and UDP addresses; it hands records to dialers and tells the target to punch at the same moment. State
//! is soft: it is rebuilt from re-registrations after a restart.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::Rng;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, info};

use crate::control::{self, Sessions};
use crate::identity::{Keypair, PeerId, TrustPolicy};
use crate::net::{bind_tcp, bind_udp};
use crate::tls::{quic_identity, Expect, Tls, ALPN_PEER, ALPN_RENDEZVOUS};
use crate::wire::{read_frame, write_frame, DialBack, Msg, Record};
use crate::{Error, Transport};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DIAL_BACK_TIMEOUT: Duration = Duration::from_secs(3);
const PUNCH_ANSWER_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct RendezvousConfig {
    pub keypair: Keypair,
    pub trust: TrustPolicy,
    /// TCP and UDP (QUIC) on the same port.
    pub listen: SocketAddr,
    pub max_peers: usize,
}

struct Registered {
    record: Record,
    push: mpsc::Sender<Msg>,
}

#[derive(Default)]
struct State {
    peers: Sessions<Registered>,
    udp_observed: Sessions<SocketAddr>,
    /// Open TCP punches: token -> (target, initiator's observed address, where to send the target's).
    tcp_punches: HashMap<u64, (PeerId, SocketAddr, oneshot::Sender<SocketAddr>)>,
}

impl State {
    fn record(&self, peer: &PeerId) -> Option<Record> {
        let mut record = self.peers.latest(peer)?.record.clone();
        record.udp_observed = self.udp_observed.latest(peer).copied();
        Some(record)
    }
}

struct Shared {
    tls: Tls,
    state: Mutex<State>,
    sessions: AtomicU64,
    max_peers: usize,
    quic: quinn::Endpoint,
    /// Dial-backs leave from another port: an answer from the port the peer contacted would pass its
    /// stateful firewall and prove nothing.
    dial_back: quinn::Endpoint,
}

pub struct RendezvousServer {
    shared: Arc<Shared>,
    tcp: TcpListener,
}

impl RendezvousServer {
    pub fn bind(config: RendezvousConfig) -> Result<Self, Error> {
        let tls = Tls::new(&config.keypair, config.trust)?;
        let udp = bind_udp(config.listen)?;
        let tcp = bind_tcp(udp.local_addr()?)?;
        let quic = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(tls.quic_server(&[ALPN_RENDEZVOUS])),
            udp,
            Arc::new(quinn::TokioRuntime),
        )?;
        let dial_back = quinn::Endpoint::client(SocketAddr::new(config.listen.ip(), 0))?;
        let shared = Arc::new(Shared {
            tls,
            state: Mutex::default(),
            sessions: AtomicU64::new(1),
            max_peers: config.max_peers,
            quic,
            dial_back,
        });
        Ok(Self { shared, tcp })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.tcp.local_addr()?)
    }

    /// Serves until the listener fails. Dropping the future stops every session it started.
    pub async fn run(self) -> Result<(), Error> {
        let Self { shared, tcp } = self;
        info!(addr = %tcp.local_addr()?, "rendezvous listening");
        let limit = Arc::new(Semaphore::new(shared.max_peers * 2));
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                accepted = tcp.accept() => {
                    let (stream, remote) = accepted?;
                    let Ok(permit) = limit.clone().try_acquire_owned() else {
                        debug!(%remote, "session limit reached");
                        continue;
                    };
                    let shared = shared.clone();
                    tasks.spawn(async move {
                        let error = session(&shared, stream, remote).await;
                        debug!(%remote, %error, "rendezvous session ended");
                        drop(permit);
                    });
                }
                incoming = shared.quic.accept() => {
                    let incoming = incoming.ok_or(Error::Closed)?;
                    tasks.spawn(observe_udp(shared.clone(), incoming));
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }
}

async fn observe_udp(shared: Arc<Shared>, incoming: quinn::Incoming) {
    let result: Result<(), Error> = async {
        let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming)
            .await
            .map_err(|_| Error::Timeout("QUIC handshake"))??;
        let (peer, _) = quic_identity(&conn)?;
        let (mut send, mut recv) = conn.accept_bi().await?;
        read_frame(&mut recv).await?;
        let addr = conn.remote_address();
        let id = conn.stable_id() as u64;
        shared
            .state
            .lock()
            .expect("state lock")
            .udp_observed
            .insert(peer, id, addr);
        write_frame(&mut send, 1, Msg::Observed { addr }).await?;
        // The client's keepalives hold this connection, and with it the NAT binding, open.
        conn.closed().await;
        shared
            .state
            .lock()
            .expect("state lock")
            .udp_observed
            .remove(&peer, id);
        Ok(())
    }
    .await;
    if let Err(error) = result {
        debug!(%error, "QUIC observe ended");
    }
}

async fn session(shared: &Arc<Shared>, stream: TcpStream, remote: SocketAddr) -> Error {
    let handshake = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        shared.tls.accept(stream, &[ALPN_RENDEZVOUS]),
    )
    .await;
    let (stream, peer) = match handshake {
        Err(_) => return Error::Timeout("TLS handshake"),
        Ok(Err(e)) => return e,
        Ok(Ok((stream, peer, _, _))) => (stream, peer),
    };
    let id = shared.sessions.fetch_add(1, Ordering::Relaxed);
    let (push, pushes) = mpsc::channel(64);
    let error = control::serve(stream, pushes, |msg| {
        handle(shared, peer, id, remote, push.clone(), msg)
    })
    .await;
    let mut state = shared.state.lock().expect("state lock");
    if state.peers.remove(&peer, id) {
        info!(%peer, "peer left");
    }
    error
}

async fn handle(
    shared: &Arc<Shared>,
    peer: PeerId,
    session: u64,
    remote: SocketAddr,
    push: mpsc::Sender<Msg>,
    msg: Msg,
) -> Msg {
    match msg {
        Msg::Register { listen, relays } => {
            let mut state = shared.state.lock().expect("state lock");
            if !state.peers.contains(&peer) && state.peers.peers() >= shared.max_peers {
                return Msg::Error {
                    message: format!("rendezvous full ({} peers)", shared.max_peers),
                };
            }
            let record = Record {
                listen,
                tcp_observed: Some(remote),
                udp_observed: None,
                relays,
            };
            info!(%peer, ?record, "peer registered");
            state
                .peers
                .insert(peer, session, Registered { record, push });
            Msg::Registered { observed: remote }
        }
        Msg::Lookup { target, punch } => {
            let state = shared.state.lock().expect("state lock");
            let (Some(record), Some(own)) = (state.record(&target), state.record(&peer)) else {
                return Msg::Error {
                    message: format!("peer {target} is not registered here"),
                };
            };
            if punch
                && state
                    .peers
                    .latest(&target)
                    .expect("record found above")
                    .push
                    .try_send(Msg::PunchUdp {
                        from: peer,
                        record: own,
                    })
                    .is_err()
            {
                return Msg::Error {
                    message: format!("peer {target} is not draining its session"),
                };
            }
            Msg::Found { record }
        }
        Msg::TcpPunch { target } => {
            let token = rand::thread_rng().gen();
            let (answer_tx, answer) = oneshot::channel();
            {
                let mut state = shared.state.lock().expect("state lock");
                let Some(registered) = state.peers.latest(&target) else {
                    return Msg::Error {
                        message: format!("peer {target} is not registered here"),
                    };
                };
                if registered
                    .push
                    .try_send(Msg::TcpPunchRequest {
                        from: peer,
                        addr: remote,
                        token,
                    })
                    .is_err()
                {
                    return Msg::Error {
                        message: format!("peer {target} is not draining its session"),
                    };
                }
                state.tcp_punches.insert(token, (target, remote, answer_tx));
            }
            let answered = tokio::time::timeout(PUNCH_ANSWER_TIMEOUT, answer).await;
            shared
                .state
                .lock()
                .expect("state lock")
                .tcp_punches
                .remove(&token);
            match answered {
                Ok(Ok(addr)) => Msg::PunchAddr { addr },
                _ => Msg::Error {
                    message: format!("peer {target} did not join the TCP punch"),
                },
            }
        }
        Msg::TcpPunchAnswer { token } => {
            let mut state = shared.state.lock().expect("state lock");
            match state.tcp_punches.remove(&token) {
                Some((target, initiator, answer)) if target == peer => match answer.send(remote) {
                    Ok(()) => Msg::PunchAddr { addr: initiator },
                    Err(_) => Msg::Error {
                        message: "the initiator gave up".into(),
                    },
                },
                Some(entry) => {
                    state.tcp_punches.insert(token, entry);
                    Msg::Error {
                        message: "punch token belongs to another peer".into(),
                    }
                }
                None => Msg::Error {
                    message: "unknown or expired punch token".into(),
                },
            }
        }
        Msg::DialBackRequest => {
            let Some(record) = shared.state.lock().expect("state lock").record(&peer) else {
                return Msg::Error {
                    message: "register before asking for a dial-back".into(),
                };
            };
            Msg::DialBackResult {
                results: dial_back(shared, peer, &record).await,
            }
        }
        other => Msg::Error {
            message: format!("unexpected {other:?}"),
        },
    }
}

/// Tries to reach the peer from here at each of its addresses, as an unrelated host would.
async fn dial_back(shared: &Arc<Shared>, peer: PeerId, record: &Record) -> Vec<DialBack> {
    let mut probes = JoinSet::new();
    let tcp = record
        .listen
        .iter()
        .chain(&record.tcp_observed)
        .map(|&a| (a, Transport::Tcp));
    let mut targets: Vec<(SocketAddr, Transport)> = tcp
        .chain(
            record
                .udp_candidates()
                .into_iter()
                .map(|a| (a, Transport::Quic)),
        )
        .collect();
    targets.sort();
    targets.dedup();
    for (addr, transport) in targets {
        let shared = shared.clone();
        probes.spawn(async move {
            let attempt = async {
                match transport {
                    Transport::Tcp => {
                        let stream = TcpStream::connect(addr).await?;
                        shared
                            .tls
                            .connect(stream, Expect::Peer(peer), ALPN_PEER)
                            .await
                            .map(drop)
                    }
                    Transport::Quic => {
                        let config = shared.tls.quic_client(Expect::Peer(peer), ALPN_PEER);
                        let conn = shared
                            .dial_back
                            .connect_with(config, addr, "otela")?
                            .await?;
                        conn.close(0u32.into(), b"dial-back");
                        Ok(())
                    }
                }
            };
            let error = match tokio::time::timeout(DIAL_BACK_TIMEOUT, attempt).await {
                Err(_) => Some("timed out".to_string()),
                Ok(Err(e)) => Some(e.to_string()),
                Ok(Ok(())) => None,
            };
            DialBack {
                addr,
                transport,
                error,
            }
        });
    }
    let mut results = probes.join_all().await;
    results.sort_by_key(|r| (r.transport, r.addr));
    results
}
