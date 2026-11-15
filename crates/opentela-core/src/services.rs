//! Background sessions a node keeps with every rendezvous (TCP control plus a QUIC observer) and every relay
//! (a reservation), each re-established with backoff when it dies.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::Rng;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::control;
use crate::identity::PeerId;
use crate::net::connect_tcp;
use crate::node::{dispatch, Inner, HANDSHAKE_TIMEOUT};
use crate::punch::{respond_tcp_punch, respond_udp_punch};
use crate::stream::{PathKind, Transport};
use crate::tls::{Expect, ALPN_PEER, ALPN_RELAY, ALPN_RENDEZVOUS};
use crate::wire::{read_frame, write_frame, Msg, Purpose};
use crate::Error;

const BACKOFF_MIN: Duration = Duration::from_millis(250);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// A session that lived this long resets the backoff.
const HEALTHY_SESSION: Duration = Duration::from_secs(60);

/// Re-runs `session` forever with jittered exponential backoff between failures.
pub(crate) async fn maintain<F, Fut>(what: &str, addr: &str, mut session: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Error>,
{
    let mut failures = 0u32;
    loop {
        let started = Instant::now();
        let error = session().await;
        if started.elapsed() > HEALTHY_SESSION {
            failures = 0;
        }
        let delay = BACKOFF_MIN
            .saturating_mul(1 << failures.min(8))
            .min(BACKOFF_MAX)
            .mul_f64(rand::thread_rng().gen_range(0.5..1.0));
        if failures == 0 {
            info!(what, addr, %error, retry_in = ?delay, "session lost");
        } else {
            debug!(what, addr, %error, retry_in = ?delay, "session retry failed");
        }
        failures += 1;
        tokio::time::sleep(delay).await;
    }
}

pub(crate) async fn resolve(inner: &Inner, addr: &str) -> Result<Vec<SocketAddr>, Error> {
    let addrs: Vec<_> = tokio::net::lookup_host(addr)
        .await
        .map_err(|e| Error::Config(format!("resolve {addr}: {e}")))?
        .filter(|a| a.is_ipv4() == inner.local.is_ipv4())
        .collect();
    if addrs.is_empty() {
        return Err(Error::Config(format!(
            "{addr} has no address of our family"
        )));
    }
    Ok(addrs)
}

/// TCP+TLS to the first reachable address of a rendezvous or relay, leaving from `local` if given.
pub(crate) async fn dial_service(
    inner: &Inner,
    addr: &str,
    local: Option<SocketAddr>,
    alpn: &[u8],
) -> Result<
    (
        tokio_rustls::client::TlsStream<TcpStream>,
        SocketAddr,
        Duration,
    ),
    Error,
> {
    let mut last = None;
    for remote in resolve(inner, addr).await? {
        let attempt = async {
            let stream = connect_tcp(local, remote, inner.timeouts.control).await?;
            let local_addr = stream.local_addr()?;
            let started = Instant::now();
            let (stream, _, _) = tokio::time::timeout(
                inner.timeouts.control,
                inner.tls.connect(stream, Expect::AnyTrusted, alpn),
            )
            .await
            .map_err(|_| Error::Timeout("TLS handshake"))??;
            Ok::<_, Error>((stream, local_addr, started.elapsed()))
        };
        match attempt.await {
            Ok(done) => return Ok(done),
            Err(e) => last = Some(e),
        }
    }
    Err(last.expect("resolve returns at least one address"))
}

pub(crate) async fn rendezvous_session(inner: &Arc<Inner>, i: usize) -> Error {
    let slot = &inner.rendezvous[i];
    let (stream, local_addr, handshake) =
        match dial_service(inner, &slot.addr, Some(inner.local), ALPN_RENDEZVOUS).await {
            Ok(done) => done,
            Err(e) => {
                slot.update(|s| s.error = Some(e.to_string()));
                return e;
            }
        };
    let listen = if inner.advertise.is_empty() {
        vec![SocketAddr::new(local_addr.ip(), inner.local.port())]
    } else {
        inner.advertise.clone()
    };
    let relays = inner.relays.iter().map(|r| r.addr.clone()).collect();
    let (pushes_tx, mut pushes) = mpsc::channel(64);
    let (control, driver) = control::session(stream, pushes_tx);
    let work = async {
        let Msg::Registered { observed } = control
            .request(Msg::Register { listen, relays }, inner.timeouts.control)
            .await?
        else {
            return Err(Error::Protocol("expected registered".into()));
        };
        info!(addr = %slot.addr, %observed, "registered with rendezvous");
        slot.update(|s| {
            s.connected = true;
            s.handshake = Some(handshake);
            s.error = None;
            s.tcp_observed = Some(observed);
        });
        *slot.control.lock().expect("slot lock") = Some(control.clone());
        while let Some(msg) = pushes.recv().await {
            match msg {
                Msg::PunchUdp { from, record } => {
                    tokio::spawn(respond_udp_punch(inner.clone(), from, record));
                }
                Msg::TcpPunchRequest { from, addr, token } => {
                    let inner = inner.clone();
                    tokio::spawn(async move {
                        if let Err(error) = respond_tcp_punch(&inner, i, from, addr, token).await {
                            debug!(%from, %error, "TCP punch found no path");
                        }
                    });
                }
                other => debug!(?other, "unexpected rendezvous push"),
            }
        }
        Ok(())
    };
    let error = tokio::select! {
        e = driver => e,
        r = work => r.err().unwrap_or(Error::Closed),
    };
    *slot.control.lock().expect("slot lock") = None;
    slot.update(|s| {
        s.connected = false;
        s.error = Some(error.to_string());
    });
    error
}

/// A QUIC connection to the rendezvous from our listen socket: reveals the UDP mapping and keeps it alive.
pub(crate) async fn rendezvous_quic(inner: &Arc<Inner>, i: usize) -> Error {
    let slot = &inner.rendezvous[i];
    let result = async {
        let remote = resolve(inner, &slot.addr).await?[0];
        let config = inner.tls.quic_client(Expect::AnyTrusted, ALPN_RENDEZVOUS);
        let conn = tokio::time::timeout(
            inner.timeouts.control,
            inner.quic.connect_with(config, remote, "otela")?,
        )
        .await
        .map_err(|_| Error::Timeout("QUIC handshake"))??;
        let (mut send, mut recv) = conn.open_bi().await?;
        write_frame(&mut send, 1, Msg::Observe).await?;
        let Msg::Observed { addr } =
            tokio::time::timeout(inner.timeouts.control, read_frame(&mut recv))
                .await
                .map_err(|_| Error::Timeout("observe"))??
                .msg
        else {
            return Err(Error::Protocol("expected observed".into()));
        };
        slot.update(|s| {
            s.udp_observed = Some(addr);
            s.quic_error = None;
        });
        Ok(conn.closed().await)
    }
    .await;
    let error = match result {
        Ok(closed) => Error::Quic(closed),
        Err(e) => e,
    };
    slot.update(|s| {
        s.udp_observed = None;
        s.quic_error = Some(error.to_string());
    });
    error
}

pub(crate) async fn relay_session(inner: &Arc<Inner>, i: usize) -> Error {
    let slot = &inner.relays[i];
    let (stream, _, handshake) = match dial_service(inner, &slot.addr, None, ALPN_RELAY).await {
        Ok(done) => done,
        Err(e) => {
            slot.update(|s| s.error = Some(e.to_string()));
            return e;
        }
    };
    let (pushes_tx, mut pushes) = mpsc::channel(64);
    let (control, driver) = control::session(stream, pushes_tx);
    let work = async {
        let Msg::Reserved = control
            .request(Msg::Reserve, inner.timeouts.control)
            .await?
        else {
            return Err(Error::Protocol("expected reserved".into()));
        };
        info!(addr = %slot.addr, "relay reservation held");
        slot.update(|s| {
            s.connected = true;
            s.handshake = Some(handshake);
            s.error = None;
        });
        while let Some(msg) = pushes.recv().await {
            match msg {
                Msg::Circuit { from, circuit } => {
                    let inner = inner.clone();
                    tokio::spawn(async move {
                        if let Err(error) = accept_circuit(&inner, i, from, circuit).await {
                            warn!(%from, circuit, %error, "relayed circuit failed");
                        }
                    });
                }
                other => debug!(?other, "unexpected relay push"),
            }
        }
        Ok(())
    };
    let error = tokio::select! {
        e = driver => e,
        r = work => r.err().unwrap_or(Error::Closed),
    };
    slot.update(|s| {
        s.connected = false;
        s.error = Some(error.to_string());
    });
    error
}

async fn accept_circuit(
    inner: &Arc<Inner>,
    relay: usize,
    from: PeerId,
    circuit: u64,
) -> Result<(), Error> {
    if !inner.tls.trust().allows(&from) {
        return Err(Error::Untrusted(from));
    }
    let setup = async {
        let raw = open_circuit(
            inner,
            &inner.relays[relay].addr,
            Purpose::Accept { circuit },
        )
        .await?;
        let (stream, peer, binding, _) = inner.tls.accept(raw, &[ALPN_PEER]).await?;
        Ok::<_, Error>((stream, peer, binding))
    };
    let (stream, peer, binding) = tokio::time::timeout(HANDSHAKE_TIMEOUT, setup)
        .await
        .map_err(|_| Error::Timeout("relayed circuit setup"))??;
    dispatch(
        inner,
        Box::new(stream),
        peer,
        binding,
        PathKind::Relayed,
        Transport::Tcp,
    )
    .await
}

/// A raw TCP connection to a relay, admitted for `purpose` by the signed preamble and spliced: from here on it
/// carries only the peers' own TLS.
pub(crate) async fn open_circuit(
    inner: &Inner,
    addr: &str,
    purpose: Purpose,
) -> Result<TcpStream, Error> {
    let mut last = None;
    for remote in resolve(inner, addr).await? {
        let attempt = async {
            let mut tcp = connect_tcp(None, remote, inner.timeouts.control).await?;
            crate::circuit::open(&mut tcp, &inner.key, inner.tls.trust(), purpose).await?;
            match read_frame(&mut tcp).await?.msg {
                Msg::Spliced => Ok(tcp),
                Msg::Error { message } => Err(Error::Remote(message)),
                other => Err(Error::Protocol(format!(
                    "expected spliced, got {}",
                    other.kind()
                ))),
            }
        };
        match attempt.await {
            Ok(tcp) => return Ok(tcp),
            Err(e) => last = Some(e),
        }
    }
    Err(last.expect("resolve returns at least one address"))
}
