//! Hole punching on the responding side, and the pieces both sides share: UDP spraying, fresh punch ports
//! observed by the rendezvous, and TCP simultaneous open.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{debug, warn};

use crate::control::{self, Cleanup, Control};
use crate::identity::PeerId;
use crate::net::{bind_tcp, connect_tcp};
use crate::node::{serve_tcp, Inner};
use crate::services::dial_service;
use crate::tls::ALPN_RENDEZVOUS;
use crate::wire::{Msg, Record};
use crate::Error;

const SPRAY_EVERY: Duration = Duration::from_millis(50);

fn note_punch(inner: &Inner, from: PeerId) -> Result<(), Error> {
    if !inner.tls.trust().allows(&from) {
        return Err(Error::Untrusted(from));
    }
    inner
        .punched_by
        .lock()
        .expect("punch lock")
        .insert(from, Instant::now());
    Ok(())
}

/// Opens our NAT towards a dialer that is about to send QUIC Initials at us.
pub(crate) async fn respond_udp_punch(inner: Arc<Inner>, from: PeerId, record: Record) {
    if let Err(error) = note_punch(&inner, from) {
        warn!(%error, "ignoring punch request");
        return;
    }
    // One spray per peer at a time: repeated requests cannot multiply the packets we send.
    if !inner.spraying.lock().expect("spray lock").insert(from) {
        debug!(%from, "already spraying for this peer");
        return;
    }
    let _done = Cleanup::new(|| {
        inner.spraying.lock().expect("spray lock").remove(&from);
    });
    debug!(%from, ?record, "spraying UDP");
    spray(&inner, &record.udp_candidates(), inner.timeouts.udp_punch).await;
}

pub(crate) async fn respond_tcp_punch(
    inner: &Arc<Inner>,
    rv: usize,
    from: PeerId,
    initiator: SocketAddr,
    token: u64,
) -> Result<(), Error> {
    note_punch(inner, from)?;
    let (control, local, holder) = punch_socket(inner, rv).await?;
    // Where no NAT drops early SYNs, they arrive as RSTs and simultaneous open never lines up; a listener on
    // the punch port catches the initiator's SYN instead. Either way we are the TLS server.
    let listener = bind_tcp(local)?;
    let answer = control
        .request(Msg::TcpPunchAnswer { token }, inner.timeouts.control)
        .await;
    let stream = match answer {
        Ok(Msg::PunchAddr { .. }) => tokio::select! {
            dialed = sim_open(local, initiator, inner.timeouts.tcp_punch) => dialed,
            accepted = listener.accept() => accepted.map(|(stream, _)| stream).map_err(Error::from),
        },
        Ok(other) => Err(Error::Protocol(format!(
            "expected punch address, got {other:?}"
        ))),
        Err(e) => Err(e),
    };
    drop(holder);
    serve_tcp(inner, stream?).await
}

/// A fresh port with a rendezvous session on it, so the rendezvous observes that port's NAT mapping. The
/// returned task holds the session (and with it the mapping) until dropped.
pub(crate) async fn punch_socket(
    inner: &Arc<Inner>,
    rv: usize,
) -> Result<(Control, SocketAddr, JoinSet<Error>), Error> {
    let (stream, local, _) = dial_service(
        inner,
        &inner.rendezvous[rv].addr,
        Some(SocketAddr::new(inner.local.ip(), 0)),
        ALPN_RENDEZVOUS,
    )
    .await?;
    let (pushes, _) = mpsc::channel(1);
    let (control, driver) = control::session(stream, pushes);
    let mut holder = JoinSet::new();
    holder.spawn(driver);
    Ok((control, local, holder))
}

/// Sends small junk datagrams from the QUIC socket so our NAT admits the peer's packets; QUIC drops them.
pub(crate) async fn spray(inner: &Inner, targets: &[SocketAddr], duration: Duration) {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        for target in targets {
            if let Err(error) = inner.udp.send_to(&[0], target) {
                debug!(%target, %error, "punch datagram not sent");
            }
        }
        tokio::time::sleep(SPRAY_EVERY).await;
    }
}

/// Sends SYNs from `local` to `remote` until the peer's SYNs meet ours (simultaneous open) or time runs out.
pub(crate) async fn sim_open(
    local: SocketAddr,
    remote: SocketAddr,
    duration: Duration,
) -> Result<TcpStream, Error> {
    let deadline = tokio::time::Instant::now() + duration;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Err(Error::Timeout("TCP punch"));
        }
        match connect_tcp(Some(local), remote, left).await {
            Ok(stream) => return Ok(stream),
            // Refused or reset while the other side's NAT or socket is not open yet.
            Err(error) => {
                debug!(%local, %remote, %error, "punch dial failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
