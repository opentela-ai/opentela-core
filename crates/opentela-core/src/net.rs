//! Socket setup: one UDP and one TCP socket share a port, and outgoing TCP can leave from that port so the NAT
//! mapping seen by the rendezvous is the one peers punch towards.

use std::net::SocketAddr;
use std::time::Duration;

use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use crate::Error;

const UDP_BUFFER: usize = 8 << 20;
const TCP_KEEPALIVE: Duration = Duration::from_secs(15);

pub(crate) fn bind_udp(addr: SocketAddr) -> Result<std::net::UdpSocket, Error> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    // The kernel caps these at net.core.{r,w}mem_max; a smaller buffer only costs throughput.
    socket.set_recv_buffer_size(UDP_BUFFER)?;
    socket.set_send_buffer_size(UDP_BUFFER)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

pub(crate) fn bind_tcp(addr: SocketAddr) -> Result<TcpListener, Error> {
    let socket = reusable(addr)?;
    socket.bind(addr)?;
    Ok(socket.listen(1024)?)
}

fn reusable(addr: SocketAddr) -> Result<TcpSocket, Error> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.set_reuseport(true)?;
    Ok(socket)
}

/// Connects to `remote`, leaving from `local` (the listen port) when given.
pub(crate) async fn connect_tcp(
    local: Option<SocketAddr>,
    remote: SocketAddr,
    timeout: Duration,
) -> Result<TcpStream, Error> {
    let socket = reusable(remote)?;
    if let Some(local) = local {
        socket.bind(local)?;
    }
    let stream = tokio::time::timeout(timeout, socket.connect(remote))
        .await
        .map_err(|_| Error::Timeout("TCP connect"))??;
    tune(&stream)?;
    Ok(stream)
}

/// Servers ask for BBR on their own sockets and keep the kernel default where the module is missing.
pub(crate) fn prefer_bbr(stream: &TcpStream) {
    if let Err(error) = SockRef::from(stream).set_tcp_congestion(b"bbr") {
        tracing::debug!(%error, "bbr unavailable; keeping the default congestion control");
    }
}

/// `tcp:<algorithm>` of a connected socket, for path reports.
pub(crate) fn tcp_congestion(stream: &TcpStream) -> String {
    match SockRef::from(stream).tcp_congestion() {
        Ok(name) => format!(
            "tcp:{}",
            String::from_utf8_lossy(&name).trim_end_matches('\0')
        ),
        Err(_) => "tcp:unknown".into(),
    }
}

pub(crate) fn tune(stream: &TcpStream) -> Result<(), Error> {
    stream.set_nodelay(true)?;
    SockRef::from(stream).set_tcp_keepalive(
        &TcpKeepalive::new()
            .with_time(TCP_KEEPALIVE)
            .with_interval(TCP_KEEPALIVE),
    )?;
    Ok(())
}
