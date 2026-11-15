//! Authenticated streams and the reports describing how a peer was reached.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::identity::PeerId;
use crate::tls::ChannelBinding;

/// First byte the opener writes on every stream.
pub(crate) const HELLO_STREAM: u8 = 0;
pub(crate) const HELLO_PROBE: u8 = 1;

pub(crate) trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Quic,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PathKind {
    /// To an address the peer advertises.
    Direct,
    /// Through both NATs after a rendezvous-coordinated hole punch.
    Punched,
    /// Spliced by a relay; still end-to-end TLS between the peers.
    Relayed,
}

/// quinn's congestion controller. BBR is the default: on lossy long paths loss-based control collapses (cubic
/// moved 0.5-0.8 MB/s where BBR moved 18-20 MB/s on one), and the user-space choice needs no root or kernel module.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuicCongestion {
    #[default]
    Bbr,
    Cubic,
    NewReno,
}

impl QuicCongestion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bbr => "bbr",
            Self::Cubic => "cubic",
            Self::NewReno => "new_reno",
        }
    }
}

/// One rung of the connection ladder, tried in the configured order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Step {
    /// QUIC and TCP raced to the peer's advertised addresses.
    Direct,
    /// QUIC to the peer's observed UDP address while it sprays packets at ours.
    UdpPunch,
    /// TCP simultaneous open between both listen ports.
    TcpPunch,
    /// TCP+TLS circuit through a relay; the peer's relays first, then ours.
    Relay,
}

impl Step {
    pub const ALL: [Step; 4] = [Step::Direct, Step::UdpPunch, Step::TcpPunch, Step::Relay];
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Outcome {
    Ok { elapsed_ms: f64 },
    Failed { elapsed_ms: f64, error: String },
    Skipped { reason: String },
}

impl Outcome {
    pub(crate) fn from_result<T, E: fmt::Display>(
        elapsed: Duration,
        result: &Result<T, E>,
    ) -> Self {
        let elapsed_ms = elapsed.as_secs_f64() * 1e3;
        match result {
            Ok(_) => Self::Ok { elapsed_ms },
            Err(e) => Self::Failed {
                elapsed_ms,
                error: e.to_string(),
            },
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attempt {
    pub step: Step,
    pub outcome: Outcome,
}

/// How a connection reached its peer and what the path measured.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathReport {
    pub peer: PeerId,
    pub kind: PathKind,
    pub transport: Transport,
    /// The remote socket address, or the relay's configured address.
    pub via: String,
    /// QUIC: minimum RTT observed (unloaded path). TCP paths: duration of the TLS 1.3 handshake, about one end-to-end RTT.
    pub rtt_ms: f64,
    /// Congestion control of our end of the path: `quic:<quinn controller>` or `tcp:<kernel algorithm>` (on a
    /// relayed path, our leg to the relay).
    pub congestion: String,
    /// Set by [`crate::Connection::measure`].
    pub throughput_bps: Option<f64>,
    /// Every ladder step tried, in order, ending with the one that succeeded.
    pub attempts: Vec<Attempt>,
}

/// A bidirectional byte stream to an authenticated peer, end-to-end encrypted on every path.
pub struct Stream {
    pub(crate) io: Box<dyn Io>,
    pub(crate) peer: PeerId,
    pub(crate) binding: ChannelBinding,
    pub(crate) kind: PathKind,
    pub(crate) transport: Transport,
}

impl Stream {
    /// The remote's key, verified in the TLS handshake.
    pub fn peer(&self) -> PeerId {
        self.peer
    }

    /// RFC 9266 `tls-exporter` value of the TLS session carrying this stream; both ends see the same value.
    /// QUIC streams of one connection share a session; each TCP-path stream is its own session.
    pub fn channel_binding(&self) -> ChannelBinding {
        self.binding
    }

    /// On the accepting side, `Punched` means the peer asked us to punch within the last minute.
    pub fn path(&self) -> PathKind {
        self.kind
    }

    pub fn transport(&self) -> Transport {
        self.transport
    }
}

impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stream")
            .field("peer", &self.peer)
            .field("binding", &self.binding)
            .field("kind", &self.kind)
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.io).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
}
