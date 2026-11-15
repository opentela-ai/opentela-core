//! Control messages: length-prefixed JSON frames over an authenticated TLS stream. Frames are read exactly, so
//! the same stream can carry raw bytes afterwards (relay circuits).

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::identity::PeerId;
use crate::Error;

const MAX_FRAME: usize = 64 << 10;

/// What the rendezvous knows about a registered peer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Record {
    /// Addresses the peer advertises (its listen socket's local addresses, or configured ones).
    pub listen: Vec<SocketAddr>,
    /// Source address of its TCP control connection, which leaves from the listen port.
    pub tcp_observed: Option<SocketAddr>,
    /// Source address of its QUIC connection, which uses the listen socket.
    pub udp_observed: Option<SocketAddr>,
    /// Relays it holds a reservation on, as configured (host:port).
    pub relays: Vec<String>,
}

impl Record {
    pub(crate) fn udp_candidates(&self) -> Vec<SocketAddr> {
        dedup(self.udp_observed.iter().chain(&self.listen).copied())
    }
}

fn dedup(addrs: impl Iterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for addr in addrs {
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    out
}

/// One dial-back result from the rendezvous: can it reach us at `addr` over `transport`?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DialBack {
    pub addr: SocketAddr,
    pub transport: crate::Transport,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Msg {
    Register {
        listen: Vec<SocketAddr>,
        relays: Vec<String>,
    },
    Registered {
        observed: SocketAddr,
    },
    Observe,
    Observed {
        addr: SocketAddr,
    },
    /// Ask for a peer's record; with `punch`, the rendezvous also tells the target to spray UDP at us.
    Lookup {
        target: PeerId,
        punch: bool,
    },
    Found {
        record: Record,
    },
    PunchUdp {
        from: PeerId,
        record: Record,
    },
    /// Sent on a fresh connection whose source port is the one to punch from; answered once the target joins.
    TcpPunch {
        target: PeerId,
    },
    TcpPunchRequest {
        from: PeerId,
        addr: SocketAddr,
        token: u64,
    },
    TcpPunchAnswer {
        token: u64,
    },
    /// The other side's observed address for this punch.
    PunchAddr {
        addr: SocketAddr,
    },
    DialBackRequest,
    DialBackResult {
        results: Vec<DialBack>,
    },
    Reserve,
    Reserved,
    Dial {
        target: PeerId,
    },
    Circuit {
        from: PeerId,
        circuit: u64,
    },
    Accept {
        circuit: u64,
    },
    Spliced,
    Ping,
    Pong,
    Error {
        message: String,
    },
}

/// `id` pairs a response with its request; unsolicited pushes use 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Frame {
    pub id: u64,
    pub msg: Msg,
}

pub(crate) async fn write_frame(
    io: &mut (impl AsyncWrite + Unpin),
    id: u64,
    msg: Msg,
) -> Result<(), Error> {
    let body = serde_json::to_vec(&Frame { id, msg }).expect("frames serialize");
    assert!(
        body.len() <= MAX_FRAME,
        "frame of {} bytes exceeds the limit",
        body.len()
    );
    io.write_all(&(body.len() as u32).to_be_bytes()).await?;
    io.write_all(&body).await?;
    io.flush().await?;
    Ok(())
}

pub(crate) async fn read_frame(io: &mut (impl AsyncRead + Unpin)) -> Result<Frame, Error> {
    let len = io.read_u32().await? as usize;
    if len > MAX_FRAME {
        return Err(Error::Protocol(format!(
            "frame of {len} bytes exceeds the limit"
        )));
    }
    let mut body = vec![0u8; len];
    io.read_exact(&mut body).await?;
    serde_json::from_slice(&body).map_err(|e| Error::Protocol(format!("bad frame: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_round_trip_and_leave_trailing_bytes() {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let target = crate::Keypair::generate().peer_id();
        let msg = Msg::Lookup {
            target,
            punch: true,
        };
        write_frame(&mut a, 7, msg.clone()).await.unwrap();
        a.write_all(b"raw").await.unwrap();
        assert_eq!(read_frame(&mut b).await.unwrap(), Frame { id: 7, msg });
        let mut raw = [0u8; 3];
        b.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"raw");
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected() {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        a.write_all(&(MAX_FRAME as u32 + 1).to_be_bytes())
            .await
            .unwrap();
        assert!(matches!(read_frame(&mut b).await, Err(Error::Protocol(_))));
    }

    #[test]
    fn candidates_prefer_observed_and_dedup() {
        let listen: SocketAddr = "10.0.0.1:7000".parse().unwrap();
        let observed: SocketAddr = "1.2.3.4:7000".parse().unwrap();
        let record = Record {
            listen: vec![listen, observed],
            udp_observed: Some(observed),
            ..Default::default()
        };
        assert_eq!(record.udp_candidates(), vec![observed, listen]);
    }
}
