//! Control messages: length-prefixed JSON frames over an authenticated TLS stream. Frames are read exactly, so
//! the same stream can carry raw bytes afterwards (relay circuits).

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::identity::PeerId;
use crate::Error;

const MAX_FRAME: usize = 64 << 10;
const MAX_ERROR_TEXT: usize = 256;
const MAX_LISTEN: usize = 8;
const MAX_PUNCH_TARGETS: usize = 4;
const MAX_RELAYS: usize = 8;
/// A DNS name plus `:port`.
const MAX_RELAY_NAME: usize = 260;

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
    /// The observed UDP address first, then advertised ones; at most `MAX_PUNCH_TARGETS`, which bounds how
    /// many hosts a punch request can make us send packets to.
    pub(crate) fn udp_candidates(&self) -> Vec<SocketAddr> {
        let mut candidates = dedup(self.udp_observed.iter().chain(&self.listen).copied());
        candidates.truncate(MAX_PUNCH_TARGETS);
        candidates
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

/// What a raw circuit connection asks the relay for; signed by the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Purpose {
    Dial { target: PeerId },
    Accept { circuit: u64 },
}

/// One dial-back result: could the rendezvous reach us, from another port, at an address it observed for us?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DialBack {
    pub addr: SocketAddr,
    pub transport: crate::Transport,
    pub reachable: bool,
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
    Circuit {
        from: PeerId,
        circuit: u64,
    },
    /// Raw circuit admission (see `circuit.rs`); nonces and signatures are hex.
    CircuitHello {
        from: PeerId,
        nonce: String,
    },
    CircuitChallenge {
        relay: PeerId,
        nonce: String,
        signature: String,
    },
    CircuitAuth {
        purpose: Purpose,
        signature: String,
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
    if body.len() > MAX_FRAME {
        return Err(Error::Protocol(format!(
            "frame of {} bytes exceeds the limit",
            body.len()
        )));
    }
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
    let mut frame: Frame =
        serde_json::from_slice(&body).map_err(|e| Error::Protocol(format!("bad frame: {e}")))?;
    if let Msg::Error { message } = &mut frame.msg {
        truncate(message);
    }
    Ok(frame)
}

fn truncate(text: &mut String) {
    if text.len() > MAX_ERROR_TEXT {
        let mut end = MAX_ERROR_TEXT;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
}

impl Msg {
    /// An error frame. The text is capped, and callers never put peer-supplied content in it.
    pub(crate) fn error(text: impl Into<String>) -> Self {
        let mut message = text.into();
        truncate(&mut message);
        Self::Error { message }
    }

    /// The variant's wire name, to describe an unexpected message without echoing its content.
    pub(crate) fn kind(&self) -> String {
        match serde_json::to_value(self)
            .expect("messages serialize")
            .get("type")
        {
            Some(serde_json::Value::String(kind)) => kind.clone(),
            _ => unreachable!("Msg is internally tagged by `type`"),
        }
    }
}

/// Keeps what a peer may make us store or act on small: at most `MAX_LISTEN` advertised addresses (no
/// unspecified, multicast or broadcast ones, no port 0) and `MAX_RELAYS` relay names of sane length.
pub(crate) fn sanitize_registration(listen: &mut Vec<SocketAddr>, relays: &mut Vec<String>) {
    listen.retain(|a| {
        let ip = a.ip();
        a.port() != 0
            && !ip.is_unspecified()
            && !ip.is_multicast()
            && ip != std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
    });
    listen.truncate(MAX_LISTEN);
    relays.retain(|r| r.len() <= MAX_RELAY_NAME);
    relays.truncate(MAX_RELAYS);
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

    #[tokio::test]
    async fn oversized_outgoing_frame_is_an_error_not_a_panic() {
        let (mut a, _b) = tokio::io::duplex(1 << 16);
        let huge = Msg::Register {
            listen: Vec::new(),
            relays: vec!["r".repeat(MAX_FRAME)],
        };
        assert!(matches!(
            write_frame(&mut a, 1, huge).await,
            Err(Error::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn error_text_is_capped_on_both_sides() {
        let Msg::Error { message } = Msg::error("é".repeat(1000)) else {
            unreachable!()
        };
        assert!(message.len() <= MAX_ERROR_TEXT);
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let body = serde_json::to_vec(&Frame {
            id: 1,
            msg: Msg::Error {
                message: "x".repeat(10_000),
            },
        })
        .unwrap();
        a.write_all(&(body.len() as u32).to_be_bytes())
            .await
            .unwrap();
        a.write_all(&body).await.unwrap();
        let Msg::Error { message } = read_frame(&mut b).await.unwrap().msg else {
            unreachable!()
        };
        assert_eq!(message.len(), MAX_ERROR_TEXT);
        assert_eq!(
            Msg::Lookup {
                target: crate::Keypair::generate().peer_id(),
                punch: true
            }
            .kind(),
            "lookup"
        );
    }

    #[test]
    fn registrations_are_capped_and_filtered() {
        let mut listen: Vec<SocketAddr> = (1..=20)
            .map(|p| SocketAddr::from(([10, 0, 0, 1], p)))
            .collect();
        listen.insert(0, "0.0.0.0:7000".parse().unwrap());
        listen.insert(0, "224.0.0.1:7000".parse().unwrap());
        listen.insert(0, "10.0.0.2:0".parse().unwrap());
        let mut relays = vec!["x".repeat(1000), "relay:443".into()];
        sanitize_registration(&mut listen, &mut relays);
        assert_eq!(listen.len(), MAX_LISTEN);
        assert_eq!(listen[0], SocketAddr::from(([10, 0, 0, 1], 1)));
        assert_eq!(relays, vec!["relay:443".to_string()]);
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
        let many = Record {
            listen: (1..=8)
                .map(|p| SocketAddr::from(([10, 0, 0, 1], p)))
                .collect(),
            udp_observed: Some(observed),
            ..Default::default()
        };
        let capped = many.udp_candidates();
        assert_eq!(capped.len(), MAX_PUNCH_TARGETS);
        assert_eq!(capped[0], observed);
    }
}
