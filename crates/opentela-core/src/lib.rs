//! Peer identity, rendezvous, NAT traversal and relay fallback for a fleet we operate.
//!
//! [`Node::connect`] walks a ladder (direct, UDP hole punch with QUIC, TCP simultaneous open, relay) and returns
//! a [`Connection`] that opens authenticated, end-to-end encrypted [`Stream`]s; [`Node::accept`] yields the
//! streams peers open to us. [`RendezvousServer`] and [`RelayServer`] are the two always-on services.

mod connect;
mod control;
mod identity;
mod net;
mod node;
mod preflight;
mod punch;
mod relay;
mod rendezvous;
mod services;
mod stream;
mod tls;
mod wire;

pub use connect::Connection;
pub use identity::{Keypair, PeerId, TrustPolicy};
pub use node::{Config, Node, Timeouts};
pub use preflight::{PreflightReport, RelayCheck, RendezvousCheck, StepCheck};
pub use relay::{RelayConfig, RelayLimits, RelayServer};
pub use rendezvous::{RendezvousConfig, RendezvousServer};
pub use stream::{Attempt, Outcome, PathKind, PathReport, Step, Stream, Transport};
pub use tls::{ChannelBinding, Congestion, QuicTuning};
pub use wire::DialBack;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("config: {0}")]
    Config(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    #[error("QUIC connect: {0}")]
    QuicConnect(#[from] quinn::ConnectError),
    #[error("QUIC: {0}")]
    Quic(#[from] quinn::ConnectionError),
    #[error("protocol: {0}")]
    Protocol(String),
    /// An error frame from a rendezvous or relay, or every relay failing.
    #[error("remote: {0}")]
    Remote(String),
    #[error("timed out: {0}")]
    Timeout(&'static str),
    #[error("peer {0} is not trusted")]
    Untrusted(PeerId),
    #[error("no path to {peer}: {}", summarize(attempts))]
    NoPath {
        peer: PeerId,
        attempts: Vec<Attempt>,
    },
    #[error("closed")]
    Closed,
}

fn summarize(attempts: &[Attempt]) -> String {
    attempts
        .iter()
        .map(|a| match &a.outcome {
            Outcome::Ok { .. } => format!("{:?} ok", a.step),
            Outcome::Failed { error, .. } => format!("{:?} failed ({error})", a.step),
            Outcome::Skipped { reason } => format!("{:?} skipped ({reason})", a.step),
        })
        .collect::<Vec<_>>()
        .join(", ")
}
