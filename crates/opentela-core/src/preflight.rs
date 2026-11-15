//! Fast answer to "which ladder steps can work from this host", from the node's live sessions plus a
//! rendezvous dial-back and a relayed loopback circuit.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::task::JoinSet;

use crate::connect::relay_loopback;
use crate::identity::PeerId;
use crate::node::{Node, Slot, SlotStatus};
use crate::stream::{Outcome, Step};
use crate::wire::{DialBack, Msg};

const POLL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Serialize)]
pub struct RendezvousCheck {
    pub addr: String,
    /// TCP+TLS registration; `elapsed_ms` is the TLS handshake.
    pub control: Outcome,
    /// QUIC from the listen socket; failing means UDP egress is blocked.
    pub quic: Outcome,
    pub tcp_observed: Option<SocketAddr>,
    pub udp_observed: Option<SocketAddr>,
    /// The rendezvous dialing us back as an unrelated host would.
    pub dial_back: Vec<DialBack>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayCheck {
    pub addr: String,
    pub reservation: Outcome,
    /// A circuit to ourselves through this relay, round-tripping an empty probe.
    pub loopback: Outcome,
}

#[derive(Debug, Clone, Serialize)]
pub struct StepCheck {
    pub step: Step,
    pub usable: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreflightReport {
    pub peer: PeerId,
    pub local: SocketAddr,
    pub rendezvous: Vec<RendezvousCheck>,
    pub relays: Vec<RelayCheck>,
    pub steps: Vec<StepCheck>,
}

/// Waits until `ready` holds for the slot's status or `deadline` passes; returns the last status.
async fn settle(slot: &Slot, deadline: Instant, ready: impl Fn(&SlotStatus) -> bool) -> SlotStatus {
    loop {
        let status = slot.status();
        if ready(&status) || Instant::now() >= deadline {
            return status;
        }
        tokio::time::sleep(POLL).await;
    }
}

fn session_outcome(connected: bool, handshake: Option<Duration>, error: Option<String>) -> Outcome {
    match (connected, handshake) {
        (true, Some(handshake)) => Outcome::Ok {
            elapsed_ms: handshake.as_secs_f64() * 1e3,
        },
        _ => Outcome::Failed {
            elapsed_ms: 0.0,
            error: error.unwrap_or_else(|| "not connected yet".into()),
        },
    }
}

impl Node {
    /// Reports what works from here. Waits up to `wait` for background sessions to come up first.
    pub async fn preflight(&self, wait: Duration) -> PreflightReport {
        let inner = &self.inner;
        let deadline = Instant::now() + wait;
        let mut rendezvous = Vec::new();
        for slot in &inner.rendezvous {
            let status = settle(slot, deadline, |s| {
                s.connected && (s.udp_observed.is_some() || s.quic_error.is_some())
            })
            .await;
            let dial_back = match slot.control() {
                Some(control) => match control
                    .request(Msg::DialBackRequest, inner.timeouts.control * 2)
                    .await
                {
                    Ok(Msg::DialBackResult { results }) => results,
                    _ => Vec::new(),
                },
                None => Vec::new(),
            };
            let quic = match (status.udp_observed, &status.quic_error) {
                (Some(_), _) => Outcome::Ok { elapsed_ms: 0.0 },
                (None, error) => Outcome::Failed {
                    elapsed_ms: 0.0,
                    error: error.clone().unwrap_or_else(|| "no answer yet".into()),
                },
            };
            rendezvous.push(RendezvousCheck {
                addr: slot.addr.clone(),
                control: session_outcome(status.connected, status.handshake, status.error.clone()),
                quic,
                tcp_observed: status.tcp_observed,
                udp_observed: status.udp_observed,
                dial_back,
            });
        }
        let mut loopbacks = JoinSet::new();
        for (i, slot) in inner.relays.iter().enumerate() {
            let status = settle(slot, deadline, |s| s.connected).await;
            let node = inner.clone();
            let addr = slot.addr.clone();
            loopbacks.spawn(async move {
                let loopback = if status.connected {
                    let started = Instant::now();
                    let result = relay_loopback(&node, &addr).await;
                    match result {
                        Ok(rtt) => Outcome::Ok {
                            elapsed_ms: rtt.as_secs_f64() * 1e3,
                        },
                        Err(e) => Outcome::from_result::<(), _>(started.elapsed(), &Err(e)),
                    }
                } else {
                    Outcome::Skipped {
                        reason: "no reservation".into(),
                    }
                };
                (
                    i,
                    RelayCheck {
                        addr,
                        reservation: session_outcome(
                            status.connected,
                            status.handshake,
                            status.error,
                        ),
                        loopback,
                    },
                )
            });
        }
        let mut relays: Vec<_> = loopbacks.join_all().await;
        relays.sort_by_key(|(i, _)| *i);
        let relays: Vec<RelayCheck> = relays.into_iter().map(|(_, check)| check).collect();
        let steps = verdicts(inner.local, &rendezvous, &relays);
        PreflightReport {
            peer: inner.id,
            local: inner.local,
            rendezvous,
            relays,
            steps,
        }
    }
}

fn verdicts(
    local: SocketAddr,
    rendezvous: &[RendezvousCheck],
    relays: &[RelayCheck],
) -> Vec<StepCheck> {
    let reachable: Vec<String> = rendezvous
        .iter()
        .flat_map(|r| &r.dial_back)
        .filter(|d| d.reachable)
        .map(|d| format!("{} over {:?}", d.addr, d.transport))
        .collect();
    let direct = if reachable.is_empty() {
        StepCheck { step: Step::Direct, usable: false, detail: "no rendezvous could dial us back: peers reach us only by punching or relay (we can still dial public peers)".into() }
    } else {
        StepCheck {
            step: Step::Direct,
            usable: true,
            detail: format!("inbound reachable at {}", reachable.join(", ")),
        }
    };
    let mapping = |step: Step, observed: Vec<SocketAddr>, what: &str| {
        let mut distinct = observed.clone();
        distinct.sort();
        distinct.dedup();
        match distinct.as_slice() {
            [] => StepCheck { step, usable: false, detail: format!("no rendezvous observed our {what} address") },
            [one] => {
                let nat = if one.port() == local.port() { "port preserved" } else { "NAT rewrites the port" };
                StepCheck { step, usable: true, detail: format!("{what} mapping {one} ({nat}, seen by {} rendezvous)", observed.len()) }
            }
            many => StepCheck { step, usable: false, detail: format!("{what} mapping differs per destination ({many:?}): symmetric NAT, punching will likely fail") },
        }
    };
    let udp = mapping(
        Step::UdpPunch,
        rendezvous.iter().filter_map(|r| r.udp_observed).collect(),
        "UDP",
    );
    let tcp = mapping(
        Step::TcpPunch,
        rendezvous.iter().filter_map(|r| r.tcp_observed).collect(),
        "TCP",
    );
    let working: Vec<String> = relays
        .iter()
        .filter_map(|r| match r.loopback {
            Outcome::Ok { elapsed_ms } => Some(format!("{} ({elapsed_ms:.1} ms loopback)", r.addr)),
            _ => None,
        })
        .collect();
    let relay = if working.is_empty() {
        StepCheck {
            step: Step::Relay,
            usable: false,
            detail: "no relay completed a loopback circuit".into(),
        }
    } else {
        StepCheck {
            step: Step::Relay,
            usable: true,
            detail: format!("via {}", working.join(", ")),
        }
    };
    vec![direct, udp, tcp, relay]
}
