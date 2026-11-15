//! In-process fleets on loopback: every ladder step, fallthrough, failover, restarts, limits and preflight.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use opentela_core::{
    Config, Connection, Error, Keypair, Node, Outcome, PathKind, PeerId, RelayConfig, RelayLimits,
    RelayServer, RendezvousConfig, RendezvousServer, Step, Stream, Transport, TrustPolicy,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

const LOOPBACK: &str = "127.0.0.1:0";
const READY: Duration = Duration::from_secs(5);

struct Fleet {
    keys: Vec<Keypair>,
    trust: TrustPolicy,
}

impl Fleet {
    fn new(size: usize) -> Self {
        // RUST_LOG=opentela_core=debug shows the ladder; repeated init across tests is fine to ignore.
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init()
            .ok();
        let keys: Vec<Keypair> = (0..size).map(|_| Keypair::generate()).collect();
        let trust = TrustPolicy::AllowList(keys.iter().map(|k| k.peer_id()).collect());
        Self { keys, trust }
    }

    fn key(&self, i: usize) -> Keypair {
        // Keypair is not Clone on purpose; tests rebuild it from the same key material via a file round trip.
        let path = std::env::temp_dir().join(format!(
            "otela-test-{}-{}-{i}",
            std::process::id(),
            self.keys[i].peer_id()
        ));
        if !path.exists() {
            self.keys[i].save(&path).unwrap();
        }
        Keypair::load(&path).unwrap()
    }

    fn id(&self, i: usize) -> PeerId {
        self.keys[i].peer_id()
    }

    fn rendezvous_at(
        &self,
        i: usize,
        listen: SocketAddr,
    ) -> (SocketAddr, JoinHandle<Result<(), Error>>) {
        let server = RendezvousServer::bind(RendezvousConfig {
            keypair: self.key(i),
            trust: self.trust.clone(),
            listen,
            max_peers: 64,
        })
        .unwrap();
        let addr = server.local_addr().unwrap();
        (addr, tokio::spawn(server.run()))
    }

    fn rendezvous(&self, i: usize) -> (SocketAddr, JoinHandle<Result<(), Error>>) {
        self.rendezvous_at(i, LOOPBACK.parse().unwrap())
    }

    fn relay(&self, i: usize, limits: RelayLimits) -> (SocketAddr, JoinHandle<Result<(), Error>>) {
        let server = RelayServer::bind(RelayConfig {
            keypair: self.key(i),
            trust: self.trust.clone(),
            listen: LOOPBACK.parse().unwrap(),
            limits,
        })
        .unwrap();
        let addr = server.local_addr().unwrap();
        (addr, tokio::spawn(server.run()))
    }

    async fn node(
        &self,
        i: usize,
        rendezvous: &[SocketAddr],
        relays: &[SocketAddr],
        ladder: &[Step],
    ) -> Node {
        let mut config = Config::new(self.key(i), self.trust.clone());
        config.listen = LOOPBACK.parse().unwrap();
        config.rendezvous = rendezvous.iter().map(|a| a.to_string()).collect();
        config.relays = relays.iter().map(|a| a.to_string()).collect();
        config.ladder = ladder.to_vec();
        Node::start(config).await.unwrap()
    }
}

/// Opens a stream from `conn`, sends a message, and returns both ends.
async fn pair(conn: &Connection, server: &Node) -> (Stream, Stream) {
    let mut ours = conn.open_stream().await.unwrap();
    ours.write_all(b"ping").await.unwrap();
    ours.flush().await.unwrap();
    let mut theirs = tokio::time::timeout(READY, server.accept())
        .await
        .unwrap()
        .unwrap();
    let mut buf = [0u8; 4];
    theirs.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    (ours, theirs)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_step_authenticates_and_binds_the_channel() {
    let fleet = Fleet::new(4);
    let (rv, _rv_task) = fleet.rendezvous(0);
    let (relay, _relay_task) = fleet.relay(1, RelayLimits::default());
    let b = fleet.node(3, &[rv], &[relay], &Step::ALL).await;
    b.preflight(READY).await;
    let cases = [
        (Step::Direct, PathKind::Direct, Transport::Quic),
        (Step::UdpPunch, PathKind::Punched, Transport::Quic),
        (Step::TcpPunch, PathKind::Punched, Transport::Tcp),
        (Step::Relay, PathKind::Relayed, Transport::Tcp),
    ];
    let mut bindings = HashSet::new();
    for (step, kind, transport) in cases {
        let a = fleet.node(2, &[rv], &[relay], &[step]).await;
        a.preflight(READY).await;
        let conn = a
            .connect(fleet.id(3))
            .await
            .unwrap_or_else(|e| panic!("{step:?}: {e}"));
        let report = conn.report();
        assert_eq!(
            (report.kind, report.transport),
            (kind, transport),
            "{step:?}: {report:?}"
        );
        assert!(report.attempts.last().unwrap().outcome.is_ok());
        match transport {
            Transport::Quic => assert_eq!(report.congestion, "quic:bbr"),
            Transport::Tcp => assert!(report.congestion.starts_with("tcp:"), "{report:?}"),
        }

        let (s1, r1) = pair(&conn, &b).await;
        assert_eq!(s1.peer(), fleet.id(3));
        assert_eq!(r1.peer(), fleet.id(2));
        assert_eq!(
            s1.channel_binding(),
            r1.channel_binding(),
            "{step:?}: ends of one session agree"
        );
        assert_eq!(r1.path(), kind, "{step:?}: accepting side labels the path");
        let (s2, r2) = pair(&conn, &b).await;
        assert_eq!(s2.channel_binding(), r2.channel_binding());
        match transport {
            Transport::Quic => assert_eq!(
                s1.channel_binding(),
                s2.channel_binding(),
                "QUIC streams share a session"
            ),
            Transport::Tcp => assert_ne!(
                s1.channel_binding(),
                s2.channel_binding(),
                "each TCP stream is its own session"
            ),
        }
        assert!(
            bindings.insert(s1.channel_binding()),
            "{step:?}: binding reused across sessions"
        );
        assert!(bindings.insert(s2.channel_binding()) || transport == Transport::Quic);

        let bps = conn.measure(8 << 20, 2).await.unwrap();
        assert!(bps > 0.0);
        assert_eq!(conn.report().throughput_bps, Some(bps));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ladder_falls_through_an_unreachable_advertised_address() {
    let fleet = Fleet::new(3);
    let (rv, _rv_task) = fleet.rendezvous(0);
    let mut config = Config::new(fleet.key(2), fleet.trust.clone());
    config.listen = LOOPBACK.parse().unwrap();
    config.rendezvous = vec![rv.to_string()];
    // Simulated NAT: the advertised address goes nowhere; only the observed mapping works.
    config.advertise = vec!["127.0.0.1:9".parse().unwrap()];
    let b = Node::start(config).await.unwrap();
    b.preflight(READY).await;
    let a = fleet.node(1, &[rv], &[], &Step::ALL).await;
    a.preflight(READY).await;
    let conn = a.connect(fleet.id(2)).await.unwrap();
    let report = conn.report();
    assert_eq!(report.kind, PathKind::Punched, "{report:?}");
    assert!(
        matches!(report.attempts[0].outcome, Outcome::Failed { .. }),
        "{report:?}"
    );
    pair(&conn, &b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_works_without_any_rendezvous_and_fails_over() {
    let fleet = Fleet::new(4);
    let (relay1, relay1_task) = fleet.relay(0, RelayLimits::default());
    let (relay2, _relay2_task) = fleet.relay(1, RelayLimits::default());
    let b = fleet.node(3, &[], &[relay1, relay2], &Step::ALL).await;
    let a = fleet.node(2, &[], &[relay1, relay2], &Step::ALL).await;
    for node in [&a, &b] {
        let report = node.preflight(READY).await;
        assert!(
            report.relays.iter().all(|r| r.loopback.is_ok()),
            "{report:?}"
        );
    }
    let conn = a.connect(fleet.id(3)).await.unwrap();
    assert_eq!(conn.report().via, relay1.to_string());
    pair(&conn, &b).await;

    relay1_task.abort();
    let _ = relay1_task.await;
    let conn = a.connect(fleet.id(3)).await.unwrap();
    let report = conn.report();
    assert_eq!(
        (report.kind, report.via.as_str()),
        (PathKind::Relayed, relay2.to_string().as_str()),
        "{report:?}"
    );
    let (s, r) = pair(&conn, &b).await;
    assert_eq!(s.channel_binding(), r.channel_binding());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peers_reregister_after_a_rendezvous_restart() {
    let fleet = Fleet::new(3);
    let (rv, rv_task) = fleet.rendezvous(0);
    let a = fleet.node(1, &[rv], &[], &[Step::Direct]).await;
    let b = fleet.node(2, &[rv], &[], &[Step::Direct]).await;
    a.preflight(READY).await;
    b.preflight(READY).await;
    a.connect(fleet.id(2)).await.unwrap();

    rv_task.abort();
    let _ = rv_task.await;
    assert!(
        a.connect(fleet.id(2)).await.is_err(),
        "nobody to look the peer up with"
    );
    let mut restarted = None;
    for _ in 0..50 {
        match RendezvousServer::bind(RendezvousConfig {
            keypair: fleet.key(0),
            trust: fleet.trust.clone(),
            listen: rv,
            max_peers: 64,
        }) {
            Ok(server) => {
                restarted = Some(tokio::spawn(server.run()));
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let _restarted = restarted.expect("rendezvous port frees up");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    loop {
        match a.connect(fleet.id(2)).await {
            Ok(conn) => {
                pair(&conn, &b).await;
                break;
            }
            Err(e) if tokio::time::Instant::now() < deadline => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => panic!("never re-registered: {e}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn untrusted_peers_are_refused() {
    let fleet = Fleet::new(3);
    let (rv, _rv_task) = fleet.rendezvous(0);
    let b = fleet.node(2, &[rv], &[], &Step::ALL).await;
    b.preflight(READY).await;
    let outsider = Keypair::generate();
    let mut ids: HashSet<PeerId> = (0..3).map(|i| fleet.id(i)).collect();
    ids.insert(outsider.peer_id());
    let mut config = Config::new(outsider, TrustPolicy::AllowList(ids));
    config.listen = LOOPBACK.parse().unwrap();
    config.rendezvous = vec![rv.to_string()];
    let intruder = Node::start(config).await.unwrap();
    let report = intruder.preflight(Duration::from_secs(2)).await;
    assert!(
        !report.rendezvous[0].control.is_ok(),
        "rendezvous must refuse an unlisted key"
    );
    let a = fleet.node(1, &[rv], &[], &Step::ALL).await;
    assert!(matches!(
        a.connect(Keypair::generate().peer_id()).await,
        Err(Error::Untrusted(_))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_enforces_circuit_and_idle_limits() {
    let fleet = Fleet::new(3);
    let limits = RelayLimits {
        max_circuits_per_peer: 1,
        idle_timeout: Duration::from_millis(500),
        ..RelayLimits::default()
    };
    let (relay, _relay_task) = fleet.relay(0, limits);
    let b = fleet.node(2, &[], &[relay], &[Step::Relay]).await;
    let a = fleet.node(1, &[], &[relay], &[Step::Relay]).await;
    b.preflight(READY).await;
    a.preflight(READY).await;
    let conn = a.connect(fleet.id(2)).await.unwrap();
    let (_s, mut r) = pair(&conn, &b).await;
    let second = conn.open_stream().await;
    assert!(
        second.is_err(),
        "a second circuit exceeds the per-peer limit"
    );
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), r.read(&mut buf))
        .await
        .expect("idle circuit is closed");
    assert!(matches!(read, Ok(0) | Err(_)));
    // The idle circuit released its slot.
    let conn = a.connect(fleet.id(2)).await.unwrap();
    pair(&conn, &b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preflight_reports_every_step_on_loopback() {
    let fleet = Fleet::new(4);
    let (rv1, _t1) = fleet.rendezvous(0);
    let (rv2, _t2) = fleet.rendezvous(1);
    let (relay, _t3) = fleet.relay(2, RelayLimits::default());
    let node = fleet
        .node(
            3,
            &[rv1, rv2, "127.0.0.1:9".parse().unwrap()],
            &[relay, "127.0.0.1:9".parse().unwrap()],
            &Step::ALL,
        )
        .await;
    let report = node.preflight(READY).await;
    for step in &report.steps {
        assert!(step.usable, "{step:?} in {report:#?}");
    }
    assert!(report.rendezvous[0].dial_back.iter().any(|d| d.reachable));
    assert!(
        !report.rendezvous[2].control.is_ok(),
        "dead rendezvous is reported, not hidden"
    );
    assert!(
        !report.relays[1].reservation.is_ok(),
        "dead relay is reported, not hidden"
    );
    assert_eq!(report.rendezvous[0].udp_observed, Some(node.local_addr()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_process_with_the_same_key_does_not_unregister_the_first() {
    let fleet = Fleet::new(4);
    let (rv, _rv_task) = fleet.rendezvous(0);
    let (relay, _relay_task) = fleet.relay(1, RelayLimits::default());
    let b = fleet.node(3, &[rv], &[relay], &Step::ALL).await;
    b.preflight(READY).await;
    let preflight = fleet.node(3, &[rv], &[relay], &Step::ALL).await;
    assert!(preflight
        .preflight(READY)
        .await
        .steps
        .iter()
        .all(|s| s.usable));
    drop(preflight);
    tokio::time::sleep(Duration::from_millis(500)).await;
    for step in [Step::UdpPunch, Step::Relay] {
        let a = fleet.node(2, &[rv], &[relay], &[step]).await;
        a.preflight(READY).await;
        let conn = a
            .connect(fleet.id(3))
            .await
            .unwrap_or_else(|e| panic!("{step:?}: {e}"));
        pair(&conn, &b).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dial_back_only_targets_addresses_the_rendezvous_observed() {
    let fleet = Fleet::new(2);
    let (rv, _rv_task) = fleet.rendezvous(0);
    // A bystander the client "advertises"; the rendezvous must never connect to it.
    let bystander = tokio::net::TcpListener::bind(LOOPBACK).await.unwrap();
    let bystander_addr = bystander.local_addr().unwrap();
    let mut config = Config::new(fleet.key(1), fleet.trust.clone());
    config.listen = LOOPBACK.parse().unwrap();
    config.rendezvous = vec![rv.to_string()];
    config.advertise = vec![bystander_addr; 20];
    let node = Node::start(config).await.unwrap();
    let report = node.preflight(READY).await;
    let check = &report.rendezvous[0];
    let observed: Vec<SocketAddr> = check
        .tcp_observed
        .iter()
        .chain(&check.udp_observed)
        .copied()
        .collect();
    assert!(!check.dial_back.is_empty());
    assert!(
        check.dial_back.iter().all(|d| observed.contains(&d.addr)),
        "{check:?}"
    );
    let probed = tokio::time::timeout(Duration::from_millis(500), bystander.accept()).await;
    assert!(
        probed.is_err(),
        "rendezvous dialed a client-supplied address"
    );
}
