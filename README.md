# opentela-core

Peer identity, rendezvous, NAT traversal and relay fallback for a fleet we operate. It gives `rill-kvd`
authenticated, end-to-end encrypted byte streams to another host anywhere on the internet. Routing and PD
policy stay in Rill.

Out of scope: CRDT state, wallets, pricing, HTTP gateway, service routing, attestation.

| Crate | What |
| --- | --- |
| `crates/opentela-core` | Library linked by `rill-kvd`: `Node`, plus `RendezvousServer` and `RelayServer` |
| `crates/opentela-bin` | Binaries `rendezvous`, `relay` and `otela` (keygen, preflight, listen, bench) |

## Design

**Identity.** Each node has one Ed25519 key. Its peer id is the 32-byte public key, written as 64 hex
characters. Every connection is TLS 1.3 with RFC 7250 raw public keys. There are no certificates, CAs or
names: the key a peer shows in the handshake is its peer id. Clients pin the id they dial. Servers accept
only keys the trust policy allows.

**Trust.** `TrustPolicy` is the only place this is decided. In v1 it is `AllowList`, one operator-issued
list of peer ids that includes every node, rendezvous and relay. It is a `#[non_exhaustive]` enum, so a
later policy (for example, third-party GPUs with a signed credential) becomes a new variant without any
change to call sites. Nothing beyond the allow list is built.

**Channel binding.** `Stream::channel_binding()` returns the RFC 9266 `tls-exporter` value (label
`EXPORTER-Channel-Binding`, empty context, 32 bytes) of the end-to-end TLS session carrying the stream.
Both ends see the same value, and any other session has a different one. That includes sessions through a
relay, because the relay only forwards ciphertext. Rill can bind its HMAC transcript to this value and to
`Stream::peer()`, not to IP addresses, which NAT and relays rewrite. QUIC streams of one connection share a
session. On TCP paths each stream is its own TLS session.

**Ports.** A node binds UDP (QUIC, quinn) and TCP on the same port. Its rendezvous control connection leaves
from that port, so the TCP and UDP mappings the rendezvous observes are the ones peers punch towards.

**Connection ladder.** `Node::connect(peer)` asks every connected rendezvous for the peer's record (the first
answer wins), then tries each step in `Config::ladder` order. Each step has its own timeout, and every
attempt goes into `PathReport::attempts`:

| Step | Default timeout | How |
| --- | --- | --- |
| `Direct` | 3 s | QUIC and TCP+TLS raced to the advertised addresses. QUIC is preferred: if TCP wins, QUIC gets 500 ms more |
| `UdpPunch` | 6 s | `Lookup{punch}` makes the rendezvous tell the peer to spray UDP at our observed address. Meanwhile we send staggered QUIC dials (0, 0.2, 0.5, 1, 2, 3.5 s) to its observed and advertised addresses |
| `TcpPunch` | 6 s | Each side opens a fresh port and a rendezvous connection from it, so the rendezvous sees that port's mapping and swaps the two. Both sides then simultaneous-open. The responder also listens on its punch port, because a host with no NAT answers early SYNs with RST |
| `Relay` | 8 s per relay | TCP+TLS to a relay. The peer's relays come first (from its record), then ours. Inside the circuit, the two peers run their own TLS session. If no rendezvous is reachable, this step still works |

**Rendezvous** (`rendezvous` binary, TCP and UDP on one port). Peers register `{listen addrs, relays}` and get
back their observed TCP address. A QUIC connection from the listen socket reports the observed UDP address,
and its keepalives hold the NAT binding open. All state is soft: after a restart, peers reconnect with
backoff and register again. `DialBackRequest` makes the rendezvous dial the peer from a different port,
over TCP and over QUIC. A reply from the port the peer contacted would pass a stateful firewall and prove
nothing.

**Relay** (`relay` binary, default port 443). A peer holds a reservation, which is a long-lived control
session. To reach it, a dialer opens a TCP+TLS connection and sends `Dial{target}`. The relay pushes
`Circuit` to the target, the target opens its own connection with `Accept`, and the relay splices the two.
The relay never holds the peers' keys, so it sees only ciphertext and cannot impersonate either side.
Resources are bounded: total reservations, total circuits, circuits per peer, an idle timeout per circuit,
an accept timeout, and the number of connections in handshake. Each limit rejects with an error frame and
never queues.

**Robustness**, by failure mode:

| Failure mode | Response |
| --- | --- |
| A single pinned bootstrap address broke launchers | Any number of rendezvous and relay addresses as `host:port`, re-resolved through DNS on every reconnect. Lookups go to all of them in parallel |
| Relay reservation failures were discovered late | `Node::preflight()` / `otela preflight` reports each reservation and runs a loopback circuit through each relay within seconds |
| Rendezvous restart | Sessions ping every 10 s and count as dead after 35 s of silence. Reconnects use jittered exponential backoff (0.25 s to 30 s) and re-register |
| Relay failover | Every configured relay is tried in turn. Reservations are held on all of them |
| NAT bindings expire | QUIC keepalive every 5 s (30 s idle timeout), TCP keepalive every 15 s, control pings every 10 s |
| A second process with the same key (a preflight next to the daemon, or a restart racing the old process) | Servers keep a stack of sessions per peer. The newest one serves, and the older one takes over again when the newer one ends |
| A cancelled dial | Helper tasks live in `JoinSet`s, so a timed-out step leaks no sessions or sockets |
| Errors | `Error::NoPath` lists every step with its outcome. Remote error frames come back as `Error::Remote` |

## API

```rust
use opentela_core::{Config, Keypair, Node, TrustPolicy};

let mut config = Config::new(Keypair::load(key_path)?, TrustPolicy::load_allow_list(allow_path)?);
config.listen = "0.0.0.0:7500".parse()?;
config.rendezvous = vec!["rv1.example.org:7400".into(), "rv2.example.org:7400".into()];
config.relays = vec!["relay1.example.org:443".into(), "relay2.example.org:443".into()];
let node = Node::start(config).await?;

// Dialing side
let conn = node.connect(peer_id).await?;            // walks the ladder
let report = conn.report();                          // {kind: direct|punched|relayed, transport, via, rtt_ms, throughput_bps, attempts}
let mut streams = Vec::new();
for _ in 0..4 { streams.push(conn.open_stream().await?); }   // parallel streams for bulk transfer
conn.measure(1 << 30, 4).await?;                     // iperf-style probe; sets report.throughput_bps

// Accepting side
let stream = node.accept().await?;                   // AsyncRead + AsyncWrite
stream.peer();                                       // authenticated remote peer id
stream.channel_binding();                            // RFC 9266 tls-exporter, equal on both ends
stream.path();                                       // Direct | Punched | Relayed

// Ops
let report = node.preflight(Duration::from_secs(5)).await;  // which ladder steps work from this host
```

`Connection::is_alive()` turns false when a QUIC path closes. When that happens, call `connect` again; the
ladder takes only the time of the steps it tries. On TCP paths, every `open_stream` sets up a new
connection on the same route.

## Operating it

```sh
cargo build --release
B=target/release

# One key per node, rendezvous and relay. The allow list holds every peer id.
$B/otela keygen --out rv.key >> allow.txt
$B/otela keygen --out relay1.key >> allow.txt
$B/otela keygen --out node-a.key >> allow.txt

# Always-on public services. A host may run both. Open TCP+UDP 7400 for the rendezvous and TCP 443 for the relay.
$B/rendezvous --key rv.key --allow allow.txt --listen 0.0.0.0:7400
$B/relay --key relay1.key --allow allow.txt --listen 0.0.0.0:443 \
    --max-reservations 1024 --max-circuits 512 --max-circuits-per-peer 64 --idle-timeout-secs 120

# On a node: which ladder steps work from here? (--json for machine-readable output)
$B/otela preflight --key node-a.key --allow allow.txt \
    --rendezvous rv1.example.org:7400,rv2.example.org:7400 --relay relay1.example.org:443,relay2.example.org:443

# Bulk test between two nodes: one listens, the other benches. --ladder forces particular steps.
$B/otela listen --key node-b.key --allow allow.txt --rendezvous ... --relay ...
$B/otela bench --key node-a.key --allow allow.txt --rendezvous ... --relay ... \
    --peer <node-b id> --bytes 1073741824 --streams 8 [--ladder relay]
```

`OTELA_KEY`, `OTELA_ALLOW`, `OTELA_RENDEZVOUS` and `OTELA_RELAYS` can stand in for the matching flags.
Logging uses `tracing` and goes to stderr, filtered by `RUST_LOG` (default `info`).

Binding port 443 needs root or `CAP_NET_BIND_SERVICE` (`setcap cap_net_bind_service=+ep target/release/relay`).

## Tests

```sh
cargo test        # 9 unit + 8 in-process integration tests over loopback
```

The integration tests (`crates/opentela-core/tests/ladder.rs`) cover:

- Each ladder step forced on its own, checking the peer ids, the path label on both ends, and that the
  channel binding is equal on both ends and different across sessions (direct, punched and relayed).
- Fallthrough past an unreachable advertised address, a simulated NAT where only the observed mapping works.
- Relay with no rendezvous at all, and failover to a second relay after the first is killed.
- Re-registration after a rendezvous restart.
- Refusal of untrusted keys.
- The relay's per-peer circuit limit and idle timeout.
- A preflight that reports dead services.
- A second process with the same key leaving the first one registered.

Loopback can't exercise real NAT filtering; the real-host runs below do.

## Measured on real hosts (2026-11-15)

Test bed:

- ds6 (aarch64, 129.132.102.36, 2.5 GbE) runs the rendezvous on 7400 and two relays on 8443 and 8444. 443
  needs root there.
- sgs-gpu07 (x86_64, 172.25.4.17) reaches ds6 on a routed path with no NAT. Its inbound TCP is refused by
  its firewall, and stateful UDP is allowed. Its NAT towards the internet keeps the port (STUN:
  195.176.103.148, same port to three servers).
- CSCS compute nodes on beverin (mi200) and clariden (debug).

`otela bench` moves 1 GiB over 8 streams twice per step. The channel-binding echo matched on both ends in
every run.

| From → to | Direct | UDP punch (QUIC) | TCP punch | Relay (ds6) | Full ladder picks |
| --- | --- | --- | --- | --- | --- |
| sgs-gpu07 → ds6 | QUIC 2.23–2.30 Gbit/s, 0.15 ms | 2.23–2.27 Gbit/s | 2.34 Gbit/s, 1.0 ms | 2.33 Gbit/s, 1.2 ms | direct (QUIC) |
| ds6 → sgs-gpu07 | fails (firewall) | 2.29–2.33 Gbit/s, 0.2 ms | 2.35 Gbit/s, 1.1 ms | 2.35 Gbit/s, 1.0 ms | direct failed → UDP punch |

All four steps reach the 2.5 GbE line rate of ds6, so this pair says nothing about relay CPU limits.

**CSCS compute nodes cannot reach ds6.** TCP to ds6 on 7400, 8443 and even 22 times out from beverin and
clariden login nodes, and from beverin compute nodes. The ETH perimeter admits ds6's high ports only from
inside ETH (even the operator's laptop on 195.176.113.253 is refused). So ds6 never sees a CSCS source
address. Measured instead:

- NAT and egress. Beverin compute nodes leave through 148.187.0.208 and 148.187.0.212, a NAT pool that
  differs per node. The clariden login node leaves through 148.187.6.106. Outbound TCP to arbitrary internet
  ports (443, 8443) works. Outbound UDP from beverin compute nodes is blocked (STUN to Google and Cloudflare
  times out), so QUIC punching cannot work from there. From CSCS compute nodes only the relay step over
  TCP is viable.
- Paths through a stand-in relay. To get numbers anyway, a relay ran briefly on the CSCS login node, which
  compute nodes reach internally. sgs-gpu07 reached it through an SSH tunnel via the operator's laptop
  (sgs → laptop → CSCS login). The relay path then worked end to end, with matching channel bindings:
  beverin compute ↔ sgs-gpu07 at 0.82–0.92 Gbit/s over 1, 4 or 8 streams. The tunnel is the bottleneck, so
  this proves function, not capacity.

**What a public VM changes.** It would run the rendezvous and relays on 443 (TCP) and UDP, reachable from
CSCS compute nodes and from ETH. CSCS ↔ ETH would then go over the relay at the VM's bandwidth, with no
tunnel. Punching from CSCS compute nodes stays impossible while their UDP egress is blocked. TCP punching
might work through the CSCS NAT pool, but it is untested.

## Decisions taken here

- Peer id is the raw public key, not a hash, so no lookup is needed to verify one.
- The crypto provider is `ring`, chosen over `aws-lc-rs` so the build needs no cmake or nasm on aarch64
  and HPC images.
- The relay keeps the outer TLS on circuits, so traffic on 443 looks like TLS to middleboxes. The cost is
  double encryption at the peers, and decrypt/re-encrypt at the relay.
- TCP paths use one TLS connection per stream, with no multiplexer. Parallel streams then get independent
  congestion windows, which is what bulk transfer wants.
- TCP punching uses fresh ports per stream. Reusing the listen port allows only one connection per port
  pair, and it confuses listener and dialer roles.
- The QUIC stream receive window is 2 MiB. Above that, loss bursts at a 2.5 GbE bottleneck exceeded quinn's
  limit of 1024 reassembly gaps, and quinn then kills the connection (seen at 16 and 64 MiB). One QUIC stream
  therefore carries at most 2 MiB per RTT, so bulk transfers should use several streams. The connection
  window is 128 MiB.
- On QUIC, `PathReport::rtt_ms` is quinn's minimum RTT, because the smoothed RTT under load measures
  queueing. On TCP paths it is the duration of the TLS handshake.
- On the accepting side, `Punched` means the peer asked us to punch within the last 60 s.
- Address families: a node uses resolved addresses of the same family as its listen address (IPv4 by
  default).
- Library errors are a `thiserror` enum and the library has no `unwrap`. Logging uses `tracing`, so
  `rill-kvd` decides whether and how to install a subscriber.
