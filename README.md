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
| `Relay` | 8 s per relay | TCP to a relay, admitted by a signed preamble. The peer's relays come first (from its record), then ours. Inside the circuit, the two peers run their own TLS session. If no rendezvous is reachable, this step still works |

**Rendezvous** (`rendezvous` binary, TCP and UDP on one port). Peers register `{listen addrs, relays}` and get
back their observed TCP address. A QUIC connection from the listen socket reports the observed UDP address,
and its keepalives hold the NAT binding open. All state is soft: after a restart, peers reconnect with
backoff and register again. `DialBackRequest` makes the rendezvous dial the peer from a different port,
over TCP and over QUIC. It dials only the addresses it observed for the peer, never ones the peer
supplied, and it answers with one boolean per address. A reply from the port the peer contacted would
pass a stateful firewall and prove nothing.

**Relay** (`relay` binary, default port 443). A peer holds a reservation, which is a long-lived TLS control
session. Circuits do not use an outer TLS layer. A dialer opens a plain TCP connection and proves its key
in a signed preamble, asking to `Dial` the target. The relay pushes `Circuit` to the target, the target
opens its own connection with the same preamble to `Accept`, and the relay copies bytes between the two.
From then on a circuit carries only the peers' own TLS 1.3 session, and the relay neither decrypts nor
re-encrypts it. The relay never holds the peers' keys, so it sees only ciphertext and cannot impersonate
either side. Both kinds of connection share the port: a TLS record starts with 0x16, and a circuit starts
with `OTELACIR`.

How circuits are admitted (`crates/opentela-core/src/circuit.rs`):

1. The client sends `OTELACIR` and `{client id, client nonce}`.
2. The relay answers `{relay id, relay nonce, relay signature}`, signed over (label, both ids, both
   nonces). This proves the relay is a trusted one.
3. The client answers `{purpose, client signature}`, signed over (label, both ids, both nonces, purpose).
   The purpose is `Dial{target}` or `Accept{circuit}`.

The relay admits only allow-listed keys whose signature verifies.

- **Replay.** The relay's nonce is fresh per connection, so a recorded preamble fails.
- **Confused deputy.** The relay's id and nonce are in the signed transcript, so a signature a client
  made for one relay (even a trusted one acting maliciously) is useless at another.
- **Purpose.** The purpose is signed, so a Dial can't be relabelled as an Accept, or pointed at another
  target.
- **Accept.** An `Accept` is honoured only for the peer the circuit was offered to.

Tests cover replay, cross-relay reuse, purpose rewriting and untrusted keys on either side.

What is visible: the preamble is plaintext, so an observer sees both peer ids, the target peer id or
circuit number, and the relay's error messages. Payload stays end-to-end encrypted. An on-path attacker
can still reset or blackhole a circuit, but could do that to TCP anyway. Middleboxes see the 8-byte magic
and two short JSON frames before the TLS ClientHello. Every network in the matrix carried it on 443
unchanged (CSCS compute, mit3090, sgs-gpu07, ds6). A box that insists the first byte on 443 is TLS would
block circuits.
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
| Abuse by an allow-listed peer | Frames are capped at 64 KiB. Error frames carry fixed text of at most 256 bytes, never peer content. A registration keeps at most 8 advertised addresses (no unspecified, multicast, broadcast or port 0) and at most 8 relay names. Dial-back only targets addresses the rendezvous observed itself. UDP spraying goes to at most 4 targets, observed address first, with one active spray per peer. Registry cleanup runs in drop guards, so a panicking handler cannot leak slots |

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
let report = conn.report();                          // {kind: direct|punched|relayed, transport, via, rtt_ms, congestion, throughput_bps, attempts}
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

Binding port 443 needs root or `CAP_NET_BIND_SERVICE`.

### systemd

`deploy/systemd/` has the two units. They run under `DynamicUser`, read their key and allow list through
`LoadCredential`, get `CAP_NET_BIND_SERVICE` for 443, and cap memory with `MemoryMax`. To install them:

```sh
install -m755 target/release/{rendezvous,relay,otela} /usr/local/bin/
mkdir -m700 /etc/opentela && cd /etc/opentela
otela keygen --out rendezvous.key; otela keygen --out relay.key   # add both ids to allow.txt
cp allow.txt /etc/opentela/allow.txt
cp deploy/systemd/otela-*.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now otela-rendezvous otela-relay
```

The rendezvous listens on TCP+UDP 8443 and the relay on TCP 443. To stop and remove them:

```sh
systemctl disable --now otela-rendezvous otela-relay
rm /etc/systemd/system/otela-{rendezvous,relay}.service && systemctl daemon-reload
rm -r /etc/opentela /usr/local/bin/{rendezvous,relay,otela}
```

A changed allow list takes effect after `systemctl restart otela-rendezvous otela-relay`.

## Tests

```sh
cargo test        # 18 unit + 9 in-process integration + 1 CLI test
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
- The rendezvous never dialing a client-advertised address during dial-back.

Unit tests cover the hardening: oversized outgoing frames return an error instead of panicking, error text
is capped on both sides, registrations are capped and filtered, punch targets are capped, and cleanup
guards run on panic.

Loopback can't exercise real NAT filtering; the real-host runs below do.

## Measured on real hosts (2026-11-15)

Primary rendezvous and relay: 85.90.245.236. It is a public IP on eth0 with no NAT, 1 vCPU and 2 GB RAM,
and runs the systemd units above: rendezvous on TCP+UDP 8443, relay on TCP 443, with kernel bbr on their
own sockets. ocf-1 was not used.

`otela bench` runs twice per cell, 256 MiB from mit3090 and 512 MiB from CSCS. Throughput is shown as
`run1/run2` in Gbit/s. RTT is the minimum QUIC RTT, or the TLS handshake time on TCP. The channel-binding
echo matched on both ends in every run. Congestion control (cc) is our end's: `quic:bbr` is quinn's BBR
(the new default), and `tcp:cubic` is the hosts' kernel default (they have no bbr module).

| Pair | Full ladder picks | cc | RTT | 1 stream | 4 streams | 8 streams |
| --- | --- | --- | --- | --- | --- | --- |
| clariden compute (aarch64) → sgs-gpu07 | relay (direct, UDP and TCP punch fail) | tcp:cubic | 16 ms | 3.06/2.28 | 3.11/2.45 | 2.66/2.47 |
| beverin compute (mi200) → sgs-gpu07 | relay (same) | tcp:cubic | 16.5 ms | 3.11/2.23 | 3.05/2.49 | 2.88/2.72 |
| mit3090 → sgs-gpu07 | UDP punch (QUIC) | quic:bbr | 81 ms | 0.18/0.18 | 0.57/0.57 | 0.67/0.90 |
| mit3090 → sgs-gpu07, TCP punch forced | TCP punch | tcp:cubic | 84 ms | 0.26/0.26 | 0.70/0.70 | 0.76/0.75 |
| mit3090 → sgs-gpu07, relay forced | relay | tcp:cubic | 96 ms | 0.24/0.25 | 0.48/0.56 | 0.64/0.63 |
| mit3090 → ds6 | UDP punch (QUIC) | quic:bbr | 81 ms | 0.17/0.18 | 0.56/0.72 | 0.68/0.90 |
| mit3090 → ds6, TCP punch forced | TCP punch | tcp:cubic | 84 ms | 0.26/0.26 | 0.62/0.54 | 0.63/0.76 |
| mit3090 → ds6, relay forced | relay | tcp:cubic | 95 ms | 0.24/0.24 | 0.54/0.69 | 0.72/0.45 |
| ds6 → sgs-gpu07, relay forced | relay | tcp:cubic | 15 ms | 1.98–2.11 | – | 1.4–2.2 (6 runs) |
| sgs-gpu07 ↔ ds6 (inside ETH, before the VM) | direct / UDP punch | – | 0.15 ms | – | – | 2.23–2.35, line rate of ds6's 2.5 GbE |

Findings:

- **CSCS compute nodes** on beverin and clariden leave through a NAT pool (148.187.0.208 and
  148.187.0.212, one address per node). They reach the VM on TCP 443 and 8443. All UDP egress is blocked
  (QUIC to the rendezvous and STUN to Google and Cloudflare both time out), so UDP punching is impossible.
  TCP punching through the NAT pool was tried with the VM as rendezvous and failed every time (6 s
  timeout, 1, 4 and 8 streams, both clusters). The pool keeps the listen port's mapping (`port
  preserved`) but does not admit the peer's SYNs to fresh punch ports. CSCS ↔ anything therefore goes
  through the relay, and the ladder reaches it in about 15 s.
- **mit3090** (public, no NAT, firewalled inbound) and **sgs-gpu07** (port-preserving NAT) punch UDP to
  each other, and TCP punching works too. ds6 also punches with mit3090, even though the ETH perimeter
  refuses mit3090's unsolicited packets. A single QUIC stream is capped at 2 MiB per RTT, about 0.2
  Gbit/s at 81 ms (see Decisions), so use 8 or more streams. The mit3090 path tops out near 0.9 Gbit/s
  on every step.
- **Relay CPU, before and after dropping the outer TLS on circuits.** Both relays ran on the same VM at
  the same time (the old one on 443, the new one on 4443). Each CSCS node ran on its own, two rounds,
  with 2 GiB per run. The figures are relay process CPU on the single vCPU, then Gbit/s:

  | Pair | Streams | Outer TLS (before) | Raw splice (after) |
  | --- | --- | --- | --- |
  | clariden compute → sgs-gpu07 | 1 | 53–59%, 2.07–2.23 | 17–18%, 2.10–2.12 |
  | | 4 | 58–73%, 1.69–2.11 | 16–22%, 2.08–2.12 |
  | | 8 | 78–80%, 2.13–2.22 | 30–32%, 2.18–2.21 |
  | beverin compute → sgs-gpu07 | 1 | 51–55%, 2.07–2.23 | 16–26%, 1.78–2.24 |
  | | 4 | 56–61%, 2.07–2.12 | 17–19%, 2.11 |
  | | 8 | 68–80%, 1.53–2.22 | 32–33%, 2.15–2.20 |

  Relay CPU per byte fell about 3×, and the channel binding matched in every run. Throughput did not
  rise: both modes sit at a ceiling of about 2.2 Gbit/s that is not the relay. It is the VM's network or
  the ETH ingress to sgs-gpu07. The relay now leaves most of the core to the VM's other tenants, and the
  `ocf` process uses 30–40%. RSS stays around 11 MB.
- **A real bug found here:** one in three relayed 8-stream transfers stalled for about 120 s. The relay
  did not flush TLS after a write, so the tail of a burst sat in rustls until the idle timeout. This is
  fixed with a regression test. Since the fix, 6 of 6 runs were clean.

Before the VM, ds6 (inside ETH) could not be reached from CSCS, from mit3090 or from the operator's
laptop on any port, including 22, 443 and UDP. Only hosts inside ETH such as sgs-gpu07 got through.

## Decisions taken here

- Peer id is the raw public key, not a hash, so no lookup is needed to verify one.
- The crypto provider is `ring`, chosen over `aws-lc-rs` so the build needs no cmake or nasm on aarch64
  and HPC images.
- Circuits carry no outer TLS layer, and that mode is not kept as an option. Keeping it would mean two
  circuit protocols, and it cost 60–80% of the VM's only core. Reservations keep TLS: they are tiny, and
  TLS protects their pushes.
- TCP paths use one TLS connection per stream, with no multiplexer. Parallel streams then get independent
  congestion windows, which is what bulk transfer wants.
- TCP punching uses fresh ports per stream. Reusing the listen port allows only one connection per port
  pair, and it confuses listener and dialer roles.
- The QUIC stream receive window is 2 MiB. Above that, loss bursts at a 2.5 GbE bottleneck exceeded quinn's
  limit of 1024 reassembly gaps, and quinn then kills the connection (seen at 16 and 64 MiB). One QUIC stream
  therefore carries at most 2 MiB per RTT, so bulk transfers should use several streams. The connection
  window is 128 MiB.
- QUIC uses quinn's BBR by default (`Config::quic: QuicTuning`, `otela --congestion bbr|cubic`, plus `--stream-window-mib`).
  It runs in user space, so it works on hosts without the kernel bbr module and without root. The relay and
  rendezvous request kernel `bbr` on their own sockets and silently keep the default when it isn't loaded.
  The system-wide default is not touched. `PathReport::congestion` records what our end used.
- On QUIC, `PathReport::rtt_ms` is quinn's minimum RTT, because the smoothed RTT under load measures
  queueing. On TCP paths it is the duration of the TLS handshake.
- On the accepting side, `Punched` means the peer asked us to punch within the last 60 s.
- Address families: a node uses resolved addresses of the same family as its listen address (IPv4 by
  default).
- Library errors are a `thiserror` enum and the library has no `unwrap`. Logging uses `tracing`, so
  `rill-kvd` decides whether and how to install a subscriber.
