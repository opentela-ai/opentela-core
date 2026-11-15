//! Circuit admission without an outer TLS layer. The relay must still know who asks for a circuit, so the
//! client proves its key with a signed preamble, and the relay then splices raw bytes: the peers' own TLS 1.3
//! session is the only encryption on the circuit.
//!
//! 1. client: `OTELACIR`, then `CircuitHello { from, client nonce }`
//! 2. relay: `CircuitChallenge { relay id, relay nonce, relay signature over (label, both ids, both nonces) }`
//! 3. client: `CircuitAuth { purpose, client signature over (label, both ids, both nonces, purpose) }`
//!
//! The fresh relay nonce stops replays; signing the relay id, both nonces and the purpose stops a signature
//! made for one relay, connection or purpose from being used for another.

use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::identity::{Keypair, PeerId, TrustPolicy};
use crate::wire::{read_frame, write_frame, Msg, Purpose};
use crate::Error;

/// First bytes of a raw circuit connection. `O` (0x4f) can never start a TLS record (0x16), so the relay tells
/// the two apart on its single port by the first byte.
pub(crate) const MAGIC: &[u8; 8] = b"OTELACIR";
const RELAY_LABEL: &[u8] = b"otela relay circuit v1: relay";
const CLIENT_LABEL: &[u8] = b"otela relay circuit v1: client";

fn transcript(
    label: &[u8],
    client: PeerId,
    client_nonce: &[u8; 32],
    relay: PeerId,
    relay_nonce: &[u8; 32],
) -> Vec<u8> {
    [
        label,
        client.as_bytes(),
        client_nonce,
        relay.as_bytes(),
        relay_nonce,
    ]
    .concat()
}

fn encode_purpose(purpose: Purpose) -> Vec<u8> {
    match purpose {
        Purpose::Dial { target } => [&[1u8][..], target.as_bytes()].concat(),
        Purpose::Accept { circuit } => [&[2u8][..], &circuit.to_be_bytes()].concat(),
    }
}

fn nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

fn unhex<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    let mut out = [0u8; N];
    hex::decode_to_slice(text, &mut out)
        .map_err(|_| Error::Protocol("bad hex in circuit preamble".into()))?;
    Ok(out)
}

/// Client side: authenticates to the relay (which must be trusted) and asks for `purpose`. Returns the relay id.
pub(crate) async fn open(
    io: &mut (impl AsyncRead + AsyncWrite + Unpin),
    key: &Keypair,
    trust: &TrustPolicy,
    purpose: Purpose,
) -> Result<PeerId, Error> {
    let client_nonce = nonce();
    io.write_all(MAGIC).await?;
    write_frame(
        io,
        1,
        Msg::CircuitHello {
            from: key.peer_id(),
            nonce: hex::encode(client_nonce),
        },
    )
    .await?;
    let (relay, relay_nonce, signature) = match read_frame(io).await?.msg {
        Msg::CircuitChallenge {
            relay,
            nonce,
            signature,
        } => (relay, unhex::<32>(&nonce)?, unhex::<64>(&signature)?),
        Msg::Error { message } => return Err(Error::Remote(message)),
        other => {
            return Err(Error::Protocol(format!(
                "expected a circuit challenge, got {}",
                other.kind()
            )))
        }
    };
    if !trust.allows(&relay) {
        return Err(Error::Untrusted(relay));
    }
    let relay_proof = transcript(
        RELAY_LABEL,
        key.peer_id(),
        &client_nonce,
        relay,
        &relay_nonce,
    );
    if !relay.verifies(&relay_proof, &signature) {
        return Err(Error::Protocol("relay signature does not verify".into()));
    }
    let mut message = transcript(
        CLIENT_LABEL,
        key.peer_id(),
        &client_nonce,
        relay,
        &relay_nonce,
    );
    message.extend(encode_purpose(purpose));
    write_frame(
        io,
        2,
        Msg::CircuitAuth {
            purpose,
            signature: hex::encode(key.sign(&message)),
        },
    )
    .await?;
    Ok(relay)
}

/// Relay side, after `MAGIC`: returns the authenticated client and what it asked for.
pub(crate) async fn admit(
    io: &mut (impl AsyncRead + AsyncWrite + Unpin),
    key: &Keypair,
    trust: &TrustPolicy,
) -> Result<(PeerId, Purpose), Error> {
    let mut magic = [0u8; MAGIC.len()];
    io.read_exact(&mut magic).await?;
    if &magic != MAGIC {
        return Err(Error::Protocol("not a circuit preamble".into()));
    }
    let (client, client_nonce) = match read_frame(io).await?.msg {
        Msg::CircuitHello { from, nonce } => (from, unhex::<32>(&nonce)?),
        other => {
            return Err(Error::Protocol(format!(
                "expected a circuit hello, got {}",
                other.kind()
            )))
        }
    };
    if !trust.allows(&client) {
        write_frame(io, 0, Msg::error("not on the allow list")).await?;
        return Err(Error::Untrusted(client));
    }
    let relay = key.peer_id();
    let relay_nonce = nonce();
    let relay_proof = transcript(RELAY_LABEL, client, &client_nonce, relay, &relay_nonce);
    write_frame(
        io,
        0,
        Msg::CircuitChallenge {
            relay,
            nonce: hex::encode(relay_nonce),
            signature: hex::encode(key.sign(&relay_proof)),
        },
    )
    .await?;
    let (purpose, signature) = match read_frame(io).await?.msg {
        Msg::CircuitAuth { purpose, signature } => (purpose, unhex::<64>(&signature)?),
        other => {
            return Err(Error::Protocol(format!(
                "expected circuit auth, got {}",
                other.kind()
            )))
        }
    };
    let mut message = transcript(CLIENT_LABEL, client, &client_nonce, relay, &relay_nonce);
    message.extend(encode_purpose(purpose));
    if !client.verifies(&message, &signature) {
        write_frame(io, 0, Msg::error("circuit signature does not verify")).await?;
        return Err(Error::Protocol(format!(
            "bad circuit signature from {client}"
        )));
    }
    Ok((client, purpose))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fleet(n: usize) -> (Vec<Keypair>, TrustPolicy) {
        let keys: Vec<Keypair> = (0..n).map(|_| Keypair::generate()).collect();
        let trust = TrustPolicy::AllowList(keys.iter().map(|k| k.peer_id()).collect());
        (keys, trust)
    }

    /// The client's two messages, written by hand so tests can keep, replay or alter them.
    struct Script {
        hello: Msg,
        auth: Msg,
    }

    /// Runs a correct client by hand against `io` and returns exactly what it sent.
    async fn honest_client(
        io: &mut (impl AsyncRead + AsyncWrite + Unpin),
        client: &Keypair,
        purpose: Purpose,
    ) -> Script {
        let client_nonce = nonce();
        let hello = Msg::CircuitHello {
            from: client.peer_id(),
            nonce: hex::encode(client_nonce),
        };
        io.write_all(MAGIC).await.unwrap();
        write_frame(io, 1, hello.clone()).await.unwrap();
        let Msg::CircuitChallenge { relay, nonce, .. } = read_frame(io).await.unwrap().msg else {
            panic!("no challenge")
        };
        let mut signed = transcript(
            CLIENT_LABEL,
            client.peer_id(),
            &client_nonce,
            relay,
            &unhex::<32>(&nonce).unwrap(),
        );
        signed.extend(encode_purpose(purpose));
        let auth = Msg::CircuitAuth {
            purpose,
            signature: hex::encode(client.sign(&signed)),
        };
        write_frame(io, 2, auth.clone()).await.unwrap();
        Script { hello, auth }
    }

    /// Plays recorded messages at a relay, ignoring its challenge.
    async fn replay(io: &mut (impl AsyncRead + AsyncWrite + Unpin), hello: Msg, auth: Msg) {
        io.write_all(MAGIC).await.unwrap();
        write_frame(io, 1, hello).await.unwrap();
        read_frame(io).await.unwrap();
        write_frame(io, 2, auth).await.unwrap();
    }

    #[tokio::test]
    async fn admits_a_trusted_client_with_its_purpose() {
        let (keys, trust) = fleet(3);
        let purpose = Purpose::Dial {
            target: keys[2].peer_id(),
        };
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let (opened, admitted) = tokio::join!(
            open(&mut a, &keys[0], &trust, purpose),
            admit(&mut b, &keys[1], &trust)
        );
        assert_eq!(opened.unwrap(), keys[1].peer_id());
        assert_eq!(admitted.unwrap(), (keys[0].peer_id(), purpose));
    }

    #[tokio::test]
    async fn a_recorded_preamble_cannot_be_replayed() {
        let (keys, trust) = fleet(3);
        let purpose = Purpose::Dial {
            target: keys[2].peer_id(),
        };
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let (script, first) = tokio::join!(
            honest_client(&mut a, &keys[0], purpose),
            admit(&mut b, &keys[1], &trust)
        );
        assert!(first.is_ok());
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let ((), replayed) = tokio::join!(
            replay(&mut a, script.hello, script.auth),
            admit(&mut b, &keys[1], &trust)
        );
        assert!(
            replayed.is_err(),
            "a fresh relay nonce makes the old signature useless: {replayed:?}"
        );
    }

    #[tokio::test]
    async fn a_signature_for_one_relay_or_purpose_is_useless_elsewhere() {
        let (keys, trust) = fleet(4);
        let (client, relay_a, relay_b, target) = (&keys[0], &keys[1], &keys[2], keys[3].peer_id());
        let purpose = Purpose::Dial { target };
        // Relay A, trusted but malicious, takes what the client sent it and presents it to relay B.
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let (script, at_a) = tokio::join!(
            honest_client(&mut a, client, purpose),
            admit(&mut b, relay_a, &trust)
        );
        assert!(at_a.is_ok());
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let ((), at_b) = tokio::join!(
            replay(&mut a, script.hello.clone(), script.auth),
            admit(&mut b, relay_b, &trust)
        );
        assert!(
            at_b.is_err(),
            "B's id and nonce are in the signed transcript: {at_b:?}"
        );

        // A valid Dial signature cannot be re-labelled as another purpose.
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let tamper = async {
            let client_nonce = nonce();
            a.write_all(MAGIC).await.unwrap();
            write_frame(
                &mut a,
                1,
                Msg::CircuitHello {
                    from: client.peer_id(),
                    nonce: hex::encode(client_nonce),
                },
            )
            .await
            .unwrap();
            let Msg::CircuitChallenge { relay, nonce, .. } = read_frame(&mut a).await.unwrap().msg
            else {
                panic!("no challenge")
            };
            let mut signed = transcript(
                CLIENT_LABEL,
                client.peer_id(),
                &client_nonce,
                relay,
                &unhex::<32>(&nonce).unwrap(),
            );
            signed.extend(encode_purpose(purpose));
            let signature = hex::encode(client.sign(&signed));
            write_frame(
                &mut a,
                2,
                Msg::CircuitAuth {
                    purpose: Purpose::Accept { circuit: 1 },
                    signature,
                },
            )
            .await
            .unwrap();
        };
        let ((), relabelled) = tokio::join!(tamper, admit(&mut b, relay_b, &trust));
        assert!(relabelled.is_err(), "the purpose is signed");
    }

    #[tokio::test]
    async fn untrusted_clients_and_relays_are_refused() {
        let (keys, trust) = fleet(2);
        let outsider = Keypair::generate();
        let purpose = Purpose::Accept { circuit: 3 };
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let (_, admitted) = tokio::join!(
            open(&mut a, &outsider, &trust, purpose),
            admit(&mut b, &keys[1], &trust)
        );
        assert!(matches!(admitted, Err(Error::Untrusted(_))));
        let outsider_trust = TrustPolicy::AllowList([keys[0].peer_id()].into());
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let client = async move {
            let opened = open(&mut a, &keys[0], &trust, purpose).await;
            // Hang up, as a real client does, so the relay side stops waiting.
            drop(a);
            opened
        };
        let (opened, _) = tokio::join!(client, admit(&mut b, &outsider, &outsider_trust));
        assert!(
            matches!(opened, Err(Error::Untrusted(_))),
            "a relay off the allow list is refused"
        );
    }
}
