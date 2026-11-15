//! TLS 1.3 with RFC 7250 raw Ed25519 keys: the remote key is the peer id, pinned or checked against the trust
//! policy. No certificates, no CAs, no names.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::AlwaysResolvesClientRawPublicKeys;
use rustls::crypto::{
    verify_tls13_signature_with_raw_key, CryptoProvider, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer,
    UnixTime,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig, ConnectionCommon, DigitallySignedStruct, DistinguishedName, ServerConfig,
    SignatureScheme,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{client, server, TlsAcceptor, TlsConnector};

use crate::identity::{Keypair, PeerId, TrustPolicy};
use crate::Error;

pub(crate) const ALPN_PEER: &[u8] = b"otela/peer/1";
pub(crate) const ALPN_RENDEZVOUS: &[u8] = b"otela/rendezvous/1";
pub(crate) const ALPN_RELAY: &[u8] = b"otela/relay/1";
/// RFC 9266 `tls-exporter` label; the context is empty.
const CHANNEL_BINDING_LABEL: &[u8] = b"EXPORTER-Channel-Binding";
/// Ignored by the verifiers; QUIC and rustls want some name.
const SERVER_NAME: &str = "otela";

/// RFC 9266 `tls-exporter` value of one end-to-end TLS 1.3 session: equal on both ends of that session, and
/// unrelated for any other session (a relay in the middle cannot compute it).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelBinding(pub [u8; 32]);

impl fmt::Debug for ChannelBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChannelBinding({})", hex::encode(self.0))
    }
}

/// What the client accepts from the server.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Expect {
    Peer(PeerId),
    AnyTrusted,
}

#[derive(Debug)]
struct RawKeyVerifier {
    expect: Expect,
    trust: Arc<TrustPolicy>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl RawKeyVerifier {
    fn check(&self, end_entity: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let peer = PeerId::from_spki(end_entity).ok_or(rustls::Error::InvalidCertificate(
            rustls::CertificateError::BadEncoding,
        ))?;
        let pinned = match self.expect {
            Expect::Peer(want) => want == peer,
            Expect::AnyTrusted => true,
        };
        if pinned && self.trust.allows(&peer) {
            Ok(())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify13(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.algorithms,
        )
    }
}

impl ServerCertVerifier for RawKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.check(end_entity)
            .map(|()| ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

impl ClientCertVerifier for RawKeyVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.check(end_entity)
            .map(|()| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Peer id and channel binding of a completed handshake.
fn session_identity<D>(state: &ConnectionCommon<D>) -> Result<(PeerId, ChannelBinding), Error> {
    let peer = state
        .peer_certificates()
        .and_then(|certs| certs.first())
        .and_then(|cert| PeerId::from_spki(cert))
        .ok_or_else(|| Error::Protocol("handshake finished without a raw public key".into()))?;
    let binding = state
        .export_keying_material([0u8; 32], CHANNEL_BINDING_LABEL, None)
        .map_err(|e| Error::Protocol(format!("tls-exporter: {e}")))?;
    Ok((peer, ChannelBinding(binding)))
}

pub(crate) fn quic_identity(conn: &quinn::Connection) -> Result<(PeerId, ChannelBinding), Error> {
    let peer = conn
        .peer_identity()
        .and_then(|any| any.downcast::<Vec<CertificateDer<'static>>>().ok())
        .and_then(|certs| certs.first().and_then(|cert| PeerId::from_spki(cert)))
        .ok_or_else(|| {
            Error::Protocol("QUIC handshake finished without a raw public key".into())
        })?;
    let mut binding = [0u8; 32];
    conn.export_keying_material(&mut binding, CHANNEL_BINDING_LABEL, b"")
        .map_err(|_| Error::Protocol("QUIC tls-exporter failed".into()))?;
    Ok((peer, ChannelBinding(binding)))
}

/// Everything needed to run either side of a handshake as this node.
#[derive(Debug, Clone)]
pub(crate) struct Tls {
    key: Arc<CertifiedKey>,
    trust: Arc<TrustPolicy>,
    provider: Arc<CryptoProvider>,
}

impl Tls {
    pub(crate) fn new(keypair: &Keypair, trust: TrustPolicy) -> Result<Self, Error> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(keypair.pkcs8().to_vec()));
        let signer = provider.key_provider.load_private_key(der)?;
        let key = Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(keypair.peer_id().to_spki())],
            signer,
        ));
        Ok(Self {
            key,
            trust: Arc::new(trust),
            provider,
        })
    }

    pub(crate) fn trust(&self) -> &TrustPolicy {
        &self.trust
    }

    fn verifier(&self, expect: Expect) -> Arc<RawKeyVerifier> {
        Arc::new(RawKeyVerifier {
            expect,
            trust: self.trust.clone(),
            algorithms: self.provider.signature_verification_algorithms,
        })
    }

    fn client_config(&self, expect: Expect, alpn: &[u8]) -> ClientConfig {
        let mut config = ClientConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("ring supports TLS 1.3")
            .dangerous()
            .with_custom_certificate_verifier(self.verifier(expect))
            .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(
                self.key.clone(),
            )));
        config.alpn_protocols = vec![alpn.to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        config
    }

    fn server_config(&self, alpns: &[&[u8]]) -> ServerConfig {
        let mut config = ServerConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("ring supports TLS 1.3")
            .with_client_cert_verifier(self.verifier(Expect::AnyTrusted))
            .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(
                self.key.clone(),
            )));
        config.alpn_protocols = alpns.iter().map(|alpn| alpn.to_vec()).collect();
        config.send_tls13_tickets = 0;
        config
    }

    pub(crate) fn quic_client(&self, expect: Expect, alpn: &[u8]) -> quinn::ClientConfig {
        let crypto = QuicClientConfig::try_from(self.client_config(expect, alpn))
            .expect("TLS 1.3 with AES-128-GCM is configured");
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config.transport_config(quic_transport());
        config
    }

    pub(crate) fn quic_server(&self, alpns: &[&[u8]]) -> quinn::ServerConfig {
        let crypto = QuicServerConfig::try_from(self.server_config(alpns))
            .expect("TLS 1.3 with AES-128-GCM is configured");
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        config.transport_config(quic_transport());
        config
    }

    /// Client handshake over any byte stream; returns the stream plus the server's verified identity.
    pub(crate) async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: S,
        expect: Expect,
        alpn: &[u8],
    ) -> Result<(client::TlsStream<S>, PeerId, ChannelBinding), Error> {
        let connector = TlsConnector::from(Arc::new(self.client_config(expect, alpn)));
        let stream = connector
            .connect(
                ServerName::try_from(SERVER_NAME).expect("static name is valid"),
                io,
            )
            .await?;
        let (peer, binding) = session_identity(&**stream.get_ref().1)?;
        Ok((stream, peer, binding))
    }

    /// Server handshake; returns the stream, the client's verified identity and the negotiated ALPN.
    pub(crate) async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: S,
        alpns: &[&[u8]],
    ) -> Result<(server::TlsStream<S>, PeerId, ChannelBinding, Vec<u8>), Error> {
        let acceptor = TlsAcceptor::from(Arc::new(self.server_config(alpns)));
        let stream = acceptor.accept(io).await?;
        let (peer, binding) = session_identity(&**stream.get_ref().1)?;
        let alpn = stream
            .get_ref()
            .1
            .alpn_protocol()
            .unwrap_or_default()
            .to_vec();
        Ok((stream, peer, binding, alpn))
    }
}

/// Keepalives refresh NAT bindings. quinn closes a connection whose stream has more than 1024 reassembly gaps;
/// a 2 MiB stream window (~870 alternating lost packets) cannot reach that, where 16 MiB did under loss bursts
/// at a 2.5 GbE bottleneck. One stream then carries at most 2 MiB per RTT, so bulk transfers use several.
fn quic_transport() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(1024u32.into())
        .stream_receive_window((2u32 << 20).into())
        .receive_window((128u32 << 20).into())
        .send_window(128 << 20)
        .keep_alive_interval(Some(Duration::from_secs(5)))
        .max_idle_timeout(Some(
            Duration::from_secs(30)
                .try_into()
                .expect("30 s fits a QUIC varint"),
        ));
    Arc::new(transport)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(trust: &[PeerId], key: &Keypair) -> Tls {
        Tls::new(key, TrustPolicy::AllowList(trust.iter().copied().collect())).unwrap()
    }

    async fn handshake(
        client: &Tls,
        server: &Tls,
        expect: Expect,
    ) -> (
        Result<(PeerId, ChannelBinding), Error>,
        Result<(PeerId, ChannelBinding), Error>,
    ) {
        let (a, b) = tokio::io::duplex(64 << 10);
        let (c, s) = tokio::join!(
            client.connect(a, expect, ALPN_PEER),
            server.accept(b, &[ALPN_PEER])
        );
        (c.map(|(_, p, cb)| (p, cb)), s.map(|(_, p, cb, _)| (p, cb)))
    }

    #[tokio::test]
    async fn pinned_handshake_yields_identities_and_one_binding() {
        let (ka, kb) = (Keypair::generate(), Keypair::generate());
        let ids = [ka.peer_id(), kb.peer_id()];
        let (a, b) = (pair(&ids, &ka), pair(&ids, &kb));
        let (c, s) = handshake(&a, &b, Expect::Peer(kb.peer_id())).await;
        let ((server_seen, cb1), (client_seen, cb2)) = (c.unwrap(), s.unwrap());
        assert_eq!(server_seen, kb.peer_id());
        assert_eq!(client_seen, ka.peer_id());
        assert_eq!(cb1, cb2);
        let (c2, _) = handshake(&a, &b, Expect::Peer(kb.peer_id())).await;
        assert_ne!(c2.unwrap().1, cb1, "a new session must have a new binding");
    }

    #[tokio::test]
    async fn wrong_pin_and_untrusted_client_are_rejected() {
        let (ka, kb, kc) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let ids = [ka.peer_id(), kb.peer_id(), kc.peer_id()];
        let (a, b) = (pair(&ids, &ka), pair(&ids, &kb));
        let (c, _) = handshake(&a, &b, Expect::Peer(kc.peer_id())).await;
        assert!(c.is_err(), "server key differs from the pinned id");
        let b_without_a = pair(&[kb.peer_id()], &kb);
        let (_, s) = handshake(&a, &b_without_a, Expect::Peer(kb.peer_id())).await;
        assert!(s.is_err(), "client is not on the server's allow list");
    }
}
