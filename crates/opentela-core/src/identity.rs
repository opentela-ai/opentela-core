//! Node identity (one Ed25519 key per node) and the trust policy deciding which peers may connect.

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::str::FromStr;

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Error;

/// DER prefix of an Ed25519 SubjectPublicKeyInfo; the 32-byte key follows.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// A peer's identity: its Ed25519 public key. Displayed and parsed as 64 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId([u8; 32]);

impl PeerId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The RFC 7250 raw public key presented in TLS.
    pub(crate) fn to_spki(self) -> Vec<u8> {
        [&ED25519_SPKI_PREFIX[..], &self.0].concat()
    }

    /// Parses a raw public key; anything but an Ed25519 SPKI is rejected.
    pub(crate) fn from_spki(spki: &[u8]) -> Option<Self> {
        let key = spki.strip_prefix(&ED25519_SPKI_PREFIX[..])?;
        Some(Self(key.try_into().ok()?))
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", &hex::encode(self.0)[..12])
    }
}

impl FromStr for PeerId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s.trim(), &mut bytes)
            .map_err(|e| Error::Config(format!("bad peer id {s:?}: {e}")))?;
        Ok(Self(bytes))
    }
}

impl Serialize for PeerId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PeerId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// An Ed25519 key pair, kept as its PKCS#8 encoding.
pub struct Keypair {
    pkcs8: Vec<u8>,
    peer_id: PeerId,
}

impl Keypair {
    pub fn generate() -> Self {
        let pkcs8 =
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("system RNG is available");
        Self::from_pkcs8(pkcs8.as_ref()).expect("freshly generated PKCS#8 parses")
    }

    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, Error> {
        let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8)
            .map_err(|e| Error::Config(format!("bad Ed25519 PKCS#8 key: {e}")))?;
        let peer_id = PeerId(
            pair.public_key()
                .as_ref()
                .try_into()
                .expect("Ed25519 public keys are 32 bytes"),
        );
        Ok(Self {
            pkcs8: pkcs8.to_vec(),
            peer_id,
        })
    }

    /// Loads a key file (hex PKCS#8, one line).
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
        let pkcs8 = hex::decode(text.trim())
            .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        Self::from_pkcs8(&pkcs8)
    }

    /// Writes the key file with mode 0600; refuses to overwrite.
    pub fn save(&self, path: &Path) -> Result<(), Error> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| Error::Config(format!("create {}: {e}", path.display())))?;
        writeln!(file, "{}", hex::encode(&self.pkcs8))
            .map_err(|e| Error::Config(format!("write {}: {e}", path.display())))
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub(crate) fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

/// Which remote keys a node, rendezvous or relay accepts. The one place a future policy (e.g. third-party
/// GPUs vouched for by a signed credential) plugs in.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TrustPolicy {
    /// Operator-issued list of peer ids; every node, rendezvous and relay must be on it.
    AllowList(HashSet<PeerId>),
}

impl TrustPolicy {
    pub fn allows(&self, peer: &PeerId) -> bool {
        match self {
            Self::AllowList(ids) => ids.contains(peer),
        }
    }

    /// Reads an allow list: one hex peer id per line; blank lines and `#` comments are ignored.
    pub fn load_allow_list(path: &Path) -> Result<Self, Error> {
        let text = fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
        let ids = text
            .lines()
            .map(|line| line.split_once('#').map_or(line, |(id, _)| id).trim())
            .filter(|line| !line.is_empty())
            .map(PeerId::from_str)
            .collect::<Result<_, _>>()?;
        Ok(Self::AllowList(ids))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_round_trips_through_text_and_spki() {
        let key = Keypair::generate();
        let id = key.peer_id();
        assert_eq!(id.to_string().parse::<PeerId>().unwrap(), id);
        assert_eq!(PeerId::from_spki(&id.to_spki()), Some(id));
        assert_eq!(PeerId::from_spki(&id.to_spki()[1..]), None);
        let reloaded = Keypair::from_pkcs8(key.pkcs8()).unwrap();
        assert_eq!(reloaded.peer_id(), id);
    }

    #[test]
    fn key_file_is_private_and_not_overwritten() {
        let dir = std::env::temp_dir().join(format!("otela-key-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.key");
        let key = Keypair::generate();
        key.save(&path).unwrap();
        assert!(key.save(&path).is_err());
        let mode = fs::metadata(&path).unwrap().permissions();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777,
            0o600
        );
        assert_eq!(Keypair::load(&path).unwrap().peer_id(), key.peer_id());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn allow_list_parses_comments() {
        let a = Keypair::generate().peer_id();
        let b = Keypair::generate().peer_id();
        let path = std::env::temp_dir().join(format!("otela-allow-{}", std::process::id()));
        fs::write(&path, format!("# fleet\n{a}  # node a\n\n")).unwrap();
        let trust = TrustPolicy::load_allow_list(&path).unwrap();
        assert!(trust.allows(&a));
        assert!(!trust.allows(&b));
        fs::remove_file(&path).unwrap();
    }
}
