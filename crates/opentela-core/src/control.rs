//! Client side of a long-lived control session (to a rendezvous or a relay): requests matched to responses by
//! id, unsolicited pushes forwarded, pings so a dead session is noticed within `DEAD_AFTER`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;

use crate::identity::PeerId;
use crate::wire::{read_frame, write_frame, Msg};
use crate::Error;

const PING_EVERY: Duration = Duration::from_secs(10);
const DEAD_AFTER: Duration = Duration::from_secs(35);

type Request = (Msg, oneshot::Sender<Msg>);

/// Handle to a live session; cheap to clone. Requests fail once the session is gone.
#[derive(Debug, Clone)]
pub(crate) struct Control {
    tx: mpsc::Sender<Request>,
}

impl Control {
    pub(crate) async fn request(&self, msg: Msg, timeout: Duration) -> Result<Msg, Error> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send((msg, reply_tx))
            .await
            .map_err(|_| Error::Closed)?;
        match tokio::time::timeout(timeout, reply_rx).await {
            Err(_) => Err(Error::Timeout("control request")),
            Ok(Err(_)) => Err(Error::Closed),
            Ok(Ok(Msg::Error { message })) => Err(Error::Remote(message)),
            Ok(Ok(reply)) => Ok(reply),
        }
    }
}

/// Starts a session over `io`; returns the handle and the future that drives it until the session dies.
pub(crate) fn session<S>(
    io: S,
    pushes: mpsc::Sender<Msg>,
) -> (Control, impl std::future::Future<Output = Error>)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (tx, mut requests) = mpsc::channel::<Request>(64);
    let driver = async move {
        let (mut reader, mut writer) = tokio::io::split(io);
        let (frames_tx, mut frames) = mpsc::channel(64);
        // In a JoinSet so the reader (and the socket half it holds) dies with this future, even when cancelled.
        let mut reader_task = JoinSet::new();
        reader_task.spawn(async move {
            loop {
                let frame = read_frame(&mut reader).await;
                let failed = frame.is_err();
                if frames_tx.send(frame).await.is_err() || failed {
                    return;
                }
            }
        });
        let mut pending: HashMap<u64, oneshot::Sender<Msg>> = HashMap::new();
        let mut next_id = 1u64;
        let mut last_heard = Instant::now();
        let mut ping =
            tokio::time::interval_at(tokio::time::Instant::now() + PING_EVERY, PING_EVERY);
        let error = loop {
            tokio::select! {
                request = requests.recv() => {
                    let Some((msg, reply)) = request else { break Error::Closed };
                    pending.insert(next_id, reply);
                    if let Err(e) = write_frame(&mut writer, next_id, msg).await {
                        break e;
                    }
                    next_id += 1;
                }
                frame = frames.recv() => {
                    let frame = match frame {
                        Some(Ok(frame)) => frame,
                        Some(Err(e)) => break e,
                        None => break Error::Closed,
                    };
                    last_heard = Instant::now();
                    if frame.id == 0 {
                        if pushes.send(frame.msg).await.is_err() {
                            break Error::Closed;
                        }
                    } else if let Some(reply) = pending.remove(&frame.id) {
                        // The requester may have timed out and gone; nothing to deliver then.
                        reply.send(frame.msg).ok();
                    }
                }
                _ = ping.tick() => {
                    if last_heard.elapsed() > DEAD_AFTER {
                        break Error::Timeout("control session silent");
                    }
                    // Pong carries an id nobody waits for; any frame refreshes `last_heard`.
                    if let Err(e) = write_frame(&mut writer, next_id, Msg::Ping).await {
                        break e;
                    }
                    next_id += 1;
                }
            }
        };
        error
    };
    (Control { tx }, driver)
}

/// Server side of a session: answers each request with `handle` (in order) and forwards `pushes` to the client,
/// until the client disconnects or stays silent past `DEAD_AFTER`. Returns why it ended.
pub(crate) async fn serve<S, F, Fut>(io: S, mut pushes: mpsc::Receiver<Msg>, mut handle: F) -> Error
where
    S: AsyncRead + AsyncWrite + Send + 'static,
    F: FnMut(Msg) -> Fut,
    Fut: std::future::Future<Output = Msg>,
{
    let (mut reader, mut writer) = tokio::io::split(io);
    let (frames_tx, mut frames) = mpsc::channel(64);
    let mut reader_task = JoinSet::new();
    reader_task.spawn(async move {
        loop {
            let frame = read_frame(&mut reader).await;
            let failed = frame.is_err();
            if frames_tx.send(frame).await.is_err() || failed {
                return;
            }
        }
    });
    let error = loop {
        tokio::select! {
            frame = tokio::time::timeout(DEAD_AFTER, frames.recv()) => {
                let frame = match frame {
                    Err(_) => break Error::Timeout("client silent"),
                    Ok(Some(Ok(frame))) => frame,
                    Ok(Some(Err(e))) => break e,
                    Ok(None) => break Error::Closed,
                };
                let reply = match frame.msg {
                    Msg::Ping => Msg::Pong,
                    msg => handle(msg).await,
                };
                if let Err(e) = write_frame(&mut writer, frame.id, reply).await {
                    break e;
                }
            }
            push = pushes.recv() => {
                let Some(msg) = push else { break Error::Closed };
                if let Err(e) = write_frame(&mut writer, 0, msg).await {
                    break e;
                }
            }
        }
    };
    error
}

/// Runs its closure when dropped, so registry entries go away even if the task panics or is cancelled.
pub(crate) struct Cleanup<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> Cleanup<F> {
    pub(crate) fn new(f: F) -> Self {
        Self(Some(f))
    }
}

impl<F: FnOnce()> Drop for Cleanup<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

/// Live sessions per peer, newest last. A second process with the same key (a preflight, a restart racing the
/// old process) takes over, and the older session serves again once the newer one ends.
#[derive(Debug)]
pub(crate) struct Sessions<T> {
    by_peer: HashMap<PeerId, Vec<(u64, T)>>,
}

impl<T> Default for Sessions<T> {
    fn default() -> Self {
        Self {
            by_peer: HashMap::new(),
        }
    }
}

impl<T> Sessions<T> {
    pub(crate) fn peers(&self) -> usize {
        self.by_peer.len()
    }

    pub(crate) fn contains(&self, peer: &PeerId) -> bool {
        self.by_peer.contains_key(peer)
    }

    pub(crate) fn insert(&mut self, peer: PeerId, session: u64, value: T) {
        let sessions = self.by_peer.entry(peer).or_default();
        sessions.retain(|(id, _)| *id != session);
        sessions.push((session, value));
    }

    pub(crate) fn latest(&self, peer: &PeerId) -> Option<&T> {
        self.by_peer.get(peer)?.last().map(|(_, value)| value)
    }

    /// Returns true when this was the peer's last session.
    pub(crate) fn remove(&mut self, peer: &PeerId, session: u64) -> bool {
        let Some(sessions) = self.by_peer.get_mut(peer) else {
            return false;
        };
        sessions.retain(|(id, _)| *id != session);
        if sessions.is_empty() {
            self.by_peer.remove(peer);
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_runs_on_panic() {
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = ran.clone();
        let unwound = std::panic::catch_unwind(move || {
            let _cleanup =
                Cleanup::new(move || flag.store(true, std::sync::atomic::Ordering::SeqCst));
            panic!("handler bug");
        });
        assert!(unwound.is_err());
        assert!(ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn older_session_takes_over_when_the_newer_ends() {
        let peer = crate::Keypair::generate().peer_id();
        let mut sessions = Sessions::default();
        sessions.insert(peer, 1, "node");
        sessions.insert(peer, 2, "preflight");
        assert_eq!(sessions.latest(&peer), Some(&"preflight"));
        assert!(!sessions.remove(&peer, 2));
        assert_eq!(sessions.latest(&peer), Some(&"node"));
        sessions.insert(peer, 1, "node re-registered");
        assert_eq!(sessions.peers(), 1);
        assert!(sessions.remove(&peer, 1));
        assert!(!sessions.contains(&peer));
    }
}
