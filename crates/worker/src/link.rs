//! Liaison avec le superviseur par le pipe (docs/plan/06).
//!
//! - poignée de main : `init` → `ready` → trames de clés → `start` ([`connect`]) ;
//! - ensuite, une tâche **lectrice** distribue ce qui arrive : réponses `signed_request_response`
//!   (réassemblées par `id`) aux requêtes en attente, trames de clés au [`KeyStore`], réponses
//!   `created_key` à l'outil qui les attend, et le reste (`inbox`, `shutdown`,
//!   `snapshot_request`) sur le canal [`Control`] de la boucle d'agent ;
//! - une tâche **rédactrice** sérialise les trames sortantes.
//!
//! Aucune trame n'est journalisée ; les clés ne passent jamais en JSON.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use runtime_protocol::pipe::{
    self, CreatedKeyMsg, Frame, HttpMethod, KeyFrame, MAX_RELAY_RESPONSE_BYTES, PipeError, ReadyMsg, Reassembly,
    ShutdownMsg, SignedRequest, SupervisorMsg, WorkerMsg,
};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::sync::{Notify, mpsc, oneshot};
use zeroize::Zeroizing;

use crate::keys::KeyStore;

/// Délai maximal d'une requête relayée (le superviseur a ses propres délais réseau).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(150);

/// Message de contrôle reçu du superviseur.
#[derive(Debug)]
pub enum Control {
    /// Éléments de boîte arrivés par WebSocket (`{ t, … }`, champs encore chiffrés).
    Inbox(Vec<Value>),
    /// Arrêt demandé.
    Shutdown(ShutdownMsg),
    /// Demande de `snapshot` (05 §3).
    Snapshot(String),
}

/// Réponse relayée, réassemblée.
#[derive(Clone)]
pub struct Relayed {
    /// Statut HTTP de l'API ; `0` si le relais a échoué (cause dans `error`).
    pub status: u16,
    /// Code `relay_*` quand `status = 0`.
    pub error: Option<String>,
    /// `retry-after` (secondes), s'il est présent et entier.
    pub retry_after: Option<u64>,
    /// Corps.
    pub body: Vec<u8>,
}

impl core::fmt::Debug for Relayed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Jamais le corps (contenu chiffré, résultats d'outils en clair).
        f.debug_struct("Relayed").field("status", &self.status).field("error", &self.error).finish_non_exhaustive()
    }
}

/// Échec de la liaison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    /// Pipe fermé.
    Closed,
    /// Pas de réponse dans [`REQUEST_TIMEOUT`].
    Timeout,
}

enum Outgoing {
    Json(Box<WorkerMsg>),
    Keys(Zeroizing<Vec<u8>>),
}

struct Inner {
    out: mpsc::Sender<Outgoing>,
    pending: Mutex<HashMap<String, oneshot::Sender<Relayed>>>,
    created: Mutex<HashMap<String, oneshot::Sender<CreatedKeyMsg>>>,
    next: AtomicU64,
    closed: AtomicBool,
    keys: Mutex<KeyStore>,
    keys_changed: Notify,
}

/// Liaison partagée (clonable) avec le superviseur.
#[derive(Clone)]
pub struct Link {
    inner: Arc<Inner>,
}

impl core::fmt::Debug for Link {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Link").field("closed", &self.inner.closed.load(Ordering::Relaxed)).finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Poignée de main puis démarrage des tâches de lecture et d'écriture. Rend la liaison, `init` et
/// le canal de contrôle ; `None` si le superviseur demande l'arrêt avant `start`.
pub async fn connect<S>(io: S) -> Result<Option<(Link, pipe::Init, mpsc::Receiver<Control>)>, PipeError>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(io);
    let init = match pipe::read_frame(&mut rd).await? {
        Frame::Json(j) => match pipe::decode_json::<SupervisorMsg>(&j)? {
            SupervisorMsg::Init(init) => *init,
            _ => return Err(PipeError::BadMessage),
        },
        Frame::Keys(_) => return Err(PipeError::BadMessage),
    };
    pipe::write_json(
        &mut wr,
        &WorkerMsg::Ready(ReadyMsg { pid: std::process::id(), version: env!("CARGO_PKG_VERSION").into() }),
    )
    .await?;
    let mut keys = KeyStore::new(&init.session_id);
    loop {
        match pipe::read_frame(&mut rd).await? {
            Frame::Keys(k) => keys.apply(&KeyFrame::decode(&k)?),
            Frame::Json(j) => match pipe::decode_json::<SupervisorMsg>(&j)? {
                SupervisorMsg::Start(_) => break,
                SupervisorMsg::Shutdown(_) => {
                    let _ = pipe::write_json(
                        &mut wr,
                        &WorkerMsg::Done(pipe::DoneMsg { reason: pipe::DoneReason::Shutdown }),
                    )
                    .await;
                    return Ok(None);
                }
                _ => return Err(PipeError::BadMessage),
            },
        }
    }
    let (out_tx, out_rx) = mpsc::channel(256);
    let (ctl_tx, ctl_rx) = mpsc::channel(1024);
    let inner = Arc::new(Inner {
        out: out_tx,
        pending: Mutex::new(HashMap::new()),
        created: Mutex::new(HashMap::new()),
        next: AtomicU64::new(0),
        closed: AtomicBool::new(false),
        keys: Mutex::new(keys),
        keys_changed: Notify::new(),
    });
    tokio::spawn(writer(wr, out_rx));
    tokio::spawn(reader(rd, Arc::clone(&inner), ctl_tx));
    Ok(Some((Link { inner }, init, ctl_rx)))
}

async fn writer<S: AsyncWrite + Send>(mut wr: WriteHalf<S>, mut rx: mpsc::Receiver<Outgoing>) {
    while let Some(msg) = rx.recv().await {
        let res = match msg {
            Outgoing::Json(m) => pipe::write_json(&mut wr, &*m).await,
            Outgoing::Keys(k) => pipe::write_keys(&mut wr, &k).await,
        };
        if matches!(res, Err(PipeError::Io | PipeError::Closed)) {
            break;
        }
    }
}

async fn reader<S: AsyncRead + Send>(mut rd: ReadHalf<S>, inner: Arc<Inner>, ctl: mpsc::Sender<Control>) {
    let mut parts: HashMap<String, Reassembly> = HashMap::new();
    loop {
        let frame = match pipe::read_frame(&mut rd).await {
            Ok(f) => f,
            Err(_) => break,
        };
        let msg = match frame {
            Frame::Keys(k) => {
                match KeyFrame::decode(&k) {
                    Ok(f) => lock(&inner.keys).apply(&f),
                    Err(_) => break,
                }
                inner.keys_changed.notify_waiters();
                continue;
            }
            Frame::Json(j) => match pipe::decode_json::<SupervisorMsg>(&j) {
                Ok(m) => m,
                Err(_) => break,
            },
        };
        match msg {
            SupervisorMsg::SignedRequestResponse(r) => {
                let done = if r.status == 0 && r.error.is_some() {
                    parts.remove(&r.id);
                    Some(Relayed { status: 0, error: r.error, retry_after: None, body: Vec::new() })
                } else {
                    let buf = parts.entry(r.id.clone()).or_default();
                    match buf.push(r.part, &r.body, MAX_RELAY_RESPONSE_BYTES) {
                        Err(code) => {
                            parts.remove(&r.id);
                            Some(Relayed {
                                status: 0,
                                error: Some(code.to_owned()),
                                retry_after: None,
                                body: Vec::new(),
                            })
                        }
                        Ok(()) if r.last => {
                            let retry_after = r.headers.get("retry-after").and_then(|v| v.parse::<u64>().ok());
                            parts.remove(&r.id).map(|b| Relayed {
                                status: r.status,
                                error: None,
                                retry_after,
                                body: b.into_body(),
                            })
                        }
                        Ok(()) => None,
                    }
                };
                if let Some(resp) = done
                    && let Some(tx) = lock(&inner.pending).remove(&r.id)
                {
                    let _ = tx.send(resp);
                }
            }
            SupervisorMsg::CreatedKey(c) => {
                if let Some(tx) = lock(&inner.created).remove(&c.reference) {
                    let _ = tx.send(c);
                }
            }
            SupervisorMsg::Inbox(i) => {
                if ctl.send(Control::Inbox(i.items)).await.is_err() {
                    break;
                }
            }
            SupervisorMsg::Shutdown(s) => {
                if ctl.send(Control::Shutdown(s)).await.is_err() {
                    break;
                }
            }
            SupervisorMsg::SnapshotRequest(s) => {
                if ctl.send(Control::Snapshot(s.request_id)).await.is_err() {
                    break;
                }
            }
            // `init` / `start` répétés : violation du protocole.
            SupervisorMsg::Init(_) | SupervisorMsg::Start(_) => break,
        }
    }
    inner.closed.store(true, Ordering::Relaxed);
    lock(&inner.pending).clear();
    lock(&inner.created).clear();
    inner.keys_changed.notify_waiters();
}

impl Link {
    /// Envoie un message au superviseur.
    pub async fn send(&self, msg: WorkerMsg) -> Result<(), LinkError> {
        self.inner.out.send(Outgoing::Json(Box::new(msg))).await.map_err(|_| LinkError::Closed)
    }

    /// Le pipe est fermé (le superviseur est parti ou a envoyé une trame invalide).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Relaxed)
    }

    /// Requête vers l'API, signée par le superviseur (06 §4, §4.1).
    pub async fn request(
        &self,
        method: HttpMethod,
        path: &str,
        body: &[u8],
        with_auth: bool,
    ) -> Result<Relayed, LinkError> {
        if self.is_closed() {
            return Err(LinkError::Closed);
        }
        let n = self.inner.next.fetch_add(1, Ordering::Relaxed);
        let id = format!("r{n}");
        let (tx, rx) = oneshot::channel();
        lock(&self.inner.pending).insert(id.clone(), tx);
        for part in SignedRequest::split(&id, method, path, body, with_auth) {
            if self.send(WorkerMsg::SignedRequest(part)).await.is_err() {
                lock(&self.inner.pending).remove(&id);
                return Err(LinkError::Closed);
            }
        }
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(_)) => Err(LinkError::Closed),
            Err(_) => {
                lock(&self.inner.pending).remove(&id);
                Err(LinkError::Timeout)
            }
        }
    }

    /// Annonce au superviseur la clé d'un salon créé par le worker et attend l'enveloppe `rt1` et
    /// l'entrée chiffrée (extension L07, `created_key`).
    pub async fn created_key(
        &self,
        thread_id: &str,
        key: &synco_e2ee::SymmetricKey,
    ) -> Result<CreatedKeyMsg, LinkError> {
        let frame = KeyFrame {
            op: pipe::KeyOp::Add,
            entries: vec![pipe::KeyEntry {
                kind: pipe::KeyKind::Thread,
                reference: thread_id.to_owned(),
                version: 1,
                key: Zeroizing::new(key.as_bytes().to_vec()),
            }],
        };
        let bytes = frame.encode().map_err(|_| LinkError::Closed)?;
        let (tx, rx) = oneshot::channel();
        lock(&self.inner.created).insert(thread_id.to_owned(), tx);
        if self.inner.out.send(Outgoing::Keys(bytes)).await.is_err() {
            lock(&self.inner.created).remove(thread_id);
            return Err(LinkError::Closed);
        }
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(_)) => Err(LinkError::Closed),
            Err(_) => {
                lock(&self.inner.created).remove(thread_id);
                Err(LinkError::Timeout)
            }
        }
    }

    /// Accès au coffre.
    pub fn with_keys<T>(&self, f: impl FnOnce(&mut KeyStore) -> T) -> T {
        f(&mut lock(&self.inner.keys))
    }

    /// Attend une trame de clés (ou la fermeture), au plus `timeout`.
    pub async fn wait_keys(&self, timeout: Duration) {
        let _ = tokio::time::timeout(timeout, self.inner.keys_changed.notified()).await;
    }
}
