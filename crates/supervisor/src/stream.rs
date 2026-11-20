//! Flux de notifications sortant `GET /api/runtime/v1/stream` (docs/plan/04 §6, forme réelle de
//! synco_api §10.3) : WebSocket signé comme un `GET` de corps vide, `pong` à chaque `ping`,
//! `presence` ≤ 1 / 30 s, reconnexion avec backoff exponentiel 1 s → 60 s et gigue, puis relecture
//! des délégations et des conversations en attente (les notifications ne sont pas rejouées).
//!
//! Refus de l'API : la poignée de main aboutit puis la connexion est fermée avec `4000 + statut`,
//! raison = code (`4401 rt_revoked`, `4404 rt_unknown`, `4403 ai_disabled`, `4409 replaced`,
//! `4408 pong_timeout`, `4429 rt_rate_limited`, `4503 runtime_disabled`).

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_util::{SinkExt as _, StreamExt as _};
use runtime_protocol::stream::{ApiEvent, STREAM_PATH, parse_api_event, pong_frame, presence_frame};
use synco_e2ee::RandomSource as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::runtime::Runtime;

/// Fin d'une session du flux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEnd {
    /// Runtime désappairé ou inconnu de l'API.
    Unpaired,
    /// Arrêt du runtime.
    Shutdown,
}

/// Connexion TCP ou TLS.
enum Io {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for Io {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Io {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

type Socket = tokio_tungstenite::WebSocketStream<Io>;

/// Issue d'une tentative.
enum Attempt {
    /// Fermée par l'API avec ce code et cette raison.
    Closed(u16, String),
    /// Coupure réseau, délai.
    Lost,
    /// Arrêt demandé.
    Shutdown,
}

async fn connect(rt: &Runtime) -> Result<Socket, &'static str> {
    let base = reqwest::Url::parse(rt.api.base()).map_err(|_| "api_url")?;
    let host = base.host_str().ok_or("api_url")?.to_owned();
    let port = base.port_or_known_default().ok_or("api_url")?;
    let tls = base.scheme() == "https";
    let ws_url = format!("{}://{}{STREAM_PATH}", if tls { "wss" } else { "ws" }, base.authority());
    let mut request = ws_url.into_client_request().map_err(|_| "stream_request")?;
    for (name, value) in rt.api.signed_headers("GET", STREAM_PATH, &[], None).map_err(|_| "stream_sign")? {
        request.headers_mut().insert(name, HeaderValue::from_str(&value).map_err(|_| "stream_sign")?);
    }
    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| "stream_connect_timeout")?
        .map_err(|_| "stream_connect")?;
    let io = if tls {
        use rustls_platform_verifier::ConfigVerifierExt as _;
        let config = rustls::ClientConfig::with_platform_verifier().map_err(|_| "tls_config")?;
        let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|_| "tls_name")?;
        let stream =
            tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await.map_err(|_| "tls_handshake")?;
        Io::Tls(Box::new(stream))
    } else {
        Io::Plain(tcp)
    };
    let config = WebSocketConfig::default().max_message_size(Some(64 * 1024)).max_frame_size(Some(64 * 1024));
    let (socket, _) = tokio::time::timeout(
        Duration::from_secs(15),
        tokio_tungstenite::client_async_with_config(request, io, Some(config)),
    )
    .await
    .map_err(|_| "stream_handshake_timeout")?
    .map_err(|_| "stream_handshake")?;
    Ok(socket)
}

async fn session(rt: &Arc<Runtime>, mut socket: Socket) -> Attempt {
    let mut shutdown = rt.shutdown.subscribe();
    // Les évènements sont traités dans l'ordre par une tâche dédiée : la lecture (et le `pong`)
    // n'attend jamais un appel à l'API.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ApiEvent>(1024);
    let processor = {
        let rt = Arc::clone(rt);
        tokio::spawn(async move {
            while let Some(e) = rx.recv().await {
                rt.on_api_event(e).await;
            }
        })
    };
    // Relecture complète après (re)connexion ; annulée à la fin de la session.
    let reload = {
        let rt = Arc::clone(rt);
        tokio::spawn(async move {
            if let Err(e) = rt.load_delegations().await {
                tracing::warn!(error = %e, "délégations non relues");
            }
            if let Err(e) = rt.scan_pending().await {
                tracing::warn!(error = %e, "conversations en attente non relues");
            }
        })
    };
    let mut presence = tokio::time::interval(Duration::from_secs(30));
    let result = loop {
        tokio::select! {
            msg = tokio::time::timeout(Duration::from_secs(60), socket.next()) => match msg {
                Err(_) | Ok(None) | Ok(Some(Err(_))) => break Attempt::Lost,
                Ok(Some(Ok(Message::Text(text)))) => match parse_api_event(text.as_str()) {
                    Ok(ApiEvent::Ping) => {
                        if socket.send(Message::Text(pong_frame().into())).await.is_err() {
                            break Attempt::Lost;
                        }
                    }
                    Ok(ApiEvent::Hello { org_id, .. }) if rt.org_id().await.as_deref() != Some(org_id.as_str()) => {
                        // Le flux annonce une autre org que celle du certificat : on ferme.
                        rt.state.lock().await.alert(crate::clock::now_secs(), "stream_org_mismatch");
                        break Attempt::Lost;
                    }
                    Ok(event) => {
                        if tx.send(event).await.is_err() {
                            break Attempt::Lost;
                        }
                    }
                    Err(_) => tracing::warn!(code = "stream_bad_frame", "trame du flux ignorée"),
                },
                Ok(Some(Ok(Message::Close(frame)))) => {
                    let (code, reason) = frame.map_or((1005, String::new()), |f| (u16::from(f.code), f.reason.as_str().chars().take(64).collect()));
                    break Attempt::Closed(code, reason);
                }
                Ok(Some(Ok(_))) => {}
            },
            _ = presence.tick() => {
                let workers = rt.state.lock().await.active_workers();
                if socket.send(Message::Text(presence_frame(u64::try_from(workers).unwrap_or(0)).into())).await.is_err() {
                    break Attempt::Lost;
                }
            }
            () = crate::runtime::stopped(&mut shutdown) => break Attempt::Shutdown,
        }
    };
    drop(tx);
    reload.abort();
    let processor_abort = processor.abort_handle();
    if tokio::time::timeout(Duration::from_secs(5), processor).await.is_err() {
        processor_abort.abort();
    }
    let _ = socket.close(None).await;
    result
}

/// Boucle du flux, jusqu'au désappairage ou à l'arrêt.
pub async fn run(rt: Arc<Runtime>) -> StreamEnd {
    let mut delay = Duration::from_secs(1);
    loop {
        if rt.is_shutting_down() {
            return StreamEnd::Shutdown;
        }
        let started = Instant::now();
        let outcome = match connect(&rt).await {
            Ok(socket) => {
                tracing::info!(code = "stream_connected", "flux de notifications ouvert");
                session(&rt, socket).await
            }
            Err(code) => {
                tracing::warn!(code, "flux de notifications injoignable");
                Attempt::Lost
            }
        };
        match outcome {
            Attempt::Shutdown => return StreamEnd::Shutdown,
            Attempt::Closed(code, reason) => {
                tracing::warn!(close = code, reason = %reason, "flux fermé par l'API");
                if matches!(reason.as_str(), "rt_revoked" | "rt_unknown") {
                    return StreamEnd::Unpaired;
                }
                if code == 4409 {
                    rt.state.lock().await.alert(crate::clock::now_secs(), "stream_replaced");
                }
            }
            Attempt::Lost => {}
        }
        if started.elapsed() >= Duration::from_secs(60) {
            delay = Duration::from_secs(1);
        }
        let mut jitter = [0u8; 2];
        let _ = synco_e2ee::OsRandom.fill(&mut jitter);
        let jitter_ms = u64::from(u16::from_be_bytes(jitter)) % 1_000;
        let wait = delay.saturating_add(Duration::from_millis(jitter_ms));
        let mut shutdown = rt.shutdown.subscribe();
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = crate::runtime::stopped(&mut shutdown) => return StreamEnd::Shutdown,
        }
        delay = delay.saturating_mul(2).min(Duration::from_secs(60));
    }
}
