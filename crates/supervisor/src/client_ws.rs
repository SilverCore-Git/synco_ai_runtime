//! WebSocket client ↔ runtime `GET /v1/conversations/:sessionId/ws` (docs/plan/05).
//!
//! 1. `hello` dans les 10 s (`4408`), ticket `srt1` vérifié **localement** (`4401` + code) ;
//! 2. autorisation de la conversation connue pour l'utilisateur du ticket (`4403`) ;
//! 3. ≤ 5 connexions par conversation (`4409`), 20 trames / 10 s (`4429`), trames texte strictes
//!    ≤ 256 Kio (`4400`) ;
//! 4. `ready` (`replay`, `snapshot` ou `idle`), puis évènements du worker diffusés tels quels ;
//! 5. éléments de boîte : dépôt durable dans l'API **avant** `queued`, puis transmission au worker
//!    (ou lancement).
//!
//! Journal : `sessionId` exclu, type de trame, taille, code de fermeture. Jamais le ticket ni une
//! valeur `gcm1:`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket};
use runtime_protocol::client::{
    self, ClientFrame, CloseCode, HELLO_TIMEOUT_SECS, IDLE_TIMEOUT_SECS, Ready, ReadyMode, Resume,
};
use runtime_protocol::pipe::{InboxMsg, SnapshotRequest, SupervisorMsg};
use runtime_protocol::ticket::{self, TicketContext, TicketError};
use tokio::sync::mpsc;

use crate::clock::now_secs;
use crate::ratelimit::Window;
use crate::runtime::Runtime;
use crate::state::{ClientOut, ClientSlot, ToWorker, WorkerState};

async fn close(socket: &mut WebSocket, code: u16, reason: &str) {
    tracing::debug!(close = code, reason, "fermeture du WebSocket client");
    let _ = socket.send(Message::Close(Some(CloseFrame { code, reason: Utf8Bytes::from(reason) }))).await;
}

/// Vérifie le ticket (02 §5) ; relit les clés une fois sur `kid` inconnu (≤ 1 / min).
async fn verify_ticket(
    rt: &Arc<Runtime>,
    session_id: &str,
    ticket_text: &str,
) -> Result<ticket::RuntimeTicketClaims, TicketError> {
    for attempt in 0..2 {
        let result = {
            let st = rt.state.lock().await;
            let Some(org) = st.org_id.as_deref() else { return Err(TicketError::WrongOrg) };
            let users: Vec<_> = st.tickets.revoked_users.iter().map(|(u, _)| u.clone()).collect();
            let convs: Vec<_> = st.tickets.revoked_conversations.iter().map(|(c, _)| c.clone()).collect();
            let ctx = TicketContext {
                runtime_id: rt.keys.runtime_id(),
                org_id: org,
                conv: session_id,
                revoked_users: &users,
                revoked_conversations: &convs,
            };
            ticket::verify_runtime_ticket(ticket_text, &st.tickets.keys, &ctx, now_secs())
        };
        match result {
            Err(TicketError::UnknownKey) if attempt == 0 => {
                if !rt.refresh_ticket_keys(true).await {
                    return Err(TicketError::UnknownKey);
                }
            }
            other => return other,
        }
    }
    Err(TicketError::UnknownKey)
}

/// Conduit une connexion cliente.
pub async fn handle(rt: Arc<Runtime>, session_id: String, mut socket: WebSocket) {
    if rt.is_shutting_down() {
        return close(&mut socket, CloseCode::ShuttingDown.code(), "shutting_down").await;
    }
    // 1. `hello` dans les 10 s.
    let first = tokio::time::timeout(Duration::from_secs(HELLO_TIMEOUT_SECS), socket.recv()).await;
    let hello = match first {
        Err(_) => return close(&mut socket, CloseCode::HelloTimeout.code(), "hello_timeout").await,
        Ok(Some(Ok(Message::Text(t)))) => match ClientFrame::parse(t.as_str()) {
            Ok(ClientFrame::Hello(h)) => h,
            _ => return close(&mut socket, CloseCode::BadFrame.code(), "bad_frame").await,
        },
        Ok(Some(Ok(_))) => return close(&mut socket, CloseCode::BadFrame.code(), "bad_frame").await,
        Ok(_) => return,
    };
    // 2. Ticket.
    let claims = match verify_ticket(&rt, &session_id, &hello.ticket).await {
        Ok(c) => c,
        Err(e) => return close(&mut socket, CloseCode::Ticket.code(), e.code()).await,
    };
    let resume = hello.resume;
    drop(hello);
    // 3. Autorisation et enregistrement du client.
    let capacity = rt.config.limits.replay_buffer_events.saturating_add(256);
    let (tx, mut rx) = mpsc::channel::<ClientOut>(capacity);
    let registered = register(&rt, &session_id, &claims.sub, tx, resume).await;
    let (client_id, auth_id, needs_head) = match registered {
        Ok(r) => r,
        Err(code) => return close(&mut socket, code.code(), code.default_reason()).await,
    };
    // Sans worker : `ready { idle }` avec la révision de l'API.
    if let Some(snapshot_status) = needs_head {
        let head = rt.api.conversation_head(&session_id, &auth_id).await;
        let ready = match head {
            Ok(h) => Ready { status: h.status, rev: h.rev, epoch: h.lease_epoch, last_seq: 0, mode: ReadyMode::Idle },
            Err(e) if matches!(e.code(), Some("auth_revoked" | "auth_expired" | "auth_invalid" | "out_of_scope")) => {
                unregister(&rt, &session_id, client_id).await;
                return close(&mut socket, CloseCode::Forbidden.code(), "forbidden").await;
            }
            Err(_) => Ready { status: snapshot_status, rev: 0, epoch: 0, last_seq: 0, mode: ReadyMode::Reload },
        };
        if socket.send(Message::Text(Utf8Bytes::from(ready.to_frame()))).await.is_err() {
            unregister(&rt, &session_id, client_id).await;
            return;
        }
    }
    tracing::debug!(client = client_id, "client connecté");
    run_connection(&rt, &session_id, &auth_id, &mut socket, &mut rx).await;
    unregister(&rt, &session_id, client_id).await;
}

/// Enregistre le client sous verrou et lui met en file `ready` (+ rejeu) si un worker tourne.
/// Renvoie `(id client, authId, Some(statut) si `ready` reste à construire depuis l'API)`.
async fn register(
    rt: &Arc<Runtime>,
    session_id: &str,
    user_id: &str,
    tx: mpsc::Sender<ClientOut>,
    resume: Option<Resume>,
) -> Result<(u64, String, Option<String>), CloseCode> {
    let mut st = rt.state.lock().await;
    let auth = st.auths.get(session_id).cloned().ok_or(CloseCode::Forbidden)?;
    if auth.user_id != user_id {
        return Err(CloseCode::Forbidden);
    }
    let id = st.next_client;
    st.next_client = st.next_client.saturating_add(1);
    let conv = rt.conv_entry(&mut st, session_id, &auth);
    if conv.user_id != user_id {
        return Err(CloseCode::Forbidden);
    }
    if conv.clients.len() >= client::MAX_CONNECTIONS_PER_CONVERSATION {
        return Err(CloseCode::TooManyConnections);
    }
    let mut needs_head = None;
    if let WorkerState::Running(w) = &conv.worker {
        let replay =
            resume.and_then(|r| (r.epoch == w.epoch).then(|| conv.buffer.replay_after(r.epoch, r.seq)).flatten());
        let (mode, frames) = match replay {
            Some(frames) => (ReadyMode::Replay, frames),
            None => (ReadyMode::Snapshot, vec![]),
        };
        let ready = Ready { status: conv.status.clone(), rev: 0, epoch: w.epoch, last_seq: w.last_seq, mode };
        let _ = tx.try_send(ClientOut::Text(Arc::from(ready.to_frame())));
        for f in frames {
            let _ = tx.try_send(ClientOut::Text(f));
        }
        if mode == ReadyMode::Snapshot && w.started {
            let request_id = format!("c{id}");
            if w.tx
                .try_send(ToWorker::Json(SupervisorMsg::SnapshotRequest(SnapshotRequest {
                    request_id: request_id.clone(),
                })))
                .is_ok()
            {
                conv.snapshots.insert(request_id, id);
            }
        }
    } else {
        needs_head = Some(conv.status.clone());
    }
    conv.clients.push(ClientSlot { id, user_id: user_id.to_owned(), tx });
    Ok((id, auth.auth_id, needs_head))
}

async fn unregister(rt: &Arc<Runtime>, session_id: &str, client_id: u64) {
    let mut st = rt.state.lock().await;
    let remove = match st.convs.get_mut(session_id) {
        Some(conv) => {
            conv.clients.retain(|c| c.id != client_id);
            conv.snapshots.retain(|_, c| *c != client_id);
            conv.clients.is_empty() && !conv.worker.is_active()
        }
        None => false,
    };
    if remove {
        st.convs.remove(session_id);
    }
}

async fn run_connection(
    rt: &Arc<Runtime>,
    session_id: &str,
    auth_id: &str,
    socket: &mut WebSocket,
    rx: &mut mpsc::Receiver<ClientOut>,
) {
    let mut rate = Window::new(client::RATE_FRAMES, Duration::from_secs(client::RATE_WINDOW_SECS));
    let idle = tokio::time::sleep(Duration::from_secs(IDLE_TIMEOUT_SECS));
    tokio::pin!(idle);
    loop {
        tokio::select! {
            out = rx.recv() => match out {
                Some(ClientOut::Text(frame)) => {
                    if socket.send(Message::Text(Utf8Bytes::from(&*frame))).await.is_err() {
                        return;
                    }
                }
                Some(ClientOut::Close(code, reason)) => return close(socket, code, &reason).await,
                None => return close(socket, CloseCode::Internal.code(), "internal").await,
            },
            incoming = socket.recv() => {
                let Some(Ok(msg)) = incoming else { return };
                idle.as_mut().reset(tokio::time::Instant::now().checked_add(Duration::from_secs(IDLE_TIMEOUT_SECS)).unwrap_or_else(tokio::time::Instant::now));
                if !rate.hit(Instant::now()) {
                    return close(socket, CloseCode::RateLimited.code(), "rate_limited").await;
                }
                let text = match msg {
                    Message::Text(t) => t,
                    Message::Close(_) => return,
                    Message::Ping(_) | Message::Pong(_) => continue,
                    Message::Binary(_) => return close(socket, CloseCode::BadFrame.code(), "bad_frame").await,
                };
                let Ok(frame) = ClientFrame::parse(text.as_str()) else {
                    return close(socket, CloseCode::BadFrame.code(), "bad_frame").await;
                };
                tracing::debug!(frame = frame_type(&frame), bytes = text.len(), "trame client");
                match frame {
                    ClientFrame::Ping(_) => {
                        if socket.send(Message::Text(Utf8Bytes::from(client::pong_frame()))).await.is_err() {
                            return;
                        }
                    }
                    ClientFrame::Hello(_) => return close(socket, CloseCode::BadFrame.code(), "bad_frame").await,
                    other => {
                        let Some(item) = other.inbox_item() else { continue };
                        // Dépôt durable AVANT l'accusé (05 §5.4).
                        match rt.api.deposit_inbox(session_id, auth_id, &item.body).await {
                            Ok(()) => {}
                            Err(e) => {
                                let (code, reason) = match e.code() {
                                    Some("inbox_full" | "rate_limited" | "rt_rate_limited") => (CloseCode::RateLimited, "rate_limited"),
                                    Some("auth_revoked" | "auth_expired" | "auth_invalid" | "out_of_scope" | "delegation_expired" | "delegation_revoked") => (CloseCode::Forbidden, "revoked"),
                                    Some("not_runtime") => (CloseCode::NotRuntime, "not_runtime"),
                                    _ => (CloseCode::Internal, "internal"),
                                };
                                return close(socket, code.code(), reason).await;
                            }
                        }
                        if socket.send(Message::Text(Utf8Bytes::from(client::queued_frame(&item.id)))).await.is_err() {
                            return;
                        }
                        forward_or_launch(rt, session_id, item.body).await;
                    }
                }
            }
            () = &mut idle => return close(socket, 1000, "idle_timeout").await,
        }
    }
}

const fn frame_type(f: &ClientFrame) -> &'static str {
    match f {
        ClientFrame::Hello(_) => "hello",
        ClientFrame::Message(_) => "message",
        ClientFrame::Confirm(_) => "confirm",
        ClientFrame::Answer(_) => "answer",
        ClientFrame::Upload(_) => "upload",
        ClientFrame::Cancel(_) => "cancel",
        ClientFrame::Ping(_) => "ping",
    }
}

/// Transmet l'élément au worker en cours, ou lance un worker.
async fn forward_or_launch(rt: &Arc<Runtime>, session_id: &str, body: serde_json::Value) {
    let sent = {
        let st = rt.state.lock().await;
        match st.convs.get(session_id).map(|c| &c.worker) {
            Some(WorkerState::Running(w)) => {
                w.tx.try_send(ToWorker::Json(SupervisorMsg::Inbox(InboxMsg { items: vec![body] }))).is_ok()
            }
            Some(WorkerState::Launching) => true,
            _ => false,
        }
    };
    if !sent {
        rt.ensure_worker(session_id);
    }
}
