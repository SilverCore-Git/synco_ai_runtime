//! Lancement et conduite d'un worker (docs/plan/06 §8) : bail pris **avant** le lancement, puis
//! `init` → `ready` → clés (trames `0x02`) → `start` ; relais des `signed_request` (signés par le
//! superviseur, chemins en liste fermée) ; diffusion des évènements sans les lire.

use std::sync::Arc;
use std::time::{Duration, Instant};

use runtime_protocol::client::check_worker_event;
use runtime_protocol::pipe::{
    self, Empty, Frame, KeyEntry, KeyFrame, KeyKind, KeyOp, SignedRequest, SignedResponse, SupervisorMsg, WorkerMsg,
};
use synco_e2ee::encoding::{b64, from_b64};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::{mpsc, watch};

use crate::api::{ApiError, Method};
use crate::clock::now_secs;
use crate::launcher::{ResourceLimits, WorkerIo, WorkerSpec};
use crate::ratelimit::TokenBucket;
use crate::runtime::Runtime;
use crate::state::{ToWorker, WorkerHandle, WorkerState};

const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Tue le worker après `delay` (si l'arrêt demandé n'a pas suffi).
pub fn kill_after(kill: watch::Sender<bool>, delay: Duration) {
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        let _ = kill.send(true);
    });
}

/// Chemins qu'un worker peut faire signer (06 §4) : sa conversation, les données E2EE, le ticket
/// LLM, les entrées de la délégation de **son** propriétaire. Aucun `..`, `//`, `%`.
#[must_use]
pub fn worker_path_allowed(path: &str, session_id: &str, owner_delegation: Option<&str>) -> bool {
    let plain = path.starts_with("/api/runtime/v1/")
        && !path.contains("..")
        && !path.contains("//")
        && path.bytes().all(|b| b.is_ascii_alphanumeric() || b"/-_:.?=&".contains(&b));
    if !plain {
        return false;
    }
    let conv = format!("/api/runtime/v1/conversations/{session_id}");
    let conv_ok =
        path.strip_prefix(&conv).is_some_and(|rest| rest.is_empty() || rest.starts_with('/') || rest.starts_with('?'));
    let deleg_ok = owner_delegation.is_some_and(|d| path == format!("/api/runtime/v1/delegations/{d}/entries"));
    conv_ok || path.starts_with("/api/runtime/v1/e2ee/") || path == "/api/runtime/v1/tickets/llm" || deleg_ok
}

/// Lance le worker d'une conversation, si les conditions sont réunies. Erreur = code de journal.
pub async fn launch(rt: &Arc<Runtime>, session_id: &str) -> Result<(), &'static str> {
    if rt.is_shutting_down() {
        return Err("shutting_down");
    }
    if rt.in_crash_loop(session_id).await {
        return Err("worker_crash_loop");
    }
    // 1. Réserver la place (sous verrou).
    let (user_id, auth_id) = {
        let mut st = rt.state.lock().await;
        if st.org_id.is_none() || st.shutting_down {
            return Err("not_paired");
        }
        let auth = st.auths.get(session_id).cloned().ok_or("authorization_unknown")?;
        if !st.vault.has_conversation_key(&auth.user_id, session_id) {
            return Err("conv_key_missing");
        }
        if st.convs.get(session_id).is_some_and(|c| c.worker.is_active()) {
            return Err("already_running");
        }
        if st.active_workers() >= rt.config.limits.max_workers {
            return Err("runtime_full");
        }
        if st.active_workers_of(&auth.user_id) >= rt.config.limits.max_workers_per_user {
            return Err("user_full");
        }
        let conv = rt.conv_entry(&mut st, session_id, &auth);
        if conv.user_id != auth.user_id {
            return Err("owner_mismatch");
        }
        conv.worker = WorkerState::Launching;
        (auth.user_id, auth.auth_id)
    };
    let release_slot = |rt: Arc<Runtime>, session: String| async move {
        let mut st = rt.state.lock().await;
        if let Some(c) = st.convs.get_mut(&session)
            && matches!(c.worker, WorkerState::Launching)
        {
            c.worker = WorkerState::None;
        }
        drop(st);
        rt.wake.notify_one();
    };
    // 2. Bail (07 §4) avant tout lancement.
    let lease = match rt.api.take_lease(session_id, &auth_id).await {
        Ok(l) => l,
        Err(e) => {
            release_slot(Arc::clone(rt), session_id.to_owned()).await;
            return Err(if e.code() == Some("lease_conflict") { "lease_conflict" } else { "lease_failed" });
        }
    };
    // 3. Paramètres et clés (sous verrou), puis lancement.
    let prepared = {
        let st = rt.state.lock().await;
        rt.build_init(&st, session_id, &user_id, &auth_id, lease.lease_epoch)
    };
    let Some((init, keys)) = prepared else {
        let _ = rt.api.release_lease(session_id, &auth_id, lease.lease_epoch).await;
        release_slot(Arc::clone(rt), session_id.to_owned()).await;
        return Err("init_unavailable");
    };
    let l = &rt.config.limits;
    let spec = WorkerSpec {
        session_id: session_id.to_owned(),
        user_id: user_id.clone(),
        resources: ResourceLimits {
            memory_max_bytes: l.worker_memory_max_mib.saturating_mul(1024 * 1024),
            memory_high_bytes: l.worker_memory_high_mib.saturating_mul(1024 * 1024),
            cpu_max_percent: l.worker_cpu_percent,
            pids_max: l.worker_pids_max,
        },
        allowed_hosts: allowed_hosts(rt, &init.llm.base_url),
    };
    let spawned = match rt.launcher.spawn(spec).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(code = e.0, "lancement du worker impossible");
            let _ = rt.api.release_lease(session_id, &auth_id, lease.lease_epoch).await;
            release_slot(Arc::clone(rt), session_id.to_owned()).await;
            return Err("spawn_failed");
        }
    };
    let (tx, rx) = mpsc::channel::<ToWorker>(256);
    let (kill_tx, kill_rx) = watch::channel(false);
    {
        let mut st = rt.state.lock().await;
        let Some(conv) = st.convs.get_mut(session_id) else {
            let _ = kill_tx.send(true);
            return Err("conversation_gone");
        };
        conv.buffer.clear();
        conv.status = "running".to_owned();
        conv.worker = WorkerState::Running(Box::new(WorkerHandle {
            tx: tx.clone(),
            kill: kill_tx.clone(),
            epoch: lease.lease_epoch,
            last_seq: 0,
            started: false,
            metrics: None,
            requests: TokenBucket::new(l.worker_signed_requests_per_sec, l.worker_signed_requests_burst),
            in_flight: Arc::new(tokio::sync::Semaphore::new(crate::state::RELAY_IN_FLIGHT_PER_WORKER)),
            uploads: Default::default(),
        }));
    }
    tracing::info!(code = "worker_launched", launcher = rt.launcher.name(), epoch = lease.lease_epoch, "worker lancé");
    let rt2 = Arc::clone(rt);
    let session = session_id.to_owned();
    tokio::spawn(async move {
        drive(rt2, session, user_id, auth_id, spawned, init, keys, tx, rx, kill_rx).await;
    });
    Ok(())
}

fn allowed_hosts(rt: &Runtime, llm_base_url: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    for url in [rt.config.api_url.as_str(), llm_base_url] {
        if let Ok(u) = reqwest::Url::parse(url)
            && let (Some(h), Some(p)) = (u.host_str(), u.port_or_known_default())
        {
            hosts.push(format!("{h}:{p}"));
        }
    }
    hosts.sort();
    hosts.dedup();
    hosts
}

async fn writer(mut wr: WriteHalf<Box<dyn WorkerIo>>, mut rx: mpsc::Receiver<ToWorker>) {
    while let Some(msg) = rx.recv().await {
        let res = match msg {
            ToWorker::Json(m) => pipe::write_json(&mut wr, &m).await,
            ToWorker::Keys(k) => pipe::write_keys(&mut wr, &k).await,
        };
        match res {
            // Une trame refusée à l'encodage (trop grande) n'est jamais une raison de fermer le
            // pipe : elle est abandonnée (le relais n'en produit pas, cf. `SignedResponse::split`).
            Err(pipe::PipeError::BadFrame | pipe::PipeError::BadMessage | pipe::PipeError::BadKeys) => {
                tracing::warn!(code = "pipe_frame_dropped", "trame vers le worker abandonnée");
            }
            Err(_) => break,
            Ok(()) => {}
        }
    }
}

async fn read_msg(rd: &mut ReadHalf<Box<dyn WorkerIo>>) -> Result<WorkerMsg, pipe::PipeError> {
    match pipe::read_frame(rd).await? {
        Frame::Json(j) => pipe::decode_json(&j),
        // Le worker n'envoie jamais de clés.
        Frame::Keys(_) => Err(pipe::PipeError::BadMessage),
    }
}

/// Conduite d'un worker jusqu'à sa fin.
#[allow(clippy::too_many_arguments, reason = "contexte d'une tâche de fond, assemblé une seule fois")]
async fn drive(
    rt: Arc<Runtime>,
    session: String,
    user_id: String,
    auth_id: String,
    spawned: crate::launcher::SpawnedWorker,
    init: pipe::Init,
    keys: Vec<KeyEntry>,
    tx: mpsc::Sender<ToWorker>,
    rx: mpsc::Receiver<ToWorker>,
    mut kill_rx: watch::Receiver<bool>,
) {
    let crate::launcher::SpawnedWorker { io, mut process } = spawned;
    let lease_epoch = init.lease_epoch;
    let (mut rd, wr) = tokio::io::split(io);
    let writer_task = tokio::spawn(writer(wr, rx));
    let mut done = false;
    let started = handshake(&mut rd, &tx, init, keys).await;
    if started {
        let mut st = rt.state.lock().await;
        if let Some(WorkerState::Running(w)) = st.convs.get_mut(&session).map(|c| &mut c.worker) {
            w.started = true;
        }
    } else {
        tracing::warn!(code = "worker_handshake_failed", "le worker n'a pas démarré");
    }
    // `done` seul n'arrête pas la lecture : le worker doit encore fermer son pipe.
    if started {
        loop {
            tokio::select! {
                msg = read_msg(&mut rd) => match msg {
                    Ok(WorkerMsg::Done(d)) => {
                        tracing::info!(code = "worker_done", reason = ?d.reason, "fin du worker");
                        done = true;
                    }
                    Ok(m) => {
                        if let Err(code) = on_worker_msg(&rt, &session, &user_id, &auth_id, &tx, m).await {
                            // Incident de sécurité ou violation du protocole : le worker est tué.
                            tracing::error!(code, "worker tué (violation du protocole)");
                            rt.state.lock().await.alert(now_secs(), code);
                            break;
                        }
                    }
                    Err(pipe::PipeError::Closed) => break,
                    Err(e) => {
                        tracing::error!(code = %e, "worker tué (trame invalide)");
                        break;
                    }
                },
                changed = kill_rx.changed() => {
                    if changed.is_err() || *kill_rx.borrow() {
                        break;
                    }
                }
            }
        }
    }
    // Fin : laisser le worker partir s'il a annoncé `done`, sinon le tuer.
    if !done {
        process.kill();
    }
    let exit = match tokio::time::timeout(Duration::from_secs(5), process.wait()).await {
        Ok(e) => e,
        Err(_) => {
            process.kill();
            process.wait().await
        }
    };
    writer_task.abort();
    let clean = done && exit.is_clean();
    {
        let mut st = rt.state.lock().await;
        if let Some(conv) = st.convs.get_mut(&session)
            && matches!(&conv.worker, WorkerState::Running(w) if w.epoch == lease_epoch)
        {
            conv.worker = WorkerState::None;
            conv.snapshots.clear();
        }
    }
    if !clean && !rt.is_shutting_down() {
        tracing::warn!(code = "worker_crashed", exit = ?exit, "worker arrêté sans fin normale");
        rt.record_crash(&session, &user_id, &auth_id).await;
    }
    rt.wake.notify_one();
}

/// `init` → `ready` (≤ 10 s) → clés → `start`.
async fn handshake(
    rd: &mut ReadHalf<Box<dyn WorkerIo>>,
    tx: &mpsc::Sender<ToWorker>,
    init: pipe::Init,
    keys: Vec<KeyEntry>,
) -> bool {
    if tx.send(ToWorker::Json(SupervisorMsg::Init(Box::new(init)))).await.is_err() {
        return false;
    }
    match tokio::time::timeout(READY_TIMEOUT, read_msg(rd)).await {
        Ok(Ok(WorkerMsg::Ready(_))) => {}
        _ => return false,
    }
    let Ok(frames) = KeyFrame::split(KeyOp::Add, keys) else { return false };
    for f in frames {
        if tx.send(ToWorker::Keys(f)).await.is_err() {
            return false;
        }
    }
    tx.send(ToWorker::Json(SupervisorMsg::Start(Empty {}))).await.is_ok()
}

async fn on_worker_msg(
    rt: &Arc<Runtime>,
    session: &str,
    user_id: &str,
    auth_id: &str,
    tx: &mpsc::Sender<ToWorker>,
    msg: WorkerMsg,
) -> Result<(), &'static str> {
    match msg {
        WorkerMsg::Event(e) => {
            let pos = check_worker_event(&e.event).map_err(|_| "worker_bad_event")?;
            let frame: Arc<str> = Arc::from(e.event.to_string());
            if frame.len() > runtime_protocol::client::MAX_RUNTIME_FRAME_BYTES {
                return Err("worker_event_too_large");
            }
            let mut st = rt.state.lock().await;
            let Some(conv) = st.convs.get_mut(session) else { return Ok(()) };
            let WorkerState::Running(w) = &mut conv.worker else { return Ok(()) };
            if pos.epoch != w.epoch || pos.seq <= w.last_seq {
                return Err("worker_event_out_of_order");
            }
            w.last_seq = pos.seq;
            conv.buffer.push(pos.epoch, pos.seq, Arc::clone(&frame));
            Runtime::broadcast(conv, &frame);
        }
        WorkerMsg::Snapshot(s) => {
            check_worker_event(&s.event).map_err(|_| "worker_bad_event")?;
            let mut st = rt.state.lock().await;
            let Some(conv) = st.convs.get_mut(session) else { return Ok(()) };
            if let Some(client) = conv.snapshots.remove(&s.request_id) {
                let frame: Arc<str> = Arc::from(s.event.to_string());
                if let Some(c) = conv.clients.iter().find(|c| c.id == client) {
                    let _ = c.tx.try_send(crate::state::ClientOut::Text(frame));
                }
            }
        }
        WorkerMsg::Status(s) => {
            let mut st = rt.state.lock().await;
            if let Some(conv) = st.convs.get_mut(session)
                && s.status.len() <= 32
                && runtime_protocol::ids::is_identifier(&s.status)
            {
                conv.status = s.status;
            }
        }
        WorkerMsg::NeedKey(n) => {
            let kind = KeyKind::parse(&n.kind)
                .filter(|k| matches!(k, KeyKind::Thread | KeyKind::Space))
                .ok_or("worker_bad_need_key")?;
            let st = rt.state.lock().await;
            let ids: Vec<crate::vault::KeyId> = st
                .vault
                .get(user_id)
                .map(|d| d.key_ids().into_iter().filter(|k| k.kind == kind && k.reference == n.reference).collect())
                .unwrap_or_default();
            let entries = st.vault.org_keys(user_id, &ids);
            drop(st);
            if !entries.is_empty() {
                for f in KeyFrame::split(KeyOp::Add, entries).unwrap_or_default() {
                    let _ = tx.send(ToWorker::Keys(f)).await;
                }
            }
        }
        WorkerMsg::SignedRequest(req) => relay(rt, session, user_id, auth_id, tx, req).await?,
        WorkerMsg::InboxAck(a) => tracing::debug!(code = "inbox_ack", count = a.ids.len(), "éléments consommés"),
        WorkerMsg::Metrics(m) => {
            let mut st = rt.state.lock().await;
            if let Some(WorkerState::Running(w)) = st.convs.get_mut(session).map(|c| &mut c.worker) {
                w.metrics = Some(*m);
            }
        }
        WorkerMsg::Log(l) => {
            if l.is_contentless() {
                let fields = serde_json::Value::Object(l.fields.into_iter().collect()).to_string();
                match l.level.as_str() {
                    "error" => tracing::error!(code = %l.code, fields = %fields, "worker"),
                    "warn" => tracing::warn!(code = %l.code, fields = %fields, "worker"),
                    "info" => tracing::info!(code = %l.code, fields = %fields, "worker"),
                    _ => tracing::debug!(code = %l.code, fields = %fields, "worker"),
                }
            } else {
                tracing::warn!(code = "worker_log_rejected", "journal du worker refusé (contenu possible)");
            }
        }
        WorkerMsg::Ready(_) => return Err("worker_unexpected_ready"),
        WorkerMsg::Done(_) => {}
    }
    Ok(())
}

fn reply(tx: &mpsc::Sender<ToWorker>, resp: SignedResponse) {
    let _ = tx.try_send(ToWorker::Json(SupervisorMsg::SignedRequestResponse(resp)));
}

/// `signed_request` (06 §4) : liste fermée de chemins, débit borné, `x-synco-auth` = autorisation de
/// **cette** conversation (jamais choisie par le worker). Hors liste : incident, worker tué.
/// Corps en parties (`part`, `last`) réassemblé ici ; requêtes en vol bornées par worker et pour
/// tout le runtime (au-delà : `status = 0`, `relay_busy`, sans fermer le pipe) ; la réponse est
/// renvoyée en parties de ≤ 512 Kio.
async fn relay(
    rt: &Arc<Runtime>,
    session: &str,
    user_id: &str,
    auth_id: &str,
    tx: &mpsc::Sender<ToWorker>,
    req: SignedRequest,
) -> Result<(), &'static str> {
    if req.id.is_empty() || req.id.len() > 64 {
        return Err("worker_bad_request_id");
    }
    let (req, body, permit) = {
        let mut st = rt.state.lock().await;
        let owner_delegation = st.vault.get(user_id).map(|d| d.delegation_id().to_owned());
        if !worker_path_allowed(&req.path, session, owner_delegation.as_deref()) {
            return Err("worker_path_forbidden");
        }
        let Some(WorkerState::Running(w)) = st.convs.get_mut(session).map(|c| &mut c.worker) else { return Ok(()) };
        // Réassemblage d'un corps en plusieurs parties.
        let (req, body) = if req.part == 0 && req.last {
            let body =
                if req.body.is_empty() { None } else { Some(from_b64(&req.body).map_err(|_| "worker_bad_body")?) };
            if body.as_ref().is_some_and(|b| b.len() > pipe::RELAY_CHUNK_BYTES) {
                return Err("worker_bad_body");
            }
            (req, body)
        } else {
            let id = req.id.clone();
            if req.part == 0 {
                if w.uploads.len() >= crate::state::RELAY_UPLOADS_PER_WORKER || w.uploads.contains_key(&id) {
                    reply(tx, SignedResponse::failure(&id, "relay_busy"));
                    return Ok(());
                }
                w.uploads.insert(id.clone(), (req.clone(), pipe::Reassembly::default()));
            }
            let Some((head, buf)) = w.uploads.get_mut(&id) else {
                reply(tx, SignedResponse::failure(&id, "relay_bad_part"));
                return Ok(());
            };
            let same = head.method == req.method && head.path == req.path && head.with_auth == req.with_auth;
            let pushed =
                if same { buf.push(req.part, &req.body, pipe::MAX_RELAY_REQUEST_BYTES) } else { Err("relay_bad_part") };
            if let Err(code) = pushed {
                w.uploads.remove(&id);
                reply(tx, SignedResponse::failure(&id, code));
                return Ok(());
            }
            if !req.last {
                return Ok(());
            }
            let Some((head, buf)) = w.uploads.remove(&id) else { return Ok(()) };
            let body = if buf.is_empty() { None } else { Some(buf.into_body()) };
            (head, body)
        };
        if !w.requests.take(Instant::now()) {
            reply(
                tx,
                SignedResponse {
                    status: 429,
                    body: b64(br#"{"error":"rt_rate_limited"}"#),
                    ..SignedResponse::failure(&req.id, "relay_rate_limited")
                },
            );
            return Ok(());
        }
        let permits = Arc::clone(&w.in_flight)
            .try_acquire_owned()
            .ok()
            .zip(Arc::clone(&rt.relay_permits).try_acquire_owned().ok());
        let Some(permit) = permits else {
            reply(tx, SignedResponse::failure(&req.id, "relay_busy"));
            return Ok(());
        };
        (req, body, permit)
    };
    let auth = req.with_auth.then_some(auth_id.to_owned());
    let rt = Arc::clone(rt);
    let tx = tx.clone();
    tokio::spawn(async move {
        let _permit = permit;
        let result = rt.api.signed(Method::from(req.method), &req.path, body, auth.as_deref()).await;
        let parts = match result {
            Ok(r) => {
                let headers =
                    r.content_type.map(|c| [("content-type".to_owned(), c)].into_iter().collect()).unwrap_or_default();
                SignedResponse::split(&req.id, r.status, &headers, &r.body)
            }
            Err(e) => {
                let code = match e {
                    ApiError::Refused => "relay_refused",
                    ApiError::Decode => "relay_too_large",
                    _ => "relay_network",
                };
                vec![SignedResponse::failure(&req.id, code)]
            }
        };
        for p in parts {
            if tx.send(ToWorker::Json(SupervisorMsg::SignedRequestResponse(p))).await.is_err() {
                break;
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chemins_du_worker() {
        let s = "sess1";
        for ok in [
            "/api/runtime/v1/conversations/sess1",
            "/api/runtime/v1/conversations/sess1/transcript",
            "/api/runtime/v1/conversations/sess1/inbox?after=x",
            "/api/runtime/v1/conversations/sess1/tools/search/execute",
            "/api/runtime/v1/e2ee/threads",
            "/api/runtime/v1/tickets/llm",
            "/api/runtime/v1/delegations/d1/entries",
        ] {
            assert!(worker_path_allowed(ok, s, Some("d1")), "{ok}");
        }
        for bad in [
            "/api/runtime/v1/conversations/sess10",
            "/api/runtime/v1/conversations/autre/transcript",
            "/api/runtime/v1/conversations/sess1/../autre",
            "/api/runtime/v1/conversations?state=pending",
            "/api/runtime/v1/delegations",
            "/api/runtime/v1/delegations/d2/entries",
            "/api/runtime/v1/delegations/d1/status",
            "/api/runtime/v1/users/u1/sign-key",
            "/api/runtime/v1/register",
            "/api/runtime/v1/unpair",
            "/api/runtime/v1/e2ee/%2e%2e/x",
            "/api/orgs/o/ai/sessions",
            "https://ailleurs.example.com/api/runtime/v1/e2ee/threads",
        ] {
            assert!(!worker_path_allowed(bad, s, Some("d1")), "{bad}");
        }
        assert!(!worker_path_allowed("/api/runtime/v1/delegations/d1/entries", s, None));
    }
}
