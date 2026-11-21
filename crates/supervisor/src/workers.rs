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
/// Relevé de la consommation du cgroup d'un worker pour le dashboard (docs/plan/11).
const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);

const fn done_reason(r: pipe::DoneReason) -> &'static str {
    match r {
        pipe::DoneReason::Idle => "idle",
        pipe::DoneReason::Awaiting => "awaiting",
        pipe::DoneReason::Failed => "failed",
        pipe::DoneReason::Cancelled => "cancelled",
        pipe::DoneReason::Shutdown => "shutdown",
    }
}

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
        if !st.vault.has_conversation_key(&auth.user_id, session_id, now_secs()) {
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
    let (init, keys, llm) = match prepared {
        Ok(p) => p,
        Err(code) => {
            if code != "init_unavailable" {
                // Fournisseur LLM non configuré dans le runtime (ou URL de passerelle refusée) : la
                // conversation échoue clairement au lieu d'être relancée en boucle, avec
                // `provider_not_configured` (Q30, spec API §14.3), distinct de `provider_error` ; la
                // cause exacte est dans le journal du runtime.
                tracing::warn!(code, "conversation refusée : fournisseur LLM non utilisable");
                let _ = rt
                    .api
                    .write_status(session_id, &auth_id, lease.lease_epoch, "failed", Some("provider_not_configured"))
                    .await;
            }
            let _ = rt.api.release_lease(session_id, &auth_id, lease.lease_epoch).await;
            release_slot(Arc::clone(rt), session_id.to_owned()).await;
            return Err(code);
        }
    };
    let l = &rt.config.limits;
    let spec = WorkerSpec {
        session_id: session_id.to_owned(),
        user_id: user_id.clone(),
        resources: ResourceLimits {
            memory_max_bytes: l.worker_memory_max_mib.saturating_mul(1024 * 1024),
            cpu_max_percent: l.worker_cpu_percent,
            pids_max: l.worker_pids_max,
        },
        llm,
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
            created_keys: 0,
            created_threads: Default::default(),
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
    match read_incoming(rd).await? {
        Incoming::Msg(m) => Ok(m),
        // Avant `start`, le worker n'envoie aucune clé.
        Incoming::CreatedKey(_) => Err(pipe::PipeError::BadMessage),
    }
}

/// Trame reçue du worker.
enum Incoming {
    Msg(WorkerMsg),
    /// Seule trame `0x02` admise d'un worker : la clé d'un salon qu'il vient de créer (L07).
    CreatedKey(KeyFrame),
}

async fn read_incoming(rd: &mut ReadHalf<Box<dyn WorkerIo>>) -> Result<Incoming, pipe::PipeError> {
    match pipe::read_frame(rd).await? {
        Frame::Json(j) => pipe::decode_json(&j).map(Incoming::Msg),
        Frame::Keys(k) => {
            let frame = KeyFrame::decode(&k)?;
            if frame.is_created_thread_key() { Ok(Incoming::CreatedKey(frame)) } else { Err(pipe::PipeError::BadKeys) }
        }
    }
}

/// Clé de salon créée par le worker (`create_thread`, 03 §10, §10.1) : le superviseur calcule
/// l'engagement depuis la clé, signe l'enveloppe `rt1` avec `csk` et chiffre l'entrée sous `DK` de la
/// délégation **du propriétaire**. Il n'installe pas la clé dans le coffre : elle y entrera par le
/// chemin normal (`delegation.entries_added` après la pose de l'entrée par le worker). Borné à
/// [`pipe::MAX_CREATED_KEYS_PER_WORKER`] par worker, et réservé aux salons dont **ce** worker a
/// relayé la création réussie (`POST /e2ee/threads`, id lu dans la réponse 2xx), une clé par salon :
/// un worker compromis ne peut pas faire signer `rt1` pour un salon quelconque.
///
/// Délégation : le superviseur ne connaît que la délégation courante du propriétaire (une par
/// utilisateur dans le coffre), pas le `delegationId` de l'autorisation que l'API contrôle (04 §4.3,
/// contrôle 7 ; l'API met l'autorisation à jour au remplacement de la délégation). Si les deux
/// diffèrent un instant, l'échec est **fermé** : l'API refuse la signature (octets signés avec un
/// autre `delegationId`, `400`) et l'entrée (`/delegations/<autre>/entries` → `out_of_scope`) ; le
/// salon reste en TOFU (03 §10.1), aucune enveloppe fausse n'est posée.
pub(crate) async fn created_key(
    rt: &Arc<Runtime>,
    session: &str,
    user_id: &str,
    frame: &KeyFrame,
) -> pipe::CreatedKeyMsg {
    let Some(entry) = frame.entries.first() else {
        return created_key_error("", "created_key_failed");
    };
    let reference = entry.reference.clone();
    let mut st = rt.state.lock().await;
    let Some(WorkerState::Running(w)) = st.convs.get_mut(session).map(|c| &mut c.worker) else {
        return created_key_error(&reference, "created_key_failed");
    };
    if w.created_keys >= pipe::MAX_CREATED_KEYS_PER_WORKER {
        return created_key_error(&reference, "created_key_limit");
    }
    // Seulement un salon dont CE worker a relayé la création réussie, et une seule clé par salon.
    if !w.created_threads.remove(&reference) {
        return created_key_error(&reference, "created_key_unknown_thread");
    }
    w.created_keys = w.created_keys.saturating_add(1);
    let Some(delegation) = st.vault.get(user_id).filter(|d| d.exp() > now_secs()) else {
        return created_key_error(&reference, "delegation_unavailable");
    };
    let Ok(key) = synco_e2ee::SymmetricKey::from_slice(&entry.key) else {
        return created_key_error(&reference, "created_key_failed");
    };
    let ctx = synco_e2ee::keys::thread_context(&reference);
    let delegation_id = delegation.delegation_id().to_owned();
    let signed = synco_e2ee::keys::sign_rt1_envelope(rt.keys.csk(), key.as_bytes(), &ctx, 1, &delegation_id);
    let sealed = delegation.seal_created_thread_entry(&reference, &key);
    match (signed, sealed) {
        (Ok(sig), Ok(ciphertext)) => {
            // Q21 : registre des salons créés ici (seuls réparables par `thread.envelope_reset`).
            if !st.created_threads.record(&reference, user_id, &delegation_id) {
                st.alert(now_secs(), "created_threads_full");
            }
            // Écriture du registre hors du verrou d'état (pas de `fsync` sous le verrou).
            let snapshot = st.created_threads.snapshot();
            drop(st);
            rt.save_created_threads(snapshot).await;
            pipe::CreatedKeyMsg {
                reference,
                envelope: Some(pipe::CreatedKeyEnvelope {
                    delegation_id,
                    commitment: sig.commitment,
                    signature: sig.signature,
                    ciphertext,
                }),
                error: None,
            }
        }
        _ => created_key_error(&reference, "created_key_failed"),
    }
}

/// Route de création d'un salon par le runtime (04 §4.3).
pub const CREATE_THREAD_PATH: &str = "/api/runtime/v1/e2ee/threads";
/// Salons créés en attente de leur clé, au plus, par worker.
const MAX_PENDING_CREATED_THREADS: usize = 64;

async fn note_created_thread(rt: &Arc<Runtime>, session: &str, epoch: u64, body: &[u8]) {
    let id = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("id").and_then(serde_json::Value::as_str).map(str::to_owned))
        .filter(|id| runtime_protocol::ids::is_identifier(id));
    let Some(id) = id else { return };
    let mut st = rt.state.lock().await;
    if let Some(WorkerState::Running(w)) = st.convs.get_mut(session).map(|c| &mut c.worker)
        && w.epoch == epoch
        && w.created_threads.len() < MAX_PENDING_CREATED_THREADS
    {
        w.created_threads.insert(id);
    }
}

/// Annuaire des clés publiques des membres (04 §4.3), relu par `create_thread` avant de sceller.
pub const MEMBER_KEYS_PATH: &str = "/api/runtime/v1/e2ee/members/keys";
/// Code rendu au worker à la place de l'annuaire quand une clé a changé sans preuve (Q25).
pub const MEMBER_KEY_CHANGED: &str = "member_key_changed";
/// Vérifications de rotation (appels `sign-key`) au plus par réponse de l'annuaire.
pub const MAX_ROTATION_LOOKUPS: usize = 8;

/// Variante non canonique du chemin de l'annuaire (casse, `/` final, `//`, segment `.`) : Express
/// (ni strict, ni sensible à la casse) et la normalisation des URL l'enverraient au même annuaire,
/// sans passer par [`member_keys_gate`]. Refusée au relais (défense en profondeur, revue M1 ;
/// l'encodage `%` est déjà refusé par [`worker_path_allowed`]).
#[must_use]
pub fn member_keys_variant(path: &str) -> bool {
    let raw = path.split('?').next().unwrap_or_default();
    if raw == MEMBER_KEYS_PATH {
        return false;
    }
    let segments: Vec<String> =
        raw.split('/').filter(|s| !s.is_empty() && *s != ".").map(str::to_ascii_lowercase).collect();
    format!("/{}", segments.join("/")) == MEMBER_KEYS_PATH
}

/// Annuaire illisible (JSON invalide, `members` absent ou pas une liste) : refus fermé (502).
pub const MEMBER_KEYS_UNREADABLE: &str = "member_keys_unreadable";
/// Plafond d'épingles RSA atteint pour l'org : refus fermé.
pub const MEMBER_PINS_LIMIT: &str = "member_pins_limit";
/// Épingles RSA non enregistrées (ou runtime désappairé) : refus fermé.
pub const MEMBER_PINS_UNAVAILABLE: &str = "member_pins_unavailable";

/// Épinglage TOFU des clés RSA des membres (Q25, `member_pins`), appliqué par le superviseur à la
/// réponse 2xx de [`MEMBER_KEYS_PATH`] **avant** que le worker la voie. `Err(code)` : la réponse
/// entière est remplacée par une erreur (refus global, aucun scellement) — [`MEMBER_KEYS_UNREADABLE`]
/// (502), [`MEMBER_KEY_CHANGED`]
/// (une clé a changé sans chaîne d'identité valide), [`MEMBER_PINS_LIMIT`],
/// [`MEMBER_PINS_UNAVAILABLE`]. Un membre dont la clé est illisible ou hors bornes n'est pas
/// épinglé : le worker l'écarte lui-même (`skippedRecipients`).
///
/// Le verrou d'état n'est tenu que pour les comparaisons ; l'état est écrit **une fois** par étape,
/// hors du verrou (`Runtime::save_member_pins`), et l'écriture doit réussir avant que la réponse
/// soit rendue (sinon refus fermé).
pub async fn member_keys_gate(rt: &Arc<Runtime>, body: &[u8]) -> Result<(), &'static str> {
    use crate::member_pins::{MemberKey, SignHistory, Verdict, chain_vouches};
    // Revue M3 : un corps illisible n'est jamais transmis tel quel (échec fermé).
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else { return Err(MEMBER_KEYS_UNREADABLE) };
    let Some(members) = value.get("members").and_then(serde_json::Value::as_array) else {
        return Err(MEMBER_KEYS_UNREADABLE);
    };
    let listed: Vec<(String, MemberKey)> = members
        .iter()
        .filter_map(|m| {
            let id = m.get("userId")?.as_str().filter(|id| runtime_protocol::ids::is_identifier(id))?;
            Some((id.to_owned(), MemberKey::from_jwk(m.get("publicKey")?)?))
        })
        .collect();
    let now = now_secs();
    // (utilisateur, clé présentée, empreinte épinglée, clés de signature épinglées, liaison RSA)
    let (org, changed, full, snapshot) = {
        let mut st = rt.state.lock().await;
        let Some(org) = st.org_id.clone() else { return Err(MEMBER_PINS_UNAVAILABLE) };
        let mut changed = Vec::new();
        let mut full = false;
        for (user, key) in listed {
            match st.member_pins.check(&org, &user, &key, now) {
                Verdict::Pinned | Verdict::Trusted => {}
                Verdict::Full => full = true,
                Verdict::Changed => {
                    let from = st.member_pins.get(&org, &user).map(|p| p.fingerprint.clone()).unwrap_or_default();
                    let (sign, bound): (Vec<String>, Option<String>) = st
                        .pins
                        .get(&user)
                        .map(|p| (p.previous.iter().chain([&p.sign_key]).cloned().collect(), p.rsa_fingerprint.clone()))
                        .unwrap_or_default();
                    changed.push((user, key, from, sign, bound));
                }
            }
        }
        if full {
            st.alert(now, "member_pins_limit");
        }
        (org, changed, full, st.member_pins.snapshot())
    };
    if !rt.save_member_pins(snapshot).await {
        return Err(MEMBER_PINS_UNAVAILABLE);
    }
    if full {
        return Err(MEMBER_PINS_LIMIT);
    }
    if changed.is_empty() {
        return Ok(());
    }
    // Rotation légitime : chaîne de transitions partant de la clé de signature épinglée (03 §4).
    // Seuls les utilisateurs qui ont délégué à ce runtime ont une telle épingle (et une route
    // `sign-key` qui répond) ; les autres ne peuvent être acceptés que par l'admin (dashboard).
    let mut refused = Vec::new();
    for (i, (user, key, from, sign, bound)) in changed.into_iter().enumerate() {
        let vouched = !sign.is_empty()
            && i < MAX_ROTATION_LOOKUPS
            && match rt.api.sign_key(&user).await {
                Ok(r) => {
                    let history = SignHistory { keys: &sign, bound_rsa: bound.as_deref() };
                    chain_vouches(&user, &history, &crate::pins::chain_from(&r.transitions), &from, &key)
                }
                Err(_) => false,
            };
        let mut st = rt.state.lock().await;
        // Désappairé ou réappairé pendant l'appel réseau : rien n'est installé.
        if st.org_id.as_deref() != Some(org.as_str()) {
            return Err(MEMBER_PINS_UNAVAILABLE);
        }
        if !(vouched && st.member_pins.rotate(&org, &user, &from, &key)) {
            refused.push((user, key, from));
        }
    }
    let snapshot = {
        let mut st = rt.state.lock().await;
        if st.org_id.as_deref() != Some(org.as_str()) {
            return Err(MEMBER_PINS_UNAVAILABLE);
        }
        for (user, key, from) in &refused {
            st.member_pins.refuse(&org, user, from, key, now);
        }
        if !refused.is_empty() {
            st.alert(now, "member_rsa_key_changed");
        }
        st.member_pins.snapshot()
    };
    let saved = rt.save_member_pins(snapshot).await;
    if !refused.is_empty() {
        return Err(MEMBER_KEY_CHANGED);
    }
    if saved { Ok(()) } else { Err(MEMBER_PINS_UNAVAILABLE) }
}

fn created_key_error(reference: &str, code: &str) -> pipe::CreatedKeyMsg {
    pipe::CreatedKeyMsg { reference: reference.to_owned(), envelope: None, error: Some(code.to_owned()) }
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
    // Dashboard (L08) : uniquement des compteurs et des états de liste fermée, jamais de contenu.
    let run_id = rt.history.begin_run(&session, &user_id, init.llm.provider.as_str(), &init.llm.model, now_secs());
    let mono = Instant::now();
    let mut sampler = tokio::time::interval(SAMPLE_INTERVAL);
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
                msg = read_incoming(&mut rd) => match msg {
                    Ok(Incoming::CreatedKey(frame)) => {
                        let resp = created_key(&rt, &session, &user_id, &frame).await;
                        tracing::info!(code = "worker_created_key", ok = resp.error.is_none(), "clé de salon créée par le worker");
                        let _ = tx.send(ToWorker::Json(SupervisorMsg::CreatedKey(resp))).await;
                    }
                    Ok(Incoming::Msg(WorkerMsg::Done(d))) => {
                        tracing::info!(code = "worker_done", reason = ?d.reason, "fin du worker");
                        rt.history.on_done(&run_id, done_reason(d.reason), now_secs());
                        done = true;
                    }
                    Ok(Incoming::Msg(m)) => {
                        if let Err(code) = on_worker_msg(&rt, &run_id, &session, &user_id, &auth_id, &tx, m).await {
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
                _ = sampler.tick() => {
                    if let Some(u) = process.usage() {
                        let ms = u64::try_from(mono.elapsed().as_millis()).unwrap_or(u64::MAX);
                        rt.history.on_sample(&run_id, u, now_secs(), ms);
                    }
                }
                changed = kill_rx.changed() => {
                    if changed.is_err() || *kill_rx.borrow() {
                        break;
                    }
                }
            }
        }
    }
    // Dernier relevé du cgroup, avant que le process ne disparaisse.
    if let Some(u) = process.usage() {
        let ms = u64::try_from(mono.elapsed().as_millis()).unwrap_or(u64::MAX);
        rt.history.on_sample(&run_id, u, now_secs(), ms);
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
    rt.history.end_run(&run_id, exit, !clean && !rt.is_shutting_down(), now_secs());
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
    run_id: &str,
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
                let mut frame: Arc<str> = Arc::from(s.event.to_string());
                // 05 §2 : un `snapshot` de plus de 1 Mio est remplacé par `ready { mode: "reload" }`.
                if frame.len() > runtime_protocol::client::MAX_RUNTIME_FRAME_BYTES {
                    let (epoch, last_seq) = match &conv.worker {
                        WorkerState::Running(w) => (w.epoch, w.last_seq),
                        _ => (0, 0),
                    };
                    let ready = runtime_protocol::client::Ready {
                        status: conv.status.clone(),
                        rev: 0,
                        epoch,
                        last_seq,
                        mode: runtime_protocol::client::ReadyMode::Reload,
                    };
                    frame = Arc::from(ready.to_frame());
                }
                if let Some(c) = conv.clients.iter().find(|c| c.id == client) {
                    let _ = c.tx.try_send(crate::state::ClientOut::Text(frame));
                }
            }
        }
        WorkerMsg::Status(s) => {
            rt.history.on_status(run_id, &s.status, s.reason.as_deref(), now_secs());
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
            let entries = st.vault.org_keys(user_id, &ids, now_secs());
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
            rt.history.on_metrics(run_id, &m, now_secs());
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
    if member_keys_variant(&req.path) {
        reply(tx, SignedResponse::failure(&req.id, "relay_refused"));
        return Ok(());
    }
    let (req, body, permit, epoch) = {
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
        (req, body, permit, w.epoch)
    };
    let auth = req.with_auth.then_some(auth_id.to_owned());
    let rt = Arc::clone(rt);
    let tx = tx.clone();
    let session = session.to_owned();
    tokio::spawn(async move {
        let _permit = permit;
        let result = rt.api.signed(Method::from(req.method), &req.path, body, auth.as_deref()).await;
        let parts = match result {
            Ok(r) => {
                // Salon créé par CE worker (réponse 2xx de l'API, id lu dans la réponse) : seule
                // source admise pour `created_key`. Noté AVANT que le worker voie la réponse.
                if req.method == pipe::HttpMethod::Post
                    && req.path == CREATE_THREAD_PATH
                    && (200..300).contains(&r.status)
                {
                    note_created_thread(&rt, &session, epoch, &r.body).await;
                }
                // Q25 : annuaire des clés des membres vérifié contre les épingles AVANT le worker.
                let member_keys = req.method == pipe::HttpMethod::Get
                    && req.path.split('?').next() == Some(MEMBER_KEYS_PATH)
                    && (200..300).contains(&r.status);
                if member_keys && let Err(code) = member_keys_gate(&rt, &r.body).await {
                    let headers = [("content-type".to_owned(), "application/json".to_owned())].into_iter().collect();
                    let body = serde_json::json!({ "error": code }).to_string();
                    let status = if code == MEMBER_KEYS_UNREADABLE { 502 } else { 409 };
                    for p in SignedResponse::split(&req.id, status, &headers, body.as_bytes()) {
                        if tx.send(ToWorker::Json(SupervisorMsg::SignedRequestResponse(p))).await.is_err() {
                            break;
                        }
                    }
                    return;
                }
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
        // Revue M1 : variantes de l'annuaire des clés (contrôle d'épinglage contourné sinon).
        assert!(!member_keys_variant(MEMBER_KEYS_PATH));
        assert!(!member_keys_variant("/api/runtime/v1/e2ee/members/keys?x=1"));
        assert!(!member_keys_variant("/api/runtime/v1/e2ee/threads"));
        for v in [
            "/api/runtime/v1/e2ee/members/keys/",
            "/api/runtime/v1/e2ee/Members/Keys",
            "/API/runtime/v1/e2ee/members/keys",
            "/api/runtime/v1/e2ee//members/keys",
            "/api/runtime/v1/e2ee/./members/keys",
            "/api/runtime/v1/e2ee/members/keys/.",
            "/api/runtime/v1/e2ee/members/keys/?x=1",
        ] {
            assert!(member_keys_variant(v), "{v}");
        }
        assert!(!worker_path_allowed("/api/runtime/v1/delegations/d1/entries", s, None));
    }
}
