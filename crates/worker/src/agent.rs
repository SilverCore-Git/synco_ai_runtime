//! Boucle d'agent **durable** d'une conversation (lot L07), équivalente à `aiTurnRunner.ts` :
//!
//! - chaque étape est enregistrée **chiffrée** dans l'API (`PUT …/transcript`, `rev`, `leaseEpoch`),
//!   les deltas partent en direct aux clients (évènements chiffrés, [`crate::events`]) ;
//! - boîte de réception dédupliquée par `id` (06 §3) : messages pris en compte à l'étape suivante,
//!   décisions (`confirm`, `answer`, `upload`), annulation (08 §4) ;
//! - politique D5 (`auto` / `ask` / `deny`), outils interactifs (`awaiting_user`), clé manquante
//!   (`awaiting_key`) ; le worker s'arrête pendant une attente (P3) ;
//! - **écriture anticipée** `executing` avant tout outil mutant ; à la reprise, un outil mutant
//!   `executing` n'est **jamais** relancé (`unknown_outcome` + évènement `tool_unknown_outcome`,
//!   08 §5) ;
//! - plafonds D6 de `init.limits` ; métriques sans contenu ; bail renouvelé toutes les 20 s.
//!
//! Aucun contenu n'est journalisé : les `log` ne portent que des codes et des nombres.

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use runtime_protocol::pipe::{
    self, DoneMsg, DoneReason, HttpMethod, InboxAckMsg, LlmProvider, LogMsg, NeedKeyMsg, PipeError, ShutdownMsg,
    StatusMsg, WorkerMsg,
};
use serde_json::{Value, json};
use synco_e2ee::session::{self, ANSWER_MESSAGE_ID};
use synco_e2ee::{OsRandom, RandomSource, SymmetricKey};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::api::{Api, ApiResponse, PREFIX};
use crate::events::Emitter;
use crate::link::{self, Control, Link};
use crate::metrics::Counters;
use crate::provider::{
    self, ChatMessage, ChatRequest, ChatToolCall, FinishReason, LlmAdapter, LlmError, LlmEvent, ToolDef, Usage,
};
use crate::tools::{self, Decision, Outcome, ToolCtx, ToolSpec};
use crate::transcript::{self, Message, PendingToolCall, Role, ToolCall, ToolStatus};

/// Résultat d'un outil dont l'exécution a été interrompue (08 §5, texte exact de la spec).
pub const UNKNOWN_OUTCOME_NOTE: &str =
    "L'exécution de cet outil a été interrompue : son résultat est inconnu. Vérifie l'état avant de réessayer.";
/// Refus de l'utilisateur (même texte que `aiTurnRunner.ts`).
pub const REJECTED_BY_USER: &str = "Action refusée par l'utilisateur.";
/// Plafond de `consumedInbox` par écriture (04 §4.2).
const MAX_CONSUMED_PER_WRITE: usize = 200;

/// Réglages (les valeurs par défaut sont celles de la spec ; les tests les raccourcissent).
#[derive(Debug, Clone)]
pub struct AgentOptions {
    /// Délais entre les essais d'un appel au fournisseur (08 §6 : 1 s, 4 s, 16 s).
    pub retry_delays: Vec<Duration>,
    /// Renouvellement du bail (06 §8 : 20 s).
    pub lease_renew: Duration,
    /// Métriques périodiques (06 §4 : 10 s).
    pub metrics_every: Duration,
    /// Attente d'une clé demandée au superviseur (`need_key`) avant `awaiting_key`.
    pub need_key_wait: Duration,
}

impl Default for AgentOptions {
    fn default() -> Self {
        Self {
            retry_delays: vec![Duration::from_secs(1), Duration::from_secs(4), Duration::from_secs(16)],
            lease_renew: Duration::from_secs(20),
            metrics_every: Duration::from_secs(10),
            need_key_wait: Duration::from_secs(2),
        }
    }
}

/// Arrêt anticipé de la boucle.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Stop {
    /// Le pipe est fermé.
    Pipe,
    /// Le bail n'est plus à nous : plus aucune écriture.
    LeaseLost,
    /// Erreur non récupérable : `failed` avec ce code (08 §6).
    Fatal(&'static str),
}

impl From<link::LinkError> for Stop {
    fn from(_: link::LinkError) -> Self {
        Self::Pipe
    }
}

impl From<crate::events::EmitError> for Stop {
    fn from(e: crate::events::EmitError) -> Self {
        match e {
            crate::events::EmitError::Closed => Self::Pipe,
            crate::events::EmitError::Encode => Self::Fatal("internal"),
        }
    }
}

/// Fin d'un tour ou d'une étape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    /// Continuer (appel suivant au modèle).
    Continue,
    /// Attente d'un humain ou d'une clé : le worker s'arrête.
    Awaiting,
    /// Tour terminé (`idle`).
    Idle,
    /// Conversation en échec.
    Failed,
    /// Annulée.
    Cancelled,
    /// Arrêt demandé : état enregistré, reprise par un prochain worker.
    Shutdown,
}

/// Ce que la boîte de réception a apporté.
#[derive(Debug, Default)]
struct Absorbed {
    run_model: bool,
    cancelled: bool,
}

/// Message assistant en cours de génération (pour `snapshot`).
#[derive(Default)]
struct Live {
    id: String,
    text: String,
    thinking: String,
}

fn uuid() -> String {
    let mut b = [0u8; 16];
    let _ = OsRandom.fill(&mut b);
    runtime_protocol::ids::uuid_v4_from_bytes(b)
}

fn call_id() -> String {
    let mut b = [0u8; 12];
    let _ = OsRandom.fill(&mut b);
    format!("call_{}", synco_e2ee::encoding::hex(&b))
}

fn now() -> String {
    crate::time::now_iso8601()
}

/// Lance la boucle d'agent sur le pipe `io` jusqu'à la fin du worker.
pub async fn run<S>(io: S, llm_socket: Option<PathBuf>, opts: AgentOptions) -> Result<DoneReason, PipeError>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let Some((link, init, ctl)) = link::connect(io).await? else { return Ok(DoneReason::Shutdown) };
    let Some(ck) = link.with_keys(|k| k.conv()) else {
        // Sans `CK`, rien ne peut être lu ni écrit : échec sans contenu.
        let api = Api::new(link.clone(), &init.session_id);
        let body = json!({ "leaseEpoch": init.lease_epoch, "status": "failed", "error": "internal" });
        let _ = api.conv(HttpMethod::Post, "/status", Some(&body)).await;
        let _ = api.conv(HttpMethod::Delete, "/lease", Some(&json!({ "leaseEpoch": init.lease_epoch }))).await;
        let _ = link.send(log("error", "conv_key_missing", &[])).await;
        let _ = link.send(WorkerMsg::Done(DoneMsg { reason: DoneReason::Failed })).await;
        return Ok(DoneReason::Failed);
    };
    let mut agent = Agent::new(link, init, ck, ctl, llm_socket, opts);
    let reason = agent.run().await;
    Ok(reason)
}

fn log(level: &str, code: &str, fields: &[(&str, Value)]) -> WorkerMsg {
    WorkerMsg::Log(LogMsg {
        level: level.into(),
        code: code.into(),
        fields: fields.iter().map(|(k, v)| ((*k).to_owned(), v.clone())).collect(),
    })
}

struct Agent {
    link: Link,
    api: Api,
    init: pipe::Init,
    ck: SymmetricKey,
    em: Emitter,
    ctl: mpsc::Receiver<Control>,
    socket: Option<PathBuf>,
    adapter: Arc<dyn LlmAdapter>,
    opts: AgentOptions,
    specs: Vec<ToolSpec>,
    llm_tools: Vec<ToolDef>,
    messages: Vec<Message>,
    saved_len: usize,
    rev: u64,
    status: String,
    error: Option<&'static str>,
    pending: Option<PendingToolCall>,
    awaiting_key: Option<String>,
    consumed: Vec<String>,
    seen: HashSet<String>,
    queue: VecDeque<(String, Value)>,
    events: Vec<Value>,
    conv_tokens: u64,
    counters: Counters,
    ticket: Option<(String, Instant)>,
    live: Option<Live>,
    shutdown: Option<ShutdownMsg>,
    lease_lost: Arc<AtomicBool>,
    last_metrics: Instant,
}

impl Agent {
    fn new(
        link: Link,
        init: pipe::Init,
        ck: SymmetricKey,
        ctl: mpsc::Receiver<Control>,
        socket: Option<PathBuf>,
        opts: AgentOptions,
    ) -> Self {
        let api = Api::new(link.clone(), &init.session_id);
        let em = Emitter::new(link.clone(), ck.clone(), &init.session_id, init.lease_epoch);
        let adapter: Arc<dyn LlmAdapter> = Arc::from(provider::adapter_for(init.llm.provider));
        Self {
            link,
            api,
            em,
            ck,
            ctl,
            socket,
            adapter,
            opts,
            specs: Vec::new(),
            llm_tools: Vec::new(),
            messages: Vec::new(),
            saved_len: 0,
            rev: 0,
            status: String::new(),
            error: None,
            pending: None,
            awaiting_key: None,
            consumed: Vec::new(),
            seen: HashSet::new(),
            queue: VecDeque::new(),
            events: Vec::new(),
            conv_tokens: 0,
            counters: Counters::default(),
            ticket: None,
            live: None,
            shutdown: None,
            lease_lost: Arc::new(AtomicBool::new(false)),
            last_metrics: Instant::now(),
            init,
        }
    }

    async fn run(&mut self) -> DoneReason {
        let renew = self.spawn_lease_renewal();
        let result = self.main().await;
        renew.abort();
        let reason = match result {
            Ok(r) => r,
            Err(Stop::Pipe) => {
                self.link.with_keys(crate::keys::KeyStore::clear);
                return DoneReason::Shutdown;
            }
            Err(Stop::LeaseLost) => {
                let _ = self.link.send(log("warn", "lease_lost", &[])).await;
                self.finish(DoneReason::Shutdown, false).await;
                return DoneReason::Shutdown;
            }
            Err(Stop::Fatal(code)) => {
                let _ = self.link.send(log("error", "worker_failed", &[("code", json!(code))])).await;
                self.fail_best_effort(code).await;
                DoneReason::Failed
            }
        };
        self.finish(reason, true).await;
        reason
    }

    /// Bail rendu (si encore détenu), clés effacées, `done`.
    async fn finish(&mut self, reason: DoneReason, release: bool) {
        self.send_metrics().await;
        if release && !self.lease_lost.load(Ordering::Relaxed) {
            let body = json!({ "leaseEpoch": self.init.lease_epoch });
            let _ = self.api.conv(HttpMethod::Delete, "/lease", Some(&body)).await;
        }
        self.link.with_keys(crate::keys::KeyStore::clear);
        let _ = self.link.send(WorkerMsg::Done(DoneMsg { reason })).await;
    }

    fn spawn_lease_renewal(&self) -> tokio::task::JoinHandle<()> {
        let api = self.api.clone();
        let epoch = self.init.lease_epoch;
        let every = self.opts.lease_renew;
        let lost = Arc::clone(&self.lease_lost);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                match api.conv(HttpMethod::Post, "/lease", Some(&json!({ "leaseEpoch": epoch }))).await {
                    Ok(r) if r.code() == Some("lease_conflict") => {
                        lost.store(true, Ordering::Relaxed);
                        return;
                    }
                    Err(_) => return,
                    _ => {}
                }
            }
        })
    }

    // ------------------------------------------------------------------
    // Démarrage, reprise
    // ------------------------------------------------------------------

    async fn main(&mut self) -> Result<DoneReason, Stop> {
        let head = self.api.conv(HttpMethod::Get, "", None).await?;
        if !head.ok() {
            return Err(self.classify_write_error(&head));
        }
        self.messages = transcript::decode_messages(
            &self.ck,
            &self.init.session_id,
            head.body.get("messages").unwrap_or(&Value::Null),
        );
        self.saved_len = self.messages.len();
        self.rev = head.body.get("rev").and_then(Value::as_u64).unwrap_or(0);
        let start_status = head.body.get("status").and_then(Value::as_str).unwrap_or("idle").to_owned();
        self.status.clone_from(&start_status);
        self.pending = transcript::decode_pending(
            &self.ck,
            &self.init.session_id,
            head.body.get("pendingToolCall").unwrap_or(&Value::Null),
        );
        self.awaiting_key = head.body.get("awaitingKey").and_then(Value::as_str).map(str::to_owned);
        self.conv_tokens = self
            .messages
            .iter()
            .filter_map(|m| m.usage.as_ref()?.get("totalTokens")?.as_u64())
            .fold(0u64, u64::saturating_add);
        if start_status == "running" {
            // Le worker précédent n'a pas fini proprement (bail expiré) : il ne pouvait pas l'écrire.
            self.events.push(json!({ "type": "lease_lost" }));
        }
        self.load_tools().await?;
        self.fetch_inbox().await?;
        let (rerun, unknown) = self.recover();

        // Un résultat inconnu est donné au modèle, qui décide de la suite (08 §5).
        let mut need_model = unknown > 0;
        let has_work = !self.queue.is_empty() || !rerun.is_empty() || !self.events.is_empty();
        if has_work {
            self.set_running().await?;
        }
        for id in rerun {
            match self.execute_existing(&id).await? {
                Flow::Continue => need_model = true,
                Flow::Awaiting => return Ok(DoneReason::Awaiting),
                other => return Ok(self.flow_reason(other)),
            }
        }
        if !has_work && start_status == "queued" {
            self.persist("idle", None).await?;
        }
        loop {
            let a = self.absorb().await?;
            if a.cancelled {
                self.cancel().await?;
                return Ok(DoneReason::Cancelled);
            }
            if self.shutdown.is_some() {
                return Ok(DoneReason::Shutdown);
            }
            need_model |= a.run_model;
            if need_model {
                need_model = false;
                match self.turn().await? {
                    Flow::Idle | Flow::Continue => continue,
                    other => return Ok(self.flow_reason(other)),
                }
            }
            if self.pending.is_some() {
                // Attente d'une décision : le worker s'arrête (P3), la décision relancera un worker.
                return Ok(DoneReason::Awaiting);
            }
            if !self.wait_for_work().await? {
                return Ok(if self.shutdown.is_some() { DoneReason::Shutdown } else { DoneReason::Idle });
            }
        }
    }

    const fn flow_reason(&self, f: Flow) -> DoneReason {
        match f {
            Flow::Awaiting => DoneReason::Awaiting,
            Flow::Failed => DoneReason::Failed,
            Flow::Cancelled => DoneReason::Cancelled,
            Flow::Shutdown => DoneReason::Shutdown,
            Flow::Idle | Flow::Continue => DoneReason::Idle,
        }
    }

    async fn load_tools(&mut self) -> Result<(), Stop> {
        let r = self.api.conv(HttpMethod::Get, "/tools", None).await?;
        if r.ok() {
            self.specs = tools::parse_manifest(&r.body);
        } else {
            self.link.send(log("warn", "tools_unavailable", &[("status", json!(r.status))])).await?;
        }
        self.llm_tools = tools::llm_tools(&self.specs, &self.init.tool_policy);
        Ok(())
    }

    async fn fetch_inbox(&mut self) -> Result<(), Stop> {
        let mut after: Option<String> = None;
        for _ in 0..50 {
            let suffix = match &after {
                Some(a) => format!("/inbox?after={a}"),
                None => "/inbox".to_owned(),
            };
            let r = self.api.conv(HttpMethod::Get, &suffix, None).await?;
            if !r.ok() {
                return Err(self.classify_write_error(&r));
            }
            let items = r.body.get("items").and_then(Value::as_array).cloned().unwrap_or_default();
            let n = items.len();
            for i in items {
                let (Some(id), Some(kind)) = (i.get("id").and_then(Value::as_str), i.get("kind").cloned()) else {
                    continue;
                };
                if !runtime_protocol::ids::is_identifier(id.split(':').next_back().unwrap_or(id)) {
                    continue;
                }
                after = Some(id.to_owned());
                let mut frame = i.get("payload").cloned().unwrap_or(Value::Null);
                match frame.as_object_mut() {
                    Some(o) => {
                        o.insert("t".into(), kind);
                    }
                    // Élément illisible : consommé sans effet.
                    None => frame = json!({ "t": "unreadable" }),
                }
                self.enqueue(id.to_owned(), frame);
            }
            if n < 100 {
                break;
            }
        }
        Ok(())
    }

    fn enqueue(&mut self, id: String, frame: Value) {
        if self.seen.insert(id.clone()) {
            self.queue.push_back((id, frame));
        }
    }

    fn enqueue_ws(&mut self, items: Vec<Value>) {
        for frame in items {
            if let Some(id) = inbox_id(&frame) {
                self.enqueue(id, frame);
            }
        }
    }

    /// Reprise (08 §5) : outils `executing` mutants jamais relancés ; non mutants et `accepted`
    /// (confirmés, en attente d'une clé) rendus à exécuter.
    fn recover(&mut self) -> (Vec<String>, usize) {
        let answered: HashSet<String> = self.messages.iter().filter_map(|m| m.tool_call_id.clone()).collect();
        let mut rerun = Vec::new();
        let mut unknown = Vec::new();
        for m in &mut self.messages {
            for tc in &mut m.tool_calls {
                if answered.contains(&tc.id) {
                    continue;
                }
                match tc.status {
                    ToolStatus::Executing if tc.mutating => {
                        tc.status = ToolStatus::Error;
                        unknown.push((tc.id.clone(), tc.name.clone()));
                    }
                    ToolStatus::Executing | ToolStatus::Accepted => rerun.push(tc.id.clone()),
                    _ => {}
                }
            }
        }
        let unknown_count = unknown.len();
        for (id, name) in unknown {
            let mut t = Message::new(uuid(), Role::Tool, now());
            t.tool_call_id = Some(id);
            t.tool_result = Some(json!({ "error": "unknown_outcome", "note": UNKNOWN_OUTCOME_NOTE }));
            self.messages.push(t);
            let code: String = name.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(64).collect();
            let code = code.to_ascii_lowercase();
            self.events.push(if code.is_empty() {
                json!({ "type": "tool_unknown_outcome" })
            } else {
                json!({ "type": "tool_unknown_outcome", "code": code })
            });
        }
        if self.pending.as_ref().is_some_and(|p| rerun.contains(&p.id)) {
            self.pending = None;
            self.awaiting_key = None;
        }
        (rerun, unknown_count)
    }

    // ------------------------------------------------------------------
    // Écritures
    // ------------------------------------------------------------------

    fn classify_write_error(&self, r: &ApiResponse) -> Stop {
        match r.code() {
            Some("lease_conflict") => Stop::LeaseLost,
            Some(
                "auth_revoked" | "auth_expired" | "auth_invalid" | "out_of_scope" | "delegation_expired"
                | "delegation_revoked",
            ) => Stop::LeaseLost,
            _ => Stop::Fatal("internal"),
        }
    }

    /// `PUT …/transcript` : historique chiffré, statut, appel en attente, éléments consommés,
    /// évènements de journal. Rejoue une fois sur `rev_conflict` (titre modifié entre-temps).
    async fn persist(&mut self, status: &str, error: Option<&'static str>) -> Result<(), Stop> {
        if self.lease_lost.load(Ordering::Relaxed) {
            return Err(Stop::LeaseLost);
        }
        let sid = self.init.session_id.clone();
        let messages =
            transcript::encode_messages(&self.ck, &sid, &self.messages).map_err(|_| Stop::Fatal("internal"))?;
        let pending = match &self.pending {
            Some(p) => transcript::encode_pending(&self.ck, &sid, p).map_err(|_| Stop::Fatal("internal"))?,
            None => Value::Null,
        };
        let consumed: Vec<String> = self.consumed.iter().take(MAX_CONSUMED_PER_WRITE).cloned().collect();
        let events: Vec<Value> = self.events.iter().take(20).cloned().collect();
        let mut attempt = 0u32;
        loop {
            let mut body = json!({
                "leaseEpoch": self.init.lease_epoch,
                "baseRev": self.rev,
                "messages": messages,
                "status": status,
                "pendingToolCall": pending,
                "consumedInbox": consumed,
            });
            if let Some(e) = error {
                crate::json_set(&mut body, "error", json!(e));
            }
            if status == "awaiting_key"
                && let Some(k) = &self.awaiting_key
            {
                crate::json_set(&mut body, "awaitingKey", json!(k));
            }
            if !events.is_empty() {
                crate::json_set(&mut body, "events", Value::Array(events.clone()));
            }
            let r = self.api.conv(HttpMethod::Put, "/transcript", Some(&body)).await?;
            if r.ok() {
                self.rev = r.body.get("rev").and_then(Value::as_u64).unwrap_or(self.rev.saturating_add(1));
                break;
            }
            attempt = attempt.saturating_add(1);
            match r.code() {
                Some("rev_conflict") if attempt <= 2 => {
                    let head = self.api.conv(HttpMethod::Get, "", None).await?;
                    if let Some(rev) = head.body.get("rev").and_then(Value::as_u64) {
                        self.rev = rev;
                    }
                }
                Some(c) if c.starts_with("relay_") && attempt <= 3 => {
                    tokio::time::sleep(Duration::from_millis(200u64.saturating_mul(u64::from(attempt)))).await;
                }
                _ => return Err(self.classify_write_error(&r)),
            }
        }
        self.saved_len = self.messages.len();
        self.events.drain(..events.len());
        let acked: Vec<String> = self.consumed.drain(..consumed.len()).collect();
        if !acked.is_empty() {
            self.link.send(WorkerMsg::InboxAck(InboxAckMsg { ids: acked })).await?;
        }
        self.error = error;
        self.set_local_status(status, error).await
    }

    /// `POST …/status` (changement d'état sans réécrire l'historique).
    async fn post_status(&mut self, status: &str, error: Option<&'static str>) -> Result<(), Stop> {
        let mut body = json!({ "leaseEpoch": self.init.lease_epoch, "status": status });
        if let Some(e) = error {
            crate::json_set(&mut body, "error", json!(e));
        }
        let events: Vec<Value> = self.events.iter().take(20).cloned().collect();
        if !events.is_empty() {
            crate::json_set(&mut body, "events", Value::Array(events.clone()));
        }
        let r = self.api.conv(HttpMethod::Post, "/status", Some(&body)).await?;
        if !r.ok() {
            return Err(self.classify_write_error(&r));
        }
        self.events.drain(..events.len());
        self.error = error;
        self.set_local_status(status, error).await
    }

    async fn set_local_status(&mut self, status: &str, reason: Option<&str>) -> Result<(), Stop> {
        if self.status != status {
            self.status = status.to_owned();
            self.em.status(status, reason).await?;
            self.link
                .send(WorkerMsg::Status(StatusMsg { status: status.into(), reason: reason.map(str::to_owned) }))
                .await?;
        }
        Ok(())
    }

    async fn set_running(&mut self) -> Result<(), Stop> {
        let dirty = self.messages.len() != self.saved_len || !self.events.is_empty() || !self.consumed.is_empty();
        if dirty {
            return self.persist("running", None).await;
        }
        if self.status == "running" {
            return Ok(());
        }
        self.post_status("running", None).await
    }

    async fn push(&self, kind: &str) {
        let _ = self.api.conv(HttpMethod::Post, "/push", Some(&json!({ "type": kind }))).await;
    }

    async fn send_metrics(&mut self) {
        self.last_metrics = Instant::now();
        let _ = self.link.send(WorkerMsg::Metrics(Box::new(self.counters.m))).await;
    }

    /// Dernier recours après une erreur fatale : statut `failed` (si le bail est encore à nous).
    async fn fail_best_effort(&mut self, code: &'static str) {
        if self.lease_lost.load(Ordering::Relaxed) {
            return;
        }
        let _ = self.em.error(code, None).await;
        let body = json!({ "leaseEpoch": self.init.lease_epoch, "status": "failed", "error": code });
        if let Ok(r) = self.api.conv(HttpMethod::Post, "/status", Some(&body)).await
            && r.ok()
        {
            let _ = self.set_local_status("failed", Some(code)).await;
            self.push("AI_FAILED").await;
        }
    }

    // ------------------------------------------------------------------
    // Boîte de réception
    // ------------------------------------------------------------------

    /// Traite un message de contrôle hors flux.
    async fn on_control(&mut self, c: Control) -> Result<(), Stop> {
        match c {
            Control::Inbox(items) => self.enqueue_ws(items),
            Control::Shutdown(s) => self.shutdown = Some(s),
            Control::Snapshot(id) => self.snapshot(&id).await?,
        }
        Ok(())
    }

    async fn snapshot(&mut self, request_id: &str) -> Result<(), Stop> {
        let mut msgs: Vec<Value> =
            self.messages.get(self.saved_len..).unwrap_or_default().iter().map(clear_message).collect();
        if let Some(l) = &self.live {
            let mut m = json!({ "id": l.id, "role": "assistant", "content": l.text, "createdAt": now() });
            if !l.thinking.is_empty() {
                crate::json_set(&mut m, "thinking", json!(l.thinking));
            }
            msgs.push(m);
        }
        let pending = self.pending.as_ref().map(clear_pending).unwrap_or(Value::Null);
        let state = json!({ "messages": msgs, "status": self.status, "pendingToolCall": pending });
        self.em.snapshot(request_id, self.rev, &state).await?;
        Ok(())
    }

    /// Lit sans attendre ce que le superviseur a envoyé, puis traite la file dans l'ordre de dépôt.
    async fn absorb(&mut self) -> Result<Absorbed, Stop> {
        while let Ok(c) = self.ctl.try_recv() {
            self.on_control(c).await?;
        }
        let mut out = Absorbed::default();
        while let Some((id, frame)) = self.queue.pop_front() {
            let t = frame.get("t").and_then(Value::as_str).unwrap_or_default().to_owned();
            if t == "cancel" {
                self.consumed.push(id);
                out.cancelled = true;
                return Ok(out);
            }
            self.consumed.push(id);
            match t.as_str() {
                "message" => {
                    if self.accept_user_message(&frame).await? {
                        out.run_model = true;
                    }
                }
                "confirm" | "answer" | "upload" => match self.decision(&t, &frame).await? {
                    Some(Flow::Continue) => out.run_model = true,
                    Some(Flow::Awaiting) => {}
                    Some(_) => {}
                    None => self.em.error("stale_decision", None).await?,
                },
                _ => {}
            }
        }
        Ok(out)
    }

    /// Message utilisateur : devient tel quel un `StoredMessage` `user` (05 §6.2). Un appel en
    /// attente est clos (`superseded_by_user_message` ou `key_unavailable`, 08 §2).
    async fn accept_user_message(&mut self, frame: &Value) -> Result<bool, Stop> {
        let (Some(id), Some(content)) =
            (frame.get("id").and_then(Value::as_str), frame.get("content").and_then(Value::as_str))
        else {
            return Ok(false);
        };
        if self.messages.iter().any(|m| m.id == id) {
            // Déjà dans l'historique (reprise) : simplement consommé.
            return Ok(true);
        }
        let Ok(text) = session::decrypt_field(&self.ck, &self.init.session_id, id, "content", content) else {
            self.link.send(log("warn", "inbox_unreadable", &[])).await?;
            return Ok(false);
        };
        if let Some(p) = self.pending.take() {
            let code =
                if self.awaiting_key.take().is_some() { "key_unavailable" } else { "superseded_by_user_message" };
            let status = if code == "key_unavailable" { ToolStatus::Error } else { ToolStatus::Rejected };
            self.close_call(&p.id, &p.name, status, json!({ "error": code })).await?;
        }
        let mut m = Message::new(
            id.to_owned(),
            Role::User,
            frame.get("createdAt").and_then(Value::as_str).unwrap_or_default().to_owned(),
        );
        if m.created_at.is_empty() {
            m.created_at = now();
        }
        m.content = Some(text);
        self.messages.push(m);
        Ok(true)
    }

    /// Décision sur l'appel en attente. `None` : ne correspond à rien (`stale_decision`).
    async fn decision(&mut self, t: &str, frame: &Value) -> Result<Option<Flow>, Stop> {
        let Some(tcid) = frame.get("toolCallId").and_then(Value::as_str) else { return Ok(None) };
        let Some(p) = self.pending.clone().filter(|p| p.id == tcid) else { return Ok(None) };
        match t {
            "confirm" if self.status == "awaiting_confirmation" || (!p.interactive && self.awaiting_key.is_none()) => {
                self.pending = None;
                if frame.get("decision").and_then(Value::as_str) == Some("accept") {
                    if let Some(tc) = self.find_call_mut(&p.id) {
                        tc.status = ToolStatus::Accepted;
                    }
                    self.execute_existing(&p.id).await.map(Some)
                } else {
                    self.close_call(&p.id, &p.name, ToolStatus::Rejected, json!({ "error": REJECTED_BY_USER })).await?;
                    Ok(Some(Flow::Continue))
                }
            }
            "answer" if p.interactive && p.name == "ask_question" => {
                let value = frame.get("value").and_then(Value::as_str).unwrap_or_default();
                let field = format!("answer:{tcid}");
                let Ok(answer) =
                    session::decrypt_field(&self.ck, &self.init.session_id, ANSWER_MESSAGE_ID, &field, value)
                else {
                    return Ok(None);
                };
                self.pending = None;
                self.close_call(&p.id, &p.name, ToolStatus::Done, json!({ "answer": answer })).await?;
                Ok(Some(Flow::Continue))
            }
            "upload" if p.interactive && p.name == "request_image_upload" => {
                let r = frame.get("ref").and_then(Value::as_str).unwrap_or_default();
                self.pending = None;
                let result = json!({ "id": r, "note": format!("Utilise EXACTEMENT '{r}' pour le paramètre 'logo' de create_space.") });
                self.close_call(&p.id, &p.name, ToolStatus::Done, result).await?;
                Ok(Some(Flow::Continue))
            }
            _ => Ok(None),
        }
    }

    fn find_call_mut(&mut self, id: &str) -> Option<&mut ToolCall> {
        self.messages.iter_mut().rev().flat_map(|m| m.tool_calls.iter_mut()).find(|tc| tc.id == id)
    }

    fn assistant_of(&self, call: &str) -> Option<String> {
        self.messages.iter().rev().find(|m| m.tool_calls.iter().any(|tc| tc.id == call)).map(|m| m.id.clone())
    }

    /// Clôt un appel : statut, message `tool`, évènements (l'écriture suit à l'étape suivante).
    async fn close_call(&mut self, id: &str, name: &str, status: ToolStatus, result: Value) -> Result<(), Stop> {
        let Some(tc) = self.find_call_mut(id) else { return Ok(()) };
        tc.status = status;
        let snapshot = tc.clone();
        let result = self.truncate(result);
        let mut t = Message::new(uuid(), Role::Tool, now());
        t.tool_call_id = Some(id.to_owned());
        t.tool_result = Some(result.clone());
        let tool_msg_id = t.id.clone();
        self.messages.push(t);
        if let Some(mid) = self.assistant_of(id) {
            let interactive = self.spec(name).is_some_and(|s| s.interactive);
            self.em.tool_call(&mid, &snapshot, interactive).await?;
        }
        self.em.tool_result(&tool_msg_id, id, name, &result).await?;
        self.counters.tool(matches!(status, ToolStatus::Error | ToolStatus::Rejected));
        Ok(())
    }

    fn spec(&self, name: &str) -> Option<&ToolSpec> {
        self.specs.iter().find(|s| s.name == name)
    }

    /// Résultat tronqué à `maxToolResultBytes` (avec mention, 09 §2).
    fn truncate(&self, result: Value) -> Value {
        let max = usize::try_from(self.init.limits.max_tool_result_bytes).unwrap_or(usize::MAX);
        let text = result.to_string();
        if text.len() <= max {
            return result;
        }
        let mut cut = max.saturating_sub(256).min(text.len());
        while cut > 0 && !text.is_char_boundary(cut) {
            cut = cut.saturating_sub(1);
        }
        json!({
            "truncated": true,
            "partial": text.get(..cut).unwrap_or_default(),
            "note": "Résultat tronqué : il dépassait la taille maximale d'un résultat d'outil.",
        })
    }

    async fn cancel(&mut self) -> Result<(), Stop> {
        if let Some(p) = self.pending.take() {
            self.awaiting_key = None;
            self.close_call(
                &p.id,
                &p.name,
                ToolStatus::Rejected,
                json!({ "error": "Action annulée par l'utilisateur." }),
            )
            .await?;
        }
        self.persist("cancelled", None).await
    }

    /// Attend du travail jusqu'à `idleShutdownSecs` (P3). `false` : inactivité ou arrêt.
    async fn wait_for_work(&mut self) -> Result<bool, Stop> {
        if self.status != "idle" && !matches!(self.status.as_str(), "failed" | "cancelled") {
            if self.messages.len() != self.saved_len || !self.consumed.is_empty() {
                self.persist("idle", self.error).await?;
            } else {
                self.post_status("idle", self.error).await?;
            }
        } else if !self.consumed.is_empty() {
            let status = self.status.clone();
            self.persist(&status, self.error).await?;
        }
        let idle = tokio::time::sleep(Duration::from_secs(self.init.limits.idle_shutdown_secs));
        tokio::pin!(idle);
        loop {
            tokio::select! {
                c = self.ctl.recv() => match c {
                    None => return Err(Stop::Pipe),
                    Some(Control::Shutdown(s)) => {
                        self.shutdown = Some(s);
                        return Ok(false);
                    }
                    Some(c) => {
                        self.on_control(c).await?;
                        if !self.queue.is_empty() {
                            return Ok(true);
                        }
                    }
                },
                () = &mut idle => return Ok(false),
            }
        }
    }

    // ------------------------------------------------------------------
    // Tour
    // ------------------------------------------------------------------

    async fn turn(&mut self) -> Result<Flow, Stop> {
        self.counters.start_turn();
        let started = Instant::now();
        let mut steps = 0u64;
        let mut turn_tokens = 0u64;
        let l = self.init.limits;
        self.set_running().await?;
        let flow = loop {
            if self.conv_tokens >= l.max_tokens_per_conversation {
                break self.fail("budget_exceeded").await?;
            }
            if started.elapsed() >= Duration::from_secs(l.max_turn_duration_secs) {
                break self.fail("turn_timeout").await?;
            }
            if steps >= l.max_steps_per_turn || turn_tokens >= l.max_tokens_per_turn {
                break self.end_turn(Some("step_limit")).await?;
            }
            let a = self.absorb().await?;
            if a.cancelled {
                self.cancel().await?;
                break Flow::Cancelled;
            }
            if self.shutdown.is_some() {
                self.persist("running", None).await?;
                break Flow::Shutdown;
            }
            if self.pending.is_some() {
                // Un appel attend (une décision vient de remettre une attente) : fin du tour.
                break Flow::Awaiting;
            }
            let deadline = after(started, Duration::from_secs(l.max_turn_duration_secs));
            steps = steps.saturating_add(1);
            let step = self.model_step(deadline).await?;
            turn_tokens = turn_tokens.saturating_add(step.tokens);
            self.conv_tokens = self.conv_tokens.saturating_add(step.tokens);
            match step.end {
                StepEnd::Error(e) => {
                    let _ = self.link.send(log("warn", "llm_error", &[("code", json!(e.code()))])).await;
                    break match e {
                        LlmError::CallBudget => self.end_turn(Some("step_limit")).await?,
                        LlmError::TokenBudget => self.fail("budget_exceeded").await?,
                        LlmError::Auth => self.fail("provider_auth").await?,
                        _ => self.fail("provider_error").await?,
                    };
                }
                StepEnd::Cancelled => {
                    // Consomme la file jusqu'à l'annulation comprise (les messages d'avant restent
                    // dans l'historique) ; ce qui suit l'annulation relancera un tour.
                    let _ = self.absorb().await?;
                    self.cancel().await?;
                    break Flow::Cancelled;
                }
                StepEnd::Shutdown => {
                    self.persist("running", None).await?;
                    break Flow::Shutdown;
                }
                StepEnd::Timeout => break self.fail("turn_timeout").await?,
                StepEnd::Answer => {
                    // Messages arrivés pendant l'appel : pris en compte à l'étape suivante.
                    while let Ok(c) = self.ctl.try_recv() {
                        self.on_control(c).await?;
                    }
                    if self
                        .queue
                        .iter()
                        .any(|(_, f)| matches!(f.get("t").and_then(Value::as_str), Some("message" | "cancel")))
                    {
                        self.persist("running", None).await?;
                        continue;
                    }
                    break self.end_turn(None).await?;
                }
                StepEnd::ToolCall(idx) => match self.new_tool_call(idx).await? {
                    Flow::Continue => {}
                    other => break other,
                },
            }
        };
        self.counters.end_turn();
        self.send_metrics().await;
        Ok(flow)
    }

    async fn end_turn(&mut self, code: Option<&'static str>) -> Result<Flow, Stop> {
        if let Some(c) = code {
            self.em.error(c, None).await?;
        }
        self.persist("idle", code).await?;
        self.push("AI_TURN_DONE").await;
        Ok(Flow::Idle)
    }

    async fn fail(&mut self, code: &'static str) -> Result<Flow, Stop> {
        self.em.error(code, None).await?;
        self.persist("failed", Some(code)).await?;
        self.push("AI_FAILED").await;
        Ok(Flow::Failed)
    }

    /// Historique au format du fournisseur.
    fn chat_messages(&self) -> Vec<ChatMessage> {
        let mut out = Vec::new();
        for m in &self.messages {
            match m.role {
                Role::User => out.push(ChatMessage::User { content: m.content.clone().unwrap_or_default() }),
                Role::Assistant => out.push(ChatMessage::Assistant {
                    content: m.content.clone().filter(|c| !c.is_empty() || m.tool_calls.is_empty()),
                    tool_calls: m
                        .tool_calls
                        .iter()
                        .map(|tc| ChatToolCall {
                            id: tc.id.clone(),
                            name: tc.name.clone(),
                            arguments: tc.arguments.to_string(),
                        })
                        .collect(),
                }),
                Role::Tool => out.push(ChatMessage::Tool {
                    tool_call_id: m.tool_call_id.clone().unwrap_or_default(),
                    content: match &m.tool_result {
                        Some(Value::String(s)) => s.clone(),
                        Some(v) => v.to_string(),
                        None => "null".to_owned(),
                    },
                }),
            }
        }
        out
    }

    async fn gateway_ticket(&mut self, force: bool) -> Result<Option<String>, Stop> {
        if self.init.llm.provider != LlmProvider::Gateway {
            return Ok(None);
        }
        if !force
            && let Some((t, at)) = &self.ticket
            && at.elapsed() < Duration::from_secs(240)
        {
            return Ok(Some(t.clone()));
        }
        let r = self.api.call(HttpMethod::Post, &format!("{PREFIX}/tickets/llm"), Some(&json!({}))).await?;
        let t = r.body.get("ticket").and_then(Value::as_str).filter(|_| r.ok()).map(str::to_owned);
        self.ticket = t.clone().map(|t| (t, Instant::now()));
        Ok(t)
    }

    /// Un appel au fournisseur (avec nouveaux essais), deltas diffusés au fil de l'eau.
    async fn model_step(&mut self, deadline: Instant) -> Result<Step, Stop> {
        let Some(socket) = self.socket.clone() else {
            return Ok(Step { tokens: 0, end: StepEnd::Error(LlmError::Transport) });
        };
        let mut attempt = 0usize;
        let mut auth_retry = false;
        loop {
            let bearer = self.gateway_ticket(auth_retry).await?;
            let req = ChatRequest {
                model: self.init.llm.model.clone(),
                system: crate::prompt::system_prompt(self.init.llm.reasoning_effort),
                messages: self.chat_messages(),
                tools: self.llm_tools.clone(),
                reasoning_effort: self.init.llm.reasoning_effort,
                max_output_tokens: self.init.limits.max_output_tokens_per_call,
                bearer,
            };
            let t0 = Instant::now();
            let attempt_result = self.stream_once(&socket, req, deadline).await?;
            let latency = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
            match attempt_result {
                Attempt::Finished(step) => {
                    let usage = step.usage;
                    self.counters.llm_call(latency, usage.as_ref(), self.init.llm.pricing.as_ref());
                    return Ok(step.into_step());
                }
                Attempt::Interrupted(end) => return Ok(Step { tokens: 0, end }),
                Attempt::Failed { error, emitted } => {
                    self.counters.llm_call(latency, None, None);
                    if error == LlmError::Auth
                        && self.init.llm.provider == LlmProvider::Gateway
                        && !auth_retry
                        && !emitted
                    {
                        auth_retry = true;
                        continue;
                    }
                    let delay = self.opts.retry_delays.get(attempt).copied();
                    match (error.retryable() && !emitted, delay) {
                        (true, Some(d)) => {
                            attempt = attempt.saturating_add(1);
                            let d = match &error {
                                LlmError::RateLimited { retry_after_secs: Some(s) } => {
                                    Duration::from_secs((*s).min(60)).max(d)
                                }
                                _ => d,
                            };
                            let _ = self.link.send(log("info", "llm_retry", &[("code", json!(error.code()))])).await;
                            if after(Instant::now(), d) >= deadline {
                                return Ok(Step { tokens: 0, end: StepEnd::Timeout });
                            }
                            tokio::time::sleep(d).await;
                        }
                        _ => return Ok(Step { tokens: 0, end: StepEnd::Error(error) }),
                    }
                }
            }
        }
    }

    async fn stream_once(
        &mut self,
        socket: &std::path::Path,
        req: ChatRequest,
        deadline: Instant,
    ) -> Result<Attempt, Stop> {
        let (tx, mut rx) = mpsc::unbounded_channel::<LlmEvent>();
        let adapter = Arc::clone(&self.adapter);
        let socket = socket.to_path_buf();
        let task = tokio::spawn(async move {
            provider::stream_completion(&socket, adapter.as_ref(), &req, |ev| tx.send(ev).is_ok()).await
        });
        let abort = task.abort_handle();
        let message_id = uuid();
        self.live = Some(Live { id: message_id.clone(), ..Live::default() });
        let mut text = String::new();
        let mut thinking = String::new();
        let mut calls: Vec<ChatToolCall> = Vec::new();
        let mut usage: Option<Usage> = None;
        let mut finish = FinishReason::Stop;
        let mut emitted = false;
        let mut out_bytes = 0u64;
        let mut interrupted: Option<StepEnd> = None;
        let mut grace: Option<Instant> = None;
        let mut metrics = tokio::time::interval(self.opts.metrics_every);
        metrics.tick().await;
        loop {
            let limit = grace.map_or(deadline, |g| g.min(deadline));
            tokio::select! {
                ev = rx.recv() => match ev {
                    None => break,
                    Some(LlmEvent::Text(t)) => {
                        emitted = true;
                        out_bytes = out_bytes.saturating_add(u64::try_from(t.len()).unwrap_or(0));
                        self.em.text(&message_id, &t).await?;
                        text.push_str(&t);
                        if let Some(l) = &mut self.live { l.text.push_str(&t); }
                    }
                    Some(LlmEvent::Thinking(t)) => {
                        emitted = true;
                        out_bytes = out_bytes.saturating_add(u64::try_from(t.len()).unwrap_or(0));
                        self.em.thinking(&message_id, &t).await?;
                        thinking.push_str(&t);
                        if let Some(l) = &mut self.live { l.thinking.push_str(&t); }
                    }
                    Some(LlmEvent::ToolCall(c)) => calls.push(c),
                    Some(LlmEvent::Usage(u)) => {
                        self.em.usage(&message_id, &u).await?;
                        usage = Some(u);
                    }
                    Some(LlmEvent::Done(r)) => finish = r,
                },
                c = self.ctl.recv() => match c {
                    None => {
                        abort.abort();
                        return Err(Stop::Pipe);
                    }
                    Some(Control::Inbox(items)) => {
                        self.enqueue_ws(items);
                        if self.queue.iter().any(|(_, f)| f.get("t").and_then(Value::as_str) == Some("cancel")) {
                            abort.abort();
                            interrupted = Some(StepEnd::Cancelled);
                            break;
                        }
                    }
                    Some(Control::Shutdown(s)) => {
                        self.shutdown = Some(s);
                        if s.grace_ms == 0 {
                            abort.abort();
                            interrupted = Some(StepEnd::Shutdown);
                            break;
                        }
                        grace = Some(after(Instant::now(), Duration::from_millis(s.grace_ms)));
                    }
                    Some(Control::Snapshot(id)) => self.snapshot(&id).await?,
                },
                _ = metrics.tick() => {
                    let _ = self.link.send(WorkerMsg::Metrics(Box::new(self.counters.m))).await;
                }
                () = tokio::time::sleep_until(limit.into()) => {
                    abort.abort();
                    interrupted = Some(if grace.is_some() { StepEnd::Shutdown } else { StepEnd::Timeout });
                    break;
                }
            }
        }
        self.live = None;
        if let Some(end) = interrupted {
            if end == StepEnd::Cancelled && (!text.is_empty() || !thinking.is_empty()) {
                // Texte déjà vu par l'utilisateur : gardé.
                let mut m = Message::new(message_id, Role::Assistant, now());
                m.content = Some(text);
                m.thinking = (!thinking.is_empty()).then_some(thinking);
                self.messages.push(m);
            }
            return Ok(Attempt::Interrupted(end));
        }
        let result = match task.await {
            Ok(r) => r,
            Err(_) => Err(LlmError::Transport),
        };
        if let Err(error) = result {
            return Ok(Attempt::Failed { error, emitted });
        }
        let tokens =
            usage.map_or_else(|| out_bytes.saturating_add(estimate_request(&self.messages)) / 4, |u| u.total());
        let mut m = Message::new(message_id, Role::Assistant, now());
        m.thinking = (!thinking.is_empty()).then_some(thinking);
        m.usage = usage.map(usage_json);
        let call = calls.into_iter().next().filter(|_| finish == FinishReason::ToolCalls);
        let has_call = call.is_some();
        m.content = if has_call && text.is_empty() { None } else { Some(text) };
        if let Some(c) = call {
            let id = if runtime_protocol::ids::is_identifier(&c.id) { c.id } else { call_id() };
            let arguments =
                serde_json::from_str::<Value>(&c.arguments).ok().filter(Value::is_object).unwrap_or_else(|| json!({}));
            let spec = self.spec(&c.name).cloned();
            m.tool_calls.push(ToolCall {
                id,
                name: c.name,
                arguments,
                category: spec.as_ref().map_or_else(|| "server".to_owned(), |s| s.category.clone()),
                mutating: spec.as_ref().is_none_or(|s| s.mutating),
                status: ToolStatus::Pending,
            });
        }
        self.messages.push(m);
        let idx = self.messages.len().saturating_sub(1);
        Ok(Attempt::Finished(Finished { usage, tokens, tool_call: has_call.then_some(idx) }))
    }

    // ------------------------------------------------------------------
    // Outils
    // ------------------------------------------------------------------

    /// Appel d'outil tout juste produit par le modèle (dans `messages[idx]`).
    async fn new_tool_call(&mut self, idx: usize) -> Result<Flow, Stop> {
        let Some(tc) = self.messages.get(idx).and_then(|m| m.tool_calls.first()).cloned() else {
            return Ok(Flow::Continue);
        };
        let spec = self.spec(&tc.name).cloned();
        match tools::decide(spec.as_ref(), &self.init.tool_policy) {
            Decision::Unknown => {
                self.close_call(
                    &tc.id,
                    &tc.name,
                    ToolStatus::Error,
                    json!({ "error": format!("Outil inconnu: {}", tc.name) }),
                )
                .await?;
                self.persist("running", None).await?;
                Ok(Flow::Continue)
            }
            Decision::Deny => {
                self.close_call(&tc.id, &tc.name, ToolStatus::Rejected, json!({ "error": "tool_denied_by_policy" }))
                    .await?;
                self.persist("running", None).await?;
                Ok(Flow::Continue)
            }
            Decision::AwaitUser | Decision::AskConfirmation => {
                let Some(spec) = spec else { return Ok(Flow::Continue) };
                let (status, push) = if spec.interactive {
                    ("awaiting_user", "AI_AWAITING_USER")
                } else {
                    ("awaiting_confirmation", "AI_AWAITING_CONFIRMATION")
                };
                self.pending = Some(PendingToolCall {
                    id: tc.id.clone(),
                    name: tc.name.clone(),
                    args: tc.arguments.clone(),
                    category: spec.category.clone(),
                    mutating: spec.mutating,
                    interactive: spec.interactive,
                });
                let mid = self.messages.get(idx).map(|m| m.id.clone()).unwrap_or_default();
                self.em.tool_call(&mid, &tc, spec.interactive).await?;
                self.persist(status, None).await?;
                self.push(push).await;
                Ok(Flow::Awaiting)
            }
            Decision::Auto => self.execute_existing(&tc.id).await,
        }
    }

    /// Exécute un appel déjà présent dans l'historique (accepté, automatique, ou repris).
    async fn execute_existing(&mut self, id: &str) -> Result<Flow, Stop> {
        let Some(tc) = self.find_call_mut(id).map(|t| t.clone()) else { return Ok(Flow::Continue) };
        let Some(spec) = self.spec(&tc.name).cloned() else {
            self.close_call(
                &tc.id,
                &tc.name,
                ToolStatus::Error,
                json!({ "error": format!("Outil inconnu: {}", tc.name) }),
            )
            .await?;
            self.persist("running", None).await?;
            return Ok(Flow::Continue);
        };
        if self.init.tool_policy.get(&tc.name) == Some(&pipe::ToolPolicy::Deny) {
            self.close_call(&tc.id, &tc.name, ToolStatus::Rejected, json!({ "error": "tool_denied_by_policy" }))
                .await?;
            self.persist("running", None).await?;
            return Ok(Flow::Continue);
        }
        let mid = self.assistant_of(&tc.id).unwrap_or_default();
        if let Some(t) = self.find_call_mut(&tc.id) {
            t.status = ToolStatus::Executing;
        }
        let executing = ToolCall { status: ToolStatus::Executing, ..tc.clone() };
        if spec.mutating {
            // Écriture anticipée (08 §5) : l'outil ne s'exécute qu'une fois l'écriture confirmée.
            self.persist("running", None).await?;
        }
        self.em.tool_call(&mid, &executing, spec.interactive).await?;
        let mut outcome = self.run_tool(&spec, &tc.arguments).await;
        if let Outcome::NeedKey { kind, reference } = &outcome {
            self.link
                .send(WorkerMsg::NeedKey(NeedKeyMsg { kind: (*kind).to_owned(), reference: reference.clone() }))
                .await?;
            if self.wait_key(kind, reference).await {
                outcome = self.run_tool(&spec, &tc.arguments).await;
            }
        }
        match outcome {
            Outcome::LeaseLost => Err(Stop::LeaseLost),
            Outcome::NeedKey { kind, reference } => {
                // Clé indispensable à une ressource désignée explicitement (03 §11) : `awaiting_key`,
                // reprise automatique quand la synchro P11 l'apporte (l'appel reste `accepted`).
                if let Some(t) = self.find_call_mut(&tc.id) {
                    t.status = ToolStatus::Accepted;
                }
                self.pending = Some(PendingToolCall {
                    id: tc.id.clone(),
                    name: tc.name.clone(),
                    args: tc.arguments.clone(),
                    category: spec.category.clone(),
                    mutating: spec.mutating,
                    interactive: spec.interactive,
                });
                self.awaiting_key = Some(format!("{kind}:{reference}"));
                let accepted = ToolCall { status: ToolStatus::Accepted, ..tc };
                self.em.tool_call(&mid, &accepted, spec.interactive).await?;
                self.em.error("key_unavailable", None).await?;
                self.persist("awaiting_key", None).await?;
                self.push("AI_AWAITING_KEY").await;
                Ok(Flow::Awaiting)
            }
            Outcome::Done(v) => {
                self.close_call(&tc.id, &tc.name, ToolStatus::Done, v).await?;
                self.persist("running", None).await?;
                Ok(Flow::Continue)
            }
            Outcome::Failed(v) => {
                self.close_call(&tc.id, &tc.name, ToolStatus::Error, v).await?;
                self.persist("running", None).await?;
                Ok(Flow::Continue)
            }
        }
    }

    async fn run_tool(&self, spec: &ToolSpec, args: &Value) -> Outcome {
        let ctx = ToolCtx { api: &self.api, lease_epoch: self.init.lease_epoch, user_id: &self.init.user_id };
        tools::execute(&ctx, spec, args).await
    }

    async fn wait_key(&self, kind: &str, reference: &str) -> bool {
        let deadline = after(Instant::now(), self.opts.need_key_wait);
        loop {
            let present = self.link.with_keys(|k| match kind {
                "space" => k.space(reference).is_some(),
                _ => k.thread(reference).is_some(),
            });
            if present {
                return true;
            }
            if Instant::now() >= deadline || self.link.is_closed() {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

/// Fin d'une étape (appel au modèle).
#[derive(Debug, Clone, PartialEq, Eq)]
enum StepEnd {
    /// Réponse sans outil.
    Answer,
    /// Appel d'outil dans `messages[idx]`.
    ToolCall(usize),
    /// Échec du fournisseur.
    Error(LlmError),
    /// Annulation reçue pendant l'appel.
    Cancelled,
    /// Arrêt demandé pendant l'appel.
    Shutdown,
    /// Durée du tour dépassée pendant l'appel.
    Timeout,
}

struct Step {
    tokens: u64,
    end: StepEnd,
}

struct Finished {
    usage: Option<Usage>,
    tokens: u64,
    tool_call: Option<usize>,
}

impl Finished {
    fn into_step(self) -> Step {
        Step { tokens: self.tokens, end: self.tool_call.map_or(StepEnd::Answer, StepEnd::ToolCall) }
    }
}

enum Attempt {
    Finished(Finished),
    Interrupted(StepEnd),
    Failed { error: LlmError, emitted: bool },
}

fn estimate_request(messages: &[Message]) -> u64 {
    messages
        .iter()
        .map(|m| {
            let calls: usize = m.tool_calls.iter().map(|t| t.arguments.to_string().len()).sum();
            m.content
                .as_ref()
                .map_or(0, String::len)
                .saturating_add(m.tool_result.as_ref().map_or(0, |r| r.to_string().len()))
                .saturating_add(calls)
        })
        .fold(0u64, |acc, n| acc.saturating_add(u64::try_from(n).unwrap_or(0)))
}

/// `t + d`, borné (un délai démesuré revient à « jamais »).
fn after(t: Instant, d: Duration) -> Instant {
    t.checked_add(d).or_else(|| t.checked_add(Duration::from_secs(86_400 * 365))).unwrap_or(t)
}

fn usage_json(u: Usage) -> Value {
    let mut v = json!({});
    for (k, x) in [
        ("promptTokens", u.prompt_tokens),
        ("completionTokens", u.completion_tokens),
        ("totalTokens", u.total_tokens),
        ("reasoningTokens", u.reasoning_tokens),
    ] {
        if let Some(x) = x {
            crate::json_set(&mut v, k, json!(x));
        }
    }
    if v.get("totalTokens").is_none() {
        crate::json_set(&mut v, "totalTokens", json!(u.total()));
    }
    v
}

/// Identifiant d'un élément de boîte arrivé par WebSocket (05 §6.2).
fn inbox_id(frame: &Value) -> Option<String> {
    let t = frame.get("t")?.as_str()?;
    let id = match t {
        "message" => frame.get("id")?.as_str()?.to_owned(),
        "cancel" => format!("cancel:{}", frame.get("id")?.as_str()?),
        "confirm" | "answer" | "upload" => format!("{t}:{}", frame.get("toolCallId")?.as_str()?),
        _ => return None,
    };
    Some(id)
}

/// Message en clair pour `snapshot` (protégé par le chiffrement de `state`, 05 §5.2).
fn clear_message(m: &Message) -> Value {
    let mut v = json!({ "id": m.id, "role": m.role.as_str(), "content": m.content, "createdAt": m.created_at });
    if let Some(t) = &m.thinking {
        crate::json_set(&mut v, "thinking", json!(t));
    }
    if !m.tool_calls.is_empty() {
        crate::json_set(&mut v, "toolCalls", Value::Array(
            m.tool_calls
                .iter()
                .map(|tc| json!({ "id": tc.id, "name": tc.name, "arguments": tc.arguments, "category": tc.category, "mutating": tc.mutating, "status": tc.status.as_str() }))
                .collect(),
        ));
    }
    if let Some(id) = &m.tool_call_id {
        crate::json_set(&mut v, "toolCallId", json!(id));
    }
    if let Some(r) = &m.tool_result {
        crate::json_set(&mut v, "toolResult", r.clone());
    }
    if let Some(u) = &m.usage {
        crate::json_set(&mut v, "usage", u.clone());
    }
    v
}

fn clear_pending(p: &PendingToolCall) -> Value {
    json!({ "id": p.id, "name": p.name, "args": p.args, "category": p.category, "mutating": p.mutating, "interactive": p.interactive })
}

/// Pour les tests : identifiants des éléments de boîte.
#[doc(hidden)]
#[must_use]
pub fn inbox_item_id(frame: &Value) -> Option<String> {
    inbox_id(frame)
}
