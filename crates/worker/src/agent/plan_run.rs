//! Plans d'action dans la boucle d'agent (lot L08d, docs/plan/12 §3, §7.3, §8.3, §8.6, §8.7, §9) :
//!
//! - `propose_actions` : construction, validation et chiffrement sous `CK`, écriture par
//!   `POST …/plans` (transcript et ligne du plan dans la même requête), puis arrêt du worker ;
//! - reprise à chaque `plan_decision` / `plan_result:<k>` : l'état du plan se relit **toujours** dans
//!   `PlanView` (le worker ne garde rien qui ne se retrouve pas après une reprise) ;
//! - phase d'agent : actions d'agent prêtes en parallèle (concurrence bornée, `429` réessayé trois
//!   fois en divisant la concurrence), `refs` résolues depuis des sorties authentifiées, puis
//!   `plan_agent_result:<k>` (`POST …/agent-result`) ou fermeture de `propose_actions` avec le bilan.
//!
//! Aucun contenu n'est journalisé : ni argument, ni résumé, ni identifiant d'objet.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use runtime_protocol::pipe::{HttpMethod, PlanMode};
use serde_json::{Map, Value, json};
use synco_e2ee::plan::{ActionKind, ActionState, Executor, PlanGraph};
use synco_e2ee::{OsRandom, RandomSource};
use tokio::task::JoinSet;

use super::{Agent, Flow, Stop, uuid};
use crate::api::Api;
use crate::link::Control;
use crate::plan::{self, PROPOSE_ACTIONS, PlanView};
use crate::tools::{self, Outcome, ToolCtx};
use crate::transcript::{PendingToolCall, ToolCall, ToolStatus};

/// Plafond du `Retry-After` relayé par l'API (secondes).
const MAX_RETRY_AFTER_SECS: u64 = 30;

/// Reprises consécutives sans progrès avant d'abandonner (garde-fou contre une API qui boucle).
const MAX_REFRESH: usize = 8;

/// État d'un plan en cours côté worker (reconstruit à chaque reprise depuis `PlanView`).
pub(super) struct PlanSt {
    pub plan_id: String,
    pub graph: PlanGraph,
    /// Sorties **authentifiées** (résultats de phase déchiffrés sous `CK`, sorties des appels propres).
    pub outputs: BTreeMap<u64, Map<String, Value>>,
    /// Codes d'échec des actions de cet exécutant.
    pub codes: BTreeMap<u64, String>,
    /// Issues que seul le worker connaît (`429` épuisé, issue inconnue) : l'API n'a pas d'état à
    /// changer pour une action qui n'est jamais partie ou dont elle n'a pas vu la fin.
    pub local: BTreeMap<u64, ActionState>,
    /// `plan_result` lus mais **non consommés** : ils restent dans la boîte jusqu'à la fermeture du
    /// plan, pour qu'une reprise du worker retrouve les sorties d'appareil authentifiées.
    pub held: Vec<String>,
    /// Actions d'agent déjà présentes dans un `plan_agent_result` déposé (relu à chaque reprise).
    pub reported: BTreeSet<u64>,
}

/// Suite de la conduite d'un plan.
pub(super) enum PlanFlow {
    /// Le worker s'arrête (attente de l'utilisateur ou de l'appareil).
    Awaiting,
    /// `propose_actions` fermé : le tour continue.
    Closed,
    /// Reprendre la boucle principale (annulation ou arrêt reçus).
    Again,
}

/// Fin d'une phase d'agent.
enum Phase {
    /// Plus rien à faire : le plan est fini ou terminal.
    Finished(PlanView),
    /// `plan_agent_result` déposé.
    Posted,
    /// Relire et recommencer.
    Retry,
    /// Action refusée ou incohérente : on ne poursuit pas.
    Aborted(String, PlanView),
    /// Annulation ou arrêt demandés pendant la phase.
    Interrupted,
}

/// Abandon d'une action d'agent jamais partie (12 §8.3, PC74) : `(n, état, code)`.
type Abandon = (u64, ActionState, &'static str);

/// Une action d'agent à lancer.
struct Job {
    n: u64,
    kind: ActionKind,
    tool: String,
    args: Map<String, Value>,
    args_refs: Option<Map<String, Value>>,
    refs: Option<Map<String, Value>>,
    mutating: bool,
}

/// Rapport d'une action lancée.
struct Report {
    n: u64,
    /// `None` : l'action n'est pas partie (refus de l'API) ; voir `code`.
    state: Option<ActionState>,
    output: Option<Map<String, Value>>,
    code: Option<String>,
    lease_lost: bool,
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Code d'erreur borné et sans contenu (`[a-z0-9_]`, 64 au plus).
fn clean_code(code: &str) -> String {
    let c: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(64)
        .collect::<String>()
        .to_ascii_lowercase();
    if c.is_empty() { "tool_failed".to_owned() } else { c }
}

/// `d` ± 20 % (12 §8.7).
fn jitter(d: Duration) -> Duration {
    let mut b = [0u8; 1];
    let _ = OsRandom.fill(&mut b);
    let pct = 80u32.saturating_add(u32::from(b.first().copied().unwrap_or(0)) % 41);
    d.mul_f64(f64::from(pct) / 100.0)
}

/// Attente avant un nouvel essai : `Retry-After` plafonné, sinon `d` ± 20 %.
fn retry_wait(retry_after: Option<u64>, d: Duration) -> Duration {
    retry_after.map_or_else(|| jitter(d), |s| Duration::from_secs(s.min(MAX_RETRY_AFTER_SECS)))
}

fn halve(limit: &AtomicUsize) {
    let _ = limit.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |l| Some((l / 2).max(1)));
}

fn is_blocked(code: &str) -> bool {
    matches!(code, "action_not_accepted" | "plan_not_executing" | "plan_phase_mismatch" | "action_state_conflict")
}

/// Sortie d'un `server.call` : `data.id` quand c'est un identifiant (12 §4).
fn server_output(data: &Value) -> Option<Map<String, Value>> {
    let id = data.get("id")?.as_str().filter(|i| runtime_protocol::ids::is_identifier(i))?;
    Some(json!({ "id": id }).as_object()?.clone())
}

/// Sortie d'un salon créé : `id` et `spaceId`.
fn thread_output(data: &Value) -> Option<Map<String, Value>> {
    let t = data.get("threads")?.as_array()?.first()?;
    let id = t.get("id")?.as_str().filter(|i| runtime_protocol::ids::is_identifier(i))?;
    let mut out = Map::new();
    out.insert("id".into(), json!(id));
    if let Some(s) = t.get("workspaceId").and_then(Value::as_str).filter(|s| runtime_protocol::ids::is_identifier(s)) {
        out.insert("spaceId".into(), json!(s));
    }
    Some(out)
}

/// Exécute une action d'agent (tâche tokio) : `429` réessayé (le même appel, rien n'a été exécuté),
/// transport coupé après envoi jamais réessayé (`unknown_outcome`).
async fn run_job(
    api: Api,
    epoch: u64,
    user_id: String,
    plan_id: String,
    job: Job,
    delays: Vec<Duration>,
    limit: Arc<AtomicUsize>,
) -> Report {
    let report = |state, output, code: Option<String>, lease_lost| Report { n: job.n, state, output, code, lease_lost };
    let mut attempt = 0usize;
    loop {
        let (outcome, limited) = match job.kind {
            ActionKind::ServerCall => call_server(&api, epoch, &plan_id, &job).await,
            _ => call_thread(&api, epoch, &user_id, &plan_id, &job).await,
        };
        if let Some(retry_after) = limited {
            halve(&limit);
            match delays.get(attempt) {
                Some(d) => {
                    attempt = attempt.saturating_add(1);
                    // `Retry-After` de l'API (plafonné à 30 s) ; sinon 1, 2, 4 s ± 20 %.
                    let wait = retry_wait(retry_after, *d);
                    tokio::time::sleep(wait).await;
                    continue;
                }
                None => return report(Some(ActionState::Failed), None, Some("rate_limited".into()), false),
            }
        }
        return match outcome {
            Called::Done(out) => report(Some(ActionState::Done), out, None, false),
            Called::Failed(code) => report(Some(ActionState::Failed), None, Some(code), false),
            Called::Unknown => report(Some(ActionState::UnknownOutcome), None, Some("unknown_outcome".into()), false),
            Called::Blocked(code) => report(None, None, Some(code), false),
            Called::LeaseLost => report(None, None, None, true),
        };
    }
}

enum Called {
    Done(Option<Map<String, Value>>),
    Failed(String),
    Unknown,
    Blocked(String),
    LeaseLost,
}

/// `server.call` : `POST …/tools/:name/execute` avec `plan`, `args` **non résolus**, `argsRefs` et
/// `refs` (12 §8.4).
async fn call_server(api: &Api, epoch: u64, plan_id: &str, job: &Job) -> (Called, Option<Option<u64>>) {
    let mut body = json!({ "leaseEpoch": epoch, "args": job.args, "plan": { "planId": plan_id, "n": job.n } });
    if let Some(r) = &job.args_refs {
        crate::json_set(&mut body, "argsRefs", Value::Object(r.clone()));
    }
    if let Some(r) = &job.refs {
        crate::json_set(&mut body, "refs", Value::Object(r.clone()));
    }
    let raw = api.conv(HttpMethod::Post, &format!("/tools/{}/execute", job.tool), Some(&body)).await;
    if let Ok(r) = &raw
        && (r.status == 429 || (r.status == 0 && r.relay_error.as_deref() == Some("relay_rate_limited")))
    {
        return (Called::Unknown, Some(r.retry_after));
    }
    let r = match tools::sent(raw) {
        tools::Sent::Answered(r) => r,
        tools::Sent::LocallyRefused => return (Called::Failed("tool_failed".into()), None),
        tools::Sent::Unknown => {
            return (if job.mutating { Called::Unknown } else { Called::Failed("tool_failed".into()) }, None);
        }
    };
    if r.ok() {
        return match r.body.get("ok").and_then(Value::as_bool) {
            Some(true) => (Called::Done(r.body.get("data").and_then(server_output)), None),
            _ => (Called::Failed("tool_failed".into()), None),
        };
    }
    match r.code() {
        Some("lease_conflict") => (Called::LeaseLost, None),
        Some(c) if is_blocked(c) => (Called::Blocked(c.to_owned()), None),
        Some(c) => (Called::Failed(clean_code(c)), None),
        None => (Called::Failed("tool_failed".into()), None),
    }
}

/// `thread.create` du mode autonome (politique `ask`) : `POST /e2ee/threads` avec `rt1` et `plan`.
async fn call_thread(api: &Api, epoch: u64, user_id: &str, plan_id: &str, job: &Job) -> (Called, Option<Option<u64>>) {
    let ctx = ToolCtx { api, lease_epoch: epoch, user_id, plan: Some((plan_id, job.n)) };
    let args = json!({ "threads": [Value::Object(job.args.clone())] });
    match tools::threads::run(&ctx, &args).await {
        Outcome::Done(v) => (Called::Done(thread_output(&v)), None),
        Outcome::LeaseLost => (Called::LeaseLost, None),
        Outcome::NeedKey { .. } => (Called::Failed("key_unavailable".into()), None),
        Outcome::Failed(v) => {
            let code = v.get("error").and_then(Value::as_str).unwrap_or("tool_failed");
            match code {
                "unknown_outcome" => (Called::Unknown, None),
                "rate_limited" | "rt_rate_limited" => (Called::Unknown, Some(None)),
                c if is_blocked(c) => (Called::Blocked(c.to_owned()), None),
                c => (Called::Failed(clean_code(c)), None),
            }
        }
    }
}

impl Agent {
    /// `planId` de l'appel en attente, s'il s'agit d'un `propose_actions`.
    pub(super) fn pending_plan_id(&self) -> Option<String> {
        self.pending.as_ref().and_then(|p| p.plan_id.clone())
    }

    /// Plans proposés depuis le dernier message de l'utilisateur (12 §7.3 : 3 par tour au plus).
    pub(super) fn plans_in_turn(&self) -> usize {
        self.messages
            .iter()
            .rev()
            .take_while(|m| m.role != crate::transcript::Role::User)
            .flat_map(|m| m.tool_calls.iter())
            .filter(|tc| tc.name == PROPOSE_ACTIONS)
            .count()
    }

    /// Appel `propose_actions` du modèle (dans `messages[idx]`).
    pub(super) async fn propose_actions(&mut self, idx: usize, tc: ToolCall) -> Result<Flow, Stop> {
        let Some(cfg) = self.init.plan else { return Ok(Flow::Continue) };
        // Le plan en cours de proposition est déjà compté (son message est dans l'historique).
        if self.plans_in_turn() > plan::MAX_PLANS_PER_TURN {
            self.close_call(&tc.id, &tc.name, ToolStatus::Error, json!({ "error": "plan_limit" })).await?;
            return self.fail("plan_limit").await;
        }
        let plan_id = uuid();
        let proposal = plan::propose(
            &tc.arguments,
            (&plan_id, &self.init.session_id, &tc.id),
            unix_secs(),
            &cfg,
            &self.specs,
            &self.init.tool_policy,
        );
        let proposal = match proposal {
            Ok(p) => p,
            Err(detail) => return self.refuse_plan(&tc, detail).await,
        };
        self.pending = Some(PendingToolCall {
            id: tc.id.clone(),
            name: tc.name.clone(),
            args: proposal.plan.clone(),
            category: "client".to_owned(),
            mutating: true,
            interactive: false,
            plan_id: Some(plan_id.clone()),
            guard: None,
        });
        let mid = self.messages.get(idx).map(|m| m.id.clone()).unwrap_or_default();
        self.em.tool_call(&mid, &tc, false).await?;
        if self.persist_inner("awaiting_confirmation", None, Some(&proposal.meta)).await?.is_err() {
            // Refusé par l'API (`plan_exists`, forme) : rien n'est écrit, le modèle corrige.
            self.pending = None;
            return self.refuse_plan(&tc, "plan_refused").await;
        }
        self.push("AI_AWAITING_CONFIRMATION").await;
        Ok(Flow::Awaiting)
    }

    /// `{"error":"plan_invalid","detail":…}` rendu au modèle ; le tour continue (12 §3.1).
    async fn refuse_plan(&mut self, tc: &ToolCall, detail: &str) -> Result<Flow, Stop> {
        self.close_call(&tc.id, &tc.name, ToolStatus::Error, json!({ "error": "plan_invalid", "detail": detail }))
            .await?;
        self.persist("running", None).await?;
        Ok(Flow::Continue)
    }

    async fn fetch_view(&mut self, plan_id: &str) -> Result<Option<PlanView>, Stop> {
        let r = self.api.conv(HttpMethod::Get, &format!("/plans/{plan_id}"), None).await?;
        if r.ok() {
            return Ok(PlanView::parse(&r.body));
        }
        match r.code() {
            Some("not_found") => Ok(None),
            _ => Err(self.classify_write_error(&r)),
        }
    }

    /// Superpose les issues locales du worker à une vue de l'API.
    fn overlay(&self, v: PlanView) -> PlanView {
        match self.plan.as_ref() {
            Some(st) => v.with_local(&st.local),
            None => v,
        }
    }

    /// Construit (ou met à jour) l'état du plan : graphe contrôlé contre ce que l'API sert (règle 8),
    /// résultats de phase d'agent déjà déposés déchiffrés et recontrôlés (AAD, `planId`, `phase`).
    /// `false` : incohérent, le plan n'est plus exécuté (`tool_call_unverified`).
    fn sync_plan(&mut self, view: &PlanView) -> bool {
        let Some(p) = self.pending.clone() else { return false };
        let Some(plan_id) = p.plan_id.clone() else { return false };
        if self.plan.as_ref().is_none_or(|s| s.plan_id != plan_id) {
            let Some(graph) = plan::graph_from(&p.args, view, self.init.plan.map_or(PlanMode::Plan, |c| c.mode)) else {
                return false;
            };
            self.plan = Some(PlanSt {
                plan_id: plan_id.clone(),
                graph,
                outputs: BTreeMap::new(),
                codes: BTreeMap::new(),
                local: BTreeMap::new(),
                held: Vec::new(),
                reported: BTreeSet::new(),
            });
        }
        let ck = self.ck.clone();
        let sid = self.init.session_id.clone();
        let Some(st) = self.plan.as_mut() else { return false };
        st.reported.clear();
        for (phase, value) in &view.agent_results {
            let Ok(clear) =
                synco_e2ee::plan::decrypt_phase_result(&ck, &sid, &plan_id, Executor::Agent, *phase, &st.graph, value)
            else {
                return false;
            };
            merge_outputs(&mut st.outputs, &clear);
            reported_in(&mut st.reported, &mut st.codes, &clear);
        }
        true
    }

    /// `plan_result:<k>` de la boîte (12 §9) : déchiffré et recontrôlé contre le plan déchiffré ; sinon
    /// l'appel est clos `tool_call_unverified`. Rend vrai si le modèle doit reprendre la main.
    pub(super) async fn on_plan_result(&mut self, id: String, frame: &Value) -> Result<bool, Stop> {
        let Some(plan_id) = self.pending_plan_id() else {
            self.consumed.push(id);
            self.em.error("stale_decision", None).await?;
            return Ok(false);
        };
        // Un autre `planId` (plan clos ou remplacé) : périmé, consommé et ignoré. Seule une AAD fausse
        // sur le **même** plan vaut `tool_call_unverified`.
        if frame.get("planId").and_then(Value::as_str) != Some(plan_id.as_str()) {
            self.consumed.push(id);
            self.em.error("stale_decision", None).await?;
            return Ok(false);
        }
        let phase = frame.get("phase").and_then(Value::as_u64);
        let value = frame.get("value").and_then(Value::as_str);
        let view = self.fetch_view(&plan_id).await?;
        let verified = match (view, phase, value) {
            (Some(view), Some(phase), Some(value)) if self.sync_plan(&view) => {
                let sid = self.init.session_id.clone();
                let ck = self.ck.clone();
                self.plan.as_mut().and_then(|st| {
                    let clear = synco_e2ee::plan::decrypt_phase_result(
                        &ck,
                        &sid,
                        &plan_id,
                        Executor::Device,
                        phase,
                        &st.graph,
                        value,
                    )
                    .ok()?;
                    merge_outputs(&mut st.outputs, &clear);
                    st.held.push(id.clone());
                    Some(())
                })
            }
            _ => None,
        };
        if verified.is_some() {
            return Ok(false);
        }
        self.consumed.push(id);
        self.abandon_unverified(&plan_id).await?;
        self.close_plan(ToolStatus::Error, json!({ "error": "tool_call_unverified" })).await?;
        Ok(true)
    }

    /// Un message de l'utilisateur arrivé alors qu'un plan **accepté** est en cours attend la
    /// fermeture de `propose_actions` (12 §8.6) ; avant la décision, il remplace le plan.
    pub(super) async fn plan_defers_message(&mut self) -> Result<bool, Stop> {
        let Some(plan_id) = self.pending_plan_id() else { return Ok(false) };
        Ok(self.fetch_view(&plan_id).await?.is_some_and(|v| v.status != "proposed"))
    }

    /// Ferme `propose_actions` : résultat, éléments `plan_result` consommés, messages différés remis
    /// en tête de file (traités au tour suivant, 12 §8.6), écriture.
    async fn close_plan(&mut self, status: ToolStatus, result: Value) -> Result<(), Stop> {
        let Some(p) = self.pending.take() else { return Ok(()) };
        self.awaiting_key = None;
        if let Some(st) = self.plan.take() {
            self.consumed.extend(st.held);
        }
        self.close_call(&p.id, &p.name, status, result).await?;
        while let Some(item) = self.deferred.pop_back() {
            self.queue.push_front(item);
        }
        self.persist("running", None).await
    }

    /// Conduit le plan en attente jusqu'à la prochaine attente ou à la fermeture.
    pub(super) async fn drive_plan(&mut self) -> Result<PlanFlow, Stop> {
        let Some(plan_id) = self.pending_plan_id() else { return Ok(PlanFlow::Closed) };
        let mut refresh = 0usize;
        loop {
            let Some(view) = self.fetch_view(&plan_id).await? else {
                self.close_plan(ToolStatus::Error, json!({ "error": "plan_unavailable" })).await?;
                return Ok(PlanFlow::Closed);
            };
            if !self.sync_plan(&view) {
                self.abandon_unverified(&plan_id).await?;
                self.close_plan(ToolStatus::Error, json!({ "error": "tool_call_unverified" })).await?;
                return Ok(PlanFlow::Closed);
            }
            match view.status.as_str() {
                "proposed" => return self.wait_decision().await,
                "rejected" => {
                    let mut result = json!({ "error": "plan_rejected" });
                    if let Some(r) = self.plan_reject_reason.take() {
                        crate::json_set(&mut result, "reason", json!(r));
                    }
                    self.close_plan(ToolStatus::Rejected, result).await?;
                    return Ok(PlanFlow::Closed);
                }
                _ if view.terminal() => {
                    let bilan = self.bilan(&plan_id, &view);
                    self.close_plan(ToolStatus::Done, bilan).await?;
                    return Ok(PlanFlow::Closed);
                }
                _ => {}
            }
            match self.agent_phase(&plan_id, view).await? {
                Phase::Finished(view) => {
                    let bilan = self.bilan(&plan_id, &view);
                    self.close_plan(ToolStatus::Done, bilan).await?;
                    return Ok(PlanFlow::Closed);
                }
                Phase::Posted => return Ok(PlanFlow::Awaiting),
                Phase::Retry => {
                    refresh = refresh.saturating_add(1);
                    if refresh > MAX_REFRESH {
                        return Err(Stop::Fatal("internal"));
                    }
                }
                Phase::Aborted(code, view) => {
                    let mut bilan = self.bilan(&plan_id, &view);
                    crate::json_set(&mut bilan, "error", json!("plan_aborted"));
                    crate::json_set(&mut bilan, "detail", json!(code));
                    self.close_plan(ToolStatus::Error, bilan).await?;
                    return Ok(PlanFlow::Closed);
                }
                Phase::Interrupted => return Ok(PlanFlow::Again),
            }
        }
    }

    /// Plan `proposed` : le worker s'arrête (les éléments consommés entre-temps sont écrits, comme
    /// pour toute attente).
    async fn wait_decision(&mut self) -> Result<PlanFlow, Stop> {
        if !self.consumed.is_empty() || self.status == "queued" {
            self.persist("awaiting_confirmation", None).await?;
        }
        Ok(PlanFlow::Awaiting)
    }

    fn bilan(&self, plan_id: &str, view: &PlanView) -> Value {
        let empty = BTreeMap::new();
        let (outputs, codes) = self.plan.as_ref().map_or((&empty, BTreeMap::new()), |s| (&s.outputs, s.codes.clone()));
        // Action d'agent `done` dont la sortie n'est dans aucun résultat lu (exécutée avant une reprise,
        // pas encore déposée) : la sortie enregistrée par l'API, pour que le bilan ne la perde pas.
        let mut merged = outputs.clone();
        for a in view.actions.iter().filter(|a| a.executor == Executor::Agent && a.state == ActionState::Done) {
            if let (false, Some(o)) = (merged.contains_key(&a.n), a.output.as_ref()) {
                merged.insert(a.n, o.clone());
            }
        }
        plan::bilan(plan_id, view, &merged, &codes)
    }

    /// Phase d'agent (12 §8.3) : lance les actions prêtes en parallèle, une place libérée est reprise
    /// aussitôt, plus petite `n` d'abord ; aucune action ne démarre après `expiresAt`, un arrêt ou
    /// une annulation ; celles en cours vont à leur terme. Une action qui n'a pas pu partir est
    /// **abandonnée** par `agent-result` (PC74), jamais relancée.
    async fn agent_phase(&mut self, plan_id: &str, raw: PlanView) -> Result<Phase, Stop> {
        let mut raw = raw;
        let mut view = self.overlay(raw.clone());
        let Some(cfg) = self.init.plan else { return Ok(Phase::Finished(raw)) };
        let expires_at =
            self.pending.as_ref().and_then(|p| p.args.get("expiresAt")).and_then(Value::as_u64).unwrap_or(0);
        let limit = Arc::new(AtomicUsize::new(usize::from(cfg.concurrency.clamp(1, 8))));
        let mut set: JoinSet<Report> = JoinSet::new();
        let (mut started, mut in_flight): (BTreeSet<u64>, BTreeSet<u64>) = (BTreeSet::new(), BTreeSet::new());
        let mut blocked: Vec<String> = Vec::new();
        let mut stopping = false;
        let mut running = self.status == "running";
        loop {
            let live = !stopping && !view.terminal() && unix_secs() < expires_at && blocked.is_empty();
            if live {
                for n in ready_agent_actions(&view, &started) {
                    if in_flight.len() >= limit.load(Ordering::SeqCst) {
                        break;
                    }
                    if !running {
                        self.set_running().await?;
                        running = true;
                    }
                    let job = match self.build_job(n, &view, cfg.mode) {
                        Ok(j) => j,
                        Err(code) => {
                            // Action qui ne part pas : abandon (code de la liste fermée).
                            started.insert(n);
                            self.fail_locally(n, ActionState::Failed, abandon_code(code));
                            continue;
                        }
                    };
                    started.insert(n);
                    in_flight.insert(n);
                    set.spawn(run_job(
                        self.api.clone(),
                        self.init.lease_epoch,
                        self.init.user_id.clone(),
                        plan_id.to_owned(),
                        job,
                        self.opts.rate_limit_delays.clone(),
                        Arc::clone(&limit),
                    ));
                }
                view = self.overlay(raw.clone());
            }
            if in_flight.is_empty() {
                break;
            }
            tokio::select! {
                done = set.join_next() => {
                    let Some(done) = done else { break };
                    let Ok(rep) = done else { return Err(Stop::Fatal("internal")) };
                    in_flight.remove(&rep.n);
                    if rep.lease_lost {
                        set.abort_all();
                        return Err(Stop::LeaseLost);
                    }
                    match (rep.state, rep.code) {
                        (Some(state), code) => {
                            if let Some(st) = self.plan.as_mut() {
                                if let Some(out) = &rep.output {
                                    st.outputs.insert(rep.n, out.clone());
                                }
                                if let Some(c) = code {
                                    st.codes.insert(rep.n, c);
                                }
                                if state != ActionState::Done {
                                    st.local.insert(rep.n, state);
                                }
                            }
                        }
                        // Verrou refusé : l'action n'est pas acceptée pour l'API, elle est abandonnée.
                        (None, Some(c)) if c == "action_not_accepted" => {
                            self.fail_locally(rep.n, ActionState::Failed, "action_not_accepted");
                        }
                        (None, code) => blocked.push(code.unwrap_or_else(|| "plan_phase_mismatch".to_owned())),
                    }
                    match self.fetch_view(plan_id).await? {
                        Some(v) => {
                            raw = v;
                            view = self.overlay(raw.clone());
                        }
                        None => return Ok(Phase::Aborted("plan_unavailable".into(), raw)),
                    }
                }
                c = self.ctl.recv() => match c {
                    None => {
                        set.abort_all();
                        return Err(Stop::Pipe);
                    }
                    Some(Control::Shutdown(s)) => {
                        self.shutdown = Some(s);
                        stopping = true;
                    }
                    Some(c) => {
                        self.on_control(c).await?;
                        if self.queue.iter().any(|(_, f)| f.get("t").and_then(Value::as_str) == Some("cancel")) {
                            stopping = true;
                        }
                    }
                },
            }
        }
        if stopping {
            return Ok(Phase::Interrupted);
        }
        // Seule la vue de l'API décide de la fin du plan : la vue superposée ne sert qu'au bilan et à
        // ne jamais relancer une action.
        let Some(raw) = self.fetch_view(plan_id).await? else {
            return Ok(Phase::Aborted("plan_unavailable".into(), raw));
        };
        if raw.terminal() || raw.finished() {
            return Ok(Phase::Finished(raw));
        }
        if let Some(code) = blocked.into_iter().next() {
            return Ok(Phase::Aborted(code, raw));
        }
        let abandons = match self.abandons(&raw) {
            Ok(a) => a,
            Err(code) => return Ok(Phase::Aborted(code, raw)),
        };
        if unix_secs() >= expires_at && abandons.is_empty() && !ready_agent_actions(&raw, &started).is_empty() {
            // `expiresAt` passé : aucune action ne démarre, le plan expire côté API (12 §7.1).
            return Ok(Phase::Aborted("plan_expired".into(), raw));
        }
        let Some(graph) = self.plan.as_ref().map(|st| st.graph.clone()) else { return Err(Stop::Fatal("internal")) };
        self.post_agent_result(plan_id, &raw, &abandons, &graph).await
    }

    /// Issue locale d'une action d'agent jamais partie (ou dont l'issue est inconnue) : le worker se
    /// souvient de l'état et du code, pour ne pas la relancer et pour l'abandon (PC74).
    fn fail_locally(&mut self, n: u64, state: ActionState, code: &str) {
        if let Some(st) = self.plan.as_mut() {
            st.local.insert(n, state);
            st.codes.insert(n, code.to_owned());
        }
    }

    /// Abandons à déclarer : issues locales dont l'API garde l'action `pending` (donc acceptée), avec
    /// un code de la liste fermée. `Err(code)` : issue locale sans code déclarable (plan clos
    /// `plan_aborted`).
    fn abandons(&self, raw: &PlanView) -> Result<Vec<Abandon>, String> {
        let Some(st) = self.plan.as_ref() else { return Ok(Vec::new()) };
        let mut out = Vec::new();
        for (n, state) in &st.local {
            let pending =
                raw.action(*n).is_some_and(|a| a.executor == Executor::Agent && a.state == ActionState::Pending);
            if !pending {
                continue;
            }
            let code = st.codes.get(n).map_or("", String::as_str);
            // Issue inconnue sans code propre (transport coupé) : l'API n'a rien exécuté.
            let code = if *state == ActionState::UnknownOutcome && !plan_abandon_code(code) {
                "action_not_accepted"
            } else {
                code
            };
            let Some(code) = synco_e2ee::plan::ABANDON_CODES.iter().find(|c| **c == code) else {
                return Err(if code.is_empty() { "tool_failed".to_owned() } else { code.to_owned() });
            };
            out.push((*n, *state, *code));
        }
        Ok(out)
    }

    /// Actions d'agent devenues finales (`done`, `failed`, `unknown_outcome`) et absentes des
    /// `plan_agent_result` déjà déposés, plus les abandons : tout ce que le prochain résultat doit
    /// porter, dans l'ordre de `n`, même après un `Retry`, un `Interrupted` ou une reprise du worker.
    fn outcome_list(&self, raw: &PlanView, abandons: &[Abandon]) -> Vec<Value> {
        let reported = self.plan.as_ref().map(|st| &st.reported);
        let mut list: BTreeMap<u64, Value> = BTreeMap::new();
        for a in raw.actions.iter().filter(|a| {
            a.executor == Executor::Agent
                && matches!(a.state, ActionState::Done | ActionState::Failed | ActionState::UnknownOutcome)
                && !reported.is_some_and(|r| r.contains(&a.n))
        }) {
            let mut o = json!({ "n": a.n, "state": a.state.as_str() });
            let out = (a.state == ActionState::Done)
                .then(|| self.plan.as_ref().and_then(|st| st.outputs.get(&a.n)).or(a.output.as_ref()))
                .flatten();
            if let Some(out) = out {
                crate::json_set(&mut o, "output", Value::Object(out.clone()));
            }
            list.insert(a.n, o);
        }
        for (n, state, code) in abandons {
            list.insert(*n, json!({ "n": n, "state": state.as_str(), "code": code }));
        }
        list.into_values().collect()
    }

    /// `tool_call_unverified` : le worker ne peut plus exécuter ce plan ; ses actions d'agent encore
    /// `pending` sont abandonnées (`action_not_accepted`) avant la clôture de `propose_actions`.
    /// Tout échec de l'API est toléré (le plan expirera) ; seules les pannes du worker remontent.
    async fn abandon_unverified(&mut self, plan_id: &str) -> Result<(), Stop> {
        let Some(raw) = self.fetch_view(plan_id).await? else { return Ok(()) };
        if !matches!(raw.status.as_str(), "accepted" | "executing") {
            return Ok(());
        }
        let abandons: Vec<Abandon> = raw
            .actions
            .iter()
            .filter(|a| a.executor == Executor::Agent && a.state == ActionState::Pending)
            .map(|a| (a.n, ActionState::Failed, "action_not_accepted"))
            .collect();
        let graph = PlanGraph::new(
            raw.actions
                .iter()
                .map(|a| synco_e2ee::plan::GraphAction { n: a.n, executor: a.executor, after: a.after.clone() })
                .collect(),
        );
        if let (false, Ok(graph)) = (abandons.is_empty(), graph) {
            let _ = self.post_agent_result(plan_id, &raw, &abandons, &graph).await?;
        }
        Ok(())
    }

    /// `POST …/agent-result` (12 §8.3, étape 3, §12.2) : résultat de phase chiffré et abandons.
    async fn post_agent_result(
        &mut self,
        plan_id: &str,
        raw: &PlanView,
        abandons: &[Abandon],
        graph: &PlanGraph,
    ) -> Result<Phase, Stop> {
        let phase = raw.agent_phases.saturating_add(1);
        let list = self.outcome_list(raw, abandons);
        let clear = json!({ "v": 1, "planId": plan_id, "phase": phase, "outcomes": list });
        let value = synco_e2ee::plan::encrypt_phase_result(
            &self.ck,
            &self.init.session_id,
            Executor::Agent,
            graph,
            &clear,
            &mut OsRandom,
        )
        .map_err(|_| Stop::Fatal("internal"))?;
        let mut body =
            json!({ "leaseEpoch": self.init.lease_epoch, "baseRev": self.rev, "phase": phase, "value": value });
        if !abandons.is_empty() {
            let a: Vec<Value> =
                abandons.iter().map(|(n, s, c)| json!({ "n": n, "state": s.as_str(), "code": c })).collect();
            crate::json_set(&mut body, "abandoned", Value::Array(a));
        }
        let r = self.api.conv(HttpMethod::Post, &format!("/plans/{plan_id}/agent-result"), Some(&body)).await?;
        if r.ok() {
            // Plan devenu terminal (abandons) : `200 { status }`, rien à attendre ; on relit et on clôt.
            if r.body.get("status").and_then(Value::as_str).is_some_and(is_terminal_status) {
                if let Some(rev) = r.body.get("rev").and_then(Value::as_u64) {
                    self.rev = rev;
                }
                return Ok(Phase::Retry);
            }
            self.rev = r.body.get("rev").and_then(Value::as_u64).unwrap_or(self.rev.saturating_add(1));
            self.set_local_status("awaiting_confirmation", None).await?;
            return Ok(Phase::Posted);
        }
        match r.code() {
            // Une action d'agent est devenue prête entre-temps, ou le plan est fini : relire.
            Some("plan_phase_mismatch" | "plan_not_executing") => Ok(Phase::Retry),
            Some("rev_conflict") => {
                let head = self.api.conv(HttpMethod::Get, "", None).await?;
                if let Some(rev) = head.body.get("rev").and_then(Value::as_u64) {
                    self.rev = rev;
                }
                Ok(Phase::Retry)
            }
            _ => Err(self.classify_write_error(&r)),
        }
    }

    /// Prépare une action : `args` et `argsRefs` du **plan déchiffré**, `refs` résolues depuis des
    /// sorties authentifiées et comparées à celles de l'API. `Err(code)` : l'action ne part pas.
    fn build_job(&self, n: u64, view: &PlanView, mode: PlanMode) -> Result<Job, &'static str> {
        let p = self.pending.as_ref().ok_or("plan_unavailable")?;
        let st = self.plan.as_ref().ok_or("plan_unavailable")?;
        let a = plan::plan_action(&p.args, n).ok_or("plan_unavailable")?;
        let kind = a.get("kind").and_then(Value::as_str).and_then(|k| ActionKind::parse(k).ok()).ok_or("plan_kind")?;
        let args = a.get("args").and_then(Value::as_object).cloned().ok_or("plan_args")?;
        let args_refs = a.get("argsRefs").and_then(Value::as_object).cloned();
        let refs = match &args_refs {
            Some(r) if !r.is_empty() => Some(plan::resolve_refs(r, &st.outputs, view)?),
            _ => None,
        };
        match kind {
            ActionKind::ServerCall => {
                let tool = a.get("tool").and_then(Value::as_str).ok_or("plan_kind")?.to_owned();
                let mutating = self.spec(&tool).is_none_or(|s| s.mutating);
                Ok(Job { n, kind, tool, args, args_refs, refs, mutating })
            }
            ActionKind::ThreadCreate => {
                // 12 §11.4 : un mandat qui n'est plus `auto` ne signe plus rien.
                if mode != PlanMode::Auto {
                    return Err("autonomy_required");
                }
                let mut merged = args;
                for (k, v) in refs.iter().flatten() {
                    merged.insert(k.clone(), v.clone());
                }
                Ok(Job { n, kind, tool: String::new(), args: merged, args_refs: None, refs: None, mutating: true })
            }
            _ => Err("plan_kind"),
        }
    }
}

/// Actions d'agent prêtes (12 §8.1) : `pending`, prête pour l'API **et** toutes les dépendances `done`
/// (recontrôle local), pas déjà lancées par cette phase ; plus petite `n` d'abord.
fn ready_agent_actions(view: &PlanView, started: &BTreeSet<u64>) -> Vec<u64> {
    view.actions
        .iter()
        .filter(|a| {
            a.executor == Executor::Agent
                && a.state == ActionState::Pending
                && a.ready
                && !started.contains(&a.n)
                && a.after.iter().all(|m| view.action(*m).is_some_and(|d| d.state == ActionState::Done))
        })
        .map(|a| a.n)
        .collect()
}

/// Code d'abandon d'une erreur de préparation (`build_job`) : hors liste, `action_not_accepted`.
fn abandon_code(code: &str) -> &'static str {
    synco_e2ee::plan::ABANDON_CODES.iter().find(|c| **c == code).copied().unwrap_or("action_not_accepted")
}

fn plan_abandon_code(code: &str) -> bool {
    synco_e2ee::plan::is_abandon_code(code)
}

fn is_terminal_status(s: &str) -> bool {
    matches!(s, "done" | "failed" | "interrupted" | "rejected" | "stopped" | "expired")
}

/// Actions citées par un résultat de phase déjà recontrôlé (quel que soit l'état),
/// et codes d'abandon (le bilan les garde après une reprise).
fn reported_in(reported: &mut BTreeSet<u64>, codes: &mut BTreeMap<u64, String>, clear: &Value) {
    for o in clear.get("outcomes").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default() {
        if let Some(n) = o.get("n").and_then(Value::as_u64) {
            reported.insert(n);
            if let Some(code) = o.get("code").and_then(Value::as_str) {
                codes.insert(n, code.to_owned());
            }
        }
    }
}

/// Sorties d'un résultat de phase déjà recontrôlé : seulement celles des actions `done`.
fn merge_outputs(outputs: &mut BTreeMap<u64, Map<String, Value>>, clear: &Value) {
    for o in clear.get("outcomes").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default() {
        let done = o.get("state").and_then(Value::as_str) == Some("done");
        if let (true, Some(n), Some(out)) =
            (done, o.get("n").and_then(Value::as_u64), o.get("output").and_then(Value::as_object))
        {
            outputs.insert(n, out.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_plafonne_a_30_secondes() {
        let d = Duration::from_secs(1);
        assert_eq!(retry_wait(Some(5), d), Duration::from_secs(5));
        assert_eq!(retry_wait(Some(3_600), d), Duration::from_secs(30));
        let j = retry_wait(None, d);
        assert!(j >= Duration::from_millis(800) && j <= Duration::from_millis(1_200), "{j:?}");
    }
}
