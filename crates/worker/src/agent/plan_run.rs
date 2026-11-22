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

/// Issues des actions d'une phase : état final et sortie.
type Outcomes = BTreeMap<u64, (ActionState, Option<Map<String, Value>>)>;

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
        let (outcome, rate_limited) = match job.kind {
            ActionKind::ServerCall => call_server(&api, epoch, &plan_id, &job).await,
            _ => call_thread(&api, epoch, &user_id, &plan_id, &job).await,
        };
        if rate_limited {
            halve(&limit);
            match delays.get(attempt) {
                Some(d) => {
                    attempt = attempt.saturating_add(1);
                    tokio::time::sleep(jitter(*d)).await;
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
async fn call_server(api: &Api, epoch: u64, plan_id: &str, job: &Job) -> (Called, bool) {
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
        return (Called::Unknown, true);
    }
    let r = match tools::sent(raw) {
        tools::Sent::Answered(r) => r,
        tools::Sent::LocallyRefused => return (Called::Failed("tool_failed".into()), false),
        tools::Sent::Unknown => {
            return (if job.mutating { Called::Unknown } else { Called::Failed("tool_failed".into()) }, false);
        }
    };
    if r.ok() {
        return match r.body.get("ok").and_then(Value::as_bool) {
            Some(true) => (Called::Done(r.body.get("data").and_then(server_output)), false),
            _ => (Called::Failed("tool_failed".into()), false),
        };
    }
    match r.code() {
        Some("lease_conflict") => (Called::LeaseLost, false),
        Some(c) if is_blocked(c) => (Called::Blocked(c.to_owned()), false),
        Some(c) => (Called::Failed(clean_code(c)), false),
        None => (Called::Failed("tool_failed".into()), false),
    }
}

/// `thread.create` du mode autonome (politique `ask`) : `POST /e2ee/threads` avec `rt1` et `plan`.
async fn call_thread(api: &Api, epoch: u64, user_id: &str, plan_id: &str, job: &Job) -> (Called, bool) {
    let ctx = ToolCtx { api, lease_epoch: epoch, user_id, plan: Some((plan_id, job.n)) };
    let args = json!({ "threads": [Value::Object(job.args.clone())] });
    match tools::threads::run(&ctx, &args).await {
        Outcome::Done(v) => (Called::Done(thread_output(&v)), false),
        Outcome::LeaseLost => (Called::LeaseLost, false),
        Outcome::NeedKey { .. } => (Called::Failed("key_unavailable".into()), false),
        Outcome::Failed(v) => {
            let code = v.get("error").and_then(Value::as_str).unwrap_or("tool_failed");
            match code {
                "unknown_outcome" => (Called::Unknown, false),
                "rate_limited" | "rt_rate_limited" => (Called::Unknown, true),
                c if is_blocked(c) => (Called::Blocked(c.to_owned()), false),
                c => (Called::Failed(clean_code(c)), false),
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

    /// [`Self::fetch_view`] avec les issues locales du worker ([`PlanView::with_local`]).
    async fn fetch_overlaid(&mut self, plan_id: &str) -> Result<Option<PlanView>, Stop> {
        let view = self.fetch_view(plan_id).await?;
        Ok(view.map(|v| self.overlay(v)))
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
            let Some(graph) = plan::graph_from(&p.args, view) else { return false };
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
            reported_in(&mut st.reported, &clear);
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
                self.close_plan(ToolStatus::Error, json!({ "error": "tool_call_unverified" })).await?;
                return Ok(PlanFlow::Closed);
            }
            // Vue superposée dès l'entrée : une action déjà `failed` / `unknown_outcome` sur place ne
            // repart jamais (08 §5), même après un `Retry`.
            let view = self.overlay(view);
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
    /// une annulation ; celles en cours vont à leur terme.
    async fn agent_phase(&mut self, plan_id: &str, view: PlanView) -> Result<Phase, Stop> {
        let mut view = self.overlay(view);
        let Some(cfg) = self.init.plan else { return Ok(Phase::Finished(view)) };
        let expires_at =
            self.pending.as_ref().and_then(|p| p.args.get("expiresAt")).and_then(Value::as_u64).unwrap_or(0);
        let limit = Arc::new(AtomicUsize::new(usize::from(cfg.concurrency.clamp(1, 8))));
        let mut set: JoinSet<Report> = JoinSet::new();
        let (mut started, mut in_flight): (BTreeSet<u64>, BTreeSet<u64>) = (BTreeSet::new(), BTreeSet::new());
        let mut outcomes = self.unreported_outcomes(&view);
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
                            blocked.push(code.to_owned());
                            break;
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
                            outcomes.insert(rep.n, (state, rep.output));
                        }
                        (None, code) => blocked.push(code.unwrap_or_else(|| "plan_phase_mismatch".to_owned())),
                    }
                    match self.fetch_overlaid(plan_id).await? {
                        Some(v) => view = v,
                        None => return Ok(Phase::Aborted("plan_unavailable".into(), view)),
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
        let Some(fresh) = self.fetch_overlaid(plan_id).await? else {
            return Ok(Phase::Aborted("plan_unavailable".into(), view));
        };
        view = fresh;
        if view.terminal() || view.finished() {
            return Ok(Phase::Finished(view));
        }
        if let Some(code) = blocked.into_iter().next() {
            return Ok(Phase::Aborted(code, view));
        }
        if unix_secs() >= expires_at && !ready_agent_actions(&view, &started).is_empty() {
            // `expiresAt` passé : aucune action ne démarre, le plan expire côté API (12 §7.1).
            return Ok(Phase::Aborted("plan_expired".into(), view));
        }
        self.post_agent_result(plan_id, &view, &outcomes).await
    }

    /// Actions d'agent devenues finales (`done`, `failed`, `unknown_outcome`) et absentes des
    /// `plan_agent_result` déjà déposés : elles figurent dans le prochain, même après un `Retry`, un
    /// `Interrupted` ou une reprise du worker (le bilan garde ainsi leurs sorties).
    fn unreported_outcomes(&self, view: &PlanView) -> Outcomes {
        let Some(st) = self.plan.as_ref() else { return Outcomes::new() };
        view.actions
            .iter()
            .filter(|a| {
                a.executor == Executor::Agent
                    && matches!(a.state, ActionState::Done | ActionState::Failed | ActionState::UnknownOutcome)
                    && !st.reported.contains(&a.n)
            })
            .map(|a| {
                let out = (a.state == ActionState::Done)
                    .then(|| st.outputs.get(&a.n).or(a.output.as_ref()).cloned())
                    .flatten();
                (a.n, (a.state, out))
            })
            .collect()
    }

    /// `POST …/agent-result` (12 §8.3, étape 3, §12.2).
    async fn post_agent_result(&mut self, plan_id: &str, view: &PlanView, outcomes: &Outcomes) -> Result<Phase, Stop> {
        let phase = view.agent_phases.saturating_add(1);
        let list: Vec<Value> = outcomes
            .iter()
            .map(|(n, (state, out))| {
                let mut o = json!({ "n": n, "state": state.as_str() });
                if let Some(out) = out {
                    crate::json_set(&mut o, "output", Value::Object(out.clone()));
                }
                o
            })
            .collect();
        let clear = json!({ "v": 1, "planId": plan_id, "phase": phase, "outcomes": list });
        let Some(st) = self.plan.as_ref() else { return Err(Stop::Fatal("internal")) };
        let value = synco_e2ee::plan::encrypt_phase_result(
            &self.ck,
            &self.init.session_id,
            Executor::Agent,
            &st.graph,
            &clear,
            &mut OsRandom,
        )
        .map_err(|_| Stop::Fatal("internal"))?;
        let body = json!({ "leaseEpoch": self.init.lease_epoch, "baseRev": self.rev, "phase": phase, "value": value });
        let r = self.api.conv(HttpMethod::Post, &format!("/plans/{plan_id}/agent-result"), Some(&body)).await?;
        if r.ok() {
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

/// Actions citées par un résultat de phase déjà recontrôlé (quel que soit l'état).
fn reported_in(reported: &mut BTreeSet<u64>, clear: &Value) {
    for o in clear.get("outcomes").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default() {
        if let Some(n) = o.get("n").and_then(Value::as_u64) {
            reported.insert(n);
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
