//! Plans d'action côté worker (lot L08d, docs/plan/12) : outil `propose_actions`, construction et
//! validation du plan (fonctions pures de `synco-e2ee`, jamais réimplémentées ici), lecture de
//! `PlanView`, références (`argsRefs` → `refs`) et bilan rendu au modèle.
//!
//! Le worker ne fait confiance à rien de ce que l'API sert : les sorties qui alimentent `refs` sont
//! lues dans des résultats de phase authentifiés par `CK` ([`crate::agent`]) et **comparées** à la
//! sortie que l'API a enregistrée ([`resolve_refs`]).

use std::collections::BTreeMap;

use runtime_protocol::pipe::{PlanInit, PlanMode, ToolPolicy};
use serde_json::{Map, Value, json};
use synco_e2ee::delegation::MandateMode;
use synco_e2ee::plan::{
    ActionKind, ActionState, Executor, GraphAction, PlanContext, PlanGraph, ToolManifest, parse_arg_ref,
    plan_server_digests, validate_plan,
};

use crate::provider::ToolDef;
use crate::tools::{ToolSpec, effective_policy};

/// Nom de l'outil interne.
pub const PROPOSE_ACTIONS: &str = "propose_actions";
/// Plans consécutifs au plus par tour (12 §7.3) ; au-delà, `failed` `plan_limit`.
pub const MAX_PLANS_PER_TURN: usize = 3;

/// Description de l'outil donnée au modèle (12 §3.1, PC58), reprise telle quelle.
pub const DESCRIPTION: &str = "Propose un plan d'actions que l'utilisateur validera. Déclare pour chaque action, dans `after`, toutes les actions dont elle a **réellement** besoin, et seulement celles-là : une action sans `after` démarre tout de suite, et les actions prêtes s'exécutent **en parallèle**. N'ajoute jamais de dépendance pour imposer un ordre d'affichage ou par prudence : chaque `after` superflu ralentit le plan. Quand une action utilise l'identifiant créé par une autre, mets cette autre dans `after` et l'identifiant dans `argsRefs` (`\"$<n>.id\"`). Regroupe les actions liées avec `groups` (par exemple une catégorie et ses salons) pour que l'utilisateur lise le plan facilement ; les groupes ne changent pas l'exécution. Un plan compte **au plus 100 actions** (et 2 000 dépendances au total) : au-delà, découpe le travail en plusieurs plans successifs, chacun cohérent et utile seul (par exemple une catégorie complète par plan), et propose le suivant une fois le précédent exécuté. Tu as droit à 3 plans consécutifs par tour.";

/// `propose_actions` tel que le voit le modèle.
#[must_use]
pub fn tool_def() -> ToolDef {
    ToolDef {
        name: PROPOSE_ACTIONS.to_owned(),
        description: DESCRIPTION.to_owned(),
        parameters: json!({
            "type": "object",
            "properties": {
                "summary": { "type": "string", "description": "Résumé du plan, affiché tel quel à l'utilisateur." },
                "groups": { "type": "array", "items": { "type": "object", "properties": {
                    "id": { "type": "string", "description": "[a-z0-9_-]{1,32}" },
                    "label": { "type": "string", "description": "1 à 100 caractères" } },
                    "required": ["id", "label"] } },
                "actions": { "type": "array", "items": { "type": "object", "properties": {
                    "n": { "type": "integer", "description": "Position, de 1 sans trou." },
                    "kind": { "type": "string", "enum": ["category.create", "thread.create", "folder.create", "file.create_text", "server.call"] },
                    "tool": { "type": "string", "description": "Seulement pour server.call." },
                    "args": { "type": "object" },
                    "group": { "type": "string" },
                    "after": { "type": "array", "items": { "type": "integer" } },
                    "argsRefs": { "type": "object", "additionalProperties": { "type": "string" } } },
                    "required": ["n", "kind", "args"] } }
            },
            "required": ["summary", "actions"]
        }),
    }
}

/// Plan prêt à écrire.
#[derive(Debug)]
pub struct Proposal {
    /// Clair du plan (12 §3.2).
    pub plan: Value,
    /// Graphe validé.
    pub graph: PlanGraph,
    /// Corps de `plan` pour `POST …/plans` (12 §12.2).
    pub meta: Value,
}

/// Secondes Unix → ISO 8601 (dates du canal).
fn iso(secs: u64) -> String {
    crate::time::iso8601(secs.saturating_mul(1_000))
}

/// Construit et valide le plan demandé par le modèle (12 §3.1, §5). `Err(detail)` : `detail` de
/// `{"error":"plan_invalid","detail":…}` (texte court, sans valeur reçue).
pub fn propose(
    args: &Value,
    ids: (&str, &str, &str),
    now_secs: u64,
    cfg: &PlanInit,
    specs: &[ToolSpec],
    policy: &BTreeMap<String, ToolPolicy>,
) -> Result<Proposal, &'static str> {
    let (plan_id, session_id, tool_call_id) = ids;
    let root = args.as_object().ok_or("plan_header")?;
    if root.keys().any(|k| !matches!(k.as_str(), "summary" | "groups" | "actions")) {
        return Err("plan_header");
    }
    let mut plan = Map::new();
    plan.insert("v".into(), json!(1));
    plan.insert("planId".into(), json!(plan_id));
    plan.insert("sessionId".into(), json!(session_id));
    plan.insert("toolCallId".into(), json!(tool_call_id));
    plan.insert("createdAt".into(), json!(now_secs));
    plan.insert("expiresAt".into(), json!(now_secs.saturating_add(cfg.confirmation_timeout_secs)));
    plan.insert("summary".into(), root.get("summary").cloned().ok_or("plan_header")?);
    if let Some(groups) = root.get("groups") {
        plan.insert("groups".into(), groups.clone());
    }
    plan.insert("actions".into(), root.get("actions").cloned().ok_or("plan_actions")?);
    let plan = Value::Object(plan);

    // `deny` n'est jamais proposé (12 §2) : ni un outil serveur interdit, ni `create_thread` interdit.
    let denied = |name: &str| policy.get(name) == Some(&ToolPolicy::Deny);
    let actions = plan.get("actions").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    for a in actions {
        let kind = a.get("kind").and_then(Value::as_str);
        let refused = match kind {
            Some("server.call") => a.get("tool").and_then(Value::as_str).is_some_and(denied),
            Some("thread.create") => denied("create_thread"),
            _ => false,
        };
        if refused {
            return Err("plan_kind");
        }
    }
    let manifest = ToolManifest::from_json(&Value::Array(
        specs
            .iter()
            .map(|s| json!({ "name": s.name, "category": s.category, "mutating": s.mutating, "parameters": s.parameters }))
            .collect(),
    ));
    let create_thread_ask =
        specs.iter().find(|s| s.name == "create_thread").is_none_or(|s| effective_policy(s, policy) == ToolPolicy::Ask);
    let ctx = PlanContext {
        session_id,
        max_lifetime_secs: cfg.confirmation_timeout_secs,
        manifest: &manifest,
        mode: match cfg.mode {
            PlanMode::Plan => MandateMode::Plan,
            PlanMode::Auto => MandateMode::Auto,
        },
        create_thread_ask,
    };
    let graph = validate_plan(&plan, &ctx).map_err(synco_e2ee::plan::PlanInvalid::detail)?;
    let digests = plan_server_digests(&plan).map_err(|_| "plan_args")?;
    let meta = json!({
        "planId": plan_id,
        "toolCallId": tool_call_id,
        "actionCount": graph.actions().len(),
        "createdAt": iso(now_secs),
        "expiresAt": iso(now_secs.saturating_add(cfg.confirmation_timeout_secs)),
        "actions": graph.actions().iter().map(|a| json!({ "n": a.n, "executor": a.executor.as_str(), "after": a.after })).collect::<Vec<_>>(),
        "serverDigests": digests.iter().map(|(n, d)| json!({ "n": n, "sha256Hex": d })).collect::<Vec<_>>(),
    });
    Ok(Proposal { plan, graph, meta })
}

/// Action telle que l'API la sert (`PlanView.actions`, 12 §12.1).
#[derive(Debug, Clone)]
pub struct ViewAction {
    /// Position.
    pub n: u64,
    /// Exécutant.
    pub executor: Executor,
    /// Dépendances.
    pub after: Vec<u64>,
    /// Prête selon l'API.
    pub ready: bool,
    /// État.
    pub state: ActionState,
    /// Sortie enregistrée par l'API (identifiants), si elle existe.
    pub output: Option<Map<String, Value>>,
}

/// `PlanView` (12 §12.1) : seulement les champs utiles au worker. **Aucune** confiance : tout ce
/// qui entre dans une exécution est recontrôlé contre le plan déchiffré.
#[derive(Debug, Clone)]
pub struct PlanView {
    /// Statut du plan.
    pub status: String,
    /// Actions, dans l'ordre de `n`.
    pub actions: Vec<ViewAction>,
    /// Phases d'agent closes.
    pub agent_phases: u64,
    /// Résultats de phase d'agent chiffrés `(phase, valeur)`.
    pub agent_results: Vec<(u64, String)>,
}

impl PlanView {
    /// Lecture tolérante du corps ; `None` si une action est illisible.
    #[must_use]
    pub fn parse(v: &Value) -> Option<Self> {
        let mut actions = Vec::new();
        for a in v.get("actions")?.as_array()? {
            actions.push(ViewAction {
                n: a.get("n")?.as_u64()?,
                executor: Executor::parse(a.get("executor")?.as_str()?).ok()?,
                after: a.get("after")?.as_array()?.iter().map(Value::as_u64).collect::<Option<Vec<_>>>()?,
                ready: a.get("ready").and_then(Value::as_bool).unwrap_or(false),
                state: ActionState::parse(a.get("state")?.as_str()?).ok()?,
                output: a.get("output").and_then(Value::as_object).cloned(),
            });
        }
        let agent_results = v
            .get("agentResults")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter_map(|r| Some((r.get("phase")?.as_u64()?, r.get("value")?.as_str()?.to_owned())))
            .collect();
        Some(Self {
            status: v.get("status")?.as_str()?.to_owned(),
            actions,
            agent_phases: v.get("agentPhases").and_then(Value::as_u64).unwrap_or(0),
            agent_results,
        })
    }

    /// Action `n`.
    #[must_use]
    pub fn action(&self, n: u64) -> Option<&ViewAction> {
        self.actions.iter().find(|a| a.n == n)
    }

    /// Plus aucune action `pending` ni `executing`.
    #[must_use]
    pub fn finished(&self) -> bool {
        self.actions.iter().all(|a| a.state.is_final())
    }

    /// Vue avec les issues **locales** : une action d'agent qui n'a jamais atteint l'API (`429`
    /// persistant) ou dont l'issue est inconnue côté worker n'a pas changé d'état chez elle ; le
    /// worker la compte `failed` / `unknown_outcome` et passe `skipped` ses dépendantes transitives
    /// encore `pending` (PC54), pour le bilan et pour savoir si le plan est fini.
    #[must_use]
    pub fn with_local(&self, local: &BTreeMap<u64, ActionState>) -> Self {
        let mut v = self.clone();
        for a in &mut v.actions {
            if let Some(s) = local.get(&a.n).filter(|_| !a.state.is_final() || a.state == ActionState::Executing) {
                a.state = *s;
            }
        }
        let snapshot: Vec<(u64, ActionState)> = v.actions.iter().map(|a| (a.n, a.state)).collect();
        for a in &mut v.actions {
            let bad = a.after.iter().any(|m| {
                snapshot.iter().any(|(n, s)| {
                    n == m && matches!(s, ActionState::Failed | ActionState::UnknownOutcome | ActionState::Skipped)
                })
            });
            if bad && a.state == ActionState::Pending {
                a.state = ActionState::Skipped;
            }
        }
        if !local.is_empty() && v.finished() && !v.terminal() {
            let any = |s: ActionState| v.actions.iter().any(|a| a.state == s);
            v.status = if any(ActionState::Failed) { "failed" } else { "interrupted" }.to_owned();
        }
        v
    }

    /// Statut terminal (12 §7.1).
    #[must_use]
    pub fn terminal(&self) -> bool {
        matches!(self.status.as_str(), "done" | "failed" | "interrupted" | "rejected" | "stopped" | "expired")
    }
}

/// Graphe d'un plan en cours, depuis le clair déchiffré (`CK`) et ce que l'API sert : l'exécutant
/// servi doit être plausible pour le `kind` (12 §4) et l'`after` servi égal à celui du plan (règle 8,
/// même contrôle que l'appareil). `None` : incohérent (`tool_call_unverified`).
#[must_use]
pub fn graph_from(plan: &Value, view: &PlanView) -> Option<PlanGraph> {
    let actions = plan.get("actions")?.as_array()?;
    if actions.len() != view.actions.len() {
        return None;
    }
    let mut graph = Vec::new();
    for (a, served) in actions.iter().zip(&view.actions) {
        let n = a.get("n")?.as_u64()?;
        let kind = ActionKind::parse(a.get("kind")?.as_str()?).ok()?;
        let plausible = match kind {
            ActionKind::ServerCall => served.executor == Executor::Agent,
            ActionKind::ThreadCreate => true,
            _ => served.executor == Executor::Device,
        };
        let mut after: Vec<u64> = match a.get("after") {
            None => Vec::new(),
            Some(l) => l.as_array()?.iter().map(Value::as_u64).collect::<Option<Vec<_>>>()?,
        };
        after.sort_unstable();
        let mut served_after = served.after.clone();
        served_after.sort_unstable();
        if !plausible || served.n != n || after != served_after {
            return None;
        }
        graph.push(GraphAction { n, executor: served.executor, after });
    }
    PlanGraph::new(graph).ok()
}

/// Action `n` du clair du plan.
#[must_use]
pub fn plan_action(plan: &Value, n: u64) -> Option<&Map<String, Value>> {
    plan.get("actions")?
        .as_array()?
        .iter()
        .filter_map(Value::as_object)
        .find(|a| a.get("n").and_then(Value::as_u64) == Some(n))
}

/// Résout `argsRefs` (12 §8.3, §8.4) : chaque valeur vient d'une sortie **authentifiée** (résultats de
/// phase déchiffrés sous `CK`) et doit **égaler** la sortie enregistrée par l'API ; la cible doit être
/// `done`. `Err` : résultat incohérent, l'action ne part pas.
pub fn resolve_refs(
    args_refs: &Map<String, Value>,
    authenticated: &BTreeMap<u64, Map<String, Value>>,
    view: &PlanView,
) -> Result<Map<String, Value>, &'static str> {
    let mut refs = Map::new();
    for (field, target) in args_refs {
        let (m, export) = target.as_str().and_then(parse_arg_ref).ok_or("refs_invalid")?;
        let source = view.action(m).ok_or("refs_invalid")?;
        let own = authenticated.get(&m).and_then(|o| o.get(export)).and_then(Value::as_str);
        let served = source.output.as_ref().and_then(|o| o.get(export)).and_then(Value::as_str);
        match (own, served) {
            (Some(a), Some(b)) if a == b && source.state == ActionState::Done => {
                refs.insert(field.clone(), Value::String(a.to_owned()));
            }
            _ => return Err("refs_inconsistent"),
        }
    }
    Ok(refs)
}

/// Bilan rendu au modèle à la fermeture de `propose_actions` (12 §8.3) : état et sortie de chaque
/// action, dans l'ordre de `n`. Jamais d'argument : seulement des états, des identifiants et des codes.
#[must_use]
pub fn bilan(
    plan_id: &str,
    view: &PlanView,
    outputs: &BTreeMap<u64, Map<String, Value>>,
    codes: &BTreeMap<u64, String>,
) -> Value {
    let actions: Vec<Value> = view
        .actions
        .iter()
        .map(|a| {
            let mut o = json!({ "n": a.n, "state": a.state.as_str() });
            if let Some(out) = outputs.get(&a.n) {
                crate::json_set(&mut o, "output", Value::Object(out.clone()));
            }
            if let Some(code) = codes.get(&a.n) {
                crate::json_set(&mut o, "code", json!(code));
            }
            o
        })
        .collect();
    let mut v = json!({ "planId": plan_id, "status": view.status, "actions": actions });
    match view.status.as_str() {
        "stopped" => crate::json_set(&mut v, "stopped", json!(true)),
        "expired" => crate::json_set(&mut v, "expired", json!(true)),
        _ => {}
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_exacte() {
        let d = tool_def();
        assert_eq!(d.name, "propose_actions");
        assert!(d.description.starts_with("Propose un plan d'actions que l'utilisateur validera."));
        assert!(d.description.ends_with("Tu as droit à 3 plans consécutifs par tour."));
    }

    #[test]
    fn issues_locales_et_dependantes() {
        let view = PlanView::parse(&json!({ "status": "executing", "actions": [
            { "n": 1, "executor": "agent", "after": [], "ready": true, "state": "pending", "output": null },
            { "n": 2, "executor": "agent", "after": [1], "ready": false, "state": "pending", "output": null },
            { "n": 3, "executor": "agent", "after": [], "ready": false, "state": "done", "output": null } ] }))
        .unwrap();
        let local = BTreeMap::from([(1, ActionState::Failed)]);
        let v = view.with_local(&local);
        let states: Vec<&str> = v.actions.iter().map(|a| a.state.as_str()).collect();
        assert_eq!(states, ["failed", "skipped", "done"], "PC54 : seules les dépendantes transitives");
        assert!(v.finished() && v.terminal() && v.status == "failed");
        assert!(!view.finished(), "la vue de l'API n'est pas modifiée");
    }

    #[test]
    fn references_comparees_a_l_api() {
        let view = PlanView::parse(&json!({ "status": "executing", "actions": [
            { "n": 1, "executor": "device", "after": [], "ready": false, "state": "done", "output": { "id": "cm1" } },
            { "n": 2, "executor": "agent", "after": [1], "ready": true, "state": "pending", "output": null } ] }))
        .unwrap();
        let refs = json!({ "categoryId": "$1.id" });
        let refs = refs.as_object().unwrap();
        let own = BTreeMap::from([(1, json!({ "id": "cm1" }).as_object().unwrap().clone())]);
        assert_eq!(resolve_refs(refs, &own, &view).unwrap()["categoryId"], "cm1");
        let forged = BTreeMap::from([(1, json!({ "id": "cm2" }).as_object().unwrap().clone())]);
        assert_eq!(
            resolve_refs(refs, &forged, &view),
            Err("refs_inconsistent"),
            "API et résultat authentifié diffèrent"
        );
        assert_eq!(resolve_refs(refs, &BTreeMap::new(), &view), Err("refs_inconsistent"), "rien d'authentifié");
    }
}
