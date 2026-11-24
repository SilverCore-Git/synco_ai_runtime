//! Outils de l'agent : manifeste de l'API (source unique, `GET …/conversations/:sessionId/tools`,
//! même contenu que `GET /api/orgs/:orgId/ai/tools`), politique D5, exécution.
//!
//! | Catégorie | Exécution |
//! |---|---|
//! | `server` | par l'API au nom de l'utilisateur : `POST …/tools/:name/execute { leaseEpoch, args }` (04 §5) |
//! | `client` E2EE | **dans le worker** avec les clés déléguées : `create_thread` ([`threads`]), `search_messages` ([`search`], repli lexical) |
//! | `client` hors d'atteinte | `create_file`, `create_folder`, documentation : résultat d'erreur explicite ([`unavailable`]) et retirés de la liste donnée au modèle |
//! | interactif | `ask_question`, `request_image_upload` : `awaiting_user` (boucle d'agent) |

pub mod agenda;
pub mod agent;
pub mod files;
pub mod members;
pub mod messages;
pub mod notifications;
pub mod reports;
pub mod search;
pub mod spaces;
pub mod support;
pub mod tasks;
pub mod threads;
pub mod web;

use std::collections::BTreeMap;

use runtime_protocol::pipe::{HttpMethod, PlanMode, ToolPolicy};
use serde_json::{Value, json};

use crate::api::Api;
use crate::provider::ToolDef;

/// Outil du manifeste.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolSpec {
    /// Nom.
    pub name: String,
    /// Description.
    pub description: String,
    /// `server` ou `client`.
    pub category: String,
    /// Mutant.
    pub mutating: bool,
    /// Interactif.
    pub interactive: bool,
    /// JSON Schema.
    pub parameters: Value,
    /// Domaine du catalogue (L14 §1.5), absent d'un ancien manifeste.
    pub domain: Option<String>,
    /// Niveau de risque `R0`…`RP`, absent d'un ancien manifeste.
    pub risk: Option<String>,
    /// `sensitive` du manifeste (R3, R4, RP), recalculé aussi depuis `risk` : jamais `auto`.
    pub sensitive: bool,
    /// Politique par défaut du manifeste (`auto`, `ask`, `interactive`).
    pub default_policy: Option<String>,
    /// `yes` ou `device_only` ; absent d'un ancien manifeste (liste historique [`UNAVAILABLE_IN_RUNTIME`]).
    pub runtime: Option<String>,
}

/// Outils `client` que le worker ne peut pas exécuter dans son bac à sable (pas de réseau hors du
/// mandataire LLM, pas de fichier) : retirés de la liste donnée au modèle, refus explicite s'il les
/// appelle quand même.
///
/// Liste **historique**, lue seulement quand le manifeste n'a pas le champ `runtime` (L15-0 : le manifeste
/// de l'API fait foi, `runtime: "device_only"`).
///
/// - `create_file` : l'envoi chiffré part vers le CDN (`cdnUrl` + ticket), injoignable du worker ;
/// - `create_folder` : aucune route du canal (04 §4.3) ;
/// - `list_documentation`, `read_documentation`, `search_documentation` : la documentation est
///   embarquée dans `synco_app` (`doc/`), absente du runtime.
pub const UNAVAILABLE_IN_RUNTIME: [&str; 5] =
    ["create_file", "create_folder", "list_documentation", "read_documentation", "search_documentation"];

/// Outils `client` exécutés par le worker.
pub const WORKER_CLIENT_TOOLS: [&str; 2] = ["create_thread", "search_messages"];

/// Lit le manifeste (entrées mal formées ignorées) : tableau (ancien format) ou `{ version, tools }`.
#[must_use]
pub fn parse_manifest(v: &Value) -> Vec<ToolSpec> {
    v.as_array()
        .or_else(|| v.get("tools").and_then(Value::as_array))
        .map(|a| {
            a.iter()
                .filter_map(|t| {
                    let name = t.get("name")?.as_str()?.to_owned();
                    if !runtime_protocol::ids::is_identifier(&name) {
                        return None;
                    }
                    let text = |k: &str| t.get(k).and_then(Value::as_str).map(str::to_owned);
                    let risk = text("risk");
                    let sensitive = t.get("sensitive").and_then(Value::as_bool).unwrap_or(false)
                        || risk.as_deref().is_some_and(|r| matches!(r, "R3" | "R4" | "RP"));
                    Some(ToolSpec {
                        domain: text("domain"),
                        sensitive,
                        risk,
                        default_policy: text("defaultPolicy"),
                        runtime: text("runtime"),
                        name,
                        description: t.get("description").and_then(Value::as_str).unwrap_or_default().to_owned(),
                        category: t.get("category").and_then(Value::as_str).unwrap_or("server").to_owned(),
                        mutating: t.get("mutating").and_then(Value::as_bool).unwrap_or(true),
                        interactive: t.get("interactive").and_then(Value::as_bool).unwrap_or(false),
                        parameters: t.get("parameters").cloned().unwrap_or_else(|| json!({ "type": "object" })),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Outils d'appareil (12 §2) : l'app les exécute avec ses clés, jamais le modèle directement.
pub const DEVICE_TOOLS: [&str; 3] = ["create_thread", "create_folder", "create_file"];

/// Politique effective d'un outil (12 §2) : celle de l'org si elle est donnée, sinon `ask` pour un
/// outil mutant et `auto` pour les autres.
///
/// Un outil sensible n'est jamais `auto` (PC86), même si une politique enregistrée le dit ; un geste
/// personnel (`default_policy: "auto"`, PC89) est `auto` par défaut bien que mutant.
#[must_use]
pub fn effective_policy(spec: &ToolSpec, policy: &BTreeMap<String, ToolPolicy>) -> ToolPolicy {
    match policy.get(&spec.name).copied() {
        Some(ToolPolicy::Auto) if spec.sensitive => ToolPolicy::Ask,
        Some(p) => p,
        None if spec.sensitive => ToolPolicy::Ask,
        None if spec.default_policy.as_deref() == Some("auto") => ToolPolicy::Auto,
        None if spec.mutating => ToolPolicy::Ask,
        None => ToolPolicy::Auto,
    }
}

/// Outils proposés au modèle : ceux que le worker sait exécuter, sauf ceux que la politique de l'org
/// interdit (le modèle ne les voit pas ; s'il les appelle quand même, refus `tool_denied_by_policy`).
///
/// `plan` (12 §2) : sous un plan d'action, le modèle ne voit plus aucun outil mutant dont la politique
/// effective est `ask`, ni aucun outil d'appareil (`create_thread`, `create_folder`, `create_file`) —
/// sauf `create_thread` en mode autonome quand sa politique effective n'est pas `ask` — et reçoit à
/// la place `propose_actions` ([`crate::plan::tool_def`]).
#[must_use]
pub fn llm_tools(specs: &[ToolSpec], policy: &BTreeMap<String, ToolPolicy>, plan: Option<PlanMode>) -> Vec<ToolDef> {
    let hidden_by_plan = |s: &ToolSpec| {
        let Some(mode) = plan else { return false };
        let ask = effective_policy(s, policy) == ToolPolicy::Ask;
        let device = DEVICE_TOOLS.contains(&s.name.as_str());
        (device && (mode == PlanMode::Plan || ask)) || (!s.interactive && s.mutating && ask)
    };
    let mut out: Vec<ToolDef> = specs
        .iter()
        .filter(|s| executable(s) && policy.get(&s.name) != Some(&ToolPolicy::Deny) && !hidden_by_plan(s))
        .map(|s| ToolDef { name: s.name.clone(), description: s.description.clone(), parameters: s.parameters.clone() })
        .collect();
    // `send_file` (13 §2.5) : propre au worker, hors plan ; `deny` seul le retire.
    if policy.get(crate::artifact::SEND_FILE) != Some(&ToolPolicy::Deny) {
        out.push(crate::artifact::tool_def());
    }
    if plan.is_some() {
        out.push(crate::plan::tool_def());
    }
    out
}

/// Outils `client` des modules de domaine (`tools/<domaine>.rs`).
fn domain_handles(name: &str) -> bool {
    [
        tasks::HANDLED.as_slice(),
        agenda::HANDLED.as_slice(),
        spaces::HANDLED.as_slice(),
        messages::HANDLED.as_slice(),
        files::HANDLED.as_slice(),
        members::HANDLED.as_slice(),
        notifications::HANDLED.as_slice(),
        reports::HANDLED.as_slice(),
        support::HANDLED.as_slice(),
        web::HANDLED.as_slice(),
        agent::HANDLED.as_slice(),
    ]
    .iter()
    .any(|names| names.contains(&name))
}

fn worker_runs_client_tool(name: &str) -> bool {
    WORKER_CLIENT_TOOLS.contains(&name) || domain_handles(name)
}

/// Le worker peut-il exécuter l'outil ? Le champ `runtime` du manifeste fait foi ; sans lui (ancien
/// manifeste), la liste historique [`UNAVAILABLE_IN_RUNTIME`] reste lue.
fn executable(s: &ToolSpec) -> bool {
    if s.category == "server" || s.interactive {
        return true;
    }
    match s.runtime.as_deref() {
        Some("device_only") => false,
        Some(_) => worker_runs_client_tool(&s.name),
        None => worker_runs_client_tool(&s.name) && !UNAVAILABLE_IN_RUNTIME.contains(&s.name.as_str()),
    }
}

/// Décision avant exécution (D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Outil absent du manifeste.
    Unknown,
    /// `deny` : jamais exécuté, résultat `tool_denied_by_policy`.
    Deny,
    /// Outil interactif : `awaiting_user`.
    AwaitUser,
    /// `ask` (défaut des outils mutants) : `awaiting_confirmation`.
    AskConfirmation,
    /// Exécution immédiate.
    Auto,
}

/// Politique d'un outil : celle de l'org si elle est donnée, sinon `ask` pour un outil mutant et
/// `auto` pour les autres (défaut par niveau de risque, D5), selon [`effective_policy`].
#[must_use]
pub fn decide(spec: Option<&ToolSpec>, policy: &BTreeMap<String, ToolPolicy>) -> Decision {
    let Some(spec) = spec else { return Decision::Unknown };
    if policy.get(&spec.name) == Some(&ToolPolicy::Deny) {
        return Decision::Deny;
    }
    if spec.interactive {
        return Decision::AwaitUser;
    }
    match effective_policy(spec, policy) {
        ToolPolicy::Ask => Decision::AskConfirmation,
        _ => Decision::Auto,
    }
}

/// Issue d'une exécution.
#[derive(Clone, PartialEq)]
pub enum Outcome {
    /// Résultat donné au modèle.
    Done(Value),
    /// Résultat d'erreur donné au modèle (`{"error": …}`).
    Failed(Value),
    /// Clé de l'org absente de la délégation (03 §11).
    NeedKey {
        /// `thread` ou `space`.
        kind: &'static str,
        /// Identifiant.
        reference: String,
    },
    /// Le bail n'est plus à ce worker : il doit s'arrêter sans rien écrire.
    LeaseLost,
}

impl core::fmt::Debug for Outcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Done(_) => "Done(…)",
            Self::Failed(_) => "Failed(…)",
            Self::NeedKey { .. } => "NeedKey",
            Self::LeaseLost => "LeaseLost",
        })
    }
}

/// Résultat d'erreur `{"error": code}`.
#[must_use]
pub fn error(code: &str) -> Outcome {
    Outcome::Failed(json!({ "error": code }))
}

/// Refus explicite d'un outil hors d'atteinte du runtime.
#[must_use]
pub fn unavailable(name: &str) -> Outcome {
    Outcome::Failed(json!({
        "error": "tool_unavailable_in_runtime",
        "tool": name,
        "note": "Cet outil n'est pas disponible quand la conversation s'exécute sur le runtime Synco AI. Propose à l'utilisateur de le faire depuis Synco.",
    }))
}

/// Contexte d'exécution.
#[derive(Debug)]
pub struct ToolCtx<'a> {
    /// Client de l'API.
    pub api: &'a Api,
    /// Bail courant.
    pub lease_epoch: u64,
    /// Propriétaire de la conversation.
    pub user_id: &'a str,
    /// Action de plan exécutée par cet appel (`plan: { planId, n }` du verrou, 12 §8.4).
    pub plan: Option<(&'a str, u64)>,
}

/// Exécute un outil accepté (politique déjà appliquée).
pub async fn execute(ctx: &ToolCtx<'_>, spec: &ToolSpec, args: &Value) -> Outcome {
    if spec.category == "server" {
        return execute_server(ctx, &spec.name, spec.mutating, args).await;
    }
    match spec.name.as_str() {
        "search_messages" => search::run(ctx, args).await,
        "create_thread" => threads::run(ctx, args).await,
        name => run_domain(ctx, name, args).await,
    }
}

/// Délègue aux modules de domaine ; un nom qu'aucun ne reconnaît est refusé.
async fn run_domain(ctx: &ToolCtx<'_>, name: &str, args: &Value) -> Outcome {
    if let Some(o) = tasks::run(ctx, name, args).await {
        return o;
    }
    if let Some(o) = agenda::run(ctx, name, args).await {
        return o;
    }
    if let Some(o) = spaces::run(ctx, name, args).await {
        return o;
    }
    if let Some(o) = messages::run(ctx, name, args).await {
        return o;
    }
    if let Some(o) = files::run(ctx, name, args).await {
        return o;
    }
    if let Some(o) = members::run(ctx, name, args).await {
        return o;
    }
    if let Some(o) = notifications::run(ctx, name, args).await {
        return o;
    }
    if let Some(o) = reports::run(ctx, name, args).await {
        return o;
    }
    if let Some(o) = support::run(ctx, name, args).await {
        return o;
    }
    if let Some(o) = web::run(ctx, name, args).await {
        return o;
    }
    agent::run(ctx, name, args).await.unwrap_or_else(|| unavailable(name))
}

/// Résultat d'un outil dont l'issue est inconnue (08 §5, texte exact de la spec).
pub const UNKNOWN_OUTCOME_NOTE: &str =
    "L'exécution de cet outil a été interrompue : son résultat est inconnu. Vérifie l'état avant de réessayer.";

/// `{"error":"unknown_outcome","note":…}`.
#[must_use]
pub fn unknown_outcome() -> Outcome {
    Outcome::Failed(json!({ "error": "unknown_outcome", "note": UNKNOWN_OUTCOME_NOTE }))
}

/// Ce qu'on sait d'une requête d'action après coup.
#[derive(Debug)]
pub(crate) enum Sent {
    /// Réponse de l'API (succès ou erreur explicite).
    Answered(crate::api::ApiResponse),
    /// Refus **local** du relais, avant tout envoi à l'API (`relay_busy`, `relay_rate_limited`,
    /// `relay_refused`, `relay_bad_part`) : l'action n'a pas eu lieu.
    LocallyRefused,
    /// Envoyée, sans réponse exploitable (délai, pipe fermé, `relay_network`, réponse illisible ou
    /// trop grande, `5xx`) : l'action a pu avoir lieu.
    Unknown,
}

pub(crate) fn sent(r: Result<crate::api::ApiResponse, crate::link::LinkError>) -> Sent {
    match r {
        Err(_) => Sent::Unknown,
        Ok(r) if r.status == 0 => match r.relay_error.as_deref() {
            Some("relay_busy" | "relay_rate_limited" | "relay_refused" | "relay_bad_part") => Sent::LocallyRefused,
            _ => Sent::Unknown,
        },
        Ok(r) if r.status >= 500 => Sent::Unknown,
        Ok(r) => Sent::Answered(r),
    }
}

/// Échec d'une action envoyée : issue inconnue pour un outil mutant (l'action a pu avoir lieu),
/// simple échec sinon.
#[must_use]
pub fn transport_failure(mutating: bool) -> Outcome {
    if mutating { unknown_outcome() } else { error("tool_failed") }
}

async fn execute_server(ctx: &ToolCtx<'_>, name: &str, mutating: bool, args: &Value) -> Outcome {
    let body = json!({ "leaseEpoch": ctx.lease_epoch, "args": args });
    let r = match sent(ctx.api.conv(HttpMethod::Post, &format!("/tools/{name}/execute"), Some(&body)).await) {
        Sent::Answered(r) => r,
        Sent::LocallyRefused => return error("tool_failed"),
        Sent::Unknown => return transport_failure(mutating),
    };
    if r.ok() {
        return match r.body.get("ok").and_then(Value::as_bool) {
            Some(true) => Outcome::Done(r.body.get("data").cloned().unwrap_or(Value::Null)),
            _ => Outcome::Failed(json!({
                "error": r.body.get("message").and_then(Value::as_str).unwrap_or("tool_failed"),
                "status": r.body.get("status").cloned().unwrap_or(Value::Null),
            })),
        };
    }
    match r.code() {
        Some("lease_conflict") => Outcome::LeaseLost,
        Some(code) => error(code),
        None => error("tool_failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifeste_et_politique() {
        let specs = parse_manifest(&json!([
            { "name": "create_task", "description": "d", "category": "server", "mutating": true, "interactive": false, "parameters": {} },
            { "name": "list_spaces", "category": "server", "mutating": false },
            { "name": "ask_question", "category": "client", "mutating": false, "interactive": true },
            { "name": "create_file", "category": "client", "mutating": true },
            { "name": "search_messages", "category": "client", "mutating": false },
            { "name": "a|b", "category": "server" },
        ]));
        assert_eq!(specs.len(), 5);
        let policy = BTreeMap::from([("list_spaces".to_owned(), ToolPolicy::Deny)]);
        let names: Vec<_> = llm_tools(&specs, &policy, None).into_iter().map(|t| t.name).collect();
        assert_eq!(names, ["create_task", "ask_question", "search_messages", "send_file"]);
        // Plan d'action : les outils mutants `ask` et ceux d'appareil disparaissent, `propose_actions`
        // arrive ; `deny` n'est jamais proposé.
        let plan =
            |mode| -> Vec<String> { llm_tools(&specs, &policy, Some(mode)).into_iter().map(|t| t.name).collect() };
        assert_eq!(plan(PlanMode::Plan), ["ask_question", "search_messages", "send_file", "propose_actions"]);
        assert_eq!(plan(PlanMode::Auto), ["ask_question", "search_messages", "send_file", "propose_actions"]);
        let get = |n: &str| specs.iter().find(|s| s.name == n);
        assert_eq!(decide(get("create_task"), &BTreeMap::new()), Decision::AskConfirmation);
        assert_eq!(
            decide(get("create_task"), &BTreeMap::from([("create_task".into(), ToolPolicy::Auto)])),
            Decision::Auto
        );
        assert_eq!(decide(get("list_spaces"), &policy), Decision::Deny);
        assert_eq!(decide(get("ask_question"), &BTreeMap::new()), Decision::AwaitUser);
        assert_eq!(
            decide(get("ask_question"), &BTreeMap::from([("ask_question".into(), ToolPolicy::Deny)])),
            Decision::Deny
        );
        assert_eq!(decide(get("search_messages"), &BTreeMap::new()), Decision::Auto);
        assert_eq!(decide(None, &BTreeMap::new()), Decision::Unknown);
    }

    #[test]
    fn manifeste_versionne_runtime_et_sensibles() {
        let specs = parse_manifest(&json!({ "version": "abc", "tools": [
            { "name": "create_file", "category": "client", "mutating": true, "runtime": "device_only" },
            { "name": "search_messages", "category": "client", "mutating": false, "runtime": "yes" },
            { "name": "inconnu_yes", "category": "client", "mutating": false, "runtime": "yes" },
            { "name": "create_thread", "category": "client", "mutating": true },
            { "name": "delete_task", "category": "server", "mutating": true, "risk": "R3", "defaultPolicy": "ask" },
            { "name": "mark_read", "category": "server", "mutating": true, "risk": "R2p", "defaultPolicy": "auto" },
            { "name": "leak", "category": "server", "mutating": true, "sensitive": true, "defaultPolicy": "auto" },
        ] }));
        assert_eq!(specs.len(), 7);
        let policy = BTreeMap::new();
        let names: Vec<_> = llm_tools(&specs, &policy, None).into_iter().map(|t| t.name).collect();
        // `device_only` retiré, `runtime: yes` sans exécutant retiré, champ absent : liste historique.
        assert_eq!(names, ["search_messages", "create_thread", "delete_task", "mark_read", "leak", "send_file"]);
        let get = |n: &str| specs.iter().find(|s| s.name == n);
        assert_eq!(decide(get("mark_read"), &policy), Decision::Auto);
        assert_eq!(decide(get("delete_task"), &policy), Decision::AskConfirmation);
        // PC86 : `auto` configuré ou déclaré par défaut sur un outil sensible retombe sur `ask`.
        let auto = |n: &str| BTreeMap::from([(n.to_owned(), ToolPolicy::Auto)]);
        assert_eq!(decide(get("delete_task"), &auto("delete_task")), Decision::AskConfirmation);
        assert_eq!(decide(get("leak"), &policy), Decision::AskConfirmation);
        assert_eq!(decide(get("leak"), &auto("leak")), Decision::AskConfirmation);
        assert_eq!(
            decide(get("delete_task"), &BTreeMap::from([("delete_task".to_owned(), ToolPolicy::Deny)])),
            Decision::Deny
        );
    }

    #[test]
    fn modules_de_domaine_vides_au_socle() {
        assert!(!domain_handles("create_task"));
        assert!(!worker_runs_client_tool("create_file"));
        assert!(worker_runs_client_tool("search_messages"));
    }
}
