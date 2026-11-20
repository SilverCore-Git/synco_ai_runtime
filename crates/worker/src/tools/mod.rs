//! Outils de l'agent : manifeste de l'API (source unique, `GET …/conversations/:sessionId/tools`,
//! même contenu que `GET /api/orgs/:orgId/ai/tools`), politique D5, exécution.
//!
//! | Catégorie | Exécution |
//! |---|---|
//! | `server` | par l'API au nom de l'utilisateur : `POST …/tools/:name/execute { leaseEpoch, args }` (04 §5) |
//! | `client` E2EE | **dans le worker** avec les clés déléguées : `create_thread` ([`threads`]), `search_messages` ([`search`], repli lexical) |
//! | `client` hors d'atteinte | `create_file`, `create_folder`, documentation : résultat d'erreur explicite ([`unavailable`]) et retirés de la liste donnée au modèle |
//! | interactif | `ask_question`, `request_image_upload` : `awaiting_user` (boucle d'agent) |

pub mod search;
pub mod threads;

use std::collections::BTreeMap;

use runtime_protocol::pipe::{HttpMethod, ToolPolicy};
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
}

/// Outils `client` que le worker ne peut pas exécuter dans son bac à sable (pas de réseau hors du
/// mandataire LLM, pas de fichier) : retirés de la liste donnée au modèle, refus explicite s'il les
/// appelle quand même.
///
/// - `create_file` : l'envoi chiffré part vers le CDN (`cdnUrl` + ticket), injoignable du worker ;
/// - `create_folder` : aucune route du canal (04 §4.3) ;
/// - `list_documentation`, `read_documentation`, `search_documentation` : la documentation est
///   embarquée dans `synco_app` (`doc/`), absente du runtime.
pub const UNAVAILABLE_IN_RUNTIME: [&str; 5] =
    ["create_file", "create_folder", "list_documentation", "read_documentation", "search_documentation"];

/// Outils `client` exécutés par le worker.
pub const WORKER_CLIENT_TOOLS: [&str; 2] = ["create_thread", "search_messages"];

/// Lit le manifeste (entrées mal formées ignorées).
#[must_use]
pub fn parse_manifest(v: &Value) -> Vec<ToolSpec> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|t| {
                    let name = t.get("name")?.as_str()?.to_owned();
                    if !runtime_protocol::ids::is_identifier(&name) {
                        return None;
                    }
                    Some(ToolSpec {
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

/// Outils proposés au modèle : ceux que le worker sait exécuter, sauf ceux que la politique de l'org
/// interdit (le modèle ne les voit pas ; s'il les appelle quand même, refus `tool_denied_by_policy`).
#[must_use]
pub fn llm_tools(specs: &[ToolSpec], policy: &BTreeMap<String, ToolPolicy>) -> Vec<ToolDef> {
    specs
        .iter()
        .filter(|s| executable(s) && policy.get(&s.name) != Some(&ToolPolicy::Deny))
        .map(|s| ToolDef { name: s.name.clone(), description: s.description.clone(), parameters: s.parameters.clone() })
        .collect()
}

fn executable(s: &ToolSpec) -> bool {
    s.category == "server" || s.interactive || WORKER_CLIENT_TOOLS.contains(&s.name.as_str())
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
/// `auto` pour les autres (défaut par niveau de risque, D5 ; L14 affinera).
#[must_use]
pub fn decide(spec: Option<&ToolSpec>, policy: &BTreeMap<String, ToolPolicy>) -> Decision {
    let Some(spec) = spec else { return Decision::Unknown };
    match policy.get(&spec.name) {
        Some(ToolPolicy::Deny) => Decision::Deny,
        _ if spec.interactive => Decision::AwaitUser,
        Some(ToolPolicy::Auto) => Decision::Auto,
        Some(ToolPolicy::Ask) => Decision::AskConfirmation,
        None if spec.mutating => Decision::AskConfirmation,
        None => Decision::Auto,
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
}

/// Exécute un outil accepté (politique déjà appliquée).
pub async fn execute(ctx: &ToolCtx<'_>, spec: &ToolSpec, args: &Value) -> Outcome {
    if spec.category == "server" {
        return execute_server(ctx, &spec.name, args).await;
    }
    match spec.name.as_str() {
        "search_messages" => search::run(ctx, args).await,
        "create_thread" => threads::run(ctx, args).await,
        name => unavailable(name),
    }
}

async fn execute_server(ctx: &ToolCtx<'_>, name: &str, args: &Value) -> Outcome {
    let body = json!({ "leaseEpoch": ctx.lease_epoch, "args": args });
    let Ok(r) = ctx.api.conv(HttpMethod::Post, &format!("/tools/{name}/execute"), Some(&body)).await else {
        return error("tool_failed");
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
        let names: Vec<_> = llm_tools(&specs, &policy).into_iter().map(|t| t.name).collect();
        assert_eq!(names, ["create_task", "ask_question", "search_messages"]);
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
}
