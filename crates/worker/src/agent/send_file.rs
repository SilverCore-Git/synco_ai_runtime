//! Outil `send_file` dans la boucle d'agent (lot L08e, docs/plan/13 §2.3 à §2.5, §5.1, §6.1) :
//! validation, chiffrement sous `CK`, dépôt `POST …/artifacts` (un nouvel essai, même `id`), trame
//! `artifact`, puis clôture de l'appel avec la **forme réduite** des arguments (le contenu n'entre
//! jamais dans l'historique). Aucun contenu, aucun nom n'est journalisé.

use std::time::Duration;

use runtime_protocol::pipe::{HttpMethod, ToolPolicy};
use serde_json::{Value, json};
use synco_e2ee::OsRandom;

use super::{Agent, Flow, Stop, uuid};
use crate::api::ApiResponse;
use crate::artifact::{self, Binding, File, MAX_PER_TURN, SEND_FILE};
use crate::link::LinkError;
use crate::transcript::{Role, ToolCall, ToolStatus};

/// Plafond du `Retry-After` honoré avant le nouvel essai (secondes).
const MAX_RETRY_WAIT_SECS: u64 = 10;

/// Issue d'un essai de dépôt.
enum Try {
    /// `201` ou `200` (rejeu identique).
    Stored,
    /// `409 artifact_quota`.
    Quota,
    /// `413 artifact_too_large`.
    TooLarge,
    /// Refus définitif (forme, `artifact_exists`, régime).
    Refused,
    /// Panne passagère : transport, `429`, `5xx`.
    Retry(Option<u64>),
}

fn classify(r: &Result<ApiResponse, LinkError>) -> Result<Try, Stop> {
    let r = match r {
        Err(LinkError::Closed) => return Err(Stop::Pipe),
        Err(LinkError::Timeout) => return Ok(Try::Retry(None)),
        Ok(r) => r,
    };
    if r.ok() {
        return Ok(Try::Stored);
    }
    match (r.status, r.code()) {
        (_, Some("artifact_quota")) => Ok(Try::Quota),
        (413, _) | (_, Some("artifact_too_large")) => Ok(Try::TooLarge),
        (_, Some("lease_conflict")) => Err(Stop::LeaseLost),
        (
            _,
            Some(
                "auth_revoked" | "auth_expired" | "auth_invalid" | "out_of_scope" | "delegation_expired"
                | "delegation_revoked",
            ),
        ) => Err(Stop::LeaseLost),
        (0 | 429 | 500..=599, _) => Ok(Try::Retry(r.retry_after)),
        _ => Ok(Try::Refused),
    }
}

impl Agent {
    /// Artefacts **déposés** dans le tour en cours : appels `send_file` réussis après le dernier
    /// message de l'utilisateur (relu de l'historique, donc stable après une reprise).
    fn files_in_turn(&self) -> usize {
        self.messages
            .iter()
            .rev()
            .take_while(|m| m.role != Role::User)
            .flat_map(|m| m.tool_calls.iter())
            .filter(|tc| tc.name == SEND_FILE && tc.status == ToolStatus::Done)
            .count()
    }

    /// Ferme un appel `send_file` qui n'a rien déposé : arguments réduits à `name` et `ext`, statut,
    /// résultat `{"error":"<code>"}` ; le tour continue.
    async fn refuse_file(&mut self, tc: &ToolCall, status: ToolStatus, result: Value) -> Result<Flow, Stop> {
        if let Some(t) = self.find_call_mut(&tc.id) {
            t.arguments = artifact::refused_args(&tc.arguments);
        }
        self.close_call(&tc.id, &tc.name, status, result).await?;
        self.persist("running", None).await?;
        Ok(Flow::Continue)
    }

    /// Un ou deux essais du dépôt (même corps, donc même `id` : idempotent).
    async fn deposit_file(&mut self, body: &Value) -> Result<Try, Stop> {
        let mut last = Try::Refused;
        for attempt in 0..2 {
            let r = self.api.conv(HttpMethod::Post, "/artifacts", Some(body)).await;
            match classify(&r)? {
                Try::Retry(wait) => {
                    if let (0, Some(s)) = (attempt, wait) {
                        tokio::time::sleep(Duration::from_secs(s.min(MAX_RETRY_WAIT_SECS))).await;
                    }
                    last = Try::Retry(wait);
                }
                done => return Ok(done),
            }
        }
        Ok(last)
    }

    /// Appel `send_file` du modèle (dans `messages[idx]`).
    pub(super) async fn send_file(&mut self, idx: usize, tc: ToolCall) -> Result<Flow, Stop> {
        if self.init.tool_policy.get(SEND_FILE) == Some(&ToolPolicy::Deny) {
            return self.refuse_file(&tc, ToolStatus::Rejected, json!({ "error": "tool_denied_by_policy" })).await;
        }
        let file: File = match artifact::validate(&tc.arguments) {
            Ok(f) => f,
            Err(r) => return self.refuse_file(&tc, ToolStatus::Error, artifact::error_result(r.code())).await,
        };
        // Le tour compte les artefacts déjà déposés ; l'appel en cours n'est pas `done`.
        if self.files_in_turn() >= MAX_PER_TURN {
            return self.refuse_file(&tc, ToolStatus::Error, artifact::error_result("artifact_turn_limit")).await;
        }
        let message_id = self.messages.get(idx).map(|m| m.id.clone()).unwrap_or_default();
        let artifact_id = uuid();
        let binding = Binding {
            session_id: &self.init.session_id,
            message_id: &message_id,
            tool_call_id: &tc.id,
            artifact_id: &artifact_id,
        };
        let Ok(sealed) = artifact::seal(&self.ck, &binding, &file, &mut OsRandom) else {
            return self.refuse_file(&tc, ToolStatus::Error, artifact::error_result("artifact_not_sent")).await;
        };
        let body = artifact::deposit_body(self.init.lease_epoch, &artifact_id, &sealed);
        let code = match self.deposit_file(&body).await? {
            Try::Stored => None,
            Try::Quota => Some("artifact_quota"),
            Try::TooLarge => Some("artifact_too_large"),
            Try::Refused | Try::Retry(_) => Some("artifact_not_sent"),
        };
        if let Some(code) = code {
            return self.refuse_file(&tc, ToolStatus::Error, artifact::error_result(code)).await;
        }
        // L'artefact est lisible : trame (identifiants seulement), puis appel clos sans le contenu.
        self.em.artifact(&message_id, &tc.id, &artifact_id).await?;
        if let Some(t) = self.find_call_mut(&tc.id) {
            t.arguments = artifact::reduced_args(&artifact_id, &file);
        }
        self.close_call(&tc.id, &tc.name, ToolStatus::Done, artifact::success_result(&artifact_id, &file)).await?;
        self.persist("running", None).await?;
        Ok(Flow::Continue)
    }
}
