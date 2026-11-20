//! Interface des **adaptateurs LLM** du worker (lot L07 ; Mistral et Gemini : L07b).
//!
//! Un adaptateur ne fait **aucune** entrée/sortie : il traduit une requête normalisée
//! ([`ChatRequest`]) en appel HTTP ([`HttpCall`]) et décode le flux de la réponse en évènements
//! normalisés ([`LlmEvent`]) au fil des octets reçus ([`StreamDecoder`]). Le transport est commun
//! ([`stream_completion`]) : le **mandataire LLM** du superviseur, par le socket Unix du bac à sable
//! (`crate::llm`, docs/plan/10 §4), qui ajoute lui-même la clé du fournisseur (D1) et n'admet que
//! `POST /chat/completions` (`/v1/chat/completions` pour la passerelle) et `GET /models`.
//!
//! Comportements attendus de tout adaptateur (mêmes que `synco_api/src/services/ai/providerAdapters/`) :
//!
//! - flux (`stream`) ; **un seul** appel d'outil traité par réponse (le premier) ;
//! - raisonnement : champ dédié du fournisseur s'il existe, sinon extraction `<think>`
//!   ([`think::ThinkTagSplitter`]) ;
//! - usage demandé dans le flux et rendu par [`LlmEvent::Usage`] ;
//! - fin : exactement un [`LlmEvent::Done`], après les appels d'outils ;
//! - aucune clé dans la requête (le mandataire l'ajoute) ; pour la passerelle, `authorization:
//!   Bearer sgt1…` est fourni par l'appelant ([`ChatRequest::bearer`]) ;
//! - erreurs typées ([`LlmError`]), jamais de texte du fournisseur (il peut recopier le contenu).

pub mod gemini;
pub mod mistral;
pub mod openai;
pub mod think;

use std::path::Path;
use std::time::Duration;

use runtime_protocol::pipe::{LlmProvider, ReasoningEffort};
use serde_json::Value;

use crate::llm::{self, LlmRequest};

/// Message normalisé envoyé au modèle.
#[derive(Clone, PartialEq, Eq)]
pub enum ChatMessage {
    /// Message de l'utilisateur.
    User {
        /// Texte.
        content: String,
    },
    /// Réponse du modèle (texte et/ou appels d'outils).
    Assistant {
        /// Texte.
        content: Option<String>,
        /// Appels d'outils.
        tool_calls: Vec<ChatToolCall>,
    },
    /// Résultat d'un outil.
    Tool {
        /// Appel auquel il répond.
        tool_call_id: String,
        /// Résultat (JSON sérialisé ou texte).
        content: String,
    },
}

impl core::fmt::Debug for ChatMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::User { .. } => "ChatMessage::User(…)",
            Self::Assistant { .. } => "ChatMessage::Assistant(…)",
            Self::Tool { .. } => "ChatMessage::Tool(…)",
        })
    }
}

/// Appel d'outil (demandé par le modèle ou rejoué dans l'historique).
#[derive(Clone, PartialEq, Eq)]
pub struct ChatToolCall {
    /// Identifiant (celui du fournisseur, ou un identifiant tiré par le worker s'il n'est pas conforme).
    pub id: String,
    /// Outil.
    pub name: String,
    /// Arguments : texte JSON tel que produit par le modèle.
    pub arguments: String,
}

impl core::fmt::Debug for ChatToolCall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChatToolCall").field("id", &self.id).field("name", &self.name).finish_non_exhaustive()
    }
}

/// Outil proposé au modèle (manifeste `GET …/tools`, `parameters` en JSON Schema).
#[derive(Debug, Clone, PartialEq)]
pub struct ToolDef {
    /// Nom.
    pub name: String,
    /// Description.
    pub description: String,
    /// JSON Schema des paramètres.
    pub parameters: Value,
}

/// Requête normalisée.
#[derive(Debug, Clone)]
pub struct ChatRequest {
    /// Modèle.
    pub model: String,
    /// Prompt système.
    pub system: String,
    /// Historique.
    pub messages: Vec<ChatMessage>,
    /// Outils.
    pub tools: Vec<ToolDef>,
    /// Effort de raisonnement de l'org.
    pub reasoning_effort: ReasoningEffort,
    /// Plafond de tokens de sortie (`maxOutputTokensPerCall`).
    pub max_output_tokens: u64,
    /// `authorization: Bearer <ticket sgt1>` (passerelle seulement).
    pub bearer: Option<String>,
}

/// Appel HTTP à faire par le mandataire.
#[derive(Clone)]
pub struct HttpCall {
    /// `POST` ou `GET`.
    pub method: &'static str,
    /// Chemin relatif à l'URL de base (`/chat/completions`, `/v1/chat/completions`).
    pub path: &'static str,
    /// En-têtes (jamais de clé de fournisseur).
    pub headers: Vec<(String, String)>,
    /// Corps.
    pub body: Vec<u8>,
}

impl core::fmt::Debug for HttpCall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HttpCall").field("method", &self.method).field("path", &self.path).finish_non_exhaustive()
    }
}

/// Usage d'un appel (`UsageInfo`, `types.ts:12-17`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    /// Tokens d'entrée.
    pub prompt_tokens: Option<u64>,
    /// Tokens de sortie.
    pub completion_tokens: Option<u64>,
    /// Total.
    pub total_tokens: Option<u64>,
    /// Tokens de raisonnement.
    pub reasoning_tokens: Option<u64>,
}

impl Usage {
    /// Total connu (`total`, sinon entrée + sortie).
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total_tokens
            .unwrap_or_else(|| self.prompt_tokens.unwrap_or(0).saturating_add(self.completion_tokens.unwrap_or(0)))
    }
}

/// Raison de fin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinishReason {
    /// Réponse complète.
    Stop,
    /// Appel d'outil.
    ToolCalls,
    /// Plafond de sortie atteint.
    Length,
    /// Autre valeur du fournisseur (code court).
    Other(String),
}

/// Évènement normalisé du flux.
#[derive(Clone, PartialEq, Eq)]
pub enum LlmEvent {
    /// Morceau de réponse.
    Text(String),
    /// Morceau de raisonnement.
    Thinking(String),
    /// Appel d'outil complet (arguments réassemblés).
    ToolCall(ChatToolCall),
    /// Usage.
    Usage(Usage),
    /// Fin (toujours le dernier évènement).
    Done(FinishReason),
}

impl core::fmt::Debug for LlmEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Text(t) => write!(f, "Text({} octets)", t.len()),
            Self::Thinking(t) => write!(f, "Thinking({} octets)", t.len()),
            Self::ToolCall(c) => write!(f, "{c:?}"),
            Self::Usage(u) => write!(f, "{u:?}"),
            Self::Done(r) => write!(f, "Done({r:?})"),
        }
    }
}

/// Échec typé d'un appel (sans aucun texte du fournisseur).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlmError {
    /// Socket du mandataire injoignable, échange interrompu, ou mandataire absent.
    Transport,
    /// Clé ou ticket refusé (401, 403).
    Auth,
    /// Débit dépassé (fournisseur, ou `proxy_rate_limited` / `proxy_runtime_*`) : réessayer.
    RateLimited {
        /// Délai conseillé (`retry-after`), s'il est donné.
        retry_after_secs: Option<u64>,
    },
    /// Quota d'appels du tour du mandataire (`proxy_call_budget`) : fin du tour (`step_limit`).
    CallBudget,
    /// Quota de tokens du mandataire (`proxy_token_budget`) : `budget_exceeded`.
    TokenBudget,
    /// Délai du fournisseur dépassé (`proxy_upstream_timeout`, 408, 504).
    Timeout,
    /// Requête refusée par le fournisseur (4xx autre) : pas de nouvel essai.
    Rejected {
        /// Statut HTTP.
        status: u16,
    },
    /// Erreur du fournisseur (5xx) : réessayer.
    Provider {
        /// Statut HTTP.
        status: u16,
    },
    /// Flux illisible ou erreur annoncée dans le flux.
    BadStream,
    /// Réponse au-delà des bornes du worker (texte ou arguments d'outil cumulés) : pas de nouvel
    /// essai, la conversation échoue en `provider_error`.
    TooLarge,
}

impl LlmError {
    /// Un nouvel essai a un sens (08 §6 : 3 essais, 1 s, 4 s, 16 s).
    #[must_use]
    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Transport | Self::RateLimited { .. } | Self::Timeout | Self::Provider { .. } | Self::BadStream
        )
    }

    /// Code machine (journaux, métriques).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Transport => "llm_transport",
            Self::Auth => "llm_auth",
            Self::RateLimited { .. } => "llm_rate_limited",
            Self::CallBudget => "llm_call_budget",
            Self::TokenBudget => "llm_token_budget",
            Self::Timeout => "llm_timeout",
            Self::Rejected { .. } => "llm_rejected",
            Self::Provider { .. } => "llm_provider",
            Self::BadStream => "llm_bad_stream",
            Self::TooLarge => "llm_too_large",
        }
    }
}

/// Texte et raisonnement cumulés au plus dans une réponse (bien au-delà de `maxOutputTokensPerCall`).
pub const MAX_STREAM_TEXT_BYTES: usize = 4 * 1024 * 1024;
/// Arguments d'outils cumulés au plus dans une réponse.
pub const MAX_TOOL_ARGS_BYTES: usize = 1024 * 1024;

/// Décodeur du flux d'une réponse `2xx`, alimenté octet par octet. Tout décodeur borne le texte
/// cumulé ([`MAX_STREAM_TEXT_BYTES`]) et les arguments d'outils ([`MAX_TOOL_ARGS_BYTES`]) :
/// au-delà, [`LlmError::TooLarge`].
pub trait StreamDecoder: Send {
    /// Morceau reçu : ajoute les évènements complets à `out`.
    fn push(&mut self, chunk: &[u8], out: &mut Vec<LlmEvent>) -> Result<(), LlmError>;
    /// Fin du corps : vide les réserves, ajoute les appels d'outils puis **un** `Done`.
    fn finish(&mut self, out: &mut Vec<LlmEvent>) -> Result<(), LlmError>;
}

/// Adaptateur d'un fournisseur.
pub trait LlmAdapter: Send + Sync {
    /// Identifiant (`openai`, `gateway`…).
    fn id(&self) -> &'static str;
    /// Traduit la requête (aucune clé).
    fn build(&self, req: &ChatRequest) -> Result<HttpCall, LlmError>;
    /// Nouveau décodeur pour une réponse `2xx`.
    fn decoder(&self) -> Box<dyn StreamDecoder>;
    /// Classe une réponse d'erreur (statut, `retry-after`, début du corps). Par défaut : codes
    /// `proxy_*` du mandataire, puis statut HTTP.
    fn classify_error(&self, status: u16, retry_after_secs: Option<u64>, body: &[u8]) -> LlmError {
        classify_http_error(status, retry_after_secs, body)
    }
}

/// Classement commun : refus du mandataire (`{"error":"proxy_…"}`, docs/plan/10 §4) puis statut.
#[must_use]
pub fn classify_http_error(status: u16, retry_after_secs: Option<u64>, body: &[u8]) -> LlmError {
    let code = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_default();
    match code.as_str() {
        "proxy_call_budget" => return LlmError::CallBudget,
        "proxy_token_budget" => return LlmError::TokenBudget,
        "proxy_rate_limited" | "proxy_runtime_rate_limited" | "proxy_runtime_token_budget" | "proxy_busy" => {
            return LlmError::RateLimited { retry_after_secs };
        }
        "proxy_upstream_timeout" => return LlmError::Timeout,
        c if c.starts_with("proxy_") => return LlmError::Transport,
        _ => {}
    }
    match status {
        401 | 403 => LlmError::Auth,
        408 | 504 => LlmError::Timeout,
        429 => LlmError::RateLimited { retry_after_secs },
        500..=599 => LlmError::Provider { status },
        _ => LlmError::Rejected { status },
    }
}

/// Adaptateur du fournisseur configuré : `openai`, `gateway` et `custom` parlent le dialecte compatible
/// OpenAI ; Mistral et Gemini (par son endpoint compatible OpenAI) ont leur adaptateur (L07b).
#[must_use]
pub fn adapter_for(provider: LlmProvider) -> Box<dyn LlmAdapter> {
    match provider {
        LlmProvider::Openai => Box::new(openai::OpenAiCompatible::openai()),
        LlmProvider::Gateway => Box::new(openai::OpenAiCompatible::gateway()),
        LlmProvider::Custom => Box::new(openai::OpenAiCompatible::custom()),
        LlmProvider::Mistral => Box::new(mistral::Mistral),
        LlmProvider::Gemini => Box::new(gemini::Gemini),
    }
}

/// Plafond d'un corps d'erreur lu (jamais journalisé).
const MAX_ERROR_BODY: usize = 16 * 1024;
/// Délai sans octet reçu (09 §2).
pub const IDLE_READ_TIMEOUT: Duration = Duration::from_secs(120);

/// Appelle le fournisseur par le mandataire et rend chaque évènement à `on_event`, dans l'ordre.
/// `on_event` peut interrompre le flux en rendant `false` (annulation).
pub async fn stream_completion<F>(
    socket: &Path,
    adapter: &dyn LlmAdapter,
    req: &ChatRequest,
    mut on_event: F,
) -> Result<(), LlmError>
where
    F: FnMut(LlmEvent) -> bool,
{
    let call = adapter.build(req)?;
    let mut request = LlmRequest::new(call.method, call.path);
    for (k, v) in &call.headers {
        request = request.header(k, v);
    }
    let mut resp = llm::send(socket, request.body(call.body)).await.map_err(|_| LlmError::Transport)?;
    if !(200..300).contains(&resp.status()) {
        let retry = resp.header("retry-after").and_then(|v| v.trim().parse::<u64>().ok());
        let mut body = Vec::new();
        while body.len() < MAX_ERROR_BODY {
            match tokio::time::timeout(Duration::from_secs(10), resp.next_chunk()).await {
                Ok(Ok(Some(c))) => body.extend_from_slice(&c),
                _ => break,
            }
        }
        return Err(adapter.classify_error(resp.status(), retry, &body));
    }
    let mut decoder = adapter.decoder();
    let mut events = Vec::new();
    loop {
        let chunk = match tokio::time::timeout(IDLE_READ_TIMEOUT, resp.next_chunk()).await {
            Err(_) => return Err(LlmError::Timeout),
            Ok(Err(_)) => return Err(LlmError::Transport),
            Ok(Ok(c)) => c,
        };
        match chunk {
            Some(c) => decoder.push(&c, &mut events)?,
            None => decoder.finish(&mut events)?,
        }
        let ended = chunk_ended(&events);
        for ev in events.drain(..) {
            if !on_event(ev) {
                return Ok(());
            }
        }
        if ended {
            return Ok(());
        }
    }
}

fn chunk_ended(events: &[LlmEvent]) -> bool {
    events.iter().any(|e| matches!(e, LlmEvent::Done(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classement_des_erreurs() {
        assert_eq!(classify_http_error(429, Some(2), br#"{"error":"proxy_call_budget"}"#), LlmError::CallBudget);
        assert_eq!(classify_http_error(429, None, br#"{"error":"proxy_token_budget"}"#), LlmError::TokenBudget);
        assert_eq!(
            classify_http_error(429, Some(3), br#"{"error":"proxy_rate_limited"}"#),
            LlmError::RateLimited { retry_after_secs: Some(3) }
        );
        assert_eq!(classify_http_error(502, None, br#"{"error":"proxy_upstream_timeout"}"#), LlmError::Timeout);
        assert_eq!(classify_http_error(404, None, br#"{"error":"proxy_path"}"#), LlmError::Transport);
        assert_eq!(classify_http_error(401, None, br#"{"error":{"message":"bad key"}}"#), LlmError::Auth);
        assert_eq!(classify_http_error(503, None, b""), LlmError::Provider { status: 503 });
        assert_eq!(classify_http_error(400, None, b"x"), LlmError::Rejected { status: 400 });
        assert!(!LlmError::Auth.retryable() && LlmError::Provider { status: 500 }.retryable());
    }
}
