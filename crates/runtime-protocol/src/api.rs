//! Formes des réponses du canal interne (docs/plan/04 §4, forme réelle de synco_api
//! `routes/runtimeInternal/*` ; voir `vibe/features/SYNCOAI_REFONTE_FEATURE.md` §10–§12).
//! Lecture tolérante (champs en plus ignorés) : l'API peut s'enrichir sans casser le runtime.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Préfixe du canal.
pub const CHANNEL_PREFIX: &str = "/api/runtime/v1";
/// Clés publiques des tickets.
pub const TICKET_KEYS_PATH: &str = "/api/ai/ticket-keys";

/// `GET /api/ai/ticket-keys`.
#[derive(Debug, Clone, Deserialize)]
pub struct TicketKeysResponse {
    /// Version (1).
    pub v: u64,
    /// `kid` → clé publique `b64u`.
    pub keys: BTreeMap<String, String>,
}

/// Corps de `POST /register`.
#[derive(Debug, Clone, Serialize)]
pub struct RegisterRequest<'a> {
    /// URL publique configurée.
    pub url: &'a str,
    /// Logiciel.
    pub software: Software<'a>,
}

/// Version du logiciel.
#[derive(Debug, Clone, Serialize)]
pub struct Software<'a> {
    /// Version.
    pub version: &'a str,
}

/// `POST /register` → appairé.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResponse {
    /// Org appairée.
    pub org_id: String,
    /// Certificat (01 §6.2), vérifié par le runtime.
    pub certificate: serde_json::Value,
}

/// Élément de `GET /delegations`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegationRecord {
    /// Délégation.
    pub delegation_id: String,
    /// Utilisateur.
    pub user_id: String,
    /// Périmètre.
    pub scope: String,
    /// Émission (s).
    pub iat: u64,
    /// Expiration (s).
    pub exp: u64,
    /// Enveloppe de tête `srd1.…` (jamais journalisée).
    pub wrap: String,
    /// Signature du mandat (jamais journalisée).
    pub mandate_signature: String,
    /// Nom d'affichage du délégant (PC17, spec API §14.2) : absent ou `null` → le dashboard montre
    /// l'identifiant. Donnée du serveur : jamais une preuve d'identité.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Version du mandat servie (`1` si absente, 03 §4.1) : ne vaut rien tant que la signature n'est
    /// pas vérifiée.
    #[serde(default)]
    pub mandate_version: Option<u64>,
    /// Mode servi (`plan` ou `auto`, mandat v2).
    #[serde(default)]
    pub mode: Option<String>,
    /// Empreinte RSA du propriétaire servie (mandat v2).
    #[serde(default)]
    pub owner_rsa_spki_hex: Option<String>,
}

/// Entrée de délégation.
#[derive(Debug, Clone, Deserialize)]
pub struct EntryRecord {
    /// Curseur.
    pub id: String,
    /// Type.
    pub kind: String,
    /// Référence.
    #[serde(rename = "ref")]
    pub reference: String,
    /// Version.
    pub version: u64,
    /// `sre1.…`.
    pub ciphertext: String,
}

/// `GET /delegations/:id/entries`.
#[derive(Debug, Clone, Deserialize)]
pub struct EntriesPage {
    /// Entrées.
    pub entries: Vec<EntryRecord>,
    /// Curseur suivant.
    pub next: Option<String>,
}

/// Maillon de la chaîne de transitions d'identité.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransitionRecord {
    /// Rang.
    pub seq: u64,
    /// Ancienne clé de signature (JWK).
    pub old_public_sign_key: String,
    /// Nouvelle clé RSA (JWK).
    pub new_public_key: String,
    /// Nouvelle clé de signature (JWK).
    pub new_public_sign_key: String,
    /// Signature `b64`.
    pub signature: String,
}

/// `GET /users/:userId/sign-key`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignKeyResponse {
    /// Clé de signature courante (JWK sérialisée).
    pub public_sign_key: Option<String>,
    /// Chaîne de transitions.
    pub transitions: Vec<TransitionRecord>,
}

/// Élément de `GET /authorizations?state=active` (spec API §14.1).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ActiveAuthorization {
    /// Autorisation.
    pub auth_id: String,
    /// Conversation.
    pub session_id: String,
    /// Propriétaire.
    pub user_id: String,
    /// Délégation.
    pub delegation_id: String,
    /// Expiration (s Unix).
    pub exp: u64,
    /// Nom d'affichage du délégant, s'il en a un.
    #[serde(default)]
    pub display_name: Option<String>,
}

/// Page de `GET /authorizations?state=active` : `next = null` marque la fin (une page peut avoir
/// moins d'éléments que `limit`).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AuthorizationsPage {
    /// Autorisations de la page.
    pub authorizations: Vec<ActiveAuthorization>,
    /// Curseur suivant.
    pub next: Option<String>,
}

/// Élément de `GET /e2ee/threads/envelope-resets` (spec API §14.8, L03f) : une réinitialisation
/// d'enveloppe `rt1` en attente de réparation. **Jamais une décision** : le runtime refait toutes
/// ses vérifications locales (registre des salons créés, délégation, clé) avant de signer.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeResetItem {
    /// Salon.
    pub thread_id: String,
    /// Utilisateur propriétaire.
    pub user_id: String,
    /// Délégation avec laquelle réparer.
    pub delegation_id: String,
    /// Instant de la réinitialisation (ISO 8601) : non exploité.
    #[serde(default)]
    pub reset_at: Option<String>,
}

/// Page de `GET /e2ee/threads/envelope-resets?limit=&cursor=` : `next_cursor = null` marque la fin.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeResetsPage {
    /// Réinitialisations de la page.
    pub items: Vec<EnvelopeResetItem>,
    /// Curseur suivant.
    pub next_cursor: Option<String>,
}

/// Élément de `GET /conversations?state=pending`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PendingConversation {
    /// Conversation.
    pub session_id: String,
    /// Propriétaire.
    pub user_id: String,
    /// Autorisation.
    pub auth_id: String,
    /// Statut.
    pub status: String,
}

/// `POST /conversations/:sessionId/lease`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaseResponse {
    /// Époque du bail.
    pub lease_epoch: u64,
    /// Expiration (ISO 8601).
    pub expires_at: String,
    /// Fonctionnalités de l'utilisateur de l'autorisation (L00i, 04 §4.2) ; absent = API antérieure.
    #[serde(default)]
    pub features: LeaseFeatures,
}

/// `features` du bail : absent ou illisible = tout refusé.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaseFeatures {
    /// `isFeatureAllowed(web_access)` autorisé **et** activé (12 §11.2).
    #[serde(default)]
    pub web_allowed: bool,
}

/// `GET /conversations/:sessionId` (seuls les champs que lit le superviseur).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationHead {
    /// Révision.
    pub rev: u64,
    /// Statut.
    pub status: String,
    /// Époque du bail.
    pub lease_epoch: u64,
}

/// Réponse d'erreur du canal : `{ "error": "<code>" }`.
#[derive(Debug, Clone, Deserialize)]
pub struct ErrorBody {
    /// Code machine.
    pub error: String,
}

/// Fournisseur autorisé par l'org (`GET /llm-policy`).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyProvider {
    /// Identifiant (`openai`, `gateway`…).
    pub id: String,
    /// Modèle choisi par l'org.
    pub model_id: Option<String>,
    /// URL de la passerelle.
    pub gateway_url: Option<String>,
}

/// Plafonds de l'org (abaissables seulement, D6).
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OrgLimits {
    /// Appels au fournisseur par tour.
    pub max_steps_per_turn: u64,
    /// Tokens par conversation.
    pub max_tokens_per_conversation: u64,
    /// Tokens par tour.
    pub max_tokens_per_turn: u64,
    /// Durée d'un tour (s).
    pub max_turn_duration_secs: u64,
    /// Tokens de sortie par appel.
    pub max_output_tokens_per_call: u64,
    /// Délai des attentes `awaiting_confirmation` et durée de vie d'un plan (09 §3) ; absent = 7 j.
    #[serde(default)]
    pub confirmation_timeout_secs: Option<u64>,
}

/// Politique runtime de l'org.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OrgRuntimePolicy {
    /// Mode runtime proposé.
    pub enabled: bool,
    /// Durée maximale d'une délégation (jours, fraction admise).
    pub max_delegation_days: f64,
    /// Politique par outil.
    pub tool_policy: BTreeMap<String, crate::pipe::ToolPolicy>,
    /// Plafonds.
    pub limits: OrgLimits,
}

/// `GET /llm-policy` (D1 : aucun secret).
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LlmPolicy {
    /// Org.
    pub org_id: String,
    /// Fournisseur par défaut.
    pub default_provider: Option<String>,
    /// Effort de raisonnement.
    pub reasoning_effort: Option<String>,
    /// Fournisseurs autorisés.
    pub providers: Vec<PolicyProvider>,
    /// Politique runtime.
    pub runtime: OrgRuntimePolicy,
}
