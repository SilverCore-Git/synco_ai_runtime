//! Pipe superviseur ↔ worker (docs/plan/06-superviseur-worker.md).
//!
//! ```text
//! trame = longueur (u32 gros-boutiste : octets qui suivent, genre compris) ‖ genre (u8) ‖ charge
//! ```
//!
//! - genre `0x01` : un objet JSON (≤ 1 Mio), désérialisation **stricte** ([`SupervisorMsg`],
//!   [`WorkerMsg`]) ;
//! - genre `0x02` : trame de clés binaire (≤ 64 Kio) ([`KeyFrame`]), lue dans des tampons effacés à
//!   la libération. Les clés ne passent **jamais** en JSON.
//!
//! Longueur nulle, trop grande, ou genre inconnu : le lecteur ferme le canal ([`PipeError`]).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::ids::is_identifier;

/// Genre : message JSON.
pub const KIND_JSON: u8 = 0x01;
/// Genre : trame de clés.
pub const KIND_KEYS: u8 = 0x02;
/// Charge maximale d'une trame JSON.
pub const MAX_JSON_PAYLOAD: usize = 1024 * 1024;
/// Charge maximale d'une trame de clés.
pub const MAX_KEYS_PAYLOAD: usize = 64 * 1024;
/// Longueur d'une clé `conv`, `thread` ou `space`.
pub const SYMMETRIC_KEY_LEN: usize = 32;
/// Longueur maximale d'un secret de fournisseur LLM.
pub const MAX_CREDENTIAL_LEN: usize = 4096;

/// Refus du canal : le lecteur ferme (côté superviseur, le worker est tué).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeError {
    /// Fin du flux (worker parti, canal fermé).
    Closed,
    /// Erreur d'entrée/sortie.
    Io,
    /// Longueur nulle ou trop grande, genre inconnu.
    BadFrame,
    /// JSON invalide, champ inconnu, type inconnu.
    BadMessage,
    /// Trame de clés mal formée.
    BadKeys,
}

impl core::fmt::Display for PipeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Closed => "pipe_closed",
            Self::Io => "pipe_io",
            Self::BadFrame => "pipe_bad_frame",
            Self::BadMessage => "pipe_bad_message",
            Self::BadKeys => "pipe_bad_keys",
        })
    }
}

impl std::error::Error for PipeError {}

// ---------------------------------------------------------------------------
// Cadrage
// ---------------------------------------------------------------------------

/// Trame reçue.
pub enum Frame {
    /// Charge JSON (non encore désérialisée).
    Json(Vec<u8>),
    /// Charge de clés (effacée à la libération).
    Keys(Zeroizing<Vec<u8>>),
}

impl core::fmt::Debug for Frame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Json(b) => write!(f, "Frame::Json({} octets)", b.len()),
            Self::Keys(b) => write!(f, "Frame::Keys({} octets, ***)", b.len()),
        }
    }
}

fn header(kind: u8, payload_len: usize) -> Result<[u8; 5], PipeError> {
    let max = if kind == KIND_JSON { MAX_JSON_PAYLOAD } else { MAX_KEYS_PAYLOAD };
    if payload_len == 0 || payload_len > max {
        return Err(PipeError::BadFrame);
    }
    let len = u32::try_from(payload_len.saturating_add(1)).map_err(|_| PipeError::BadFrame)?;
    let [a, b, c, d] = len.to_be_bytes();
    Ok([a, b, c, d, kind])
}

/// Écrit une trame JSON.
pub async fn write_json<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, msg: &T) -> Result<(), PipeError> {
    let payload = serde_json::to_vec(msg).map_err(|_| PipeError::BadMessage)?;
    w.write_all(&header(KIND_JSON, payload.len())?).await.map_err(|_| PipeError::Io)?;
    w.write_all(&payload).await.map_err(|_| PipeError::Io)?;
    w.flush().await.map_err(|_| PipeError::Io)
}

/// Écrit une trame de clés déjà encodée ([`KeyFrame::encode`]).
pub async fn write_keys<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> Result<(), PipeError> {
    w.write_all(&header(KIND_KEYS, payload.len())?).await.map_err(|_| PipeError::Io)?;
    w.write_all(payload).await.map_err(|_| PipeError::Io)?;
    w.flush().await.map_err(|_| PipeError::Io)
}

/// Lit une trame. Toute anomalie de cadrage est une erreur : l'appelant ferme le canal.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Frame, PipeError> {
    let mut head = [0u8; 5];
    match r.read_exact(&mut head).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(PipeError::Closed),
        Err(_) => return Err(PipeError::Io),
    }
    let [a, b, c, d, kind] = head;
    let len = usize::try_from(u32::from_be_bytes([a, b, c, d])).map_err(|_| PipeError::BadFrame)?;
    let payload_len = len.checked_sub(1).ok_or(PipeError::BadFrame)?;
    let max = match kind {
        KIND_JSON => MAX_JSON_PAYLOAD,
        KIND_KEYS => MAX_KEYS_PAYLOAD,
        _ => return Err(PipeError::BadFrame),
    };
    if payload_len == 0 || payload_len > max {
        return Err(PipeError::BadFrame);
    }
    let mut payload = Zeroizing::new(vec![0u8; payload_len]);
    r.read_exact(&mut payload).await.map_err(|_| PipeError::Closed)?;
    Ok(if kind == KIND_JSON { Frame::Json(core::mem::take(&mut *payload)) } else { Frame::Keys(payload) })
}

// ---------------------------------------------------------------------------
// Trame de clés (06 §2)
// ---------------------------------------------------------------------------

/// Opération d'une trame de clés.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOp {
    /// Ajouter.
    Add,
    /// Retirer (sans octets de clé).
    Remove,
}

/// Type de clé transmise au worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyKind {
    /// `CK` de la conversation.
    Conv,
    /// Clé de salon.
    Thread,
    /// Clé d'espace.
    Space,
    /// Secret d'un fournisseur LLM (D1 : configuré dans le runtime).
    LlmCredential,
}

impl KeyKind {
    const fn byte(self) -> u8 {
        match self {
            Self::Conv => 0x01,
            Self::Thread => 0x02,
            Self::Space => 0x03,
            Self::LlmCredential => 0x10,
        }
    }

    const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Conv),
            0x02 => Some(Self::Thread),
            0x03 => Some(Self::Space),
            0x10 => Some(Self::LlmCredential),
            _ => None,
        }
    }

    /// Nom (`conv`, `thread`, `space`, `llm_credential`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Conv => "conv",
            Self::Thread => "thread",
            Self::Space => "space",
            Self::LlmCredential => "llm_credential",
        }
    }

    /// Lecture du nom.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "conv" => Some(Self::Conv),
            "thread" => Some(Self::Thread),
            "space" => Some(Self::Space),
            "llm_credential" => Some(Self::LlmCredential),
            _ => None,
        }
    }

    fn key_len_ok(self, len: usize) -> bool {
        match self {
            Self::LlmCredential => (1..=MAX_CREDENTIAL_LEN).contains(&len),
            _ => len == SYMMETRIC_KEY_LEN,
        }
    }
}

/// Une clé d'une trame `0x02`.
pub struct KeyEntry {
    /// Type.
    pub kind: KeyKind,
    /// Référence (identifiant 00 §3.2 ; fournisseur pour `llm_credential`).
    pub reference: String,
    /// Version.
    pub version: u32,
    /// Octets (vide pour un retrait), effacés à la libération.
    pub key: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for KeyEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyEntry")
            .field("kind", &self.kind)
            .field("reference", &self.reference)
            .field("version", &self.version)
            .field("key", &"***")
            .finish()
    }
}

/// Trame de clés.
#[derive(Debug)]
pub struct KeyFrame {
    /// Opération.
    pub op: KeyOp,
    /// Clés.
    pub entries: Vec<KeyEntry>,
}

fn entry_size(e: &KeyEntry, op: KeyOp) -> usize {
    let key = if op == KeyOp::Add { e.key.len() } else { 0 };
    1usize.saturating_add(2).saturating_add(e.reference.len()).saturating_add(4).saturating_add(2).saturating_add(key)
}

impl KeyFrame {
    /// Encode (≤ 64 Kio). Contrôle chaque entrée.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, PipeError> {
        let count = u16::try_from(self.entries.len()).map_err(|_| PipeError::BadKeys)?;
        // Capacité exacte calculée d'avance : aucune réallocation ne laisse de copie des clés.
        let size = self.entries.iter().fold(3usize, |acc, e| acc.saturating_add(entry_size(e, self.op)));
        if size > MAX_KEYS_PAYLOAD {
            return Err(PipeError::BadKeys);
        }
        let mut out = Zeroizing::new(Vec::with_capacity(size));
        out.push(if self.op == KeyOp::Add { 0x01 } else { 0x02 });
        out.extend_from_slice(&count.to_be_bytes());
        for e in &self.entries {
            if !is_identifier(&e.reference) {
                return Err(PipeError::BadKeys);
            }
            let key: &[u8] = if self.op == KeyOp::Add { &e.key } else { &[] };
            if self.op == KeyOp::Add && !e.kind.key_len_ok(key.len()) {
                return Err(PipeError::BadKeys);
            }
            out.push(e.kind.byte());
            out.extend_from_slice(&u16::try_from(e.reference.len()).map_err(|_| PipeError::BadKeys)?.to_be_bytes());
            out.extend_from_slice(e.reference.as_bytes());
            out.extend_from_slice(&e.version.to_be_bytes());
            out.extend_from_slice(&u16::try_from(key.len()).map_err(|_| PipeError::BadKeys)?.to_be_bytes());
            out.extend_from_slice(key);
        }
        if out.len() > MAX_KEYS_PAYLOAD || out.capacity() != size {
            return Err(PipeError::BadKeys);
        }
        Ok(out)
    }

    /// Découpe des entrées en trames de ≤ 64 Kio.
    pub fn split(op: KeyOp, entries: Vec<KeyEntry>) -> Result<Vec<Zeroizing<Vec<u8>>>, PipeError> {
        let mut frames = Vec::new();
        let mut current = Vec::new();
        let mut size = 3usize;
        for e in entries {
            let s = entry_size(&e, op);
            if s.saturating_add(3) > MAX_KEYS_PAYLOAD {
                return Err(PipeError::BadKeys);
            }
            if size.saturating_add(s) > MAX_KEYS_PAYLOAD || current.len() >= usize::from(u16::MAX) {
                frames.push(Self { op, entries: core::mem::take(&mut current) }.encode()?);
                size = 3;
            }
            size = size.saturating_add(s);
            current.push(e);
        }
        if !current.is_empty() {
            frames.push(Self { op, entries: current }.encode()?);
        }
        Ok(frames)
    }

    /// Décode une charge `0x02`. Les octets de clé sont copiés dans des tampons effacés.
    pub fn decode(payload: &[u8]) -> Result<Self, PipeError> {
        let mut r = Reader { buf: payload };
        let op = match r.u8()? {
            0x01 => KeyOp::Add,
            0x02 => KeyOp::Remove,
            _ => return Err(PipeError::BadKeys),
        };
        let count = r.u16()?;
        let mut entries = Vec::with_capacity(usize::from(count).min(1024));
        for _ in 0..count {
            let kind = KeyKind::from_byte(r.u8()?).ok_or(PipeError::BadKeys)?;
            let ref_len = usize::from(r.u16()?);
            let reference = core::str::from_utf8(r.take(ref_len)?).map_err(|_| PipeError::BadKeys)?.to_owned();
            if !is_identifier(&reference) {
                return Err(PipeError::BadKeys);
            }
            let version = r.u32()?;
            let key_len = usize::from(r.u16()?);
            let key = Zeroizing::new(r.take(key_len)?.to_vec());
            let ok = match op {
                KeyOp::Add => kind.key_len_ok(key.len()),
                KeyOp::Remove => key.is_empty(),
            };
            if !ok {
                return Err(PipeError::BadKeys);
            }
            entries.push(KeyEntry { kind, reference, version, key });
        }
        if !r.buf.is_empty() {
            return Err(PipeError::BadKeys);
        }
        Ok(Self { op, entries })
    }
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], PipeError> {
        let (head, rest) = self.buf.split_at_checked(n).ok_or(PipeError::BadKeys)?;
        self.buf = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, PipeError> {
        let [b] = self.take(1)?.try_into().map_err(|_| PipeError::BadKeys)?;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16, PipeError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| PipeError::BadKeys)?))
    }

    fn u32(&mut self) -> Result<u32, PipeError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| PipeError::BadKeys)?))
    }
}

// ---------------------------------------------------------------------------
// Messages JSON (06 §3, §4)
// ---------------------------------------------------------------------------

/// Fournisseur LLM (06 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LlmProvider {
    /// OpenAI.
    Openai,
    /// Mistral.
    Mistral,
    /// Gemini.
    Gemini,
    /// Passerelle Synco (ticket `sgt1`).
    Gateway,
    /// Point d'accès compatible OpenAI configuré dans le runtime.
    Custom,
}

impl LlmProvider {
    /// Nom.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Openai => "openai",
            Self::Mistral => "mistral",
            Self::Gemini => "gemini",
            Self::Gateway => "gateway",
            Self::Custom => "custom",
        }
    }
}

/// Effort de raisonnement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReasoningEffort {
    /// Faible.
    Low,
    /// Moyen.
    Medium,
    /// Élevé.
    High,
}

/// Tarif indicatif (€ par million de tokens).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Pricing {
    /// Entrée.
    pub input_per_m_tok: f64,
    /// Sortie.
    pub output_per_m_tok: f64,
}

/// Configuration LLM du worker, **sans secret** (le secret passe en trame `0x02`, D1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LlmConfig {
    /// Fournisseur.
    pub provider: LlmProvider,
    /// Modèle.
    pub model: String,
    /// URL de base de l'API du fournisseur.
    pub base_url: String,
    /// Effort de raisonnement.
    pub reasoning_effort: ReasoningEffort,
    /// Tarif, si connu.
    pub pricing: Option<Pricing>,
}

/// Plafonds du worker (06 §3.2, 09 §2), déjà bornés par la politique de l'org.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WorkerLimits {
    /// Appels au fournisseur par tour.
    pub max_steps_per_turn: u64,
    /// Tokens cumulés par conversation.
    pub max_tokens_per_conversation: u64,
    /// Tokens par tour (09 §2).
    pub max_tokens_per_turn: u64,
    /// Durée d'un tour (s).
    pub max_turn_duration_secs: u64,
    /// Tokens de sortie par appel (09 §2).
    pub max_output_tokens_per_call: u64,
    /// Taille d'un résultat d'outil.
    pub max_tool_result_bytes: u64,
    /// Arrêt après inactivité (s).
    pub idle_shutdown_secs: u64,
}

/// Politique d'un outil (D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolPolicy {
    /// Exécution sans confirmation.
    Auto,
    /// Confirmation de l'utilisateur.
    Ask,
    /// Interdit.
    Deny,
}

/// Raison d'un arrêt demandé.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShutdownReason {
    /// Inactivité.
    Idle,
    /// Conversation ou délégation révoquée.
    Revoked,
    /// Désappairage.
    Unpaired,
    /// Arrêt du runtime.
    Sigterm,
    /// Plafond atteint.
    Limit,
}

/// `init` (06 §3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Init {
    /// Conversation.
    pub session_id: String,
    /// Propriétaire.
    pub user_id: String,
    /// Organisation.
    pub org_id: String,
    /// Runtime.
    pub runtime_id: String,
    /// Autorisation de session.
    pub auth_id: String,
    /// Bail pris par le superviseur.
    pub lease_epoch: u64,
    /// URL de l'API.
    pub api_base_url: String,
    /// Configuration LLM.
    pub llm: LlmConfig,
    /// Plafonds.
    pub limits: WorkerLimits,
    /// Politique par outil.
    pub tool_policy: BTreeMap<String, ToolPolicy>,
    /// Niveau de journal.
    pub log_level: String,
    /// Plans d'action (12) : absent = ancien superviseur, aucun plan (confirmation outil par outil).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<PlanInit>,
}

/// Mode du mandat **vérifié** de la délégation courante du propriétaire (12 §10.1) ; `auto` seulement
/// pour un mandat v2 `auto` quand `autonomy.allowed` est vrai (12 §10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanMode {
    /// Plan d'action (défaut ; tout mandat v1).
    Plan,
    /// Mode autonome.
    Auto,
}

/// Réglages des plans d'action donnés au worker (12 §8.7, §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PlanInit {
    /// Mode du mandat vérifié.
    pub mode: PlanMode,
    /// Actions d'agent en parallèle (`plan.concurrency`, [1, 8]).
    pub concurrency: u8,
    /// `confirmationTimeoutSecs` de l'org, borné [3 600, 604 800] : durée de vie d'un plan.
    pub confirmation_timeout_secs: u64,
}

/// Message superviseur → worker (trames `0x01`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SupervisorMsg {
    /// Première trame.
    Init(Box<Init>),
    /// Toutes les clés initiales sont envoyées.
    Start(Empty),
    /// Éléments de boîte arrivés par WebSocket (champs encore chiffrés).
    Inbox(InboxMsg),
    /// Arrêt demandé.
    Shutdown(ShutdownMsg),
    /// Réponse à `signed_request`.
    SignedRequestResponse(SignedResponse),
    /// Demande d'un `snapshot` pour un client qui reprend hors du tampon (extension L05, 05 §3).
    SnapshotRequest(SnapshotRequest),
    /// Réponse à une clé de salon créée par le worker (extension L07, 03 §10, §10.1).
    CreatedKey(CreatedKeyMsg),
}

/// Nombre maximal de clés créées qu'un worker peut faire sceller par le superviseur au cours de sa
/// vie (extension L07) ; au-delà, `created_key` répond `created_key_limit`.
pub const MAX_CREATED_KEYS_PER_WORKER: u32 = 32;

/// Enveloppe `rt1` et entrée de délégation d'une clé créée par le worker (03 §10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreatedKeyEnvelope {
    /// Délégation du propriétaire (`creatorId = rt1:<delegationId>`).
    pub delegation_id: String,
    /// `keyCommitment(clé, ctx, version)`, calculé par le superviseur depuis la clé elle-même.
    pub commitment: String,
    /// Signature `csk` (P1363, `b64`) des octets `synco-key-envelope-rt-v1|ctx|version|commitment|delegationId`.
    pub signature: String,
    /// Entrée `sre1.…` de la clé, chiffrée sous `DK` (03 §5), à poser par
    /// `POST /delegations/:delegationId/entries`.
    pub ciphertext: String,
}

/// `created_key` (extension L07) : réponse à une trame `0x02` **du worker** (une seule entrée,
/// `op = ajouter`, `kind = thread`, version 1) qui annonce la clé d'un salon qu'il vient de créer
/// (`create_thread`). Le worker n'a ni `csk` ni `DK` (mesure 7) : le superviseur signe l'enveloppe
/// `rt1` et chiffre l'entrée, le worker les pose ensuite lui-même par `signed_request` (bail exigé).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreatedKeyMsg {
    /// Identifiant du salon.
    #[serde(rename = "ref")]
    pub reference: String,
    /// Enveloppe et entrée (absentes en cas d'échec).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope: Option<CreatedKeyEnvelope>,
    /// Code machine d'échec : `created_key_limit`, `delegation_unavailable`, `autonomy_required`, `created_key_failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl KeyFrame {
    /// Vrai si la trame est une annonce de clé créée admissible venant d'un worker : une entrée,
    /// ajout, salon, version 1, clé de 32 octets.
    #[must_use]
    pub fn is_created_thread_key(&self) -> bool {
        matches!(self.entries.as_slice(), [e] if self.op == KeyOp::Add && e.kind == KeyKind::Thread && e.version == 1 && e.key.len() == SYMMETRIC_KEY_LEN)
    }
}

/// Corps vide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

/// `inbox`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboxMsg {
    /// Trames `{ t, … }` (05 §6.2).
    pub items: Vec<Value>,
}

/// `shutdown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ShutdownMsg {
    /// Délai pour finir l'étape (ms) ; 0 = quitter tout de suite.
    pub grace_ms: u64,
    /// Raison.
    pub reason: ShutdownReason,
}

fn yes() -> bool {
    true
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

fn is_true(v: &bool) -> bool {
    *v
}

/// `signed_request_response`, éventuellement découpée en parties (extension L05 de 06 §4) : une
/// réponse dont le corps dépasse [`RELAY_CHUNK_BYTES`] est envoyée en plusieurs trames de même
/// `id`, `part` = 0, 1, 2…, la dernière avec `last = true`. `status` et `headers` sont répétés.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedResponse {
    /// Identifiant de la requête.
    pub id: String,
    /// Statut HTTP. `0` : pas de réponse de l'API, la cause est dans `error`.
    pub status: u16,
    /// En-têtes utiles (`content-type`, `retry-after` en secondes entières).
    pub headers: BTreeMap<String, String>,
    /// Morceau du corps (`b64`).
    pub body: String,
    /// Rang de la partie (0 si absente).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub part: u32,
    /// Dernière partie (vrai si absent).
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub last: bool,
    /// Code machine quand `status = 0` : `relay_refused`, `relay_busy`, `relay_too_large`,
    /// `relay_bad_part`, `relay_network`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Taille brute maximale d'une partie de corps relayé (sa forme `b64` tient largement dans une
/// trame JSON de 1 Mio).
pub const RELAY_CHUNK_BYTES: usize = 512 * 1024;
/// Corps maximal d'une requête relayée (historique ≤ 8 Mio, 09 §4).
pub const MAX_RELAY_REQUEST_BYTES: usize = 8 * 1024 * 1024 + 64 * 1024;
/// Corps maximal d'une réponse relayée.
pub const MAX_RELAY_RESPONSE_BYTES: usize = 9 * 1024 * 1024;

impl SignedResponse {
    /// Réponse d'échec sans corps (`status = 0`).
    #[must_use]
    pub fn failure(id: &str, code: &str) -> Self {
        Self {
            id: id.to_owned(),
            status: 0,
            headers: BTreeMap::new(),
            body: String::new(),
            part: 0,
            last: true,
            error: Some(code.to_owned()),
        }
    }

    /// Découpe une réponse en parties de ≤ [`RELAY_CHUNK_BYTES`] octets bruts.
    #[must_use]
    pub fn split(id: &str, status: u16, headers: &BTreeMap<String, String>, body: &[u8]) -> Vec<Self> {
        let chunks: Vec<&[u8]> = if body.is_empty() { vec![&[][..]] } else { body.chunks(RELAY_CHUNK_BYTES).collect() };
        let n = chunks.len();
        chunks
            .into_iter()
            .enumerate()
            .map(|(i, c)| Self {
                id: id.to_owned(),
                status,
                headers: headers.clone(),
                body: synco_e2ee::encoding::b64(c),
                part: u32::try_from(i).unwrap_or(u32::MAX),
                last: i.saturating_add(1) == n,
                error: None,
            })
            .collect()
    }
}

/// Réassemblage de parties successives (requête ou réponse relayée).
#[derive(Debug, Default)]
pub struct Reassembly {
    next_part: u32,
    body: Vec<u8>,
}

impl Reassembly {
    /// Ajoute la partie `part` (`b64`). Erreur si hors d'ordre, illisible ou au-delà de `max`.
    pub fn push(&mut self, part: u32, b64_chunk: &str, max: usize) -> Result<(), &'static str> {
        if part != self.next_part {
            return Err("relay_bad_part");
        }
        let bytes = synco_e2ee::encoding::from_b64(b64_chunk).map_err(|_| "relay_bad_part")?;
        if bytes.len() > RELAY_CHUNK_BYTES || self.body.len().saturating_add(bytes.len()) > max {
            return Err("relay_too_large");
        }
        self.body.extend_from_slice(&bytes);
        self.next_part = self.next_part.saturating_add(1);
        Ok(())
    }

    /// Octets reçus.
    #[must_use]
    pub fn len(&self) -> usize {
        self.body.len()
    }

    /// Aucun octet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }

    /// Corps complet.
    #[must_use]
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
}

/// `snapshot_request`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SnapshotRequest {
    /// Identifiant de la demande.
    pub request_id: String,
}

/// Méthode d'une requête relayée.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// GET.
    Get,
    /// POST.
    Post,
    /// PUT.
    Put,
    /// DELETE.
    Delete,
}

impl HttpMethod {
    /// Nom.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

/// Message worker → superviseur (trames `0x01`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerMsg {
    /// Prêt à recevoir les clés.
    Ready(ReadyMsg),
    /// Évènement runtime → client complet, déjà chiffré (diffusé sans être lu).
    Event(EventMsg),
    /// Changement d'état (déjà enregistré dans l'API par le worker).
    Status(StatusMsg),
    /// Clé absente de la délégation (03 §11).
    NeedKey(NeedKeyMsg),
    /// Requête vers l'API que le superviseur signe.
    SignedRequest(SignedRequest),
    /// Éléments consommés.
    InboxAck(InboxAckMsg),
    /// Métriques sans contenu.
    Metrics(Box<Metrics>),
    /// Journal structuré sans contenu.
    Log(LogMsg),
    /// Le worker va quitter.
    Done(DoneMsg),
    /// Réponse à `snapshot_request` (extension L05).
    Snapshot(SnapshotMsg),
}

/// `ready`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadyMsg {
    /// PID vu du worker.
    pub pid: u32,
    /// Version du worker.
    pub version: String,
}

/// `event`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventMsg {
    /// Trame 05 §5 complète.
    pub event: Value,
}

/// `status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusMsg {
    /// Statut (08).
    pub status: String,
    /// Code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `need_key`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NeedKeyMsg {
    /// `thread` ou `space`.
    pub kind: String,
    /// Référence.
    #[serde(rename = "ref")]
    pub reference: String,
}

/// `signed_request`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignedRequest {
    /// Identifiant (renvoyé dans la réponse).
    pub id: String,
    /// Méthode.
    pub method: HttpMethod,
    /// Chemin et requête, relatif à l'API (`/api/runtime/v1/…`).
    pub path: String,
    /// Morceau du corps (`b64`, vide si aucun).
    pub body: String,
    /// Ajouter `x-synco-auth` (autorisation de la conversation du worker).
    pub with_auth: bool,
    /// Rang de la partie (0 si absente) : un corps > [`RELAY_CHUNK_BYTES`] est envoyé en plusieurs
    /// trames de même `id` ; `method`, `path` et `withAuth` sont répétés à l'identique.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub part: u32,
    /// Dernière partie (vrai si absent).
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub last: bool,
}

impl SignedRequest {
    /// Découpe une requête en parties.
    #[must_use]
    pub fn split(id: &str, method: HttpMethod, path: &str, body: &[u8], with_auth: bool) -> Vec<Self> {
        SignedResponse::split(id, 0, &BTreeMap::new(), body)
            .into_iter()
            .map(|r| Self {
                id: r.id,
                method,
                path: path.to_owned(),
                body: r.body,
                with_auth,
                part: r.part,
                last: r.last,
            })
            .collect()
    }
}

/// `inbox_ack`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboxAckMsg {
    /// Éléments consommés.
    pub ids: Vec<String>,
}

/// Latences d'appel au fournisseur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Latency {
    /// Médiane (ms).
    pub p50: u64,
    /// Maximum (ms).
    pub max: u64,
}

/// `metrics` (06 §5) : uniquement des compteurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Metrics {
    /// Tour.
    pub turn: u64,
    /// Étapes.
    pub steps: u64,
    /// Appels au fournisseur.
    pub llm_calls: u64,
    /// Appels d'outils.
    pub tool_calls: u64,
    /// Erreurs d'outils.
    pub tool_errors: u64,
    /// Tokens d'entrée.
    pub prompt_tokens: u64,
    /// Tokens de sortie.
    pub completion_tokens: u64,
    /// Tokens de raisonnement.
    pub reasoning_tokens: u64,
    /// Coût estimé (micro-euros).
    pub cost_eur_micro: u64,
    /// Latences.
    pub llm_latency_ms: Latency,
    /// Durée du tour (ms).
    pub turn_duration_ms: u64,
}

/// `log` : un code et des champs **sans contenu** (nombres, booléens, codes courts).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogMsg {
    /// `error`, `warn`, `info`, `debug`.
    pub level: String,
    /// Code machine.
    pub code: String,
    /// Champs.
    pub fields: BTreeMap<String, Value>,
}

impl LogMsg {
    /// Vrai si le journal ne peut pas porter de contenu : niveau connu, code et clés conformes
    /// (00 §3.2), valeurs numériques, booléennes ou codes courts (identifiants).
    #[must_use]
    pub fn is_contentless(&self) -> bool {
        matches!(self.level.as_str(), "error" | "warn" | "info" | "debug")
            && is_identifier(&self.code)
            && self.fields.len() <= 16
            && self.fields.iter().all(|(k, v)| {
                is_identifier(k)
                    && match v {
                        Value::Bool(_) | Value::Number(_) | Value::Null => true,
                        Value::String(s) => is_identifier(s),
                        Value::Array(_) | Value::Object(_) => false,
                    }
            })
    }
}

/// Raison de fin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DoneReason {
    /// Tour terminé, rien à faire.
    Idle,
    /// En attente d'un humain ou d'une clé.
    Awaiting,
    /// Échec.
    Failed,
    /// Annulé.
    Cancelled,
    /// Arrêt demandé.
    Shutdown,
}

/// `done`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoneMsg {
    /// Raison.
    pub reason: DoneReason,
}

/// `snapshot` (extension L05).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SnapshotMsg {
    /// Demande.
    pub request_id: String,
    /// Trame `snapshot` complète (05 §5.2), déjà chiffrée.
    pub event: Value,
}

/// Désérialisation stricte d'une charge JSON.
pub fn decode_json<T: for<'de> Deserialize<'de>>(payload: &[u8]) -> Result<T, PipeError> {
    serde_json::from_slice(payload).map_err(|_| PipeError::BadMessage)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: KeyKind, reference: &str, key: &[u8]) -> KeyEntry {
        KeyEntry { kind, reference: reference.into(), version: 1, key: Zeroizing::new(key.to_vec()) }
    }

    #[test]
    fn cles_aller_retour() {
        let frame = KeyFrame {
            op: KeyOp::Add,
            entries: vec![entry(KeyKind::Conv, "s1", &[7; 32]), entry(KeyKind::LlmCredential, "openai", b"cle")],
        };
        let bytes = frame.encode().unwrap();
        let back = KeyFrame::decode(&bytes).unwrap();
        assert_eq!(back.op, KeyOp::Add);
        assert_eq!(back.entries.len(), 2);
        assert_eq!(back.entries[0].key.as_slice(), &[7; 32]);
        assert_eq!(back.entries[1].kind, KeyKind::LlmCredential);
        assert!(!format!("{back:?}").contains('7'), "clés masquées dans Debug");
        assert_eq!(bytes.capacity(), bytes.len(), "aucune réallocation pendant l'encodage");
    }

    #[test]
    fn cle_creee_par_le_worker() {
        let ok = KeyFrame { op: KeyOp::Add, entries: vec![entry(KeyKind::Thread, "t1", &[1; 32])] };
        assert!(ok.is_created_thread_key());
        for bad in [
            KeyFrame { op: KeyOp::Remove, entries: vec![entry(KeyKind::Thread, "t1", &[])] },
            KeyFrame { op: KeyOp::Add, entries: vec![entry(KeyKind::Space, "s1", &[1; 32])] },
            KeyFrame { op: KeyOp::Add, entries: vec![entry(KeyKind::Conv, "c1", &[1; 32])] },
            KeyFrame { op: KeyOp::Add, entries: vec![entry(KeyKind::LlmCredential, "openai", b"cle")] },
            KeyFrame { op: KeyOp::Add, entries: vec![] },
            KeyFrame {
                op: KeyOp::Add,
                entries: vec![entry(KeyKind::Thread, "t1", &[1; 32]), entry(KeyKind::Thread, "t2", &[1; 32])],
            },
            KeyFrame {
                op: KeyOp::Add,
                entries: vec![KeyEntry {
                    kind: KeyKind::Thread,
                    reference: "t1".into(),
                    version: 2,
                    key: Zeroizing::new(vec![1; 32]),
                }],
            },
        ] {
            assert!(!bad.is_created_thread_key(), "{bad:?}");
        }
        let msg = SupervisorMsg::CreatedKey(CreatedKeyMsg {
            reference: "t1".into(),
            envelope: None,
            error: Some("created_key_limit".into()),
        });
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, r#"{"type":"created_key","ref":"t1","error":"created_key_limit"}"#);
        assert_eq!(decode_json::<SupervisorMsg>(json.as_bytes()).unwrap(), msg);
    }

    #[test]
    fn cles_refusees() {
        assert!(KeyFrame { op: KeyOp::Add, entries: vec![entry(KeyKind::Thread, "t", &[1; 31])] }.encode().is_err());
        assert!(KeyFrame { op: KeyOp::Add, entries: vec![entry(KeyKind::Thread, "a|b", &[1; 32])] }.encode().is_err());
        let ok = KeyFrame { op: KeyOp::Add, entries: vec![entry(KeyKind::Thread, "t", &[1; 32])] }.encode().unwrap();
        let mut extra = ok.to_vec();
        extra.push(0);
        assert!(KeyFrame::decode(&extra).is_err(), "octets en trop");
        assert!(KeyFrame::decode(&ok[..ok.len() - 1]).is_err(), "tronquée");
        let mut bad_kind = ok.to_vec();
        bad_kind[3] = 0x04;
        assert!(KeyFrame::decode(&bad_kind).is_err(), "genre de clé inconnu");
    }

    #[test]
    fn decoupage() {
        let entries: Vec<_> = (0..3000).map(|i| entry(KeyKind::Thread, &format!("thread{i:058}"), &[1; 32])).collect();
        let frames = KeyFrame::split(KeyOp::Add, entries).unwrap();
        assert!(frames.len() > 1);
        let total: usize = frames.iter().map(|f| KeyFrame::decode(f).unwrap().entries.len()).sum();
        assert_eq!(total, 3000);
        assert!(frames.iter().all(|f| f.len() <= MAX_KEYS_PAYLOAD));
    }

    #[test]
    fn decoupage_des_reponses_relayees() {
        let body: Vec<u8> = (0..(3 * RELAY_CHUNK_BYTES + 10)).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let parts = SignedResponse::split("r1", 200, &BTreeMap::new(), &body);
        assert_eq!(parts.len(), 4);
        let mut re = Reassembly::default();
        for p in &parts {
            // Chaque partie tient dans une trame JSON.
            assert!(
                serde_json::to_vec(&SupervisorMsg::SignedRequestResponse(p.clone())).unwrap().len() <= MAX_JSON_PAYLOAD
            );
            re.push(p.part, &p.body, MAX_RELAY_RESPONSE_BYTES).unwrap();
        }
        assert!(parts.last().unwrap().last && !parts[0].last);
        assert_eq!(re.into_body(), body);
        let mut re = Reassembly::default();
        assert_eq!(re.push(1, &parts[1].body, MAX_RELAY_RESPONSE_BYTES), Err("relay_bad_part"), "hors d'ordre");
        assert_eq!(re.push(0, &parts[0].body, 10), Err("relay_too_large"));
    }

    #[tokio::test]
    async fn cadrage() {
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        write_json(&mut a, &SupervisorMsg::Start(Empty {})).await.unwrap();
        write_keys(&mut a, &KeyFrame { op: KeyOp::Remove, entries: vec![] }.encode().unwrap()).await.unwrap();
        let Frame::Json(j) = read_frame(&mut b).await.unwrap() else { panic!() };
        assert_eq!(decode_json::<SupervisorMsg>(&j).unwrap(), SupervisorMsg::Start(Empty {}));
        assert!(matches!(read_frame(&mut b).await.unwrap(), Frame::Keys(_)));
        // Longueur nulle, genre inconnu, trop grand : refus.
        for head in [[0u8, 0, 0, 0, 1], [0, 0, 0, 2, 9], [0, 0x10, 0, 2, 1]] {
            let (mut a, mut b) = tokio::io::duplex(64);
            tokio::io::AsyncWriteExt::write_all(&mut a, &head).await.unwrap();
            assert_eq!(read_frame(&mut b).await.unwrap_err(), PipeError::BadFrame);
        }
        drop(a);
        assert_eq!(read_frame(&mut b).await.unwrap_err(), PipeError::Closed);
    }

    #[test]
    fn messages_stricts() {
        assert!(decode_json::<SupervisorMsg>(br#"{"type":"start"}"#).is_ok());
        assert!(decode_json::<SupervisorMsg>(br#"{"type":"start","x":1}"#).is_err());
        assert!(decode_json::<WorkerMsg>(br#"{"type":"done","reason":"idle"}"#).is_ok());
        assert!(decode_json::<WorkerMsg>(br#"{"type":"done","reason":"idle","extra":true}"#).is_err());
        assert!(decode_json::<WorkerMsg>(br#"{"type":"keys"}"#).is_err());
        let log = LogMsg {
            level: "info".into(),
            code: "turn_done".into(),
            fields: BTreeMap::from([("steps".into(), Value::from(3))]),
        };
        assert!(log.is_contentless());
        // Compatibilité : `part`/`last` absents = une seule partie.
        let r: SignedResponse = serde_json::from_str(r#"{"id":"r1","status":200,"headers":{},"body":""}"#).unwrap();
        assert!(r.last && r.part == 0);
        let bad = LogMsg {
            level: "info".into(),
            code: "x".into(),
            fields: BTreeMap::from([("texte".into(), Value::from("Bonjour !"))]),
        };
        assert!(!bad.is_contentless());
    }
}
