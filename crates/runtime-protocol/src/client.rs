//! WebSocket client ↔ runtime (docs/plan/05-flux-client-runtime.md).
//!
//! Client → runtime : désérialisation **stricte** (champ inconnu, binaire, trop grand → `4400`).
//! Runtime → client : `ready`, `queued`, `pong` sont construits par le superviseur ; les évènements
//! de déroulement viennent du worker, déjà chiffrés, et ne sont **pas lus** par le superviseur
//! au-delà de `t`, `epoch` et `seq` ([`check_worker_event`]).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ids::is_identifier;

/// Taille maximale d'une trame client → runtime (05 §2).
pub const MAX_CLIENT_FRAME_BYTES: usize = 256 * 1024;
/// Taille maximale d'une trame runtime → client.
pub const MAX_RUNTIME_FRAME_BYTES: usize = 1024 * 1024;
/// Délai du `hello` (s).
pub const HELLO_TIMEOUT_SECS: u64 = 10;
/// Connexions simultanées par conversation.
pub const MAX_CONNECTIONS_PER_CONVERSATION: usize = 5;
/// Débit client → runtime : trames par fenêtre.
pub const RATE_FRAMES: u32 = 20;
/// Débit client → runtime : fenêtre (s).
pub const RATE_WINDOW_SECS: u64 = 10;
/// Sans trame reçue pendant ce délai, la connexion est fermée (05 §6.3).
pub const IDLE_TIMEOUT_SECS: u64 = 60;

/// Codes de fermeture (05 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseCode {
    /// `4400 bad_frame`.
    BadFrame,
    /// `4401` + code de ticket.
    Ticket,
    /// `4403 forbidden` / `revoked`.
    Forbidden,
    /// `4404 not_runtime`.
    NotRuntime,
    /// `4408 hello_timeout`.
    HelloTimeout,
    /// `4409 too_many_connections`.
    TooManyConnections,
    /// `4429 rate_limited`.
    RateLimited,
    /// `4500 internal`.
    Internal,
    /// `4503 shutting_down`.
    ShuttingDown,
}

impl CloseCode {
    /// Valeur numérique.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::BadFrame => 4400,
            Self::Ticket => 4401,
            Self::Forbidden => 4403,
            Self::NotRuntime => 4404,
            Self::HelloTimeout => 4408,
            Self::TooManyConnections => 4409,
            Self::RateLimited => 4429,
            Self::Internal => 4500,
            Self::ShuttingDown => 4503,
        }
    }

    /// Raison par défaut (code machine).
    #[must_use]
    pub const fn default_reason(self) -> &'static str {
        match self {
            Self::BadFrame => "bad_frame",
            Self::Ticket => "ticket_invalid",
            Self::Forbidden => "forbidden",
            Self::NotRuntime => "not_runtime",
            Self::HelloTimeout => "hello_timeout",
            Self::TooManyConnections => "too_many_connections",
            Self::RateLimited => "rate_limited",
            Self::Internal => "internal",
            Self::ShuttingDown => "shutting_down",
        }
    }
}

/// Position de reprise `{ epoch, seq }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resume {
    /// Époque.
    pub epoch: u64,
    /// Dernier `seq` reçu.
    pub seq: u64,
}

/// Décision sur un outil.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Accepter.
    Accept,
    /// Refuser.
    Reject,
}

/// Trame client → runtime (05 §6), sans `v` (vérifié à part).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum ClientFrame {
    /// Première trame : ticket et reprise.
    Hello(Hello),
    /// Message utilisateur (contenu chiffré).
    Message(MessageItem),
    /// Décision.
    Confirm(ConfirmItem),
    /// Réponse à `ask_question` (valeur chiffrée).
    Answer(AnswerItem),
    /// Référence d'une image envoyée.
    Upload(UploadItem),
    /// Annulation du tour.
    Cancel(CancelItem),
    /// Maintien.
    Ping(Ping),
}

/// `hello`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    /// Ticket `srt1` (jamais journalisé).
    pub ticket: String,
    /// Dernière position reçue, ou `null`.
    pub resume: Option<Resume>,
}

impl core::fmt::Debug for Hello {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Hello").field("ticket", &"***").field("resume", &self.resume).finish()
    }
}

/// `message`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MessageItem {
    /// UUID v4 tiré par le client.
    pub id: String,
    /// `gcm1:` chiffré par `CK`.
    pub content: String,
    /// ISO 8601.
    pub created_at: String,
}

/// `confirm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConfirmItem {
    /// Appel d'outil.
    pub tool_call_id: String,
    /// Décision.
    pub decision: Decision,
}

/// `answer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AnswerItem {
    /// Appel d'outil.
    pub tool_call_id: String,
    /// `gcm1:` chiffré.
    pub value: String,
}

/// `upload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UploadItem {
    /// Appel d'outil.
    pub tool_call_id: String,
    /// Référence (format fixé par L12).
    #[serde(rename = "ref")]
    pub reference: String,
}

/// `cancel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelItem {
    /// UUID v4.
    pub id: String,
}

/// `ping`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ping {}

/// Trame client invalide (→ `4400 bad_frame`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadFrame;

/// Taille maximale d'une valeur `gcm1:` dans une trame client (la trame entière est bornée à 256 Kio).
const MAX_GCM1_CHARS: usize = 240 * 1024;

fn gcm1(v: &str) -> bool {
    v.starts_with("gcm1:") && v.len() <= MAX_GCM1_CHARS
}

impl ClientFrame {
    /// Analyse stricte d'une trame texte : taille, `v` = 1, `t` connu, aucun champ inconnu,
    /// identifiants conformes (00 §3.2), valeurs chiffrées au format `gcm1:`.
    pub fn parse(text: &str) -> Result<Self, BadFrame> {
        if text.len() > MAX_CLIENT_FRAME_BYTES {
            return Err(BadFrame);
        }
        let mut value: Value = serde_json::from_str(text).map_err(|_| BadFrame)?;
        let obj = value.as_object_mut().ok_or(BadFrame)?;
        if obj.remove("v").and_then(|v| v.as_u64()) != Some(1) {
            return Err(BadFrame);
        }
        let frame: Self = serde_json::from_value(value).map_err(|_| BadFrame)?;
        if frame.is_valid() { Ok(frame) } else { Err(BadFrame) }
    }

    fn is_valid(&self) -> bool {
        match self {
            Self::Hello(h) => !h.ticket.is_empty() && h.ticket.len() <= crate::ticket::MAX_LENGTH,
            Self::Message(m) => is_identifier(&m.id) && gcm1(&m.content) && (1..=40).contains(&m.created_at.len()),
            Self::Confirm(c) => is_identifier(&c.tool_call_id),
            Self::Answer(a) => is_identifier(&a.tool_call_id) && gcm1(&a.value),
            Self::Upload(u) => is_identifier(&u.tool_call_id) && (1..=512).contains(&u.reference.len()),
            Self::Cancel(c) => is_identifier(&c.id),
            Self::Ping(_) => true,
        }
    }

    /// Élément de boîte de réception (05 §6.2) : `id` idempotent et corps de
    /// `POST /api/runtime/v1/conversations/:sessionId/inbox` (`{ t, … }`, sans `v`).
    /// `None` pour `hello` et `ping`.
    #[must_use]
    pub fn inbox_item(&self) -> Option<InboxItem> {
        let id = match self {
            Self::Message(m) => m.id.clone(),
            Self::Confirm(c) => format!("confirm:{}", c.tool_call_id),
            Self::Answer(a) => format!("answer:{}", a.tool_call_id),
            Self::Upload(u) => format!("upload:{}", u.tool_call_id),
            Self::Cancel(c) => format!("cancel:{}", c.id),
            Self::Hello(_) | Self::Ping(_) => return None,
        };
        let body = serde_json::to_value(self).ok()?;
        Some(InboxItem { id, body })
    }
}

/// Élément de boîte prêt à déposer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxItem {
    /// Identifiant idempotent (`queued.id`).
    pub id: String,
    /// Trame `{ t, … }` (champs encore chiffrés).
    pub body: Value,
}

/// Mode de `ready`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadyMode {
    /// Le tampon rejoue la suite.
    Replay,
    /// Un `snapshot` suit.
    Snapshot,
    /// Aucun worker : l'historique de l'API suffit.
    Idle,
    /// Relire l'historique puis se reconnecter.
    Reload,
}

/// `ready` (05 §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready {
    /// Statut de la conversation (08).
    pub status: String,
    /// Révision enregistrée.
    pub rev: u64,
    /// Époque courante.
    pub epoch: u64,
    /// Dernier `seq` émis.
    pub last_seq: u64,
    /// Mode.
    pub mode: ReadyMode,
}

fn json_str(s: &str) -> String {
    Value::from(s).to_string()
}

impl ReadyMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Replay => "replay",
            Self::Snapshot => "snapshot",
            Self::Idle => "idle",
            Self::Reload => "reload",
        }
    }
}

impl Ready {
    /// Trame JSON (`v` et `t` en tête).
    #[must_use]
    pub fn to_frame(&self) -> String {
        format!(
            r#"{{"v":1,"t":"ready","status":{},"rev":{},"epoch":{},"lastSeq":{},"mode":"{}"}}"#,
            json_str(&self.status),
            self.rev,
            self.epoch,
            self.last_seq,
            self.mode.as_str()
        )
    }
}

/// Trame `queued` (05 §5.4), envoyée après le dépôt durable dans l'API.
#[must_use]
pub fn queued_frame(id: &str) -> String {
    format!(r#"{{"v":1,"t":"queued","id":{}}}"#, json_str(id))
}

/// Trame `pong`.
#[must_use]
pub fn pong_frame() -> String {
    r#"{"v":1,"t":"pong"}"#.to_owned()
}

/// Types d'évènement que le worker peut émettre (05 §5.2, §5.3).
pub const WORKER_EVENT_TYPES: [&str; 8] =
    ["snapshot", "text", "thinking", "tool_call", "tool_result", "status", "usage", "error"];

/// Position d'un évènement de worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventPosition {
    /// Époque.
    pub epoch: u64,
    /// Séquence.
    pub seq: u64,
}

/// Contrôle minimal d'un évènement de worker avant diffusion : objet, `v` = 1, `t` connu, `epoch`
/// et `seq` entiers, taille ≤ 1 Mio. Le reste (contenu chiffré) n'est pas lu.
pub fn check_worker_event(event: &Value) -> Result<EventPosition, BadFrame> {
    let obj = event.as_object().ok_or(BadFrame)?;
    let t = obj.get("t").and_then(Value::as_str).ok_or(BadFrame)?;
    if obj.get("v").and_then(Value::as_u64) != Some(1) || !WORKER_EVENT_TYPES.contains(&t) {
        return Err(BadFrame);
    }
    let epoch = obj.get("epoch").and_then(Value::as_u64).ok_or(BadFrame)?;
    let seq = obj.get("seq").and_then(Value::as_u64).ok_or(BadFrame)?;
    Ok(EventPosition { epoch, seq })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trames_client() {
        let h = ClientFrame::parse(r#"{"v":1,"t":"hello","ticket":"srt1.a.b.c","resume":null}"#).unwrap();
        assert!(matches!(h, ClientFrame::Hello(_)));
        assert!(format!("{h:?}").contains("***"), "ticket masqué");
        assert!(!format!("{h:?}").contains("srt1"));
        let m = ClientFrame::parse(
            r#"{"v":1,"t":"message","id":"3c2b1a09-8f7e-4d6c-9b5a-493827161504","content":"gcm1:AAAA","createdAt":"2026-11-18T10:00:00.000Z"}"#,
        )
        .unwrap();
        let item = m.inbox_item().unwrap();
        assert_eq!(item.id, "3c2b1a09-8f7e-4d6c-9b5a-493827161504");
        assert_eq!(item.body["t"], "message");
        assert!(item.body.get("v").is_none());
        assert_eq!(item.body["createdAt"], "2026-11-18T10:00:00.000Z");
        let c = ClientFrame::parse(r#"{"v":1,"t":"confirm","toolCallId":"call_1","decision":"accept"}"#).unwrap();
        assert_eq!(c.inbox_item().unwrap().id, "confirm:call_1");
        assert!(ClientFrame::parse(r#"{"v":1,"t":"ping"}"#).is_ok());
    }

    #[test]
    fn trames_client_refusees() {
        for bad in [
            r#"{"t":"ping"}"#,
            r#"{"v":2,"t":"ping"}"#,
            r#"{"v":1,"t":"ping","x":1}"#,
            r#"{"v":1,"t":"inconnu"}"#,
            r#"{"v":1,"t":"hello","ticket":"x","resume":null,"admin":true}"#,
            r#"{"v":1,"t":"message","id":"a|b","content":"gcm1:AA","createdAt":"x"}"#,
            r#"{"v":1,"t":"message","id":"a","content":"en clair","createdAt":"x"}"#,
            r#"{"v":1,"t":"confirm","toolCallId":"c","decision":"maybe"}"#,
            r#"[]"#,
            "pas du json",
        ] {
            assert_eq!(ClientFrame::parse(bad), Err(BadFrame), "{bad}");
        }
        let big = format!(r#"{{"v":1,"t":"cancel","id":"{}"}}"#, "a".repeat(MAX_CLIENT_FRAME_BYTES));
        assert_eq!(ClientFrame::parse(&big), Err(BadFrame));
    }

    #[test]
    fn trames_runtime() {
        let r = Ready { status: "idle".into(), rev: 12, epoch: 1, last_seq: 0, mode: ReadyMode::Idle }.to_frame();
        assert_eq!(r, r#"{"v":1,"t":"ready","status":"idle","rev":12,"epoch":1,"lastSeq":0,"mode":"idle"}"#);
        assert_eq!(queued_frame("x"), r#"{"v":1,"t":"queued","id":"x"}"#);
        let ev: Value =
            serde_json::from_str(r#"{"v":1,"t":"text","epoch":2,"seq":3,"messageId":"m","delta":"gcm1:x"}"#).unwrap();
        assert_eq!(check_worker_event(&ev), Ok(EventPosition { epoch: 2, seq: 3 }));
        let bad: Value = serde_json::from_str(r#"{"v":1,"t":"ready","epoch":2,"seq":3}"#).unwrap();
        assert!(check_worker_event(&bad).is_err());
    }
}
