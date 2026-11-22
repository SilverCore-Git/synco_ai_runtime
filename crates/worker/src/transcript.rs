//! Historique d'une conversation (`StoredMessage[]`, `synco_api/src/services/ai/types.ts`) et son
//! chiffrement champ par champ sous `CK` (docs/plan/03 §6.3).
//!
//! En mémoire, le worker garde le **clair** ; à l'écriture (`PUT …/transcript`), chaque champ de
//! contenu est chiffré au format `gcm1:` avec l'AAD `sessionId:messageId:champ` :
//!
//! | champ | AAD |
//! |---|---|
//! | `content` | `<id>:content` |
//! | `thinking` | `<id>:thinking` |
//! | `toolResult` (JSON) | `<id>:tool_result` |
//! | `toolCalls[i].arguments` (JSON) | `<id>:tool_call_arguments:<toolCalls[i].id>` |
//! | `pendingToolCall.args` (JSON) | `__pending__:pending_tool_call_args` |
//!
//! Restent en clair : `id`, `role`, `toolCallId`, `createdAt`, `usage`,
//! `toolCalls[i].{id,name,category,mutating,status}`, `pendingToolCall.{id,name,category,mutating,interactive}`.
//! C'est exactement ce que lit `decryptGatewaySessionMessages` de `synco_app` (`AIService.ts`).
//!
//! Lecture **tolérante** (formats rétrocompatibles) : un champ en clair est accepté tel quel, un
//! champ illisible est remplacé par un marqueur ; les champs inconnus d'un message sont conservés et
//! réécrits à l'identique.

use serde_json::{Map, Value, json};
use synco_e2ee::session::{self, FieldName, PENDING_MESSAGE_ID, VERSION_PREFIX};
use synco_e2ee::{OsRandom, SymmetricKey};

/// Marqueur d'un contenu illisible (même sens que celui de l'app).
pub const UNREADABLE: &str = "[Contenu illisible.]";

/// Rôle d'un message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Utilisateur.
    User,
    /// Assistant.
    Assistant,
    /// Résultat d'outil.
    Tool,
}

impl Role {
    /// Nom.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::Tool => "tool",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "user" => Some(Self::User),
            "assistant" => Some(Self::Assistant),
            "tool" => Some(Self::Tool),
            _ => None,
        }
    }
}

/// Statut d'un appel d'outil (`ToolCallStatus`, `types.ts:1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolStatus {
    /// En attente d'une décision.
    Pending,
    /// Accepté (exécution à venir, éventuellement après une clé).
    Accepted,
    /// Refusé (utilisateur ou politique).
    Rejected,
    /// En cours (écriture anticipée des outils mutants, 08 §5).
    Executing,
    /// Terminé.
    Done,
    /// Échec.
    Error,
}

impl ToolStatus {
    /// Nom.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Executing => "executing",
            Self::Done => "done",
            Self::Error => "error",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "pending" => Self::Pending,
            "accepted" => Self::Accepted,
            "rejected" => Self::Rejected,
            "executing" => Self::Executing,
            "done" => Self::Done,
            _ => Self::Error,
        }
    }
}

/// Appel d'outil d'un message assistant.
#[derive(Clone, PartialEq)]
pub struct ToolCall {
    /// Identifiant (00 §3.2).
    pub id: String,
    /// Outil.
    pub name: String,
    /// Arguments (clair en mémoire).
    pub arguments: Value,
    /// `server` ou `client`.
    pub category: String,
    /// Mutant.
    pub mutating: bool,
    /// Statut.
    pub status: ToolStatus,
}

impl core::fmt::Debug for ToolCall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ToolCall")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// Un message de l'historique, en clair.
#[derive(Clone, PartialEq)]
pub struct Message {
    /// Identifiant.
    pub id: String,
    /// Rôle.
    pub role: Role,
    /// Texte.
    pub content: Option<String>,
    /// Valeur `gcm1:` d'origine de `content`, réécrite **telle quelle** (message de l'utilisateur
    /// « tel quel », 05 §6.2 ; historique stable d'une écriture à l'autre). À remettre à `None` si
    /// `content` change.
    pub content_sealed: Option<String>,
    /// Raisonnement.
    pub thinking: Option<String>,
    /// Appels d'outils (assistant).
    pub tool_calls: Vec<ToolCall>,
    /// Appel auquel répond ce message (`tool`).
    pub tool_call_id: Option<String>,
    /// Résultat (`tool`).
    pub tool_result: Option<Value>,
    /// Date ISO 8601.
    pub created_at: String,
    /// Usage (clair).
    pub usage: Option<Value>,
    /// Champs inconnus, conservés tels quels.
    pub extra: Map<String, Value>,
}

impl core::fmt::Debug for Message {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Jamais le contenu.
        f.debug_struct("Message")
            .field("id", &self.id)
            .field("role", &self.role)
            .field("tool_calls", &self.tool_calls)
            .finish_non_exhaustive()
    }
}

impl Message {
    /// Message vide d'un rôle.
    #[must_use]
    pub fn new(id: String, role: Role, created_at: String) -> Self {
        Self {
            id,
            role,
            content: None,
            content_sealed: None,
            thinking: None,
            tool_calls: Vec::new(),
            tool_call_id: None,
            tool_result: None,
            created_at,
            usage: None,
            extra: Map::new(),
        }
    }
}

/// Appel en attente (`PendingToolCall`, `types.ts`).
#[derive(Clone, PartialEq)]
pub struct PendingToolCall {
    /// Identifiant de l'appel.
    pub id: String,
    /// Outil.
    pub name: String,
    /// Arguments (clair en mémoire).
    pub args: Value,
    /// Catégorie.
    pub category: String,
    /// Mutant.
    pub mutating: bool,
    /// Interactif.
    pub interactive: bool,
    /// `planId` d'un `propose_actions` (12 §3.4) : `args` est alors le plan, chiffré avec l'AAD du plan
    /// (`sessionId:planId:plan`) au lieu de celle de `pendingToolCall.args`.
    pub plan_id: Option<String>,
}

impl core::fmt::Debug for PendingToolCall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingToolCall").field("id", &self.id).field("name", &self.name).finish_non_exhaustive()
    }
}

/// Échec du chiffrement (identifiant non conforme, aléa indisponible).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeError;

fn enc_text(ck: &SymmetricKey, sid: &str, mid: &str, field: &FieldName, text: &str) -> Result<Value, EncodeError> {
    session::encrypt_field(ck, sid, mid, field, text, &mut OsRandom).map(Value::String).map_err(|_| EncodeError)
}

fn enc_json(ck: &SymmetricKey, sid: &str, mid: &str, field: &FieldName, v: &Value) -> Result<Value, EncodeError> {
    session::encrypt_json_field(ck, sid, mid, field, v, &mut OsRandom).map(Value::String).map_err(|_| EncodeError)
}

/// Chiffre un message pour l'écriture (03 §6.3).
pub fn encode_message(ck: &SymmetricKey, sid: &str, m: &Message) -> Result<Value, EncodeError> {
    let mut o = m.extra.clone();
    o.insert("id".into(), Value::String(m.id.clone()));
    o.insert("role".into(), Value::String(m.role.as_str().into()));
    let content = match (&m.content, &m.content_sealed) {
        (Some(_), Some(sealed)) => Value::String(sealed.clone()),
        (Some(t), None) => enc_text(ck, sid, &m.id, &FieldName::Content, t)?,
        (None, _) => Value::Null,
    };
    o.insert("content".into(), content);
    if let Some(t) = &m.thinking {
        o.insert("thinking".into(), enc_text(ck, sid, &m.id, &FieldName::Thinking, t)?);
    }
    if !m.tool_calls.is_empty() {
        let calls = m
            .tool_calls
            .iter()
            .map(|tc| {
                Ok(json!({
                    "id": tc.id,
                    "name": tc.name,
                    "arguments": enc_json(ck, sid, &m.id, &FieldName::ToolCallArguments(tc.id.clone()), &tc.arguments)?,
                    "category": tc.category,
                    "mutating": tc.mutating,
                    "status": tc.status.as_str(),
                }))
            })
            .collect::<Result<Vec<_>, EncodeError>>()?;
        o.insert("toolCalls".into(), Value::Array(calls));
    }
    if let Some(id) = &m.tool_call_id {
        o.insert("toolCallId".into(), Value::String(id.clone()));
    }
    if let Some(r) = &m.tool_result {
        o.insert("toolResult".into(), enc_json(ck, sid, &m.id, &FieldName::ToolResult, r)?);
    }
    o.insert("createdAt".into(), Value::String(m.created_at.clone()));
    if let Some(u) = &m.usage {
        o.insert("usage".into(), u.clone());
    }
    Ok(Value::Object(o))
}

/// Chiffre tout l'historique.
pub fn encode_messages(ck: &SymmetricKey, sid: &str, messages: &[Message]) -> Result<Vec<Value>, EncodeError> {
    messages.iter().map(|m| encode_message(ck, sid, m)).collect()
}

fn is_gcm1(v: &Value) -> Option<&str> {
    v.as_str().filter(|s| s.starts_with(VERSION_PREFIX))
}

/// Mode de lecture d'un historique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Read {
    /// Schéma `conv-gcm1-v1` (tout historique d'une conversation en mode runtime) : un champ de
    /// contenu qui n'est pas `gcm1:` est **illisible**, jamais repris en clair (sinon l'API
    /// pourrait injecter du contenu ou un appel d'outil non authentifié par `CK`).
    Strict,
    /// Anciens schémas (`null`, `gateway-aes-gcm-v1`) : clair accepté tel quel. Jamais utilisé par
    /// la boucle d'agent.
    Tolerant,
}

fn dec_text(ck: &SymmetricKey, sid: &str, mid: &str, field: &str, v: &Value, mode: Read) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) if s.starts_with(VERSION_PREFIX) => {
            Some(session::decrypt_field(ck, sid, mid, field, s).unwrap_or_else(|_| UNREADABLE.to_owned()))
        }
        Value::String(s) if mode == Read::Tolerant => Some(s.clone()),
        _ if mode == Read::Strict => Some(UNREADABLE.to_owned()),
        _ => None,
    }
}

/// `None` : illisible.
fn dec_json(ck: &SymmetricKey, sid: &str, mid: &str, field: &str, v: &Value, mode: Read) -> Option<Value> {
    match is_gcm1(v) {
        Some(s) => session::decrypt_field(ck, sid, mid, field, s).ok().and_then(|t| serde_json::from_str(&t).ok()),
        None if mode == Read::Strict => None,
        // Ancien format : arguments en chaîne JSON ou déjà en objet.
        None => Some(match v {
            Value::String(s) => serde_json::from_str(s).unwrap_or_else(|_| v.clone()),
            other => other.clone(),
        }),
    }
}

/// Lit un message. `None` pour une entrée sans `id` ni rôle reconnu. En lecture stricte, un appel
/// d'outil dont les arguments sont illisibles passe au statut `error` (jamais exécuté).
#[must_use]
pub fn decode_message(ck: &SymmetricKey, sid: &str, v: &Value, mode: Read) -> Option<Message> {
    let mut o = v.as_object()?.clone();
    let id = o.remove("id")?.as_str()?.to_owned();
    let role = Role::parse(o.remove("role")?.as_str()?)?;
    let created_at = o.remove("createdAt").and_then(|c| c.as_str().map(str::to_owned)).unwrap_or_default();
    let mut m = Message::new(id, role, created_at);
    if let Some(c) = o.remove("content") {
        m.content = dec_text(ck, sid, &m.id, "content", &c, mode);
        if m.content.as_deref() != Some(UNREADABLE) {
            m.content_sealed = is_gcm1(&c).map(str::to_owned);
        }
    }
    if let Some(t) = o.remove("thinking") {
        m.thinking = dec_text(ck, sid, &m.id, "thinking", &t, mode);
    }
    if let Some(calls) = o.remove("toolCalls").and_then(|c| c.as_array().cloned()) {
        for c in calls {
            let Some(id) = c.get("id").and_then(Value::as_str).map(str::to_owned) else { continue };
            let args = c.get("arguments").cloned().unwrap_or(Value::Null);
            let arguments = dec_json(ck, sid, &m.id, &format!("tool_call_arguments:{id}"), &args, mode);
            let status = ToolStatus::parse(c.get("status").and_then(Value::as_str).unwrap_or("error"));
            m.tool_calls.push(ToolCall {
                status: if arguments.is_none() && mode == Read::Strict { ToolStatus::Error } else { status },
                arguments: arguments.unwrap_or_else(|| json!({})),
                id,
                name: c.get("name").and_then(Value::as_str).unwrap_or_default().to_owned(),
                category: c.get("category").and_then(Value::as_str).unwrap_or("server").to_owned(),
                mutating: c.get("mutating").and_then(Value::as_bool).unwrap_or(true),
            });
        }
    }
    m.tool_call_id = o.remove("toolCallId").and_then(|c| c.as_str().map(str::to_owned));
    if let Some(r) = o.remove("toolResult") {
        m.tool_result = Some(
            dec_json(ck, sid, &m.id, "tool_result", &r, mode)
                .unwrap_or_else(|| json!({ "error": "Résultat illisible." })),
        );
    }
    m.usage = o.remove("usage").filter(|u| !u.is_null());
    m.extra = o;
    Some(m)
}

/// Lit tout l'historique.
#[must_use]
pub fn decode_messages(ck: &SymmetricKey, sid: &str, v: &Value, mode: Read) -> Vec<Message> {
    v.as_array().map(|a| a.iter().filter_map(|m| decode_message(ck, sid, m, mode)).collect()).unwrap_or_default()
}

/// Chiffre `pendingToolCall`.
pub fn encode_pending(ck: &SymmetricKey, sid: &str, p: &PendingToolCall) -> Result<Value, EncodeError> {
    let args = match &p.plan_id {
        Some(_) => {
            synco_e2ee::plan::encrypt_plan(ck, &p.args, &mut OsRandom).map(Value::String).map_err(|_| EncodeError)?
        }
        None => enc_json(ck, sid, PENDING_MESSAGE_ID, &FieldName::PendingToolCallArgs, &p.args)?,
    };
    let mut out = json!({
        "id": p.id,
        "name": p.name,
        "args": args,
        "category": p.category,
        "mutating": p.mutating,
        "interactive": p.interactive,
    });
    if let Some(plan_id) = &p.plan_id {
        crate::json_set(&mut out, "planId", json!(plan_id));
    }
    Ok(out)
}

/// Lit `pendingToolCall`. En lecture stricte, des arguments illisibles (ou en clair) font
/// ignorer l'appel en attente.
#[must_use]
pub fn decode_pending(ck: &SymmetricKey, sid: &str, v: &Value, mode: Read) -> Option<PendingToolCall> {
    let o = v.as_object()?;
    // `propose_actions` seulement : `planId` en clair, plan chiffré sous l'AAD du plan, déchiffré
    // strictement (le clair doit porter ce `sessionId` et ce `planId`, 12 §3.4).
    let plan_id = match o.get("planId") {
        None | Some(Value::Null) => None,
        Some(Value::String(id)) if o.get("name").and_then(Value::as_str) == Some("propose_actions") => Some(id.clone()),
        Some(_) => return None,
    };
    let args = match &plan_id {
        Some(plan_id) => {
            let value = o.get("args")?.as_str()?;
            Some(synco_e2ee::plan::decrypt_plan(ck, sid, plan_id, value).ok()?)
        }
        None => {
            dec_json(ck, sid, PENDING_MESSAGE_ID, "pending_tool_call_args", o.get("args").unwrap_or(&Value::Null), mode)
        }
    };
    Some(PendingToolCall {
        plan_id,
        id: o.get("id")?.as_str()?.to_owned(),
        name: o.get("name")?.as_str()?.to_owned(),
        args: if mode == Read::Strict { args? } else { args.unwrap_or_else(|| json!({})) },
        category: o.get("category").and_then(Value::as_str).unwrap_or("server").to_owned(),
        mutating: o.get("mutating").and_then(Value::as_bool).unwrap_or(true),
        interactive: o.get("interactive").and_then(Value::as_bool).unwrap_or(false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "0f0e0d0c-0b0a-4908-8706-050403020100";

    #[test]
    fn aller_retour_et_aad() {
        let ck = SymmetricKey::from_bytes([0xdd; 32]);
        let mut a = Message::new("m1".into(), Role::Assistant, "2026-11-20T10:00:00.000Z".into());
        a.content = Some("Voici".into());
        a.thinking = Some("je réfléchis".into());
        a.tool_calls.push(ToolCall {
            id: "call_1".into(),
            name: "create_task".into(),
            arguments: json!({ "title": "secret" }),
            category: "server".into(),
            mutating: true,
            status: ToolStatus::Executing,
        });
        a.usage = Some(json!({ "totalTokens": 3 }));
        a.extra.insert("attachments".into(), json!([1]));
        let mut t = Message::new("m2".into(), Role::Tool, "2026-11-20T10:00:01.000Z".into());
        t.tool_call_id = Some("call_1".into());
        t.tool_result = Some(json!({ "ok": "résultat" }));
        let enc = encode_messages(&ck, SID, &[a.clone(), t.clone()]).unwrap();
        let text = serde_json::to_string(&enc).unwrap();
        for clear in ["Voici", "réfléchis", "secret", "résultat"] {
            assert!(!text.contains(clear), "{clear} en clair");
        }
        assert_eq!(enc[0]["toolCalls"][0]["status"], "executing");
        assert_eq!(enc[0]["attachments"], json!([1]));
        // AAD : champ attendu par l'app.
        let args = session::decrypt_field(
            &ck,
            SID,
            "m1",
            "tool_call_arguments:call_1",
            enc[0]["toolCalls"][0]["arguments"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(args, r#"{"title":"secret"}"#);
        let mut back = decode_messages(&ck, SID, &Value::Array(enc.clone()), Read::Strict);
        // Chiffré d'origine gardé et réécrit tel quel.
        assert_eq!(back[0].content_sealed.as_deref(), enc[0]["content"].as_str());
        assert_eq!(encode_message(&ck, SID, &back[0]).unwrap()["content"], enc[0]["content"]);
        back[0].content_sealed = None;
        assert_eq!(back, vec![a, t]);
    }

    #[test]
    fn lecture_tolerante() {
        let ck = SymmetricKey::from_bytes([0xdd; 32]);
        let v = json!([
            { "id": "u1", "role": "user", "content": "en clair (ancien format)", "createdAt": "x" },
            { "id": "a1", "role": "assistant", "content": "gcm1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "createdAt": "x",
              "toolCalls": [{ "id": "c1", "name": "n", "arguments": "{\"q\":1}", "category": "client", "mutating": false, "status": "done" }] },
            { "role": "user" },
            { "id": "z", "role": "system", "content": "?" }
        ]);
        let m = decode_messages(&ck, SID, &v, Read::Tolerant);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].content.as_deref(), Some("en clair (ancien format)"));
        assert_eq!(m[1].content.as_deref(), Some(UNREADABLE));
        assert_eq!(m[1].tool_calls[0].arguments, json!({ "q": 1 }));
        // Schéma conv-gcm1-v1 : le clair est illisible, l'appel aux arguments en clair n'est plus
        // exécutable.
        let m = decode_messages(&ck, SID, &v, Read::Strict);
        assert_eq!(m[0].content.as_deref(), Some(UNREADABLE));
        assert_eq!(m[1].tool_calls[0].arguments, json!({}));
        assert_eq!(m[1].tool_calls[0].status, ToolStatus::Error);
        let forged = json!({ "id": "c1", "name": "create_task", "args": { "title": "x" }, "category": "server", "mutating": true });
        assert_eq!(decode_pending(&ck, SID, &forged, Read::Strict), None);
        let p = PendingToolCall {
            id: "c1".into(),
            name: "create_task".into(),
            args: json!({ "title": "t" }),
            category: "server".into(),
            mutating: true,
            interactive: false,
            plan_id: None,
        };
        let e = encode_pending(&ck, SID, &p).unwrap();
        assert!(e["args"].as_str().unwrap().starts_with("gcm1:"));
        assert_eq!(decode_pending(&ck, SID, &e, Read::Strict), Some(p));
    }

    #[test]
    fn appel_en_attente_d_un_plan() {
        let ck = SymmetricKey::from_bytes([0xdd; 32]);
        let plan_id = "3c2b1a09-8f7e-4d6c-9b5a-493827161504";
        let plan = json!({ "v": 1, "planId": plan_id, "sessionId": SID, "toolCallId": "call_7", "createdAt": 1, "expiresAt": 2,
            "summary": "secret", "actions": [] });
        let p = PendingToolCall {
            id: "call_7".into(),
            name: "propose_actions".into(),
            args: plan,
            category: "client".into(),
            mutating: true,
            interactive: false,
            plan_id: Some(plan_id.into()),
        };
        let e = encode_pending(&ck, SID, &p).unwrap();
        assert_eq!(e["planId"], plan_id, "planId en clair");
        assert!(!e.to_string().contains("secret"));
        // AAD du plan (`sessionId:planId:plan`), pas celle de `pendingToolCall.args`.
        let clear = synco_e2ee::plan::decrypt_plan(&ck, SID, plan_id, e["args"].as_str().unwrap()).unwrap();
        assert_eq!(clear["summary"], "secret");
        assert_eq!(decode_pending(&ck, SID, &e, Read::Strict), Some(p.clone()));
        // Un plan rejoué sous un autre `planId` (même chiffré) ou sous un autre nom d'outil est refusé.
        let mut swapped = e.clone();
        swapped["planId"] = json!("4d3c2b1a-8f7e-4d6c-9b5a-493827161505");
        assert_eq!(decode_pending(&ck, SID, &swapped, Read::Strict), None);
        let mut renamed = e.clone();
        renamed["name"] = json!("create_task");
        assert_eq!(decode_pending(&ck, SID, &renamed, Read::Strict), None);
        // Un plan en clair n'est jamais lu.
        let mut clear_args = e;
        clear_args["args"] = p.args.clone();
        assert_eq!(decode_pending(&ck, SID, &clear_args, Read::Strict), None);
    }
}
