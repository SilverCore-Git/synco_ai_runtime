//! Banc d'essai du worker : **API simulée** (routes du canal 04 §4.2, §4.3, §5 avec leurs
//! contrôles de bail et de format chiffré), **superviseur simulé** (pipe 06 : poignée de main,
//! relais `signed_request` en parties, `created_key` avec une `csk` et une `DK` de test) et
//! **LLM simulé** (serveur HTTP sur socket Unix, comme le mandataire, qui rejoue des flux SSE
//! enregistrés).

#![allow(dead_code, reason = "chaque fichier de test n'utilise qu'une partie du banc")]

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use runtime_protocol::pipe::{
    self, CreatedKeyEnvelope, CreatedKeyMsg, Empty, Frame, Init, KeyEntry, KeyFrame, KeyKind, KeyOp, LlmConfig,
    LlmProvider, ReasoningEffort, Reassembly, SignedResponse, SupervisorMsg, ToolPolicy, WorkerLimits, WorkerMsg,
};
use serde_json::{Value, json};
use synco_e2ee::delegation::{DelegationContext, DelegationKey, EntryKind, Scope};
use synco_e2ee::ec::EcSigningKey;
use synco_e2ee::session::{self, FieldName};
use synco_e2ee::{OsRandom, SymmetricKey};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{Notify, mpsc};
use zeroize::Zeroizing;

pub const SID: &str = "0f0e0d0c-0b0a-4908-8706-050403020100";
pub const USER: &str = "66666666-7777-4888-9999-aaaaaaaaaaaa";
pub const MEMBER: &str = "77777777-7777-4888-9999-bbbbbbbbbbbb";
pub const ORG: &str = "cm3orgexample000000000001";
pub const RUNTIME: &str = "5e4d3c2b-1a09-4f8e-9d7c-6b5a49382716";
pub const AUTH: &str = "9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a";
pub const DELEGATION: &str = "d1e2f3a4-b5c6-4d7e-8f90-a1b2c3d4e5f6";
pub const SPACE: &str = "cm3spaceexample0000000001";
pub const THREAD: &str = "cm3threadexample000000001";
pub const CK: [u8; 32] = [0xdd; 32];
pub const SPACE_KEY: [u8; 32] = [0x5a; 32];
pub const THREAD_KEY: [u8; 32] = [0xbb; 32];
pub const PREFIX: &str = "/api/runtime/v1";

pub fn ck() -> SymmetricKey {
    SymmetricKey::from_bytes(CK)
}

/// Manifeste de test (extrait fidèle de `GET /ai/tools`).
pub fn manifest() -> Value {
    json!([
        { "name": "create_task", "description": "Créer une tâche.", "category": "server", "mutating": true, "interactive": false,
          "parameters": { "type": "object", "properties": { "title": { "type": "string" } }, "required": ["title"] } },
        { "name": "list_spaces", "description": "Lister les espaces.", "category": "server", "mutating": false, "interactive": false,
          "parameters": { "type": "object", "properties": {} } },
        { "name": "delete_task", "description": "Supprimer une tâche.", "category": "server", "mutating": true, "interactive": false,
          "parameters": { "type": "object", "properties": { "taskId": { "type": "string" } } } },
        { "name": "search_messages", "description": "Rechercher.", "category": "client", "mutating": false, "interactive": false,
          "parameters": { "type": "object", "properties": { "query": { "type": "string" } }, "required": ["query"] } },
        { "name": "create_thread", "description": "Créer des salons.", "category": "client", "mutating": true, "interactive": false,
          "parameters": { "type": "object", "properties": { "threads": { "type": "array" } } } },
        { "name": "create_file", "description": "Créer un fichier.", "category": "client", "mutating": true, "interactive": false,
          "parameters": { "type": "object" } },
        { "name": "read_documentation", "description": "Doc.", "category": "client", "mutating": false, "interactive": false,
          "parameters": { "type": "object" } },
        { "name": "ask_question", "description": "Question.", "category": "client", "mutating": false, "interactive": true,
          "parameters": { "type": "object", "properties": { "question": { "type": "string" } } } },
        { "name": "request_image_upload", "description": "Image.", "category": "client", "mutating": false, "interactive": true,
          "parameters": { "type": "object" } }
    ])
}

/// Clé RSA de test (WebCrypto) : `publicJwk`, `privateJwk`.
pub fn rsa_fixture() -> Value {
    serde_json::from_str(include_str!("../fixtures/test-member-rsa.json")).unwrap()
}

/// Requête vue par l'API simulée.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub body: String,
}

/// État de l'API simulée.
#[derive(Debug, Default)]
pub struct ApiState {
    pub messages: Vec<Value>,
    pub rev: u64,
    pub status: String,
    pub pending: Value,
    pub lease_epoch: u64,
    pub last_error: Option<String>,
    pub awaiting_key: Option<String>,
    pub lease_released: bool,
    pub lease_conflict: bool,
    pub renewals: u32,
    /// `(id, trame { t, … }, consommé)`.
    pub inbox: Vec<(String, Value, bool)>,
    pub tools: Value,
    pub deny: Vec<String>,
    pub tool_runs: Vec<(String, Value)>,
    pub tool_data: HashMap<String, Value>,
    /// Outil dont l'exécution ne répond jamais (test de `kill -9`).
    pub block_tool: Option<String>,
    pub transcripts: Vec<Value>,
    pub statuses: Vec<(String, Option<String>)>,
    pub events: Vec<Value>,
    pub pushes: Vec<String>,
    pub members: Value,
    pub threads_created: Vec<Value>,
    pub envelopes: Vec<(String, Value)>,
    pub entries: Vec<(String, Value)>,
    pub search_index: HashMap<String, Value>,
    pub seen: Vec<Seen>,
    pub refused: Vec<String>,
    pub tickets: u32,
}

impl ApiState {
    fn gcm1_ok(v: Option<&Value>) -> bool {
        match v {
            None | Some(Value::Null) => true,
            Some(Value::String(s)) => s.starts_with("gcm1:"),
            _ => false,
        }
    }

    /// Contrôle de l'API (`checkConvContent`) : tout contenu en `gcm1:`.
    fn transcript_ok(messages: &[Value]) -> bool {
        messages.iter().all(|m| {
            Self::gcm1_ok(m.get("content"))
                && Self::gcm1_ok(m.get("thinking"))
                && Self::gcm1_ok(m.get("toolResult"))
                && m.get("toolCalls")
                    .and_then(Value::as_array)
                    .is_none_or(|c| c.iter().all(|tc| Self::gcm1_ok(tc.get("arguments"))))
        })
    }
}

/// API simulée.
#[derive(Clone, Default)]
pub struct FakeApi {
    pub st: Arc<Mutex<ApiState>>,
    /// Signalé quand l'outil bloqué est appelé.
    pub blocked: Arc<Notify>,
    next_thread: Arc<Mutex<u32>>,
}

fn err(status: u16, code: &str) -> (u16, Value) {
    (status, json!({ "error": code }))
}

impl FakeApi {
    pub fn new() -> Self {
        let api = Self::default();
        api.with(|st| {
            st.status = "idle".into();
            st.lease_epoch = 1;
            st.pending = Value::Null;
            st.tools = manifest();
            let rsa = rsa_fixture();
            st.members = json!([
                { "userId": USER, "publicKey": rsa["publicJwk"].to_string(), "publicSignKey": null },
                { "userId": MEMBER, "publicKey": rsa["publicJwk"].to_string(), "publicSignKey": null },
                { "userId": "bad-key", "publicKey": "pas une clé", "publicSignKey": null }
            ]);
        });
        api
    }

    pub fn with<T>(&self, f: impl FnOnce(&mut ApiState) -> T) -> T {
        f(&mut self.st.lock().unwrap())
    }

    /// Dépose un message utilisateur chiffré (comme `POST …/inbox`).
    pub fn deposit_message(&self, id: &str, text: &str) -> Value {
        let frame = message_frame(id, text);
        self.with(|st| st.inbox.push((id.to_owned(), frame.clone(), false)));
        frame
    }

    pub fn deposit(&self, id: &str, frame: Value) {
        self.with(|st| st.inbox.push((id.to_owned(), frame, false)));
    }

    pub async fn handle(&self, method: &str, path: &str, body: &[u8]) -> (u16, Value) {
        let text = String::from_utf8_lossy(body).into_owned();
        let json: Value =
            if body.is_empty() { Value::Null } else { serde_json::from_slice(body).unwrap_or(Value::Null) };
        let route = path.strip_prefix(PREFIX).unwrap_or(path).to_owned();
        let (route_path, query) = route.split_once('?').map_or((route.as_str(), ""), |(a, b)| (a, b));
        let segs: Vec<String> = route_path.trim_start_matches('/').split('/').map(str::to_owned).collect();
        let segs: Vec<&str> = segs.iter().map(String::as_str).collect();
        self.with(|st| st.seen.push(Seen { method: method.into(), path: path.into(), body: text }));
        let lease_ok = |st: &ApiState, b: &Value| {
            b.get("leaseEpoch").and_then(Value::as_u64) == Some(st.lease_epoch) && !st.lease_conflict
        };
        match (method, segs.as_slice()) {
            ("POST", ["tickets", "llm"]) => self.with(|st| {
                st.tickets += 1;
                (200, json!({ "ticket": format!("sgt1.test{}", st.tickets), "expiresAt": "2030-01-01T00:00:00.000Z", "url": "https://gw.example.com" }))
            }),
            ("GET", ["e2ee", "members", "keys"]) => self.with(|st| (200, json!({ "members": st.members }))),
            ("GET", ["e2ee", "search-index", "workspace", ws]) => self.with(|st| match st.search_index.get(*ws) {
                Some(v) => (200, v.clone()),
                None => err(403, "key_not_delegated"),
            }),
            ("POST", ["e2ee", "threads"]) => {
                let n = {
                    let mut n = self.next_thread.lock().unwrap();
                    *n += 1;
                    *n
                };
                self.with(|st| {
                    if !lease_ok(st, &json) {
                        return err(409, "lease_conflict");
                    }
                    if json.get("commitment").is_some() || json.get("creatorId").is_some() {
                        return err(400, "invalid_body");
                    }
                    let id = format!("cm3threadnew{n:013}");
                    st.threads_created.push(json.clone());
                    (201, json!({ "id": id, "name": json["name"], "type": json["type"], "workspaceId": json.get("spaceId") }))
                })
            }
            ("POST", ["e2ee", "threads", tid, "key-envelope"]) => self.with(|st| {
                if !lease_ok(st, &json) || json["ctx"] != format!("thread:{tid}") {
                    return err(400, "invalid_body");
                }
                st.envelopes.push(((*tid).to_owned(), json.clone()));
                (200, json!({ "threadId": tid, "updated": 1 }))
            }),
            ("POST", ["delegations", d, "entries"]) => self.with(|st| {
                st.entries.push(((*d).to_owned(), json.clone()));
                (201, json!({ "added": 1 }))
            }),
            (m, ["conversations", sid, rest @ ..]) if *sid == SID => self.conv(m, rest, query, &json).await,
            _ => err(404, "not_found"),
        }
    }

    async fn conv(&self, method: &str, rest: &[&str], query: &str, b: &Value) -> (u16, Value) {
        let lease_ok =
            |st: &ApiState| b.get("leaseEpoch").and_then(Value::as_u64) == Some(st.lease_epoch) && !st.lease_conflict;
        match (method, rest) {
            ("GET", []) => self.with(|st| {
                (200, json!({ "id": SID, "title": null, "messages": st.messages, "rev": st.rev, "status": st.status,
                    "pendingToolCall": st.pending, "encryptionScheme": "conv-gcm1-v1", "leaseEpoch": st.lease_epoch,
                    "lastErrorCode": st.last_error, "awaitingKey": st.awaiting_key }))
            }),
            ("POST", ["lease"]) => self.with(|st| {
                st.renewals += 1;
                if lease_ok(st) { (200, json!({ "leaseEpoch": st.lease_epoch, "expiresAt": "2030-01-01T00:00:00.000Z" })) } else { err(409, "lease_conflict") }
            }),
            ("DELETE", ["lease"]) => self.with(|st| {
                st.lease_released = true;
                (204, Value::Null)
            }),
            ("PUT", ["transcript"]) => self.with(|st| {
                if !lease_ok(st) {
                    st.refused.push("lease_conflict".into());
                    return err(409, "lease_conflict");
                }
                if b["baseRev"].as_u64() != Some(st.rev) {
                    st.refused.push("rev_conflict".into());
                    return err(409, "rev_conflict");
                }
                let status = b["status"].as_str().unwrap_or_default().to_owned();
                let messages = b["messages"].as_array().cloned().unwrap_or_default();
                let awaiting_ok = (status == "awaiting_key") == b.get("awaitingKey").is_some();
                if status == "queued" || !awaiting_ok || !ApiState::transcript_ok(&messages) {
                    st.refused.push("invalid_body".into());
                    return err(400, "invalid_body");
                }
                if b["pendingToolCall"].get("args").is_some_and(|a| !a.as_str().is_some_and(|s| s.starts_with("gcm1:"))) {
                    return err(400, "invalid_body");
                }
                for c in b["consumedInbox"].as_array().cloned().unwrap_or_default() {
                    for item in &mut st.inbox {
                        if Some(item.0.as_str()) == c.as_str() {
                            item.2 = true;
                        }
                    }
                }
                st.messages = messages;
                st.pending = b["pendingToolCall"].clone();
                st.last_error = b.get("error").and_then(Value::as_str).map(str::to_owned);
                st.awaiting_key = b.get("awaitingKey").and_then(Value::as_str).map(str::to_owned);
                st.events.extend(b.get("events").and_then(Value::as_array).cloned().unwrap_or_default());
                st.status.clone_from(&status);
                st.statuses.push((status, st.last_error.clone()));
                st.rev += 1;
                st.transcripts.push(b.clone());
                (200, json!({ "rev": st.rev }))
            }),
            ("POST", ["status"]) => self.with(|st| {
                if !lease_ok(st) {
                    return err(409, "lease_conflict");
                }
                let status = b["status"].as_str().unwrap_or_default().to_owned();
                st.last_error = b.get("error").and_then(Value::as_str).map(str::to_owned);
                st.events.extend(b.get("events").and_then(Value::as_array).cloned().unwrap_or_default());
                st.status.clone_from(&status);
                st.statuses.push((status.clone(), st.last_error.clone()));
                (200, json!({ "status": status }))
            }),
            ("GET", ["inbox"]) => self.with(|st| {
                let after = query.strip_prefix("after=");
                let mut skipping = after.is_some();
                let items: Vec<Value> = st
                    .inbox
                    .iter()
                    .filter(|(id, _, consumed)| {
                        if skipping {
                            if Some(id.as_str()) == after {
                                skipping = false;
                            }
                            return false;
                        }
                        !consumed
                    })
                    .map(|(id, frame, _)| {
                        let mut payload = frame.clone();
                        let kind = payload.as_object_mut().unwrap().remove("t").unwrap();
                        json!({ "id": id, "kind": kind, "source": "api", "createdAt": "2026-11-20T00:00:00.000Z", "payload": payload })
                    })
                    .collect();
                (200, json!({ "items": items }))
            }),
            ("GET", ["tools"]) => self.with(|st| (200, st.tools.clone())),
            ("POST", ["tools", name, "execute"]) => {
                let blocked = self.with(|st| {
                    if !lease_ok(st) {
                        return Err(err(409, "lease_conflict"));
                    }
                    if st.deny.iter().any(|d| d == name) {
                        return Err(err(403, "tool_denied_by_policy"));
                    }
                    st.tool_runs.push(((*name).to_owned(), b.get("args").cloned().unwrap_or(Value::Null)));
                    Ok(st.block_tool.as_deref() == Some(*name))
                });
                match blocked {
                    Err(e) => e,
                    Ok(true) => {
                        self.blocked.notify_one();
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        err(500, "internal")
                    }
                    Ok(false) => self.with(|st| {
                        let data = st.tool_data.get(*name).cloned().unwrap_or_else(|| json!({ "id": "task-1", "title": "ok" }));
                        (200, json!({ "ok": true, "data": data }))
                    }),
                }
            }
            ("POST", ["push"]) => self.with(|st| {
                st.pushes.push(b["type"].as_str().unwrap_or_default().to_owned());
                (202, json!({ "sent": true }))
            }),
            _ => err(404, "not_found"),
        }
    }

    /// Historique déchiffré (comme le lit l'app).
    pub fn clear_messages(&self) -> Vec<Value> {
        let messages = self.with(|st| st.messages.clone());
        messages.iter().map(decrypt_message).collect()
    }
}

/// Déchiffre un `StoredMessage` persisté (AAD de 03 §6.3).
pub fn decrypt_message(m: &Value) -> Value {
    let k = ck();
    let id = m["id"].as_str().unwrap().to_owned();
    let mut out = m.clone();
    let dec = |field: &str, v: &Value| -> Value {
        match v.as_str() {
            Some(s) if s.starts_with("gcm1:") => json!(session::decrypt_field(&k, SID, &id, field, s).unwrap()),
            _ => v.clone(),
        }
    };
    out["content"] = dec("content", &m["content"]);
    if m.get("thinking").is_some() {
        out["thinking"] = dec("thinking", &m["thinking"]);
    }
    if let Some(r) = m.get("toolResult") {
        out["toolResult"] = serde_json::from_str(dec("tool_result", r).as_str().unwrap()).unwrap();
    }
    if let Some(calls) = m.get("toolCalls").and_then(Value::as_array) {
        out["toolCalls"] = Value::Array(
            calls
                .iter()
                .map(|tc| {
                    let mut tc = tc.clone();
                    let f = format!("tool_call_arguments:{}", tc["id"].as_str().unwrap());
                    tc["arguments"] = serde_json::from_str(dec(&f, &tc["arguments"]).as_str().unwrap()).unwrap();
                    tc
                })
                .collect(),
        );
    }
    out
}

/// Trame `message` chiffrée par `CK`.
pub fn message_frame(id: &str, text: &str) -> Value {
    let content = session::encrypt_field(&ck(), SID, id, &FieldName::Content, text, &mut OsRandom).unwrap();
    json!({ "t": "message", "id": id, "content": content, "createdAt": "2026-11-20T10:00:00.000Z" })
}

// ---------------------------------------------------------------------------
// Superviseur simulé
// ---------------------------------------------------------------------------

pub fn limits() -> WorkerLimits {
    WorkerLimits {
        max_steps_per_turn: 25,
        max_tokens_per_conversation: 2_000_000,
        max_tokens_per_turn: 300_000,
        max_turn_duration_secs: 60,
        max_output_tokens_per_call: 4096,
        max_tool_result_bytes: 256 * 1024,
        idle_shutdown_secs: 0,
    }
}

pub fn init(epoch: u64) -> Init {
    Init {
        session_id: SID.into(),
        user_id: USER.into(),
        org_id: ORG.into(),
        runtime_id: RUNTIME.into(),
        auth_id: AUTH.into(),
        lease_epoch: epoch,
        api_base_url: "https://api.example.com".into(),
        llm: LlmConfig {
            provider: LlmProvider::Openai,
            model: "gpt-test".into(),
            base_url: "https://api.openai.com/v1".into(),
            reasoning_effort: ReasoningEffort::Medium,
            pricing: Some(pipe::Pricing { input_per_m_tok: 2.0, output_per_m_tok: 8.0 }),
        },
        limits: limits(),
        tool_policy: BTreeMap::new(),
        log_level: "info".into(),
    }
}

pub fn policy(entries: &[(&str, ToolPolicy)]) -> BTreeMap<String, ToolPolicy> {
    entries.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect()
}

/// Clés initiales : `CK`, une clé d'espace, une clé de salon.
pub fn default_keys(with_space: bool) -> Vec<KeyEntry> {
    let mut v = vec![
        KeyEntry { kind: KeyKind::Conv, reference: SID.into(), version: 1, key: Zeroizing::new(CK.to_vec()) },
        KeyEntry {
            kind: KeyKind::Thread,
            reference: THREAD.into(),
            version: 1,
            key: Zeroizing::new(THREAD_KEY.to_vec()),
        },
    ];
    if with_space {
        v.push(KeyEntry {
            kind: KeyKind::Space,
            reference: SPACE.into(),
            version: 1,
            key: Zeroizing::new(SPACE_KEY.to_vec()),
        });
    }
    v
}

/// Ce que le superviseur simulé envoie au worker.
pub enum ToWorker {
    Msg(SupervisorMsg),
    Keys(Vec<KeyEntry>),
}

/// Délégation de test : `csk` du runtime et `DK` (le superviseur réel les garde).
pub struct TestDelegation {
    pub csk: EcSigningKey,
    pub ctx: DelegationContext,
    pub dk: DelegationKey,
}

impl TestDelegation {
    pub fn new() -> Self {
        Self {
            csk: EcSigningKey::from_scalar(&[0x42; 32]).unwrap(),
            ctx: DelegationContext {
                user_id: USER.into(),
                org_id: ORG.into(),
                runtime_id: RUNTIME.into(),
                delegation_id: DELEGATION.into(),
                scope: Scope::Org,
                iat: 1_795_000_000,
                exp: 1_795_000_000 + 7 * 86_400,
            },
            dk: DelegationKey::generate(&mut OsRandom).unwrap(),
        }
    }
}

/// Superviseur simulé.
pub struct Peer {
    pub tx: mpsc::Sender<ToWorker>,
    pub frames: Arc<Mutex<Vec<WorkerMsg>>>,
    pub raw: Arc<Mutex<Vec<String>>>,
    pub done: Arc<Notify>,
    pub delegation: Arc<TestDelegation>,
}

impl Peer {
    pub fn msgs(&self) -> Vec<WorkerMsg> {
        self.frames.lock().unwrap().clone()
    }

    /// Évènements diffusés aux clients.
    pub fn events(&self) -> Vec<Value> {
        self.msgs()
            .into_iter()
            .filter_map(|m| match m {
                WorkerMsg::Event(e) => Some(e.event),
                _ => None,
            })
            .collect()
    }

    pub fn done_reason(&self) -> Option<pipe::DoneReason> {
        self.msgs().into_iter().find_map(|m| match m {
            WorkerMsg::Done(d) => Some(d.reason),
            _ => None,
        })
    }

    pub async fn send(&self, m: SupervisorMsg) {
        self.tx.send(ToWorker::Msg(m)).await.unwrap();
    }

    pub async fn wait_done(&self) -> pipe::DoneReason {
        for _ in 0..400 {
            if let Some(r) = self.done_reason() {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("le worker n'a pas fini ; trames : {:?}", self.msgs());
    }
}

/// Relie un worker (de l'autre côté de `io`) au superviseur simulé.
pub fn start_peer<S>(io: S, api: FakeApi, init: Init, keys: Vec<KeyEntry>) -> Peer
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(io);
    let (tx, mut rx) = mpsc::channel::<ToWorker>(64);
    let (wtx, mut wrx) = mpsc::channel::<Result<SupervisorMsg, Zeroizing<Vec<u8>>>>(256);
    let frames = Arc::new(Mutex::new(Vec::new()));
    let raw = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(Notify::new());
    let delegation = Arc::new(TestDelegation::new());
    // Rédacteur.
    tokio::spawn(async move {
        while let Some(m) = wrx.recv().await {
            let r = match m {
                Ok(j) => pipe::write_json(&mut wr, &j).await,
                Err(k) => pipe::write_keys(&mut wr, &k).await,
            };
            if r.is_err() {
                break;
            }
        }
    });
    let w2 = wtx.clone();
    tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            let out = match m {
                ToWorker::Msg(m) => Ok(m),
                ToWorker::Keys(k) => Err(KeyFrame { op: KeyOp::Add, entries: k }.encode().unwrap()),
            };
            if w2.send(out).await.is_err() {
                break;
            }
        }
    });
    let (f2, r2, d2, deleg) = (Arc::clone(&frames), Arc::clone(&raw), Arc::clone(&done), Arc::clone(&delegation));
    tokio::spawn(async move {
        wtx.send(Ok(SupervisorMsg::Init(Box::new(init)))).await.unwrap();
        let mut parts: HashMap<String, (pipe::SignedRequest, Reassembly)> = HashMap::new();
        let mut started = false;
        let mut key_frame = (!keys.is_empty()).then(|| KeyFrame { op: KeyOp::Add, entries: keys }.encode().unwrap());
        loop {
            let frame = match pipe::read_frame(&mut rd).await {
                Ok(f) => f,
                Err(_) => break,
            };
            match frame {
                Frame::Keys(k) => {
                    let f = KeyFrame::decode(&k).unwrap();
                    assert!(f.is_created_thread_key(), "seule une clé créée peut venir du worker");
                    let e = &f.entries[0];
                    let key = SymmetricKey::from_slice(&e.key).unwrap();
                    let ctx = synco_e2ee::keys::thread_context(&e.reference);
                    let sig =
                        synco_e2ee::keys::sign_rt1_envelope(&deleg.csk, key.as_bytes(), &ctx, 1, DELEGATION).unwrap();
                    let ct = synco_e2ee::delegation::seal_entry(
                        &deleg.dk,
                        &deleg.ctx,
                        EntryKind::Thread,
                        &e.reference,
                        1,
                        &key,
                        &mut OsRandom,
                    )
                    .unwrap();
                    let resp = CreatedKeyMsg {
                        reference: e.reference.clone(),
                        envelope: Some(CreatedKeyEnvelope {
                            delegation_id: DELEGATION.into(),
                            commitment: sig.commitment,
                            signature: sig.signature,
                            ciphertext: ct,
                        }),
                        error: None,
                    };
                    let _ = wtx.send(Ok(SupervisorMsg::CreatedKey(resp))).await;
                }
                Frame::Json(j) => {
                    r2.lock().unwrap().push(String::from_utf8_lossy(&j).into_owned());
                    let msg: WorkerMsg = pipe::decode_json(&j).expect("trame stricte du worker");
                    match &msg {
                        WorkerMsg::Ready(_) if !started => {
                            started = true;
                            if let Some(k) = key_frame.take() {
                                wtx.send(Err(k)).await.unwrap();
                            }
                            wtx.send(Ok(SupervisorMsg::Start(Empty {}))).await.unwrap();
                        }
                        WorkerMsg::SignedRequest(req) => {
                            assert!(req.with_auth, "toutes les routes du worker sont S+A");
                            let id = req.id.clone();
                            let entry = parts.entry(id.clone()).or_insert_with(|| (req.clone(), Reassembly::default()));
                            entry.1.push(req.part, &req.body, pipe::MAX_RELAY_REQUEST_BYTES).unwrap();
                            if req.last {
                                let (head, body) = parts.remove(&id).unwrap();
                                let api = api.clone();
                                let wtx = wtx.clone();
                                tokio::spawn(async move {
                                    let body = body.into_body();
                                    let (status, resp) = api.handle(head.method.as_str(), &head.path, &body).await;
                                    let bytes = if resp.is_null() { Vec::new() } else { resp.to_string().into_bytes() };
                                    for p in SignedResponse::split(&id, status, &BTreeMap::new(), &bytes) {
                                        let _ = wtx.send(Ok(SupervisorMsg::SignedRequestResponse(p))).await;
                                    }
                                });
                            }
                        }
                        WorkerMsg::Log(l) => assert!(l.is_contentless(), "journal avec contenu possible : {l:?}"),
                        _ => {}
                    }
                    let is_done = matches!(msg, WorkerMsg::Done(_));
                    f2.lock().unwrap().push(msg);
                    if is_done {
                        d2.notify_waiters();
                    }
                }
            }
        }
    });
    Peer { tx, frames, raw, done, delegation }
}

/// Lance un worker en processus (tâche tokio) relié au superviseur simulé.
pub fn spawn_worker(
    api: &FakeApi,
    llm: &FakeLlm,
    init: Init,
    keys: Vec<KeyEntry>,
) -> (Peer, tokio::task::JoinHandle<()>) {
    let (a, b) = tokio::io::duplex(4 << 20);
    let socket = llm.path.clone();
    let opts = synco_ai_runtime_worker::agent::AgentOptions {
        retry_delays: vec![Duration::from_millis(10), Duration::from_millis(20), Duration::from_millis(40)],
        lease_renew: Duration::from_millis(200),
        metrics_every: Duration::from_millis(500),
        need_key_wait: Duration::from_millis(100),
    };
    let task = tokio::spawn(async move {
        let _ = synco_ai_runtime_worker::agent::run(a, Some(socket), opts).await;
    });
    (start_peer(b, api.clone(), init, keys), task)
}

// ---------------------------------------------------------------------------
// LLM simulé (serveur HTTP/1.1 sur socket Unix, comme le mandataire)
// ---------------------------------------------------------------------------

/// Réponse enregistrée.
#[derive(Clone, Default)]
pub struct Script {
    pub status: u16,
    pub chunks: Vec<String>,
    /// Pause avant ce rang de morceau jusqu'à `release`.
    pub hold_before: Option<usize>,
    pub release: Option<Arc<Notify>>,
}

impl Script {
    pub fn ok(chunks: Vec<String>) -> Self {
        Self { status: 200, chunks, ..Self::default() }
    }

    pub fn error(status: u16, body: Value) -> Self {
        Self { status, chunks: vec![body.to_string()], ..Self::default() }
    }
}

#[derive(Default)]
pub struct LlmState {
    pub scripts: VecDeque<Script>,
    pub requests: Vec<Value>,
    pub headers: Vec<String>,
}

pub struct FakeLlm {
    pub path: PathBuf,
    pub st: Arc<Mutex<LlmState>>,
    _dir: tempfile::TempDir,
}

impl FakeLlm {
    pub fn start() -> Self {
        let dir = tempfile::Builder::new().prefix("l07llm").tempdir().unwrap();
        let path = dir.path().join("llm.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let st: Arc<Mutex<LlmState>> = Arc::default();
        let s2 = Arc::clone(&st);
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let st = Arc::clone(&s2);
                tokio::spawn(serve(sock, st));
            }
        });
        Self { path, st, _dir: dir }
    }

    pub fn push(&self, s: Script) {
        self.st.lock().unwrap().scripts.push_back(s);
    }

    pub fn requests(&self) -> Vec<Value> {
        self.st.lock().unwrap().requests.clone()
    }

    pub async fn wait_requests(&self, n: usize) {
        for _ in 0..400 {
            if self.requests().len() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("le LLM n'a pas reçu {n} requêtes");
    }
}

async fn serve(mut sock: tokio::net::UnixStream, st: Arc<Mutex<LlmState>>) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        let n = sock.read(&mut tmp).await.unwrap_or(0);
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
    let len: usize =
        head.lines().find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())).unwrap_or(0);
    while buf.len() < head_end + len {
        let n = sock.read(&mut tmp).await.unwrap_or(0);
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body: Value = serde_json::from_slice(&buf[head_end..head_end + len]).unwrap_or(Value::Null);
    let script = {
        let mut s = st.lock().unwrap();
        s.requests.push(body);
        s.headers.push(head.clone());
        s.scripts.pop_front()
    };
    let script = script.unwrap_or_else(|| Script::error(500, json!({ "error": "aucun flux enregistré" })));
    let ctype = if script.status == 200 { "text/event-stream" } else { "application/json" };
    let line = format!("HTTP/1.1 {} X\r\ncontent-type: {ctype}\r\nconnection: close\r\n\r\n", script.status);
    if sock.write_all(line.as_bytes()).await.is_err() {
        return;
    }
    for (i, c) in script.chunks.iter().enumerate() {
        if script.hold_before == Some(i)
            && let Some(r) = &script.release
        {
            r.notified().await;
        }
        if sock.write_all(c.as_bytes()).await.is_err() {
            return;
        }
        let _ = sock.flush().await;
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let _ = sock.shutdown().await;
}

/// Flux SSE d'une réponse texte (avec usage).
pub fn sse_text(parts: &[&str], usage: (u64, u64)) -> Vec<String> {
    let mut v: Vec<String> = parts
        .iter()
        .map(|p| format!("data: {}\n\n", json!({ "choices": [{ "index": 0, "delta": { "content": p } }] })))
        .collect();
    v.push(format!("data: {}\n\n", json!({ "choices": [{ "index": 0, "delta": {}, "finish_reason": "stop" }] })));
    v.push(format!(
        "data: {}\n\n",
        json!({ "choices": [], "usage": { "prompt_tokens": usage.0, "completion_tokens": usage.1, "total_tokens": usage.0 + usage.1 } })
    ));
    v.push("data: [DONE]\n\n".into());
    v
}

/// Flux SSE d'un appel d'outil (arguments coupés en deux morceaux).
pub fn sse_tool(id: &str, name: &str, args: &Value, usage: (u64, u64)) -> Vec<String> {
    let a = args.to_string();
    let (x, y) = a.split_at(a.len() / 2);
    vec![
        format!(
            "data: {}\n\n",
            json!({ "choices": [{ "index": 0, "delta": { "tool_calls": [{ "index": 0, "id": id, "type": "function", "function": { "name": name, "arguments": x } }] } }] })
        ),
        format!(
            "data: {}\n\n",
            json!({ "choices": [{ "index": 0, "delta": { "tool_calls": [{ "index": 0, "function": { "arguments": y } }] }, "finish_reason": "tool_calls" }] })
        ),
        format!(
            "data: {}\n\n",
            json!({ "choices": [], "usage": { "prompt_tokens": usage.0, "completion_tokens": usage.1, "total_tokens": usage.0 + usage.1 } })
        ),
        "data: [DONE]\n\n".into(),
    ]
}

/// Déchiffre les deltas `text` d'une suite d'évènements.
pub fn streamed_text(events: &[Value]) -> String {
    let k = ck();
    events
        .iter()
        .filter(|e| e["t"] == "text")
        .map(|e| {
            let f = format!("ws:text:{}:{}", e["epoch"], e["seq"]);
            session::decrypt_field(&k, SID, e["messageId"].as_str().unwrap(), &f, e["delta"].as_str().unwrap()).unwrap()
        })
        .collect()
}

pub fn path_exists(p: &Path) -> bool {
    p.exists()
}
