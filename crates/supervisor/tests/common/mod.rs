//! API simulée pour les tests d'intégration du superviseur : HTTP + WebSocket du flux, qui
//! **vérifie chaque requête signée** avec la règle de l'API (`runtime_protocol::signing`, celle
//! que rejouent les vecteurs `internal-requests.json`) et le second verrou minimal (`x-synco-auth`
//! = autorisation de la conversation).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    dead_code,
    clippy::result_large_err,
    missing_docs,
    reason = "tests : l'API simulée échoue bruyamment"
)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use runtime_protocol::signing::{self, NonceCache, RegisteredRuntime};
use serde_json::{Value, json};
use synco_e2ee::encoding::b64u;
use tokio::sync::broadcast;

pub const TICKET_KID: &str = "test-1";
pub const ORG: &str = "cm3orgexample0000000000001";

/// Requête vue par l'API simulée.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub auth: Option<String>,
    pub body: Value,
}

#[derive(Default)]
pub struct Conversation {
    pub auth_id: String,
    pub lease_epoch: u64,
    pub rev: u64,
    pub messages: Vec<Value>,
    pub inbox: Vec<(String, Value, bool)>,
    pub statuses: Vec<String>,
    /// Codes d'erreur des statuts écrits (`error`).
    pub errors: Vec<String>,
    pub lease_released: bool,
}

#[derive(Default)]
pub struct MockState {
    pub runtime_id: String,
    pub runtime_key: Option<VerifyingKey>,
    pub paired: bool,
    pub certificate: Value,
    pub nonces: Option<NonceCache>,
    pub signature_failures: Vec<String>,
    pub auth_failures: Vec<String>,
    pub seen: Vec<Seen>,
    pub delegations: Vec<Value>,
    pub entries: BTreeMap<String, Vec<Value>>,
    pub delegation_status: BTreeMap<String, String>,
    pub sign_keys: BTreeMap<String, String>,
    /// Chaîne de transitions servie avec `sign-key`, par utilisateur.
    pub transitions: BTreeMap<String, Vec<Value>>,
    /// `GET /e2ee/members/keys` : `members`.
    pub members: Value,
    /// Délai de `GET /users/:userId/sign-key` (ms).
    pub slow_sign_key_ms: u64,
    pub pending: Vec<Value>,
    pub conversations: BTreeMap<String, Conversation>,
    pub stream_hellos: u32,
    /// Org annoncée dans `hello` (défaut : `ORG`).
    pub hello_org: Option<String>,
    /// Délai (ms) avant de servir les entrées d'une délégation.
    pub slow_entries_ms: u64,
    /// Requêtes d'entrées reçues (avant le délai).
    pub entries_requested: u32,
    pub presences: u32,
    /// Salons créés par `POST /e2ee/threads`.
    pub threads_created: u32,
    /// `POST /e2ee/threads/:id/key-envelope/repose` : réponse imposée (statut, code) ; sinon 200,
    /// puis `envelope_exists` si l'enveloppe est différente de la première reçue.
    pub repose_override: Option<(u16, String)>,
    /// Première enveloppe reposée par salon (`commitment`, `signature`) : l'API (L03f) compare les
    /// deux ; même enveloppe = 200 `updated: 0`, autre = 409 `envelope_exists`.
    pub reposed: BTreeMap<String, (String, String)>,
    /// Délai (ms) avant de répondre à `…/key-envelope/repose` (mesure de la concurrence).
    pub repose_delay_ms: u64,
    /// Appels `…/key-envelope/repose` en cours, et leur maximum observé.
    pub repose_in_flight: u32,
    pub repose_max_in_flight: u32,
    /// `GET /e2ee/threads/envelope-resets` (L03f, en cours de développement : mock) : items servis.
    pub resets: Vec<Value>,
    /// Taille de page (0 = tout sur une page).
    pub resets_page: usize,
    /// Statut d'erreur à servir (route absente : 404).
    pub resets_fail: Option<u16>,
    /// Requêtes reçues (chemin + requête).
    pub resets_requests: Vec<String>,
    /// `GET /authorizations` : taille de page (0 = tout sur une page).
    pub authorizations_page: usize,
    /// `GET /authorizations` : statut d'erreur à servir.
    pub authorizations_fail: Option<u16>,
    /// `GET /authorizations` : conversations dont l'autorisation est omise (révoquée).
    pub authorizations_omitted: Vec<String>,
    /// `GET /llm-policy` remplacé (défaut : `openai`, `gpt-test`).
    pub policy: Option<Value>,
}

pub struct MockApi {
    pub addr: SocketAddr,
    pub state: Arc<Mutex<MockState>>,
    pub events: broadcast::Sender<String>,
    pub ticket_key: SigningKey,
}

impl MockApi {
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut MockState) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }

    /// Envoie un évènement du flux (`{ v: 1, type, … }`).
    pub fn push(&self, event: Value) {
        let mut e = event;
        e.as_object_mut().unwrap().insert("v".into(), json!(1));
        let _ = self.events.send(e.to_string());
    }

    /// Ticket `srt1` signé par la clé de test de l'API.
    pub fn ticket(&self, claims: &Value) -> String {
        sign_ticket(&self.ticket_key, "srt1", b"synco-ai-runtime-ticket\0", claims)
    }
}

pub fn sign_ticket(key: &SigningKey, prefix: &str, domain: &[u8], claims: &Value) -> String {
    let payload = b64u(claims.to_string().as_bytes());
    let signed = format!("{prefix}.{TICKET_KID}.{payload}");
    let mut bytes = domain.to_vec();
    bytes.extend_from_slice(signed.as_bytes());
    format!("{signed}.{}", b64u(&key.sign(&bytes).to_bytes()))
}

type Shared = (Arc<Mutex<MockState>>, broadcast::Sender<String>, VerifyingKey);

fn error(status: u16, code: &str) -> Response {
    (StatusCode::from_u16(status).unwrap(), axum::Json(json!({ "error": code }))).into_response()
}

fn verify(
    st: &mut MockState,
    method: &str,
    path: &str,
    body: &[u8],
    headers: &HeaderMap,
) -> Result<Option<String>, Response> {
    let now = runtime_protocol_now();
    let registry =
        st.runtime_key.map(|k| (st.runtime_id.clone(), RegisteredRuntime { sig_public_key: k, active: true }));
    let nonces = st.nonces.get_or_insert_with(|| NonceCache::new(8000, signing::NONCE_TTL_SECS));
    let result = signing::verify_request(
        method,
        path,
        body,
        |n| headers.get(n).and_then(|v| v.to_str().ok()),
        |id| registry.as_ref().filter(|(rid, _)| rid == id).map(|(_, r)| r.clone()),
        nonces,
        now,
    );
    match result {
        Ok(h) => Ok(h.auth_id),
        Err(e) => {
            st.signature_failures.push(format!("{method} {path} : {}", e.code()));
            Err(error(e.http_status(), e.code()))
        }
    }
}

fn runtime_protocol_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

async fn ticket_keys(State((_, _, pk)): State<Shared>) -> Response {
    axum::Json(json!({ "v": 1, "keys": { TICKET_KID: b64u(pk.as_bytes()) } })).into_response()
}

async fn stream(State((state, events, _)): State<Shared>, headers: HeaderMap, ws: WebSocketUpgrade) -> Response {
    let verified = {
        let mut st = state.lock().unwrap();
        verify(&mut st, "GET", runtime_protocol::stream::STREAM_PATH, &[], &headers).map(|_| ())
    };
    let ok = verified.is_ok() && state.lock().unwrap().paired;
    ws.on_upgrade(move |socket| async move {
        if ok {
            run_stream(state, events, socket).await;
        } else {
            let mut socket = socket;
            let _ = socket.send(Message::Close(Some(CloseFrame { code: 4401, reason: "rt_sig_invalid".into() }))).await;
        }
    })
}

async fn run_stream(state: Arc<Mutex<MockState>>, events: broadcast::Sender<String>, mut socket: WebSocket) {
    let mut rx = events.subscribe();
    let org = state.lock().unwrap().hello_org.clone().unwrap_or_else(|| ORG.to_owned());
    let hello = json!({ "v": 1, "type": "hello", "orgId": org, "serverTime": runtime_protocol_now() });
    if socket.send(Message::Text(hello.to_string().into())).await.is_err() {
        return;
    }
    state.lock().unwrap().stream_hellos += 1;
    loop {
        tokio::select! {
            e = rx.recv() => match e {
                Ok(text) => {
                    if text.contains("\"__close__\"") {
                        let _ = socket.send(Message::Close(Some(CloseFrame { code: 4409, reason: "replaced".into() }))).await;
                        return;
                    }
                    let close = text.contains("\"runtime.unpaired\"");
                    if socket.send(Message::Text(text.into())).await.is_err() { return; }
                    if close {
                        let _ = socket.send(Message::Close(Some(CloseFrame { code: 4401, reason: "rt_revoked".into() }))).await;
                        return;
                    }
                }
                Err(_) => return,
            },
            m = socket.recv() => match m {
                Some(Ok(Message::Text(t))) => {
                    let v: Value = serde_json::from_str(t.as_str()).unwrap_or(Value::Null);
                    if v["type"] == "presence" { state.lock().unwrap().presences += 1; }
                }
                Some(Ok(_)) => {}
                _ => return,
            },
        }
    }
}

async fn channel(
    State((state, _, _)): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path_and_query().map(|p| p.as_str().to_owned()).unwrap_or_default();
    if uri.path().ends_with("/entries") && method == Method::GET {
        let delay = {
            let mut st = state.lock().unwrap();
            st.entries_requested += 1;
            st.slow_entries_ms
        };
        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
    }
    if uri.path().ends_with("/sign-key") {
        let delay = state.lock().unwrap().slow_sign_key_ms;
        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
    }
    if method == Method::POST && uri.path().ends_with("/key-envelope/repose") {
        let delay = {
            let mut st = state.lock().unwrap();
            st.repose_in_flight += 1;
            st.repose_max_in_flight = st.repose_max_in_flight.max(st.repose_in_flight);
            st.repose_delay_ms
        };
        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        state.lock().unwrap().repose_in_flight -= 1;
    }
    // Route lente (tests de concurrence du relais).
    if uri.path().ends_with("/tools") {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    }
    let mut st = state.lock().unwrap();
    let auth = match verify(&mut st, method.as_str(), &path, &body, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let json_body: Value =
        if body.is_empty() { Value::Null } else { serde_json::from_slice(&body).unwrap_or(Value::Null) };
    st.seen.push(Seen { method: method.to_string(), path: path.clone(), auth: auth.clone(), body: json_body.clone() });
    let route = path.trim_start_matches("/api/runtime/v1");
    let (route_path, query) = route.split_once('?').unwrap_or((route, ""));
    let segs: Vec<&str> = route_path.trim_start_matches('/').split('/').collect();
    match (method.as_str(), segs.as_slice()) {
        ("POST", ["register"]) => {
            if st.paired {
                axum::Json(json!({ "orgId": ORG, "certificate": st.certificate })).into_response()
            } else {
                error(404, "rt_unknown")
            }
        }
        ("GET", ["llm-policy"]) if st.policy.is_some() => axum::Json(st.policy.clone().unwrap()).into_response(),
        ("GET", ["llm-policy"]) => axum::Json(json!({
            "v": 1, "orgId": ORG, "defaultProvider": "openai", "reasoningEffort": "medium",
            "providers": [{ "id": "openai", "modelId": "gpt-test" }],
            "runtime": { "enabled": true, "maxDelegationDays": 7, "toolPolicy": { "create_task": "ask" },
                "limits": { "maxStepsPerTurn": 10, "maxTokensPerConversation": 1000, "maxTokensPerTurn": 500,
                    "maxTurnDurationSecs": 60, "maxOutputTokensPerCall": 100 } }
        }))
        .into_response(),
        ("POST", ["metrics"]) => axum::Json(json!({ "ok": true })).into_response(),
        ("POST", ["e2ee", "threads"]) => {
            st.threads_created += 1;
            let id = format!("cm3threadmock{:012}", st.threads_created);
            (StatusCode::CREATED, axum::Json(json!({ "id": id, "name": json_body["name"] }))).into_response()
        }
        ("GET", ["delegations"]) => axum::Json(Value::Array(st.delegations.clone())).into_response(),
        ("GET", ["delegations", id, "entries"]) => {
            let entries = st.entries.get(*id).cloned().unwrap_or_default();
            axum::Json(json!({ "entries": entries, "next": null })).into_response()
        }
        ("POST", ["delegations", id, "status"]) => {
            let s = json_body["status"].as_str().unwrap_or("?").to_owned();
            st.delegation_status.insert((*id).to_owned(), s);
            StatusCode::NO_CONTENT.into_response()
        }
        ("POST", ["e2ee", "threads", tid, "key-envelope", "repose"]) => {
            if let Some((status, code)) = st.repose_override.clone() {
                return error(status, &code);
            }
            let pair = (
                json_body["commitment"].as_str().unwrap_or_default().to_owned(),
                json_body["signature"].as_str().unwrap_or_default().to_owned(),
            );
            match st.reposed.get(*tid) {
                Some(first) if *first != pair => error(409, "envelope_exists"),
                Some(_) => axum::Json(json!({ "threadId": tid, "updated": 0 })).into_response(),
                None => {
                    st.reposed.insert((*tid).to_owned(), pair);
                    axum::Json(json!({ "threadId": tid, "updated": 1 })).into_response()
                }
            }
        }
        ("GET", ["e2ee", "threads", "envelope-resets"]) => {
            st.resets_requests.push(route.to_owned());
            if let Some(status) = st.resets_fail {
                return error(status, "not_found");
            }
            let param = |k: &str| query.split('&').find_map(|p| p.strip_prefix(&format!("{k}=")).map(str::to_owned));
            let start: usize = param("cursor").and_then(|c| c.parse().ok()).unwrap_or(0);
            let size = if st.resets_page == 0 { st.resets.len().max(1) } else { st.resets_page };
            let page: Vec<Value> = st.resets.iter().skip(start).take(size).cloned().collect();
            let next = (start + page.len() < st.resets.len()).then(|| (start + page.len()).to_string());
            axum::Json(json!({ "items": page, "nextCursor": next })).into_response()
        }
        ("GET", ["e2ee", "members", "keys"]) => axum::Json(json!({ "members": st.members })).into_response(),
        ("GET", ["users", id, "sign-key"]) => match st.sign_keys.get(*id) {
            Some(k) => {
                let chain = st.transitions.get(*id).cloned().unwrap_or_default();
                axum::Json(json!({ "publicSignKey": k, "transitions": chain })).into_response()
            }
            None => error(404, "not_found"),
        },
        ("GET", ["authorizations"]) => {
            if let Some(status) = st.authorizations_fail {
                return error(status, "internal");
            }
            if !query.contains("state=active") {
                return error(400, "invalid_body");
            }
            let after = query.split('&').find_map(|p| p.strip_prefix("after=")).map(str::to_owned);
            let all: Vec<(String, String)> = st
                .conversations
                .iter()
                .filter(|(sid, _)| !st.authorizations_omitted.contains(sid))
                .map(|(sid, c)| (sid.clone(), c.auth_id.clone()))
                .collect();
            let start = match &after {
                Some(a) => all.iter().position(|(_, auth)| auth == a).map_or(all.len(), |i| i + 1),
                None => 0,
            };
            let size = if st.authorizations_page == 0 { all.len().max(1) } else { st.authorizations_page };
            let page: Vec<&(String, String)> = all.iter().skip(start).take(size).collect();
            let next = (start + page.len() < all.len()).then(|| page.last().map(|(_, a)| a.clone())).flatten();
            let items: Vec<Value> = page
                .iter()
                .map(|(sid, auth)| {
                    json!({ "authId": auth, "sessionId": sid, "userId": "66666666-7777-4888-9999-aaaaaaaaaaaa",
                        "delegationId": "d-good", "exp": 4_000_000_000_u64, "displayName": null })
                })
                .collect();
            axum::Json(json!({ "authorizations": items, "next": next })).into_response()
        }
        ("GET", ["conversations"]) => axum::Json(Value::Array(st.pending.clone())).into_response(),
        (m, ["conversations", sid, rest @ ..]) => {
            let sid = (*sid).to_owned();
            let Some(conv) = st.conversations.get(&sid) else { return error(403, "out_of_scope") };
            if auth.as_deref() != Some(conv.auth_id.as_str()) {
                st.auth_failures.push(format!("{m} {path}"));
                return error(403, "auth_invalid");
            }
            let conv = st.conversations.get_mut(&sid).unwrap();
            match (m, rest) {
                ("GET", []) => axum::Json(json!({
                    "id": sid, "title": null, "messages": conv.messages, "rev": conv.rev, "status": "idle",
                    "pendingToolCall": null, "encryptionScheme": "conv-gcm1-v1", "leaseEpoch": conv.lease_epoch,
                    "lastErrorCode": null, "awaitingKey": null
                }))
                .into_response(),
                ("POST", ["lease"]) => {
                    if json_body.get("leaseEpoch").is_none() {
                        conv.lease_epoch += 1;
                        conv.lease_released = false;
                    }
                    axum::Json(json!({ "leaseEpoch": conv.lease_epoch, "expiresAt": "2030-01-01T00:00:00.000Z" }))
                        .into_response()
                }
                ("DELETE", ["lease"]) => {
                    conv.lease_released = true;
                    StatusCode::NO_CONTENT.into_response()
                }
                ("POST", ["status"]) => {
                    conv.statuses.push(json_body["status"].as_str().unwrap_or("?").to_owned());
                    if let Some(e) = json_body["error"].as_str() {
                        conv.errors.push(e.to_owned());
                    }
                    axum::Json(json!({ "rev": conv.rev })).into_response()
                }
                ("GET", ["inbox"]) => {
                    let items: Vec<Value> = conv
                        .inbox
                        .iter()
                        .filter(|(_, _, consumed)| !consumed)
                        .map(|(id, frame, _)| {
                            let mut payload = frame.clone();
                            let kind = payload.as_object_mut().unwrap().remove("t").unwrap();
                            json!({ "id": id, "kind": kind, "source": "ws", "createdAt": "2026-11-19T00:00:00.000Z", "payload": payload })
                        })
                        .collect();
                    axum::Json(json!({ "items": items })).into_response()
                }
                ("POST", ["inbox"]) => {
                    let id = match json_body["t"].as_str() {
                        Some("message") | Some("cancel") if json_body["t"] == "message" => {
                            json_body["id"].as_str().unwrap().to_owned()
                        }
                        Some("cancel") => format!("cancel:{}", json_body["id"].as_str().unwrap()),
                        Some(t) => format!("{t}:{}", json_body["toolCallId"].as_str().unwrap()),
                        None => return error(400, "invalid_body"),
                    };
                    conv.inbox.push((id.clone(), json_body, false));
                    (StatusCode::CREATED, axum::Json(json!({ "id": id, "status": "queued" }))).into_response()
                }
                ("PUT", ["transcript"]) => {
                    if json_body["leaseEpoch"].as_u64() != Some(conv.lease_epoch) {
                        return error(409, "lease_conflict");
                    }
                    for c in json_body["consumedInbox"].as_array().cloned().unwrap_or_default() {
                        for item in conv.inbox.iter_mut() {
                            if Some(item.0.as_str()) == c.as_str() {
                                item.2 = true;
                            }
                        }
                    }
                    conv.messages = json_body["messages"].as_array().cloned().unwrap_or_default();
                    conv.rev += 1;
                    conv.statuses.push(json_body["status"].as_str().unwrap_or("?").to_owned());
                    if let Some(e) = json_body["error"].as_str() {
                        conv.errors.push(e.to_owned());
                    }
                    axum::Json(json!({ "rev": conv.rev })).into_response()
                }
                _ => error(404, "not_found"),
            }
        }
        _ => error(404, "not_found"),
    }
}

/// Démarre l'API simulée.
pub async fn start(runtime_id: &str, runtime_key: VerifyingKey, ticket_key: SigningKey) -> MockApi {
    let state = Arc::new(Mutex::new(MockState {
        runtime_id: runtime_id.to_owned(),
        runtime_key: Some(runtime_key),
        ..MockState::default()
    }));
    let (events, _) = broadcast::channel(64);
    let shared: Shared = (Arc::clone(&state), events.clone(), ticket_key.verifying_key());
    let app = Router::new()
        .route("/api/ai/ticket-keys", get(ticket_keys))
        .route(runtime_protocol::stream::STREAM_PATH, get(stream))
        .fallback(channel)
        .layer(axum::extract::DefaultBodyLimit::max(9 * 1024 * 1024))
        .with_state(shared);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    MockApi { addr, state, events, ticket_key }
}
