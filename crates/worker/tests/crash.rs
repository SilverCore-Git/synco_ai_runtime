//! Reprise après un **vrai** `kill -9` du worker au milieu d'un outil mutant (08 §5, invariant
//! « un outil mutant en cours au moment d'un plantage n'est jamais relancé »).
//!
//! Le worker tourne dans un **processus enfant** (ce binaire de test relancé, point d'entrée
//! `entry::run` sur un pipe hérité en entrée standard, comme dans le bac à sable) ; le parent joue
//! le superviseur et l'API, bloque l'outil, puis tue l'enfant par `SIGKILL`. Un second worker
//! reprend la conversation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::exit,
    missing_docs,
    reason = "tests"
)]

mod common;

use std::os::fd::AsFd as _;
use std::time::Duration;

use common::*;
use runtime_protocol::pipe::{DoneReason, ToolPolicy};
use serde_json::json;

const CHILD_ENV: &str = "SYNCO_L07_CHILD_WORKER";
const SOCKET_ENV: &str = "SYNCO_L07_CHILD_LLM_SOCKET";

/// Point d'entrée du processus enfant (sans effet dans une exécution normale des tests).
#[test]
fn child_worker() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let fd = std::io::stdin().as_fd().try_clone_to_owned().unwrap();
    let pipe = std::os::unix::net::UnixStream::from(fd);
    let socket = std::env::var_os(SOCKET_ENV).map(std::path::PathBuf::from);
    let code = synco_ai_runtime_worker::entry::run(pipe, socket);
    std::process::exit(i32::from(code));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reprise_apres_kill_9_au_milieu_d_un_outil() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message("3c2b1a09-8f7e-4d6c-9b5a-493827161504", "Crée la tâche Rapport");
    api.with(|st| st.block_tool = Some("create_task".into()));
    llm.push(Script::ok(sse_tool("call_1", "create_task", &json!({ "title": "Rapport" }), (10, 3))));
    let mut ini = init(1);
    ini.tool_policy = policy(&[("create_task", ToolPolicy::Auto)]);

    // 1. Worker enfant, relié par une paire de sockets : son bout devient son entrée standard.
    let (parent, child_end) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_worker", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .env(SOCKET_ENV, &llm.path)
        .stdin(std::process::Stdio::from(std::os::fd::OwnedFd::from(child_end)))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    parent.set_nonblocking(true).unwrap();
    let peer =
        start_peer(tokio::net::UnixStream::from_std(parent).unwrap(), api.clone(), ini.clone(), default_keys(false));

    // L'outil est en cours côté API (écriture anticipée faite) : kill -9.
    tokio::time::timeout(Duration::from_secs(20), api.blocked.notified()).await.expect("outil appelé");
    child.kill().unwrap();
    let status = child.wait().unwrap();
    assert!(!status.success(), "tué par SIGKILL");
    drop(peer);
    let executing = api.clear_messages()[1]["toolCalls"][0].clone();
    assert_eq!(executing["status"], "executing", "écriture anticipée avant l'outil");
    assert_eq!(api.with(|st| st.status.clone()), "running");
    assert_eq!(api.with(|st| st.tool_runs.len()), 1);

    // 2. Bail expiré, nouveau worker (nouvelle époque) : l'outil n'est PAS relancé.
    api.with(|st| {
        st.lease_epoch = 2;
        st.block_tool = None;
    });
    llm.push(Script::ok(sse_text(&["Je vérifie : la tâche existe peut-être déjà."], (10, 3))));
    let mut ini2 = ini;
    ini2.lease_epoch = 2;
    let (peer, _t) = spawn_worker(&api, &llm, ini2, default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    api.with(|st| {
        assert_eq!(st.tool_runs.len(), 1, "outil mutant jamais relancé");
        // Journal : `lease_lost` (le précédent n'a pas fini) et `tool_unknown_outcome`.
        assert!(st.events.contains(&json!({ "type": "lease_lost" })), "{:?}", st.events);
        assert!(
            st.events.contains(&json!({ "type": "tool_unknown_outcome", "code": "create_task" })),
            "{:?}",
            st.events
        );
    });
    let msgs = api.clear_messages();
    assert_eq!(msgs[1]["toolCalls"][0]["status"], "error");
    assert_eq!(
        msgs[2]["toolResult"],
        json!({ "error": "unknown_outcome", "note": synco_ai_runtime_worker::agent::UNKNOWN_OUTCOME_NOTE })
    );
    // Le modèle reçoit ce résultat et décide de la suite.
    let req = llm.requests().last().unwrap().clone();
    let tool = req["messages"].as_array().unwrap().iter().find(|m| m["role"] == "tool").unwrap().clone();
    assert!(tool["content"].as_str().unwrap().contains("unknown_outcome"));
}

#[tokio::test]
async fn outil_non_mutant_executing_relance_a_la_reprise() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    // Historique laissé par un worker tué pendant `list_spaces` (lecture sans effet de bord).
    let ck = ck();
    let mut a = synco_ai_runtime_worker::transcript::Message::new(
        "a1".into(),
        synco_ai_runtime_worker::transcript::Role::Assistant,
        "2026-11-20T10:00:00.000Z".into(),
    );
    a.tool_calls.push(synco_ai_runtime_worker::transcript::ToolCall {
        id: "call_r".into(),
        name: "list_spaces".into(),
        arguments: json!({}),
        category: "server".into(),
        mutating: false,
        status: synco_ai_runtime_worker::transcript::ToolStatus::Executing,
    });
    let enc = synco_ai_runtime_worker::transcript::encode_messages(&ck, SID, &[a]).unwrap();
    api.with(|st| {
        st.messages = enc;
        st.status = "running".into();
        st.lease_epoch = 4;
    });
    llm.push(Script::ok(sse_text(&["Voici les espaces."], (10, 3))));
    let (peer, _t) = spawn_worker(&api, &llm, init(4), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    api.with(|st| {
        assert_eq!(st.tool_runs.len(), 1, "lecture relancée");
        assert!(!st.events.iter().any(|e| e["type"] == "tool_unknown_outcome"));
    });
    assert_eq!(api.clear_messages()[0]["toolCalls"][0]["status"], "done");
}
