//! Boucle d'agent du worker contre une **API simulée** et un **LLM simulé** (critères du lot L07).

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

use std::sync::Arc;
use std::time::Duration;

use common::*;
use runtime_protocol::pipe::{DoneReason, InboxMsg, ShutdownMsg, ShutdownReason, SupervisorMsg, ToolPolicy, WorkerMsg};
use serde_json::{Value, json};
use tokio::sync::Notify;

const M1: &str = "3c2b1a09-8f7e-4d6c-9b5a-493827161504";
const M2: &str = "4d3c2b1a-8f7e-4d6c-9b5a-493827161505";

fn statuses(api: &FakeApi) -> Vec<String> {
    api.with(|st| st.statuses.iter().map(|(s, _)| s.clone()).collect())
}

#[tokio::test]
async fn tour_simple() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Bonjour, qui es-tu ?");
    llm.push(Script::ok(sse_text(&["<think>Je me présente.</think>Bon", "jour, je suis Synco AI."], (12, 7))));
    let (peer, _t) = spawn_worker(&api, &llm, init(1), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);

    // Historique enregistré : message de l'utilisateur tel quel, réponse chiffrée, statut idle.
    let msgs = api.clear_messages();
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0]["id"], M1);
    assert_eq!(msgs[0]["content"], "Bonjour, qui es-tu ?");
    assert_eq!(msgs[1]["role"], "assistant");
    assert_eq!(msgs[1]["content"], "Bonjour, je suis Synco AI.");
    assert_eq!(msgs[1]["thinking"], "Je me présente.");
    assert_eq!(msgs[1]["usage"]["totalTokens"], 19);
    api.with(|st| {
        assert_eq!(st.status, "idle");
        assert!(st.inbox.iter().all(|i| i.2), "message consommé");
        assert_eq!(st.pushes, ["AI_TURN_DONE"]);
        assert!(st.lease_released, "bail rendu");
        assert!(st.refused.is_empty(), "{:?}", st.refused);
    });
    assert_eq!(statuses(&api).last().unwrap(), "idle");
    assert!(statuses(&api).contains(&"running".to_owned()));

    // Requête au fournisseur : prompt système, message en clair pour le modèle, outils filtrés.
    let req = &llm.requests()[0];
    assert_eq!(req["model"], "gpt-test");
    assert_eq!(req["messages"][0]["role"], "system");
    assert_eq!(req["messages"][1], json!({ "role": "user", "content": "Bonjour, qui es-tu ?" }));
    let tools: Vec<&str> =
        req["tools"].as_array().unwrap().iter().map(|t| t["function"]["name"].as_str().unwrap()).collect();
    assert!(tools.contains(&"create_task") && tools.contains(&"search_messages") && tools.contains(&"ask_question"));
    assert!(!tools.contains(&"create_file") && !tools.contains(&"read_documentation"), "{tools:?}");
    assert_eq!(req["max_completion_tokens"], 4096);

    // Évènements : running, deltas chiffrés (ws:text:<epoch>:<seq>), usage, idle ; seq croissant.
    let ev = peer.events();
    assert_eq!(streamed_text(&ev), "Bonjour, je suis Synco AI.");
    let seqs: Vec<u64> = ev.iter().map(|e| e["seq"].as_u64().unwrap()).collect();
    assert!(seqs.windows(2).all(|w| w[1] > w[0]) && seqs[0] == 1);
    assert!(ev.iter().all(|e| e["epoch"] == 1 && e["v"] == 1));
    let kinds: Vec<&str> = ev.iter().map(|e| e["t"].as_str().unwrap()).collect();
    assert_eq!(kinds.first(), Some(&"status"));
    assert!(kinds.contains(&"thinking") && kinds.contains(&"usage"));
    assert_eq!(ev.last().unwrap()["status"], "idle");
    // Métriques sans contenu, coût estimé (2 €/Mtok × 12 + 8 €/Mtok × 7 = 80 µ€).
    let m = peer
        .msgs()
        .into_iter()
        .rev()
        .filter_map(|m| match m {
            WorkerMsg::Metrics(m) => Some(*m),
            _ => None,
        })
        .next()
        .unwrap();
    assert_eq!((m.llm_calls, m.prompt_tokens, m.completion_tokens, m.cost_eur_micro), (1, 12, 7, 80));
    // Accusé des éléments consommés.
    assert!(peer.msgs().iter().any(|m| matches!(m, WorkerMsg::InboxAck(a) if a.ids == [M1])));
}

#[tokio::test]
async fn outil_serveur_lecture_puis_ecriture_anticipee() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.with(|st| {
        st.tool_data.insert("list_spaces".into(), json!([{ "id": "s1", "name": "Marketing" }]));
    });
    api.deposit_message(M1, "Crée une tâche dans Marketing");
    llm.push(Script::ok(sse_tool("call_1", "list_spaces", &json!({}), (10, 3))));
    llm.push(Script::ok(sse_tool("call_2", "create_task", &json!({ "title": "Rapport" }), (20, 3))));
    llm.push(Script::ok(sse_text(&["C'est fait."], (30, 3))));
    let mut ini = init(1);
    ini.tool_policy = policy(&[("create_task", ToolPolicy::Auto)]);
    let (peer, _t) = spawn_worker(&api, &llm, ini, default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);

    api.with(|st| {
        assert_eq!(st.tool_runs.len(), 2);
        assert_eq!(st.tool_runs[1], ("create_task".into(), json!({ "title": "Rapport" })));
        // Écriture anticipée : un historique avec create_task `executing` est écrit AVANT l'exécution.
        let pos_exec = st.seen.iter().position(|s| s.path.ends_with("/tools/create_task/execute")).unwrap();
        let pos_ahead = st
            .seen
            .iter()
            .position(|s| s.path.ends_with("/transcript") && s.body.contains("\"status\":\"executing\""))
            .unwrap();
        assert!(pos_ahead < pos_exec, "écriture anticipée avant l'outil mutant");
        // Le bail courant accompagne l'exécution.
        assert!(st.seen[pos_exec].body.contains("\"leaseEpoch\":1"));
    });
    let msgs = api.clear_messages();
    let roles: Vec<&str> = msgs.iter().map(|m| m["role"].as_str().unwrap()).collect();
    assert_eq!(roles, ["user", "assistant", "tool", "assistant", "tool", "assistant"]);
    assert_eq!(msgs[1]["toolCalls"][0]["status"], "done");
    assert_eq!(msgs[2]["toolResult"], json!([{ "id": "s1", "name": "Marketing" }]));
    assert_eq!(msgs[3]["toolCalls"][0]["status"], "done");
    // Le modèle reçoit le résultat au tour suivant.
    let second = &llm.requests()[1];
    let tool_msg = second["messages"].as_array().unwrap().iter().find(|m| m["role"] == "tool").unwrap();
    assert_eq!(tool_msg["tool_call_id"], "call_1");
    // Évènements tool_call (executing → done) et tool_result, arguments chiffrés.
    let ev = peer.events();
    let tc: Vec<&Value> = ev.iter().filter(|e| e["t"] == "tool_call" && e["toolCallId"] == "call_2").collect();
    assert_eq!(tc.iter().map(|e| e["status"].as_str().unwrap()).collect::<Vec<_>>(), ["executing", "done"]);
    assert!(tc[0]["args"].as_str().unwrap().starts_with("gcm1:"));
    assert!(ev.iter().any(|e| e["t"] == "tool_result" && e["toolCallId"] == "call_2"));
}

#[tokio::test]
async fn confirmation_acceptee_refusee_et_interdite() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Crée la tâche Rapport");
    llm.push(Script::ok(sse_tool("call_1", "create_task", &json!({ "title": "Rapport" }), (10, 3))));
    // 1er worker : outil mutant sans politique → `ask` → awaiting_confirmation, le worker s'arrête.
    let (peer, _t) = spawn_worker(&api, &llm, init(1), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Awaiting);
    api.with(|st| {
        assert_eq!(st.status, "awaiting_confirmation");
        assert!(st.tool_runs.is_empty(), "rien n'est exécuté avant la décision");
        assert_eq!(st.pending["id"], "call_1");
        assert!(st.pending["args"].as_str().unwrap().starts_with("gcm1:"));
        assert_eq!(st.pushes, ["AI_AWAITING_CONFIRMATION"]);
        assert!(st.lease_released);
    });
    assert_eq!(api.clear_messages()[1]["toolCalls"][0]["status"], "pending");

    // Décision déposée, 2e worker (nouvelle époque) : exécution puis suite du tour.
    api.with(|st| {
        st.lease_epoch = 2;
        st.status = "queued".into();
    });
    api.deposit("confirm:call_1", json!({ "t": "confirm", "toolCallId": "call_1", "decision": "accept" }));
    llm.push(Script::ok(sse_tool("call_2", "delete_task", &json!({ "taskId": "t9" }), (10, 3))));
    let (peer, _t) = spawn_worker(&api, &llm, init(2), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Awaiting);
    api.with(|st| {
        assert_eq!(st.tool_runs, [("create_task".to_owned(), json!({ "title": "Rapport" }))]);
        assert_eq!(st.pending["id"], "call_2");
        assert!(st.events.is_empty());
    });
    assert!(peer.events().iter().all(|e| e["epoch"] == 2));

    // Refus : jamais exécuté, résultat « refusé » donné au modèle.
    api.with(|st| {
        st.lease_epoch = 3;
        st.status = "queued".into();
    });
    api.deposit("confirm:call_2", json!({ "t": "confirm", "toolCallId": "call_2", "decision": "reject" }));
    llm.push(Script::ok(sse_tool("call_3", "delete_task", &json!({ "taskId": "t9" }), (10, 3))));
    llm.push(Script::ok(sse_text(&["Bien, je n'ai rien supprimé."], (10, 3))));
    let mut ini = init(3);
    ini.tool_policy = policy(&[("delete_task", ToolPolicy::Deny)]);
    api.with(|st| st.deny.push("delete_task".into()));
    let (peer, _t) = spawn_worker(&api, &llm, ini, default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    api.with(|st| assert_eq!(st.tool_runs.len(), 1, "ni refusé ni interdit exécuté"));
    let msgs = api.clear_messages();
    let results: Vec<&Value> = msgs.iter().filter(|m| m["role"] == "tool").map(|m| &m["toolResult"]).collect();
    assert_eq!(results[1], &json!({ "error": "Action refusée par l'utilisateur." }));
    assert_eq!(results[2], &json!({ "error": "tool_denied_by_policy" }));
    let calls: Vec<String> = msgs
        .iter()
        .flat_map(|m| m["toolCalls"].as_array().cloned().unwrap_or_default())
        .map(|c| c["status"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(calls, ["done", "rejected", "rejected"]);
    // L'outil interdit n'est même pas proposé au modèle.
    let last = llm.requests().last().unwrap().clone();
    assert!(!last["tools"].as_array().unwrap().iter().any(|t| t["function"]["name"] == "delete_task"));
}

#[tokio::test]
async fn message_en_file_pendant_un_tour_et_doublon() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    let first = api.deposit_message(M1, "Premier message");
    let release = Arc::new(Notify::new());
    llm.push(Script {
        status: 200,
        chunks: sse_text(&["Je réponds au premier", " message."], (10, 5)),
        hold_before: Some(1),
        release: Some(Arc::clone(&release)),
    });
    llm.push(Script::ok(sse_text(&["Et voici pour le second."], (20, 5))));
    let (peer, _t) = spawn_worker(&api, &llm, init(1), default_keys(false));
    llm.wait_requests(1).await;
    // Pendant l'appel : le premier élément revient en direct (doublon), puis un nouveau message.
    let second = message_frame(M2, "Second message pendant le tour");
    api.deposit(M2, second.clone());
    peer.send(SupervisorMsg::Inbox(InboxMsg { items: vec![first, second] })).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    release.notify_one();
    assert_eq!(peer.wait_done().await, DoneReason::Idle);

    let msgs = api.clear_messages();
    let users: Vec<&str> =
        msgs.iter().filter(|m| m["role"] == "user").map(|m| m["content"].as_str().unwrap()).collect();
    assert_eq!(users, ["Premier message", "Second message pendant le tour"], "dédupliqué, pris à l'étape suivante");
    let roles: Vec<&str> = msgs.iter().map(|m| m["role"].as_str().unwrap()).collect();
    assert_eq!(roles, ["user", "assistant", "user", "assistant"]);
    let req2 = &llm.requests()[1];
    assert_eq!(req2["messages"].as_array().unwrap().last().unwrap()["content"], "Second message pendant le tour");
    api.with(|st| assert!(st.inbox.iter().all(|i| i.2)));
}

#[tokio::test]
async fn plafonds_etapes_budget_et_mandataire() {
    // maxStepsPerTurn = 2 : le tour s'arrête en `idle` + `step_limit`.
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Boucle");
    for i in 0..3 {
        llm.push(Script::ok(sse_tool(&format!("call_{i}"), "list_spaces", &json!({}), (10, 2))));
    }
    let mut ini = init(1);
    ini.limits.max_steps_per_turn = 2;
    let (peer, _t) = spawn_worker(&api, &llm, ini, default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    assert_eq!(llm.requests().len(), 2);
    api.with(|st| {
        assert_eq!(st.statuses.last().unwrap(), &("idle".to_owned(), Some("step_limit".to_owned())));
        assert_eq!(st.pushes, ["AI_TURN_DONE"]);
    });
    assert!(peer.events().iter().any(|e| e["t"] == "error" && e["code"] == "step_limit"));

    // Budget de la conversation atteint (usage cumulé de l'historique) : `failed` + `budget_exceeded`.
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Encore");
    llm.push(Script::ok(sse_tool("call_a", "list_spaces", &json!({}), (900, 200))));
    let mut ini = init(1);
    ini.limits.max_tokens_per_conversation = 1000;
    let (peer, _t) = spawn_worker(&api, &llm, ini, default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Failed);
    api.with(|st| {
        assert_eq!(st.statuses.last().unwrap(), &("failed".to_owned(), Some("budget_exceeded".to_owned())));
        assert_eq!(st.pushes, ["AI_FAILED"]);
    });
    assert_eq!(llm.requests().len(), 1);

    // Quotas du mandataire : appels du tour → step_limit ; erreur 5xx → 3 nouveaux essais puis provider_error.
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Quota");
    llm.push(Script::error(429, json!({ "error": "proxy_call_budget" })));
    let (peer, _t) = spawn_worker(&api, &llm, init(1), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    api.with(|st| assert_eq!(st.last_error.as_deref(), Some("step_limit")));

    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Panne");
    for _ in 0..4 {
        llm.push(Script::error(503, json!({ "error": { "message": "surcharge" } })));
    }
    let (peer, _t) = spawn_worker(&api, &llm, init(1), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Failed);
    assert_eq!(llm.requests().len(), 4, "1 essai + 3 nouveaux essais");
    api.with(|st| assert_eq!(st.last_error.as_deref(), Some("provider_error")));

    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Clé");
    llm.push(Script::error(401, json!({ "error": { "message": "bad key" } })));
    let (peer, _t) = spawn_worker(&api, &llm, init(1), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Failed);
    assert_eq!(llm.requests().len(), 1, "pas de nouvel essai sur une clé refusée");
    api.with(|st| assert_eq!(st.last_error.as_deref(), Some("provider_auth")));
}

#[tokio::test]
async fn annulation_pendant_le_flux() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Écris un long texte");
    let release = Arc::new(Notify::new());
    llm.push(Script {
        status: 200,
        chunks: sse_text(&["Début du texte", " jamais envoyé"], (10, 5)),
        hold_before: Some(1),
        release: Some(Arc::clone(&release)),
    });
    let (peer, _t) = spawn_worker(&api, &llm, init(1), default_keys(false));
    llm.wait_requests(1).await;
    for _ in 0..100 {
        if !streamed_text(&peer.events()).is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let cancel = json!({ "t": "cancel", "id": "5e4d3c2b-1a09-4f8e-9d7c-6b5a49382799" });
    api.deposit("cancel:5e4d3c2b-1a09-4f8e-9d7c-6b5a49382799", cancel.clone());
    peer.send(SupervisorMsg::Inbox(InboxMsg { items: vec![cancel] })).await;
    assert_eq!(peer.wait_done().await, DoneReason::Cancelled);
    release.notify_one();
    api.with(|st| {
        assert_eq!(st.status, "cancelled");
        assert!(st.inbox.iter().all(|i| i.2));
        assert!(st.pushes.is_empty(), "pas de notification pour une annulation");
    });
    let msgs = api.clear_messages();
    assert_eq!(msgs.last().unwrap()["content"], "Début du texte", "le texte déjà vu est gardé");
    assert_eq!(llm.requests().len(), 1);
}

#[tokio::test]
async fn question_interactive_puis_reponse() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Crée un rapport");
    llm.push(Script::ok(sse_tool("call_q", "ask_question", &json!({ "question": "Quel rythme ?" }), (10, 3))));
    let mut ini = init(1);
    // Même `auto`, un outil interactif attend l'utilisateur.
    ini.tool_policy = policy(&[("ask_question", ToolPolicy::Auto)]);
    let (peer, _t) = spawn_worker(&api, &llm, ini.clone(), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Awaiting);
    api.with(|st| {
        assert_eq!(st.status, "awaiting_user");
        assert_eq!(st.pending["interactive"], true);
        assert_eq!(st.pushes, ["AI_AWAITING_USER"]);
    });
    // Réponse chiffrée (AAD __answer__:answer:<toolCallId>).
    let value = synco_e2ee::session::encrypt_field(
        &ck(),
        SID,
        "__answer__",
        &synco_e2ee::session::FieldName::Answer("call_q".into()),
        "Chaque lundi",
        &mut synco_e2ee::OsRandom,
    )
    .unwrap();
    api.with(|st| {
        st.lease_epoch = 2;
        st.status = "queued".into();
    });
    // Une décision qui ne correspond à rien : consommée, `stale_decision`.
    api.deposit("confirm:call_x", json!({ "t": "confirm", "toolCallId": "call_x", "decision": "accept" }));
    api.deposit("answer:call_q", json!({ "t": "answer", "toolCallId": "call_q", "value": value }));
    llm.push(Script::ok(sse_text(&["Noté : chaque lundi."], (10, 3))));
    let mut ini2 = ini;
    ini2.lease_epoch = 2;
    let (peer, _t) = spawn_worker(&api, &llm, ini2, default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    assert!(peer.events().iter().any(|e| e["t"] == "error" && e["code"] == "stale_decision"));
    let msgs = api.clear_messages();
    let tool = msgs.iter().find(|m| m["role"] == "tool").unwrap();
    assert_eq!(tool["toolResult"], json!({ "answer": "Chaque lundi" }));
    api.with(|st| assert!(st.inbox.iter().all(|i| i.2)));
}

#[tokio::test]
async fn cle_manquante_awaiting_key_puis_reprise() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Cherche « budget » dans l'espace Marketing");
    llm.push(Script::ok(sse_tool(
        "call_s",
        "search_messages",
        &json!({ "query": "budget", "spaceId": SPACE }),
        (10, 3),
    )));
    // Sans la clé de l'espace : need_key au superviseur, puis awaiting_key.
    let (peer, _t) = spawn_worker(&api, &llm, init(1), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Awaiting);
    assert!(
        peer.msgs().iter().any(|m| matches!(m, WorkerMsg::NeedKey(n) if n.kind == "space" && n.reference == SPACE))
    );
    api.with(|st| {
        assert_eq!(st.status, "awaiting_key");
        assert_eq!(st.awaiting_key.as_deref(), Some(&*format!("space:{SPACE}")));
        assert_eq!(st.pushes, ["AI_AWAITING_KEY"]);
    });
    assert_eq!(api.clear_messages()[1]["toolCalls"][0]["status"], "accepted");

    // La synchro P11 apporte la clé ; l'API repasse `queued` ; le worker suivant relance l'appel.
    let blob = index_blob("Le budget 2027 est validé.");
    api.with(|st| {
        st.lease_epoch = 2;
        st.status = "queued".into();
        st.search_index.insert(SPACE.into(), json!({ "indexes": [blob] }));
    });
    llm.push(Script::ok(sse_text(&["Le budget 2027 est validé."], (10, 3))));
    let (peer, _t) = spawn_worker(&api, &llm, init(2), default_keys(true));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    let msgs = api.clear_messages();
    let tool = msgs.iter().find(|m| m["role"] == "tool").unwrap();
    assert_eq!(tool["toolResult"]["mode"], "lexical");
    assert_eq!(tool["toolResult"]["results"][0]["excerpt"], "Le budget 2027 est validé.");
    assert_eq!(tool["toolResult"]["results"][0]["senderName"], "Alice");
    api.with(|st| assert_eq!(st.awaiting_key, None));
}

/// Index de recherche chiffré par la clé du salon (format de `SearchSyncService`).
fn index_blob(text: &str) -> Value {
    let payload =
        json!({ "textContent": text, "vector": [0.1, 0.2], "metadata": { "senderName": "Alice", "secret": "x" } });
    let sealed =
        synco_e2ee::primitives::seal(&THREAD_KEY, b"", payload.to_string().as_bytes(), &mut synco_e2ee::OsRandom)
            .unwrap();
    let (iv, ct) = sealed.split_at(12);
    json!({ "id": "i1", "workspaceId": SPACE, "threadId": THREAD, "type": "message", "resourceId": "msg-1",
        "encryptedBlob": synco_e2ee::encoding::b64(ct), "iv": synco_e2ee::encoding::b64(iv) })
}

#[tokio::test]
async fn outils_hors_d_atteinte_refuses_explicitement() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Lis la doc");
    llm.push(Script::ok(sse_tool("call_d", "read_documentation", &json!({ "docId": "x" }), (10, 3))));
    llm.push(Script::ok(sse_tool("call_u", "outil_imaginaire", &json!({}), (10, 3))));
    llm.push(Script::ok(sse_text(&["Je ne peux pas."], (10, 3))));
    let (peer, _t) = spawn_worker(&api, &llm, init(1), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    let msgs = api.clear_messages();
    let results: Vec<&Value> = msgs.iter().filter(|m| m["role"] == "tool").map(|m| &m["toolResult"]).collect();
    assert_eq!(results[0]["error"], "tool_unavailable_in_runtime");
    assert_eq!(results[1]["error"], "Outil inconnu: outil_imaginaire");
}

#[tokio::test]
async fn snapshot_pendant_le_flux_et_arret_demande() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Raconte");
    let release = Arc::new(Notify::new());
    llm.push(Script {
        status: 200,
        chunks: sse_text(&["Il était", " une fois"], (10, 5)),
        hold_before: Some(1),
        release: Some(Arc::clone(&release)),
    });
    let (peer, _t) = spawn_worker(&api, &llm, init(1), default_keys(false));
    llm.wait_requests(1).await;
    for _ in 0..100 {
        if !streamed_text(&peer.events()).is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    peer.send(SupervisorMsg::SnapshotRequest(runtime_protocol::pipe::SnapshotRequest { request_id: "c1".into() }))
        .await;
    let mut snap = None;
    for _ in 0..100 {
        snap = peer.msgs().into_iter().find_map(|m| match m {
            WorkerMsg::Snapshot(s) => Some(s),
            _ => None,
        });
        if snap.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let snap = snap.expect("snapshot");
    assert_eq!(snap.request_id, "c1");
    let field = format!("snapshot:{}:{}", snap.event["epoch"], snap.event["seq"]);
    let state: Value = serde_json::from_str(
        &synco_e2ee::session::decrypt_field(&ck(), SID, "__snapshot__", &field, snap.event["state"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(state["status"], "running");
    assert_eq!(state["messages"].as_array().unwrap().last().unwrap()["content"], "Il était");
    // Arrêt immédiat : état enregistré `running` (reprise par un prochain worker), bail rendu.
    peer.send(SupervisorMsg::Shutdown(ShutdownMsg { grace_ms: 0, reason: ShutdownReason::Sigterm })).await;
    assert_eq!(peer.wait_done().await, DoneReason::Shutdown);
    release.notify_one();
    api.with(|st| {
        assert_eq!(st.status, "running");
        assert!(st.lease_released);
    });
}
