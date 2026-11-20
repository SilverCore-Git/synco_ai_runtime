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

/// Clé privée RSA de test (JWK) pour ouvrir les scellés comme le ferait un membre.
fn rsa_private() -> rsa::PrivateKey {
    use rsa::BoxedUint;
    let j = rsa_fixture()["privateJwk"].clone();
    let n = synco_e2ee::encoding::from_b64u(j["n"].as_str().unwrap()).unwrap();
    let bits = u32::try_from(n.len() * 8).unwrap();
    let int = |k: &str| {
        BoxedUint::from_be_slice(&synco_e2ee::encoding::from_b64u(j[k].as_str().unwrap()).unwrap(), bits).unwrap()
    };
    rsa::PrivateKey::from_components(int("n"), int("e"), int("d"), vec![int("p"), int("q")]).unwrap()
}

#[tokio::test]
async fn outil_e2ee_create_thread_enveloppe_rt1_et_entree() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Crée le salon Projets à l'accueil et un salon vocal dans Marketing");
    let args = json!({ "threads": [
        { "name": "Projets", "type": "text", "categoryId": "cm3categoryhome0000000001" },
        { "name": "Réunions", "type": "voice", "spaceId": SPACE }
    ] });
    llm.push(Script::ok(sse_tool("call_t", "create_thread", &args, (10, 3))));
    llm.push(Script::ok(sse_text(&["Salons créés."], (10, 3))));
    let mut ini = init(1);
    ini.tool_policy = policy(&[("create_thread", ToolPolicy::Auto)]);
    let (peer, _t) = spawn_worker(&api, &llm, ini, default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);

    let private = rsa_private();
    let (created, envelopes, entries) =
        api.with(|st| (st.threads_created.clone(), st.envelopes.clone(), st.entries.clone()));
    assert_eq!(created.len(), 2);
    // Accueil : tous les membres dont la clé RSA est lisible ; espace : le seul propriétaire.
    let home_keys: Vec<&str> =
        created[0]["keys"].as_array().unwrap().iter().map(|k| k["userId"].as_str().unwrap()).collect();
    assert_eq!(home_keys, [USER, MEMBER]);
    let space_keys: Vec<&str> =
        created[1]["keys"].as_array().unwrap().iter().map(|k| k["userId"].as_str().unwrap()).collect();
    assert_eq!(space_keys, [USER]);
    assert_eq!(created[1]["type"], "vocal");
    assert_eq!(created[1]["spaceId"], SPACE);
    assert_eq!(created[0]["categoryId"], "cm3categoryhome0000000001");
    assert_eq!(created[0]["leaseEpoch"], 1);
    assert!(created[0].get("commitment").is_none(), "Q11 = B : enveloppe posée après la création");
    assert_eq!(envelopes.len(), 2);
    assert_eq!(entries.len(), 2);
    let csk_pub = peer.delegation.csk.public_key().unwrap();
    for (i, (tid, env)) in envelopes.iter().enumerate() {
        // Le membre ouvre la clé (RSA-OAEP-SHA256)…
        let sealed = synco_e2ee::encoding::from_b64(created[i]["keys"][0]["encryptedKey"].as_str().unwrap()).unwrap();
        let raw = private.decrypt(rsa::Oaep::<rsa::sha2::Sha256>::new(), &sealed).unwrap();
        assert_eq!(raw.len(), 32);
        // … vérifie l'enveloppe rt1 signée par la csk du runtime pour ce salon…
        let ctx = format!("thread:{tid}");
        assert_eq!(env["ctx"], ctx);
        let sig = synco_e2ee::keys::KeyEnvelopeSignature {
            commitment: env["commitment"].as_str().unwrap().into(),
            signature: env["signature"].as_str().unwrap().into(),
        };
        synco_e2ee::keys::verify_rt1_envelope(&csk_pub, &raw, &ctx, 1, DELEGATION, &sig).unwrap();
        // … et l'entrée posée dans la délégation s'ouvre avec DK.
        let (d, body) = &entries[i];
        assert_eq!(d, DELEGATION);
        let e = &body["entries"][0];
        assert_eq!(e["ref"], tid.as_str());
        let k = synco_e2ee::delegation::open_entry(
            &peer.delegation.dk,
            &peer.delegation.ctx,
            "thread",
            tid,
            1,
            e["ciphertext"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(k.as_bytes().as_slice(), raw.as_slice());
    }
    let msgs = api.clear_messages();
    let tool = msgs.iter().find(|m| m["role"] == "tool").unwrap();
    assert_eq!(tool["toolResult"]["threads"].as_array().unwrap().len(), 2);
    assert!(tool["toolResult"]["threads"][0].get("warning").is_none());

    // Fixture pour le test croisé TS (bun crates/worker/tests/ts/read-from-worker.ts).
    if std::env::var_os("L07_WRITE_FIXTURES").is_some() {
        let (tid, env) = &envelopes[0];
        let fixture = json!({
            "description": "Produit par le worker (test outil_e2ee_create_thread_enveloppe_rt1_et_entree) : relu par le code TS de synco_app.",
            "sessionId": SID,
            "ckHex": synco_e2ee::encoding::hex(&CK),
            "messages": api.with(|st| st.messages.clone()),
            "expectedClear": msgs,
            "thread": {
                "threadId": tid,
                "encryptedKey": created[0]["keys"][0]["encryptedKey"],
                "memberPrivateJwk": rsa_fixture()["privateJwk"],
                "ctx": env["ctx"], "version": 1,
                "commitment": env["commitment"], "signature": env["signature"],
                "delegationId": DELEGATION,
                "cskPublic": serde_json::from_str::<Value>(&csk_pub.to_canonical()).unwrap(),
            },
        });
        std::fs::write(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transcript-from-worker.json"),
            serde_json::to_string_pretty(&fixture).unwrap() + "\n",
        )
        .unwrap();
    }
}

/// Le fixture croisé (relu par le TS de synco_app) reste lisible par le worker lui-même.
#[test]
fn fixture_croise_relu_par_le_worker() {
    let f: Value = serde_json::from_str(include_str!("fixtures/transcript-from-worker.json")).unwrap();
    let msgs = synco_ai_runtime_worker::transcript::decode_messages(&ck(), SID, &f["messages"]);
    assert_eq!(msgs.len(), f["expectedClear"].as_array().unwrap().len());
    for (m, e) in msgs.iter().zip(f["expectedClear"].as_array().unwrap()) {
        assert_eq!(m.content.as_deref(), e["content"].as_str());
        assert_ne!(m.content.as_deref(), Some(synco_ai_runtime_worker::transcript::UNREADABLE));
    }
    // Tous les champs de contenu sont chiffrés (contrôle de l'API, checkConvContent).
    for m in f["messages"].as_array().unwrap() {
        for k in ["content", "toolResult", "thinking"] {
            assert!(m.get(k).is_none_or(|v| v.is_null() || v.as_str().unwrap().starts_with("gcm1:")), "{k}");
        }
    }
}

/// Aucun contenu en clair dans ce qui sort du worker hors des canaux prévus pour du clair (corps
/// des appels au fournisseur, arguments de `tools/:name/execute`) : journaux, métriques, statuts,
/// évènements et écritures de l'historique ne portent que du chiffré ou des codes.
#[tokio::test]
async fn aucun_contenu_en_clair_dans_les_journaux() {
    const SECRETS: [&str; 5] = [
        "MARQUEUR-UTILISATEUR-7f3a",
        "MARQUEUR-MODELE-91bc",
        "MARQUEUR-ARGUMENT-55d0",
        "MARQUEUR-RESULTAT-c0de",
        "MARQUEUR-PENSEE-1a2b",
    ];
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.with(|st| {
        st.tool_data.insert("list_spaces".into(), json!([{ "name": SECRETS[3] }]));
    });
    api.deposit_message(M1, &format!("Question {}", SECRETS[0]));
    llm.push(Script::ok(sse_tool("call_1", "list_spaces", &json!({ "filtre": SECRETS[2] }), (10, 3))));
    llm.push(Script::ok(sse_text(
        &[&format!("<think>{}</think>", SECRETS[4]), &format!("Réponse {}", SECRETS[1])],
        (10, 3),
    )));
    for _ in 0..4 {
        llm.push(Script::error(500, json!({ "error": { "message": SECRETS[1] } })));
    }
    let mut ini = init(1);
    ini.limits.idle_shutdown_secs = 5;
    let (peer, _t) = spawn_worker(&api, &llm, ini, default_keys(false));
    // Second message, au tour suivant (même worker), qui échoue : journaux d'erreur couverts.
    for _ in 0..200 {
        if api.with(|st| st.pushes.contains(&"AI_TURN_DONE".to_owned())) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let second = message_frame(M2, &format!("Encore {}", SECRETS[0]));
    api.deposit(M2, second.clone());
    peer.send(SupervisorMsg::Inbox(InboxMsg { items: vec![second] })).await;
    assert_eq!(peer.wait_done().await, DoneReason::Failed);
    // Le scénario a bien véhiculé les marqueurs (sinon le test ne prouverait rien).
    let clear = serde_json::to_string(&api.clear_messages()).unwrap();
    for s in SECRETS {
        assert!(clear.contains(s), "{s} absent du scénario");
    }
    // 1. Toutes les trames du worker vers le superviseur (log, metrics, status, event, …).
    let raw = peer.raw.lock().unwrap().join("\n");
    for s in SECRETS {
        assert!(!raw.contains(s), "{s} en clair dans une trame du pipe");
    }
    assert!(peer.msgs().iter().filter(|m| matches!(m, WorkerMsg::Log(_))).count() >= 2, "des journaux ont été émis");
    // 2. Tout ce que le worker envoie à l'API, sauf les arguments d'un outil serveur (clair par
    //    conception, 04 §5).
    api.with(|st| {
        for seen in st.seen.iter().filter(|s| !s.path.ends_with("/execute")) {
            for s in SECRETS {
                assert!(!seen.body.contains(s), "{s} en clair vers {}", seen.path);
            }
        }
    });
}

#[tokio::test]
async fn passerelle_ticket_sgt1_par_signed_request() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Bonjour");
    llm.push(Script::ok(sse_tool("call_1", "list_spaces", &json!({}), (5, 1))));
    llm.push(Script::ok(sse_text(&["Salut"], (5, 1))));
    let mut ini = init(1);
    ini.llm.provider = runtime_protocol::pipe::LlmProvider::Gateway;
    ini.llm.reasoning_effort = runtime_protocol::pipe::ReasoningEffort::High;
    let (peer, _t) = spawn_worker(&api, &llm, ini, default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    let heads = llm.st.lock().unwrap().headers.clone();
    assert!(heads.iter().all(|h| h.starts_with("post /v1/chat/completions ")), "{heads:?}");
    assert!(heads.iter().all(|h| h.contains("authorization: bearer sgt1.test1")), "ticket réutilisé");
    assert_eq!(api.with(|st| st.tickets), 1);
    let req = &llm.requests()[0];
    assert_eq!(req["reasoning_effort"], "high");
    assert!(req["messages"][0]["content"].as_str().unwrap().contains("<think>"), "consigne d'effort élevé");
}

#[tokio::test]
async fn bail_perdu_aucune_ecriture() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Bonjour");
    let release = Arc::new(Notify::new());
    llm.push(Script {
        status: 200,
        chunks: sse_text(&["Bon", "jour"], (5, 1)),
        hold_before: Some(1),
        release: Some(Arc::clone(&release)),
    });
    let (peer, _t) = spawn_worker(&api, &llm, init(1), default_keys(false));
    llm.wait_requests(1).await;
    // Un autre worker a pris le bail : le renouvellement échoue.
    api.with(|st| st.lease_conflict = true);
    tokio::time::sleep(Duration::from_millis(450)).await;
    release.notify_one();
    assert_eq!(peer.wait_done().await, DoneReason::Shutdown);
    api.with(|st| {
        assert!(!st.statuses.iter().any(|(s, _)| s == "idle"), "plus aucune écriture");
        assert!(!st.lease_released, "le bail n'est pas « rendu » : il n'est plus à nous");
        assert!(st.messages.len() <= 1);
    });
    assert!(peer.msgs().iter().any(|m| matches!(m, WorkerMsg::Log(l) if l.code == "lease_lost")));
}
