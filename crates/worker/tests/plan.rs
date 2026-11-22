//! Plans d'action du worker (lot L08d, docs/plan/12) contre une **API simulée** qui tient le graphe,
//! les états, les sorties enregistrées et le verrou serveur (condensat et `refs` contrôlés avec les
//! vraies fonctions de `synco-e2ee`), et un **LLM simulé**.

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

use std::time::Duration;

use common::*;
use runtime_protocol::pipe::{DoneReason, Init, PlanInit, PlanMode, ToolPolicy};
use serde_json::{Value, json};
use synco_e2ee::plan::{decrypt_plan, plan_server_digests};

const M1: &str = "3c2b1a09-8f7e-4d6c-9b5a-493827161504";
const M2: &str = "4d3c2b1a-8f7e-4d6c-9b5a-493827161505";

fn plan_init(mode: PlanMode, concurrency: u8) -> Init {
    let mut i = init(1);
    i.plan = Some(PlanInit { mode, concurrency, confirmation_timeout_secs: 604_800 });
    i
}

fn task(n: u64, title: &str, after: &[u64]) -> Value {
    json!({ "n": n, "kind": "server.call", "tool": "create_task", "args": { "title": title }, "after": after })
}

fn args(actions: &[Value]) -> Value {
    json!({ "summary": "Mon plan", "actions": actions })
}

/// Premier worker : le modèle propose, le worker écrit le plan et s'arrête (`awaiting`).
async fn propose(api: &FakeApi, llm: &FakeLlm, args: &Value, ini: Init) -> String {
    api.deposit_message(M1, "Fais ceci");
    llm.push(Script::ok(sse_tool("call_p", "propose_actions", args, (10, 3))));
    let (peer, _t) = spawn_worker(api, llm, ini, default_keys(true));
    assert_eq!(peer.wait_done().await, DoneReason::Awaiting);
    api.with(|st| st.plans.keys().next().unwrap().clone())
}

/// Worker de reprise : le modèle conclut après le bilan.
async fn resume(api: &FakeApi, llm: &FakeLlm, ini: Init) -> Peer {
    llm.push(Script::ok(sse_text(&["Terminé."], (5, 2))));
    let (peer, _t) = spawn_worker(api, llm, ini, default_keys(true));
    peer
}

/// Résultat de l'outil `propose_actions` tel qu'écrit dans l'historique.
fn plan_result(api: &FakeApi) -> Value {
    let msgs = api.clear_messages();
    let m = msgs.iter().rev().find(|m| m["role"] == "tool").expect("résultat d'outil");
    m["toolResult"].clone()
}

fn state_of(result: &Value, n: u64) -> String {
    result["actions"].as_array().unwrap().iter().find(|a| a["n"] == n).unwrap()["state"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn proposition_valide_ecrite_chiffree_puis_arret() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    let actions = [
        task(1, "Rapport", &[]),
        json!({ "n": 2, "kind": "thread.create", "args": { "name": "budget", "type": "text" } }),
        task(3, "Suite", &[1]),
    ];
    let pid = propose(&api, &llm, &args(&actions), plan_init(PlanMode::Plan, 4)).await;
    // Le modèle voit `propose_actions` et plus aucun outil mutant `ask` ni d'appareil.
    let tools: Vec<String> = llm.requests()[0]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["function"]["name"].as_str().unwrap().to_owned())
        .collect();
    assert!(tools.contains(&"propose_actions".to_owned()), "{tools:?}");
    for hidden in ["create_task", "delete_task", "create_thread", "create_file"] {
        assert!(!tools.contains(&hidden.to_owned()), "{hidden} masqué : {tools:?}");
    }
    assert!(tools.contains(&"list_spaces".to_owned()), "lectures conservées");
    api.with(|st| {
        assert_eq!(st.status, "awaiting_confirmation");
        assert_eq!(st.pushes, ["AI_AWAITING_CONFIRMATION"]);
        let post = &st.plan_posts[0];
        let meta = &post["plan"];
        // Exécutants selon 12 §4 : server.call → agent, thread.create (mode plan) → appareil.
        let ex: Vec<&str> =
            meta["actions"].as_array().unwrap().iter().map(|a| a["executor"].as_str().unwrap()).collect();
        assert_eq!(ex, ["agent", "device", "agent"]);
        assert_eq!(meta["actions"][2]["after"], json!([1]));
        assert_eq!(meta["actionCount"], 3);
        // `pendingToolCall` : plan chiffré sous l'AAD du plan, `planId` en clair.
        let pending = &post["pendingToolCall"];
        assert_eq!(
            (pending["name"].as_str(), pending["planId"].as_str()),
            (Some("propose_actions"), Some(pid.as_str()))
        );
        let clear = decrypt_plan(&ck(), SID, &pid, pending["args"].as_str().unwrap()).unwrap();
        assert_eq!(clear["toolCallId"], pending["id"]);
        assert_eq!(clear["summary"], "Mon plan");
        // Condensats = ceux de `synco-e2ee` sur le clair ; `thread.create` n'en a pas.
        let digests: Vec<(u64, String)> = meta["serverDigests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| (d["n"].as_u64().unwrap(), d["sha256Hex"].as_str().unwrap().to_owned()))
            .collect();
        assert_eq!(digests, plan_server_digests(&clear).unwrap());
        assert_eq!(digests.len(), 2);
        // Rien en clair dans l'historique écrit.
        let text = serde_json::to_string(&st.messages).unwrap();
        assert!(!text.contains("Rapport") && !text.contains("budget"), "contenu du plan en clair");
        assert!(st.refused.is_empty(), "{:?}", st.refused);
    });
}

#[tokio::test]
async fn proposition_refusee_n_ecrit_rien() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Fais ceci");
    let too_many: Vec<Value> = (1..=101).map(|n| task(n, "t", &[])).collect();
    // Kind inconnu, dépendance non antérieure, plan trop gros : rien n'est écrit, le modèle corrige.
    llm.push(Script::ok(sse_tool(
        "c1",
        "propose_actions",
        &args(&[json!({ "n": 1, "kind": "tout.supprimer", "args": {} })]),
        (1, 1),
    )));
    llm.push(Script::ok(sse_tool("c2", "propose_actions", &args(&[task(1, "a", &[2]), task(2, "b", &[])]), (1, 1))));
    llm.push(Script::ok(sse_tool("c3", "propose_actions", &args(&too_many), (1, 1))));
    llm.push(Script::ok(sse_text(&["Je découpe."], (1, 1))));
    let (peer, _t) = spawn_worker(&api, &llm, plan_init(PlanMode::Plan, 4), default_keys(true));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    api.with(|st| {
        assert!(st.plan_posts.is_empty() && st.plans.is_empty(), "aucun plan écrit");
        assert!(st.refused.is_empty(), "{:?}", st.refused);
    });
    let results: Vec<Value> =
        api.clear_messages().iter().filter(|m| m["role"] == "tool").map(|m| m["toolResult"].clone()).collect();
    let details: Vec<&str> = results.iter().map(|r| r["detail"].as_str().unwrap()).collect();
    assert_eq!(details, ["plan_kind", "plan_after", "plan_too_large"]);
    assert!(results.iter().all(|r| r["error"] == "plan_invalid"));
    // Un outil `deny` n'est jamais proposé.
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Fais ceci");
    llm.push(Script::ok(sse_tool("c1", "propose_actions", &args(&[task(1, "a", &[])]), (1, 1))));
    llm.push(Script::ok(sse_text(&["Ok."], (1, 1))));
    let mut ini = plan_init(PlanMode::Plan, 4);
    ini.tool_policy = policy(&[("create_task", ToolPolicy::Deny)]);
    let (peer, _t) = spawn_worker(&api, &llm, ini, default_keys(true));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    assert_eq!(plan_result(&api)["detail"], "plan_kind");
}

#[tokio::test]
async fn reprise_apres_decision_partielle() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    // 1 ; 2 indépendante (décochée) ; 3 dépend de 1 ; 4 dépend de 2 (décochée en cascade).
    let actions = [task(1, "a", &[]), task(2, "b", &[]), task(3, "c", &[1]), task(4, "d", &[2])];
    let pid = propose(&api, &llm, &args(&actions), plan_init(PlanMode::Plan, 4)).await;
    api.decide(&pid, &[1, 3]);
    let peer = resume(&api, &llm, plan_init(PlanMode::Plan, 4)).await;
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    api.with(|st| {
        let runs: Vec<&str> = st.tool_runs.iter().map(|(_, a)| a["title"].as_str().unwrap()).collect();
        assert_eq!(runs, ["a", "c"], "seules les actions acceptées, une dépendante après sa cible");
        assert_eq!(st.plans[&pid].status, "done");
        assert!(st.refused.is_empty(), "{:?}", st.refused);
        assert!(st.inbox.iter().all(|i| i.2), "décision consommée");
    });
    // `propose_actions` est clos par un `tool_result` avec le bilan, avant la suite du tour.
    let r = plan_result(&api);
    assert_eq!(r["status"], "done");
    let states: Vec<String> = (1..=4).map(|n| state_of(&r, n)).collect();
    assert_eq!(states, ["done", "skipped", "done", "skipped"]);
    assert!(r["actions"][0]["output"]["id"].as_str().unwrap().starts_with("cm3obj"));
    // Le modèle a reçu le bilan avant de conclure.
    let last = llm.requests().last().unwrap().clone();
    assert!(last["messages"].as_array().unwrap().iter().any(|m| m["role"] == "tool"));
    assert_eq!(api.with(|st| st.status.clone()), "idle");
}

#[tokio::test]
async fn parallelisme_borne_par_la_concurrence() {
    for (concurrency, expected) in [(2u8, 2usize), (4, 4), (8, 6)] {
        let api = FakeApi::new();
        let llm = FakeLlm::start();
        let actions: Vec<Value> = (1..=6).map(|n| task(n, &format!("t{n}"), &[])).collect();
        let pid = propose(&api, &llm, &args(&actions), plan_init(PlanMode::Plan, concurrency)).await;
        api.with(|st| st.exec_delay_ms = 120);
        api.decide(&pid, &[1, 2, 3, 4, 5, 6]);
        let peer = resume(&api, &llm, plan_init(PlanMode::Plan, concurrency)).await;
        assert_eq!(peer.wait_done().await, DoneReason::Idle);
        api.with(|st| {
            assert_eq!(
                st.max_active, expected,
                "concurrence {concurrency} : ni plus, ni moins quand le travail suffit"
            );
            assert_eq!(st.plans[&pid].status, "done");
            // Plus petite `n` d'abord.
            assert_eq!(st.tool_runs.first().unwrap().1["title"], "t1");
        });
    }
}

#[tokio::test]
async fn limite_de_debit_429_reessayee_puis_echec() {
    // Deux 429 : le même appel est réessayé, l'action aboutit.
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    let pid = propose(&api, &llm, &args(&[task(1, "a", &[])]), plan_init(PlanMode::Plan, 4)).await;
    api.with(|st| st.throttle_429 = 2);
    api.decide(&pid, &[1]);
    let peer = resume(&api, &llm, plan_init(PlanMode::Plan, 4)).await;
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    api.with(|st| {
        assert_eq!(st.throttled, 2);
        assert_eq!(st.tool_runs.len(), 1, "exécutée une seule fois");
        assert_eq!(st.plans[&pid].status, "done");
    });
    assert_eq!(state_of(&plan_result(&api), 1), "done");

    // Toujours limité : 4 essais en tout (3 nouveaux), puis `failed` `rate_limited`, dépendantes `skipped`.
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    let pid = propose(&api, &llm, &args(&[task(1, "a", &[]), task(2, "b", &[1])]), plan_init(PlanMode::Plan, 4)).await;
    api.with(|st| st.throttle_429 = 100);
    api.decide(&pid, &[1, 2]);
    let peer = resume(&api, &llm, plan_init(PlanMode::Plan, 4)).await;
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    api.with(|st| assert_eq!(st.throttled, 4, "1 essai + 3 nouveaux"));
    let r = plan_result(&api);
    assert_eq!((state_of(&r, 1).as_str(), r["actions"][0]["code"].as_str()), ("failed", Some("rate_limited")));
    assert_eq!(state_of(&r, 2), "skipped");
}

#[tokio::test]
async fn refs_resolues_depuis_les_resultats_authentifies() {
    let ref_task = json!({ "n": 2, "kind": "server.call", "tool": "create_task", "args": {}, "after": [1],
        "argsRefs": { "title": "$1.id" } });
    let cat = json!({ "n": 1, "kind": "category.create", "args": { "name": "Finance" } });

    // Nominal : l'appareil crée la catégorie, le worker résout `$1.id` et l'API compare.
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    let pid = propose(&api, &llm, &args(&[cat.clone(), ref_task.clone()]), plan_init(PlanMode::Plan, 4)).await;
    api.decide(&pid, &[1, 2]);
    api.device_phase(&pid, 1, &[(1, "done", Some("cm3categorie0000000001"))], None);
    let peer = resume(&api, &llm, plan_init(PlanMode::Plan, 4)).await;
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    api.with(|st| {
        let exec = &st.plan_execs[0];
        assert_eq!(exec["args"], json!({}), "`args` envoyés non résolus");
        assert_eq!(exec["argsRefs"], json!({ "title": "$1.id" }));
        assert_eq!(exec["refs"], json!({ "title": "cm3categorie0000000001" }));
        assert_eq!(st.tool_runs[0].1["title"], "cm3categorie0000000001", "arguments exécutés = args ∪ refs");
        assert_eq!(st.plans[&pid].status, "done");
        assert!(st.inbox.iter().all(|i| i.2), "plan_result consommé à la fermeture");
    });

    // Sortie enregistrée par l'API différente de celle du résultat authentifié : rien ne part.
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    let pid = propose(&api, &llm, &args(&[cat, ref_task]), plan_init(PlanMode::Plan, 4)).await;
    api.decide(&pid, &[1, 2]);
    api.device_phase(&pid, 1, &[(1, "done", Some("cm3categorie0000000001"))], Some("cm3autre00000000000000"));
    let peer = resume(&api, &llm, plan_init(PlanMode::Plan, 4)).await;
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    api.with(|st| assert!(st.plan_execs.is_empty(), "résultat incohérent : aucune exécution"));
    let r = plan_result(&api);
    assert_eq!((r["error"].as_str(), r["detail"].as_str()), (Some("plan_aborted"), Some("refs_inconsistent")));
}

#[tokio::test]
async fn resultat_de_phase_forge_clot_tool_call_unverified() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    let pid = propose(&api, &llm, &args(&[task(1, "a", &[])]), plan_init(PlanMode::Plan, 4)).await;
    api.decide(&pid, &[1]);
    // Valeur chiffrée pour une autre phase que celle annoncée dans l'élément de boîte (AAD fausse).
    api.device_phase(&pid, 1, &[], None);
    api.with(|st| {
        let item = st.inbox.last_mut().unwrap();
        item.1["phase"] = json!(2);
        item.0 = format!("plan:{pid}:2");
    });
    let peer = resume(&api, &llm, plan_init(PlanMode::Plan, 4)).await;
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    assert_eq!(plan_result(&api)["error"], "tool_call_unverified");
    api.with(|st| assert!(st.tool_runs.is_empty(), "rien n'est exécuté sur un résultat non authentifié"));
}

#[tokio::test]
async fn arret_du_plan_pas_de_nouvelle_action() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    let actions: Vec<Value> = (1..=4).map(|n| task(n, &format!("t{n}"), &[])).collect();
    let pid = propose(&api, &llm, &args(&actions), plan_init(PlanMode::Plan, 1)).await;
    api.with(|st| st.exec_delay_ms = 300);
    api.decide(&pid, &[1, 2, 3, 4]);
    let peer = resume(&api, &llm, plan_init(PlanMode::Plan, 1)).await;
    // La première action est en cours : l'utilisateur arrête le plan.
    for _ in 0..200 {
        if api.with(|st| st.active) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    api.stop_plan(&pid);
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    api.with(|st| assert_eq!(st.tool_runs.len(), 1, "celle en cours va à son terme, aucune autre ne démarre"));
    let r = plan_result(&api);
    assert_eq!(r["stopped"], true);
    let states: Vec<String> = (1..=4).map(|n| state_of(&r, n)).collect();
    assert_eq!(states, ["done", "skipped", "skipped", "skipped"]);
}

#[tokio::test]
async fn message_pendant_un_plan_accepte_traite_apres_la_cloture() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    let pid = propose(&api, &llm, &args(&[task(1, "a", &[])]), plan_init(PlanMode::Plan, 4)).await;
    api.decide(&pid, &[1]);
    api.deposit_message(M2, "Et le budget ?");
    llm.push(Script::ok(sse_text(&["Voici le budget."], (5, 2))));
    let peer = resume(&api, &llm, plan_init(PlanMode::Plan, 4)).await;
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    let msgs = api.clear_messages();
    let roles: Vec<&str> = msgs.iter().map(|m| m["role"].as_str().unwrap()).collect();
    // user, assistant(propose_actions), tool(bilan), user(message différé), assistant.
    assert_eq!(roles[..4], ["user", "assistant", "tool", "user"], "{roles:?}");
    assert_eq!(msgs[3]["id"], M2);
    api.with(|st| assert!(st.inbox.iter().all(|i| i.2)));

    // Avant la décision, le message remplace le plan (règle existante, 08 §2).
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    let _pid = propose(&api, &llm, &args(&[task(1, "a", &[])]), plan_init(PlanMode::Plan, 4)).await;
    api.deposit_message(M2, "Finalement non.");
    api.with(|st| st.status = "queued".into());
    llm.push(Script::ok(sse_text(&["D'accord."], (5, 2))));
    let (peer, _t) = spawn_worker(&api, &llm, plan_init(PlanMode::Plan, 4), default_keys(true));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    assert_eq!(plan_result(&api)["error"], "superseded_by_user_message");
}

#[tokio::test]
async fn confirm_visant_propose_actions_ignore() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    let _pid = propose(&api, &llm, &args(&[task(1, "a", &[])]), plan_init(PlanMode::Plan, 4)).await;
    let call = api.with(|st| st.pending["id"].as_str().unwrap().to_owned());
    api.deposit(&format!("confirm:{call}"), json!({ "t": "confirm", "toolCallId": call, "decision": "accept" }));
    api.with(|st| st.status = "queued".into());
    let (peer, _t) = spawn_worker(&api, &llm, plan_init(PlanMode::Plan, 4), default_keys(true));
    assert_eq!(peer.wait_done().await, DoneReason::Awaiting);
    api.with(|st| {
        assert!(st.tool_runs.is_empty(), "un confirm ne déclenche aucune exécution");
        assert_eq!(st.plans.values().next().unwrap().status, "proposed");
    });
}

#[tokio::test]
async fn au_plus_trois_plans_par_tour() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Fais ceci");
    let bad = args(&[json!({ "n": 1, "kind": "tout.supprimer", "args": {} })]);
    for i in 0..4 {
        llm.push(Script::ok(sse_tool(&format!("c{i}"), "propose_actions", &bad, (1, 1))));
    }
    let (peer, _t) = spawn_worker(&api, &llm, plan_init(PlanMode::Plan, 4), default_keys(true));
    assert_eq!(peer.wait_done().await, DoneReason::Failed);
    api.with(|st| {
        assert_eq!(st.status, "failed");
        assert_eq!(st.last_error.as_deref(), Some("plan_limit"));
    });
}

#[tokio::test]
async fn mode_autonome_thread_create_par_le_runtime() {
    // Autonome, `create_thread` en `ask` (défaut) : exécuté par le worker (`POST /e2ee/threads` + plan).
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    let actions =
        [json!({ "n": 1, "kind": "thread.create", "args": { "name": "budget", "type": "text", "spaceId": SPACE } })];
    let pid = propose(&api, &llm, &args(&actions), plan_init(PlanMode::Auto, 4)).await;
    api.with(|st| {
        assert_eq!(st.plan_posts[0]["plan"]["actions"][0]["executor"], "agent");
        let members = st.members.clone();
        st.space_members.insert(SPACE.to_owned(), members);
    });
    api.decide(&pid, &[1]);
    let peer = resume(&api, &llm, plan_init(PlanMode::Auto, 4)).await;
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    api.with(|st| {
        assert_eq!(st.threads_created[0]["plan"], json!({ "planId": pid, "n": 1 }));
        assert_eq!(st.threads_created[0]["name"], "budget");
        assert_eq!(st.plans[&pid].status, "done");
    });
    let r = plan_result(&api);
    assert_eq!(state_of(&r, 1), "done");
    assert!(r["actions"][0]["output"]["id"].as_str().unwrap().starts_with("cm3threadnew"));

    // Autonome mais `create_thread` en `auto` : hors plan, l'outil reste appelé directement.
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Crée un salon");
    llm.push(Script::ok(sse_tool("c1", "propose_actions", &args(&actions), (1, 1))));
    llm.push(Script::ok(sse_text(&["Ok."], (1, 1))));
    let mut ini = plan_init(PlanMode::Auto, 4);
    ini.tool_policy = policy(&[("create_thread", ToolPolicy::Auto)]);
    let (peer, _t) = spawn_worker(&api, &llm, ini, default_keys(true));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    assert_eq!(plan_result(&api)["detail"], "plan_kind", "action hors plan refusée");
    let tools: Vec<String> = llm.requests()[0]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["function"]["name"].as_str().unwrap().to_owned())
        .collect();
    assert!(tools.contains(&"create_thread".to_owned()), "{tools:?}");
}

#[tokio::test]
async fn plan_mixte_phases_alternees_et_reprise_apres_agent_result() {
    use synco_e2ee::plan::{Executor, GraphAction, PlanGraph, decrypt_phase_result};
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    // 1 (agent) ; 2 (appareil, indépendante de 1) ; 3 (agent) a besoin de 1 et de 2.
    let actions = [
        task(1, "a", &[]),
        json!({ "n": 2, "kind": "category.create", "args": { "name": "Finance" } }),
        json!({ "n": 3, "kind": "server.call", "tool": "create_task", "args": {}, "after": [1, 2],
            "argsRefs": { "title": "$2.id" } }),
    ];
    let pid = propose(&api, &llm, &args(&actions), plan_init(PlanMode::Plan, 4)).await;
    api.decide(&pid, &[1, 2, 3]);

    // Phase d'agent 1 : l'action 1 part, la 3 attend l'appareil → `plan_agent_result:1`, le worker s'arrête.
    let (peer, _t) = spawn_worker(&api, &llm, plan_init(PlanMode::Plan, 4), default_keys(true));
    assert_eq!(peer.wait_done().await, DoneReason::Awaiting);
    let graph = api.with(|st| {
        let p = &st.plans[&pid];
        assert_eq!(p.agent_phases, 1);
        assert_eq!(st.status, "awaiting_confirmation");
        assert_eq!(st.agent_posts[0]["phase"], 1);
        PlanGraph::new(
            p.actions
                .iter()
                .map(|a| GraphAction {
                    n: a.n,
                    executor: Executor::parse(&a.executor).unwrap(),
                    after: a.after.clone(),
                })
                .collect(),
        )
        .unwrap()
    });
    // Le résultat de phase est chiffré sous `CK` avec l'AAD de l'agent, la phase et le plan.
    let value = api.with(|st| st.plans[&pid].agent_results[0].1.clone());
    let clear = decrypt_phase_result(&ck(), SID, &pid, Executor::Agent, 1, &graph, &value).unwrap();
    assert_eq!(clear["outcomes"].as_array().unwrap().len(), 1);
    assert_eq!(clear["outcomes"][0]["state"], "done");
    assert!(
        decrypt_phase_result(&ck(), SID, &pid, Executor::Device, 1, &graph, &value).is_err(),
        "AAD de l'autre exécutant"
    );
    api.with(|st| assert!(st.tool_runs.len() == 1 && st.plan_execs.len() == 1));

    // L'appareil termine l'action 2 ; le worker reprend, résout `$2.id` et ferme le plan.
    api.device_phase(&pid, 1, &[(2, "done", Some("cm3categorie0000000002"))], None);
    let peer = resume(&api, &llm, plan_init(PlanMode::Plan, 4)).await;
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    api.with(|st| {
        assert_eq!(st.tool_runs.len(), 2);
        assert_eq!(st.tool_runs[1].1["title"], "cm3categorie0000000002");
        assert_eq!(st.plans[&pid].status, "done");
    });
    assert_eq!(plan_result(&api)["status"], "done");
}

#[tokio::test]
async fn action_echouee_sur_place_ne_repart_jamais_apres_un_retry() {
    // 1 (agent, toujours limitée en 429) ; 2 (appareil, encore `pending`) ; 3 (agent) dépend de 1.
    // L'API garde 1 `pending` et prête : `agent-result` est refusé (`plan_phase_mismatch`), le worker
    // relit, mais l'action déjà `failed` sur place (vue superposée) ne doit pas repartir (08 §5).
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    let actions = [
        task(1, "a", &[]),
        json!({ "n": 2, "kind": "category.create", "args": { "name": "Finance" } }),
        task(3, "c", &[1]),
    ];
    let pid = propose(&api, &llm, &args(&actions), plan_init(PlanMode::Plan, 4)).await;
    api.with(|st| st.throttle_429 = 1000);
    api.decide(&pid, &[1, 2, 3]);
    let (peer, _t) = spawn_worker(&api, &llm, plan_init(PlanMode::Plan, 4), default_keys(true));
    let _ = peer.wait_done().await;
    api.with(|st| {
        assert_eq!(st.throttled, 4, "1 essai + 3 nouveaux, jamais relancée après le Retry");
        assert!(st.tool_runs.is_empty());
    });
}

#[tokio::test]
async fn actions_finales_non_rapportees_figurent_dans_le_resultat_et_le_bilan() {
    use synco_e2ee::plan::{Executor, GraphAction, PlanGraph, decrypt_phase_result};
    // 1 (agent) déjà `done` sur place, jamais rapportée (worker précédent mort avant le dépôt) ;
    // 2 (appareil) ; 3 (agent) a besoin de 1 et de 2.
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    let actions = [
        task(1, "a", &[]),
        json!({ "n": 2, "kind": "category.create", "args": { "name": "Finance" } }),
        json!({ "n": 3, "kind": "server.call", "tool": "create_task", "args": {}, "after": [1, 2],
            "argsRefs": { "title": "$2.id" } }),
    ];
    let pid = propose(&api, &llm, &args(&actions), plan_init(PlanMode::Plan, 4)).await;
    api.decide(&pid, &[1, 2, 3]);
    api.with(|st| {
        let a = &mut st.plans.get_mut(&pid).unwrap().actions[0];
        a.state = "done".into();
        a.output = Some(json!({ "id": "cm3dejafait0000000001" }));
    });
    let (peer, _t) = spawn_worker(&api, &llm, plan_init(PlanMode::Plan, 4), default_keys(true));
    assert_eq!(peer.wait_done().await, DoneReason::Awaiting);
    let graph = api.with(|st| {
        PlanGraph::new(
            st.plans[&pid]
                .actions
                .iter()
                .map(|a| GraphAction {
                    n: a.n,
                    executor: Executor::parse(&a.executor).unwrap(),
                    after: a.after.clone(),
                })
                .collect(),
        )
        .unwrap()
    });
    let value = api.with(|st| st.plans[&pid].agent_results[0].1.clone());
    let clear = decrypt_phase_result(&ck(), SID, &pid, Executor::Agent, 1, &graph, &value).unwrap();
    assert_eq!(clear["outcomes"], json!([{ "n": 1, "state": "done", "output": { "id": "cm3dejafait0000000001" } }]));

    // Après la phase d'appareil, le bilan garde la sortie de 1 (relue dans le résultat déposé).
    api.device_phase(&pid, 1, &[(2, "done", Some("cm3categorie0000000002"))], None);
    let peer = resume(&api, &llm, plan_init(PlanMode::Plan, 4)).await;
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    let r = plan_result(&api);
    assert_eq!(r["status"], "done");
    assert_eq!(r["actions"][0]["output"]["id"], "cm3dejafait0000000001");
}
