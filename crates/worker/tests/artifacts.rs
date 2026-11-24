//! Outil `send_file` (lot L08e, docs/plan/13) : vecteurs `artifacts.json` rejoués sans modification
//! (validation, chiffrement exact, forme réduite, corps de dépôt, trame, bornes de tour), puis la
//! boucle d'agent contre l'API simulée (dépôt, rejeu, quota, refus, politique, transcript sans clair).

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

use common::*;
use runtime_protocol::pipe::{DoneReason, ToolPolicy};
use serde_json::{Value, json};
use synco_ai_runtime_worker::artifact::{self, Binding, Refusal};
use synco_e2ee::encoding::from_hex;
use synco_e2ee::session;
use synco_e2ee::{RandomSource, Result as E2eeResult, SymmetricKey};

const M1: &str = "3c2b1a09-8f7e-4d6c-9b5a-493827161504";

fn vectors() -> Value {
    let path = format!("{}/../../docs/plan/vectors/artifacts.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap()
}

fn key(hex_key: &str) -> SymmetricKey {
    SymmetricKey::from_bytes(from_hex(hex_key).unwrap().as_slice().try_into().unwrap())
}

/// IV figé par appel, dans l'ordre : uniquement pour rejouer les vecteurs.
struct Ivs(Vec<Vec<u8>>);

impl RandomSource for Ivs {
    fn fill(&mut self, dest: &mut [u8]) -> E2eeResult<()> {
        dest.copy_from_slice(&self.0.remove(0));
        Ok(())
    }
}

fn filled(c: &Value) -> String {
    match c.get("fill") {
        Some(f) => f.as_str().unwrap().repeat(usize::try_from(c["fillLength"].as_u64().unwrap()).unwrap()),
        None => c["content"].as_str().unwrap().to_owned(),
    }
}

fn code_of(r: Refusal) -> &'static str {
    r.code()
}

#[test]
fn vecteurs_formats_noms_et_contenus() {
    let v = vectors();
    let formats: Vec<&str> = v["formats"].as_array().unwrap().iter().map(|f| f.as_str().unwrap()).collect();
    assert_eq!(formats, artifact::FORMATS, "liste des 25 extensions");

    let mut n = 0;
    for c in v["nameCases"].as_array().unwrap() {
        let args = json!({ "name": c["input"]["name"], "ext": c["input"]["ext"], "content": "x" });
        let name = s(c, "name");
        match (s(c, "expect"), artifact::validate(&args)) {
            ("ok", Ok(f)) => {
                assert_eq!(f.name, s(c, "finalName"), "{name}");
                assert_eq!(f.ext, s(c, "ext"), "{name}");
            }
            (expect, Err(r)) => assert_eq!(code_of(r), expect, "{name}"),
            (expect, other) => panic!("{name} : attendu {expect}, obtenu {other:?}"),
        }
        n += 1;
    }
    for c in v["contentCases"].as_array().unwrap() {
        let args = json!({ "name": "fichier", "ext": "txt", "content": filled(c) });
        let name = s(c, "name");
        match (s(c, "expect"), artifact::validate(&args)) {
            ("ok", Ok(f)) => {
                assert_eq!(u64::try_from(f.content.len()).unwrap(), c["expectSize"].as_u64().unwrap(), "{name}");
                let sha = synco_e2ee::encoding::hex(&synco_e2ee::primitives::sha256(f.content.as_bytes()));
                assert_eq!(sha, s(c, "expectSha256"), "{name}");
            }
            (expect, Err(r)) => assert_eq!(code_of(r), expect, "{name}"),
            (expect, other) => panic!("{name} : attendu {expect}, obtenu {other:?}"),
        }
        n += 1;
    }
    assert_eq!(n, 28 + 8, "vecteurs de validation rejoués");
}

#[test]
fn vecteurs_chiffrement_exact_forme_reduite_et_depot() {
    let v = vectors();
    let ck = key(s(&v["keys"], "ckHex"));
    let model = &v["toolCall"]["modelArgs"];
    let file = artifact::validate(model).unwrap();
    assert_eq!(file.name, "budget-lancement.csv");
    let b = Binding {
        session_id: s(&v, "sessionId"),
        message_id: s(&v, "messageId"),
        tool_call_id: s(&v, "toolCallId"),
        artifact_id: s(&v, "artifactId"),
    };
    let ivs = Ivs(vec![from_hex(s(&v, "ivMetaHex")).unwrap(), from_hex(s(&v, "ivContentHex")).unwrap()]);
    let sealed = artifact::seal(&ck, &b, &file, &mut { ivs }).unwrap();
    assert_eq!(sealed.meta, s(&v, "metaValue"));
    assert_eq!(sealed.value, s(&v, "contentValue"));
    // Clair de `meta` : JCS exact.
    let clear = session::decrypt_field(&ck, b.session_id, b.artifact_id, "artifact_meta", &sealed.meta).unwrap();
    assert_eq!(clear, s(&v, "metaCanonical"));
    // Corps de dépôt, forme réduite des arguments et résultat d'outil.
    assert_eq!(artifact::deposit_body(3, b.artifact_id, &sealed), v["deposit"]);
    assert_eq!(artifact::reduced_args(b.artifact_id, &file), v["toolCall"]["storedArgs"]);
    assert_eq!(
        synco_e2ee::plan::jcs(&artifact::reduced_args(b.artifact_id, &file)).unwrap(),
        s(&v["toolCall"], "storedArgsCanonical")
    );
    assert_eq!(artifact::success_result(b.artifact_id, &file), v["toolCall"]["toolResult"]);
    assert_eq!(
        synco_e2ee::plan::jcs(&artifact::success_result(b.artifact_id, &file)).unwrap(),
        s(&v["toolCall"], "toolResultCanonical")
    );
}

#[test]
fn vecteurs_chiffrement_cas_d_echec_et_de_lecture() {
    let v = vectors();
    let ck = key(s(&v["keys"], "ckHex"));
    let other = key(s(&v["keys"], "otherCkHex"));
    let cases = v["encryptionCases"].as_array().unwrap();
    for c in cases {
        let name = s(c, "name");
        // « autre CK » : mêmes entrées que le cas de référence, clé différente.
        let k = if name == "autre CK" { &other } else { &ck };
        let r = session::decrypt_field(k, s(c, "sessionId"), s(c, "messageId"), s(c, "fieldName"), s(c, "value"));
        match s(c, "expect") {
            "ok" => assert_eq!(r.unwrap(), s(c, "expectClear"), "{name}"),
            code => assert_eq!(r.unwrap_err().code(), code, "{name}"),
        }
    }
    assert_eq!(cases.len(), 8, "vecteurs de chiffrement rejoués");
}

#[test]
fn vecteurs_bornes_de_tour_et_taille_chiffree() {
    let v = vectors();
    // Bornes de tour (quotaCases, partie worker) : 5 par tour.
    for c in v["quotaCases"].as_array().unwrap().iter().filter(|c| c.get("sentThisTurn").is_some()) {
        let sent = usize::try_from(c["sentThisTurn"].as_u64().unwrap()).unwrap();
        let ok = sent < artifact::MAX_PER_TURN;
        assert_eq!(ok, s(c, "expect") == "ok", "{}", s(c, "name"));
    }
    // 262 144 octets de contenu : `value` ≤ 349 569 caractères, `meta` ≤ 1 409 (boundCases, 13 §4.2).
    let ck = key(s(&v["keys"], "ckHex"));
    let file =
        artifact::validate(&json!({ "name": "n".repeat(116), "ext": "csv", "content": "é".repeat(131_072) })).unwrap();
    let b = Binding {
        session_id: s(&v, "sessionId"),
        message_id: s(&v, "messageId"),
        tool_call_id: "call_3",
        artifact_id: s(&v, "artifactId"),
    };
    let sealed = artifact::seal(&ck, &b, &file, &mut synco_e2ee::OsRandom).unwrap();
    assert_eq!(sealed.value.len(), 349_569);
    assert!(sealed.meta.len() <= 1_409);
}

// ---------------------------------------------------------------------------
// Boucle d'agent
// ---------------------------------------------------------------------------

const SECRET: &str = "Location salle;1200;SECRET-LIGNE";

fn csv() -> Value {
    json!({ "name": "budget-lancement", "ext": "csv", "content": format!("poste;montant\n{SECRET}\n") })
}

fn tool_result_of(msgs: &[Value], nth: usize) -> Value {
    msgs.iter().filter(|m| m["role"] == "tool").nth(nth).unwrap()["toolResult"].clone()
}

#[tokio::test]
async fn depot_chiffre_trame_et_transcript_sans_contenu() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Fais-moi un budget");
    llm.push(Script::ok(sse_tool("c1", "send_file", &csv(), (10, 3))));
    llm.push(Script::ok(sse_text(&["Voilà le budget."], (20, 3))));
    let (peer, _t) = spawn_worker(&api, &llm, init(1), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);

    let (body, requests) = api.with(|st| (st.artifacts.clone(), st.artifact_requests));
    assert_eq!((body.len(), requests), (1, 1));
    let aid = body[0]["id"].as_str().unwrap().to_owned();
    assert_eq!(body[0]["leaseEpoch"], 1);
    let ck = ck();
    let content = session::decrypt_field(&ck, SID, &aid, "artifact", body[0]["value"].as_str().unwrap()).unwrap();
    assert_eq!(content, format!("poste;montant\n{SECRET}\n"));
    let meta: Value = serde_json::from_str(
        &session::decrypt_field(&ck, SID, &aid, "artifact_meta", body[0]["meta"].as_str().unwrap()).unwrap(),
    )
    .unwrap();

    // Transcript : forme réduite, jamais le contenu ; résultat d'outil conforme au §2.3.
    let msgs = api.clear_messages();
    let call = &msgs.iter().find(|m| m["role"] == "assistant").unwrap()["toolCalls"][0];
    assert_eq!(call["status"], "done");
    assert_eq!((call["category"].as_str(), call["mutating"].as_bool()), (Some("client"), Some(false)));
    assert_eq!(call["arguments"], json!({ "artifactId": aid, "ext": "csv", "name": "budget-lancement.csv" }));
    assert_eq!(
        tool_result_of(&msgs, 0),
        json!({ "artifactId": aid, "name": "budget-lancement.csv", "size": content.len() })
    );
    // `meta` lie l'artefact à son message et à son appel.
    let mid = msgs.iter().find(|m| m["role"] == "assistant").unwrap()["id"].as_str().unwrap().to_owned();
    assert_eq!(
        (meta["messageId"].as_str(), meta["toolCallId"].as_str(), meta["sessionId"].as_str(), meta["v"].as_u64()),
        (Some(mid.as_str()), call["id"].as_str(), Some(SID), Some(1))
    );
    assert_eq!(meta["size"].as_u64().unwrap(), u64::try_from(content.len()).unwrap());

    // Trame `artifact` : identifiants seulement, après le dépôt.
    let ev = peer.events();
    let frame = ev.iter().find(|e| e["t"] == "artifact").unwrap();
    assert_eq!(
        frame,
        &json!({ "v": 1, "t": "artifact", "epoch": 1, "seq": frame["seq"], "messageId": mid,
                 "toolCallId": call["id"], "artifactId": aid })
    );

    // Aucun clair : ni dans le transcript écrit, ni dans les évènements, ni dans les requêtes à l'API
    // (hors dépôt chiffré), ni dans les messages du pipe, ni rendu au modèle.
    for marker in ["SECRET-LIGNE", "budget-lancement"] {
        if marker == "SECRET-LIGNE" {
            assert!(!serde_json::to_string(&msgs).unwrap().contains(marker), "transcript");
        }
        assert!(!serde_json::to_string(&ev).unwrap().contains(marker), "évènements");
        assert!(!format!("{:?}", peer.msgs()).contains(marker), "pipe");
        api.with(|st| {
            for seen in &st.seen {
                assert!(!seen.body.contains(marker), "{marker} en clair vers {}", seen.path);
            }
        });
    }
    let second = serde_json::to_string(&llm.requests()[1]).unwrap();
    assert!(!second.contains("SECRET-LIGNE"), "le contenu n'est jamais rejoué au modèle");
    assert!(second.contains(&aid), "forme réduite rejouée");
}

#[tokio::test]
async fn l_outil_est_donne_au_modele_et_retire_par_deny() {
    for deny in [false, true] {
        let api = FakeApi::new();
        let llm = FakeLlm::start();
        api.deposit_message(M1, "Un fichier");
        llm.push(Script::ok(sse_tool("c1", "send_file", &csv(), (10, 3))));
        llm.push(Script::ok(sse_text(&["Ok."], (20, 3))));
        let mut ini = init(1);
        if deny {
            ini.tool_policy = policy(&[("send_file", ToolPolicy::Deny)]);
        }
        let (peer, _t) = spawn_worker(&api, &llm, ini, default_keys(false));
        assert_eq!(peer.wait_done().await, DoneReason::Idle);
        let req = &llm.requests()[0];
        let tool = req["tools"].as_array().unwrap().iter().find(|t| t["function"]["name"] == "send_file").cloned();
        let msgs = api.clear_messages();
        if deny {
            assert!(tool.is_none(), "retiré de la liste");
            assert_eq!(tool_result_of(&msgs, 0), json!({ "error": "tool_denied_by_policy" }));
            assert_eq!(api.with(|st| st.artifact_requests), 0);
            let call = &msgs.iter().find(|m| m["role"] == "assistant").unwrap()["toolCalls"][0];
            assert_eq!(call["status"], "rejected");
            assert!(call["arguments"].get("content").is_none());
        } else {
            let tool = tool.unwrap();
            assert_eq!(tool["function"]["description"], artifact::DESCRIPTION);
            assert_eq!(tool["function"]["parameters"]["required"], json!(["name", "ext", "content"]));
            assert_eq!(api.with(|st| st.artifacts.len()), 1);
        }
    }
}

#[tokio::test]
async fn refus_de_validation_rien_n_est_depose_le_tour_continue() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Des fichiers");
    for args in [
        json!({ "name": "x", "ext": "exe", "content": "a" }),
        json!({ "name": "../x", "ext": "txt", "content": "a" }),
        json!({ "name": "x", "ext": "txt", "content": "" }),
        json!({ "name": "x", "ext": "txt", "content": "a".repeat(262_145) }),
        json!({ "name": "x", "ext": "txt" }),
    ] {
        llm.push(Script::ok(sse_tool("c", "send_file", &args, (10, 3))));
    }
    llm.push(Script::ok(sse_text(&["Rien envoyé."], (20, 3))));
    let (peer, _t) = spawn_worker(&api, &llm, init(1), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    assert_eq!(api.with(|st| st.artifact_requests), 0, "aucun dépôt");
    let msgs = api.clear_messages();
    let results: Vec<Value> = (0..5).map(|i| tool_result_of(&msgs, i)).collect();
    assert_eq!(
        results,
        [
            json!({ "error": "artifact_format" }),
            json!({ "error": "artifact_name" }),
            json!({ "error": "artifact_not_text" }),
            json!({ "error": "artifact_too_large", "max": 262_144 }),
            json!({ "error": "artifact_not_text" }),
        ]
    );
    let calls: Vec<&Value> = msgs
        .iter()
        .filter(|m| m["role"] == "assistant")
        .flat_map(|m| m["toolCalls"].as_array().into_iter().flatten())
        .collect();
    assert!(calls.iter().all(|c| c["status"] == "error" && c["arguments"].get("content").is_none()));
    // Le contenu de 256 Kio refusé n'est pas gardé non plus.
    assert!(serde_json::to_string(&calls).unwrap().len() < 1_000);
}

#[tokio::test]
async fn cinq_par_tour_puis_artifact_turn_limit() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.deposit_message(M1, "Beaucoup de fichiers");
    for i in 0..6 {
        let args = json!({ "name": format!("f{i}"), "ext": "txt", "content": format!("contenu {i}") });
        llm.push(Script::ok(sse_tool("c", "send_file", &args, (10, 3))));
    }
    llm.push(Script::ok(sse_text(&["Fini."], (20, 3))));
    let (peer, _t) = spawn_worker(&api, &llm, init(1), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    assert_eq!(api.with(|st| st.artifacts.len()), 5, "5e déposé, 6e refusé");
    let msgs = api.clear_messages();
    assert_eq!(tool_result_of(&msgs, 5), json!({ "error": "artifact_turn_limit" }));
    assert_eq!(api.with(|st| st.artifact_requests), 5, "le 6e n'atteint pas l'API");
}

#[tokio::test]
async fn quota_de_conversation_rendu_par_l_api() {
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.with(|st| st.artifact_preexisting = 20);
    api.deposit_message(M1, "Un de plus");
    llm.push(Script::ok(sse_tool("c1", "send_file", &csv(), (10, 3))));
    llm.push(Script::ok(sse_text(&["Plus de place."], (20, 3))));
    let (peer, _t) = spawn_worker(&api, &llm, init(1), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    let msgs = api.clear_messages();
    assert_eq!(tool_result_of(&msgs, 0), json!({ "error": "artifact_quota" }));
    assert!(peer.events().iter().all(|e| e["t"] != "artifact"), "aucune trame");
    let call = &msgs.iter().find(|m| m["role"] == "assistant").unwrap()["toolCalls"][0];
    assert_eq!(call["status"], "error");
    assert!(!serde_json::to_string(&msgs).unwrap().contains("SECRET-LIGNE"));
}

#[tokio::test]
async fn panne_passagere_un_seul_nouvel_essai_meme_id() {
    // Une panne puis le succès : deux requêtes, un seul artefact, même `id` (rejeu idempotent).
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.with(|st| st.artifact_503 = 1);
    api.deposit_message(M1, "Un fichier");
    llm.push(Script::ok(sse_tool("c1", "send_file", &csv(), (10, 3))));
    llm.push(Script::ok(sse_text(&["Envoyé."], (20, 3))));
    let (peer, _t) = spawn_worker(&api, &llm, init(1), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    assert_eq!(api.with(|st| (st.artifacts.len(), st.artifact_requests)), (1, 2));
    assert!(peer.events().iter().any(|e| e["t"] == "artifact"));

    // Deux pannes : `artifact_not_sent`, pas de troisième essai, pas de trame.
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.with(|st| st.artifact_503 = 5);
    api.deposit_message(M1, "Un fichier");
    llm.push(Script::ok(sse_tool("c1", "send_file", &csv(), (10, 3))));
    llm.push(Script::ok(sse_text(&["Échec."], (20, 3))));
    let (peer, _t) = spawn_worker(&api, &llm, init(1), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    assert_eq!(api.with(|st| (st.artifacts.len(), st.artifact_requests)), (0, 2));
    let msgs = api.clear_messages();
    assert_eq!(tool_result_of(&msgs, 0), json!({ "error": "artifact_not_sent" }));
    assert!(peer.events().iter().all(|e| e["t"] != "artifact"));
}

#[tokio::test]
async fn reponse_perdue_le_nouvel_essai_est_un_rejeu_identique() {
    // La requête part, la réponse se perd (`503` après l'écriture) : l'API a déjà l'artefact ; le nouvel
    // essai (même corps) reçoit `200`, donc un seul artefact et aucune erreur de doublon.
    let api = FakeApi::new();
    let llm = FakeLlm::start();
    api.with(|st| st.artifact_lost = 1);
    api.deposit_message(M1, "Un fichier");
    llm.push(Script::ok(sse_tool("c1", "send_file", &csv(), (10, 3))));
    llm.push(Script::ok(sse_text(&["Fini."], (20, 3))));
    let (peer, _t) = spawn_worker(&api, &llm, init(1), default_keys(false));
    assert_eq!(peer.wait_done().await, DoneReason::Idle);
    assert_eq!(api.with(|st| st.artifacts.len()), 1, "un seul artefact malgré deux requêtes");
    assert_eq!(api.with(|st| st.artifact_requests), 2);
    let msgs = api.clear_messages();
    assert_eq!(tool_result_of(&msgs, 0)["name"], "budget-lancement.csv");
}

#[tokio::test]
async fn disponible_en_mode_plan_et_jamais_dans_le_manifeste() {
    use runtime_protocol::pipe::PlanMode;
    use synco_ai_runtime_worker::tools::{llm_tools, parse_manifest};
    let specs = parse_manifest(&manifest());
    assert!(specs.iter().all(|t| t.name != "send_file"), "propre au worker");
    for mode in [None, Some(PlanMode::Plan), Some(PlanMode::Auto)] {
        let names: Vec<String> = llm_tools(&specs, &policy(&[]), mode).into_iter().map(|t| t.name).collect();
        assert!(names.contains(&"send_file".to_owned()), "{mode:?}");
        assert_eq!(names.contains(&"propose_actions".to_owned()), mode.is_some());
    }
}
