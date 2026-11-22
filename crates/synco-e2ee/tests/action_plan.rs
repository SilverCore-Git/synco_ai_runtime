//! Vecteurs figés par la spécification (L00f) : `docs/plan/vectors/action-plan.json`, rejoués sans
//! modification (12 §3 à §9). Chaque cas compte une vérification ; le total est affiché par
//! `cargo test -- --nocapture`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stdout,
    reason = "tests : un vecteur illisible doit échouer bruyamment"
)]

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};
use synco_e2ee::delegation::MandateMode;
use synco_e2ee::encoding::{from_hex, hex};
use synco_e2ee::error::Result;
use synco_e2ee::plan::{
    self, ActionState, Executor, GraphAction, PlanContext, PlanGraph, PlanRun, ServerCall, ToolManifest,
};
use synco_e2ee::primitives::sha256;
use synco_e2ee::rng::RandomSource;
use synco_e2ee::secret::SymmetricKey;
use synco_e2ee::session;

fn load() -> Value {
    let path = format!("{}/../../docs/plan/vectors/action-plan.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("champ {key} absent"))
}

fn key(hex_key: &str) -> SymmetricKey {
    SymmetricKey::from_slice(&from_hex(hex_key).unwrap()).unwrap()
}

/// IV figé : uniquement dans les vecteurs.
struct FixedIv(Vec<u8>);

impl RandomSource for FixedIv {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        dest.copy_from_slice(&self.0);
        Ok(())
    }
}

fn iv(hex_iv: &str) -> FixedIv {
    FixedIv(from_hex(hex_iv).unwrap())
}

fn ns(v: &Value) -> Vec<u64> {
    v.as_array().unwrap().iter().map(|n| n.as_u64().unwrap()).collect()
}

fn ctx<'a>(v: &'a Value, manifest: &'a ToolManifest) -> PlanContext<'a> {
    PlanContext {
        session_id: s(v, "sessionId"),
        max_lifetime_secs: 604_800,
        manifest,
        mode: MandateMode::Plan,
        create_thread_ask: true,
    }
}

fn graph_of(plan: &Value, v: &Value, manifest: &ToolManifest) -> PlanGraph {
    plan::validate_plan(plan, &ctx(v, manifest)).unwrap_or_else(|e| panic!("plan invalide : {}", e.detail()))
}

fn executors(g: &PlanGraph) -> Vec<&'static str> {
    g.actions().iter().map(|a| a.executor.as_str()).collect()
}

fn named_plan<'a>(v: &'a Value, name: &str) -> &'a Value {
    match name {
        "plan" => &v["plan"],
        "mixedPlan" => &v["mixedPlan"]["plan"],
        "categoryPlan" => &v["categoryPlan"]["plan"],
        other => panic!("plan inconnu {other}"),
    }
}

/// Simulation par pas unitaires de `runCases` : chaque exécutant démarre ses actions prêtes (plus
/// petite `n` d'abord, dans la limite de `concurrency`), toutes finissent en fin de pas.
fn simulate(
    graph: PlanGraph,
    accepted: &[u64],
    concurrency: usize,
    failed: &[u64],
    expires_before: Option<u64>,
) -> (Vec<Value>, PlanRun) {
    let mut run = PlanRun::new(graph, accepted).unwrap();
    let mut ticks = Vec::new();
    for tick in 1u64.. {
        if expires_before.is_some_and(|t| tick >= t) {
            run.expire();
        }
        let device: Vec<u64> = run.ready(Executor::Device).into_iter().take(concurrency).collect();
        let agent: Vec<u64> = run.ready(Executor::Agent).into_iter().take(concurrency).collect();
        if device.is_empty() && agent.is_empty() {
            break;
        }
        for &n in device.iter().chain(&agent) {
            run.start(n).unwrap();
        }
        for &n in device.iter().chain(&agent) {
            let outcome = if failed.contains(&n) { ActionState::Failed } else { ActionState::Done };
            run.finish(n, outcome).unwrap();
        }
        ticks.push(serde_json::json!({ "device": device, "agent": agent }));
    }
    (ticks, run)
}

fn check_states(run: &PlanRun, expect: &Value, name: &str) {
    for (n, state) in expect.as_object().unwrap() {
        assert_eq!(run.state(n.parse().unwrap()).unwrap().as_str(), state.as_str().unwrap(), "{name} : action {n}");
    }
}

fn field_name(text: &str) -> session::FieldName {
    match text.split_once(':') {
        None => session::FieldName::Plan,
        Some(("plan_result", k)) => session::FieldName::PlanResult(k.parse().unwrap()),
        Some((_, k)) => session::FieldName::PlanAgentResult(k.parse().unwrap()),
    }
}

/// Graphe du plan figé qui porte ce `planId` (le plan de référence par défaut).
fn graph_by_id(v: &Value, manifest: &ToolManifest, plan_id: &str) -> PlanGraph {
    let name = ["mixedPlan", "categoryPlan"].into_iter().find(|n| s(&v[n], "planId") == plan_id).unwrap_or("plan");
    graph_of(named_plan(v, name), v, manifest)
}

/// Lecture typée d'un cas (`sessionId`, `planId`) : `decrypt_plan` ou `decrypt_phase_result`, ce
/// dernier contre le graphe du plan figé de même `planId`.
fn typed_decrypt(ck: &SymmetricKey, v: &Value, manifest: &ToolManifest, c: &Value, value: &str) -> Result<Value> {
    let (sid, pid) = (s(c, "sessionId"), c.get("planId").or_else(|| c.get("messageId")).unwrap().as_str().unwrap());
    match s(c, "fieldName").split_once(':') {
        None => plan::decrypt_plan(ck, sid, pid, value),
        Some((label, k)) => {
            let executor = if label == "plan_result" { Executor::Device } else { Executor::Agent };
            plan::decrypt_phase_result(
                ck,
                sid,
                pid,
                executor,
                k.parse().unwrap(),
                &graph_by_id(v, manifest, pid),
                value,
            )
        }
    }
}

#[test]
fn vecteurs_du_plan_d_action() {
    let v = load();
    let manifest = ToolManifest::from_json(&v["toolManifest"]);
    let ck = key(s(&v, "ckHex"));
    let sid = s(&v, "sessionId");
    let mut checks = 0usize;

    // Plan de référence : JCS, AAD, chiffré exact, exécutants, niveaux, pendingToolCall.
    let p = &v["plan"];
    assert_eq!(plan::jcs(p).unwrap(), s(&v, "planCanonical"));
    assert_eq!(serde_json::to_string(p).unwrap(), s(&v, "planCanonical"), "serde_json = JCS");
    assert_eq!(plan::plan_aad(sid, s(&v, "planId")).unwrap(), s(&v, "aadPlan"));
    assert_eq!(plan::encrypt_plan(&ck, p, &mut iv(s(&v, "ivPlanHex"))).unwrap(), s(&v, "planValue"));
    assert_eq!(&plan::decrypt_plan(&ck, sid, s(&v, "planId"), s(&v, "planValue")).unwrap(), p);
    let g = graph_of(p, &v, &manifest);
    assert_eq!(
        executors(&g),
        v["planExecutors"].as_array().unwrap().iter().map(|e| e.as_str().unwrap()).collect::<Vec<_>>()
    );
    assert_eq!(g.levels(), ns(&v["planLevels"]));
    let ptc = &v["pendingToolCall"];
    assert_eq!(
        (s(ptc, "name"), s(ptc, "planId"), s(ptc, "args")),
        ("propose_actions", s(&v, "planId"), s(&v, "planValue"))
    );
    assert_eq!(g.check_served(g.actions()), Ok(()));
    checks += 1;

    // plan_result partiel de la phase d'appareil 1.
    let r = &v["planResult"];
    assert_eq!(plan::jcs(r).unwrap(), s(&v, "planResultCanonical"));
    assert_eq!(plan::phase_result_aad(sid, s(&v, "planId"), Executor::Device, 1).unwrap(), s(&v, "aadPlanResult"));
    let rg = graph_of(p, &v, &manifest);
    let value =
        plan::encrypt_phase_result(&ck, sid, Executor::Device, &rg, r, &mut iv(s(&v, "ivPlanResultHex"))).unwrap();
    assert_eq!(value, s(&v, "planResultValue"));
    assert_eq!(&plan::decrypt_phase_result(&ck, sid, s(&v, "planId"), Executor::Device, 1, &rg, &value).unwrap(), r);
    checks += 1;

    // Plan mixte : plan et résultats de phase numérotés par exécutant.
    let mixed = &v["mixedPlan"];
    let mixed_id = s(mixed, "planId");
    let g = graph_of(&mixed["plan"], &v, &manifest);
    assert_eq!(
        executors(&g),
        mixed["executors"].as_array().unwrap().iter().map(|e| e.as_str().unwrap()).collect::<Vec<_>>()
    );
    assert_eq!(g.levels(), ns(&mixed["levels"]));
    for e in mixed["encrypted"].as_array().unwrap() {
        let field = s(e, "fieldName");
        let clear = &e["clear"];
        assert_eq!(plan::jcs(clear).unwrap(), s(e, "canonical"), "{}", s(e, "label"));
        let mut rng = iv(s(e, "ivHex"));
        let (aad, value) = if field == "plan" {
            (plan::plan_aad(sid, mixed_id).unwrap(), plan::encrypt_plan(&ck, clear, &mut rng).unwrap())
        } else {
            let (executor, k) = field.rsplit_once(':').unwrap();
            let executor = if executor == "plan_result" { Executor::Device } else { Executor::Agent };
            let k: u64 = k.parse().unwrap();
            let value = plan::encrypt_phase_result(&ck, sid, executor, &g, clear, &mut rng).unwrap();
            assert_eq!(&plan::decrypt_phase_result(&ck, sid, mixed_id, executor, k, &g, &value).unwrap(), clear);
            (plan::phase_result_aad(sid, mixed_id, executor, k).unwrap(), value)
        };
        assert_eq!(aad, s(e, "aad"), "{}", s(e, "label"));
        assert_eq!(value, s(e, "value"), "{}", s(e, "label"));
        checks += 1;
    }

    // Plan des catégories (PC58).
    let cat = &v["categoryPlan"];
    let cp = &cat["plan"];
    assert_eq!(plan::jcs(cp).unwrap(), s(cat, "canonical"));
    assert_eq!(plan::plan_aad(sid, s(cat, "planId")).unwrap(), s(cat, "aad"));
    assert_eq!(plan::encrypt_plan(&ck, cp, &mut iv(s(cat, "ivHex"))).unwrap(), s(cat, "value"));
    let g = graph_of(cp, &v, &manifest);
    assert_eq!(
        executors(&g),
        cat["executors"].as_array().unwrap().iter().map(|e| e.as_str().unwrap()).collect::<Vec<_>>()
    );
    assert_eq!(g.levels(), ns(&cat["expectLevels"]));
    checks += 1;
    let all: Vec<u64> = (1..=12).collect();
    let (ticks, _) = simulate(g.clone(), &all, usize::MAX, &[], None);
    let waves: Vec<Value> = ticks.iter().map(|t| t["device"].clone()).collect();
    assert_eq!(Value::Array(waves), cat["wavesUnbounded"]);
    checks += 1;
    for key in ["scheduleConcurrency4", "failureOfCategory2"] {
        let c = &cat[key];
        let failed = c.get("failedAt").map(ns).unwrap_or_default();
        let (ticks, run) =
            simulate(g.clone(), &all, c["concurrency"].as_u64().unwrap().try_into().unwrap(), &failed, None);
        assert_eq!(Value::Array(ticks), c["expectTicks"], "{key}");
        if let Some(states) = c.get("expectStates") {
            check_states(&run, states, key);
        }
        assert_eq!(run.status().as_str(), s(c, "expectStatus"), "{key}");
        checks += 1;
    }

    // serverDigests (PC47).
    for c in v["serverDigests"].as_array().unwrap() {
        let input = &c["input"];
        assert_eq!(plan::jcs(input).unwrap(), s(c, "canonical"), "{}", s(c, "name"));
        assert_eq!(hex(&sha256(s(c, "canonical").as_bytes())), s(c, "sha256Hex"));
        let digest = plan::server_digest(
            s(input, "tool"),
            input["args"].as_object().unwrap(),
            input.get("argsRefs").map(|r| r.as_object().unwrap()),
        )
        .unwrap();
        assert_eq!(digest, s(c, "sha256Hex"), "{}", s(c, "name"));
        if let Some(name) = c["plan"].as_str() {
            let digests = plan::plan_server_digests(named_plan(&v, name)).unwrap();
            let n = c["n"].as_u64().unwrap();
            assert!(digests.contains(&(n, digest)), "{}", s(c, "name"));
        }
        checks += 1;
    }

    // Verrou de 12 §8.4.
    for c in v["executeCases"].as_array().unwrap() {
        let name = s(c, "name");
        let recorded: BTreeMap<u64, Map<String, Value>> = c["recordedOutputs"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(m, o)| (m.parse().unwrap(), o.as_object().unwrap().clone()))
            .collect();
        let call = &c["call"];
        let call = ServerCall {
            tool: s(call, "tool"),
            args: call["args"].as_object().unwrap(),
            args_refs: call.get("argsRefs").map(|r| r.as_object().unwrap()),
            refs: call.get("refs").map(|r| r.as_object().unwrap()),
        };
        // Sans `plan`, le condensat attendu est celui de l'appel lui-même (cas hors des plans figés).
        if let Some(plan_name) = c["plan"].as_str() {
            let digests = plan::plan_server_digests(named_plan(&v, plan_name)).unwrap();
            assert!(digests.contains(&(c["n"].as_u64().unwrap(), s(c, "serverDigest").to_owned())), "{name}");
        } else {
            assert_eq!(
                plan::server_digest(call.tool, call.args, call.args_refs).unwrap(),
                s(c, "serverDigest"),
                "{name}"
            );
        }
        let r = plan::check_server_call(s(c, "serverDigest"), &call, &recorded);
        match s(c, "expect") {
            "ok" => assert_eq!(Value::Object(r.unwrap()), c["effectiveArgs"], "{name}"),
            code => assert_eq!(r.unwrap_err().code(), code, "{name}"),
        }
        checks += 1;
    }

    // Chiffrement : mêmes champs et codes que conversation-fields.json.
    for c in v["encryptionCases"].as_array().unwrap() {
        let name = s(c, "name");
        let k = c.get("ckHex").map_or_else(|| key(s(&v, "ckHex")), |h| key(h.as_str().unwrap()));
        let r = session::decrypt_field(&k, s(c, "sessionId"), s(c, "messageId"), s(c, "fieldName"), s(c, "value"));
        match s(c, "expect") {
            "ok" => {
                let clear = r.unwrap_or_else(|e| panic!("{name} : {e}"));
                assert_eq!(clear, s(c, "plaintext"), "{name}");
                // Chemin typé : la même valeur se relit par la fonction du plan.
                let parsed: Value = serde_json::from_str(&clear).unwrap();
                let typed = typed_decrypt(&k, &v, &manifest, c, s(c, "value"));
                assert_eq!(typed.unwrap(), parsed, "{name}");
            }
            code => assert_eq!(r.unwrap_err().code(), code, "{name}"),
        }
        checks += 1;
    }

    // Clairs bruts (lecture stricte) : nombres, demi-paires, BOM, résultats de phase.
    for c in v["clearCases"].as_array().unwrap() {
        let name = s(c, "name");
        let field = field_name(s(c, "fieldName"));
        let rebuilt = session::encrypt_field(
            &ck,
            s(c, "sessionId"),
            s(c, "planId"),
            &field,
            s(c, "clear"),
            &mut iv(s(c, "ivHex")),
        );
        assert_eq!(rebuilt.unwrap(), s(c, "value"), "{name} : vecteur");
        let r = typed_decrypt(&ck, &v, &manifest, c, s(c, "value"));
        match s(c, "expect") {
            "ok" => assert_eq!(plan::jcs(&r.unwrap_or_else(|e| panic!("{name} : {e}"))).unwrap(), s(c, "canonical")),
            code => assert_eq!(r.map(|_| ()).unwrap_err().code(), code, "{name}"),
        }
        checks += 1;
    }

    // Borne de la valeur chiffrée (PC61), avant le base64.
    assert_eq!(plan::MAX_PLAN_VALUE_LEN, 349_569);
    for c in v["boundCases"].as_array().unwrap() {
        let name = s(c, "name");
        let fill = s(c, "fill").repeat(c["fillLength"].as_u64().unwrap().try_into().unwrap());
        let value = format!("{}{fill}", s(c, "valuePrefix"));
        let r = typed_decrypt(&ck, &v, &manifest, c, &value);
        assert_eq!(r.unwrap_err().code(), s(c, "expect"), "{name}");
        checks += 1;
    }

    // Validation (12 §5, PC61).
    for c in v["validationCases"].as_array().unwrap() {
        let name = s(c, "name");
        let r = plan::validate_plan(&c["plan"], &ctx(&v, &manifest));
        match s(c, "expect") {
            "ok" => assert!(r.is_ok(), "{name} : {:?}", r.err()),
            code => {
                let e = r.err().unwrap_or_else(|| panic!("{name} : accepté"));
                assert_eq!(synco_e2ee::Error::from(e).code(), code, "{name}");
                if let Some(detail) = c.get("detail") {
                    assert_eq!(e.detail(), detail.as_str().unwrap(), "{name}");
                } else {
                    assert_ne!(e.detail(), "plan_too_large", "{name}");
                }
            }
        }
        checks += 1;
    }

    let reference = graph_of(p, &v, &manifest);
    let graph_from = |c: &Value| -> PlanGraph {
        c.get("actions").map_or_else(
            || reference.clone(),
            |list| {
                let actions = list
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| GraphAction {
                        n: a["n"].as_u64().unwrap(),
                        executor: a
                            .get("executor")
                            .map_or(Executor::Device, |e| Executor::parse(e.as_str().unwrap()).unwrap()),
                        after: a.get("after").map(ns).unwrap_or_default(),
                    })
                    .collect();
                PlanGraph::new(actions).unwrap()
            },
        )
    };

    for c in v["levelCases"].as_array().unwrap() {
        assert_eq!(graph_from(c).levels(), ns(&c["expectLevels"]), "{}", s(c, "name"));
        checks += 1;
    }

    for c in v["cascadeCases"].as_array().unwrap() {
        let skipped = graph_from(c).cascade(&ns(&c["unchecked"])).unwrap();
        assert_eq!(skipped, ns(&c["expectSkipped"]).into_iter().collect::<BTreeSet<_>>(), "{}", s(c, "name"));
        checks += 1;
    }

    for c in v["failureCases"].as_array().unwrap() {
        let name = s(c, "name");
        let failed = [c["failedAt"].as_u64().unwrap()];
        let (_, run) = simulate(reference.clone(), &ns(&c["accepted"]), usize::MAX, &failed, None);
        check_states(&run, &c["expectStates"], name);
        assert_eq!(run.status().as_str(), s(c, "expectStatus"), "{name}");
        checks += 1;
    }

    for c in v["runCases"].as_array().unwrap() {
        let name = s(c, "name");
        let g = graph_of(named_plan(&v, s(c, "plan")), &v, &manifest);
        let failed = c.get("failedAt").map(ns).unwrap_or_default();
        let concurrency = c["concurrency"].as_u64().unwrap().try_into().unwrap();
        let (ticks, run) =
            simulate(g, &ns(&c["accepted"]), concurrency, &failed, c.get("expiresBeforeTick").and_then(Value::as_u64));
        assert_eq!(Value::Array(ticks), c["expectTicks"], "{name}");
        check_states(&run, &c["expectStates"], name);
        assert_eq!(run.status().as_str(), s(c, "expectStatus"), "{name}");
        checks += 1;
    }

    println!("action-plan.json : {checks} vérifications rejouées");
    assert_eq!(checks, 2 + 4 + 4 + 4 + 12 + 20 + 20 + 4 + 45 + 6 + 7 + 2 + 7, "un cas n'a pas été rejoué");
}

/// Protections propres au code (hors vecteurs) : chacune échoue sans la règle qu'elle couvre.
#[test]
fn garde_fous() {
    let v = load();
    let manifest = ToolManifest::from_json(&v["toolManifest"]);

    // JCS : nombre décimal ou hors de 2⁵³ − 1 refusé ; tri par unités UTF-16 (≠ octets UTF-8).
    assert!(plan::jcs(&serde_json::json!({ "a": 1.5 })).is_err());
    assert!(plan::jcs(&serde_json::json!({ "a": 9_007_199_254_740_992u64 })).is_err());
    // Profondeur : 65 tableaux imbriqués admis, 66 refusés (même borne que `parseJsonStrict`).
    let nested = |k: usize| -> Value { serde_json::from_str(&format!("{}{}", "[".repeat(k), "]".repeat(k))).unwrap() };
    assert!(plan::jcs(&nested(65)).is_ok());
    assert!(plan::jcs(&nested(66)).is_err());
    assert_eq!(
        plan::jcs(&serde_json::json!({ "\u{ff61}": 1, "\u{1f600}": 2 })).unwrap(),
        "{\"\u{1f600}\":2,\"\u{ff61}\":1}"
    );

    // Exécutants selon le mode : thread.create au runtime en autonome sous `ask`, hors plan sous `auto`.
    let mut auto = ctx(&v, &manifest);
    auto.mode = MandateMode::Auto;
    let g = plan::validate_plan(&v["plan"], &auto).unwrap();
    assert_eq!(executors(&g), ["agent", "agent", "device", "device", "agent"]);
    auto.create_thread_ask = false;
    assert_eq!(plan::validate_plan(&v["plan"], &auto).unwrap_err().detail(), "plan_kind");

    // Règle 8 : exécutant servi différent.
    let g = graph_of(&v["plan"], &v, &manifest);
    let mut served = g.actions().to_vec();
    served[4].executor = Executor::Device;
    assert!(g.check_served(&served).is_err());

    // Délai de l'org plus court que 7 jours.
    let mut short = ctx(&v, &manifest);
    short.max_lifetime_secs = 3_600;
    assert_eq!(plan::validate_plan(&v["plan"], &short).unwrap_err().detail(), "plan_header");

    // Résultat de phase : planId et phase du clair recontrôlés après déchiffrement.
    let ck = key(s(&v, "ckHex"));
    let mut rng = iv("000102030405060708090a0b");
    let mut other = v["planResult"].clone();
    other["phase"] = 2.into();
    let value = plan::encrypt_phase_result(&ck, s(&v, "sessionId"), Executor::Device, &g, &other, &mut rng).unwrap();
    assert!(
        plan::decrypt_phase_result(&ck, s(&v, "sessionId"), s(&v, "planId"), Executor::Device, 2, &g, &value).is_ok()
    );
    // Le chiffrement refuse aussi un n de l'agent dans un résultat d'appareil.
    let mut agent_n = v["planResult"].clone();
    agent_n["outcomes"][3]["n"] = 5.into();
    assert!(plan::encrypt_phase_result(&ck, s(&v, "sessionId"), Executor::Device, &g, &agent_n, &mut rng).is_err());
    let forged = session::encrypt_field(
        &ck,
        s(&v, "sessionId"),
        s(&v, "planId"),
        &Executor::Device.result_field(1),
        &plan::jcs(&other).unwrap(),
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        plan::decrypt_phase_result(&ck, s(&v, "sessionId"), s(&v, "planId"), Executor::Device, 1, &g, &forged)
            .unwrap_err()
            .code(),
        "plan_invalid"
    );

    // Exécution : une action non prête ne démarre pas ; issue inconnue → interrupted.
    let mut run = PlanRun::new(g, &[1, 2, 3, 4, 5]).unwrap();
    assert!(run.start(5).is_err());
    run.start(1).unwrap();
    run.finish(1, ActionState::UnknownOutcome).unwrap();
    assert_eq!(run.state(5), Some(ActionState::Skipped));
    for n in [2, 3] {
        run.start(n).unwrap();
        run.finish(n, ActionState::Done).unwrap();
    }
    run.start(4).unwrap();
    run.stop();
    assert_eq!(run.status().as_str(), "executing");
    run.finish(4, ActionState::Done).unwrap();
    assert_eq!(run.status().as_str(), "stopped");
}
