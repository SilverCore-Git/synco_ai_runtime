//! Test d'intégration local : le superviseur contre une API simulée (HTTP + flux WebSocket) qui
//! vérifie **chaque** requête signée avec la règle de l'API, et un aller-retour
//! client → superviseur → bouchon de worker → client.

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

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{Value, json};
use synco_ai_runtime::config::Config;
use synco_ai_runtime::launcher::InProcessStubLauncher;
use synco_ai_runtime::seal::{self, Backend, KdfParams, PassphraseSource};
use synco_e2ee::delegation::{self, DelegationContext, DelegationKey, EntryKind, Scope};
use synco_e2ee::ec::{EcSigningKey, EcdhSecret};
use synco_e2ee::runtime_cert::{self, ChallengePurpose, ChallengeRequest, RuntimeCertificate, UrlPolicy};
use synco_e2ee::session::{self, FieldName};
use synco_e2ee::{OsRandom, SymmetricKey};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use zeroize::Zeroizing;

use common::{MockApi, ORG};

const ORIGIN: &str = "https://app.example.com";
const PUBLIC_URL: &str = "https://runtime.example.com";
const USER: &str = "66666666-7777-4888-9999-aaaaaaaaaaaa";
const BAD_USER: &str = "77777777-7777-4888-9999-aaaaaaaaaaaa";
const SESSION: &str = "0f0e0d0c-0b0a-4908-8706-050403020100";
const AUTH: &str = "9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a";
const DASH_PW: &str = "mot de passe du dashboard de test";
const PASSPHRASE: &str = "phrase de passe des tests d'intégration";
const CK: [u8; 32] = [0xdd; 32];
const THREAD_KEY: [u8; 32] = [0xbb; 32];

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn backend() -> Backend {
    Backend::Passphrase {
        source: PassphraseSource::Provided(Zeroizing::new(PASSPHRASE.into())),
        kdf: KdfParams { m_kib: 256, t: 1, p: 1 },
    }
}

struct Env {
    _dir: tempfile::TempDir,
    state_dir: std::path::PathBuf,
    api: MockApi,
    running: synco_ai_runtime::app::Running,
    keys_secret: Zeroizing<Vec<u8>>,
    /// Clé de signature d'identité de `USER` (transitions d'identité).
    user_key: EcSigningKey,
}

/// Délégation : mandat signé par `signer`, enveloppe vers `kex`, entrées `conv` et `thread`.
fn delegation_record(
    kex: &synco_e2ee::ec::EcPublicKey,
    fpr: &str,
    runtime_id: &str,
    user: &str,
    delegation_id: &str,
    signer: &EcSigningKey,
    served_exp_shift: u64,
) -> (Value, Vec<Value>) {
    let iat = now() - 60;
    let ctx = DelegationContext {
        user_id: user.into(),
        org_id: ORG.into(),
        runtime_id: runtime_id.into(),
        delegation_id: delegation_id.into(),
        scope: Scope::Org,
        iat,
        exp: iat + 7 * 86_400,
    };
    let dk = DelegationKey::generate(&mut OsRandom).unwrap();
    let wrap = delegation::seal_delegation(&ctx, kex, &dk, &mut OsRandom).unwrap();
    let sig = delegation::sign_mandate(signer, &ctx, fpr, &wrap).unwrap();
    let entry = |kind: EntryKind, r: &str, k: [u8; 32], id: &str| {
        let ct = delegation::seal_entry(&dk, &ctx, kind, r, 1, &SymmetricKey::from_bytes(k), &mut OsRandom).unwrap();
        json!({ "id": id, "kind": kind.as_str(), "ref": r, "version": 1, "ciphertext": ct })
    };
    let entries = vec![
        entry(EntryKind::Conv, SESSION, CK, "e1"),
        entry(EntryKind::Thread, "cm3threadexample000000001", THREAD_KEY, "e2"),
    ];
    // Enregistrement servi par l'API (éventuellement altéré : `exp` différent de l'AAD).
    let record = json!({
        "delegationId": delegation_id, "userId": user, "scope": "org",
        "iat": ctx.iat, "exp": ctx.exp + served_exp_shift, "wrap": wrap, "mandateSignature": sig,
    });
    (record, entries)
}

async fn setup() -> Env {
    setup_with(Arc::new(InProcessStubLauncher)).await
}

async fn setup_with(launcher: Arc<dyn synco_ai_runtime::launcher::WorkerLauncher>) -> Env {
    setup_full(launcher, 0).await
}

async fn setup_full(launcher: Arc<dyn synco_ai_runtime::launcher::WorkerLauncher>, slow_entries_ms: u64) -> Env {
    setup_policy(launcher, slow_entries_ms, None).await
}

async fn setup_policy(
    launcher: Arc<dyn synco_ai_runtime::launcher::WorkerLauncher>,
    slow_entries_ms: u64,
    policy: Option<Value>,
) -> Env {
    setup_llm(launcher, slow_entries_ms, policy, "http://127.0.0.1:9/v1").await
}

async fn setup_llm(
    launcher: Arc<dyn synco_ai_runtime::launcher::WorkerLauncher>,
    slow_entries_ms: u64,
    policy: Option<Value>,
    llm_base_url: &str,
) -> Env {
    setup_hops(launcher, slow_entries_ms, policy, llm_base_url, 0).await
}

/// Comme `setup_llm`, avec `listen.trust_proxy_hops = listen_hops` (le `[dashboard]` reste par défaut).
async fn setup_hops(
    launcher: Arc<dyn synco_ai_runtime::launcher::WorkerLauncher>,
    slow_entries_ms: u64,
    policy: Option<Value>,
    llm_base_url: &str,
    listen_hops: usize,
) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("etat");
    // Clés générées et scellées par phrase de passe (comme au premier démarrage).
    let keys = seal::create(&state_dir, &backend()).unwrap();
    // Dashboard (L08) : un mot de passe est défini, le dashboard démarre sur 127.0.0.1:0.
    synco_ai_runtime::dashboard::auth::set_password(
        &state_dir,
        DASH_PW,
        synco_ai_runtime::seal::KdfParams { m_kib: 256, t: 1, p: 1 },
    )
    .unwrap();
    let keys_secret = keys.to_secret_bytes();
    let ticket_key = SigningKey::from_bytes(&[0x2c; 32]);
    let api = common::start(keys.runtime_id(), keys.sig().verifying_key(), ticket_key).await;

    // Certificat signé par un admin, portant nos clés et notre URL.
    let admin = EcSigningKey::generate(&mut OsRandom).unwrap();
    let cert = RuntimeCertificate {
        org_id: ORG.into(),
        runtime_id: keys.runtime_id().into(),
        url: PUBLIC_URL.into(),
        keys: keys.public().clone(),
        admin_id: "11111111-2222-4333-8444-555555555555".into(),
        issued_at: now(),
        serial: 1,
    };
    let signature = cert.sign(&admin, UrlPolicy::Production).unwrap();
    let jwk = |k: &synco_e2ee::ec::EcPublicKey| serde_json::from_str::<Value>(&k.to_canonical()).unwrap();
    let certificate = json!({
        "v": 1, "orgId": ORG, "runtimeId": keys.runtime_id(), "url": PUBLIC_URL,
        "keys": { "sig": keys.public().sig_b64u(), "kex": jwk(&keys.public().kex), "csk": jwk(&keys.public().csk) },
        "adminId": cert.admin_id, "issuedAt": cert.issued_at, "serial": 1, "signature": signature,
    });

    // Utilisateur légitime ; un second dont l'API sert une délégation altérée (`exp`).
    let user_key = EcSigningKey::generate(&mut OsRandom).unwrap();
    let bad_key = EcSigningKey::generate(&mut OsRandom).unwrap();
    let kex = keys.public().kex.clone();
    let fpr = keys.fingerprint_hex().to_owned();
    let (mut good, good_entries) = delegation_record(&kex, &fpr, keys.runtime_id(), USER, "d-good", &user_key, 0);
    good["displayName"] = json!("Alice\u{7} Martin");
    let (bad, bad_entries) = delegation_record(&kex, &fpr, keys.runtime_id(), BAD_USER, "d-bad", &bad_key, 3_600);
    api.with(|st| {
        st.slow_entries_ms = slow_entries_ms;
        st.policy = policy;
        st.paired = true;
        st.certificate = certificate;
        st.delegations = vec![good, bad];
        st.entries.insert("d-good".into(), good_entries);
        st.entries.insert("d-bad".into(), bad_entries);
        st.sign_keys.insert(USER.into(), user_key.public_key().unwrap().to_canonical());
        st.sign_keys.insert(BAD_USER.into(), bad_key.public_key().unwrap().to_canonical());
        st.conversations.insert(SESSION.into(), common::Conversation { auth_id: AUTH.into(), ..Default::default() });
    });

    let config = Config::parse(&format!(
        r#"
public_url = "{PUBLIC_URL}"
api_url = "{}"
state_dir = "{}"
allowed_origins = ["{ORIGIN}"]
log_level = "debug"
[listen]
public = "127.0.0.1:0"
dashboard = "127.0.0.1:0"
trust_proxy_hops = {listen_hops}
[limits]
idle_shutdown_secs = 1
shutdown_grace_secs = 2
[llm.providers.openai]
base_url = "{llm_base_url}"
"#,
        api.url(),
        state_dir.display()
    ))
    .unwrap();
    let keys = seal::load(&state_dir, &backend()).unwrap().unwrap();
    let running = synco_ai_runtime::app::start(config, keys, launcher, BTreeMap::new()).await.unwrap();
    Env { _dir: dir, state_dir, api, running, keys_secret, user_key }
}

async fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("délai dépassé : {what}");
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(env: &Env, session: &str, origin: &str) -> Result<Ws, u16> {
    let url = format!("ws://{}/v1/conversations/{session}/ws", env.running.public_addr);
    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert("origin", origin.parse().unwrap());
    match tokio_tungstenite::connect_async(req).await {
        Ok((ws, _)) => Ok(ws),
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => Err(resp.status().as_u16()),
        Err(e) => panic!("{e}"),
    }
}

async fn next_json(ws: &mut Ws) -> Value {
    loop {
        let msg =
            tokio::time::timeout(Duration::from_secs(10), ws.next()).await.expect("trame attendue").unwrap().unwrap();
        match msg {
            Message::Text(t) => return serde_json::from_str(t.as_str()).unwrap(),
            Message::Close(f) => {
                let f = f.unwrap();
                return json!({ "closed": u16::from(f.code), "reason": f.reason.as_str() });
            }
            _ => {}
        }
    }
}

fn ticket(env: &Env, overrides: Value) -> String {
    let t = now();
    let mut claims = json!({
        "op": "connect", "sub": USER, "org": ORG, "rt": env.running.runtime.keys.runtime_id(), "conv": SESSION,
        "iat": t, "exp": t + 300,
    });
    for (k, v) in overrides.as_object().unwrap() {
        claims[k] = v.clone();
    }
    env.api.ticket(&claims)
}

async fn hello(ws: &mut Ws, ticket: &str) -> Value {
    ws.send(Message::Text(json!({ "v": 1, "t": "hello", "ticket": ticket, "resume": null }).to_string().into()))
        .await
        .unwrap();
    next_json(ws).await
}

async fn authorize(env: &Env) {
    // L'autorisation arrive par le flux de notifications (04 §6).
    wait_until("flux ouvert", || env.api.with(|st| st.stream_hellos > 0)).await;
    env.api.push(json!({ "type": "conversation.authorized", "sessionId": SESSION, "userId": USER, "authId": AUTH }));
    let rt = Arc::clone(&env.running.runtime);
    for _ in 0..100 {
        if rt.state.lock().await.auths.get(SESSION).is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("autorisation non reçue");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aller_retour_client_superviseur_worker() {
    aller_retour(setup().await, synco_ai_runtime_worker::stub::STUB_REPLY).await;
}

/// Réponse du fournisseur simulé derrière le mandataire LLM.
const LLM_REPLY: &str = "Bonjour depuis le worker isolé (L07).";

/// Fournisseur compatible OpenAI simulé (HTTP sur la boucle locale, admis par le mandataire) :
/// vérifie la clé injectée par le mandataire et rejoue un flux SSE.
async fn fake_provider() -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/v1", listener.local_addr().unwrap());
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen2 = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let seen = Arc::clone(&seen2);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 8192];
                loop {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some(p) = text.find("\r\n\r\n") {
                        let len: usize = text
                            .get(..p)
                            .unwrap()
                            .lines()
                            .find_map(|l| {
                                l.to_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())
                            })
                            .unwrap_or(0);
                        if buf.len() >= p + 4 + len {
                            break;
                        }
                    }
                }
                seen.lock().unwrap().push(String::from_utf8_lossy(&buf).to_string());
                let mut body = String::new();
                for part in ["Bonjour depuis", " le worker isolé (L07)."] {
                    body.push_str(&format!(
                        "data: {}\n\n",
                        json!({ "choices": [{ "index": 0, "delta": { "content": part } }] })
                    ));
                }
                body.push_str(&format!(
                    "data: {}\n\n",
                    json!({ "choices": [{ "index": 0, "delta": {}, "finish_reason": "stop" }] })
                ));
                body.push_str(&format!("data: {}\n\n", json!({ "choices": [], "usage": { "prompt_tokens": 30, "completion_tokens": 9, "total_tokens": 39 } })));
                body.push_str("data: [DONE]\n\n");
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (base, seen)
}

/// Même scénario avec le **vrai** bac à sable (L06) et la **vraie** boucle d'agent (L07) : le
/// worker est un processus isolé, relancé depuis le binaire du superviseur, qui appelle le
/// fournisseur par le mandataire LLM (clé ajoutée par le superviseur). Sur l'hôte seulement, dans
/// un cgroup délégué (`crates/supervisor/tests/sandbox-host.sh`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "noyau : espaces de noms, cgroup délégué (tests/sandbox-host.sh)"]
async fn aller_retour_avec_bac_a_sable() {
    use synco_ai_runtime::config::ProviderSecret;
    use synco_ai_runtime::sandbox::{Mode, SandboxLauncher, SandboxSettings, proxy::LlmProxy};
    let run = tempfile::Builder::new().prefix("l06").tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let settings = SandboxSettings {
        program: Some(env!("CARGO_BIN_EXE_synco-ai-runtime").into()),
        cgroup_root: None,
        run_dir: run.path().join("w"),
    };
    let (base, seen) = fake_provider().await;
    let secrets = BTreeMap::from([("openai".to_owned(), ProviderSecret(Zeroizing::new(b"sk-test-l07".to_vec())))]);
    let launcher =
        SandboxLauncher::new(&settings, Mode::Sandboxed, LlmProxy::new(secrets, Default::default()).unwrap())
            .await
            .unwrap();
    // Plafonds réalistes : ceux de la politique par défaut du simulateur (1 000 tokens) sont
    // inférieurs à la réservation du mandataire pour une vraie requête (prompt + outils).
    let policy = json!({
        "v": 1, "orgId": ORG, "defaultProvider": "openai", "reasoningEffort": "medium",
        "providers": [{ "id": "openai", "modelId": "gpt-test" }],
        "runtime": { "enabled": true, "maxDelegationDays": 7, "toolPolicy": {},
            "limits": { "maxStepsPerTurn": 10, "maxTokensPerConversation": 200000, "maxTokensPerTurn": 100000,
                "maxTurnDurationSecs": 60, "maxOutputTokensPerCall": 1000 } }
    });
    aller_retour(setup_llm(Arc::new(launcher), 0, Some(policy), &base).await, LLM_REPLY).await;
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "un appel au fournisseur");
    let req = seen[0].to_lowercase();
    assert!(req.starts_with("post /v1/chat/completions "), "{}", req.lines().next().unwrap_or_default());
    assert!(req.contains("authorization: bearer sk-test-l07"), "clé ajoutée par le mandataire, jamais par le worker");
    assert!(seen[0].contains("Bonjour"), "message déchiffré par le worker pour le fournisseur");
}

async fn aller_retour(env: Env, expected: &str) {
    let rt = Arc::clone(&env.running.runtime);
    let http = reqwest::Client::new();
    let base = format!("http://{}", env.running.public_addr);

    // Fiche publique : clés, empreinte recalculable, CORS limité à l'origine configurée.
    let resp = http.get(format!("{base}/v1/identity")).header("origin", ORIGIN).send().await.unwrap();
    assert_eq!(resp.headers()["access-control-allow-origin"], ORIGIN);
    let identity: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    assert_eq!(identity["runtimeId"], rt.keys.runtime_id());
    assert_eq!(runtime_cert::fingerprint_hex(rt.keys.runtime_id(), rt.keys.public()).unwrap(), identity["fingerprint"]);
    let other =
        http.get(format!("{base}/v1/identity")).header("origin", "https://evil.example.com").send().await.unwrap();
    assert!(other.headers().get("access-control-allow-origin").is_none());

    // Défi de possession (01 §5) vérifié côté client avec les clés publiées.
    let eph = EcdhSecret::generate(&mut OsRandom).unwrap();
    let request = ChallengeRequest {
        purpose: ChallengePurpose::Delegate,
        org_id: ORG.into(),
        user_id: USER.into(),
        nonce: [7; 32],
        client_eph: eph.public_key().unwrap(),
    };
    let body = json!({
        "v": 1, "purpose": "delegate", "orgId": ORG, "userId": USER,
        "nonce": synco_e2ee::encoding::b64u(&[7; 32]),
        "clientEph": serde_json::from_str::<Value>(&request.client_eph.to_canonical()).unwrap(),
    });
    let answer: Value = serde_json::from_str(
        &http.post(format!("{base}/v1/challenge")).body(body.to_string()).send().await.unwrap().text().await.unwrap(),
    )
    .unwrap();
    runtime_cert::verify_challenge_response(
        &request,
        rt.keys.runtime_id(),
        rt.keys.fingerprint_hex(),
        &eph,
        rt.keys.public(),
        answer["mac"].as_str().unwrap(),
        answer["sig"].as_str().unwrap(),
    )
    .expect("défi correct");
    let refused = http.post(format!("{base}/v1/challenge")).body("{}").send().await.unwrap();
    assert_eq!(refused.status(), 400);

    // Appairage, flux, délégations : la bonne est ouverte, l'altérée (AAD ≠) est `unusable`.
    wait_until("délégations traitées", || env.api.with(|st| st.delegation_status.len() == 2)).await;
    env.api.with(|st| {
        assert_eq!(st.delegation_status["d-good"], "ok");
        assert_eq!(st.delegation_status["d-bad"], "unusable");
    });
    assert_eq!(rt.org_id().await.as_deref(), Some(ORG));
    authorize(&env).await;

    // Client : hello → ready (idle) → message → queued → évènements du worker.
    let mut ws = connect(&env, SESSION, ORIGIN).await.unwrap();
    let ready = hello(&mut ws, &ticket(&env, json!({}))).await;
    assert_eq!(ready["t"], "ready", "{ready}");
    assert_eq!(ready["mode"], "idle");
    let msg_id = "3c2b1a09-8f7e-4d6c-9b5a-493827161504";
    let ck = SymmetricKey::from_bytes(CK);
    let content = session::encrypt_field(&ck, SESSION, msg_id, &FieldName::Content, "Bonjour", &mut OsRandom).unwrap();
    ws.send(Message::Text(
        json!({ "v": 1, "t": "message", "id": msg_id, "content": content, "createdAt": "2026-11-19T10:00:00.000Z" })
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    assert_eq!(next_json(&mut ws).await, json!({ "v": 1, "t": "queued", "id": msg_id }));
    let mut texts = Vec::new();
    let mut statuses = Vec::new();
    while statuses.last().map(String::as_str) != Some("idle") {
        let ev = next_json(&mut ws).await;
        assert_eq!(ev["epoch"], 1, "{ev}");
        match ev["t"].as_str().unwrap() {
            "status" => statuses.push(ev["status"].as_str().unwrap().to_owned()),
            "text" => texts.push(ev),
            "usage" | "thinking" => {}
            other => panic!("évènement inattendu {other} : {ev}"),
        }
    }
    assert_eq!(statuses, ["running", "idle"]);
    // Les deltas sont chiffrés par CK avec l'AAD ws:text:<epoch>:<seq> : seul le client les lit.
    assert!(!texts.is_empty(), "delta de texte");
    let clear: String = texts
        .iter()
        .map(|text| {
            session::decrypt_field(
                &ck,
                SESSION,
                text["messageId"].as_str().unwrap(),
                &format!("ws:text:1:{}", text["seq"]),
                text["delta"].as_str().unwrap(),
            )
            .unwrap()
        })
        .collect();
    assert_eq!(clear, expected);

    // Côté API : dépôt durable avant `queued`, historique écrit avec le message consommé, bail rendu.
    wait_until("bail rendu", || env.api.with(|st| st.conversations[SESSION].lease_released)).await;
    env.api.with(|st| {
        let conv = &st.conversations[SESSION];
        assert!(conv.inbox.iter().all(|(_, _, consumed)| *consumed));
        assert_eq!(conv.messages.len(), 2);
        assert_eq!(conv.messages[0]["content"], content);
        let reply = &conv.messages[1];
        let stored = session::decrypt_field(
            &ck,
            SESSION,
            reply["id"].as_str().unwrap(),
            "content",
            reply["content"].as_str().unwrap(),
        );
        assert_eq!(stored.unwrap(), expected);
        assert!(conv.statuses.contains(&"running".to_owned()));
        // Toutes les requêtes du canal sont signées correctement ; les routes de conversation
        // portent l'autorisation de CETTE conversation.
        assert!(st.signature_failures.is_empty(), "{:?}", st.signature_failures);
        assert!(st.auth_failures.is_empty(), "{:?}", st.auth_failures);
        assert!(st.seen.iter().filter(|s| s.path.contains("/conversations/")).all(|s| s.auth.as_deref() == Some(AUTH)));
        assert!(st.seen.iter().any(|s| s.path == "/api/runtime/v1/register"));
        // Aucune clé ni valeur chiffrée dans les corps envoyés hors des routes de conversation.
        assert!(
            st.seen
                .iter()
                .filter(|s| !s.path.contains("/conversations/"))
                .all(|s| !s.body.to_string().contains("gcm1:"))
        );
    });

    // Révocation de la conversation : le client est fermé en 4403.
    env.api.push(json!({ "type": "conversation.revoked", "sessionId": SESSION, "reason": "user_switched" }));
    let closed = next_json(&mut ws).await;
    assert_eq!(closed["closed"], 4403, "{closed}");

    // Arrêt propre ; aucune clé privée du runtime en clair dans le répertoire d'état.
    synco_ai_runtime::app::shutdown(&rt).await;
    assert_no_private_key_on_disk(&env);
}

/// Tous les fichiers sous `dir`, récursivement.
fn all_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(all_files(&path));
        } else {
            out.push(path);
        }
    }
    out
}

fn assert_no_private_key_on_disk(env: &Env) {
    let privates: Vec<&[u8]> = env.keys_secret[4 + 1 + 36..].chunks(32).collect();
    assert_eq!(privates.len(), 3);
    let mut files = 0;
    for path in all_files(&env.state_dir) {
        let bytes = std::fs::read(path).unwrap();
        files += 1;
        for p in &privates {
            for needle in
                [p.to_vec(), synco_e2ee::encoding::hex(p).into_bytes(), synco_e2ee::encoding::b64u(p).into_bytes()]
            {
                assert!(!bytes.windows(needle.len()).any(|w| w == needle.as_slice()), "clé privée en clair sur disque");
            }
        }
    }
    assert!(files >= 3, "keys.sealed, user-pins.json, authorizations.json");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tickets_et_origine_refuses() {
    let env = setup().await;
    wait_until("délégations traitées", || env.api.with(|st| st.delegation_status.len() == 2)).await;
    authorize(&env).await;

    // Origine non configurée : 403 avant la mise à niveau.
    assert_eq!(connect(&env, SESSION, "https://evil.example.com").await.err(), Some(403));

    let t = now();
    let other_key = SigningKey::from_bytes(&[0x01; 32]);
    let forged = common::sign_ticket(
        &other_key,
        "srt1",
        b"synco-ai-runtime-ticket\0",
        &json!({ "op": "connect", "sub": USER, "org": ORG, "rt": env.running.runtime.keys.runtime_id(), "conv": SESSION, "iat": t, "exp": t + 300 }),
    );
    let gateway_domain = common::sign_ticket(
        &env.api.ticket_key,
        "srt1",
        b"synco-ai-gateway-ticket\0",
        &json!({ "op": "connect", "sub": USER, "org": ORG, "rt": env.running.runtime.keys.runtime_id(), "conv": SESSION, "iat": t, "exp": t + 300 }),
    );
    let cases = [
        (forged, "ticket_invalid"),
        (gateway_domain, "ticket_invalid"),
        (ticket(&env, json!({ "iat": t - 700, "exp": t - 400 })), "ticket_expired"),
        (ticket(&env, json!({ "org": "autreorg" })), "ticket_wrong_org"),
        (ticket(&env, json!({ "rt": "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d" })), "ticket_wrong_audience"),
        (ticket(&env, json!({ "conv": "autreconversation" })), "ticket_wrong_conversation"),
        (ticket(&env, json!({ "op": "llm" })), "ticket_wrong_operation"),
    ];
    for (tk, code) in cases {
        let mut ws = connect(&env, SESSION, ORIGIN).await.unwrap();
        let r = hello(&mut ws, &tk).await;
        assert_eq!(r, json!({ "closed": 4401, "reason": code }));
    }
    // Ticket valide d'un autre utilisateur que le propriétaire de l'autorisation : 4403.
    let mut ws = connect(&env, SESSION, ORIGIN).await.unwrap();
    assert_eq!(hello(&mut ws, &ticket(&env, json!({ "sub": BAD_USER }))).await["closed"], 4403);
    // Trame inconnue après hello : 4400.
    let mut ws = connect(&env, SESSION, ORIGIN).await.unwrap();
    assert_eq!(hello(&mut ws, &ticket(&env, json!({}))).await["t"], "ready");
    ws.send(Message::Text(r#"{"v":1,"t":"ping","admin":true}"#.into())).await.unwrap();
    assert_eq!(next_json(&mut ws).await["closed"], 4400);

    // Q13 : `user.revoked { until }` ferme les connexions de l'utilisateur et refuse ses tickets
    // émis avant `until`.
    let mut ws = connect(&env, SESSION, ORIGIN).await.unwrap();
    assert_eq!(hello(&mut ws, &ticket(&env, json!({}))).await["t"], "ready");
    env.api.push(json!({ "type": "user.revoked", "userId": USER, "until": now() + 1 }));
    assert_eq!(next_json(&mut ws).await["closed"], 4403);
    let mut ws = connect(&env, SESSION, ORIGIN).await.unwrap();
    assert_eq!(hello(&mut ws, &ticket(&env, json!({}))).await, json!({ "closed": 4401, "reason": "ticket_revoked" }));

    env.api.with(|st| assert!(st.signature_failures.is_empty(), "{:?}", st.signature_failures));
    synco_ai_runtime::app::shutdown(&env.running.runtime).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn desappairage_efface_les_cles_deleguees() {
    let env = setup().await;
    let rt = Arc::clone(&env.running.runtime);
    wait_until("délégations traitées", || env.api.with(|st| st.delegation_status.len() == 2)).await;
    for _ in 0..100 {
        if rt.state.lock().await.vault.get(USER).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(rt.state.lock().await.vault.get(USER).is_some());
    env.api.with(|st| st.paired = false);
    env.api.push(json!({ "type": "runtime.unpaired" }));
    for _ in 0..100 {
        if rt.org_id().await.is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let st = rt.state.lock().await;
    assert!(st.org_id.is_none());
    assert!(st.vault.users().is_empty(), "clés déléguées effacées");
    assert!(st.auths.get(SESSION).is_none());
    drop(st);
    let identity: Value = serde_json::from_str(
        &reqwest::get(format!("http://{}/v1/identity", env.running.public_addr)).await.unwrap().text().await.unwrap(),
    )
    .unwrap();
    assert_eq!(identity["orgId"], Value::Null, "les mêmes clés, non appairé");
    assert_eq!(identity["runtimeId"], rt.keys.runtime_id());
    synco_ai_runtime::app::shutdown(&rt).await;
}

// ---------------------------------------------------------------------------
// Relais signed_request : réponses > 1 Mio en parties, requêtes en vol bornées
// ---------------------------------------------------------------------------

use runtime_protocol::pipe::{self as wire, Frame, HttpMethod, Reassembly, SignedRequest, SupervisorMsg, WorkerMsg};
use synco_ai_runtime::launcher::{
    BoxFuture, LaunchError, SpawnedWorker, WorkerExit, WorkerLauncher, WorkerProcess, WorkerSpec,
};

#[derive(Debug, Default)]
struct Report {
    big_len: usize,
    statuses: Vec<(u16, Option<String>)>,
    upload_status: u16,
    after: u16,
}

struct Scripted(tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<Report>>>);

struct Task(Option<tokio::task::JoinHandle<()>>);

impl WorkerProcess for Task {
    fn kill(&mut self) {
        if let Some(t) = &self.0 {
            t.abort();
        }
    }
    fn wait(&mut self) -> BoxFuture<'_, WorkerExit> {
        Box::pin(async move {
            match self.0.take() {
                Some(t) => {
                    let _ = t.await;
                    WorkerExit::Exited(0)
                }
                None => WorkerExit::Unknown,
            }
        })
    }
    fn usage(&self) -> Option<synco_ai_runtime::launcher::ResourceUsage> {
        None
    }
    fn pid(&self) -> Option<u32> {
        None
    }
}

async fn read(rd: &mut tokio::io::ReadHalf<tokio::io::DuplexStream>) -> SupervisorMsg {
    loop {
        match wire::read_frame(rd).await.unwrap() {
            Frame::Json(j) => return wire::decode_json(&j).unwrap(),
            Frame::Keys(_) => {}
        }
    }
}

/// Réponse complète d'une requête (parties réassemblées).
async fn response(rd: &mut tokio::io::ReadHalf<tokio::io::DuplexStream>, id: &str) -> (u16, Option<String>, Vec<u8>) {
    let mut buf = Reassembly::default();
    loop {
        if let SupervisorMsg::SignedRequestResponse(r) = read(rd).await {
            assert_eq!(r.id, id, "réponses dans l'ordre d'émission pour ce test");
            buf.push(r.part, &r.body, wire::MAX_RELAY_RESPONSE_BYTES).unwrap();
            if r.last {
                return (r.status, r.error, buf.into_body());
            }
        }
    }
}

async fn script(io: tokio::io::DuplexStream, report: tokio::sync::oneshot::Sender<Report>) {
    let (mut rd, mut wr) = tokio::io::split(io);
    let SupervisorMsg::Init(init) = read(&mut rd).await else { panic!("init attendu") };
    wire::write_json(&mut wr, &WorkerMsg::Ready(wire::ReadyMsg { pid: 1, version: "test".into() })).await.unwrap();
    while !matches!(read(&mut rd).await, SupervisorMsg::Start(_)) {}
    let conv = format!("/api/runtime/v1/conversations/{}", init.session_id);
    let send = |id: &str, method: HttpMethod, path: String, body: Vec<u8>| {
        SignedRequest::split(id, method, &path, &body, true)
    };
    let mut out = Report::default();
    // 1. Réponse de plus de 1 Mio : reçue en parties, le pipe reste ouvert.
    for p in send("big", HttpMethod::Get, conv.clone(), vec![]) {
        wire::write_json(&mut wr, &WorkerMsg::SignedRequest(p)).await.unwrap();
    }
    let (status, _, body) = response(&mut rd, "big").await;
    assert_eq!(status, 200);
    out.big_len = body.len();
    serde_json::from_slice::<Value>(&body).expect("corps réassemblé lisible");
    // 2. Corps de requête de plus de 1 Mio (historique) en parties.
    let messages: Vec<Value> = (0..300).map(|i| json!({ "id": format!("m{i}"), "pad": "x".repeat(8_000) })).collect();
    let transcript = json!({ "leaseEpoch": init.lease_epoch, "baseRev": 0, "messages": messages, "status": "idle",
        "pendingToolCall": null, "consumedInbox": [] });
    let bytes = transcript.to_string().into_bytes();
    assert!(bytes.len() > 2 * 1024 * 1024);
    for p in send("up", HttpMethod::Put, format!("{conv}/transcript"), bytes) {
        wire::write_json(&mut wr, &WorkerMsg::SignedRequest(p)).await.unwrap();
    }
    out.upload_status = response(&mut rd, "up").await.0;
    // 3. Six requêtes lentes d'un coup : 4 en vol au plus, les autres `relay_busy`, sans fermeture.
    for i in 0..6 {
        for p in send(&format!("slow{i}"), HttpMethod::Get, format!("{conv}/tools"), vec![]) {
            wire::write_json(&mut wr, &WorkerMsg::SignedRequest(p)).await.unwrap();
        }
    }
    for _ in 0..6 {
        if let SupervisorMsg::SignedRequestResponse(r) = read(&mut rd).await {
            out.statuses.push((r.status, r.error));
        }
    }
    // 4. Le pipe fonctionne toujours.
    for p in send("after", HttpMethod::Get, format!("{conv}/inbox"), vec![]) {
        wire::write_json(&mut wr, &WorkerMsg::SignedRequest(p)).await.unwrap();
    }
    out.after = response(&mut rd, "after").await.0;
    let _ = report.send(out);
    wire::write_json(&mut wr, &WorkerMsg::Done(wire::DoneMsg { reason: wire::DoneReason::Idle })).await.unwrap();
}

impl WorkerLauncher for Scripted {
    fn spawn(&self, _spec: WorkerSpec) -> BoxFuture<'_, Result<SpawnedWorker, LaunchError>> {
        Box::pin(async move {
            let report = self.0.lock().await.take().ok_or(LaunchError("une seule fois"))?;
            let (ours, theirs) = tokio::io::duplex(1 << 20);
            let task = tokio::spawn(script(theirs, report));
            Ok(SpawnedWorker { io: Box::new(ours), process: Box::new(Task(Some(task))) })
        })
    }
    fn name(&self) -> &'static str {
        "scripted"
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relais_signed_request_borne_et_decoupe() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let env = setup_with(Arc::new(Scripted(tokio::sync::Mutex::new(Some(tx))))).await;
    // Historique de ~3 Mio servi par l'API.
    env.api.with(|st| {
        st.conversations.get_mut(SESSION).unwrap().messages =
            (0..400).map(|i| json!({ "id": format!("m{i}"), "pad": "y".repeat(8_000) })).collect();
    });
    wait_until("délégations traitées", || env.api.with(|st| st.delegation_status.len() == 2)).await;
    authorize(&env).await;
    env.api.push(json!({ "type": "conversation.wake", "sessionId": SESSION, "authId": AUTH, "reason": "inbox" }));
    let report = tokio::time::timeout(Duration::from_secs(20), rx).await.expect("rapport du worker").unwrap();
    assert!(report.big_len > 3 * 1024 * 1024, "{}", report.big_len);
    assert_eq!(report.upload_status, 200);
    let busy = report.statuses.iter().filter(|(s, e)| *s == 0 && e.as_deref() == Some("relay_busy")).count();
    let served = report.statuses.iter().filter(|(s, _)| *s == 404).count();
    assert_eq!((served, busy), (4, 2), "{:?}", report.statuses);
    assert_eq!(report.after, 200, "pipe toujours ouvert");
    env.api.with(|st| {
        assert_eq!(st.conversations[SESSION].messages.len(), 300, "corps de requête réassemblé");
        assert!(st.signature_failures.is_empty(), "{:?}", st.signature_failures);
    });
    synco_ai_runtime::app::shutdown(&env.running.runtime).await;
}

// ---------------------------------------------------------------------------
// Une délégation révoquée ne « ressuscite » pas (chargement en cours)
// ---------------------------------------------------------------------------

async fn vault_has(env: &Env, user: &str) -> bool {
    env.running.runtime.state.lock().await.vault.get(user).is_some()
}

/// PC17 : le nom d'affichage de `GET /delegations` est conservé (nettoyé), absent → identifiant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn noms_d_affichage_des_delegants() {
    let env = setup().await;
    wait_until("délégations traitées", || env.api.with(|st| st.delegation_status.len() == 2)).await;
    {
        let st = env.running.runtime.state.lock().await;
        assert_eq!(st.display_names.get(USER).map(String::as_str), Some("Alice  Martin"));
        assert!(!st.display_names.contains_key(BAD_USER), "sans nom : repli sur l'identifiant");
    }
    let base = format!("http://{}", env.running.dashboard_addr.expect("dashboard démarré"));
    let c = reqwest::Client::new();
    let login = c
        .post(format!("{base}/api/login"))
        .header("origin", &base)
        .header("content-type", "application/json")
        .body(json!({ "password": DASH_PW }).to_string())
        .send()
        .await
        .unwrap();
    let cookie = login.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_owned();
    let body = c.get(format!("{base}/api/names")).header("cookie", &cookie).send().await.unwrap().text().await.unwrap();
    let names: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(names["names"][USER], "Alice  Martin");
    assert!(names["names"].get(BAD_USER).is_none());
    synco_ai_runtime::app::shutdown(&env.running.runtime).await;
}

const THREAD: &str = "cm3threadexample000000001";

fn reposes(env: &Env) -> Vec<common::Seen> {
    env.api.with(|st| st.seen.iter().filter(|r| r.path.ends_with("/key-envelope/repose")).cloned().collect())
}

fn reset_frame(thread: &str, user: &str, delegation: &str) -> Value {
    json!({ "type": "thread.envelope_reset", "threadId": thread, "userId": user, "delegationId": delegation })
}

/// Q21 : `thread.envelope_reset`. Chemin nominal (commitment recalculé depuis la clé réelle,
/// signature `rt1` valide, S seule), puis refus silencieux : salon étranger, salon d'un autre
/// utilisateur, délégation inconnue ; rejeu idempotent (pas de boucle) ; refus de l'API définitifs ;
/// délégation inactive (révoquée).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enveloppe_rt1_reposee_apres_reinitialisation() {
    let env = setup().await;
    let rt = Arc::clone(&env.running.runtime);
    wait_until("délégations traitées", || env.api.with(|st| st.delegation_status.len() == 2)).await;
    wait_until("flux ouvert", || env.api.with(|st| st.stream_hellos > 0)).await;
    // La clé du salon est dans le coffre de USER, mais le registre ne le connaît pas (salon créé
    // par l'utilisateur, non par ce runtime) : refus, même avec une délégation active.
    env.api.push(reset_frame(THREAD, USER, "d-good"));
    env.api.push(reset_frame("cm3threadetranger00000001", USER, "d-good"));
    wait_until("trames lues", || env.api.with(|st| st.stream_hellos > 0)).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(reposes(&env).is_empty(), "salon absent du registre : rien n'est signé");
    // Salon créé par ce runtime, mais pour un autre utilisateur : refus (clé et délégation de USER
    // pourtant valides).
    {
        let mut st = rt.state.lock().await;
        assert!(st.created_threads.record(THREAD, "cm3userautre0000000000001", "d-autre-user"));
    }
    env.api.push(reset_frame(THREAD, USER, "d-good"));
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(reposes(&env).is_empty(), "salon créé pour un autre utilisateur : rien n'est signé");
    // Le runtime a créé ce salon pour USER.
    {
        let mut st = rt.state.lock().await;
        assert!(st.created_threads.record(THREAD, USER, "d-good"));
    }
    // Refusés : autre utilisateur, délégation inconnue (le coffre de USER n'a que `d-good`).
    env.api.push(reset_frame(THREAD, BAD_USER, "d-bad"));
    env.api.push(reset_frame(THREAD, BAD_USER, "d-good"));
    env.api.push(reset_frame(THREAD, USER, "d-autre"));
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(reposes(&env).is_empty(), "délégation inconnue : rien n'est signé");
    // Nominal.
    env.api.push(reset_frame(THREAD, USER, "d-good"));
    wait_until("enveloppe reposée", || !reposes(&env).is_empty()).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let first = reposes(&env);
    assert_eq!(first.len(), 1, "seule la trame légitime a produit un appel : {first:?}");
    assert_eq!(first[0].auth, None, "S seule : pas d'autorisation de session");
    let body = &first[0].body;
    assert_eq!(
        body.as_object().unwrap().keys().map(String::as_str).collect::<std::collections::BTreeSet<_>>(),
        ["commitment", "ctx", "delegationId", "signature", "version"].into_iter().collect()
    );
    assert_eq!(
        (body["delegationId"].as_str(), body["ctx"].as_str(), body["version"].as_u64()),
        (Some("d-good"), Some("thread:cm3threadexample000000001"), Some(1))
    );
    let envelope = synco_e2ee::keys::KeyEnvelopeSignature {
        commitment: body["commitment"].as_str().unwrap().to_owned(),
        signature: body["signature"].as_str().unwrap().to_owned(),
    };
    let csk = rt.keys.csk().public_key().unwrap();
    synco_e2ee::keys::verify_rt1_envelope(
        &csk,
        &THREAD_KEY,
        "thread:cm3threadexample000000001",
        1,
        "d-good",
        &envelope,
    )
    .expect("signature rt1 valide, commitment de la vraie clé");

    // Rejeu : un second appel, l'API répond `envelope_exists` ou `updated: 0` ; jamais de boucle.
    env.api.push(reset_frame(THREAD, USER, "d-good"));
    wait_until("rejeu traité", || reposes(&env).len() == 2).await;
    env.api.with(|st| st.repose_override = Some((409, "envelope_exists".into())));
    env.api.push(reset_frame(THREAD, USER, "d-good"));
    wait_until("refus de l'API", || reposes(&env).len() == 3).await;
    env.api.with(|st| st.repose_override = Some((403, "forbidden".into())));
    env.api.push(reset_frame(THREAD, USER, "d-good"));
    wait_until("refus forbidden", || reposes(&env).len() == 4).await;
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(reposes(&env).len(), 4, "aucun nouvel essai après un refus de l'API");
    assert!(rt.state.lock().await.repose_inflight.is_empty());

    // Délégation inactive (révoquée) : rien n'est signé.
    env.api.push(
        json!({ "type": "delegation.revoked", "userId": USER, "delegationId": "d-good", "reason": "user_revoked" }),
    );
    wait_until_async(&rt, |st| st.vault.get(USER).is_none()).await;
    env.api.with(|st| st.repose_override = None);
    env.api.push(reset_frame(THREAD, USER, "d-good"));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(reposes(&env).len(), 4, "délégation révoquée : pas de signature");
    synco_ai_runtime::app::shutdown(&rt).await;
}

/// Scénario A : `delegation.revoked` arrive pendant le chargement des entrées.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_pendant_le_chargement() {
    let env = setup_full(Arc::new(InProcessStubLauncher), 800).await;
    wait_until("entrées demandées", || env.api.with(|st| st.entries_requested > 0)).await;
    env.api.push(
        json!({ "type": "delegation.revoked", "userId": USER, "delegationId": "d-good", "reason": "user_revoked" }),
    );
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert!(!vault_has(&env, USER).await, "délégation révoquée réinstallée");
    // Et elle n'est pas rouverte par une relecture ultérieure.
    env.running.runtime.load_delegations().await.unwrap();
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    assert!(!vault_has(&env, USER).await);
    env.api
        .with(|st| assert!(!st.delegation_status.contains_key("d-good"), "aucun statut pour une délégation révoquée"));
    synco_ai_runtime::app::shutdown(&env.running.runtime).await;
}

/// Scénario B : désappairage pendant le chargement des entrées.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn desappairage_pendant_le_chargement() {
    let env = setup_full(Arc::new(InProcessStubLauncher), 800).await;
    wait_until("entrées demandées", || env.api.with(|st| st.entries_requested > 0)).await;
    env.api.with(|st| st.paired = false);
    env.api.push(json!({ "type": "runtime.unpaired" }));
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let st = env.running.runtime.state.lock().await;
    assert!(st.org_id.is_none());
    assert!(st.vault.users().is_empty(), "clés installées après le désappairage");
    drop(st);
    synco_ai_runtime::app::shutdown(&env.running.runtime).await;
}

/// Connexions sans `hello` : au plus 8 par adresse, puis 429 avant la mise à niveau ; une place se
/// libère quand une connexion inoccupée est fermée (délai du `hello`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connexions_non_authentifiees_bornees() {
    let env = setup().await;
    let mut idle = Vec::new();
    for _ in 0..synco_ai_runtime::server::MAX_UNAUTHENTICATED_PER_IP {
        idle.push(connect(&env, SESSION, ORIGIN).await.unwrap());
    }
    assert_eq!(connect(&env, SESSION, ORIGIN).await.err(), Some(429));
    // Délai du hello écoulé : fermées en 4408, les places sont rendues.
    let closed = next_json(&mut idle[0]).await;
    assert_eq!(closed["closed"], 4408, "{closed}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(connect(&env, SESSION, ORIGIN).await.is_ok());
    synco_ai_runtime::app::shutdown(&env.running.runtime).await;
}

/// Un `hello` du flux qui annonce une autre org que celle du certificat ferme le flux.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flux_d_une_autre_org_ferme() {
    let env = setup().await;
    wait_until("flux ouvert", || env.api.with(|st| st.stream_hellos > 0)).await;
    env.api.with(|st| st.hello_org = Some("autreorg".into()));
    env.api.push(json!({ "type": "__close__" }));
    let rt = Arc::clone(&env.running.runtime);
    let mut seen = false;
    for _ in 0..100 {
        if rt.state.lock().await.alerts.iter().any(|(_, c)| *c == "stream_org_mismatch") {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(seen, "alerte stream_org_mismatch attendue");
    // Le flux ne reste pas ouvert : une nouvelle tentative suit, refermée à son tour.
    wait_until("reconnexions", || env.api.with(|st| st.stream_hellos >= 3)).await;
    synco_ai_runtime::app::shutdown(&rt).await;
}

/// authorizations.json : purge sur `user.revoked` et `delegation.revoked`, réconciliation avec
/// l'API à la reconnexion du flux.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn autorisations_purgees_et_reconciliees() {
    let env = setup().await;
    let rt = Arc::clone(&env.running.runtime);
    wait_until("délégations traitées", || env.api.with(|st| st.delegation_status.len() == 2)).await;
    authorize(&env).await;
    // Réconciliation : l'API ne reconnaît plus l'autorisation (403 auth_invalid).
    env.api.with(|st| st.conversations.get_mut(SESSION).unwrap().auth_id = "autre-autorisation".into());
    env.api.push(json!({ "type": "__close__" }));
    let mut gone = false;
    for _ in 0..100 {
        if rt.state.lock().await.auths.get(SESSION).is_none() {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(gone, "autorisation retirée à la réconciliation");
    // Purge sur user.revoked.
    env.api.with(|st| st.conversations.get_mut(SESSION).unwrap().auth_id = AUTH.into());
    authorize(&env).await;
    env.api.push(json!({ "type": "user.revoked", "userId": USER, "until": now() }));
    wait_until_async(&rt, |st| st.auths.get(SESSION).is_none()).await;
    // Purge sur delegation.revoked.
    authorize(&env).await;
    env.api.push(
        json!({ "type": "delegation.revoked", "userId": USER, "delegationId": "d-good", "reason": "user_revoked" }),
    );
    wait_until_async(&rt, |st| st.auths.get(SESSION).is_none() && st.vault.get(USER).is_none()).await;
    let persisted = std::fs::read_to_string(env.state_dir.join("authorizations.json")).unwrap();
    assert!(!persisted.contains(AUTH), "fichier purgé");
    synco_ai_runtime::app::shutdown(&rt).await;
}

/// Q18 : un seul `GET /authorizations?state=active` (paginé), plus un appel par conversation ; une
/// autorisation absente est retirée, une erreur de l'API garde tout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconciliation_par_la_liste_des_autorisations_actives() {
    const S2: &str = "1f0e0d0c-0b0a-4908-8706-050403020100";
    const S3: &str = "2f0e0d0c-0b0a-4908-8706-050403020100";
    const A2: &str = "ae8d7c6b-5a49-4382-9170-6f5e4d3c2b1a";
    const A3: &str = "be8d7c6b-5a49-4382-9170-6f5e4d3c2b1a";
    let env = setup().await;
    let rt = Arc::clone(&env.running.runtime);
    wait_until("délégations traitées", || env.api.with(|st| st.delegation_status.len() == 2)).await;
    env.api.with(|st| {
        st.authorizations_page = 1;
        st.conversations.insert(S2.into(), common::Conversation { auth_id: A2.into(), ..Default::default() });
        st.conversations.insert(S3.into(), common::Conversation { auth_id: A3.into(), ..Default::default() });
    });
    for (s, a) in [(SESSION, AUTH), (S2, A2), (S3, A3)] {
        rt.remember_authorization(s, USER, a).await;
    }
    // Panne de l'API : rien n'est retiré.
    env.api.with(|st| st.authorizations_fail = Some(500));
    rt.reconcile_authorizations().await;
    assert_eq!(rt.state.lock().await.auths.entries().len(), 3, "erreur : on garde");
    // S2 n'est plus dans la liste (révoquée) ; la liste est paginée (1 par page).
    env.api.with(|st| {
        st.authorizations_fail = None;
        st.authorizations_omitted = vec![S2.into()];
        st.seen.clear();
    });
    rt.reconcile_authorizations().await;
    {
        let st = rt.state.lock().await;
        assert!(st.auths.get(S2).is_none(), "autorisation absente = révoquée");
        assert!(st.auths.get(SESSION).is_some() && st.auths.get(S3).is_some());
    }
    env.api.with(|st| {
        let pages = st.seen.iter().filter(|r| r.path.contains("/authorizations?state=active")).count();
        assert_eq!(pages, 2, "deux pages de 1 sur 2 autorisations actives");
        assert!(
            st.seen.iter().all(|r| !r.path.contains("/conversations/")),
            "plus d'appel par conversation : {:?}",
            st.seen.iter().map(|r| r.path.clone()).collect::<Vec<_>>()
        );
    });
    synco_ai_runtime::app::shutdown(&rt).await;
}

async fn wait_until_async(
    rt: &Arc<synco_ai_runtime::runtime::Runtime>,
    f: impl Fn(&synco_ai_runtime::state::State) -> bool,
) {
    for _ in 0..100 {
        if f(&*rt.state.lock().await) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("délai dépassé");
}

fn policy(default_provider: &str, gateway_url: Option<&str>) -> Value {
    json!({
        "v": 1, "orgId": ORG, "defaultProvider": default_provider, "reasoningEffort": "medium",
        "providers": [{ "id": default_provider, "modelId": "m", "gatewayUrl": gateway_url }],
        "runtime": { "enabled": true, "maxDelegationDays": 7, "toolPolicy": {},
            "limits": { "maxStepsPerTurn": 10, "maxTokensPerConversation": 1000, "maxTokensPerTurn": 500,
                "maxTurnDurationSecs": 60, "maxOutputTokensPerCall": 100 } }
    })
}

/// B1 : un fournisseur absent de la configuration du runtime (ici `mistral`, un identifiant inconnu,
/// ou une passerelle dont l'URL de la politique vise une adresse de métadonnées) n'obtient ni
/// worker ni clé : la conversation passe en `failed` (`provider_not_configured`, Q30) et le bail est rendu.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fournisseur_non_configure_refuse() {
    for p in [
        policy("mistral", None),
        policy("evil", Some("https://gw.example.com")),
        policy("gateway", Some("https://169.254.169.254")),
    ] {
        let env = setup_policy(Arc::new(InProcessStubLauncher), 0, Some(p.clone())).await;
        wait_until("délégations traitées", || env.api.with(|st| st.delegation_status.len() == 2)).await;
        authorize(&env).await;
        let mut ws = connect(&env, SESSION, ORIGIN).await.unwrap();
        let ready = hello(&mut ws, &ticket(&env, json!({}))).await;
        assert_eq!(ready["t"], "ready", "{ready}");
        let msg_id = "3c2b1a09-8f7e-4d6c-9b5a-493827161504";
        let content = session::encrypt_field(
            &SymmetricKey::from_bytes(CK),
            SESSION,
            msg_id,
            &FieldName::Content,
            "x",
            &mut OsRandom,
        )
        .unwrap();
        ws.send(Message::Text(
            json!({ "v": 1, "t": "message", "id": msg_id, "content": content, "createdAt": "2026-11-19T10:00:00.000Z" })
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
        // Le bail est libéré par une requête distincte, après l'écriture de l'état `failed` : attendre les deux.
        wait_until("conversation en échec et bail libéré", || {
            env.api.with(|st| {
                let c = &st.conversations[SESSION];
                c.statuses.iter().any(|s| s == "failed") && c.lease_released
            })
        })
        .await;
        env.api.with(|st| {
            let c = &st.conversations[SESSION];
            assert_eq!(c.errors, vec!["provider_not_configured".to_owned()], "{p}");
            assert!(!c.statuses.iter().any(|s| s == "running"), "aucun worker lancé : {p}");
            assert!(c.lease_released);
        });
        synco_ai_runtime::app::shutdown(&env.running.runtime).await;
    }
}

// ---------------------------------------------------------------------------
// created_key (L07) : le vrai code du superviseur contre un worker scripté
// ---------------------------------------------------------------------------

type ScriptFn = Arc<dyn Fn(usize, tokio::io::DuplexStream) -> BoxFuture<'static, ()> + Send + Sync>;

/// Lanceur dont chaque lancement exécute `script(rang, pipe)`.
struct ScriptedEach {
    script: ScriptFn,
    n: std::sync::atomic::AtomicUsize,
}

impl WorkerLauncher for ScriptedEach {
    fn spawn(&self, _spec: WorkerSpec) -> BoxFuture<'_, Result<SpawnedWorker, LaunchError>> {
        Box::pin(async move {
            let i = self.n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (ours, theirs) = tokio::io::duplex(1 << 20);
            let task = tokio::spawn((self.script)(i, theirs));
            Ok(SpawnedWorker { io: Box::new(ours), process: Box::new(Task(Some(task))) })
        })
    }
    fn name(&self) -> &'static str {
        "scripted-each"
    }
}

type Rd = tokio::io::ReadHalf<tokio::io::DuplexStream>;
type Wr = tokio::io::WriteHalf<tokio::io::DuplexStream>;

async fn handshake(rd: &mut Rd, wr: &mut Wr) -> wire::Init {
    let SupervisorMsg::Init(init) = read(rd).await else { panic!("init attendu") };
    wire::write_json(wr, &WorkerMsg::Ready(wire::ReadyMsg { pid: 1, version: "test".into() })).await.unwrap();
    while !matches!(read(rd).await, SupervisorMsg::Start(_)) {}
    *init
}

/// `POST /e2ee/threads` relayé : id du salon créé.
async fn create_thread(rd: &mut Rd, wr: &mut Wr, id: &str) -> String {
    for p in SignedRequest::split(id, HttpMethod::Post, "/api/runtime/v1/e2ee/threads", br#"{"name":"t"}"#, true) {
        wire::write_json(wr, &WorkerMsg::SignedRequest(p)).await.unwrap();
    }
    let (status, _, body) = response(rd, id).await;
    assert_eq!(status, 201);
    serde_json::from_slice::<Value>(&body).unwrap()["id"].as_str().unwrap().to_owned()
}

async fn created_key(rd: &mut Rd, wr: &mut Wr, thread: &str, key: [u8; 32]) -> wire::CreatedKeyMsg {
    let frame = wire::KeyFrame {
        op: wire::KeyOp::Add,
        entries: vec![wire::KeyEntry {
            kind: wire::KeyKind::Thread,
            reference: thread.into(),
            version: 1,
            key: Zeroizing::new(key.to_vec()),
        }],
    };
    wire::write_keys(wr, &frame.encode().unwrap()).await.unwrap();
    loop {
        if let SupervisorMsg::CreatedKey(c) = read(rd).await {
            return c;
        }
    }
}

#[derive(Default)]
struct CreatedReport {
    first: Vec<(String, [u8; 32], wire::CreatedKeyMsg)>,
    /// Le worker a pu continuer après la trame interdite (ne doit jamais arriver).
    survived: bool,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn created_key_reserve_aux_salons_crees_par_ce_worker() {
    let report = Arc::new(std::sync::Mutex::new(CreatedReport::default()));
    let (remove_tx, mut remove_rx) = tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<()>>(1);
    let (r2, remove_tx) = (Arc::clone(&report), Arc::new(remove_tx));
    let script: ScriptFn = Arc::new(move |i, io| {
        let report = Arc::clone(&r2);
        let remove_tx = Arc::clone(&remove_tx);
        Box::pin(async move {
            let (mut rd, mut wr) = tokio::io::split(io);
            handshake(&mut rd, &mut wr).await;
            let push =
                |t: &str, k: [u8; 32], c: wire::CreatedKeyMsg| report.lock().unwrap().first.push((t.to_owned(), k, c));
            if i == 0 {
                // a. Salon jamais créé par ce worker.
                let c = created_key(&mut rd, &mut wr, "cm3threadautre0000000001", [1; 32]).await;
                push("autre", [1; 32], c);
                // b. Salon créé (2xx relayé) : enveloppe signée.
                let t1 = create_thread(&mut rd, &mut wr, "c1").await;
                let c = created_key(&mut rd, &mut wr, &t1, [2; 32]).await;
                push(&t1, [2; 32], c);
                // c. Une seule clé par salon.
                let c = created_key(&mut rd, &mut wr, &t1, [3; 32]).await;
                push("deuxieme", [3; 32], c);
                // d. Plafond : 32 clés au plus par worker.
                for n in 0..32u8 {
                    let t = create_thread(&mut rd, &mut wr, &format!("p{n}")).await;
                    let c = created_key(&mut rd, &mut wr, &t, [n; 32]).await;
                    push(&format!("plafond{n}"), [n; 32], c);
                }
                wire::write_json(&mut wr, &WorkerMsg::Done(wire::DoneMsg { reason: wire::DoneReason::Idle }))
                    .await
                    .unwrap();
            } else {
                // e. Délégation retirée entre la création et la clé.
                let t = create_thread(&mut rd, &mut wr, "d1").await;
                let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
                remove_tx.send(ack_tx).await.unwrap();
                ack_rx.await.unwrap();
                let c = created_key(&mut rd, &mut wr, &t, [9; 32]).await;
                push("delegation", [9; 32], c);
                // f. Trame de clés non admissible (espace) : le worker est tué.
                let bad = wire::KeyFrame {
                    op: wire::KeyOp::Add,
                    entries: vec![wire::KeyEntry {
                        kind: wire::KeyKind::Space,
                        reference: "s1".into(),
                        version: 1,
                        key: Zeroizing::new(vec![1; 32]),
                    }],
                };
                wire::write_keys(&mut wr, &bad.encode().unwrap()).await.unwrap();
                // Tué : cette tâche est interrompue avant d'obtenir une réponse.
                let next = tokio::time::timeout(Duration::from_secs(3), create_thread(&mut rd, &mut wr, "apres")).await;
                if next.is_ok() {
                    report.lock().unwrap().survived = true;
                }
            }
        })
    });
    let launcher = ScriptedEach { script, n: Default::default() };
    let env = setup_with(Arc::new(launcher)).await;
    wait_until("délégations traitées", || env.api.with(|st| st.delegation_status.len() == 2)).await;
    authorize(&env).await;
    let rt = Arc::clone(&env.running.runtime);
    env.api.push(json!({ "type": "conversation.wake", "sessionId": SESSION, "authId": AUTH, "reason": "inbox" }));
    wait_until("premier worker", || report.lock().unwrap().first.len() == 35).await;
    for _ in 0..100 {
        if rt.state.lock().await.convs.get(SESSION).is_some_and(|c| !c.worker.is_active()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    {
        let r = report.lock().unwrap();
        assert_eq!(r.first[0].2.error.as_deref(), Some("created_key_unknown_thread"));
        let (t1, k1, ok) = &r.first[1];
        let env1 = ok.envelope.as_ref().expect("enveloppe");
        let sig = synco_e2ee::keys::KeyEnvelopeSignature {
            commitment: env1.commitment.clone(),
            signature: env1.signature.clone(),
        };
        synco_e2ee::keys::verify_rt1_envelope(&rt.keys.public().csk, k1, &format!("thread:{t1}"), 1, "d-good", &sig)
            .expect("rt1 signée par la csk du runtime, délégation du propriétaire");
        assert_eq!(env1.delegation_id, "d-good");
        assert_eq!(r.first[2].2.error.as_deref(), Some("created_key_unknown_thread"), "une seule clé par salon");
        let ok_count = r.first[3..].iter().filter(|(_, _, c)| c.envelope.is_some()).count();
        assert_eq!(ok_count, 31, "32 clés au plus (1 + 31)");
        assert_eq!(r.first[34].2.error.as_deref(), Some("created_key_limit"));
    }
    // Q21 : les salons dont la clé a été signée sont enregistrés (réparables), l'étranger non.
    {
        let st = rt.state.lock().await;
        let signed: Vec<_> =
            (0..40).filter(|i| st.created_threads.get(&format!("cm3threadmock{:012}", i + 1)).is_some()).collect();
        assert_eq!(signed.len(), 32, "32 clés signées au plus, toutes enregistrées");
        assert!(st.created_threads.get("cm3threadautre0000000001").is_none());
    }
    // Second worker : délégation retirée pendant qu'il travaille, puis trame interdite.
    env.api.push(json!({ "type": "conversation.wake", "sessionId": SESSION, "authId": AUTH, "reason": "inbox" }));
    let ack = tokio::time::timeout(Duration::from_secs(10), remove_rx.recv()).await.unwrap().unwrap();
    rt.state.lock().await.vault.remove_user(USER);
    ack.send(()).unwrap();
    wait_until("second worker", || report.lock().unwrap().first.len() == 36).await;
    assert_eq!(report.lock().unwrap().first[35].2.error.as_deref(), Some("delegation_unavailable"));
    for _ in 0..100 {
        if rt.state.lock().await.convs.get(SESSION).is_some_and(|c| !c.worker.is_active()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(rt.state.lock().await.convs.get(SESSION).is_some_and(|c| !c.worker.is_active()), "worker arrêté");
    assert!(!report.lock().unwrap().survived, "trame de clés interdite : worker tué");
    env.api.with(|st| assert_eq!(st.threads_created, 34, "aucune requête relayée après la trame interdite"));
    synco_ai_runtime::app::shutdown(&rt).await;
}

// ---------------------------------------------------------------------------
// Dashboard (L08) : aucun contenu de conversation dans ses réponses ni dans son stockage
// ---------------------------------------------------------------------------

/// Marqueur injecté partout où un contenu de conversation peut passer par le superviseur.
const MARKER: &str = "MARQUEUR-CONFIDENTIEL-9f3a7c";

struct Marked;

async fn marked_script(io: tokio::io::DuplexStream) {
    let (mut rd, mut wr) = tokio::io::split(io);
    let SupervisorMsg::Init(init) = read(&mut rd).await else { panic!("init attendu") };
    wire::write_json(&mut wr, &WorkerMsg::Ready(wire::ReadyMsg { pid: 1, version: "test".into() })).await.unwrap();
    while !matches!(read(&mut rd).await, SupervisorMsg::Start(_)) {}
    // Journal avec le marqueur (refusé par le superviseur, jamais copié ailleurs).
    wire::write_json(
        &mut wr,
        &WorkerMsg::Log(wire::LogMsg {
            level: "info".into(),
            code: "marqueur_dans_un_journal".into(),
            fields: [("texte".to_owned(), json!(MARKER)), ("outil".to_owned(), json!(format!("outil_{MARKER}")))]
                .into(),
        }),
    )
    .await
    .unwrap();
    // État et code libres contenant le marqueur : ramenés à `other`.
    wire::write_json(&mut wr, &WorkerMsg::Status(wire::StatusMsg { status: MARKER.into(), reason: None }))
        .await
        .unwrap();
    wire::write_json(
        &mut wr,
        &WorkerMsg::Status(wire::StatusMsg { status: "running".into(), reason: Some(MARKER.into()) }),
    )
    .await
    .unwrap();
    // Évènements chiffrés (ici en clair, pire cas) : texte, appel d'outil avec arguments, résultat.
    for (seq, (t, field)) in
        [("text", "content"), ("tool_call", "args"), ("tool_result", "result")].into_iter().enumerate()
    {
        let event = json!({ "v": 1, "t": t, "epoch": init.lease_epoch, "seq": seq + 1, field: MARKER, "name": MARKER });
        wire::write_json(&mut wr, &WorkerMsg::Event(wire::EventMsg { event })).await.unwrap();
    }
    // Historique de la conversation écrit par le worker (contenu, arguments et résultats d'outils).
    let conv = format!("/api/runtime/v1/conversations/{}", init.session_id);
    let transcript = json!({ "leaseEpoch": init.lease_epoch, "baseRev": 0, "status": "idle", "pendingToolCall": null,
        "consumedInbox": [], "messages": [
            { "id": "m1", "role": "user", "content": MARKER },
            { "id": "m2", "role": "assistant", "content": MARKER,
              "toolCalls": [{ "id": "c1", "name": "search_messages", "args": { "q": MARKER }, "result": MARKER }] },
        ] });
    for p in SignedRequest::split(
        "t1",
        HttpMethod::Put,
        &format!("{conv}/transcript"),
        transcript.to_string().as_bytes(),
        true,
    ) {
        wire::write_json(&mut wr, &WorkerMsg::SignedRequest(p)).await.unwrap();
    }
    // Métriques réelles (sans contenu), puis fin.
    let metrics = wire::Metrics {
        turn: 1,
        steps: 3,
        llm_calls: 3,
        tool_calls: 2,
        tool_errors: 1,
        prompt_tokens: 1234,
        completion_tokens: 321,
        reasoning_tokens: 55,
        cost_eur_micro: 4242,
        turn_duration_ms: 9000,
        ..wire::Metrics::default()
    };
    wire::write_json(&mut wr, &WorkerMsg::Metrics(Box::new(metrics))).await.unwrap();
    wire::write_json(&mut wr, &WorkerMsg::Done(wire::DoneMsg { reason: wire::DoneReason::Idle })).await.unwrap();
    // Laisse le superviseur traiter le relais avant de fermer le pipe.
    tokio::time::sleep(Duration::from_millis(500)).await;
}

impl WorkerLauncher for Marked {
    fn spawn(&self, _spec: WorkerSpec) -> BoxFuture<'_, Result<SpawnedWorker, LaunchError>> {
        Box::pin(async move {
            let (ours, theirs) = tokio::io::duplex(1 << 20);
            let task = tokio::spawn(marked_script(theirs));
            Ok(SpawnedWorker { io: Box::new(ours), process: Box::new(Task(Some(task))) })
        })
    }
    fn name(&self) -> &'static str {
        "marked"
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dashboard_sans_contenu_de_conversation() {
    let env = setup_with(Arc::new(Marked)).await;
    wait_until("délégations traitées", || env.api.with(|st| st.delegation_status.len() == 2)).await;
    authorize(&env).await;
    env.api.push(json!({ "type": "conversation.wake", "sessionId": SESSION, "authId": AUTH, "reason": "inbox" }));
    let addr = env.running.dashboard_addr.expect("dashboard démarré (mot de passe défini)");
    let base = format!("http://{addr}");
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let login = client
        .post(format!("{base}/api/login"))
        .header("origin", &base)
        .header("content-type", "application/json")
        .body(json!({ "password": DASH_PW }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 200);
    let cookie = login.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_owned();
    let get = |path: String| {
        let (client, cookie, base) = (client.clone(), cookie.clone(), base.clone());
        async move {
            let r = client.get(format!("{base}{path}")).header("cookie", cookie).send().await.unwrap();
            (r.status().as_u16(), r.text().await.unwrap())
        }
    };
    // Attend la fin de l'exécution (visible dans la liste).
    let mut list = String::new();
    for _ in 0..200 {
        let (_, body) = get("/api/sessions".into()).await;
        let v: Value = serde_json::from_str(&body).unwrap();
        if v["items"].as_array().is_some_and(|i| i.first().is_some_and(|s| s["active"] == false)) {
            list = body;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!list.is_empty(), "exécution terminée attendue");
    let v: Value = serde_json::from_str(&list).unwrap();
    let s = &v["items"][0];
    // Les compteurs sans contenu sont bien là.
    assert_eq!(s["sessionId"], SESSION);
    assert_eq!(s["userId"], USER);
    assert_eq!((s["steps"].as_u64(), s["toolCalls"].as_u64(), s["errors"].as_u64()), (Some(3), Some(2), Some(1)));
    assert_eq!(
        (s["promptTokens"].as_u64(), s["completionTokens"].as_u64(), s["costMicro"].as_u64()),
        (Some(1234), Some(321), Some(4242))
    );
    // Toutes les réponses du dashboard, avec plusieurs filtres et tris.
    let paths = [
        "/api/overview".to_owned(),
        "/api/session".to_owned(),
        "/api/sessions".to_owned(),
        "/api/sessions?sort=cost&desc=false&state=ended&errorsOnly=true".to_owned(),
        format!("/api/sessions?user={USER}&provider=openai&sort=tokens"),
        format!("/api/sessions/{SESSION}"),
        "/api/totals?by=user".to_owned(),
        "/api/totals?by=provider".to_owned(),
        "/".to_owned(),
        "/login".to_owned(),
        "/assets/app.js".to_owned(),
        "/assets/login.js".to_owned(),
        "/assets/style.css".to_owned(),
        "/api/inconnu".to_owned(),
    ];
    let mut total_bytes = 0;
    for p in paths {
        let (status, body) = get(p.clone()).await;
        assert!(status == 200 || status == 404, "{p} : {status}");
        assert!(!body.contains(MARKER), "contenu de conversation dans la réponse de {p}");
        total_bytes += body.len();
    }
    assert!(total_bytes > 1000);
    let (_, detail) = get(format!("/api/sessions/{SESSION}")).await;
    assert!(
        detail.contains("\"k\":\"metrics\"") && detail.contains("\"k\":\"done\""),
        "chronologie sans contenu : {detail}"
    );
    // Stockage : aucun fichier du répertoire d'état ne contient le marqueur ; l'historique existe.
    synco_ai_runtime::app::shutdown(&env.running.runtime).await;
    let history: Vec<_> = all_files(&env.state_dir)
        .into_iter()
        .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("history-")))
        .collect();
    assert_eq!(history.len(), 1, "un fichier d'historique du jour");
    assert!(
        std::fs::read_to_string(&history[0]).unwrap().contains("\"cost_micro\"")
            || std::fs::read_to_string(&history[0]).unwrap().contains("costMicro")
    );
    for path in all_files(&env.state_dir) {
        let bytes = std::fs::read(&path).unwrap();
        assert!(!bytes.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()), "marqueur dans {}", path.display());
    }
    // L'API simulée, elle, a bien reçu le contenu : le test injecte donc réellement le marqueur.
    env.api.with(|st| {
        assert!(st.conversations[SESSION].messages.iter().any(|m| m.to_string().contains(MARKER)));
    });
}

/// Câblage de `dashboard.trust_proxy_hops` : le dashboard ne reprend PAS `listen.trust_proxy_hops`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dashboard_ignore_listen_trust_proxy_hops() {
    let env = setup_hops(Arc::new(InProcessStubLauncher), 0, None, "http://127.0.0.1:9/v1", 1).await;
    assert_eq!(env.running.runtime.config.listen.trust_proxy_hops, 1);
    assert_eq!(env.running.runtime.config.dashboard.trust_proxy_hops, 0);
    let addr = env.running.dashboard_addr.expect("dashboard démarré");
    let base = format!("http://{addr}");
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let attempt = |i: usize, password: String| {
        let r = client
            .post(format!("{base}/api/login"))
            .header("origin", &base)
            .header("x-forwarded-for", format!("203.0.113.{i}"))
            .header("x-forwarded-proto", "https")
            .header("content-type", "application/json")
            .body(json!({ "password": password }).to_string());
        async move { r.send().await.unwrap() }
    };
    // Un X-Forwarded-Proto forgé sur une connexion directe ne pose pas `Secure`.
    let ok = attempt(0, DASH_PW.into()).await;
    assert_eq!(ok.status(), 200);
    assert!(!ok.headers()["set-cookie"].to_str().unwrap().contains("Secure"));
    let mut codes = Vec::new();
    for i in 0..8 {
        codes.push(attempt(i, "faux".into()).await.status().as_u16());
    }
    assert_eq!(codes, [401, 401, 401, 401, 401, 429, 429, 429], "X-Forwarded-For ignoré : une seule adresse");
    synco_ai_runtime::app::shutdown(&env.running.runtime).await;
}

// ---------------------------------------------------------------------------
// Q25 : épinglage TOFU des clés RSA des membres, appliqué par le vrai superviseur au relais de
// `GET /e2ee/members/keys`
// ---------------------------------------------------------------------------

const OTHER: &str = "cm3membreautre00000000001";

/// JWK RSA synthétique de 2048 bits (l'épinglage ne demande pas une vraie clé).
fn rsa_jwk(seed: u8) -> String {
    let mut n = vec![seed; 256];
    n[0] |= 0x80;
    json!({ "kty": "RSA", "n": synco_e2ee::encoding::b64u(&n), "e": "AQAB" }).to_string()
}

fn spki(seed: u8) -> String {
    synco_ai_runtime::member_pins::MemberKey::from_jwk_str(&rsa_jwk(seed)).unwrap().fingerprint
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cles_rsa_des_membres_epinglees_par_le_superviseur() {
    use synco_ai_runtime::dashboard::routes::OverviewSource as _;
    // Le worker scripté fait un `GET /e2ee/members/keys` à chaque ordre reçu et rend la réponse.
    let (go_tx, go_rx) = tokio::sync::mpsc::channel::<String>(1);
    let (res_tx, res_rx) = tokio::sync::mpsc::channel::<(u16, Value)>(1);
    let go_rx = Arc::new(tokio::sync::Mutex::new(Some(go_rx)));
    let script: ScriptFn = Arc::new(move |_, io| {
        let (go_rx, res_tx) = (Arc::clone(&go_rx), res_tx.clone());
        Box::pin(async move {
            let Some(mut go) = go_rx.lock().await.take() else { return };
            let (mut rd, mut wr) = tokio::io::split(io);
            handshake(&mut rd, &mut wr).await;
            let mut n = 0;
            while let Some(path) = go.recv().await {
                n += 1;
                let id = format!("m{n}");
                for p in SignedRequest::split(&id, HttpMethod::Get, &path, b"", true) {
                    wire::write_json(&mut wr, &WorkerMsg::SignedRequest(p)).await.unwrap();
                }
                let (status, error, body) = response(&mut rd, &id).await;
                let body = serde_json::from_slice(&body).unwrap_or_else(|_| json!({ "relay": error }));
                res_tx.send((status, body)).await.unwrap();
            }
            let _ = wire::write_json(&mut wr, &WorkerMsg::Done(wire::DoneMsg { reason: wire::DoneReason::Idle })).await;
        })
    });
    let env = setup_with(Arc::new(ScriptedEach { script, n: Default::default() })).await;
    wait_until("délégations traitées", || env.api.with(|st| st.delegation_status.len() == 2)).await;
    authorize(&env).await;
    let rt = Arc::clone(&env.running.runtime);
    let members = |user: u8, other: u8| {
        json!([
            { "userId": USER, "publicKey": rsa_jwk(user), "publicSignKey": null },
            { "userId": OTHER, "publicKey": rsa_jwk(other), "publicSignKey": null },
        ])
    };
    let res_rx = Arc::new(tokio::sync::Mutex::new(res_rx));
    let ask_path = |m: Value, path: &str| {
        env.api.with(|st| st.members = m);
        let (go, res, path) = (go_tx.clone(), Arc::clone(&res_rx), path.to_owned());
        async move {
            go.send(path).await.unwrap();
            tokio::time::timeout(Duration::from_secs(10), res.lock().await.recv()).await.unwrap().unwrap()
        }
    };
    let ask = |m: Value| ask_path(m, "/api/runtime/v1/e2ee/members/keys");
    env.api.push(json!({ "type": "conversation.wake", "sessionId": SESSION, "authId": AUTH, "reason": "inbox" }));

    // 1. Première vue : épinglées, réponse transmise telle quelle.
    let (status, body) = ask(members(1, 2)).await;
    assert_eq!(status, 200);
    assert_eq!(body["members"].as_array().unwrap().len(), 2);
    // 2. Même clé : acceptée.
    assert_eq!(ask(members(1, 2)).await.0, 200);
    // Q23 : l'annuaire d'un espace (`?spaceId=`) passe par le même contrôle d'épinglage.
    let space_dir = "/api/runtime/v1/e2ee/members/keys?spaceId=cm3spaceexample0000000001";
    assert_eq!(ask_path(members(1, 2), space_dir).await.0, 200);
    // Revue M1 : variante du chemin (contournerait le contrôle) refusée au relais, sans appel à l'API.
    let directory_calls =
        || env.api.with(|st| st.seen.iter().filter(|r| r.path.to_ascii_lowercase().contains("members")).count());
    let before = directory_calls();
    let (status, body) = ask_path(members(1, 3), "/api/runtime/v1/e2ee/Members/keys/").await;
    assert_eq!((status, body), (0, json!({ "relay": "relay_refused" })));
    assert_eq!(directory_calls(), before, "rien n'est parti vers l'API");
    // 3. Clé substituée (membre sans délégation, donc sans chaîne vérifiable) : refus global.
    let (status, body) = ask(members(1, 3)).await;
    assert_eq!((status, body), (409, json!({ "error": "member_key_changed" })), "aucune clé transmise au worker");
    {
        let st = rt.state.lock().await;
        assert!(st.alerts.iter().any(|(_, c)| *c == "member_rsa_key_changed"), "alerte au dashboard");
        assert_eq!(st.member_pins.get(ORG, OTHER).unwrap().fingerprint, spki(2), "épingle inchangée");
    }
    let o = rt.overview().await;
    assert_eq!(o.member_key_changes.len(), 1);
    assert_eq!(
        (o.member_key_changes[0].user_id.as_str(), o.member_key_changes[0].fingerprint.clone()),
        (OTHER, spki(3))
    );
    assert_eq!(ask(members(1, 3)).await.0, 409, "toujours refusée");
    let (status, body) = ask_path(members(1, 3), space_dir).await;
    assert_eq!((status, body), (409, json!({ "error": "member_key_changed" })), "annuaire d'espace contrôlé aussi");
    env.api
        .with(|st| assert!(st.seen.iter().any(|r| r.path.ends_with("members/keys?spaceId=cm3spaceexample0000000001"))));
    // 4. Rotation légitime de USER : transition signée par sa clé de signature épinglée.
    let k2 = EcSigningKey::generate(&mut OsRandom).unwrap();
    let t = synco_e2ee::identity::sign_identity_transition(
        &env.user_key,
        USER,
        0,
        &rsa_jwk(4),
        &k2.public_key().unwrap().to_canonical(),
    )
    .unwrap();
    env.api.with(|st| {
        st.transitions.insert(
            USER.into(),
            vec![json!({ "seq": t.seq, "oldPublicSignKey": t.old_public_sign_key, "newPublicKey": t.new_public_key,
                "newPublicSignKey": t.new_public_sign_key, "signature": t.signature })],
        );
    });
    assert_eq!(ask(members(4, 2)).await.0, 200, "rotation prouvée acceptée");
    assert_eq!(rt.state.lock().await.member_pins.get(ORG, USER).unwrap().fingerprint, spki(4));
    // 5. Clé substituée pour USER malgré la chaîne (qui aboutit à une autre clé) : refus.
    assert_eq!(ask(members(5, 2)).await.0, 409);
    // 6. Acceptation manuelle par l'admin de la clé affichée (et d'elle seule).
    assert!(!rt.accept_member_key(OTHER.into(), spki(9)).await, "autre empreinte");
    assert!(rt.accept_member_key(OTHER.into(), spki(3)).await);
    assert_eq!(ask(members(4, 3)).await.0, 200, "clé acceptée par l'admin");
    assert_eq!(rt.overview().await.member_key_changes.len(), 1, "reste USER (clé 5)");
    drop(go_tx);
    env.api.with(|st| assert_eq!(st.threads_created, 0));
    synco_ai_runtime::app::shutdown(&rt).await;
    // 7. Persistance : relu depuis le répertoire d'état (comme au redémarrage).
    let reopened = synco_ai_runtime::member_pins::MemberPinStore::open(&env.state_dir).unwrap();
    assert_eq!(reopened.get(ORG, USER).unwrap().fingerprint, spki(4));
    assert_eq!(reopened.get(ORG, OTHER).unwrap().fingerprint, spki(3));
    assert_eq!(reopened.pending(ORG).len(), 1);
}

/// Revue I3 : 2 000 premières vues dans une réponse = une seule écriture, hors du verrou d'état
/// (mesure : durée du contrôle, attente maximale du verrou pendant ce temps) ; au-delà du plafond
/// d'épingles par org, refus fermé.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cles_rsa_charge_et_plafond() {
    use synco_ai_runtime::member_pins::MAX_PINS_PER_ORG;
    use synco_ai_runtime::workers::member_keys_gate;
    let env = setup().await;
    wait_until("appairé", || env.api.with(|st| st.delegation_status.len() == 2)).await;
    let rt = Arc::clone(&env.running.runtime);
    // Revue M3 : corps illisible → échec fermé.
    for bad in [&b"pas du json"[..], br#"{"members":{}}"#, br#"{"autre":[]}"#] {
        assert_eq!(member_keys_gate(&rt, bad).await, Err("member_keys_unreadable"));
    }
    // Revue M5 : première vue qui ne peut pas être enregistrée → refus fermé et alerte.
    {
        use std::os::unix::fs::PermissionsExt as _;
        let first =
            json!({ "members": [{ "userId": "cm3charge0000000000000000", "publicKey": rsa_jwk(1) }] }).to_string();
        std::fs::set_permissions(&env.state_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = member_keys_gate(&rt, first.as_bytes()).await;
        std::fs::set_permissions(&env.state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(result, Err("member_pins_unavailable"));
        assert!(rt.state.lock().await.alerts.iter().any(|(_, c)| *c == "member_pins_not_saved"));
    }
    let members: Vec<Value> = (0..MAX_PINS_PER_ORG)
        .map(|i| json!({ "userId": format!("cm3charge{i:016}"), "publicKey": rsa_jwk(u8::try_from(i % 200).unwrap() + 1) }))
        .collect();
    let body = json!({ "members": members }).to_string();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let probe = {
        let (rt, stop) = (Arc::clone(&rt), Arc::clone(&stop));
        tokio::spawn(async move {
            let mut worst = Duration::ZERO;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let t = std::time::Instant::now();
                drop(rt.state.lock().await);
                worst = worst.max(t.elapsed());
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            worst
        })
    };
    let t = std::time::Instant::now();
    assert_eq!(member_keys_gate(&rt, body.as_bytes()).await, Ok(()));
    let elapsed = t.elapsed();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let worst = probe.await.unwrap();
    eprintln!("mesure I3 : {MAX_PINS_PER_ORG} premières vues en {elapsed:?}, attente maximale du verrou {worst:?}");
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    let text = std::fs::read_to_string(env.state_dir.join(synco_ai_runtime::member_pins::MEMBER_PINS_FILE)).unwrap();
    assert_eq!(text.matches("\"fingerprint\"").count(), MAX_PINS_PER_ORG, "toutes écrites");
    // Même réponse : rien à écrire, acceptée.
    assert_eq!(member_keys_gate(&rt, body.as_bytes()).await, Ok(()));
    // Un membre de plus : plafond, refus fermé, alerte.
    let more = json!({ "members": [{ "userId": "cm3chargeenplus0000000001", "publicKey": rsa_jwk(1) }] }).to_string();
    assert_eq!(member_keys_gate(&rt, more.as_bytes()).await, Err("member_pins_limit"));
    assert!(rt.state.lock().await.alerts.iter().any(|(_, c)| *c == "member_pins_limit"));
    // Revue M5 : échec d'écriture → refus fermé et alerte visible au dashboard.
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&env.state_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let changed =
        json!({ "members": [{ "userId": "cm3charge0000000000000000", "publicKey": rsa_jwk(250) }] }).to_string();
    let result = member_keys_gate(&rt, changed.as_bytes()).await;
    std::fs::set_permissions(&env.state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(result, Err("member_key_changed"), "refus maintenu même si sa mémorisation échoue");
    assert!(rt.state.lock().await.alerts.iter().any(|(_, c)| *c == "member_pins_not_saved"));
    synco_ai_runtime::app::shutdown(&rt).await;
}

/// Revue L05b : vérifications de rotation bornées par réponse, org revérifiée après l'appel
/// `sign-key`, deux réponses concurrentes pour un même membre jamais vu.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cles_rsa_bornes_org_et_concurrence() {
    use synco_ai_runtime::workers::{MAX_ROTATION_LOOKUPS, member_keys_gate};
    let env = setup().await;
    wait_until("délégations traitées", || env.api.with(|st| st.delegation_status.len() == 2)).await;
    let rt = Arc::clone(&env.running.runtime);
    let org = rt.state.lock().await.org_id.clone().unwrap();
    let body = |m: &[(&str, u8)]| {
        json!({ "members": m.iter().map(|(u, k)| json!({ "userId": u, "publicKey": rsa_jwk(*k) })).collect::<Vec<_>>() })
            .to_string()
    };

    // 1. Au plus MAX_ROTATION_LOOKUPS appels `sign-key` par réponse.
    let users: Vec<String> = (0..MAX_ROTATION_LOOKUPS + 3).map(|i| format!("cm3rotation{i:014}")).collect();
    for u in &users {
        let k = EcSigningKey::generate(&mut OsRandom).unwrap().public_key().unwrap().to_canonical();
        rt.state.lock().await.pins.check_or_pin(u, Some(&k), &[], now()).unwrap();
        env.api.with(|st| st.sign_keys.insert(u.clone(), k.clone()));
    }
    let first: Vec<(&str, u8)> = users.iter().map(|u| (u.as_str(), 1)).collect();
    assert_eq!(member_keys_gate(&rt, body(&first).as_bytes()).await, Ok(()));
    let changed: Vec<(&str, u8)> = users.iter().map(|u| (u.as_str(), 2)).collect();
    let lookups = || env.api.with(|st| st.seen.iter().filter(|r| r.path.contains("cm3rotation")).count());
    let before = lookups();
    assert_eq!(member_keys_gate(&rt, body(&changed).as_bytes()).await, Err("member_key_changed"));
    assert_eq!(lookups() - before, MAX_ROTATION_LOOKUPS, "vérifications de rotation bornées");

    // 2. Rotation valide de USER, mais désappairage pendant l'appel `sign-key` : rien d'installé.
    assert_eq!(member_keys_gate(&rt, body(&[(USER, 1)]).as_bytes()).await, Ok(()));
    let k2 = EcSigningKey::generate(&mut OsRandom).unwrap();
    let t = synco_e2ee::identity::sign_identity_transition(
        &env.user_key,
        USER,
        0,
        &rsa_jwk(4),
        &k2.public_key().unwrap().to_canonical(),
    )
    .unwrap();
    env.api.with(|st| {
        st.slow_sign_key_ms = 400;
        st.transitions.insert(
            USER.into(),
            vec![json!({ "seq": t.seq, "oldPublicSignKey": t.old_public_sign_key, "newPublicKey": t.new_public_key,
                "newPublicSignKey": t.new_public_sign_key, "signature": t.signature })],
        );
    });
    let gate = {
        let (rt, b) = (Arc::clone(&rt), body(&[(USER, 4)]));
        tokio::spawn(async move { member_keys_gate(&rt, b.as_bytes()).await })
    };
    tokio::time::sleep(Duration::from_millis(150)).await;
    rt.state.lock().await.org_id = None;
    let result = gate.await.unwrap();
    rt.state.lock().await.org_id = Some(org.clone());
    assert_eq!(result, Err("member_pins_unavailable"));
    assert_eq!(
        rt.state.lock().await.member_pins.get(&org, USER).unwrap().fingerprint,
        spki(1),
        "org revérifiée après l'appel réseau : rotation non installée"
    );
    // Même rotation, org stable : acceptée.
    env.api.with(|st| st.slow_sign_key_ms = 0);
    assert_eq!(member_keys_gate(&rt, body(&[(USER, 4)]).as_bytes()).await, Ok(()));
    assert_eq!(rt.state.lock().await.member_pins.get(&org, USER).unwrap().fingerprint, spki(4));

    // 3. Deux réponses concurrentes pour un membre jamais vu, avec deux clés différentes : une seule
    //    est épinglée, l'autre refusée.
    let (a, b) = (body(&[("cm3concurrent0000000000001", 5)]), body(&[("cm3concurrent0000000000001", 6)]));
    let (ra, rb) = tokio::join!(member_keys_gate(&rt, a.as_bytes()), member_keys_gate(&rt, b.as_bytes()));
    let pinned = rt.state.lock().await.member_pins.get(&org, "cm3concurrent0000000000001").unwrap().fingerprint.clone();
    match (ra, rb) {
        (Ok(()), Err("member_key_changed")) => assert_eq!(pinned, spki(5)),
        (Err("member_key_changed"), Ok(())) => assert_eq!(pinned, spki(6)),
        other => panic!("une seule clé doit gagner : {other:?}"),
    }
    synco_ai_runtime::app::shutdown(&rt).await;
}
