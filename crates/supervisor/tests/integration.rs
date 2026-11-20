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
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("etat");
    // Clés générées et scellées par phrase de passe (comme au premier démarrage).
    let keys = seal::create(&state_dir, &backend()).unwrap();
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
    let (good, good_entries) = delegation_record(&kex, &fpr, keys.runtime_id(), USER, "d-good", &user_key, 0);
    let (bad, bad_entries) = delegation_record(&kex, &fpr, keys.runtime_id(), BAD_USER, "d-bad", &bad_key, 3_600);
    api.with(|st| {
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
trust_proxy_hops = 0
[limits]
idle_shutdown_secs = 1
shutdown_grace_secs = 2
"#,
        api.url(),
        state_dir.display()
    ))
    .unwrap();
    let keys = seal::load(&state_dir, &backend()).unwrap().unwrap();
    let running =
        synco_ai_runtime::app::start(config, keys, Arc::new(InProcessStubLauncher), BTreeMap::new()).await.unwrap();
    Env { _dir: dir, state_dir, api, running, keys_secret }
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
    let env = setup().await;
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
    let mut text = None;
    let mut statuses = Vec::new();
    while statuses.last().map(String::as_str) != Some("idle") {
        let ev = next_json(&mut ws).await;
        assert_eq!(ev["epoch"], 1, "{ev}");
        match ev["t"].as_str().unwrap() {
            "status" => statuses.push(ev["status"].as_str().unwrap().to_owned()),
            "text" => text = Some(ev),
            other => panic!("évènement inattendu {other}"),
        }
    }
    assert_eq!(statuses, ["running", "idle"]);
    // Le delta est chiffré par CK avec l'AAD ws:text:<epoch>:<seq> : seul le client le lit.
    let text = text.expect("delta de texte");
    let clear = session::decrypt_field(
        &ck,
        SESSION,
        text["messageId"].as_str().unwrap(),
        &format!("ws:text:1:{}", text["seq"]),
        text["delta"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(clear, synco_ai_runtime_worker::stub::STUB_REPLY);

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
        assert_eq!(stored.unwrap(), synco_ai_runtime_worker::stub::STUB_REPLY);
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

fn assert_no_private_key_on_disk(env: &Env) {
    let privates: Vec<&[u8]> = env.keys_secret[4 + 1 + 36..].chunks(32).collect();
    assert_eq!(privates.len(), 3);
    let mut files = 0;
    for entry in std::fs::read_dir(&env.state_dir).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
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
