//! Vecteurs de synco_api (`tests/vectors/ai-runtime/`, générés par le code réel de l'API, copiés
//! sans modification) rejoués côté runtime :
//! - `tickets-runtime.json` : chaque cas `srt1` donne exactement le code attendu ;
//! - `internal-requests.json` : pour chaque requête valide, la chaîne signée par le runtime est
//!   **identique** à `signedString` et la signature Ed25519 (déterministe) identique à l'en-tête ;
//!   chaque cas (valide ou non) donne le code attendu avec le vérificateur de `signing`, qui sert
//!   aussi à l'API simulée des tests du superviseur.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests : un vecteur illisible doit échouer bruyamment"
)]

use std::collections::BTreeMap;

use ed25519_dalek::{SigningKey, VerifyingKey};
use runtime_protocol::signing::{self, NonceCache, RegisteredRuntime, RequestFields};
use runtime_protocol::ticket::{self, RevokedUser, TicketContext, TicketKeys};
use serde_json::Value;
use synco_e2ee::encoding::{from_b64, from_b64u_array, from_hex};

fn load(name: &str) -> Value {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path} : {e}"))).unwrap()
}

#[test]
fn tickets_runtime() {
    let v = load("tickets-runtime.json");
    assert_eq!(v["policy"]["clock_skew_secs"], ticket::CLOCK_SKEW_SECS);
    assert_eq!(v["policy"]["max_lifetime_secs"], ticket::MAX_LIFETIME_SECS);
    assert_eq!(v["policy"]["max_length"], ticket::MAX_LENGTH);
    let keys_map: BTreeMap<String, String> = serde_json::from_value(v["publicKeys"].clone()).unwrap();
    let (keys, rejected) = TicketKeys::from_b64u_map(keys_map.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    assert_eq!(rejected, 0);
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 30, "tous les cas de 02 §5 attendus");
    let mut failures = Vec::new();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let revoked_users: Vec<RevokedUser> = c
            .get("revokedUsers")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|r| RevokedUser {
                        user_id: r["userId"].as_str().unwrap().to_owned(),
                        until: r["until"].as_u64().unwrap(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let revoked_conversations: Vec<String> = c
            .get("revokedConversations")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(|s| s.as_str().unwrap().to_owned()).collect())
            .unwrap_or_default();
        let ctx = TicketContext {
            runtime_id: c["runtimeId"].as_str().unwrap(),
            org_id: c["orgId"].as_str().unwrap(),
            conv: c["conv"].as_str().unwrap(),
            revoked_users: &revoked_users,
            revoked_conversations: &revoked_conversations,
        };
        let got =
            match ticket::verify_runtime_ticket(c["ticket"].as_str().unwrap(), &keys, &ctx, c["now"].as_u64().unwrap())
            {
                Ok(claims) => {
                    assert_eq!(claims.rt, ctx.runtime_id, "{name}");
                    "ok"
                }
                Err(e) => e.code(),
            };
        if got != c["expect"].as_str().unwrap() {
            failures.push(format!("{name} : attendu {}, obtenu {got}", c["expect"]));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

struct Request<'a> {
    method: &'a str,
    path: &'a str,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    now: u64,
    signed_string: Option<&'a str>,
}

fn request(r: &Value) -> Request<'_> {
    Request {
        method: r["method"].as_str().unwrap(),
        path: r["path"].as_str().unwrap(),
        headers: serde_json::from_value(r["headers"].clone()).unwrap(),
        body: from_b64(r["bodyB64"].as_str().unwrap()).unwrap(),
        now: r["now"].as_u64().unwrap(),
        signed_string: r.get("signedString").and_then(Value::as_str),
    }
}

#[test]
fn requetes_internes() {
    let v = load("internal-requests.json");
    assert_eq!(v["domain"].as_str().unwrap().replace("\\0", "\0").as_bytes(), signing::DOMAIN);
    assert_eq!(v["policy"]["max_clock_drift_secs"], signing::MAX_CLOCK_DRIFT_SECS);
    assert_eq!(v["policy"]["nonce_ttl_secs"], signing::NONCE_TTL_SECS);
    let seed: [u8; 32] = from_hex(v["seedHex"].as_str().unwrap()).unwrap().try_into().unwrap();
    let key = SigningKey::from_bytes(&seed);
    let registry: BTreeMap<String, RegisteredRuntime> = v["runtimes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let pk = from_b64u_array::<32>(r["sigPublicKey"].as_str().unwrap()).unwrap();
            (
                r["runtimeId"].as_str().unwrap().to_owned(),
                RegisteredRuntime {
                    sig_public_key: VerifyingKey::from_bytes(&pk).unwrap(),
                    active: r["status"] == "active",
                },
            )
        })
        .collect();
    let own_runtime = registry
        .iter()
        .find(|(_, r)| r.sig_public_key == key.verifying_key())
        .map(|(id, _)| id.clone())
        .expect("la graine du fichier signe pour un runtime du registre");

    let mut failures = Vec::new();
    let mut signed_checked = 0;
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let requests: Vec<Request<'_>> = match c.get("requests") {
            Some(list) => list.as_array().unwrap().iter().map(request).collect(),
            None => vec![request(&c["request"])],
        };
        let mut nonces = NonceCache::new(8000, signing::NONCE_TTL_SECS);
        let last = requests.len() - 1;
        for (i, r) in requests.iter().enumerate() {
            // Sens runtime : la chaîne signée et la signature du runtime sont celles de l'API.
            if let Some(expected) = r.signed_string {
                let h = |n: &str| r.headers.get(n).map(String::as_str);
                let fields = RequestFields {
                    method: r.method,
                    path: r.path,
                    timestamp: h(signing::HEADER_TIMESTAMP).unwrap(),
                    nonce: h(signing::HEADER_NONCE).unwrap(),
                    runtime_id: h(signing::HEADER_RUNTIME).unwrap(),
                    auth_id: h(signing::HEADER_AUTH),
                    body: &r.body,
                };
                if signing::signing_string(&fields) != expected {
                    failures.push(format!("{name} : chaîne signée différente"));
                }
                if fields.runtime_id == own_runtime {
                    let headers = signing::signature_headers(&fields, &key);
                    let sig = headers.iter().find(|(n, _)| *n == signing::HEADER_SIGNATURE).unwrap();
                    if Some(sig.1.as_str()) != h(signing::HEADER_SIGNATURE) {
                        failures.push(format!("{name} : signature du runtime différente"));
                    }
                    signed_checked += 1;
                }
            }
            // Sens vérificateur : même règle que l'API.
            let got = match signing::verify_request(
                r.method,
                r.path,
                &r.body,
                |n| r.headers.get(n).map(String::as_str),
                |id| registry.get(id).cloned(),
                &mut nonces,
                r.now,
            ) {
                Ok(_) => "ok",
                Err(e) => e.code(),
            };
            let expected = if i == last { c["expect"].as_str().unwrap() } else { "ok" };
            if got != expected {
                failures.push(format!("{name} (requête {i}) : attendu {expected}, obtenu {got}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    assert!(signed_checked >= 8, "les signatures des cas valides sont recalculées ({signed_checked})");
}
