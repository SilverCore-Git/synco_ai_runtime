//! Vecteurs TS → Rust produits par le code réel de l'app
//! (`synco_app/scripts/e2ee-vectors/generate.ts`, docs/plan/vectors/README.md §3) et rejoués ici.
//! Valeurs déterministes comparées à l'octet près ; signatures ECDSA vérifiées.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests : un vecteur illisible doit échouer bruyamment"
)]

use serde_json::Value;
use synco_e2ee::delegation::{self, DelegationContext, DelegationKey, EntryKind, Scope};
use synco_e2ee::device;
use synco_e2ee::ec::{EcPublicKey, EcSigningKey, EcdhSecret};
use synco_e2ee::encoding::{b64u, from_b64u, from_hex, hex};
use synco_e2ee::identity::{self, IdentityPurpose, IdentityTransition, SealedIdentityKey};
use synco_e2ee::keys::{self, KeyEnvelopeSignature};
use synco_e2ee::primitives::{hkdf32, sha256};
use synco_e2ee::runtime_cert::{
    self, ChallengePurpose, ChallengeRequest, RuntimeCertificate, RuntimePublicKeys, SignedRuntimeCertificate,
};
use synco_e2ee::session;
use synco_e2ee::{Error, RandomSource, Result, SymmetricKey};

fn load(name: &str) -> Value {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path} : {e}"))).unwrap()
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("champ {key} absent : {v}"))
}

fn u(v: &Value, key: &str) -> u64 {
    v[key].as_u64().unwrap_or_else(|| panic!("champ {key} absent : {v}"))
}

fn bytes(v: &Value, key: &str) -> Vec<u8> {
    from_hex(s(v, key)).unwrap()
}

fn outcome<T>(r: &Result<T>) -> &'static str {
    match r {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

fn cases<'a>(v: &'a Value, key: &str) -> &'a Vec<Value> {
    let list = v[key].as_array().unwrap_or_else(|| panic!("liste {key} absente"));
    assert!(!list.is_empty(), "liste {key} vide");
    list
}

/// Aléa rejoué dans l'ordre (vecteurs uniquement).
struct Fixed(Vec<Vec<u8>>);

impl RandomSource for Fixed {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        assert!(!self.0.is_empty(), "aléa inattendu");
        let next = self.0.remove(0);
        assert_eq!(next.len(), dest.len(), "longueur d'aléa");
        dest.copy_from_slice(&next);
        Ok(())
    }
}

fn runtime_keys(v: &Value) -> RuntimePublicKeys {
    RuntimePublicKeys::from_parts(
        s(v, "sig"),
        EcPublicKey::from_canonical(s(v, "kex")).unwrap(),
        EcPublicKey::from_canonical(s(v, "csk")).unwrap(),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------

#[test]
fn identite_du_runtime() {
    let v = load("runtime-identity.json");
    let f = &v["fingerprint"];
    let keys = runtime_keys(&f["keys"]);
    let runtime_id = s(f, "runtimeId");
    // Les clés publiques se dérivent des scalaires de test.
    let kex = EcdhSecret::from_scalar(&bytes(f, "kexScalarHex")).unwrap();
    let csk = EcSigningKey::from_scalar(&bytes(f, "cskScalarHex")).unwrap();
    assert_eq!(kex.public_key().unwrap(), keys.kex);
    assert_eq!(csk.public_key().unwrap(), keys.csk);

    assert_eq!(runtime_cert::fingerprint_input(runtime_id, &keys).unwrap(), s(f, "fprInput"));
    let fpr = runtime_cert::fingerprint(runtime_id, &keys).unwrap();
    assert_eq!(hex(&fpr), s(f, "fprHex"));
    assert_eq!(runtime_cert::display_fingerprint(s(f, "fprHex")).unwrap(), s(f, "display"));
    assert_eq!(runtime_cert::pairing_code(&fpr), s(f, "code"));

    for c in cases(&v, "pairingCases") {
        let fpr: [u8; 32] = bytes(c, "fprHex").try_into().unwrap();
        let got = runtime_cert::check_pairing_code(s(c, "input"), &fpr);
        assert_eq!(outcome(&got), s(c, "expect"), "{}", s(c, "name"));
    }
    for c in cases(&v, "urlCases") {
        let got = runtime_cert::canonical_runtime_url(s(c, "input"), c["allowDevHttp"].as_bool().unwrap());
        assert_eq!(outcome(&got), s(c, "expect"), "{}", s(c, "name"));
        if let Ok(url) = got {
            assert_eq!(url, s(c, "canonical"), "{}", s(c, "name"));
        }
    }
    for c in cases(&v, "jwkCases") {
        let got = EcPublicKey::from_jwk(s(c, "jwk"));
        assert_eq!(outcome(&got), s(c, "expect"), "{}", s(c, "name"));
        if let Ok(key) = got {
            assert_eq!(key.to_canonical(), s(c, "canonical"), "{}", s(c, "name"));
        }
    }
}

fn certificate(v: &Value) -> RuntimeCertificate {
    RuntimeCertificate {
        org_id: s(v, "orgId").into(),
        runtime_id: s(v, "runtimeId").into(),
        url: s(v, "url").into(),
        keys: runtime_keys(&v["keys"]),
        admin_id: s(v, "adminId").into(),
        issued_at: u(v, "issuedAt"),
        serial: u(v, "serial"),
    }
}

#[test]
fn certificat_du_runtime() {
    let v = load("runtime-cert.json");
    let admin = EcPublicKey::from_canonical(s(&v, "adminSignKey")).unwrap();
    let cert = certificate(&v["certificate"]);
    assert_eq!(cert.cert_bytes().unwrap(), s(&v, "certBytes"));
    cert.verify(&admin, s(&v, "signature")).unwrap();

    let stored = SignedRuntimeCertificate::from_json(s(&v, "storedJson")).unwrap();
    assert_eq!(stored.certificate, cert);
    stored.certificate.verify(&admin, &stored.signature).unwrap();

    for c in cases(&v, "cases") {
        // Un champ hors contrainte peut ne pas même se lire (clé invalide…) : cert_invalid.
        let got = cert_outcome(&c["certificate"], &admin, s(c, "signature"));
        assert_eq!(got, s(c, "expect"), "{}", s(c, "name"));
    }

    // Forme stockée : champ inconnu ou version inconnue refusés.
    let mut extra: Value = serde_json::from_str(s(&v, "storedJson")).unwrap();
    extra["admin"] = Value::Bool(true);
    assert_eq!(SignedRuntimeCertificate::from_json(&extra.to_string()).unwrap_err(), Error::CertInvalid);
    let mut v2: Value = serde_json::from_str(s(&v, "storedJson")).unwrap();
    v2["v"] = Value::from(2);
    assert_eq!(SignedRuntimeCertificate::from_json(&v2.to_string()).unwrap_err(), Error::CertInvalid);
}

fn cert_outcome(c: &Value, admin: &EcPublicKey, signature: &str) -> &'static str {
    let keys = RuntimePublicKeys::from_parts(
        s(&c["keys"], "sig"),
        EcPublicKey::from_jwk(s(&c["keys"], "kex")).unwrap(),
        EcPublicKey::from_jwk(s(&c["keys"], "csk")).unwrap(),
    )
    .unwrap();
    let cert = RuntimeCertificate {
        org_id: s(c, "orgId").into(),
        runtime_id: s(c, "runtimeId").into(),
        url: s(c, "url").into(),
        keys,
        admin_id: s(c, "adminId").into(),
        issued_at: u(c, "issuedAt"),
        serial: u(c, "serial"),
    };
    outcome(&cert.verify(admin, signature))
}

fn challenge_request(v: &Value) -> ChallengeRequest {
    ChallengeRequest {
        purpose: ChallengePurpose::parse(s(v, "purpose")).unwrap(),
        org_id: s(v, "orgId").into(),
        user_id: s(v, "userId").into(),
        nonce: from_b64u(s(v, "nonce")).unwrap().try_into().unwrap(),
        client_eph: EcPublicKey::from_canonical(s(v, "clientEph")).unwrap(),
    }
}

#[test]
fn defi_de_possession() {
    let v = load("challenge.json");
    let runtime_id = s(&v, "runtimeId");
    let fpr_hex = s(&v, "fprHex");
    let keys = runtime_keys(&v["keys"]);
    let kex = EcdhSecret::from_scalar(&bytes(&v, "kexScalarHex")).unwrap();
    let csk = EcSigningKey::from_scalar(&bytes(&v, "cskScalarHex")).unwrap();
    let client = EcdhSecret::from_scalar(&bytes(&v, "clientEphScalarHex")).unwrap();

    let request = ChallengeRequest::from_json(s(&v, "requestJson")).unwrap();
    assert_eq!(request, challenge_request(&v["request"]));
    assert_eq!(request.client_eph, client.public_key().unwrap());
    let transcript = request.transcript(runtime_id, fpr_hex).unwrap();
    assert_eq!(transcript, s(&v, "transcript"));
    let shared = kex.shared_secret(&request.client_eph);
    assert_eq!(hex(shared.as_ref()), s(&v, "sharedHex"));
    assert_eq!(hex(client.shared_secret(&keys.kex).as_ref()), s(&v, "sharedHex"));
    let kch = hkdf32(shared.as_ref(), runtime_cert::CHALLENGE_LABEL.as_bytes(), transcript.as_bytes()).unwrap();
    assert_eq!(hex(kch.as_ref()), s(&v, "kchHex"));

    // La réponse Rust a le même mac (exact) et une signature que le TS vérifiera (sens Rust → TS).
    let response = runtime_cert::respond_challenge(&request, runtime_id, fpr_hex, &kex, &csk).unwrap();
    assert_eq!(response.mac_b64u(), s(&v, "mac"));
    runtime_cert::verify_challenge_response(&request, runtime_id, fpr_hex, &client, &keys, s(&v, "mac"), s(&v, "sig"))
        .unwrap();

    for c in cases(&v, "cases") {
        let req = challenge_request(&c["request"]);
        let got = runtime_cert::verify_challenge_response(
            &req,
            runtime_id,
            s(c, "fprHex"),
            &client,
            &keys,
            s(c, "mac"),
            s(c, "sig"),
        );
        assert_eq!(outcome(&got), s(c, "expect"), "{}", s(c, "name"));
    }

    for bad in [
        r#"{"v":1}"#,
        &s(&v, "requestJson").replace(r#""v":1"#, r#""v":2"#),
        &s(&v, "requestJson").replace("delegate", "steal"),
        &s(&v, "requestJson").replace(r#""v":1,"#, r#""v":1,"admin":true,"#),
    ] {
        assert_eq!(ChallengeRequest::from_json(bad).unwrap_err(), Error::ChallengeInvalid, "{bad}");
    }
}

/// Lecture d'un contexte de délégation tel qu'il viendrait de l'API : un champ illisible (scope
/// inconnu) rend la délégation inutilisable.
fn delegation_context(v: &Value) -> Result<DelegationContext> {
    Ok(DelegationContext {
        user_id: s(v, "userId").into(),
        org_id: s(v, "orgId").into(),
        runtime_id: s(v, "runtimeId").into(),
        delegation_id: s(v, "delegationId").into(),
        scope: Scope::parse(s(v, "scope")).map_err(|_| Error::DelegationUnusable)?,
        iat: u(v, "iat"),
        exp: u(v, "exp"),
    })
}

#[test]
fn delegation() {
    let v = load("delegation.json");
    let ctx = delegation_context(&v["context"]).unwrap();
    let kex = EcdhSecret::from_scalar(&bytes(&v, "kexScalarHex")).unwrap();
    let kex_pub = EcPublicKey::from_canonical(s(&v, "kex")).unwrap();
    let epk = EcPublicKey::from_canonical(s(&v, "epk")).unwrap();
    assert_eq!(kex.public_key().unwrap(), kex_pub);
    assert_eq!(EcdhSecret::from_scalar(&bytes(&v, "epkScalarHex")).unwrap().public_key().unwrap(), epk);

    // Valeurs exactes.
    let wrap_ctx = ctx.wrap_context(&kex_pub, &epk).unwrap();
    assert_eq!(wrap_ctx, s(&v, "ctx"));
    let shared = kex.shared_secret(&epk);
    assert_eq!(hex(shared.as_ref()), s(&v, "sharedHex"));
    let kek = hkdf32(shared.as_ref(), delegation::WRAP_LABEL.as_bytes(), wrap_ctx.as_bytes()).unwrap();
    assert_eq!(hex(kek.as_ref()), s(&v, "kekHex"));
    let dk = DelegationKey::from_bytes(bytes(&v, "dkHex").try_into().unwrap());
    let mut rng = Fixed(vec![bytes(&v, "epkScalarHex"), bytes(&v, "ivHex")]);
    let wrap = delegation::seal_delegation(&ctx, &kex_pub, &dk, &mut rng).unwrap();
    assert_eq!(wrap, s(&v, "wrap"), "la crate produit exactement l'enveloppe du TS");
    assert_eq!(delegation::wrap_hash(&wrap), s(&v, "wrapHash"));
    assert_eq!(ctx.mandate_bytes(s(&v, "fprHex"), s(&v, "wrapHash")).unwrap(), s(&v, "mandateBytes"));
    assert_eq!(delegation::open_delegation(&ctx, &kex, s(&v, "wrap")).unwrap(), dk);
    let user = EcPublicKey::from_canonical(s(&v, "userSignKey")).unwrap();
    delegation::verify_mandate(&user, &ctx, s(&v, "fprHex"), s(&v, "wrap"), s(&v, "mandateSignature")).unwrap();

    for c in cases(&v, "wrapCases") {
        let got = delegation_context(&c["context"]).and_then(|cc| {
            let k = EcdhSecret::from_scalar(&bytes(c, "kexScalarHex")).unwrap();
            delegation::open_delegation(&cc, &k, s(c, "wrap"))
        });
        assert_eq!(outcome(&got), s(c, "expect"), "{}", s(c, "name"));
        if let Ok(opened) = got {
            assert_eq!(opened, dk, "{}", s(c, "name"));
        }
    }
    for c in cases(&v, "mandateCases") {
        let cc = delegation_context(&c["context"]).unwrap();
        let key = EcPublicKey::from_canonical(s(c, "userSignKey")).unwrap();
        let got = delegation::verify_mandate(&key, &cc, s(c, "fprHex"), s(c, "wrap"), s(c, "signature"));
        assert_eq!(outcome(&got), s(c, "expect"), "{}", s(c, "name"));
    }
    for e in cases(&v, "entries") {
        let kind = EntryKind::parse(s(e, "kind")).unwrap();
        assert_eq!(ctx.entry_aad(kind, s(e, "ref"), u(e, "version")).unwrap(), s(e, "aad"));
        let key = SymmetricKey::from_slice(&bytes(e, "keyHex")).unwrap();
        let mut rng = Fixed(vec![bytes(e, "ivHex")]);
        let sealed = delegation::seal_entry(&dk, &ctx, kind, s(e, "ref"), u(e, "version"), &key, &mut rng).unwrap();
        assert_eq!(sealed, s(e, "ciphertext"), "{}", s(e, "name"));
    }
    for c in cases(&v, "entryCases") {
        let entry_dk = DelegationKey::from_bytes(bytes(c, "dkHex").try_into().unwrap());
        let cc = delegation_context(&c["context"]).unwrap();
        let got =
            delegation::open_entry(&entry_dk, &cc, s(c, "kind"), s(c, "ref"), u(c, "version"), s(c, "ciphertext"));
        assert_eq!(outcome(&got), s(c, "expect"), "{}", s(c, "name"));
    }
}

#[test]
fn champs_de_conversation() {
    let v = load("conversation-fields.json");
    let key_of = |name: &str| {
        let field = match name {
            "ck" => "ckHex",
            "aiSessionKey" => "aiSessionKeyHex",
            "gateway" => "gatewayKeyHex",
            other => panic!("clé inconnue {other}"),
        };
        SymmetricKey::from_slice(&bytes(&v["keys"], field)).unwrap()
    };
    for c in cases(&v, "cases") {
        let key = key_of(s(c, "keyName"));
        let (sid, mid, field, value) = (s(c, "sessionId"), s(c, "messageId"), s(c, "fieldName"), s(c, "value"));
        let got = if s(c, "mode") == "tolerant" {
            session::decrypt_field_if_encrypted(&key, sid, mid, field, value)
        } else {
            session::decrypt_field(&key, sid, mid, field, value)
        };
        assert_eq!(outcome(&got), s(c, "expect"), "{}", s(c, "name"));
        if let Ok(plain) = got {
            assert_eq!(plain, s(c, "plaintext"), "{}", s(c, "name"));
        }
        // Valeurs produites par encryptAiField : la crate les reproduit à l'octet près avec le même IV.
        if s(c, "expect") == "ok" && value.starts_with("gcm1:") && c["forged"].is_null() && session_ids_ok(sid, mid) {
            let iv = bytes(c, "ivHex");
            let reproduced = reencrypt(&key, sid, mid, field, s(c, "plaintext"), iv);
            assert_eq!(reproduced, value, "{}", s(c, "name"));
        }
    }
}

fn session_ids_ok(sid: &str, mid: &str) -> bool {
    synco_e2ee::encoding::is_valid_id(sid) && synco_e2ee::encoding::is_valid_id(mid)
}

/// Rechiffre via l'API typée de la crate (nom de champ reconstruit depuis l'AAD).
fn reencrypt(key: &SymmetricKey, sid: &str, mid: &str, field: &str, plain: &str, iv: Vec<u8>) -> String {
    use session::FieldName;
    let counters = |rest: &str| {
        let (e, q) = rest.split_once(':').unwrap();
        (e.parse::<u64>().unwrap(), q.parse::<u64>().unwrap())
    };
    let name = if let Some(id) = field.strip_prefix("tool_call_arguments:") {
        FieldName::ToolCallArguments(id.into())
    } else if let Some(id) = field.strip_prefix("answer:") {
        FieldName::Answer(id.into())
    } else if let Some(rest) = field.strip_prefix("ws:text:") {
        let (epoch, seq) = counters(rest);
        FieldName::WsText { epoch, seq }
    } else if let Some(rest) = field.strip_prefix("ws:thinking:") {
        let (epoch, seq) = counters(rest);
        FieldName::WsThinking { epoch, seq }
    } else if let Some(rest) = field.strip_prefix("snapshot:") {
        let (epoch, seq) = counters(rest);
        FieldName::Snapshot { epoch, seq }
    } else if let Some(rest) = field.strip_prefix("error:") {
        let (epoch, seq) = counters(rest);
        FieldName::ErrorDetail { epoch, seq }
    } else {
        match field {
            "content" => FieldName::Content,
            "thinking" => FieldName::Thinking,
            "tool_result" => FieldName::ToolResult,
            "pending_tool_call_args" => FieldName::PendingToolCallArgs,
            "title" => FieldName::Title,
            other => panic!("champ inattendu {other}"),
        }
    };
    assert_eq!(name.to_aad_part().unwrap(), field);
    session::encrypt_field(key, sid, mid, &name, plain, &mut Fixed(vec![iv])).unwrap()
}

#[test]
fn enveloppe_rt1() {
    let v = load("rt1-envelope.json");
    let csk = EcPublicKey::from_canonical(s(&v, "csk")).unwrap();
    let raw = bytes(&v, "threadKeyHex");
    let (ctx, version, delegation_id) = (s(&v, "ctx"), u(&v, "version"), s(&v, "delegationId"));
    assert_eq!(keys::key_commitment(&raw, ctx, version), s(&v, "commitment"));
    assert_eq!(keys::rt1_envelope_bytes(ctx, version, s(&v, "commitment"), delegation_id).unwrap(), s(&v, "bytes"));
    assert_eq!(keys::rt1_creator_id(delegation_id).unwrap(), s(&v, "creatorId"));
    assert_eq!(keys::parse_rt1_creator(s(&v, "creatorId")), Some(delegation_id));
    let env = KeyEnvelopeSignature { commitment: s(&v, "commitment").into(), signature: s(&v, "signature").into() };
    keys::verify_rt1_envelope(&csk, &raw, ctx, version, delegation_id, &env).unwrap();

    for c in cases(&v, "cases") {
        let key = EcPublicKey::from_canonical(s(c, "verifyKey")).unwrap();
        let env = KeyEnvelopeSignature { commitment: s(c, "commitment").into(), signature: s(c, "signature").into() };
        let got = keys::verify_rt1_envelope(
            &key,
            &bytes(c, "keyHex"),
            s(c, "ctx"),
            u(c, "version"),
            s(c, "delegationId"),
            &env,
        );
        assert_eq!(outcome(&got), s(c, "expect"), "{}", s(c, "name"));
    }

    // Chaîne de vérification d'un client à jour : le mandat lie la délégation à l'utilisateur.
    let m = &v["mandate"];
    let ctx = delegation_context(&m["context"]).unwrap();
    let user = EcPublicKey::from_canonical(s(m, "userSignKey")).unwrap();
    let other = EcPublicKey::from_canonical(s(m, "otherUserSignKey")).unwrap();
    delegation::verify_mandate_offline_from_wrap_hash(&user, &ctx, s(m, "fprHex"), s(m, "wrapHash"), s(m, "signature"))
        .unwrap();
    assert_eq!(
        delegation::verify_mandate_offline_from_wrap_hash(
            &other,
            &ctx,
            s(m, "fprHex"),
            s(m, "wrapHash"),
            s(m, "signature")
        )
        .unwrap_err(),
        Error::DelegationUnusable
    );
    assert_eq!(s(&v["compat"], "result"), "accepted_unverified");
}

#[test]
fn formats_v4_existants() {
    let v = load("e2ee-v4.json");
    let user_id = s(&v, "userId");
    let device_id = s(&v, "deviceId");

    // Clé d'identité scellée par AK.
    let id = &v["identity"];
    let sealed =
        SealedIdentityKey { ciphertext: s(&id["sealed"], "ciphertext").into(), iv: s(&id["sealed"], "iv").into() };
    for c in cases(id, "cases") {
        let ak = synco_e2ee::account::AccountKey::from_slice(&bytes(c, "akHex")).unwrap();
        let purpose = if s(c, "purpose") == "sign" { IdentityPurpose::Sign } else { IdentityPurpose::Rsa };
        let got = identity::open_identity_key(&ak, purpose, s(c, "userId"), &sealed);
        assert_eq!(outcome(&got), s(c, "expect"), "{}", s(c, "name"));
        if let Ok(pkcs8) = got {
            assert_eq!(hex(&pkcs8), s(id, "pkcs8Hex"));
        }
    }

    // Enveloppe d'appareil (ordre JSON historique).
    let de = &v["deviceEnvelope"];
    let device_secret = EcdhSecret::from_scalar(&bytes(de, "deviceScalarHex")).unwrap();
    assert_eq!(device_secret.public_key().unwrap().to_legacy_json(), s(de, "devicePublic"));
    for c in cases(de, "cases") {
        let secret = EcdhSecret::from_scalar(&bytes(c, "deviceScalarHex")).unwrap();
        let got = device::open_device_envelope(&secret, s(c, "envelope"), s(c, "userId"), s(c, "deviceId"));
        assert_eq!(outcome(&got), s(c, "expect"), "{}", s(c, "name"));
        if let Ok(ak) = got {
            assert_eq!(hex(ak.as_bytes()), s(de, "akHex"));
        }
    }
    #[cfg(feature = "legacy-seal")]
    {
        let ak = synco_e2ee::account::AccountKey::from_slice(&bytes(de, "akHex")).unwrap();
        let mut rng = Fixed(vec![bytes(de, "ephScalarHex"), bytes(de, "ivHex")]);
        let envelope =
            device::seal_device_envelope(&device_secret.public_key().unwrap(), &ak, user_id, device_id, &mut rng)
                .unwrap();
        assert_eq!(envelope, s(de, "envelope"), "la crate produit exactement l'enveloppe du TS");
        let ak_id = synco_e2ee::account::AccountKey::from_slice(&bytes(id, "akHex")).unwrap();
        let iv = synco_e2ee::encoding::from_b64(s(&id["sealed"], "iv")).unwrap();
        let resealed = identity::seal_identity_key(
            &ak_id,
            IdentityPurpose::Sign,
            user_id,
            &bytes(id, "pkcs8Hex"),
            &mut Fixed(vec![iv]),
        )
        .unwrap();
        assert_eq!(resealed, sealed);
    }

    // Certificat d'appareil.
    let dc = &v["deviceCertificate"];
    let device_public = EcPublicKey::from_jwk(s(dc, "devicePublic")).unwrap();
    assert_eq!(device::device_cert_bytes(user_id, device_id, "web", &device_public), s(dc, "certBytes"));
    for c in cases(dc, "cases") {
        let key = EcPublicKey::from_canonical(s(c, "signKey")).unwrap();
        let got = device::verify_device_certificate(
            &key,
            s(c, "certificate"),
            user_id,
            device_id,
            s(c, "platform"),
            &device_public,
        );
        assert_eq!(outcome(&got), s(c, "expect"), "{}", s(c, "name"));
    }

    // Enveloppes FC4.
    for c in cases(&v, "keyEnvelopes") {
        let key = EcPublicKey::from_canonical(s(c, "creatorSignKey")).unwrap();
        let env = KeyEnvelopeSignature { commitment: s(c, "commitment").into(), signature: s(c, "signature").into() };
        let raw = bytes(c, "keyHex");
        if s(c, "expect") == "ok" {
            assert_eq!(keys::key_commitment(&raw, s(c, "ctx"), u(c, "version")), s(c, "commitment"));
        }
        let got = keys::verify_key_envelope(&raw, s(c, "ctx"), u(c, "version"), &env, &key);
        assert_eq!(outcome(&got), s(c, "expect"), "{}", s(c, "name"));
    }

    // Chaîne de transitions d'identité.
    let chain: Vec<IdentityTransition> = cases(&v["identityChain"], "chain")
        .iter()
        .map(|t| IdentityTransition {
            seq: u(t, "seq"),
            old_public_sign_key: s(t, "oldPublicSignKey").into(),
            new_public_key: s(t, "newPublicKey").into(),
            new_public_sign_key: s(t, "newPublicSignKey").into(),
            signature: s(t, "signature").into(),
        })
        .collect();
    for p in cases(&v["identityChain"], "paths") {
        let path = identity::identity_chain_path(s(p, "userId"), s(p, "pinned"), &chain).unwrap();
        let expected = p["path"].as_array().unwrap();
        assert_eq!(path.len(), expected.len(), "{}", s(p, "name"));
        for (got, want) in path.iter().zip(expected) {
            assert_eq!(got.public_key, s(want, "publicKey"), "{}", s(p, "name"));
            assert_eq!(got.public_sign_key, s(want, "publicSignKey"), "{}", s(p, "name"));
        }
    }
}

#[test]
fn coherence_sha256_b64u() {
    // Garde-fou des encodages utilisés par wrapHash.
    assert_eq!(b64u(&sha256(b"")), "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
}
