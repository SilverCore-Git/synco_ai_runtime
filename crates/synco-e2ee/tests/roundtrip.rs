//! Allers-retours et refus de chaque format, sans vecteurs externes.
#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "tests : les fonctions utilitaires échouent bruyamment"
)]

use synco_e2ee::delegation::{self, DelegationContext, DelegationKey, EntryKind, Scope};
use synco_e2ee::ec::{EcPublicKey, EcSigningKey, EcdhSecret};
use synco_e2ee::identity::{self, IdentityTransition};
use synco_e2ee::keys;
use synco_e2ee::runtime_cert::{self, ChallengePurpose, ChallengeRequest, RuntimeCertificate, RuntimePublicKeys};
use synco_e2ee::session::{self, FieldName};
use synco_e2ee::{Error, OsRandom, SymmetricKey, device};

fn ctx() -> DelegationContext {
    DelegationContext {
        user_id: "66666666-7777-4888-9999-aaaaaaaaaaaa".into(),
        org_id: "cm3orgexample0000000000001".into(),
        runtime_id: "7d3f2c1e-8a4b-4c6d-9e0f-1a2b3c4d5e6f".into(),
        delegation_id: "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d".into(),
        scope: Scope::Org,
        iat: 1_795_000_000,
        exp: 1_795_604_800,
    }
}

fn runtime_keys() -> (EcdhSecret, EcSigningKey, RuntimePublicKeys) {
    let kex = EcdhSecret::from_scalar(&[0x22; 32]).unwrap();
    let csk = EcSigningKey::from_scalar(&[0x33; 32]).unwrap();
    let keys = RuntimePublicKeys::new([0x44; 32], kex.public_key().unwrap(), csk.public_key().unwrap());
    (kex, csk, keys)
}

#[test]
fn secrets_jamais_affiches() {
    let rendered = format!(
        "{:?} {:?} {:?} {:?} {:?}",
        SymmetricKey::from_bytes([0xab; 32]),
        DelegationKey::from_bytes([0xab; 32]),
        synco_e2ee::account::AccountKey::from_bytes([0xab; 32]),
        EcdhSecret::from_scalar(&[0x22; 32]).unwrap(),
        EcSigningKey::from_scalar(&[0x33; 32]).unwrap(),
    );
    assert!(!rendered.contains("ab"), "{rendered}");
    assert!(!rendered.contains("171"), "{rendered}");
    assert!(rendered.contains("***"));
}

#[test]
fn scalaires_invalides_refuses() {
    assert_eq!(EcdhSecret::from_scalar(&[0; 32]).unwrap_err(), Error::InvalidKey);
    assert_eq!(EcSigningKey::from_scalar(&[0xff; 32]).unwrap_err(), Error::InvalidKey, "≥ ordre de la courbe");
    assert_eq!(EcSigningKey::from_scalar(&[1; 31]).unwrap_err(), Error::InvalidKey);
}

#[test]
fn jwk_canonique_et_historique() {
    let key = EcdhSecret::from_scalar(&[0x22; 32]).unwrap().public_key().unwrap();
    let canon = key.to_canonical();
    assert!(canon.starts_with(r#"{"crv":"P-256","kty":"EC","x":""#));
    assert!(key.to_legacy_json().starts_with(r#"{"kty":"EC","crv":"P-256","x":""#));
    assert_eq!(EcPublicKey::from_canonical(&canon).unwrap(), key);
    assert_eq!(EcPublicKey::from_canonical(&key.to_legacy_json()).unwrap_err(), Error::InvalidKey);
    assert_eq!(EcPublicKey::from_jwk(&key.to_legacy_json()).unwrap(), key);
}

#[test]
fn signature_der_ou_alteree_refusee() {
    let sk = EcSigningKey::from_scalar(&[0x55; 32]).unwrap();
    let pk = sk.public_key().unwrap();
    let mut sig = sk.sign(b"message");
    assert!(pk.verify(b"message", &sig));
    assert!(!pk.verify(b"messagE", &sig));
    assert!(!pk.verify(b"message", &sig[..63]));
    if let Some(b) = sig.get_mut(10) {
        *b ^= 1;
    }
    assert!(!pk.verify(b"message", &sig));
}

#[test]
fn delegation_aller_retour_et_refus() {
    let mut rng = OsRandom;
    let (kex, csk, keys) = runtime_keys();
    let user = EcSigningKey::from_scalar(&[0x55; 32]).unwrap();
    let fpr_hex = runtime_cert::fingerprint_hex(&ctx().runtime_id, &keys).unwrap();
    let dk = DelegationKey::generate(&mut rng).unwrap();
    let c = ctx();
    let wrap = delegation::seal_delegation(&c, &keys.kex, &dk, &mut rng).unwrap();
    assert_eq!(delegation::open_delegation(&c, &kex, &wrap).unwrap(), dk);

    // Mandat.
    let sig = delegation::sign_mandate(&user, &c, &fpr_hex, &wrap).unwrap();
    let wrap_hash = delegation::wrap_hash(&wrap);
    delegation::verify_mandate(&user.public_key().unwrap(), &c, &fpr_hex, &wrap_hash, &sig).unwrap();
    let other_user = EcSigningKey::from_scalar(&[0x56; 32]).unwrap().public_key().unwrap();
    assert_eq!(
        delegation::verify_mandate(&other_user, &c, &fpr_hex, &wrap_hash, &sig).unwrap_err(),
        Error::DelegationUnusable
    );

    // Autre runtime, champ modifié, enveloppe tronquée : refus propres.
    let other_kex = EcdhSecret::from_scalar(&[0x23; 32]).unwrap();
    assert_eq!(delegation::open_delegation(&c, &other_kex, &wrap).unwrap_err(), Error::DelegationUnusable);
    let mut later = c.clone();
    later.exp = later.exp.saturating_add(1);
    assert_eq!(delegation::open_delegation(&later, &kex, &wrap).unwrap_err(), Error::DelegationUnusable);
    for cut in [0, 5, 10, wrap.len().saturating_sub(1)] {
        let truncated = wrap.get(..cut).unwrap();
        assert_eq!(delegation::open_delegation(&c, &kex, truncated).unwrap_err(), Error::DelegationUnusable);
    }
    let _ = csk;

    // Entrées.
    let thread_key = SymmetricKey::generate(&mut rng).unwrap();
    let entry = delegation::seal_entry(&dk, &c, EntryKind::Thread, "cm3thread", 1, &thread_key, &mut rng).unwrap();
    assert_eq!(delegation::open_entry(&dk, &c, "thread", "cm3thread", 1, &entry).unwrap(), thread_key);
    for (kind, reference, version) in [("space", "cm3thread", 1), ("thread", "cm3other", 1), ("thread", "cm3thread", 2)]
    {
        assert_eq!(
            delegation::open_entry(&dk, &c, kind, reference, version, &entry).unwrap_err(),
            Error::EntryUnusable
        );
    }
    for kind in ["dm", "support", "ai", "org", "account", "identity", ""] {
        assert_eq!(delegation::open_entry(&dk, &c, kind, "cm3thread", 1, &entry).unwrap_err(), Error::EntryUnusable);
    }
    let other_dk = DelegationKey::generate(&mut rng).unwrap();
    assert_eq!(
        delegation::open_entry(&other_dk, &c, "thread", "cm3thread", 1, &entry).unwrap_err(),
        Error::EntryUnusable
    );
}

#[test]
fn delegation_horloge() {
    let c = ctx();
    let week = 7 * 86_400;
    c.check_time(c.iat, week).unwrap();
    c.check_time(c.iat - 300, week).unwrap();
    assert_eq!(c.check_time(c.iat - 301, week).unwrap_err(), Error::DelegationUnusable);
    assert_eq!(c.check_time(c.exp, week).unwrap_err(), Error::DelegationUnusable);
    assert_eq!(c.check_time(c.iat, week - 1).unwrap_err(), Error::DelegationUnusable);
}

#[test]
fn contexte_de_delegation_valide() {
    let mut c = ctx();
    c.user_id = "a|b".into();
    assert_eq!(c.validate().unwrap_err(), Error::InvalidInput);
    let mut c = ctx();
    c.exp = c.iat;
    assert_eq!(c.validate().unwrap_err(), Error::InvalidInput);
    let mut c = ctx();
    c.exp = 1 << 53;
    assert_eq!(c.validate().unwrap_err(), Error::InvalidInput);
    assert_eq!(Scope::parse("all").unwrap_err(), Error::InvalidInput);
}

#[test]
fn champs_de_conversation() {
    let mut rng = OsRandom;
    let ck = SymmetricKey::generate(&mut rng).unwrap();
    let field = FieldName::WsText { epoch: 2, seq: 42 };
    let wire = session::encrypt_field(&ck, "s1", "m1", &field, "Bonjour", &mut rng).unwrap();
    assert_eq!(session::decrypt_field(&ck, "s1", "m1", "ws:text:2:42", &wire).unwrap(), "Bonjour");
    assert_eq!(
        session::decrypt_field(&ck, "s1", "m1", "ws:text:2:43", &wire).unwrap_err(),
        Error::FieldAuthenticationFailed
    );
    assert_eq!(session::decrypt_field(&ck, "s1", "m1", "x", "en clair").unwrap_err(), Error::FieldUnknownVersion);
    assert_eq!(session::decrypt_field_if_encrypted(&ck, "s1", "m1", "x", "en clair").unwrap(), "en clair");
    assert_eq!(
        session::encrypt_field(&ck, "s:1", "m1", &FieldName::Content, "x", &mut rng).unwrap_err(),
        Error::InvalidInput
    );
    assert_eq!(
        session::encrypt_field(&ck, "s1", "m1", &FieldName::Answer("a|b".into()), "x", &mut rng).unwrap_err(),
        Error::InvalidInput
    );
    let json = serde_json::json!({ "ok": true });
    let wire = session::encrypt_json_field(&ck, "s1", "m1", &FieldName::ToolResult, &json, &mut rng).unwrap();
    assert_eq!(session::decrypt_json_field(&ck, "s1", "m1", "tool_result", &wire).unwrap(), json);
}

#[test]
fn enveloppes_fc4_et_rt1() {
    let creator = EcSigningKey::from_scalar(&[0x55; 32]).unwrap();
    let raw = [0xbb; 32];
    let env = keys::sign_key_envelope(&creator, &raw, "thread:t1", 1);
    keys::verify_key_envelope(&raw, "thread:t1", 1, &env, &creator.public_key().unwrap()).unwrap();
    assert_eq!(
        keys::verify_key_envelope(&[0xbc; 32], "thread:t1", 1, &env, &creator.public_key().unwrap()).unwrap_err(),
        Error::KeyCommitmentMismatch
    );

    let (_, csk, keys_pub) = runtime_keys();
    let rt = keys::sign_rt1_envelope(&csk, &raw, "thread:t1", 1, "d1").unwrap();
    keys::verify_rt1_envelope(&keys_pub.csk, &raw, "thread:t1", 1, "d1", &rt).unwrap();
    assert_eq!(
        keys::verify_rt1_envelope(&keys_pub.csk, &raw, "thread:t1", 1, "d2", &rt).unwrap_err(),
        Error::KeyBadSignature
    );
    assert_eq!(keys::sign_rt1_envelope(&csk, &raw, "dm:t1", 1, "d1").unwrap_err(), Error::InvalidInput);
    assert_eq!(keys::rt1_creator_id("d1").unwrap(), "rt1:d1");
    assert_eq!(keys::parse_rt1_creator("rt1:d1"), Some("d1"));
    assert_eq!(keys::parse_rt1_creator("user-1"), None);
}

#[test]
fn appareil_et_identite() {
    let device = EcdhSecret::from_scalar(&[0x12; 32]).unwrap();
    let id_key = EcSigningKey::from_scalar(&[0x13; 32]).unwrap();
    let cert = device::sign_device_certificate(&id_key, "u1", "d1", "web", &device.public_key().unwrap());
    device::verify_device_certificate(
        &id_key.public_key().unwrap(),
        &cert,
        "u1",
        "d1",
        "web",
        &device.public_key().unwrap(),
    )
    .unwrap();
    assert_eq!(
        device::verify_device_certificate(
            &id_key.public_key().unwrap(),
            &cert,
            "u1",
            "d1",
            "ios",
            &device.public_key().unwrap()
        )
        .unwrap_err(),
        Error::BadSignature
    );
    assert_eq!(
        device::open_device_envelope(&device, "pas.une.enveloppe", "u1", "d1").unwrap_err(),
        Error::EnvelopeUnusable
    );

    // Chaîne de transitions : A → B, puis un maillon C signé par une clé étrangère est ignoré.
    let a = EcSigningKey::from_scalar(&[0x21; 32]).unwrap();
    let b = EcSigningKey::from_scalar(&[0x31; 32]).unwrap();
    let mallory = EcSigningKey::from_scalar(&[0x41; 32]).unwrap();
    let rsa = r#"{"kty":"RSA","n":"AQAB","e":"AQAB","alg":"RSA-OAEP-256"}"#;
    let t1 = identity::sign_identity_transition(&a, "u1", 1, rsa, &b.public_key().unwrap().to_legacy_json()).unwrap();
    let forged = IdentityTransition {
        old_public_sign_key: b.public_key().unwrap().to_canonical(),
        ..identity::sign_identity_transition(&mallory, "u1", 2, rsa, &mallory.public_key().unwrap().to_canonical())
            .unwrap()
    };
    let path = identity::identity_chain_path("u1", &a.public_key().unwrap().to_legacy_json(), &[forged, t1]).unwrap();
    assert_eq!(path.len(), 1);
    assert_eq!(path.first().unwrap().public_sign_key, b.public_key().unwrap().to_canonical());
    assert_eq!(path.first().unwrap().public_key, r#"{"e":"AQAB","kty":"RSA","n":"AQAB"}"#);
}

#[test]
fn certificat_et_defi() {
    let (kex, csk, keys) = runtime_keys();
    let admin = EcSigningKey::from_scalar(&[0x44; 32]).unwrap();
    let cert = RuntimeCertificate {
        org_id: "org1".into(),
        runtime_id: "rt1".into(),
        url: "https://runtime.example.com".into(),
        keys: keys.clone(),
        admin_id: "admin1".into(),
        issued_at: 1_795_000_000,
        serial: 1,
    };
    let sig = cert.sign(&admin).unwrap();
    cert.verify(&admin.public_key().unwrap(), &sig).unwrap();
    let mut other = cert.clone();
    other.serial = 2;
    assert_eq!(other.verify(&admin.public_key().unwrap(), &sig).unwrap_err(), Error::CertBadSignature);
    let mut bad = cert.clone();
    bad.url = "https://Runtime.example.com/".into();
    assert_eq!(bad.verify(&admin.public_key().unwrap(), &sig).unwrap_err(), Error::CertInvalid);

    let client = EcdhSecret::from_scalar(&[0x66; 32]).unwrap();
    let request = ChallengeRequest {
        purpose: ChallengePurpose::Delegate,
        org_id: "org1".into(),
        user_id: "user1".into(),
        nonce: [0x77; 32],
        client_eph: client.public_key().unwrap(),
    };
    let fpr = cert.fingerprint_hex().unwrap();
    let resp = runtime_cert::respond_challenge(&request, "rt1", &fpr, &kex, &csk).unwrap();
    runtime_cert::verify_challenge_response(&request, "rt1", &fpr, &client, &keys, &resp.mac_b64u(), &resp.sig_b64u())
        .unwrap();
    let mut pair = request.clone();
    pair.purpose = ChallengePurpose::Pair;
    assert_eq!(
        runtime_cert::verify_challenge_response(&pair, "rt1", &fpr, &client, &keys, &resp.mac_b64u(), &resp.sig_b64u())
            .unwrap_err(),
        Error::ChallengeFailed
    );
}

#[test]
fn code_d_appairage() {
    let fpr = [0x5a; 32];
    let code = runtime_cert::pairing_code(&fpr);
    assert_eq!(code.len(), 34);
    runtime_cert::check_pairing_code(&code, &fpr).unwrap();
    runtime_cert::check_pairing_code(&code.to_lowercase().replace('-', " "), &fpr).unwrap();
    assert_eq!(runtime_cert::check_pairing_code(&code, &[0x5b; 32]).unwrap_err(), Error::PairCodeMismatch);
    assert_eq!(runtime_cert::parse_pairing_code("ABCD").unwrap_err(), Error::PairCodeInvalid);
    assert_eq!(
        runtime_cert::parse_pairing_code("ÉÉÉÉ-ÉÉÉÉ-ÉÉÉÉ-ÉÉÉÉ-ÉÉÉÉ-ÉÉÉÉ-ÉÉÉÉ").unwrap_err(),
        Error::PairCodeInvalid
    );
}
