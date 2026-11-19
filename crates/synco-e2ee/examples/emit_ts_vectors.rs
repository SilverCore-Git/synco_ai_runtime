//! Vecteurs Rust → TS (docs/plan/vectors/README.md §1) : la crate produit des valeurs que les tests
//! de synco_app ouvrent ou vérifient (`scripts/e2ee-vectors/from-rust.test.ts`).
//!
//! ```text
//! cargo run -q -p synco-e2ee --example emit_ts_vectors --features legacy-seal \
//!   > <synco_app>/scripts/e2ee-vectors/from-rust.json
//! ```
//!
//! Sortie entièrement déterministe : aléa figé (vecteurs uniquement) et ECDSA RFC 6979.

use std::io::Write as _;

use serde_json::{Value, json};
use synco_e2ee::account::AccountKey;
use synco_e2ee::delegation::{self, DelegationContext, DelegationKey, EntryKind, Scope};
use synco_e2ee::device;
use synco_e2ee::ec::{EcSigningKey, EcdhSecret};
use synco_e2ee::encoding::{b64u, hex};
use synco_e2ee::identity::{self, IdentityPurpose};
use synco_e2ee::keys;
use synco_e2ee::runtime_cert::{
    self, ChallengePurpose, ChallengeRequest, RuntimeCertificate, RuntimePublicKeys, UrlPolicy,
};
use synco_e2ee::session::{self, FieldName};
use synco_e2ee::{Error, RandomSource, SymmetricKey};

/// Aléa figé : chaque appel rend le prochain bloc (longueur exacte).
struct Fixed(Vec<Vec<u8>>);

impl RandomSource for Fixed {
    fn fill(&mut self, dest: &mut [u8]) -> synco_e2ee::Result<()> {
        if self.0.is_empty() {
            return Err(Error::RandomUnavailable);
        }
        let next = self.0.remove(0);
        if next.len() != dest.len() {
            return Err(Error::RandomUnavailable);
        }
        dest.copy_from_slice(&next);
        Ok(())
    }
}

fn fill(byte: u8, n: usize) -> Vec<u8> {
    vec![byte; n]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime_id = "5e4d3c2b-1a09-4f8e-9d7c-6b5a49382716";
    let org_id = "cm3orgrust000000000000001";
    let user_id = "77777777-8888-4999-aaaa-bbbbbbbbbbbb";
    let admin_id = "22222222-3333-4444-8555-666666666666";

    // Runtime.
    let kex = EcdhSecret::from_scalar(&fill(0x24, 32))?;
    let csk = EcSigningKey::from_scalar(&fill(0x35, 32))?;
    let keys = RuntimePublicKeys::new([0x45; 32], kex.public_key()?, csk.public_key()?);
    let fpr = runtime_cert::fingerprint(runtime_id, &keys)?;
    let fpr_hex = hex(&fpr);
    let keys_json = json!({ "sig": keys.sig_b64u(), "kex": keys.kex.to_canonical(), "csk": keys.csk.to_canonical() });

    // Certificat.
    let admin = EcSigningKey::from_scalar(&fill(0x46, 32))?;
    let cert = RuntimeCertificate {
        org_id: org_id.into(),
        runtime_id: runtime_id.into(),
        url: runtime_cert::canonical_runtime_url("HTTPS://Rust-Runtime.Example.com:443/synco/", false)?,
        keys: keys.clone(),
        admin_id: admin_id.into(),
        issued_at: 1_795_100_000,
        serial: 3,
    };
    let cert_sig = cert.sign(&admin, UrlPolicy::Production)?;

    // Défi : le TS vérifie la réponse avec la clé éphémère du client.
    let client = EcdhSecret::from_scalar(&fill(0x67, 32))?;
    let request = ChallengeRequest {
        purpose: ChallengePurpose::Pair,
        org_id: org_id.into(),
        user_id: admin_id.into(),
        nonce: [0x79; 32],
        client_eph: client.public_key()?,
    };
    let response = runtime_cert::respond_challenge(&request, runtime_id, &fpr_hex, &kex, &csk)?;

    // Délégation complète.
    let user = EcSigningKey::from_scalar(&fill(0x57, 32))?;
    let ctx = DelegationContext {
        user_id: user_id.into(),
        org_id: org_id.into(),
        runtime_id: runtime_id.into(),
        delegation_id: "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e".into(),
        scope: Scope::Org,
        iat: 1_795_100_000,
        exp: 1_795_100_000 + 3 * 86_400,
    };
    let dk = DelegationKey::from_bytes([0x89; 32]);
    let wrap = delegation::seal_delegation(&ctx, &keys.kex, &dk, &mut Fixed(vec![fill(0x9a, 32), fill(0xab, 12)]))?;
    let mandate_signature = delegation::sign_mandate(&user, &ctx, &fpr_hex, &wrap)?;
    let mut entries = Vec::new();
    for (kind, reference, version, key_byte, iv_byte) in [
        (EntryKind::Thread, "cm3threadrust000000000001", 1, 0xb1, 0xc1),
        (EntryKind::Space, "cm3spacerust0000000000001", 2, 0xb2, 0xc2),
        (EntryKind::Conv, "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", 1, 0xb3, 0xc3),
    ] {
        let key = SymmetricKey::from_bytes([key_byte; 32]);
        let ciphertext =
            delegation::seal_entry(&dk, &ctx, kind, reference, version, &key, &mut Fixed(vec![fill(iv_byte, 12)]))?;
        entries.push(json!({ "kind": kind.as_str(), "ref": reference, "version": version, "keyHex": hex(key.as_bytes()), "ciphertext": ciphertext }));
    }

    // Champs gcm1 sous CK.
    let ck = SymmetricKey::from_bytes([0xde; 32]);
    let session_id = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
    let message_id = "6f5e4d3c-2b1a-4098-8f7e-6d5c4b3a2918";
    let mut fields = Vec::new();
    let defs: [(&str, FieldName, &str); 6] = [
        (message_id, FieldName::Content, "Réponse écrite par le runtime ✓"),
        (message_id, FieldName::ToolCallArguments("call_7".into()), r#"{"title":"Créer"}"#),
        (message_id, FieldName::WsText { epoch: 4, seq: 9 }, "Bon"),
        (
            session::SNAPSHOT_MESSAGE_ID,
            FieldName::Snapshot { epoch: 4, seq: 10 },
            r#"{"messages":[],"status":"idle","pendingToolCall":null}"#,
        ),
        (session::SESSION_TITLE_MESSAGE_ID, FieldName::Title, "Titre chiffré"),
        (session::ANSWER_MESSAGE_ID, FieldName::Answer("call_8".into()), "Oui"),
    ];
    for (i, (mid, field, plain)) in defs.into_iter().enumerate() {
        let iv = fill(u8::try_from(i)?.wrapping_add(0x50), 12);
        let value = session::encrypt_field(&ck, session_id, mid, &field, plain, &mut Fixed(vec![iv]))?;
        fields.push(json!({ "messageId": mid, "fieldName": field.to_aad_part()?, "plaintext": plain, "value": value }));
    }

    // Enveloppe rt1.
    let created = [0xb0; 32];
    let rt1 = keys::sign_rt1_envelope(&csk, &created, "thread:cm3threadrust000000000009", 1, &ctx.delegation_id)?;

    // Formats v4 existants.
    let v4_user = "user-v4-rust000000000001";
    let device_id = "9c8b7a6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";
    let device_secret = EcdhSecret::from_scalar(&fill(0x64, 32))?;
    let ak = AccountKey::from_bytes([0x43; 32]);
    let envelope = device::seal_device_envelope(
        &device_secret.public_key()?,
        &ak,
        v4_user,
        device_id,
        &mut Fixed(vec![fill(0x65, 32), fill(0x33, 12)]),
    )?;
    let identity_payload = fill(0x30, 48);
    let sealed = identity::seal_identity_key(
        &ak,
        IdentityPurpose::Rsa,
        v4_user,
        &identity_payload,
        &mut Fixed(vec![fill(0x34, 12)]),
    )?;
    let id_sign = EcSigningKey::from_scalar(&fill(0x58, 32))?;
    let device_cert =
        device::sign_device_certificate(&id_sign, v4_user, device_id, "android", &device_secret.public_key()?);
    let key_env = keys::sign_key_envelope(&id_sign, &[0xb4; 32], "space:cm3spacerust0000000000001", 2);
    let next_sign = EcSigningKey::from_scalar(&fill(0x59, 32))?;
    let transition = identity::sign_identity_transition(
        &id_sign,
        v4_user,
        1,
        r#"{"kty":"RSA","n":"bnJ1c3Q","e":"AQAB"}"#,
        &next_sign.public_key()?.to_legacy_json(),
    )?;

    let out: Value = json!({
        "description": "Valeurs produites par la crate synco-e2ee (examples/emit_ts_vectors.rs), ouvertes ou vérifiées par le code TS de l'app.",
        "runtime": {
            "runtimeId": runtime_id, "keys": keys_json, "kexScalarHex": hex(&fill(0x24, 32)),
            "fprHex": fpr_hex, "display": runtime_cert::display_fingerprint(&fpr_hex)?, "code": runtime_cert::pairing_code(&fpr),
        },
        "certificate": {
            "adminSignKey": admin.public_key()?.to_canonical(),
            "certificate": { "orgId": cert.org_id, "runtimeId": cert.runtime_id, "url": cert.url, "keys": keys_json, "adminId": cert.admin_id, "issuedAt": cert.issued_at, "serial": cert.serial },
            "certBytes": cert.cert_bytes(UrlPolicy::Production)?, "signature": cert_sig,
        },
        "challenge": {
            "clientEphScalarHex": hex(&fill(0x67, 32)),
            "request": { "purpose": request.purpose.as_str(), "orgId": request.org_id, "userId": request.user_id, "nonce": b64u(&request.nonce), "clientEph": request.client_eph.to_canonical() },
            "transcript": request.transcript(runtime_id, &fpr_hex)?, "mac": response.mac_b64u(), "sig": response.sig_b64u(),
        },
        "delegation": {
            "context": { "userId": ctx.user_id, "orgId": ctx.org_id, "runtimeId": ctx.runtime_id, "delegationId": ctx.delegation_id, "scope": ctx.scope.as_str(), "iat": ctx.iat, "exp": ctx.exp },
            "dkHex": hex(dk.as_bytes()), "userSignKey": user.public_key()?.to_canonical(),
            "wrap": wrap, "wrapHash": delegation::wrap_hash(&wrap), "mandateSignature": mandate_signature, "entries": entries,
        },
        "fields": { "ckHex": hex(ck.as_bytes()), "sessionId": session_id, "cases": fields },
        "rt1": {
            "ctx": "thread:cm3threadrust000000000009", "version": 1, "keyHex": hex(&created),
            "delegationId": ctx.delegation_id, "commitment": rt1.commitment, "signature": rt1.signature,
        },
        "v4": {
            "userId": v4_user, "deviceId": device_id,
            "deviceScalarHex": hex(&fill(0x64, 32)), "devicePublic": device_secret.public_key()?.to_legacy_json(),
            "akHex": hex(ak.as_bytes()), "deviceEnvelope": envelope,
            "identity": { "purpose": "rsa", "payloadHex": hex(&identity_payload), "ciphertext": sealed.ciphertext, "iv": sealed.iv },
            "identitySignKey": id_sign.public_key()?.to_canonical(),
            "deviceCertificate": { "platform": "android", "certificate": device_cert },
            "keyEnvelope": { "ctx": "space:cm3spacerust0000000000001", "version": 2, "keyHex": hex(&[0xb4; 32]), "commitment": key_env.commitment, "signature": key_env.signature },
            "transition": { "seq": transition.seq, "oldPublicSignKey": transition.old_public_sign_key, "newPublicKey": transition.new_public_key, "newPublicSignKey": transition.new_public_sign_key, "signature": transition.signature },
        },
    });
    writeln!(std::io::stdout().lock(), "{}", serde_json::to_string_pretty(&out)?)?;
    Ok(())
}
