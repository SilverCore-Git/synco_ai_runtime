//! Vecteurs figés par la spécification (L00f) : `docs/plan/vectors/mandate-v2.json`, rejoués sans
//! modification (03 §4.1, 12 §10.2).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests : un vecteur illisible doit échouer bruyamment"
)]

use serde_json::Value;
use synco_e2ee::delegation::{
    self, DelegationContext, MandateMode, MandateVersion, Rt1Verdict, Scope, ServedMandate, VerifiedMandate,
};
use synco_e2ee::ec::{EcPublicKey, EcSigningKey};
use synco_e2ee::encoding::from_hex;

fn load() -> Value {
    let path = format!("{}/../../docs/plan/vectors/mandate-v2.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("champ {key} absent"))
}

fn context(v: &Value) -> DelegationContext {
    DelegationContext {
        user_id: s(v, "userId").to_owned(),
        org_id: s(v, "orgId").to_owned(),
        runtime_id: s(v, "runtimeId").to_owned(),
        delegation_id: s(v, "delegationId").to_owned(),
        scope: Scope::parse(s(v, "scope")).unwrap(),
        iat: v["iat"].as_u64().unwrap(),
        exp: v["exp"].as_u64().unwrap(),
    }
}

fn served(c: &Value) -> ServedMandate<'_> {
    ServedMandate {
        version: c.get("mandateVersion").map(|v| v.as_u64().unwrap()),
        mode: c.get("mode").and_then(Value::as_str),
        owner_rsa_spki_hex: c.get("ownerRsaSpkiHex").and_then(Value::as_str),
    }
}

#[test]
fn octets_et_signatures_v2() {
    let v = load();
    let ctx = context(&v["context"]);
    let (fpr, hash, owner) = (s(&v, "fprHex"), s(&v, "wrapHash"), s(&v["keys"], "ownerRsaSpkiHex"));
    assert_eq!(delegation::wrap_hash(s(&v, "wrap")), hash);
    assert_eq!(delegation::owner_rsa_spki_hex(&from_hex(s(&v["keys"], "ownerRsaSpkiDerHex")).unwrap()), owner);
    assert_eq!(
        delegation::owner_rsa_spki_hex(&from_hex(s(&v["keys"], "otherRsaSpkiDerHex")).unwrap()),
        s(&v["keys"], "otherRsaSpkiHex")
    );
    assert_eq!(ctx.mandate_bytes_v2(fpr, hash, owner, MandateMode::Plan).unwrap(), s(&v, "mandateBytesPlan"));
    assert_eq!(ctx.mandate_bytes_v2(fpr, hash, owner, MandateMode::Auto).unwrap(), s(&v, "mandateBytesAuto"));
    assert_eq!(ctx.mandate_bytes(fpr, hash).unwrap(), s(&v, "mandateBytesV1"));
    // La crate signe en RFC 6979 : elle retrouve les signatures à l'octet près.
    let key = EcSigningKey::from_scalar(&from_hex(s(&v["keys"], "userSignScalarHex")).unwrap()).unwrap();
    assert_eq!(key.public_key().unwrap().to_canonical(), s(&v, "userSignKey"));
    let wrap = s(&v, "wrap");
    assert_eq!(
        delegation::sign_mandate_v2(&key, &ctx, fpr, wrap, owner, MandateMode::Plan).unwrap(),
        s(&v, "signaturePlan")
    );
    assert_eq!(
        delegation::sign_mandate_v2(&key, &ctx, fpr, wrap, owner, MandateMode::Auto).unwrap(),
        s(&v, "signatureAuto")
    );
    // Empreinte RSA mal formée : refusée avant toute signature.
    assert!(ctx.mandate_bytes_v2(fpr, hash, &owner.to_uppercase(), MandateMode::Auto).is_err());
}

#[test]
fn cas_de_mandat() {
    let v = load();
    let cases = v["mandateCases"].as_array().unwrap();
    assert_eq!(cases.len(), 21);
    for c in cases {
        let name = s(c, "name");
        let ctx = context(&c["context"]);
        let key = EcPublicKey::from_canonical(s(c, "userSignKey")).unwrap();
        let r = delegation::verify_mandate_versioned_offline_from_wrap_hash(
            &key,
            &ctx,
            s(c, "fprHex"),
            s(c, "wrapHash"),
            s(c, "signature"),
            &served(c),
        );
        match s(c, "expect") {
            "ok" => {
                let m = r.unwrap_or_else(|e| panic!("{name} : {e}"));
                assert_eq!(m.mode.as_str(), s(c, "expectMode"), "{name}");
                match m.version {
                    MandateVersion::V2 => assert_eq!(m.owner_rsa_spki_hex.as_deref(), Some(s(c, "ownerRsaSpkiHex"))),
                    MandateVersion::V1 => assert_eq!(m.owner_rsa_spki_hex, None, "{name}"),
                }
            }
            code => assert_eq!(r.map(|_| ()).unwrap_err().code(), code, "{name}"),
        }
    }
}

#[test]
fn politique_rt1() {
    let v = load();
    let cases = v["rt1Policy"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    for c in cases {
        let mandate = if c.get("mandateUnusable").and_then(Value::as_bool) == Some(true) {
            None
        } else {
            let version = match c["mandateVersion"].as_u64().unwrap() {
                1 => MandateVersion::V1,
                _ => MandateVersion::V2,
            };
            let mode = match version {
                MandateVersion::V1 => MandateMode::Plan,
                MandateVersion::V2 => MandateMode::parse(s(c, "mode")).unwrap(),
            };
            Some(VerifiedMandate { version, mode, owner_rsa_spki_hex: None })
        };
        let verdict: Rt1Verdict = delegation::rt1_verdict(mandate.as_ref(), c["envelopeValid"].as_bool().unwrap());
        assert_eq!(verdict.as_str(), s(c, "expect"), "{}", s(c, "name"));
    }
}

/// Chemin du runtime (03 §4 étapes 1 à 3 puis §3) avec un mandat v1 ou v2 : la clé `kex` et `DK`
/// viennent de `tests/vectors/delegation.json`, d'où sont repris le contexte et `wrap`.
#[test]
fn acceptation_par_le_runtime() {
    let v = load();
    let path = format!("{}/tests/vectors/delegation.json", env!("CARGO_MANIFEST_DIR"));
    let d: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(s(&d, "wrap"), s(&v, "wrap"));
    let kex = synco_e2ee::ec::EcdhSecret::from_scalar(&from_hex(s(&d, "kexScalarHex")).unwrap()).unwrap();
    let ctx = context(&v["context"]);
    let me = delegation::RuntimeSelf {
        runtime_id: &ctx.runtime_id,
        org_id: &ctx.org_id,
        fpr_hex: s(&v, "fprHex"),
        kex: &kex,
        max_lifetime_secs: 604_800,
    };
    let now = ctx.iat + 10;
    let user = EcPublicKey::from_canonical(s(&v, "userSignKey")).unwrap();
    let owner = s(&v["keys"], "ownerRsaSpkiHex");
    let auto = ServedMandate { version: Some(2), mode: Some("auto"), owner_rsa_spki_hex: Some(owner) };
    let (dk, m) =
        delegation::accept_delegation_versioned(&me, now, &ctx, &user, s(&v, "wrap"), s(&v, "signatureAuto"), &auto)
            .unwrap();
    assert_eq!(synco_e2ee::encoding::hex(dk.as_bytes()), s(&d, "dkHex"));
    assert_eq!((m.version, m.mode), (MandateVersion::V2, MandateMode::Auto));
    // Mode servi échangé, horloge dépassée, autre enveloppe : refus.
    let swapped = ServedMandate { mode: Some("plan"), ..auto };
    for (sig, served, at) in [
        (s(&v, "signatureAuto"), swapped, now),
        (s(&v, "signatureAuto"), auto, ctx.exp),
        (s(&v, "signaturePlan"), auto, now),
    ] {
        let r = delegation::accept_delegation_versioned(&me, at, &ctx, &user, s(&v, "wrap"), sig, &served);
        assert_eq!(r.map(|_| ()).unwrap_err().code(), "delegation_unusable");
    }
    // Mandat v1 livré : accepté, lu comme plan.
    let v1_user = EcPublicKey::from_canonical(s(&v["keys"], "v1UserSignKey")).unwrap();
    let (_, m) = delegation::accept_delegation_versioned(
        &me,
        now,
        &ctx,
        &v1_user,
        s(&v, "wrap"),
        s(&v, "signatureV1"),
        &ServedMandate { version: None, mode: Some("auto"), owner_rsa_spki_hex: None },
    )
    .unwrap();
    assert_eq!((m.version, m.mode), (MandateVersion::V1, MandateMode::Plan));
}
