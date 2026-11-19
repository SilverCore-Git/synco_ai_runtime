//! Identité E2EE v4 : clés privées scellées par AK et chaîne de transitions d'identité.
//!
//! - [`open_identity_key`] ouvre une clé privée d'identité scellée par AK (`sealIdentityKey`,
//!   `e2eeV4.ts:75-98`). **Tests de compatibilité uniquement** : le runtime ne détient ni AK ni clé
//!   d'identité.
//! - [`identity_chain_path`] est le portage de `identityChainPath` (`e2eeV4.ts:530-544`) dont le
//!   runtime a besoin pour suivre la clé de signature d'un utilisateur depuis son épingle TOFU
//!   (docs/plan/03-delegation.md §4).

use serde_json::Value;
use zeroize::Zeroizing;

use crate::account::AccountKey;
use crate::ec::EcPublicKey;
use crate::encoding::{b64, from_b64};
use crate::error::{Error, Result};
use crate::primitives;

/// Usage d'une clé privée d'identité.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityPurpose {
    /// Clé RSA-OAEP de chiffrement.
    Rsa,
    /// Clé ECDSA P-256 de signature.
    Sign,
}

impl IdentityPurpose {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Rsa => "rsa",
            Self::Sign => "sign",
        }
    }
}

fn identity_aad(purpose: IdentityPurpose, user_id: &str) -> String {
    format!("synco-e4-identity|{}|{user_id}", purpose.as_str())
}

/// Clé privée d'identité scellée : colonnes `ciphertext` (chiffré ‖ tag) et `iv`, en `b64`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedIdentityKey {
    /// `b64(chiffré ‖ tag)`.
    pub ciphertext: String,
    /// `b64(iv)`.
    pub iv: String,
}

/// Ouvre une clé privée d'identité (PKCS#8) scellée par AK. Erreur : [`Error::EnvelopeUnusable`].
pub fn open_identity_key(
    ak: &AccountKey,
    purpose: IdentityPurpose,
    user_id: &str,
    sealed: &SealedIdentityKey,
) -> Result<Zeroizing<Vec<u8>>> {
    let iv = from_b64(&sealed.iv).map_err(|_| Error::EnvelopeUnusable)?;
    let ct = from_b64(&sealed.ciphertext).map_err(|_| Error::EnvelopeUnusable)?;
    let mut blob = iv;
    blob.extend_from_slice(&ct);
    primitives::open(ak.as_bytes(), identity_aad(purpose, user_id).as_bytes(), &blob).ok_or(Error::EnvelopeUnusable)
}

/// Scelle une clé privée d'identité sous AK (format de `sealIdentityKey`).
///
/// Réservé aux vecteurs de compatibilité (fonctionnalité `legacy-seal`).
#[cfg(feature = "legacy-seal")]
pub fn seal_identity_key(
    ak: &AccountKey,
    purpose: IdentityPurpose,
    user_id: &str,
    pkcs8: &[u8],
    rng: &mut impl crate::RandomSource,
) -> Result<SealedIdentityKey> {
    let blob = primitives::seal(ak.as_bytes(), identity_aad(purpose, user_id).as_bytes(), pkcs8, rng)?;
    let (iv, ct) = blob.split_at_checked(primitives::IV_LENGTH).ok_or(Error::InvalidInput)?;
    Ok(SealedIdentityKey { ciphertext: b64(ct), iv: b64(iv) })
}

// ---------------------------------------------------------------------------
// Transitions d'identité
// ---------------------------------------------------------------------------

/// Maillon de la chaîne servi par l'API (`GET /api/e2ee/v4/users/:id/transitions`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityTransition {
    /// Rang du maillon.
    pub seq: u64,
    /// Clé de signature remplacée (JWK EC, chaîne JSON).
    pub old_public_sign_key: String,
    /// Nouvelle clé publique RSA (JWK, chaîne JSON).
    pub new_public_key: String,
    /// Nouvelle clé de signature (JWK EC, chaîne JSON).
    pub new_public_sign_key: String,
    /// Signature `b64` P1363 par l'ancienne clé de signature.
    pub signature: String,
}

/// Identité traversée par la chaîne : JWK canoniques (`ecCanonical`, `rsaCanonical`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityKeys {
    /// Clé publique RSA, `{"e","kty","n"}`.
    pub public_key: String,
    /// Clé de signature, `{"crv","kty","x","y"}`.
    pub public_sign_key: String,
}

fn json_str(value: &Value, name: &str) -> Option<String> {
    value.get(name).and_then(Value::as_str).map(str::to_owned)
}

/// `ecCanonical` (`e2eeV4.ts:473-476`) : forme canonique sans validation du point (comme le TS,
/// qui ne la valide qu'à l'import de la clé).
pub fn ec_canonical_json(jwk: &str) -> Result<String> {
    let value: Value = serde_json::from_str(jwk).map_err(|_| Error::InvalidKey)?;
    let (Some(kty), Some(crv), Some(x), Some(y)) =
        (json_str(&value, "kty"), json_str(&value, "crv"), json_str(&value, "x"), json_str(&value, "y"))
    else {
        return Err(Error::InvalidKey);
    };
    if kty != "EC" || crv != "P-256" {
        return Err(Error::InvalidKey);
    }
    let x = serde_json::to_string(&x).map_err(|_| Error::InvalidKey)?;
    let y = serde_json::to_string(&y).map_err(|_| Error::InvalidKey)?;
    Ok(format!(r#"{{"crv":"P-256","kty":"EC","x":{x},"y":{y}}}"#))
}

/// `rsaCanonical` (`e2eeV4.ts:469-472`) : `{"e","kty","n"}`.
pub fn rsa_canonical_json(jwk: &str) -> Result<String> {
    let value: Value = serde_json::from_str(jwk).map_err(|_| Error::InvalidKey)?;
    let (Some(kty), Some(n), Some(e)) = (json_str(&value, "kty"), json_str(&value, "n"), json_str(&value, "e")) else {
        return Err(Error::InvalidKey);
    };
    if kty != "RSA" {
        return Err(Error::InvalidKey);
    }
    let e = serde_json::to_string(&e).map_err(|_| Error::InvalidKey)?;
    let n = serde_json::to_string(&n).map_err(|_| Error::InvalidKey)?;
    Ok(format!(r#"{{"e":{e},"kty":"RSA","n":{n}}}"#))
}

/// Octets signés d'une transition (`identityTransitionBytes`, `e2eeV4.ts:479-480`).
#[must_use]
pub fn identity_transition_bytes(user_id: &str, seq: u64, old_sign: &str, new_pub: &str, new_sign: &str) -> String {
    format!("synco-e4-identity-transition|{user_id}|{seq}|{old_sign}|{new_pub}|{new_sign}")
}

struct Link {
    old_sign: String,
    new_pub: String,
    new_sign: String,
}

/// `transitionSignedByOld` : maillon valide s'il est signé par la clé qu'il remplace.
fn transition_signed_by_old(user_id: &str, t: &IdentityTransition) -> Option<Link> {
    let old_sign = ec_canonical_json(&t.old_public_sign_key).ok()?;
    let new_pub = rsa_canonical_json(&t.new_public_key).ok()?;
    let new_sign = ec_canonical_json(&t.new_public_sign_key).ok()?;
    let key = EcPublicKey::from_jwk(&old_sign).ok()?;
    let sig = from_b64(&t.signature).ok()?;
    let bytes = identity_transition_bytes(user_id, t.seq, &old_sign, &new_pub, &new_sign);
    key.verify(bytes.as_bytes(), &sig).then_some(Link { old_sign, new_pub, new_sign })
}

/// Suit la chaîne depuis la clé de signature **épinglée** (jamais depuis une valeur de l'API) et
/// renvoie chaque identité traversée, dans l'ordre. Portage exact de `identityChainPath` : maillons
/// triés par `seq` (tri stable), un maillon invalide ou qui ne part pas de la clé courante est
/// ignoré.
pub fn identity_chain_path(
    user_id: &str,
    pinned_public_sign_key: &str,
    chain: &[IdentityTransition],
) -> Result<Vec<IdentityKeys>> {
    let mut current = ec_canonical_json(pinned_public_sign_key)?;
    let mut sorted: Vec<&IdentityTransition> = chain.iter().collect();
    sorted.sort_by_key(|t| t.seq);
    let mut path = Vec::new();
    for t in sorted {
        let Some(link) = transition_signed_by_old(user_id, t) else { continue };
        if link.old_sign != current {
            continue;
        }
        current.clone_from(&link.new_sign);
        path.push(IdentityKeys { public_key: link.new_pub, public_sign_key: link.new_sign });
    }
    Ok(path)
}

/// Identité au bout de la partie valide de la chaîne (`followIdentityChain`), ou `None`.
pub fn follow_identity_chain(
    user_id: &str,
    pinned_public_sign_key: &str,
    chain: &[IdentityTransition],
) -> Result<Option<IdentityKeys>> {
    Ok(identity_chain_path(user_id, pinned_public_sign_key, chain)?.pop())
}

/// Signe une transition avec la clé de signature actuelle (`signIdentityTransition`).
pub fn sign_identity_transition(
    old_sign_key: &crate::ec::EcSigningKey,
    user_id: &str,
    seq: u64,
    new_public_key: &str,
    new_public_sign_key: &str,
) -> Result<IdentityTransition> {
    let old_sign = old_sign_key.public_key()?.to_canonical();
    let new_pub = rsa_canonical_json(new_public_key)?;
    let new_sign = ec_canonical_json(new_public_sign_key)?;
    let sig = old_sign_key.sign(identity_transition_bytes(user_id, seq, &old_sign, &new_pub, &new_sign).as_bytes());
    Ok(IdentityTransition {
        seq,
        old_public_sign_key: old_sign,
        new_public_key: new_pub,
        new_public_sign_key: new_sign,
        signature: b64(&sig),
    })
}
