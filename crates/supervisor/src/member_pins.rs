//! Épinglage TOFU des clés RSA publiques des membres (Q25, revue L07 I5 ; docs/plan/04 §4.3,
//! 06 §4.3).
//!
//! Le worker scelle la clé d'un salon qu'il crée (`create_thread`) pour les clés RSA publiques
//! servies par `GET /api/runtime/v1/e2ee/members/keys`. Il n'a pas de disque : c'est le superviseur,
//! qui relaie cette réponse, qui tient l'épinglage et **refuse la réponse entière** (`409
//! member_key_changed`) si une clé a changé sans preuve. Rien n'est scellé, aucun salon n'est créé.
//!
//! - Identité épinglée : `SHA-256(SubjectPublicKeyInfo DER)` de la clé, calculé depuis `n` et `e`
//!   (indépendant de l'encodage du JWK). Est aussi gardée l'empreinte RFC 7638 (`SHA-256` du JWK
//!   canonique `{"e","kty","n"}`), **affichée** au dashboard : c'est celle que montre l'app
//!   (`computeKeyFingerprint`, `keyTrust.ts`), pour une comparaison hors bande.
//! - Première vue d'un couple (org, utilisateur) : épinglée.
//! - Même clé : acceptée.
//! - Clé différente : acceptée **seulement** si une chaîne de transitions d'identité valide partant
//!   de la clé de **signature** épinglée de l'utilisateur (`pins.rs`) aboutit exactement à cette clé
//!   RSA ([`chain_vouches`]) ; sinon refus, changement mis en attente ([`MemberPin::pending`]) et
//!   alerte ; l'admin du runtime peut l'accepter depuis le dashboard ([`MemberPinStore::accept_pending`]).
//!
//! Fichier `member-rsa-pins.json` du répertoire d'état : données **publiques** uniquement
//! (empreintes, jamais la clé elle-même).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use synco_e2ee::encoding::{from_b64u, hex};
use synco_e2ee::identity::{IdentityTransition, identity_chain_path, rsa_canonical_json};
use synco_e2ee::primitives::sha256;

use crate::error::{Error, Result};

/// Nom du fichier.
pub const MEMBER_PINS_FILE: &str = "member-rsa-pins.json";
/// Taille minimale d'une clé épinglée (comme le worker, `MIN_RSA_BITS`).
pub const MIN_RSA_BITS: usize = 2048;
/// Taille maximale (comme `rsa::PublicKey::MAX_SIZE`).
pub const MAX_RSA_BITS: usize = 8192;

// ---------------------------------------------------------------------------
// Empreintes
// ---------------------------------------------------------------------------

/// Empreintes d'une clé RSA publique de membre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberKey {
    /// `hex(SHA-256(SPKI DER))`, minuscules : identité épinglée.
    pub fingerprint: String,
    /// Empreinte RFC 7638 (`hex` majuscules), comme `computeKeyFingerprint` de l'app : affichage.
    pub thumbprint: String,
}

fn strip_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    bytes.get(start..).unwrap_or_default()
}

fn der_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else if len <= 0xff {
        out.push(0x81);
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        out.push(0x82);
        out.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes());
    }
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len().saturating_add(4));
    out.push(tag);
    der_len(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// Entier positif DER (sans zéros de tête, `0x00` ajouté si le bit de poids fort est à 1).
fn der_uint(magnitude: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(magnitude.len().saturating_add(1));
    if magnitude.first().is_some_and(|b| b & 0x80 != 0) {
        content.push(0);
    }
    content.extend_from_slice(magnitude);
    der(0x02, &content)
}

/// `SubjectPublicKeyInfo` DER d'une clé RSA (`rsaEncryption`, paramètres `NULL`), comme
/// `crypto.subtle.exportKey('spki')`.
#[must_use]
pub fn rsa_spki_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    const ALG: [u8; 15] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
    let mut rsa_key = der_uint(strip_zeros(n));
    rsa_key.extend_from_slice(&der_uint(strip_zeros(e)));
    let rsa_key = der(0x30, &rsa_key);
    let mut bits = Vec::with_capacity(rsa_key.len().saturating_add(1));
    bits.push(0);
    bits.extend_from_slice(&rsa_key);
    let mut spki = ALG.to_vec();
    spki.extend_from_slice(&der(0x03, &bits));
    der(0x30, &spki)
}

fn bit_len(magnitude: &[u8]) -> usize {
    match magnitude.first() {
        None => 0,
        Some(b) => {
            let lead = usize::try_from(b.leading_zeros()).unwrap_or(8);
            magnitude.len().saturating_sub(1).saturating_mul(8).saturating_add(8usize.saturating_sub(lead))
        }
    }
}

impl MemberKey {
    /// Empreintes d'un JWK RSA (chaîne JSON). `None` : illisible, ou taille hors de 2048..=8192
    /// bits, ou exposant impossible (pair, ≤ 1, > 64 bits) — le worker écarte ces membres lui-même.
    #[must_use]
    pub fn from_jwk_str(jwk: &str) -> Option<Self> {
        let canonical = rsa_canonical_json(jwk).ok()?;
        let value: Value = serde_json::from_str(&canonical).ok()?;
        let n = from_b64u(value.get("n")?.as_str()?).ok()?;
        let e = from_b64u(value.get("e")?.as_str()?).ok()?;
        let (n_mag, e_mag) = (strip_zeros(&n), strip_zeros(&e));
        if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bit_len(n_mag)) {
            return None;
        }
        if e_mag.len() > 8 || e_mag.last().is_none_or(|b| b & 1 == 0) || e_mag == [1] {
            return None;
        }
        Some(Self {
            fingerprint: hex(&sha256(&rsa_spki_der(n_mag, e_mag))),
            thumbprint: hex(&sha256(canonical.as_bytes())).to_uppercase(),
        })
    }

    /// Comme [`Self::from_jwk_str`], pour une valeur JSON (chaîne JSON ou objet), comme le worker.
    #[must_use]
    pub fn from_jwk(jwk: &Value) -> Option<Self> {
        match jwk {
            Value::String(s) => Self::from_jwk_str(s),
            Value::Object(_) => Self::from_jwk_str(&jwk.to_string()),
            _ => None,
        }
    }
}

/// Rotation légitime (03 §4) : la chaîne de transitions, chaque maillon signé par la clé de
/// signature qu'il remplace, aboutit (dernier maillon valide) **exactement** à la clé RSA présentée.
///
/// `trusted_sign_keys` : clés de signature épinglées de l'utilisateur (`pins.rs`), de la plus
/// ancienne à la **courante** (`UserPin::previous` puis `sign_key`). La chaîne est suivie depuis la
/// plus ancienne, car l'épingle de signature peut avoir déjà avancé (ouverture d'une délégation
/// après la rotation) alors que l'épingle RSA est restée en arrière ; elle doit alors **passer par
/// la clé courante** : une branche signée par une clé retirée (peut-être compromise) qui s'écarte
/// de l'identité épinglée est refusée. Une clé intermédiaire n'est jamais acceptée.
#[must_use]
pub fn chain_vouches(
    user_id: &str,
    trusted_sign_keys: &[String],
    chain: &[IdentityTransition],
    key: &MemberKey,
) -> bool {
    let (Some(root), Some(current)) = (trusted_sign_keys.first(), trusted_sign_keys.last()) else { return false };
    let Ok(path) = identity_chain_path(user_id, root, chain) else { return false };
    let Ok(current) = synco_e2ee::identity::ec_canonical_json(current) else { return false };
    let through_current = synco_e2ee::identity::ec_canonical_json(root).is_ok_and(|r| r == current)
        || path.iter().any(|k| k.public_sign_key == current);
    through_current
        && path
            .last()
            .and_then(|end| MemberKey::from_jwk_str(&end.public_key))
            .is_some_and(|end| end.fingerprint == key.fingerprint)
}

// ---------------------------------------------------------------------------
// Magasin
// ---------------------------------------------------------------------------

/// Clé refusée, en attente d'une décision de l'admin du runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingKey {
    /// `hex(SHA-256(SPKI DER))`.
    pub fingerprint: String,
    /// Empreinte RFC 7638 (affichage).
    pub thumbprint: String,
    /// Dernière présentation (s).
    pub seen: u64,
}

/// Épingle d'un membre.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberPin {
    /// `hex(SHA-256(SPKI DER))` de la clé épinglée.
    pub fingerprint: String,
    /// Empreinte RFC 7638 (affichage).
    pub thumbprint: String,
    /// Première vue (s).
    pub first_seen: u64,
    /// Empreintes précédentes (diagnostic seulement, jamais acceptées de nouveau).
    #[serde(default)]
    pub previous: Vec<String>,
    /// Dernière clé différente refusée.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<PendingKey>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PinFile {
    v: u8,
    /// org → utilisateur → épingle.
    orgs: BTreeMap<String, BTreeMap<String, MemberPin>>,
}

/// Verdict de l'épinglage pour une clé présentée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Première vue : épinglée.
    Pinned,
    /// Clé épinglée.
    Trusted,
    /// Clé différente de l'épinglée (rien n'est modifié).
    Changed,
}

/// Magasin des épingles RSA des membres.
#[derive(Debug)]
pub struct MemberPinStore {
    path: Option<PathBuf>,
    file: PinFile,
}

impl Default for MemberPinStore {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl MemberPinStore {
    /// Magasin en mémoire seulement (tests).
    #[must_use]
    pub fn in_memory() -> Self {
        Self { path: None, file: PinFile { v: 1, orgs: BTreeMap::new() } }
    }

    /// Ouvre `member-rsa-pins.json` (absent : vide). Illisible : erreur (jamais un épinglage remis
    /// à zéro en silence).
    pub fn open(state_dir: &Path) -> Result<Self> {
        let path = state_dir.join(MEMBER_PINS_FILE);
        let file = match std::fs::read(&path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|_| Error::Io(format!("{MEMBER_PINS_FILE} illisible")))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => PinFile { v: 1, orgs: BTreeMap::new() },
            Err(e) => return Err(Error::Io(format!("{MEMBER_PINS_FILE} : {}", e.kind()))),
        };
        Ok(Self { path: Some(path), file })
    }

    fn persist(&mut self) {
        // Seul le format courant est écrit.
        self.file.v = 1;
        if let Some(path) = &self.path {
            let saved = serde_json::to_vec_pretty(&self.file)
                .map_err(|_| Error::Io("sérialisation".into()))
                .and_then(|bytes| crate::seal::write_atomic(path, &bytes));
            if let Err(e) = saved {
                tracing::warn!(code = "member_pins_not_saved", error = %e, "épingles RSA non enregistrées");
            }
        }
    }

    /// Épingle d'un membre.
    #[must_use]
    pub fn get(&self, org_id: &str, user_id: &str) -> Option<&MemberPin> {
        self.file.orgs.get(org_id).and_then(|m| m.get(user_id))
    }

    /// Règle TOFU : épingle à la première vue, sinon compare. Une clé différente ne modifie rien.
    pub fn check(&mut self, org_id: &str, user_id: &str, key: &MemberKey, now: u64) -> Verdict {
        let users = self.file.orgs.entry(org_id.to_owned()).or_default();
        match users.get(user_id) {
            Some(pin) if pin.fingerprint == key.fingerprint => Verdict::Trusted,
            Some(_) => Verdict::Changed,
            None => {
                users.insert(
                    user_id.to_owned(),
                    MemberPin {
                        fingerprint: key.fingerprint.clone(),
                        thumbprint: key.thumbprint.clone(),
                        first_seen: now,
                        previous: Vec::new(),
                        pending: None,
                    },
                );
                self.persist();
                Verdict::Pinned
            }
        }
    }

    fn replace(&mut self, org_id: &str, user_id: &str, key: &MemberKey) {
        if let Some(pin) = self.file.orgs.get_mut(org_id).and_then(|m| m.get_mut(user_id)) {
            let old = core::mem::replace(&mut pin.fingerprint, key.fingerprint.clone());
            pin.previous.push(old);
            pin.thumbprint.clone_from(&key.thumbprint);
            pin.pending = None;
            self.persist();
        }
    }

    /// Rotation prouvée ([`chain_vouches`]) : remplace l'épingle **si** elle vaut toujours
    /// `from_fingerprint` (aucun autre changement entre-temps). Rend vrai si remplacée.
    pub fn rotate(&mut self, org_id: &str, user_id: &str, from_fingerprint: &str, key: &MemberKey) -> bool {
        if self.get(org_id, user_id).is_none_or(|p| p.fingerprint != from_fingerprint) {
            return false;
        }
        self.replace(org_id, user_id, key);
        tracing::info!(code = "member_rsa_key_rotated", "clé RSA d'un membre renouvelée (chaîne d'identité vérifiée)");
        true
    }

    /// Refus : la clé présentée est mise en attente (la dernière remplace la précédente) pour
    /// décision de l'admin du runtime. Journal sans clé ni empreinte.
    pub fn refuse(&mut self, org_id: &str, user_id: &str, key: &MemberKey, now: u64) {
        if let Some(pin) = self.file.orgs.get_mut(org_id).and_then(|m| m.get_mut(user_id)) {
            pin.pending = Some(PendingKey {
                fingerprint: key.fingerprint.clone(),
                thumbprint: key.thumbprint.clone(),
                seen: now,
            });
            self.persist();
        }
        tracing::warn!(code = "member_rsa_key_changed", "clé RSA d'un membre changée sans preuve : scellement refusé");
    }

    /// Acceptation manuelle (dashboard) de la clé **en attente** dont l'empreinte SPKI est
    /// `fingerprint` (celle qui a été affichée). Rend vrai si acceptée.
    pub fn accept_pending(&mut self, org_id: &str, user_id: &str, fingerprint: &str) -> bool {
        let Some(pending) = self.get(org_id, user_id).and_then(|p| p.pending.clone()) else { return false };
        if pending.fingerprint != fingerprint {
            return false;
        }
        self.replace(org_id, user_id, &MemberKey { fingerprint: pending.fingerprint, thumbprint: pending.thumbprint });
        tracing::info!(code = "member_rsa_key_accepted", "clé RSA d'un membre acceptée par l'admin du runtime");
        true
    }

    /// Changements en attente d'une org : (utilisateur, épingle).
    #[must_use]
    pub fn pending(&self, org_id: &str) -> Vec<(&str, &MemberPin)> {
        self.file
            .orgs
            .get(org_id)
            .map(|m| m.iter().filter(|(_, p)| p.pending.is_some()).map(|(u, p)| (u.as_str(), p)).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synco_e2ee::OsRandom;
    use synco_e2ee::ec::EcSigningKey;
    use synco_e2ee::encoding::b64u;
    use synco_e2ee::identity::sign_identity_transition;

    /// Clé de test de `crates/worker/tests/fixtures/test-member-rsa.json` ; empreintes calculées
    /// par WebCrypto (`exportKey('spki')` puis SHA-256 ; `computeKeyFingerprint` de l'app).
    const FIXTURE: &str = include_str!("../../worker/tests/fixtures/test-member-rsa.json");
    const FIXTURE_SPKI_SHA256: &str = "bb528f7bc0c91d89c961655e42613ee7a71619a384898e08b42c3ed7b23ab122";
    const FIXTURE_THUMBPRINT: &str = "7858C96F1F1EF190979C259EABCEB9457088859878B6439D11FD67C683E51E4E";

    /// JWK RSA synthétique de `bits` bits (l'empreinte ne demande pas une vraie clé).
    fn jwk(seed: u8, bits: usize) -> String {
        let mut n = vec![seed; bits / 8];
        if let Some(first) = n.first_mut() {
            *first |= 0x80;
        }
        format!(r#"{{"kty":"RSA","n":"{}","e":"AQAB"}}"#, b64u(&n))
    }

    fn key(seed: u8) -> MemberKey {
        MemberKey::from_jwk_str(&jwk(seed, 2048)).unwrap()
    }

    #[test]
    fn empreintes_comme_webcrypto() {
        let f: Value = serde_json::from_str(FIXTURE).unwrap();
        let k = MemberKey::from_jwk(&f["publicJwk"]).unwrap();
        assert_eq!(k.fingerprint, FIXTURE_SPKI_SHA256, "SPKI DER identique à exportKey('spki')");
        assert_eq!(k.thumbprint, FIXTURE_THUMBPRINT, "empreinte affichée = celle de l'app");
        // Même clé en chaîne JSON, ou avec des zéros de tête dans n : même empreinte SPKI.
        assert_eq!(MemberKey::from_jwk(&Value::String(f["publicJwk"].to_string())).unwrap(), k);
        let n = from_b64u(f["publicJwk"]["n"].as_str().unwrap()).unwrap();
        let padded = format!(r#"{{"kty":"RSA","n":"{}","e":"AQAB"}}"#, b64u(&[&[0u8, 0][..], &n].concat()));
        assert_eq!(MemberKey::from_jwk_str(&padded).unwrap().fingerprint, FIXTURE_SPKI_SHA256);
        // Bornes : 1024 bits (shortPublicJwk), 8200 bits, exposant pair, autre type.
        assert!(MemberKey::from_jwk(&f["shortPublicJwk"]).is_none());
        assert!(MemberKey::from_jwk_str(&jwk(1, 8200)).is_none());
        assert!(MemberKey::from_jwk_str(&jwk(1, 8192)).is_some());
        assert!(MemberKey::from_jwk_str(&jwk(1, 2048).replace("AQAB", "AQAA")).is_none());
        assert!(MemberKey::from_jwk_str(r#"{"kty":"EC","n":"AQAB","e":"AQAB"}"#).is_none());
    }

    #[test]
    fn premiere_vue_meme_cle_cle_substituee() {
        let mut s = MemberPinStore::in_memory();
        assert_eq!(s.check("o1", "u1", &key(1), 10), Verdict::Pinned, "première vue");
        assert_eq!(s.check("o1", "u1", &key(1), 11), Verdict::Trusted, "même clé");
        assert_eq!(s.check("o1", "u1", &key(2), 12), Verdict::Changed, "clé substituée");
        assert_eq!(s.get("o1", "u1").unwrap().fingerprint, key(1).fingerprint, "épingle inchangée");
        // Cloisonné par org.
        assert_eq!(s.check("o2", "u1", &key(2), 13), Verdict::Pinned);
        // Refus : mis en attente ; acceptation manuelle de CETTE clé seulement.
        s.refuse("o1", "u1", &key(2), 14);
        assert_eq!(s.pending("o1").len(), 1);
        assert!(!s.accept_pending("o1", "u1", &key(3).fingerprint), "autre empreinte que celle affichée");
        assert!(s.accept_pending("o1", "u1", &key(2).fingerprint));
        assert_eq!(s.check("o1", "u1", &key(2), 15), Verdict::Trusted);
        assert!(s.pending("o1").is_empty());
        // L'ancienne clé ne revient pas.
        assert_eq!(s.check("o1", "u1", &key(1), 16), Verdict::Changed);
        assert!(!s.accept_pending("o1", "u1", &key(1).fingerprint), "rien en attente");
    }

    #[test]
    fn rotation_par_chaine_d_identite() {
        let (k1, k2, k3, attaquant) = (
            EcSigningKey::generate(&mut OsRandom).unwrap(),
            EcSigningKey::generate(&mut OsRandom).unwrap(),
            EcSigningKey::generate(&mut OsRandom).unwrap(),
            EcSigningKey::generate(&mut OsRandom).unwrap(),
        );
        let pub_of = |k: &EcSigningKey| k.public_key().unwrap().to_canonical();
        let (rsa2, rsa3) = (jwk(2, 2048), jwk(3, 4096));
        let t1 = sign_identity_transition(&k1, "u1", 0, &rsa2, &pub_of(&k2)).unwrap();
        let t2 = sign_identity_transition(&k2, "u1", 1, &rsa3, &pub_of(&k3)).unwrap();
        let k3_rsa = MemberKey::from_jwk_str(&rsa3).unwrap();
        let k2_rsa = MemberKey::from_jwk_str(&rsa2).unwrap();
        let only_k1 = [pub_of(&k1)];
        assert!(chain_vouches("u1", &only_k1, &[t1.clone(), t2.clone()], &k3_rsa), "bout de chaîne");
        assert!(!chain_vouches("u1", &only_k1, &[t1.clone(), t2.clone()], &k2_rsa), "clé intermédiaire");
        assert!(!chain_vouches("u1", &only_k1, &[], &k3_rsa), "sans chaîne");
        assert!(!chain_vouches("u1", &[], &[t1.clone(), t2.clone()], &k3_rsa), "aucune clé de signature épinglée");
        assert!(!chain_vouches("u2", &only_k1, &[t1.clone(), t2.clone()], &k3_rsa), "autre utilisateur");
        let forged = sign_identity_transition(&attaquant, "u1", 0, &rsa3, &pub_of(&k3)).unwrap();
        assert!(!chain_vouches("u1", &only_k1, &[forged], &k3_rsa), "maillon non signé par l'épinglée");
        // Épingle de signature déjà avancée à k3 (délégation rouverte), épingle RSA restée en arrière :
        // chaîne suivie depuis k1, passant par k3.
        assert!(chain_vouches("u1", &[pub_of(&k1), pub_of(&k2), pub_of(&k3)], &[t1.clone(), t2.clone()], &k3_rsa));
        // Branche signée par k1 (retirée, supposée compromise) qui évite la clé courante k2 : refusée.
        let (rsa_x, kx) = (jwk(7, 2048), EcSigningKey::generate(&mut OsRandom).unwrap());
        let branch = sign_identity_transition(&k1, "u1", 0, &rsa_x, &pub_of(&kx)).unwrap();
        let x_rsa = MemberKey::from_jwk_str(&rsa_x).unwrap();
        assert!(chain_vouches("u1", &only_k1, std::slice::from_ref(&branch), &x_rsa), "sans clé plus récente : suivie");
        assert!(
            !chain_vouches("u1", &[pub_of(&k1), pub_of(&k2)], &[branch, t2], &x_rsa),
            "branche qui ne passe pas par la clé de signature courante"
        );
        // Rotation : seulement depuis l'épingle attendue.
        let mut s = MemberPinStore::in_memory();
        s.check("o", "u1", &key(1), 1);
        assert!(!s.rotate("o", "u1", &key(9).fingerprint, &k3_rsa), "épingle changée entre-temps");
        assert!(s.rotate("o", "u1", &key(1).fingerprint, &k3_rsa));
        assert_eq!(s.check("o", "u1", &k3_rsa, 2), Verdict::Trusted);
        assert_eq!(s.get("o", "u1").unwrap().previous, vec![key(1).fingerprint]);
    }

    #[test]
    fn persistance_et_fichier_public() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut s = MemberPinStore::open(dir.path()).unwrap();
            s.check("o1", "u1", &key(1), 1);
            assert_eq!(s.check("o1", "u1", &key(2), 2), Verdict::Changed);
            s.refuse("o1", "u1", &key(2), 2);
        }
        // « Redémarrage » : nouvelle ouverture du fichier.
        let mut s = MemberPinStore::open(dir.path()).unwrap();
        assert_eq!(s.check("o1", "u1", &key(1), 3), Verdict::Trusted);
        assert_eq!(s.check("o1", "u1", &key(2), 3), Verdict::Changed, "toujours refusée après redémarrage");
        assert_eq!(s.pending("o1").len(), 1, "changement en attente conservé");
        let text = std::fs::read_to_string(dir.path().join(MEMBER_PINS_FILE)).unwrap();
        let n2 = serde_json::from_str::<Value>(&jwk(2, 2048)).unwrap()["n"].as_str().unwrap().to_owned();
        assert!(!text.contains(n2.get(..40).unwrap()), "aucune clé, seulement des empreintes");
        // Fichier illisible : erreur, jamais une remise à zéro silencieuse.
        std::fs::write(dir.path().join(MEMBER_PINS_FILE), b"{").unwrap();
        assert!(MemberPinStore::open(dir.path()).is_err());
    }
}
