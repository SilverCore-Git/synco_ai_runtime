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
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use synco_e2ee::encoding::{b64u, from_b64u, hex};
use synco_e2ee::identity::{IdentityTransition, ec_canonical_json, identity_chain_path, rsa_canonical_json};
use synco_e2ee::primitives::sha256;

use crate::error::{Error, Result};

/// Nom du fichier.
pub const MEMBER_PINS_FILE: &str = "member-rsa-pins.json";
/// Taille minimale d'une clé épinglée (comme le worker, `MIN_RSA_BITS`).
pub const MIN_RSA_BITS: usize = 2048;
/// Taille maximale (comme `rsa::PublicKey::MAX_SIZE`).
pub const MAX_RSA_BITS: usize = 8192;
/// Épingles au plus par org (l'app vise 100 membres) ; au-delà, refus fermé (`member_pins_limit`).
pub const MAX_PINS_PER_ORG: usize = 2000;
/// Empreintes précédentes gardées par membre (refus des retours arrière).
pub const MAX_PREVIOUS: usize = 16;
/// Clés en attente au plus par org ; au-delà, le refus reste fermé mais n'est plus mémorisé.
pub const MAX_PENDING_PER_ORG: usize = 100;

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
            // Revue M6 : JWK canonique recomposé depuis les entiers sans zéros de tête (forme
            // minimale de la RFC 7518 §6.3.1, celle qu'exporte WebCrypto) : sur une clé légitime,
            // identique à `computeKeyFingerprint` de l'app ; un `n` gonflé ne change pas l'empreinte.
            thumbprint: hex(&sha256(
                format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, b64u(e_mag), b64u(n_mag)).as_bytes(),
            ))
            .to_uppercase(),
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

/// Clés de signature épinglées d'un utilisateur (`pins.rs`), vues par la règle de rotation.
#[derive(Debug, Clone, Copy)]
pub struct SignHistory<'a> {
    /// De la plus ancienne à la **courante** (`UserPin::previous` puis `sign_key`) : `pins.rs` y
    /// range chaque clé traversée par une chaîne vérifiée, dans l'ordre.
    pub keys: &'a [String],
    /// `SHA-256(SPKI)` de la clé RSA que la chaîne vérifiée par `pins.rs` liait à la clé de
    /// signature courante **au moment où l'épingle de signature a avancé** (`UserPin::rsa_fingerprint`).
    pub bound_rsa: Option<&'a str>,
}

/// Rotation légitime (03 §4) : règle **stricte**. La chaîne de transitions (chaque maillon signé par
/// la clé de signature qu'il remplace) est suivie depuis la plus ancienne clé de signature épinglée
/// et doit :
///
/// 1. **reproduire exactement** l'historique épinglé : ses premières clés de signature sont
///    `history.keys[1..]`, dans l'ordre et sans écart (une branche signée par une clé retirée,
///    même si elle rejoint ensuite la clé courante, est refusée) ;
/// 2. aboutir (dernier maillon) **exactement** à la clé RSA présentée, introduite une seule fois et
///    différente de l'épinglée (`pinned_rsa`, donc placée avant elle si la chaîne la contient) ; le
///    magasin refuse en plus toute clé déjà épinglée par le passé ([`MemberPinStore::rotate`]) ;
/// 3. et cette clé RSA doit être garantie par une clé **non retirée** : soit le maillon qui
///    l'introduit est signé par la clé de signature courante ou une successeure (la chaîne
///    continue au-delà de la clé courante) ; soit la chaîne s'arrête sur la clé courante et la clé
///    RSA est celle que `pins.rs` a liée à cette clé quand il l'a acceptée (`bound_rsa`), à une
///    époque où la clé signataire n'était pas retirée. Un maillon servi aujourd'hui et signé par
///    une clé retirée (peut-être compromise) ne suffit jamais.
#[must_use]
pub fn chain_vouches(
    user_id: &str,
    history: &SignHistory<'_>,
    chain: &[IdentityTransition],
    pinned_rsa: &str,
    key: &MemberKey,
) -> bool {
    let Ok(canon) = history.keys.iter().map(|k| ec_canonical_json(k)).collect::<core::result::Result<Vec<_>, _>>()
    else {
        return false;
    };
    let Some((root, pinned_after_root)) = canon.split_first() else { return false };
    let Ok(path) = identity_chain_path(user_id, root, chain) else { return false };
    // 1. Historique épinglé reproduit exactement.
    let signs: Vec<&str> = path.iter().map(|k| k.public_sign_key.as_str()).collect();
    if signs.len() < pinned_after_root.len()
        || signs.iter().zip(pinned_after_root).any(|(served, pinned)| *served != pinned.as_str())
    {
        return false;
    }
    // 2. Bout de chaîne = clé présentée, introduite une seule fois.
    let rsas: Vec<Option<String>> =
        path.iter().map(|k| MemberKey::from_jwk_str(&k.public_key).map(|m| m.fingerprint)).collect();
    let Some((Some(end), before)) = rsas.split_last() else { return false };
    if *end != key.fingerprint || before.iter().flatten().any(|f| *f == key.fingerprint) {
        return false;
    }
    // La clé RSA épinglée, si la chaîne la contient, vient AVANT la nouvelle (revue I2) : jamais une
    // chaîne qui la place après, ni qui « renouvelle » vers elle-même.
    if *end == pinned_rsa {
        return false;
    }
    // 3. Garantie par une clé non retirée.
    if path.len() > pinned_after_root.len() {
        return true;
    }
    !pinned_after_root.is_empty() && history.bound_rsa == Some(key.fingerprint.as_str())
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
    /// Première vue, mais l'org a déjà [`MAX_PINS_PER_ORG`] épingles : rien n'est épinglé.
    Full,
}

/// État à écrire, pris sous le verrou d'état et écrit **hors** de lui ([`Self::write`], par
/// exemple dans `spawn_blocking`) : une seule écriture atomique (`rename`) par réponse.
#[derive(Debug)]
pub struct PinSnapshot {
    path: PathBuf,
    bytes: Vec<u8>,
    generation: u64,
    written: Arc<Mutex<u64>>,
}

impl PinSnapshot {
    /// Écrit l'état (fichier temporaire, `fsync`, `rename`). Les écritures sont sérialisées et
    /// une photo plus ancienne que la dernière écrite est ignorée : l'ordre est préservé.
    pub fn write(self) -> Result<()> {
        let mut last = self.written.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.generation <= *last {
            return Ok(());
        }
        crate::seal::write_atomic(&self.path, &self.bytes)?;
        *last = self.generation;
        Ok(())
    }
}

/// Magasin des épingles RSA des membres.
#[derive(Debug)]
pub struct MemberPinStore {
    path: Option<PathBuf>,
    file: PinFile,
    dirty: bool,
    generation: u64,
    written: Arc<Mutex<u64>>,
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
        Self::with(None, PinFile { v: 1, orgs: BTreeMap::new() })
    }

    fn with(path: Option<PathBuf>, file: PinFile) -> Self {
        Self { path, file, dirty: false, generation: 0, written: Arc::new(Mutex::new(0)) }
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
        // Revue M5 : version inconnue (fichier d'un runtime plus récent) : refus de démarrer plutôt
        // qu'une relecture partielle suivie d'une réécriture qui perdrait des données.
        if file.v != 1 {
            return Err(Error::Io(format!("{MEMBER_PINS_FILE} : version {} inconnue", file.v)));
        }
        Ok(Self::with(Some(path), file))
    }

    fn persist(&mut self) {
        self.dirty = true;
    }

    /// Photo de l'état modifié depuis la dernière (`None` : rien à écrire, ou magasin en mémoire).
    /// Seul le format courant est écrit.
    pub fn snapshot(&mut self) -> Result<Option<PinSnapshot>> {
        let Some(path) = self.path.clone().filter(|_| self.dirty) else {
            self.dirty = false;
            return Ok(None);
        };
        self.file.v = 1;
        let bytes = serde_json::to_vec_pretty(&self.file).map_err(|_| Error::Io("sérialisation".into()))?;
        self.dirty = false;
        self.generation = self.generation.saturating_add(1);
        Ok(Some(PinSnapshot { path, bytes, generation: self.generation, written: Arc::clone(&self.written) }))
    }

    /// Après un échec d'écriture : la prochaine photo réécrira tout l'état.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Écrit tout de suite (tests, outils) : à ne pas appeler sous le verrou d'état.
    pub fn flush(&mut self) -> Result<()> {
        match self.snapshot()? {
            Some(snap) => snap.write(),
            None => Ok(()),
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
            None if users.len() >= MAX_PINS_PER_ORG => Verdict::Full,
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
            let excess = pin.previous.len().saturating_sub(MAX_PREVIOUS);
            pin.previous.drain(..excess);
            pin.thumbprint.clone_from(&key.thumbprint);
            pin.pending = None;
            self.persist();
        }
    }

    /// Rotation prouvée ([`chain_vouches`]) : remplace l'épingle **si** elle vaut toujours
    /// `from_fingerprint` (aucun autre changement entre-temps) et si la nouvelle clé n'est ni
    /// l'épinglée ni une clé **précédente** (aucun retour arrière, revue I2). Rend vrai si remplacée.
    pub fn rotate(&mut self, org_id: &str, user_id: &str, from_fingerprint: &str, key: &MemberKey) -> bool {
        let Some(pin) = self.get(org_id, user_id) else { return false };
        if pin.fingerprint != from_fingerprint
            || key.fingerprint == pin.fingerprint
            || pin.previous.contains(&key.fingerprint)
        {
            return false;
        }
        self.replace(org_id, user_id, key);
        tracing::info!(code = "member_rsa_key_rotated", "clé RSA d'un membre renouvelée (chaîne d'identité vérifiée)");
        true
    }

    /// Refus : la clé présentée est mise en attente (la dernière remplace la précédente) pour
    /// décision de l'admin du runtime. Journal sans clé ni empreinte.
    ///
    /// Revue M4 : rien n'est mis en attente si l'épingle n'est plus `from_fingerprint` (changée
    /// entre-temps) ni si la clé présentée est l'épinglée.
    pub fn refuse(&mut self, org_id: &str, user_id: &str, from_fingerprint: &str, key: &MemberKey, now: u64) {
        let pending_count = self.pending(org_id).len();
        if let Some(pin) = self.file.orgs.get_mut(org_id).and_then(|m| m.get_mut(user_id))
            && pin.fingerprint == from_fingerprint
            && key.fingerprint != pin.fingerprint
            && (pin.pending.is_some() || pending_count < MAX_PENDING_PER_ORG)
        {
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
        assert_eq!(MemberKey::from_jwk_str(&padded).unwrap().thumbprint, FIXTURE_THUMBPRINT, "revue M6");
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
        s.refuse("o1", "u1", &key(1).fingerprint, &key(2), 14);
        assert_eq!(s.pending("o1").len(), 1);
        assert!(!s.accept_pending("o1", "u1", &key(3).fingerprint), "autre empreinte que celle affichée");
        assert!(s.accept_pending("o1", "u1", &key(2).fingerprint));
        assert_eq!(s.check("o1", "u1", &key(2), 15), Verdict::Trusted);
        assert!(s.pending("o1").is_empty());
        // Revue M4 : refus périmé (épingle changée entre-temps) ou clé égale à l'épinglée : ignoré.
        s.refuse("o1", "u1", &key(1).fingerprint, &key(3), 15);
        s.refuse("o1", "u1", &key(2).fingerprint, &key(2), 15);
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
        let h = |keys: &[String], bound: Option<&MemberKey>| -> (Vec<String>, Option<String>) {
            (keys.to_vec(), bound.map(|b| b.fingerprint.clone()))
        };
        let vouch = |(keys, bound): &(Vec<String>, Option<String>), chain: &[IdentityTransition], k: &MemberKey| {
            chain_vouches("u1", &SignHistory { keys, bound_rsa: bound.as_deref() }, chain, "épinglée", k)
        };
        let only_k1 = h(&[pub_of(&k1)], None);
        assert!(vouch(&only_k1, &[t1.clone(), t2.clone()], &k3_rsa), "bout de chaîne");
        assert!(!vouch(&only_k1, &[t1.clone(), t2.clone()], &k2_rsa), "clé intermédiaire");
        assert!(!vouch(&only_k1, &[], &k3_rsa), "sans chaîne");
        assert!(!vouch(&h(&[], None), &[t1.clone(), t2.clone()], &k3_rsa), "aucune clé de signature épinglée");
        assert!(
            !chain_vouches(
                "u2",
                &SignHistory { keys: &only_k1.0, bound_rsa: None },
                &[t1.clone(), t2.clone()],
                "épinglée",
                &k3_rsa
            ),
            "autre utilisateur"
        );
        let forged = sign_identity_transition(&attaquant, "u1", 0, &rsa3, &pub_of(&k3)).unwrap();
        assert!(!vouch(&only_k1, &[forged], &k3_rsa), "maillon non signé par l'épinglée");
        // Épingle de signature déjà avancée à k3 (délégation rouverte), épingle RSA restée en arrière :
        // accepté seulement si pins.rs a lié rsa3 à k3 en avançant (maillon signé par k2, retiré).
        let all = [pub_of(&k1), pub_of(&k2), pub_of(&k3)];
        assert!(vouch(&h(&all, Some(&k3_rsa)), &[t1.clone(), t2.clone()], &k3_rsa));
        assert!(!vouch(&h(&all, None), &[t1.clone(), t2.clone()], &k3_rsa), "sans liaison enregistrée");
        assert!(!vouch(&h(&all, Some(&k2_rsa)), &[t1.clone(), t2.clone()], &k3_rsa), "liaison différente");
        // I1 (revue) : k1 retirée et compromise ; branche k1 → (rsa_x, kA) → (rsa_evil, k2 = courante).
        let (ka, rsa_x, rsa_evil) = (EcSigningKey::generate(&mut OsRandom).unwrap(), jwk(7, 2048), jwk(8, 2048));
        let b1 = sign_identity_transition(&k1, "u1", 0, &rsa_x, &pub_of(&ka)).unwrap();
        let b2 = sign_identity_transition(&ka, "u1", 1, &rsa_evil, &pub_of(&k2)).unwrap();
        let evil = MemberKey::from_jwk_str(&rsa_evil).unwrap();
        let k1k2 = [pub_of(&k1), pub_of(&k2)];
        assert!(!vouch(&h(&k1k2, Some(&evil)), &[b1.clone(), b2.clone()], &evil), "branche qui finit sur la courante");
        assert!(
            !vouch(&h(&k1k2, None), &[b1.clone(), b2, t2.clone()], &k3_rsa),
            "branche, puis maillon de la courante"
        );
        // Maillon forgé par k1 (retirée) vers k2 avec une autre clé RSA : pas de liaison → refus.
        let f12 = sign_identity_transition(&k1, "u1", 0, &rsa_evil, &pub_of(&k2)).unwrap();
        assert!(!vouch(&h(&k1k2, Some(&k2_rsa)), std::slice::from_ref(&f12), &evil), "liaison = rsa2, pas rsa_evil");
        // Sans clé plus récente que k1, une chaîne signée par k1 (courante) est suivie.
        let x_rsa = MemberKey::from_jwk_str(&rsa_x).unwrap();
        assert!(vouch(&only_k1, &[b1], &x_rsa));
        // I2 (revue) : chaîne qui aboutit à la clé RSA déjà épinglée : pas une rotation.
        let pinned_k3 = SignHistory { keys: &only_k1.0, bound_rsa: None };
        assert!(!chain_vouches("u1", &pinned_k3, &[t1.clone(), t2.clone()], &k3_rsa.fingerprint, &k3_rsa));
        // Rotation : seulement depuis l'épingle attendue.
        let mut s = MemberPinStore::in_memory();
        s.check("o", "u1", &key(1), 1);
        assert!(!s.rotate("o", "u1", &key(9).fingerprint, &k3_rsa), "épingle changée entre-temps");
        assert!(s.rotate("o", "u1", &key(1).fingerprint, &k3_rsa));
        assert_eq!(s.check("o", "u1", &k3_rsa, 2), Verdict::Trusted);
        assert_eq!(s.get("o", "u1").unwrap().previous, vec![key(1).fingerprint]);
        // I2 (revue) : retour arrière vers une clé précédente refusé (R1 → R3, puis R3 → R1 ou R3 → R3).
        assert!(!s.rotate("o", "u1", &k3_rsa.fingerprint, &key(1)), "retour arrière");
        assert!(!s.rotate("o", "u1", &k3_rsa.fingerprint, &k3_rsa), "même clé");
        assert!(s.rotate("o", "u1", &k3_rsa.fingerprint, &k2_rsa), "clé jamais épinglée");
        assert!(!s.rotate("o", "u1", &k2_rsa.fingerprint, &k3_rsa), "R3 → R2 → R3 : R3 est précédente");
    }

    #[test]
    fn bornes() {
        let mut s = MemberPinStore::in_memory();
        let k = key(1);
        for i in 0..MAX_PINS_PER_ORG {
            assert_eq!(s.check("o", &format!("u{i}"), &k, 1), Verdict::Pinned);
        }
        assert_eq!(s.check("o", "nouveau", &k, 1), Verdict::Full, "plafond par org");
        assert_eq!(s.check("o", "u0", &k, 1), Verdict::Trusted, "les épinglés restent vérifiés");
        assert_eq!(s.check("autre", "nouveau", &k, 1), Verdict::Pinned, "plafond par org");
        for i in 0..=MAX_PENDING_PER_ORG {
            s.refuse("o", &format!("u{i}"), &k.fingerprint, &key(2), 2);
        }
        assert_eq!(s.pending("o").len(), MAX_PENDING_PER_ORG, "attente bornée");
        let mut s = MemberPinStore::in_memory();
        s.check("o", "u", &key(0), 1);
        for seed in 1..=40u8 {
            let from = s.get("o", "u").unwrap().fingerprint.clone();
            assert!(s.rotate("o", "u", &from, &key(seed)));
        }
        assert_eq!(s.get("o", "u").unwrap().previous.len(), MAX_PREVIOUS);
    }

    #[test]
    fn ecriture_hors_verrou_et_dans_l_ordre() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = MemberPinStore::open(dir.path()).unwrap();
        assert!(s.snapshot().unwrap().is_none(), "rien à écrire");
        s.check("o", "u1", &key(1), 1);
        let first = s.snapshot().unwrap().unwrap();
        s.check("o", "u2", &key(2), 1);
        let second = s.snapshot().unwrap().unwrap();
        assert!(s.snapshot().unwrap().is_none(), "une photo par lot de modifications");
        second.write().unwrap();
        first.write().unwrap();
        let reopened = MemberPinStore::open(dir.path()).unwrap();
        assert!(reopened.get("o", "u2").is_some(), "la photo la plus ancienne n'écrase pas la plus récente");
    }

    #[test]
    fn persistance_et_fichier_public() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut s = MemberPinStore::open(dir.path()).unwrap();
            s.check("o1", "u1", &key(1), 1);
            assert_eq!(s.check("o1", "u1", &key(2), 2), Verdict::Changed);
            s.refuse("o1", "u1", &key(1).fingerprint, &key(2), 2);
            s.flush().unwrap();
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
        // Version inconnue : refus (revue M5).
        std::fs::write(dir.path().join(MEMBER_PINS_FILE), br#"{"v":2,"orgs":{}}"#).unwrap();
        assert!(MemberPinStore::open(dir.path()).is_err());
        std::fs::write(dir.path().join(MEMBER_PINS_FILE), br#"{"v":1,"orgs":{}}"#).unwrap();
        assert!(MemberPinStore::open(dir.path()).is_ok());
    }
}
