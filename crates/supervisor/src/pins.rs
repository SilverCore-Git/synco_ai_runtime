//! Épinglage TOFU des clés de signature des utilisateurs (Q3, docs/plan/03 §4 étape 2).
//!
//! - Première vue : la clé servie par `GET /api/runtime/v1/users/:userId/sign-key` est épinglée.
//! - Ensuite : la clé servie doit être l'épinglée, ou figurer sur une chaîne de transitions
//!   d'identité valide **partant de l'épinglée** (`identity_chain_path` de `synco-e2ee`, portage
//!   de `identityChainPath`) ; l'épingle avance alors. Sinon : refus et alerte (dashboard).
//!
//! Limite assumée (00 §6 Q3) : au tout premier contact, la clé vient de l'API.
//! Fichier `user-pins.json` du répertoire d'état : données **publiques** uniquement.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use synco_e2ee::ec::EcPublicKey;
use synco_e2ee::identity::{IdentityTransition, ec_canonical_json, identity_chain_path};

use crate::error::{Error, Result};

/// Nom du fichier.
pub const PINS_FILE: &str = "user-pins.json";

/// Épingle d'un utilisateur.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserPin {
    /// Clé de signature épinglée (JWK canonique RFC 7638).
    pub sign_key: String,
    /// Première vue (s).
    pub first_seen: u64,
    /// Clés précédentes (transitions suivies).
    #[serde(default)]
    pub previous: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PinFile {
    v: u8,
    users: BTreeMap<String, UserPin>,
}

/// Refus de l'épinglage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinError {
    /// Aucune clé servie, ou clé illisible.
    NoKey,
    /// Clé différente de l'épinglée, sans chaîne valide : alerte.
    KeyChanged,
}

impl PinError {
    /// Code machine (dashboard, journal).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoKey => "user_sign_key_missing",
            Self::KeyChanged => "user_sign_key_changed",
        }
    }
}

/// Clés de confiance d'un utilisateur, à essayer pour vérifier son mandat : la clé courante, puis
/// les précédentes de la chaîne (un mandat signé avant une rotation reste vérifiable).
#[derive(Debug, Clone)]
pub struct TrustedKeys(pub Vec<EcPublicKey>);

/// Magasin des épingles.
#[derive(Debug)]
pub struct PinStore {
    path: Option<PathBuf>,
    file: PinFile,
}

impl PinStore {
    /// Magasin en mémoire seulement (tests).
    #[must_use]
    pub fn in_memory() -> Self {
        Self { path: None, file: PinFile { v: 1, users: BTreeMap::new() } }
    }

    /// Ouvre `user-pins.json` (absent : vide).
    pub fn open(state_dir: &Path) -> Result<Self> {
        let path = state_dir.join(PINS_FILE);
        let file = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| Error::Io(format!("{PINS_FILE} illisible")))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => PinFile { v: 1, users: BTreeMap::new() },
            Err(e) => return Err(Error::Io(format!("{PINS_FILE} : {}", e.kind()))),
        };
        Ok(Self { path: Some(path), file })
    }

    fn save(&self) -> Result<()> {
        if let Some(path) = &self.path {
            let bytes = serde_json::to_vec_pretty(&self.file).map_err(|_| Error::Io("sérialisation".into()))?;
            crate::seal::write_atomic(path, &bytes)?;
        }
        Ok(())
    }

    /// Épingle d'un utilisateur.
    #[must_use]
    pub fn get(&self, user_id: &str) -> Option<&UserPin> {
        self.file.users.get(user_id)
    }

    /// Applique la règle TOFU à la clé servie et renvoie les clés de confiance.
    pub fn check_or_pin(
        &mut self,
        user_id: &str,
        served_sign_key: Option<&str>,
        chain: &[IdentityTransition],
        now: u64,
    ) -> core::result::Result<TrustedKeys, PinError> {
        let served = served_sign_key.and_then(|k| ec_canonical_json(k).ok()).ok_or(PinError::NoKey)?;
        let served_key = EcPublicKey::from_jwk(&served).map_err(|_| PinError::NoKey)?;
        let Some(pin) = self.file.users.get(user_id).cloned() else {
            self.file.users.insert(user_id.to_owned(), UserPin { sign_key: served, first_seen: now, previous: vec![] });
            self.persist();
            return Ok(TrustedKeys(vec![served_key]));
        };
        if pin.sign_key == served {
            return Ok(TrustedKeys(trusted(&served_key, &pin.previous)));
        }
        let path = identity_chain_path(user_id, &pin.sign_key, chain).map_err(|_| PinError::KeyChanged)?;
        let Some(pos) = path.iter().position(|k| k.public_sign_key == served) else {
            return Err(PinError::KeyChanged);
        };
        let mut previous = pin.previous;
        previous.push(pin.sign_key);
        previous.extend(path.iter().take(pos).map(|k| k.public_sign_key.clone()));
        let keys = trusted(&served_key, &previous);
        self.file.users.insert(user_id.to_owned(), UserPin { sign_key: served, first_seen: pin.first_seen, previous });
        self.persist();
        Ok(TrustedKeys(keys))
    }

    fn persist(&self) {
        if let Err(e) = self.save() {
            tracing::warn!(code = "pins_not_saved", error = %e, "épingles non enregistrées");
        }
    }
}

/// Clé courante d'abord, puis les précédentes (plus récentes d'abord).
fn trusted(current: &EcPublicKey, previous: &[String]) -> Vec<EcPublicKey> {
    let mut out = vec![current.clone()];
    out.extend(previous.iter().rev().filter_map(|k| EcPublicKey::from_jwk(k).ok()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use synco_e2ee::OsRandom;
    use synco_e2ee::ec::EcSigningKey;
    use synco_e2ee::identity::sign_identity_transition;

    const RSA: &str = r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#;

    fn key() -> EcSigningKey {
        EcSigningKey::generate(&mut OsRandom).unwrap()
    }

    fn jwk(k: &EcSigningKey) -> String {
        k.public_key().unwrap().to_canonical()
    }

    #[test]
    fn tofu_puis_chaine() {
        let mut store = PinStore::in_memory();
        let (k1, k2, k3) = (key(), key(), key());
        assert!(store.check_or_pin("u1", Some(&jwk(&k1)), &[], 1).is_ok(), "première vue");
        assert_eq!(store.check_or_pin("u1", Some(&jwk(&k1)), &[], 2).unwrap().0.len(), 1);
        // Clé changée sans chaîne : refus.
        assert_eq!(store.check_or_pin("u1", Some(&jwk(&k2)), &[], 3).unwrap_err(), PinError::KeyChanged);
        // Chaîne k1 → k2 → k3 signée par chaque ancienne clé : acceptée, l'épingle avance.
        let t1 = sign_identity_transition(&k1, "u1", 0, RSA, &jwk(&k2)).unwrap();
        let t2 = sign_identity_transition(&k2, "u1", 1, RSA, &jwk(&k3)).unwrap();
        let trusted = store.check_or_pin("u1", Some(&jwk(&k3)), &[t1.clone(), t2], 4).unwrap();
        assert_eq!(trusted.0.len(), 3, "k3 puis k2 et k1");
        assert_eq!(store.get("u1").unwrap().sign_key, jwk(&k3));
        // Retour à k1 (ancienne clé) : refusé, l'épingle ne recule pas.
        assert_eq!(store.check_or_pin("u1", Some(&jwk(&k1)), &[t1], 5).unwrap_err(), PinError::KeyChanged);
    }

    #[test]
    fn chaine_forgee_refusee() {
        let mut store = PinStore::in_memory();
        let (k1, k2, attaquant) = (key(), key(), key());
        store.check_or_pin("u1", Some(&jwk(&k1)), &[], 1).unwrap();
        // Transition vers k2 signée par une clé qui n'est pas l'épinglée.
        let forged = sign_identity_transition(&attaquant, "u1", 0, RSA, &jwk(&k2)).unwrap();
        assert_eq!(store.check_or_pin("u1", Some(&jwk(&k2)), &[forged], 2).unwrap_err(), PinError::KeyChanged);
        // Transition d'un autre utilisateur.
        let other_user = sign_identity_transition(&k1, "u2", 0, RSA, &jwk(&k2)).unwrap();
        assert_eq!(store.check_or_pin("u1", Some(&jwk(&k2)), &[other_user], 3).unwrap_err(), PinError::KeyChanged);
        assert_eq!(store.check_or_pin("u1", None, &[], 4).unwrap_err(), PinError::NoKey);
    }

    #[test]
    fn persistance() {
        let dir = tempfile::tempdir().unwrap();
        let k1 = key();
        let mut store = PinStore::open(dir.path()).unwrap();
        store.check_or_pin("u1", Some(&jwk(&k1)), &[], 1).unwrap();
        let reopened = PinStore::open(dir.path()).unwrap();
        assert_eq!(reopened.get("u1").unwrap().sign_key, jwk(&k1));
    }
}
