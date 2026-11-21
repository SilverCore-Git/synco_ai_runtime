//! Fichiers d'état scellés par HMAC-SHA256 (PC33, revue L08b).
//!
//! Le registre des salons créés et la file de réparations décident de ce que le runtime **signe**
//! (`thread.envelope_reset`) : un fichier modifié par quelqu'un d'autre ne doit jamais l'y pousser.
//! Chaque fichier porte donc un MAC, sous une clé dérivée (HKDF, étiquette propre au fichier) du
//! matériel de `keys.sealed` — que seul le runtime détient :
//!
//! ```json
//! { "v": 2, "body": "<JSON du contenu, en texte>", "mac": "<base64url HMAC-SHA256(clé, body)>" }
//! ```
//!
//! - MAC invalide, fichier illisible ou forme inconnue : [`Loaded::Tampered`] (l'appelant considère le
//!   contenu comme vide et lève une alerte ; le fichier refusé est mis de côté en `.rejected`).
//! - Ancien format (sans MAC, L08b) : [`Loaded::Legacy`], lu **une fois** puis réécrit scellé (règle
//!   de rétrocompatibilité : on lit l'ancien, on n'écrit que le nouveau). Limite assumée : qui peut
//!   écrire dans le répertoire d'état peut donc aussi déposer un fichier sans MAC ; le MAC protège
//!   contre une modification qui ne sait pas produire ce format (ou le répertoire en lecture seule
//!   pour un autre canal), pas contre un attaquant déjà maître du répertoire et de ce choix.
//!
//! L'écriture se fait **hors** du verrou d'état : [`SealedFile::snapshot`] prend l'état sous le
//! verrou, [`Snapshot::write`] l'écrit ensuite (`spawn_blocking`), comme `member_pins`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use synco_e2ee::encoding::{b64u, from_b64u};
use synco_e2ee::primitives::{hkdf32, hmac_sha256, hmac_sha256_verify};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::keys::RuntimeKeys;

const FORMAT: u32 = 2;
const SALT: &[u8] = b"synco-ai-runtime/state-mac/v1";

/// Clé de MAC d'un fichier, dérivée du matériel de `keys.sealed` (jamais écrite).
pub struct MacKey(Zeroizing<[u8; 32]>);

impl core::fmt::Debug for MacKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MacKey(..)")
    }
}

impl MacKey {
    /// Dérive la clé du fichier `label` (une étiquette distincte par fichier : un fichier ne se
    /// substitue pas à un autre).
    pub fn derive(keys: &RuntimeKeys, label: &str) -> Result<Self> {
        let secret = keys.to_secret_bytes();
        let info = format!("file:{label}");
        hkdf32(secret.as_slice(), SALT, info.as_bytes())
            .map(Self)
            .map_err(|_| Error::KeyStore("dérivation de la clé de MAC".into()))
    }
}

#[derive(Serialize, Deserialize)]
struct Sealed {
    v: u32,
    body: String,
    mac: String,
}

/// Résultat de la lecture d'un fichier scellé.
#[derive(Debug, PartialEq, Eq)]
pub enum Loaded<T> {
    /// Fichier absent.
    Absent,
    /// Fichier scellé, MAC valide.
    Sealed(T),
    /// Ancien format sans MAC (à réécrire scellé).
    Legacy(T),
    /// MAC invalide, fichier modifié ou illisible : le contenu n'est pas fiable.
    Tampered,
}

/// État à écrire, pris sous le verrou d'état et écrit hors de lui.
#[derive(Debug)]
pub struct Snapshot {
    path: PathBuf,
    bytes: Vec<u8>,
    generation: u64,
    written: Arc<Mutex<u64>>,
}

impl Snapshot {
    /// Écrit l'état (temporaire, `fsync`, `rename`). Une photo plus ancienne que la dernière écrite
    /// (ou qu'un effacement) est ignorée : l'ordre est préservé.
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

/// Un fichier scellé : chemin, clé, et suivi des écritures.
#[derive(Debug)]
pub struct SealedFile {
    path: PathBuf,
    key: MacKey,
    dirty: bool,
    generation: u64,
    written: Arc<Mutex<u64>>,
}

impl SealedFile {
    /// Fichier `name` du répertoire d'état.
    #[must_use]
    pub fn new(state_dir: &Path, name: &str, key: MacKey) -> Self {
        Self { path: state_dir.join(name), key, dirty: false, generation: 0, written: Arc::new(Mutex::new(0)) }
    }

    /// Lit le fichier. `legacy` : un contenu de l'ancien format (JSON nu) est accepté
    /// ([`Loaded::Legacy`]). Une erreur d'entrée/sortie autre que « absent » est une erreur (jamais
    /// un registre vide silencieux).
    pub fn load<T: DeserializeOwned>(&self, legacy: bool) -> Result<Loaded<T>> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Loaded::Absent),
            Err(e) => return Err(Error::Io(format!("{} : {}", self.name(), e.kind()))),
        };
        Ok(self.decode(&bytes, legacy))
    }

    fn name(&self) -> String {
        self.path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned())
    }

    fn decode<T: DeserializeOwned>(&self, bytes: &[u8], legacy: bool) -> Loaded<T> {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return Loaded::Tampered;
        };
        // Forme scellée : exactement `v`, `body`, `mac`. Toute autre forme est l'ancien format.
        let sealed_shape = value
            .as_object()
            .is_some_and(|o| o.len() == 3 && o.contains_key("v") && o.contains_key("body") && o.contains_key("mac"));
        if sealed_shape {
            let Ok(sealed) = serde_json::from_value::<Sealed>(value) else {
                return Loaded::Tampered;
            };
            let valid = sealed.v == FORMAT
                && from_b64u(&sealed.mac)
                    .is_ok_and(|tag| hmac_sha256_verify(self.key.0.as_slice(), sealed.body.as_bytes(), &tag));
            if !valid {
                return Loaded::Tampered;
            }
            return serde_json::from_str(&sealed.body).map_or(Loaded::Tampered, Loaded::Sealed);
        }
        if legacy {
            return serde_json::from_value(value).map_or(Loaded::Tampered, Loaded::Legacy);
        }
        Loaded::Tampered
    }

    /// Met de côté un fichier refusé (`.rejected`, un seul exemplaire) : la preuve reste pour
    /// l'administrateur, et le prochain enregistrement ne l'écrase pas en silence.
    pub fn quarantine(&self) {
        let _ = std::fs::rename(&self.path, self.path.with_extension("rejected"));
    }

    /// Une modification est à écrire.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Photo du contenu s'il a changé (`None` : rien à écrire).
    pub fn snapshot<T: Serialize>(&mut self, value: &T) -> Result<Option<Snapshot>> {
        if !self.dirty {
            return Ok(None);
        }
        let body = serde_json::to_string(value).map_err(|_| Error::Io("sérialisation".into()))?;
        let tag = hmac_sha256(self.key.0.as_slice(), body.as_bytes()).map_err(|_| Error::Io("MAC".into()))?;
        let bytes = serde_json::to_vec(&Sealed { v: FORMAT, body, mac: b64u(&tag) })
            .map_err(|_| Error::Io("sérialisation".into()))?;
        self.dirty = false;
        self.generation = self.generation.saturating_add(1);
        Ok(Some(Snapshot {
            path: self.path.clone(),
            bytes,
            generation: self.generation,
            written: Arc::clone(&self.written),
        }))
    }

    /// Écrit tout de suite (démarrage, tests) : à ne pas appeler sous le verrou d'état.
    pub fn flush<T: Serialize>(&mut self, value: &T) -> Result<()> {
        match self.snapshot(value)? {
            Some(s) => s.write(),
            None => Ok(()),
        }
    }

    /// Efface le fichier (désappairage). Une photo prise avant ne le recrée pas. Échec (autre
    /// que « absent ») : erreur, l'appelant ne doit pas faire comme si de rien n'était.
    pub fn erase(&mut self) -> Result<()> {
        let mut last = self.written.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        self.generation = self.generation.saturating_add(1);
        *last = self.generation;
        self.dirty = false;
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Io(format!("effacement de {} : {}", self.name(), e.kind()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn file(dir: &Path, label: &str) -> SealedFile {
        SealedFile::new(dir, "x.json", MacKey(Zeroizing::new(synco_e2ee::primitives::sha256(label.as_bytes()))))
    }

    #[test]
    fn cle_propre_a_chaque_fichier_et_a_chaque_runtime() {
        let (k1, k2) = (crate::keys::generate().unwrap(), crate::keys::generate().unwrap());
        let d = |k: &RuntimeKeys, l: &str| MacKey::derive(k, l).unwrap().0;
        assert_eq!(*d(&k1, "a"), *d(&k1, "a"));
        assert_ne!(*d(&k1, "a"), *d(&k1, "b"));
        assert_ne!(*d(&k1, "a"), *d(&k2, "a"));
    }

    type M = BTreeMap<String, String>;

    #[test]
    fn scelle_puis_relu_et_altere() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = file(dir.path(), "a");
        assert_eq!(f.load::<M>(true).unwrap(), Loaded::Absent);
        f.mark_dirty();
        let mut m = M::new();
        m.insert("t".into(), "u".into());
        f.flush(&m).unwrap();
        assert_eq!(f.load::<M>(true).unwrap(), Loaded::Sealed(m.clone()));
        // Autre clé (autre fichier, autre runtime) : refusé.
        assert_eq!(file(dir.path(), "b").load::<M>(true).unwrap(), Loaded::Tampered);
        // Corps modifié, MAC inchangé.
        let text = std::fs::read_to_string(dir.path().join("x.json")).unwrap().replace("\\\"u\\\"", "\\\"v\\\"");
        std::fs::write(dir.path().join("x.json"), text).unwrap();
        assert_eq!(f.load::<M>(true).unwrap(), Loaded::Tampered);
        // Illisible.
        std::fs::write(dir.path().join("x.json"), b"pas du json").unwrap();
        assert_eq!(f.load::<M>(true).unwrap(), Loaded::Tampered);
    }

    #[test]
    fn ancien_format_lu_une_fois() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("x.json"), br#"{"t":"u"}"#).unwrap();
        let f = file(dir.path(), "a");
        assert!(matches!(f.load::<M>(true).unwrap(), Loaded::Legacy(_)));
        assert_eq!(f.load::<M>(false).unwrap(), Loaded::Tampered, "sans rétrocompatibilité : refusé");
    }

    #[test]
    fn photo_ancienne_ignoree_apres_effacement() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = file(dir.path(), "a");
        f.mark_dirty();
        let snap = f.snapshot(&M::new()).unwrap().unwrap();
        f.erase().unwrap();
        snap.write().unwrap();
        assert!(!dir.path().join("x.json").exists(), "la photo d'avant l'effacement ne recrée rien");
    }
}
