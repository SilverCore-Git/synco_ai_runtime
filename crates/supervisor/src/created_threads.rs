//! Registre des salons créés par ce runtime (`create_thread`, 03 §10.1), persisté dans
//! `created_threads.json` : salon → (utilisateur, délégation créatrice).
//!
//! Il sert à la réparation d'une enveloppe `rt1` (Q21, spec API §14.8) : à `thread.envelope_reset`,
//! le serveur n'est pas de confiance, le runtime ne signe que pour un salon **qu'il a créé lui-même**
//! pour cet utilisateur. Données non secrètes (identifiants seulement). Borné : au-delà de
//! [`MAX_CREATED_THREADS`], un nouveau salon n'est plus enregistré (il ne pourra pas être réparé).
//!
//! PC33 : le fichier est scellé par HMAC ([`crate::sealed_file`]). MAC invalide : registre **vide**
//! (rien n'est signé), [`CreatedThreadStore::tampered`] pour l'alerte du dashboard.
//!
//! PC32 : les salons créés **avant** L08b ne sont pas dans le registre et ne sont pas réparables.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::keys::RuntimeKeys;
use crate::sealed_file::{Loaded, MacKey, SealedFile, Snapshot};

/// Nom du fichier.
pub const CREATED_THREADS_FILE: &str = "created_threads.json";
/// Salons enregistrés au plus.
pub const MAX_CREATED_THREADS: usize = 10_000;

/// Salon créé par le runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedThread {
    /// Utilisateur pour qui il a été créé (propriétaire de la conversation).
    pub user_id: String,
    /// Délégation avec laquelle l'enveloppe `rt1` initiale a été signée (`creatorId` = `rt1:<id>`).
    pub delegation_id: String,
}

/// Registre des salons créés.
#[derive(Debug)]
pub struct CreatedThreadStore {
    file: Option<SealedFile>,
    map: BTreeMap<String, CreatedThread>,
    tampered: bool,
}

impl CreatedThreadStore {
    /// En mémoire seulement.
    #[must_use]
    pub const fn in_memory() -> Self {
        Self { file: None, map: BTreeMap::new(), tampered: false }
    }

    /// Ouvre le fichier. Absent : vide. MAC
    /// invalide, fichier modifié ou sans MAC (ancien format L08b, refusé) : registre vide, fichier mis de côté, [`Self::tampered`]. Une
    /// erreur d'entrée/sortie reste une erreur (jamais un registre vide silencieux).
    pub fn open(state_dir: &Path, keys: &RuntimeKeys) -> Result<Self> {
        let mut file = SealedFile::new(state_dir, CREATED_THREADS_FILE, MacKey::derive(keys, CREATED_THREADS_FILE)?);
        let (map, tampered) = match file.load::<BTreeMap<String, CreatedThread>>()? {
            Loaded::Absent => (BTreeMap::new(), false),
            Loaded::Sealed(m) => (m, false),
            Loaded::Tampered => {
                file.quarantine();
                (BTreeMap::new(), true)
            }
        };
        Ok(Self { file: Some(file), map, tampered })
    }

    /// Lie le registre à l'org (à l'appairage) : lu pour une autre org, il est mis de côté et le
    /// registre est vide ([`Self::take_tampered`] : alerte). Sans fichier : sans effet.
    pub fn bind_org(&mut self, org: &str) {
        if let Some(f) = &mut self.file
            && !f.bind_org(org)
        {
            self.map.clear();
            self.tampered = true;
        }
    }

    /// Le fichier lu était altéré (MAC invalide) : à signaler une fois au dashboard.
    #[must_use]
    pub fn take_tampered(&mut self) -> bool {
        std::mem::take(&mut self.tampered)
    }

    fn mark_dirty(&mut self) {
        if let Some(f) = &mut self.file {
            f.mark_dirty();
        }
    }

    /// Photo de l'état s'il a changé, à écrire **hors** du verrou d'état ([`Snapshot::write`]).
    pub fn snapshot(&mut self) -> Result<Option<Snapshot>> {
        match &mut self.file {
            Some(f) => f.snapshot(&self.map),
            None => Ok(None),
        }
    }

    /// Après un échec d'écriture : la prochaine photo réécrira tout.
    pub fn mark_unsaved(&mut self) {
        self.mark_dirty();
    }

    /// Écrit tout de suite (démarrage, tests) : à ne pas appeler sous le verrou d'état.
    pub fn flush(&mut self) -> Result<()> {
        match &mut self.file {
            Some(f) => f.flush(&self.map),
            None => Ok(()),
        }
    }

    /// Enregistre un salon créé (écriture à faire ensuite par [`Self::snapshot`]) ; `false` si le
    /// plafond est atteint (rien n'est enregistré).
    pub fn record(&mut self, thread_id: &str, user_id: &str, delegation_id: &str) -> bool {
        if !self.map.contains_key(thread_id) && self.map.len() >= MAX_CREATED_THREADS {
            return false;
        }
        let entry = CreatedThread { user_id: user_id.to_owned(), delegation_id: delegation_id.to_owned() };
        if self.map.get(thread_id) != Some(&entry) {
            self.map.insert(thread_id.to_owned(), entry);
            self.mark_dirty();
        }
        true
    }

    /// Salon créé par ce runtime ?
    #[must_use]
    pub fn get(&self, thread_id: &str) -> Option<&CreatedThread> {
        self.map.get(thread_id)
    }

    /// Oublie le contenu en mémoire (ne peut pas échouer) ; le fichier est effacé ensuite par
    /// [`Self::clear`].
    pub fn forget(&mut self) {
        self.map.clear();
    }

    /// Tout oublier et **effacer le fichier** (désappairage : les salons sont ceux d'une org). Échec
    /// d'effacement : erreur, le désappairage ne doit pas laisser un registre sur le disque.
    pub fn clear(&mut self) -> Result<()> {
        self.map.clear();
        match &mut self.file {
            Some(f) => f.erase(),
            None => Ok(()),
        }
    }

    /// Nombre de salons enregistrés.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Registre vide ?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> RuntimeKeys {
        crate::keys::generate().unwrap()
    }

    #[test]
    fn persiste_et_borne() {
        let (dir, k) = (tempfile::tempdir().unwrap(), keys());
        let mut s = CreatedThreadStore::open(dir.path(), &k).unwrap();
        s.bind_org("org1");
        assert!(s.is_empty());
        assert!(s.record("t1", "u1", "d1"));
        s.flush().unwrap();
        let reopened = CreatedThreadStore::open(dir.path(), &k).unwrap();
        assert_eq!(reopened.get("t1"), Some(&CreatedThread { user_id: "u1".into(), delegation_id: "d1".into() }));
        assert!(reopened.get("t2").is_none());
        for i in 0..MAX_CREATED_THREADS {
            let _ = s.record(&format!("x{i}"), "u1", "d1");
        }
        assert_eq!(s.len(), MAX_CREATED_THREADS);
        assert!(!s.record("de-trop", "u1", "d1"), "plafond");
        assert!(s.record("t1", "u1", "d2"), "un salon connu reste mis à jour");
    }

    /// PC33 : un fichier modifié (corps ou MAC) ne donne jamais un salon réparable.
    #[test]
    fn mac_altere_registre_vide() {
        let (dir, k) = (tempfile::tempdir().unwrap(), keys());
        let mut s = CreatedThreadStore::open(dir.path(), &k).unwrap();
        s.bind_org("org1");
        assert!(s.record("t1", "u1", "d1"));
        s.flush().unwrap();
        let path = dir.path().join(CREATED_THREADS_FILE);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"mac\""), "scellé : {text}");
        // Un salon ajouté à la main dans le corps, MAC inchangé.
        std::fs::write(&path, text.replace("t1", "t2")).unwrap();
        let mut bad = CreatedThreadStore::open(dir.path(), &k).unwrap();
        bad.bind_org("org1");
        assert!(bad.is_empty() && bad.get("t2").is_none(), "registre vide");
        assert!(bad.take_tampered());
        assert!(!bad.take_tampered(), "signalé une fois");
        assert!(dir.path().join("created_threads.rejected").exists(), "fichier refusé mis de côté");
        // Le runtime continue : il enregistre à nouveau, scellé.
        assert!(bad.record("t3", "u1", "d1"));
        bad.flush().unwrap();
        assert!(CreatedThreadStore::open(dir.path(), &k).unwrap().get("t3").is_some());
        // Un fichier scellé par un autre runtime (autres clés) est refusé de même.
        assert!(CreatedThreadStore::open(dir.path(), &keys()).unwrap().is_empty());
    }

    /// Ancien format de L08b (JSON nu, jamais livré) : refusé comme altéré, registre vide, rien
    /// n'est réparable.
    #[test]
    fn ancien_format_refuse_comme_altere() {
        let (dir, k) = (tempfile::tempdir().unwrap(), keys());
        let path = dir.path().join(CREATED_THREADS_FILE);
        std::fs::write(&path, br#"{"t1":{"userId":"u1","delegationId":"d1"}}"#).unwrap();
        let mut s = CreatedThreadStore::open(dir.path(), &k).unwrap();
        assert!(s.is_empty() && s.get("t1").is_none(), "registre vide : aucune signature possible");
        assert!(s.take_tampered(), "alerte");
        assert!(dir.path().join("created_threads.rejected").exists(), "fichier mis de côté");
        assert!(!path.exists());
    }

    /// Retour en arrière : un registre scellé pour l'org A n'est pas adopté après un appairage à B.
    #[test]
    fn registre_d_une_autre_org_rejete() {
        let (dir, k) = (tempfile::tempdir().unwrap(), keys());
        let mut s = CreatedThreadStore::open(dir.path(), &k).unwrap();
        s.bind_org("orgA");
        assert!(s.record("t1", "u1", "d1"));
        s.flush().unwrap();
        let mut same = CreatedThreadStore::open(dir.path(), &k).unwrap();
        same.bind_org("orgA");
        assert!(same.get("t1").is_some() && !same.take_tampered(), "même org : adopté");
        let mut other = CreatedThreadStore::open(dir.path(), &k).unwrap();
        assert!(other.get("t1").is_some(), "lu avant que l'org soit connue");
        other.bind_org("orgB");
        assert!(other.is_empty() && other.take_tampered(), "autre org : vide et alerte");
        assert!(dir.path().join("created_threads.rejected").exists());
    }

    #[test]
    fn clear_efface_le_fichier() {
        let (dir, k) = (tempfile::tempdir().unwrap(), keys());
        let mut s = CreatedThreadStore::open(dir.path(), &k).unwrap();
        s.bind_org("org1");
        s.record("t1", "u1", "d1");
        s.flush().unwrap();
        assert!(dir.path().join(CREATED_THREADS_FILE).exists());
        s.clear().unwrap();
        assert!(!dir.path().join(CREATED_THREADS_FILE).exists() && s.is_empty());
    }
}
