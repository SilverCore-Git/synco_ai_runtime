//! File persistante des réparations d'enveloppe `rt1` en attente (PC31, revue L08b).
//!
//! Une trame `thread.envelope_reset` valide peut arriver avant que la clé du salon ou la délégation
//! soit chargée (`envelope_reset_key_missing`). Au lieu de la jeter, le runtime la range ici
//! (salon, utilisateur, délégation) ; elle est rejouée à l'arrivée d'entrées, au chargement d'une
//! délégation et à chaque reconnexion du flux. **Rien ici n'autorise une signature** : chaque rejeu
//! refait toutes les vérifications locales (registre des salons créés, délégation, clé).
//!
//! Bornée ([`MAX_REPAIRS`]), dédupliquée, vieillie ([`MAX_AGE_SECS`]) et scellée par HMAC comme le
//! registre ([`crate::sealed_file`]) : un fichier altéré donne une file vide et une alerte.
//! Fichier `envelope_repairs.json` du répertoire d'état. Données non secrètes (identifiants).

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::keys::RuntimeKeys;
use crate::sealed_file::{Loaded, MacKey, SealedFile, Snapshot};

/// Nom du fichier.
pub const REPAIRS_FILE: &str = "envelope_repairs.json";
/// Réparations en attente au plus.
pub const MAX_REPAIRS: usize = 10_000;
/// Une réparation jamais satisfaite est abandonnée après 30 jours.
pub const MAX_AGE_SECS: u64 = 30 * 86_400;

/// Une réparation demandée : identité de la file (la date n'en fait pas partie).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Repair {
    /// Salon.
    pub thread_id: String,
    /// Utilisateur.
    pub user_id: String,
    /// Délégation avec laquelle signer.
    pub delegation_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Stored {
    thread_id: String,
    user_id: String,
    delegation_id: String,
    at: u64,
}

/// Résultat d'un ajout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Push {
    /// Ajoutée.
    Added,
    /// Déjà dans la file.
    Known,
    /// File pleine : rien n'est ajouté.
    Full,
}

/// File des réparations.
#[derive(Debug)]
pub struct RepairQueue {
    file: Option<SealedFile>,
    items: BTreeMap<Repair, u64>,
    tampered: bool,
}

impl RepairQueue {
    /// En mémoire seulement.
    #[must_use]
    pub const fn in_memory() -> Self {
        Self { file: None, items: BTreeMap::new(), tampered: false }
    }

    /// Ouvre le fichier (absent : vide). MAC invalide, fichier modifié ou sans MAC (ce fichier n'a
    /// pas d'ancien format) : file vide, fichier mis de côté, [`Self::take_tampered`].
    pub fn open(state_dir: &Path, keys: &RuntimeKeys) -> Result<Self> {
        let file = SealedFile::new(state_dir, REPAIRS_FILE, MacKey::derive(keys, REPAIRS_FILE)?);
        let (stored, tampered) = match file.load::<Vec<Stored>>(false)? {
            Loaded::Absent => (Vec::new(), false),
            Loaded::Sealed(v) | Loaded::Legacy(v) => (v, false),
            Loaded::Tampered => {
                file.quarantine();
                (Vec::new(), true)
            }
        };
        let items = stored
            .into_iter()
            .take(MAX_REPAIRS)
            .map(|s| (Repair { thread_id: s.thread_id, user_id: s.user_id, delegation_id: s.delegation_id }, s.at))
            .collect();
        Ok(Self { file: Some(file), items, tampered })
    }

    /// Le fichier lu était altéré : à signaler une fois au dashboard.
    #[must_use]
    pub fn take_tampered(&mut self) -> bool {
        std::mem::take(&mut self.tampered)
    }

    fn mark_dirty(&mut self) {
        if let Some(f) = &mut self.file {
            f.mark_dirty();
        }
    }

    /// Ajoute une réparation (dédupliquée sur salon + utilisateur + délégation).
    pub fn push(&mut self, repair: Repair, now: u64) -> Push {
        if self.items.contains_key(&repair) {
            return Push::Known;
        }
        if self.items.len() >= MAX_REPAIRS {
            return Push::Full;
        }
        self.items.insert(repair, now);
        self.mark_dirty();
        Push::Added
    }

    /// Retire une réparation (faite, refusée pour de bon, ou plus d'actualité).
    pub fn remove(&mut self, repair: &Repair) {
        if self.items.remove(repair).is_some() {
            self.mark_dirty();
        }
    }

    /// Abandonne les réparations trop anciennes.
    pub fn expire(&mut self, now: u64) {
        let before = self.items.len();
        self.items.retain(|_, at| now.saturating_sub(*at) < MAX_AGE_SECS);
        if self.items.len() != before {
            self.mark_dirty();
        }
    }

    /// Réparations en attente.
    #[must_use]
    pub fn items(&self) -> Vec<Repair> {
        self.items.keys().cloned().collect()
    }

    /// Nombre en attente.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// File vide ?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Photo de l'état s'il a changé, à écrire hors du verrou d'état.
    pub fn snapshot(&mut self) -> Result<Option<Snapshot>> {
        let stored: Vec<Stored> = self
            .items
            .iter()
            .map(|(r, at)| Stored {
                thread_id: r.thread_id.clone(),
                user_id: r.user_id.clone(),
                delegation_id: r.delegation_id.clone(),
                at: *at,
            })
            .collect();
        match &mut self.file {
            Some(f) => f.snapshot(&stored),
            None => Ok(None),
        }
    }

    /// Après un échec d'écriture : la prochaine photo réécrira tout.
    pub fn mark_unsaved(&mut self) {
        self.mark_dirty();
    }

    /// Écrit tout de suite (tests) : à ne pas appeler sous le verrou d'état.
    pub fn flush(&mut self) -> Result<()> {
        match self.snapshot()? {
            Some(s) => s.write(),
            None => Ok(()),
        }
    }

    /// Tout oublier et effacer le fichier (désappairage). Échec : erreur.
    pub fn clear(&mut self) -> Result<()> {
        self.items.clear();
        match &mut self.file {
            Some(f) => f.erase(),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(t: &str) -> Repair {
        Repair { thread_id: t.into(), user_id: "u".into(), delegation_id: "d".into() }
    }

    #[test]
    fn dedupe_borne_vieillit_et_survit() {
        let (dir, keys) = (tempfile::tempdir().unwrap(), crate::keys::generate().unwrap());
        let mut q = RepairQueue::open(dir.path(), &keys).unwrap();
        assert_eq!(q.push(r("t1"), 100), Push::Added);
        assert_eq!(q.push(r("t1"), 200), Push::Known, "dédupliquée, date d'origine gardée");
        q.flush().unwrap();
        let mut again = RepairQueue::open(dir.path(), &keys).unwrap();
        assert_eq!(again.items(), vec![r("t1")], "survit à un redémarrage");
        for i in 0..MAX_REPAIRS {
            let _ = again.push(r(&format!("x{i}")), 100);
        }
        assert_eq!(again.len(), MAX_REPAIRS);
        assert_eq!(again.push(r("de-trop"), 100), Push::Full);
        again.expire(100 + MAX_AGE_SECS);
        assert!(again.is_empty(), "abandonnée après 30 jours");
    }

    #[test]
    fn mac_altere_file_vide() {
        let (dir, keys) = (tempfile::tempdir().unwrap(), crate::keys::generate().unwrap());
        let mut q = RepairQueue::open(dir.path(), &keys).unwrap();
        q.push(r("t1"), 1);
        q.flush().unwrap();
        let path = dir.path().join(REPAIRS_FILE);
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("t1", "t2")).unwrap();
        let mut bad = RepairQueue::open(dir.path(), &keys).unwrap();
        assert!(bad.is_empty() && bad.take_tampered());
        // Sans MAC (ce fichier n'a pas d'ancien format) : refusé de même.
        std::fs::write(&path, br#"[{"threadId":"t","userId":"u","delegationId":"d","at":1}]"#).unwrap();
        let mut bare = RepairQueue::open(dir.path(), &keys).unwrap();
        assert!(bare.is_empty() && bare.take_tampered());
    }
}
