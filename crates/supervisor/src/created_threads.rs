//! Registre des salons créés par ce runtime (`create_thread`, 03 §10.1), persisté dans
//! `created_threads.json` : salon → (utilisateur, délégation créatrice).
//!
//! Il sert à la réparation d'une enveloppe `rt1` (Q21, spec API §14.8) : à `thread.envelope_reset`,
//! le serveur n'est pas de confiance, le runtime ne signe que pour un salon **qu'il a créé lui-même**
//! pour cet utilisateur. Données non secrètes (identifiants seulement). Borné : au-delà de
//! [`MAX_CREATED_THREADS`], un nouveau salon n'est plus enregistré (il ne pourra pas être réparé).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

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
    path: Option<PathBuf>,
    map: BTreeMap<String, CreatedThread>,
}

impl CreatedThreadStore {
    /// En mémoire seulement.
    #[must_use]
    pub const fn in_memory() -> Self {
        Self { path: None, map: BTreeMap::new() }
    }

    /// Ouvre le fichier (absent : vide ; illisible : erreur, jamais un registre vide silencieux).
    pub fn open(state_dir: &Path) -> Result<Self> {
        let path = state_dir.join(CREATED_THREADS_FILE);
        let map = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|_| Error::Io(format!("{CREATED_THREADS_FILE} illisible")))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(Error::Io(format!("{CREATED_THREADS_FILE} : {}", e.kind()))),
        };
        Ok(Self { path: Some(path), map })
    }

    fn save(&self) {
        if let Some(path) = &self.path {
            let res = serde_json::to_vec(&self.map)
                .map_err(|_| Error::Io("sérialisation".into()))
                .and_then(|b| crate::seal::write_atomic(path, &b));
            if let Err(e) = res {
                tracing::warn!(code = "created_threads_not_saved", error = %e, "salons créés non enregistrés");
            }
        }
    }

    /// Enregistre un salon créé ; `false` si le plafond est atteint (rien n'est enregistré).
    pub fn record(&mut self, thread_id: &str, user_id: &str, delegation_id: &str) -> bool {
        if !self.map.contains_key(thread_id) && self.map.len() >= MAX_CREATED_THREADS {
            return false;
        }
        let entry = CreatedThread { user_id: user_id.to_owned(), delegation_id: delegation_id.to_owned() };
        if self.map.get(thread_id) != Some(&entry) {
            self.map.insert(thread_id.to_owned(), entry);
            self.save();
        }
        true
    }

    /// Salon créé par ce runtime ?
    #[must_use]
    pub fn get(&self, thread_id: &str) -> Option<&CreatedThread> {
        self.map.get(thread_id)
    }

    /// Tout oublier (désappairage : les salons sont ceux d'une org).
    pub fn clear(&mut self) {
        if !self.map.is_empty() {
            self.map.clear();
            self.save();
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

    #[test]
    fn persiste_et_borne() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = CreatedThreadStore::open(dir.path()).unwrap();
        assert!(s.is_empty());
        assert!(s.record("t1", "u1", "d1"));
        let reopened = CreatedThreadStore::open(dir.path()).unwrap();
        assert_eq!(reopened.get("t1"), Some(&CreatedThread { user_id: "u1".into(), delegation_id: "d1".into() }));
        assert!(reopened.get("t2").is_none());
        for i in 0..MAX_CREATED_THREADS {
            let _ = s.record(&format!("x{i}"), "u1", "d1");
        }
        assert_eq!(s.len(), MAX_CREATED_THREADS);
        assert!(!s.record("de-trop", "u1", "d1"), "plafond");
        assert!(s.record("t1", "u1", "d2"), "un salon connu reste mis à jour");
    }

    #[test]
    fn fichier_illisible_refuse_de_demarrer() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(CREATED_THREADS_FILE), b"pas du json").unwrap();
        assert!(CreatedThreadStore::open(dir.path()).is_err());
    }
}
