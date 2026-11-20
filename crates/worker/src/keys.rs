//! Clés reçues du superviseur (trames `0x02`, docs/plan/06 §2) : `CK` de **la** conversation et
//! clés de salon / d'espace de la délégation de son propriétaire. En mémoire uniquement, effacées à la
//! libération ([`SymmetricKey`]) ; jamais dans un journal ni dans une trame JSON.

use std::collections::BTreeMap;

use runtime_protocol::pipe::{KeyFrame, KeyKind, KeyOp};
use synco_e2ee::SymmetricKey;

/// Coffre du worker.
#[derive(Default)]
pub struct KeyStore {
    session_id: String,
    conv: Option<SymmetricKey>,
    threads: BTreeMap<String, BTreeMap<u32, SymmetricKey>>,
    spaces: BTreeMap<String, BTreeMap<u32, SymmetricKey>>,
}

impl core::fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyStore")
            .field("conv", &self.conv.is_some())
            .field("threads", &self.threads.len())
            .field("spaces", &self.spaces.len())
            .finish()
    }
}

fn latest(map: &BTreeMap<String, BTreeMap<u32, SymmetricKey>>, id: &str) -> Option<(u32, SymmetricKey)> {
    map.get(id).and_then(|v| v.iter().next_back()).map(|(v, k)| (*v, k.clone()))
}

impl KeyStore {
    /// Coffre de la conversation `session_id` : seule sa `CK` est retenue.
    #[must_use]
    pub fn new(session_id: &str) -> Self {
        Self { session_id: session_id.to_owned(), ..Self::default() }
    }

    /// Applique une trame de clés. Les secrets `llm_credential` (sans bac à sable) sont ignorés :
    /// le worker n'appelle le fournisseur que par le mandataire, qui ajoute la clé lui-même (D1).
    pub fn apply(&mut self, frame: &KeyFrame) {
        for e in &frame.entries {
            let key = match frame.op {
                KeyOp::Add => match SymmetricKey::from_slice(&e.key) {
                    Ok(k) => Some(k),
                    Err(_) => continue,
                },
                KeyOp::Remove => None,
            };
            match e.kind {
                KeyKind::Conv if e.reference == self.session_id => self.conv = key,
                KeyKind::Conv | KeyKind::LlmCredential => {}
                KeyKind::Thread | KeyKind::Space => {
                    let map = if e.kind == KeyKind::Thread { &mut self.threads } else { &mut self.spaces };
                    match key {
                        Some(k) => {
                            map.entry(e.reference.clone()).or_default().insert(e.version, k);
                        }
                        None => {
                            if let Some(v) = map.get_mut(&e.reference) {
                                v.remove(&e.version);
                                if v.is_empty() {
                                    map.remove(&e.reference);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// `CK` de la conversation.
    #[must_use]
    pub fn conv(&self) -> Option<SymmetricKey> {
        self.conv.clone()
    }

    /// Dernière version de la clé d'un salon.
    #[must_use]
    pub fn thread(&self, thread_id: &str) -> Option<SymmetricKey> {
        latest(&self.threads, thread_id).map(|(_, k)| k)
    }

    /// Dernière version de la clé d'un espace.
    #[must_use]
    pub fn space(&self, space_id: &str) -> Option<(u32, SymmetricKey)> {
        latest(&self.spaces, space_id)
    }

    /// Espaces dont une clé est détenue.
    #[must_use]
    pub fn space_ids(&self) -> Vec<String> {
        self.spaces.keys().cloned().collect()
    }

    /// Clé d'un salon que le worker vient de créer (gardée pour la suite de sa vie).
    pub fn insert_thread(&mut self, thread_id: &str, version: u32, key: SymmetricKey) {
        self.threads.entry(thread_id.to_owned()).or_default().insert(version, key);
    }

    /// Efface tout (fin du worker).
    pub fn clear(&mut self) {
        self.conv = None;
        self.threads.clear();
        self.spaces.clear();
    }
}

#[cfg(test)]
mod tests {
    use runtime_protocol::pipe::KeyEntry;
    use zeroize::Zeroizing;

    use super::*;

    fn e(kind: KeyKind, r: &str, v: u32, k: &[u8]) -> KeyEntry {
        KeyEntry { kind, reference: r.into(), version: v, key: Zeroizing::new(k.to_vec()) }
    }

    #[test]
    fn ajout_retrait() {
        let mut ks = KeyStore::new("s1");
        ks.apply(&KeyFrame {
            op: KeyOp::Add,
            entries: vec![
                e(KeyKind::Conv, "s1", 1, &[1; 32]),
                e(KeyKind::Conv, "autre", 1, &[2; 32]),
                e(KeyKind::Space, "w1", 1, &[3; 32]),
                e(KeyKind::Space, "w1", 2, &[4; 32]),
                e(KeyKind::Thread, "t1", 1, &[5; 32]),
            ],
        });
        assert_eq!(ks.conv().unwrap().as_bytes(), &[1; 32]);
        assert_eq!(ks.space("w1").unwrap().0, 2);
        assert!(ks.thread("t1").is_some());
        ks.apply(&KeyFrame { op: KeyOp::Remove, entries: vec![e(KeyKind::Thread, "t1", 1, &[])] });
        assert!(ks.thread("t1").is_none());
        assert!(!format!("{ks:?}").contains('5'));
    }
}
