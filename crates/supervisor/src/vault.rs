//! Délégations ouvertes, **en mémoire uniquement** (docs/plan/03 §9) : `DK` et clés de l'org dans
//! des types effacés à la libération (`synco-e2ee`), jamais sur disque ni dans un journal.
//!
//! Cloisonnement strict par utilisateur : chaque utilisateur a sa délégation et ses clés ; une
//! clé reçue dans la délégation de A ne sert **jamais** à une conversation de B, même si B a la même
//! clé de salon ([`Vault::keys_for_conversation`] ne lit que la délégation du propriétaire).
//!
//! Effacement : à `exp` ([`Vault::expire`]), à la révocation, au remplacement (une nouvelle
//! délégation du même utilisateur remplace l'ancienne), au désappairage ([`Vault::clear`]).

use std::collections::{BTreeMap, HashMap};

use runtime_protocol::pipe::{KeyEntry, KeyKind};
use synco_e2ee::SymmetricKey;
use synco_e2ee::delegation::{self, DelegationContext, DelegationKey, EntryKind, RuntimeSelf};
use synco_e2ee::ec::EcPublicKey;
use zeroize::Zeroizing;

/// Identité d'une clé de l'org dans une délégation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyId {
    /// Type.
    pub kind: KeyKind,
    /// Référence.
    pub reference: String,
    /// Version.
    pub version: u64,
}

/// Délégation ouverte d'un utilisateur.
pub struct OpenDelegation {
    ctx: DelegationContext,
    dk: DelegationKey,
    keys: BTreeMap<KeyId, SymmetricKey>,
    cursor: Option<String>,
    entries_rejected: u64,
}

impl core::fmt::Debug for OpenDelegation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenDelegation")
            .field("delegation_id", &self.ctx.delegation_id)
            .field("user_id", &self.ctx.user_id)
            .field("exp", &self.ctx.exp)
            .field("keys", &self.keys.len())
            .finish_non_exhaustive()
    }
}

impl OpenDelegation {
    /// Mandat vérifié (03 §4) puis enveloppe de tête ouverte (03 §3), **exclusivement** par
    /// `synco_e2ee::delegation::accept_delegation`, avec la seule clé de signature épinglée courante
    /// de l'utilisateur (`pins::TrustedKey`) — jamais une clé précédente.
    pub fn accept(
        me: &RuntimeSelf<'_>,
        now: u64,
        ctx: DelegationContext,
        user_sign_key: &EcPublicKey,
        wrap: &str,
        mandate_signature: &str,
    ) -> Result<Self, synco_e2ee::Error> {
        let dk = delegation::accept_delegation(me, now, &ctx, user_sign_key, wrap, mandate_signature)?;
        Ok(Self { ctx, dk, keys: BTreeMap::new(), cursor: None, entries_rejected: 0 })
    }

    /// Ouvre une entrée (03 §5 : AAD recalculée depuis la délégation, `kind` en liste fermée) et la
    /// garde. Une entrée refusée est comptée (métrique sans détail), jamais fatale.
    pub fn add_entry(&mut self, kind: &str, reference: &str, version: u64, ciphertext: &str) -> Option<KeyId> {
        let opened = delegation::open_entry(&self.dk, &self.ctx, kind, reference, version, ciphertext);
        let parsed = match EntryKind::parse(kind) {
            Ok(EntryKind::Thread) => Some(KeyKind::Thread),
            Ok(EntryKind::Space) => Some(KeyKind::Space),
            Ok(EntryKind::Conv) => Some(KeyKind::Conv),
            _ => None,
        };
        match (opened, parsed) {
            (Ok(key), Some(kind)) => {
                let id = KeyId { kind, reference: reference.to_owned(), version };
                self.keys.insert(id.clone(), key);
                Some(id)
            }
            _ => {
                self.entries_rejected = self.entries_rejected.saturating_add(1);
                None
            }
        }
    }

    /// Mémorise le curseur de la dernière entrée lue.
    pub fn set_cursor(&mut self, cursor: Option<String>) {
        if cursor.is_some() {
            self.cursor = cursor;
        }
    }

    /// Curseur.
    #[must_use]
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    /// `delegationId`.
    #[must_use]
    pub fn delegation_id(&self) -> &str {
        &self.ctx.delegation_id
    }

    /// Utilisateur.
    #[must_use]
    pub fn user_id(&self) -> &str {
        &self.ctx.user_id
    }

    /// Expiration.
    #[must_use]
    pub const fn exp(&self) -> u64 {
        self.ctx.exp
    }

    /// Entrées refusées.
    #[must_use]
    pub const fn entries_rejected(&self) -> u64 {
        self.entries_rejected
    }

    /// Nombre de clés.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Chiffre sous `DK` l'entrée d'une clé de salon créée par le runtime (03 §10), version 1.
    pub fn seal_created_thread_entry(&self, thread_id: &str, key: &SymmetricKey) -> Result<String, synco_e2ee::Error> {
        delegation::seal_entry(&self.dk, &self.ctx, EntryKind::Thread, thread_id, 1, key, &mut synco_e2ee::OsRandom)
    }

    /// Identités des clés détenues.
    #[must_use]
    pub fn key_ids(&self) -> Vec<KeyId> {
        self.keys.keys().cloned().collect()
    }
}

/// Toutes les délégations ouvertes, une par utilisateur.
#[derive(Debug, Default)]
pub struct Vault {
    by_user: HashMap<String, OpenDelegation>,
}

fn to_entry(id: &KeyId, key: &SymmetricKey) -> Option<KeyEntry> {
    Some(KeyEntry {
        kind: id.kind,
        reference: id.reference.clone(),
        version: u32::try_from(id.version).ok()?,
        key: Zeroizing::new(key.as_bytes().to_vec()),
    })
}

impl Vault {
    /// Installe la délégation d'un utilisateur ; l'ancienne (remplacée) est effacée.
    /// Renvoie les identités des clés de l'ancienne délégation.
    pub fn install(&mut self, delegation: OpenDelegation) -> Vec<KeyId> {
        let user = delegation.ctx.user_id.clone();
        self.by_user.insert(user, delegation).map(|old| old.key_ids()).unwrap_or_default()
    }

    /// Délégation d'un utilisateur.
    #[must_use]
    pub fn get(&self, user_id: &str) -> Option<&OpenDelegation> {
        self.by_user.get(user_id)
    }

    /// Délégation (mutable) par identifiant.
    pub fn by_delegation_mut(&mut self, delegation_id: &str) -> Option<&mut OpenDelegation> {
        self.by_user.values_mut().find(|d| d.ctx.delegation_id == delegation_id)
    }

    /// Retire (efface) la délégation d'un utilisateur.
    pub fn remove_user(&mut self, user_id: &str) -> bool {
        self.by_user.remove(user_id).is_some()
    }

    /// Retire (efface) une délégation par identifiant ; renvoie son utilisateur.
    pub fn remove_delegation(&mut self, delegation_id: &str) -> Option<String> {
        let user = self.by_user.iter().find(|(_, d)| d.ctx.delegation_id == delegation_id).map(|(u, _)| u.clone())?;
        self.by_user.remove(&user);
        Some(user)
    }

    /// Efface des clés d'une délégation (`delegation.entries_removed`) ; renvoie l'utilisateur.
    pub fn remove_entries(&mut self, delegation_id: &str, ids: &[KeyId]) -> Option<String> {
        let d = self.by_delegation_mut(delegation_id)?;
        for id in ids {
            d.keys.remove(id);
        }
        Some(d.ctx.user_id.clone())
    }

    /// Efface les délégations expirées (`exp ≤ now`, double verrou côté runtime) ; renvoie leurs
    /// utilisateurs.
    pub fn expire(&mut self, now: u64) -> Vec<String> {
        let expired: Vec<String> =
            self.by_user.iter().filter(|(_, d)| d.ctx.exp <= now).map(|(u, _)| u.clone()).collect();
        for u in &expired {
            self.by_user.remove(u);
        }
        expired
    }

    /// Désappairage : tout effacer.
    pub fn clear(&mut self) {
        self.by_user.clear();
    }

    /// Utilisateurs ayant une délégation ouverte.
    #[must_use]
    pub fn users(&self) -> Vec<String> {
        self.by_user.keys().cloned().collect()
    }

    /// Clés à transmettre au worker d'une conversation (06 §2, 03 §9) : uniquement depuis la
    /// délégation de **son propriétaire**, la `conv` de **cette** conversation (obligatoire), puis
    /// les clés `thread` et `space`. Jamais `DK`, jamais la `conv` d'une autre conversation.
    /// `None` si le propriétaire n'a pas de délégation ouverte ou si la `conv` manque.
    #[must_use]
    pub fn keys_for_conversation(&self, owner_id: &str, session_id: &str, now: u64) -> Option<Vec<KeyEntry>> {
        let d = self.by_user.get(owner_id).filter(|d| d.ctx.exp > now)?;
        let conv = d.keys.iter().find(|(id, _)| id.kind == KeyKind::Conv && id.reference == session_id)?;
        let mut out = vec![to_entry(conv.0, conv.1)?];
        out.extend(
            d.keys
                .iter()
                .filter(|(id, _)| matches!(id.kind, KeyKind::Thread | KeyKind::Space))
                .filter_map(|(id, k)| to_entry(id, k)),
        );
        Some(out)
    }

    /// Clés précises d'un utilisateur (synchro P11 vers un worker en cours), sans `conv`.
    #[must_use]
    pub fn org_keys(&self, owner_id: &str, ids: &[KeyId], now: u64) -> Vec<KeyEntry> {
        let Some(d) = self.by_user.get(owner_id).filter(|d| d.ctx.exp > now) else { return vec![] };
        ids.iter()
            .filter(|id| matches!(id.kind, KeyKind::Thread | KeyKind::Space))
            .filter_map(|id| d.keys.get(id).and_then(|k| to_entry(id, k)))
            .collect()
    }

    /// La délégation du propriétaire contient-elle la `conv` de cette conversation ?
    #[must_use]
    pub fn has_conversation_key(&self, owner_id: &str, session_id: &str, now: u64) -> bool {
        self.by_user
            .get(owner_id)
            .filter(|d| d.ctx.exp > now)
            .is_some_and(|d| d.keys.keys().any(|id| id.kind == KeyKind::Conv && id.reference == session_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synco_e2ee::OsRandom;
    use synco_e2ee::delegation::Scope;
    use synco_e2ee::ec::{EcSigningKey, EcdhSecret};

    pub(crate) struct Fixture {
        pub kex: EcdhSecret,
        pub fpr: String,
    }

    fn ctx(user: &str, delegation_id: &str, iat: u64, exp: u64) -> DelegationContext {
        DelegationContext {
            user_id: user.into(),
            org_id: "org1".into(),
            runtime_id: "7d3f2c1e-8a4b-4c6d-9e0f-1a2b3c4d5e6f".into(),
            delegation_id: delegation_id.into(),
            scope: Scope::Org,
            iat,
            exp,
        }
    }

    fn me<'a>(f: &'a Fixture) -> RuntimeSelf<'a> {
        RuntimeSelf {
            runtime_id: "7d3f2c1e-8a4b-4c6d-9e0f-1a2b3c4d5e6f",
            org_id: "org1",
            fpr_hex: &f.fpr,
            kex: &f.kex,
            max_lifetime_secs: 30 * 86_400,
        }
    }

    fn delegate(
        f: &Fixture,
        user_key: &EcSigningKey,
        c: &DelegationContext,
        entries: &[(&str, &str, [u8; 32])],
    ) -> (String, String, Vec<(String, String, String)>) {
        let dk = DelegationKey::generate(&mut OsRandom).unwrap();
        let wrap = delegation::seal_delegation(c, &f.kex.public_key().unwrap(), &dk, &mut OsRandom).unwrap();
        let sig = delegation::sign_mandate(user_key, c, &f.fpr, &wrap).unwrap();
        let entries = entries
            .iter()
            .map(|(kind, r, k)| {
                let ct = delegation::seal_entry(
                    &dk,
                    c,
                    EntryKind::parse(kind).unwrap(),
                    r,
                    1,
                    &SymmetricKey::from_bytes(*k),
                    &mut OsRandom,
                )
                .unwrap();
                ((*kind).to_owned(), (*r).to_owned(), ct)
            })
            .collect();
        (wrap, sig, entries)
    }

    fn fixture() -> Fixture {
        Fixture { kex: EcdhSecret::generate(&mut OsRandom).unwrap(), fpr: "ab".repeat(32) }
    }

    #[test]
    fn cloisonnement_par_utilisateur() {
        let f = fixture();
        let (ka, kb) = (EcSigningKey::generate(&mut OsRandom).unwrap(), EcSigningKey::generate(&mut OsRandom).unwrap());
        let mut vault = Vault::default();
        for (user, key, conv, thread_key) in [("a", &ka, "convA", [1u8; 32]), ("b", &kb, "convB", [2u8; 32])] {
            let c = ctx(user, &format!("d{user}"), 1_000, 1_000 + 86_400);
            let (wrap, sig, entries) = delegate(&f, key, &c, &[("conv", conv, [9; 32]), ("thread", "t1", thread_key)]);
            let mut d = OpenDelegation::accept(&me(&f), 1_100, c, &key.public_key().unwrap(), &wrap, &sig).unwrap();
            for (kind, r, ct) in entries {
                assert!(d.add_entry(&kind, &r, 1, &ct).is_some());
            }
            vault.install(d);
        }
        // Le worker de la conversation de A ne reçoit que la clé de salon de A.
        let keys_a = vault.keys_for_conversation("a", "convA", 1_100).unwrap();
        assert!(keys_a.iter().any(|k| k.kind == KeyKind::Thread && k.key.as_slice() == [1u8; 32]));
        assert!(!keys_a.iter().any(|k| k.key.as_slice() == [2u8; 32]), "clé de B jamais donnée pour A");
        // A ne peut pas obtenir la conversation de B, ni B celle de A.
        assert!(vault.keys_for_conversation("a", "convB", 1_100).is_none());
        assert!(vault.keys_for_conversation("b", "convA", 1_100).is_none());
        assert!(vault.keys_for_conversation("inconnu", "convA", 1_100).is_none());
        // Délégation expirée mais pas encore purgée : aucune clé n'est remise (double verrou).
        assert!(vault.keys_for_conversation("a", "convA", 1_000 + 86_400).is_none());
        assert!(!vault.has_conversation_key("a", "convA", 1_000 + 86_400));
        assert!(vault.org_keys("a", &vault.get("a").unwrap().key_ids(), 1_000 + 86_400).is_empty());
    }

    #[test]
    fn entree_d_une_cle_creee_par_le_runtime() {
        let f = fixture();
        let user = EcSigningKey::generate(&mut OsRandom).unwrap();
        let c = ctx("a", "d1", 1_000, 1_000 + 86_400);
        let (wrap, sig, _) = delegate(&f, &user, &c, &[]);
        let mut d = OpenDelegation::accept(&me(&f), 1_100, c, &user.public_key().unwrap(), &wrap, &sig).unwrap();
        let key = SymmetricKey::from_bytes([7; 32]);
        let ct = d.seal_created_thread_entry("tNew", &key).unwrap();
        // L'entrée s'ouvre comme une entrée déposée par le client (même AAD, même DK)…
        let id = d.add_entry("thread", "tNew", 1, &ct).unwrap();
        assert_eq!(id.reference, "tNew");
        // … et pas sous une autre référence ou version.
        assert!(d.add_entry("thread", "tAutre", 1, &ct).is_none());
        assert!(d.add_entry("thread", "tNew", 2, &ct).is_none());
    }

    #[test]
    fn aad_ou_mandat_qui_ne_correspond_pas_refuses() {
        let f = fixture();
        let user = EcSigningKey::generate(&mut OsRandom).unwrap();
        let c = ctx("a", "d1", 1_000, 1_000 + 86_400);
        let (wrap, sig, entries) = delegate(&f, &user, &c, &[("thread", "t1", [1; 32])]);
        let pk = user.public_key().unwrap();
        // AAD de l'enveloppe : autre utilisateur, autre délégation, autre expiration.
        for bad in [
            DelegationContext { user_id: "b".into(), ..c.clone() },
            DelegationContext { delegation_id: "d2".into(), ..c.clone() },
            DelegationContext { exp: c.exp + 1, ..c.clone() },
            DelegationContext { org_id: "org2".into(), ..c.clone() },
        ] {
            assert!(OpenDelegation::accept(&me(&f), 1_100, bad, &pk, &wrap, &sig).is_err());
        }
        // Mandat signé par une autre clé que celle épinglée.
        let other = EcSigningKey::generate(&mut OsRandom).unwrap().public_key().unwrap();
        assert!(OpenDelegation::accept(&me(&f), 1_100, c.clone(), &other, &wrap, &sig).is_err());
        // Expirée ou trop longue.
        assert!(OpenDelegation::accept(&me(&f), c.exp, c.clone(), &pk, &wrap, &sig).is_err());
        let mut d = OpenDelegation::accept(&me(&f), 1_100, c, &pk, &wrap, &sig).unwrap();
        // Entrées : métadonnées changées, kind hors liste.
        let (_, _, ct) = &entries[0];
        assert!(d.add_entry("thread", "t2", 1, ct).is_none());
        assert!(d.add_entry("thread", "t1", 2, ct).is_none());
        assert!(d.add_entry("dm", "t1", 1, ct).is_none());
        assert!(d.add_entry("space", "t1", 1, ct).is_none());
        assert_eq!(d.entries_rejected(), 4);
        assert!(d.add_entry("thread", "t1", 1, ct).is_some());
    }

    /// Une clé retirée par une transition d'identité ne signe plus de mandat neuf (03 §4).
    #[test]
    fn mandat_neuf_signe_par_une_cle_retiree_refuse() {
        use crate::pins::PinStore;
        use synco_e2ee::identity::sign_identity_transition;
        let f = fixture();
        let (k1, k2) = (EcSigningKey::generate(&mut OsRandom).unwrap(), EcSigningKey::generate(&mut OsRandom).unwrap());
        let jwk = |k: &EcSigningKey| k.public_key().unwrap().to_canonical();
        let mut pins = PinStore::in_memory();
        pins.check_or_pin("a", Some(&jwk(&k1)), &[], 1).unwrap();
        let t = sign_identity_transition(&k1, "a", 0, r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#, &jwk(&k2)).unwrap();
        let trusted = pins.check_or_pin("a", Some(&jwk(&k2)), &[t], 2).unwrap();
        let c = ctx("a", "d1", 1_000, 1_000 + 86_400);
        // Mandat neuf signé par k1 (retirée) : refusé.
        let (wrap, sig, _) = delegate(&f, &k1, &c, &[]);
        assert!(OpenDelegation::accept(&me(&f), 1_100, c.clone(), &trusted.0, &wrap, &sig).is_err());
        // Signé par k2 (courante) : accepté.
        let (wrap, sig, _) = delegate(&f, &k2, &c, &[]);
        assert!(OpenDelegation::accept(&me(&f), 1_100, c, &trusted.0, &wrap, &sig).is_ok());
    }

    #[test]
    fn expiration_remplacement_effacement() {
        let f = fixture();
        let user = EcSigningKey::generate(&mut OsRandom).unwrap();
        let pk = user.public_key().unwrap();
        let mut vault = Vault::default();
        let c1 = ctx("a", "d1", 1_000, 5_000);
        let (w, s, _) = delegate(&f, &user, &c1, &[]);
        vault.install(OpenDelegation::accept(&me(&f), 1_100, c1, &pk, &w, &s).unwrap());
        let c2 = ctx("a", "d2", 1_000, 9_000);
        let (w, s, _) = delegate(&f, &user, &c2, &[]);
        vault.install(OpenDelegation::accept(&me(&f), 1_100, c2, &pk, &w, &s).unwrap());
        assert_eq!(vault.get("a").unwrap().delegation_id(), "d2", "remplacée");
        assert!(vault.by_delegation_mut("d1").is_none());
        assert!(vault.expire(8_999).is_empty());
        assert_eq!(vault.expire(9_000), vec!["a".to_owned()]);
        assert!(vault.get("a").is_none());
    }
}
