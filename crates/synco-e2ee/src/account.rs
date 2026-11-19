//! Clé de compte AK (E2EE v4, `e2eeV4.ts:63-98`).
//!
//! Le runtime ne reçoit **jamais** AK (docs/plan/03-delegation.md §2). Ce type n'existe que pour
//! les tests de compatibilité des formats v4 ; aucune fonction de la crate ne scelle AK pour un
//! runtime.

use core::fmt;

use crate::error::Result;
use crate::secret::{KEY_LENGTH, SymmetricKey};

/// Clé de compte (256 bits), effacée à la libération.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountKey(SymmetricKey);

impl fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountKey(***)")
    }
}

impl AccountKey {
    /// Prend possession de 32 octets.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LENGTH]) -> Self {
        Self(SymmetricKey::from_bytes(bytes))
    }

    /// Copie une tranche d'exactement 32 octets.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        Ok(Self(SymmetricKey::from_slice(bytes)?))
    }

    /// Octets bruts (à ne jamais journaliser).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LENGTH] {
        self.0.as_bytes()
    }
}
