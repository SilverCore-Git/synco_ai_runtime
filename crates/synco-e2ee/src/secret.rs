//! Clés symétriques de 256 bits : effacées à la libération, jamais affichées.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// Longueur de toutes les clés symétriques de Synco (AES-256).
pub const KEY_LENGTH: usize = 32;

/// Clé AES-256 brute (AK, DK, `CK`, clé de salon, d'espace…).
///
/// `Debug` masque la valeur, comme `SessionKey` de la passerelle ; la mémoire est effacée à la
/// libération (`zeroize`).
#[derive(Clone)]
pub struct SymmetricKey([u8; KEY_LENGTH]);

impl Drop for SymmetricKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SymmetricKey {}

impl SymmetricKey {
    /// Prend possession de 32 octets.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Copie une tranche d'exactement 32 octets.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; KEY_LENGTH] = bytes.try_into().map_err(|_| Error::InvalidKey)?;
        Ok(Self(arr))
    }

    /// Tire une clé aléatoire.
    pub fn generate(rng: &mut impl crate::RandomSource) -> Result<Self> {
        let mut bytes = [0u8; KEY_LENGTH];
        rng.fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Octets bruts (à ne jamais journaliser).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKey(***)")
    }
}

impl PartialEq for SymmetricKey {
    /// Comparaison en temps constant.
    fn eq(&self, other: &Self) -> bool {
        use subtle_ct::ct_eq;
        ct_eq(&self.0, &other.0)
    }
}

impl Eq for SymmetricKey {}

/// Comparaison en temps constant sans dépendance supplémentaire.
pub(crate) mod subtle_ct {
    #[must_use]
    pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
        core::hint::black_box(diff) == 0
    }
}
