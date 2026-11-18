//! Source d'aléa injectée : la crate n'a ni état global ni générateur caché.
//!
//! En production, [`OsRandom`] (fonctionnalité `os-rng`, active par défaut) lit le générateur du
//! système. Les tests et les vecteurs fournissent une source fixe : les IV et clés éphémères fixes
//! n'existent **que** dans les vecteurs (docs/plan/vectors/README.md §1).

use crate::error::Result;

/// Fournit des octets aléatoires cryptographiquement sûrs.
pub trait RandomSource {
    /// Remplit `dest` ; une erreur doit être [`crate::Error::RandomUnavailable`].
    fn fill(&mut self, dest: &mut [u8]) -> Result<()>;
}

/// Générateur du système d'exploitation (`getrandom`).
#[cfg(feature = "os-rng")]
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRandom;

#[cfg(feature = "os-rng")]
impl RandomSource for OsRandom {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        getrandom::fill(dest).map_err(|_| crate::Error::RandomUnavailable)
    }
}
