//! Durcissement du processus (mesure 8), appliqué **avant** de charger les clés :
//!
//! - `PR_SET_DUMPABLE = 0` : pas de vidage mémoire, `/proc/<pid>/mem` et `ptrace` interdits aux
//!   autres processus du même utilisateur (hors `CAP_SYS_PTRACE`) ;
//! - `RLIMIT_CORE = 0` (souple et dure) : aucun fichier `core` ne peut contenir les clés.
//!
//! `mlock` des pages de clés : impossible sans `unsafe` (`rustix::mm::mlock` prend un pointeur
//! brut) ; `mlockall(MCL_FUTURE)` ferait échouer les allocations au-delà de `RLIMIT_MEMLOCK`. Non
//! appliqué : le risque d'écriture des clés dans l'espace d'échange est couvert par la
//! documentation (swap chiffré ou `MemorySwapMax=0` dans l'unité systemd, README de la crate).

use rustix::process::{
    DumpableBehavior, Resource, Rlimit, dumpable_behavior, getrlimit, set_dumpable_behavior, setrlimit,
};

use crate::error::{Error, Result};

/// Applique le durcissement. Une erreur empêche le démarrage (les clés ne sont pas chargées).
pub fn harden_process() -> Result<()> {
    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|e| Error::Io(format!("PR_SET_DUMPABLE impossible : {e}")))?;
    setrlimit(Resource::Core, Rlimit { current: Some(0), maximum: Some(0) })
        .map_err(|e| Error::Io(format!("RLIMIT_CORE impossible : {e}")))?;
    if !is_hardened() {
        return Err(Error::Io("durcissement du processus non effectif".into()));
    }
    Ok(())
}

/// Le processus est-il non « dumpable » et sans fichier `core` ?
#[must_use]
pub fn is_hardened() -> bool {
    let core = getrlimit(Resource::Core);
    matches!(dumpable_behavior(), Ok(DumpableBehavior::NotDumpable))
        && core.current == Some(0)
        && core.maximum == Some(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn processus_durci() {
        harden_process().unwrap();
        assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
        let core = getrlimit(Resource::Core);
        assert_eq!((core.current, core.maximum), (Some(0), Some(0)));
        assert!(is_hardened());
    }
}
