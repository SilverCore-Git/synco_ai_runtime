//! Seul fichier du dépôt où `unsafe` est permis (`#[allow(unsafe_code)]` posé sur ce module dans
//! `sandbox/mod.rs`, interdiction ailleurs vérifiée par `tests/unsafe_scope.rs`).
//!
//! Chaque bloc est justifié ci-dessous. Tout le reste du bac à sable passe par des API sûres
//! (`rustix`, `landlock`, `seccompiler`, `std`).

use rustix::thread::UnshareFlags;

/// `unshare(2)` des espaces de noms du worker.
///
/// `rustix` marque `unshare` comme non sûr depuis 1.1 à cause d'un seul drapeau :
/// `CLONE_FILES` (une table de descripteurs dédoublée pendant que d'autres fils d'exécution
/// partagent l'ancienne). Ce module ne passe **que** des drapeaux d'espaces de noms ; le drapeau
/// `FILES` (et `FS`, `SYSVSEM`) est refusé avant l'appel.
pub(super) fn unshare_namespaces(flags: UnshareFlags) -> rustix::io::Result<()> {
    let forbidden = UnshareFlags::FILES | UnshareFlags::FS | UnshareFlags::SYSVSEM;
    if flags.intersects(forbidden) {
        return Err(rustix::io::Errno::INVAL);
    }
    // SAFETY : la seule condition de sûreté documentée par `rustix::thread::unshare_unsafe`
    // concerne `UnshareFlags::FILES`, exclu juste au-dessus. Les autres drapeaux (espaces de noms
    // user, mount, pid, net, ipc, uts, cgroup) ne touchent ni à la mémoire ni aux descripteurs du
    // processus. L'appelant est l'assistant `__sandbox-helper`, un processus qui vient d'être
    // exécuté et n'a qu'un fil d'exécution (condition du noyau pour `CLONE_NEWUSER`).
    unsafe { rustix::thread::unshare_unsafe(flags) }
}
