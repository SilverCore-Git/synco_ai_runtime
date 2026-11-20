//! Point d'entrée du worker **dans** le bac à sable (lot L06).
//!
//! Le superviseur relance son propre binaire ; l'étape `__sandbox-worker` (crate du superviseur,
//! module `sandbox`) prépare l'isolement puis appelle [`run`] dans le même processus, avec :
//!
//! - le pipe de 06 §1, déjà placé sur le **descripteur 3** ;
//! - le chemin du socket du mandataire LLM du superviseur (`/run/synco/llm.sock` dans le bac à
//!   sable), seul accès réseau du worker (voir [`crate::llm`] et docs/plan/10).
//!
//! Le worker n'a ni système de fichiers (racine vide en lecture seule), ni réseau IP, ni `exec`,
//! ni processus enfant : seuls des fils d'exécution sont possibles (seccomp). Le moteur `tokio`
//! est mono-fil ; son pilote de signaux crée une paire `AF_UNIX` (permise par le filtre).

use std::os::unix::net::UnixStream;
use std::path::PathBuf;

/// Environnement fourni par le bac à sable (aucun secret).
#[derive(Debug, Clone, Default)]
pub struct WorkerEnv {
    /// Socket du mandataire LLM (absent si aucun fournisseur n'est routé pour cette conversation).
    pub llm_socket: Option<PathBuf>,
}

/// Code de sortie : fin normale.
pub const EXIT_OK: u8 = 0;
/// Code de sortie : erreur du protocole ou du moteur.
pub const EXIT_ERROR: u8 = 1;

/// Exécute le worker sur `pipe` jusqu'à sa fin ; rend le code de sortie du processus.
#[must_use]
pub fn run(pipe: UnixStream, llm_socket: Option<PathBuf>) -> u8 {
    // L07 remplacera le bouchon par la boucle d'agent, qui utilisera `env.llm_socket`.
    let _env = WorkerEnv { llm_socket };
    if pipe.set_nonblocking(true).is_err() {
        return EXIT_ERROR;
    }
    let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return EXIT_ERROR };
    rt.block_on(async move {
        let Ok(io) = tokio::net::UnixStream::from_std(pipe) else { return EXIT_ERROR };
        match crate::stub::run(io).await {
            Ok(_) => EXIT_OK,
            Err(_) => EXIT_ERROR,
        }
    })
}
