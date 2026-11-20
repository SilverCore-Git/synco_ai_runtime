//! Binaire du worker. Le lancement isolé (pipe hérité sur le descripteur 3, bac à sable) est le
//! travail de L06 : en attendant, le superviseur exécute le bouchon de protocole dans sa propre
//! tâche (`InProcessStubLauncher`) et ce binaire refuse de démarrer.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "synco-ai-runtime-worker {} : lancement isolé non disponible avant le lot L06 (bac à sable).",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::from(2)
}
