//! Binaire autonome du worker : **non utilisé** en fonctionnement.
//!
//! Depuis L06, le worker s'exécute dans le binaire du superviseur relancé par le bac à sable
//! (`synco-ai-runtime __sandbox-helper` puis `__sandbox-worker`) : la racine du worker est vide et
//! seccomp interdit `execve`, donc aucun autre binaire ne peut y être exécuté (docs/plan/10 §2).

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "synco-ai-runtime-worker {} : le worker est lancé par le superviseur (synco-ai-runtime), dans son bac à sable.",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::from(2)
}
