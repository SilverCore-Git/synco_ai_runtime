//! Binaire `synco-ai-runtime` (voir `synco_ai_runtime::cli`). Relancé par le bac à sable pour
//! chaque worker (`__sandbox-helper`, `__sandbox-worker`) : ces étapes passent **avant** le moteur
//! asynchrone (un seul fil d'exécution, condition de `unshare(CLONE_NEWUSER)`).

#![forbid(unsafe_code)]

use std::io::Write as _;
use std::process::ExitCode;

fn main() -> ExitCode {
    if let Some(code) = synco_ai_runtime::sandbox::child_main() {
        return code;
    }
    let result = synco_ai_runtime::cli::parse(std::env::args().skip(1)).and_then(|args| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| synco_ai_runtime::error::Error::Io(format!("moteur asynchrone : {}", e.kind())))?
            .block_on(synco_ai_runtime::cli::execute(args))
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "synco-ai-runtime : {e}");
            ExitCode::FAILURE
        }
    }
}
