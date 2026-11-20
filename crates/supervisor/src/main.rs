//! Binaire `synco-ai-runtime` (voir `synco_ai_runtime::cli`).

use std::io::Write as _;
use std::process::ExitCode;

fn main() -> ExitCode {
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
