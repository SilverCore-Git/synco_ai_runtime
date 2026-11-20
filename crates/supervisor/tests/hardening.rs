//! Mesure 8 : après l'initialisation de la ligne de commande (avant tout chargement de clé), le
//! processus n'est plus « dumpable » et ne peut pas écrire de fichier core. Binaire de test
//! séparé : l'état initial du processus n'est pas influencé par d'autres tests.

#![allow(clippy::unwrap_used, clippy::panic, missing_docs, reason = "tests")]

use synco_ai_runtime::cli::{Args, Command};

#[tokio::test]
async fn processus_durci_apres_initialisation() {
    assert_eq!(rustix::process::dumpable_behavior().unwrap(), rustix::process::DumpableBehavior::Dumpable);
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("c.toml");
    std::fs::write(
        &config,
        format!(
            "public_url = \"https://runtime.example.com\"\napi_url = \"https://api.example.com\"\nstate_dir = \"{}\"\nallowed_origins = [\"https://app.example.com\"]\n[key_sealing]\nmode = \"passphrase\"\n",
            dir.path().join("etat").display()
        ),
    )
    .unwrap();
    synco_ai_runtime::cli::execute(Args { config, command: Command::CheckConfig, insecure_no_sandbox: false })
        .await
        .unwrap();
    assert!(synco_ai_runtime::hardening::is_hardened(), "PR_SET_DUMPABLE=0 et RLIMIT_CORE=0 attendus");
}
