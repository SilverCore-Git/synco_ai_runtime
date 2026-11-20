//! Ligne de commande.
//!
//! ```text
//! synco-ai-runtime [--config <fichier>] [run]   superviseur (défaut), workers isolés (L06)
//! synco-ai-runtime [--config <fichier>] run --insecure-no-sandbox   DÉVELOPPEMENT : sans isolement
//! synco-ai-runtime [--config <fichier>] sandbox-check   tentatives d'évasion contre le bac à sable
//! synco-ai-runtime [--config <fichier>] pair    URL, identifiant, empreinte, code d'appairage
//! synco-ai-runtime [--config <fichier>] unpair  désappairage demandé par l'opérateur (01 §9)
//! synco-ai-runtime [--config <fichier>] reset-keys --yes   nouvelles clés (nouvel appairage)
//! synco-ai-runtime [--config <fichier>] --check-config     valide la configuration
//! ```
//!
//! Fichier par défaut : `$SYNCO_AI_RUNTIME_CONFIG`, sinon `/etc/synco-ai-runtime/config.toml`.

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::launcher::ResourceLimits;
use crate::sandbox::{
    Mode, SandboxLauncher,
    proxy::{LlmProxy, RuntimeQuota},
};
use crate::seal;

/// Fichier de configuration par défaut.
pub const DEFAULT_CONFIG: &str = "/etc/synco-ai-runtime/config.toml";

/// Commande.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Superviseur.
    Run,
    /// Informations d'appairage.
    Pair,
    /// Désappairage.
    Unpair,
    /// Nouvelles clés.
    ResetKeys {
        /// Confirmation explicite.
        confirmed: bool,
    },
    /// Validation de la configuration.
    CheckConfig,
    /// Autotest du bac à sable.
    SandboxCheck,
    /// Aide.
    Help,
}

/// Arguments analysés.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// Fichier de configuration.
    pub config: PathBuf,
    /// Commande.
    pub command: Command,
    /// `--insecure-no-sandbox` : workers sans isolement (développement uniquement).
    pub insecure_no_sandbox: bool,
}

/// Analyse les arguments (sans le nom du programme).
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Args> {
    let mut config =
        std::env::var_os("SYNCO_AI_RUNTIME_CONFIG").map_or_else(|| PathBuf::from(DEFAULT_CONFIG), PathBuf::from);
    let mut command = None;
    let mut yes = false;
    let mut insecure_no_sandbox = false;
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        let next = match arg.as_str() {
            "--config" | "-c" => {
                config = PathBuf::from(it.next().ok_or_else(|| Error::Config("--config sans fichier".into()))?);
                continue;
            }
            "--check-config" => Command::CheckConfig,
            "--yes" => {
                yes = true;
                continue;
            }
            "--insecure-no-sandbox" => {
                insecure_no_sandbox = true;
                continue;
            }
            "sandbox-check" => Command::SandboxCheck,
            "-h" | "--help" | "help" => Command::Help,
            "run" => Command::Run,
            "pair" => Command::Pair,
            "unpair" => Command::Unpair,
            "reset-keys" => Command::ResetKeys { confirmed: false },
            other => return Err(Error::Config(format!("argument inconnu : {other}"))),
        };
        if command.replace(next).is_some() {
            return Err(Error::Config("une seule commande à la fois".into()));
        }
    }
    let command = match command.unwrap_or(Command::Run) {
        Command::ResetKeys { .. } => Command::ResetKeys { confirmed: yes },
        c => c,
    };
    if insecure_no_sandbox && command != Command::Run {
        return Err(Error::Config("--insecure-no-sandbox ne s'emploie qu'avec run".into()));
    }
    Ok(Args { config, command, insecure_no_sandbox })
}

/// Écrit sur la sortie standard (rapport de commande, jamais de secret).
fn out(text: &str) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{text}");
}

const HELP: &str = "synco-ai-runtime [--config <fichier>] [run [--insecure-no-sandbox] | pair | unpair | reset-keys --yes | --check-config | sandbox-check]";

/// Avertissement du mode sans isolement.
pub const INSECURE_WARNING: &str = "ATTENTION : --insecure-no-sandbox. Les workers tournent SANS bac à sable (ni espaces de noms, ni seccomp, ni landlock, ni plafonds cgroup) : un worker compromis peut lire le disque, joindre n'importe quel hôte et lire la mémoire des autres workers. Réservé au développement, JAMAIS en production.";

/// Prépare le lanceur des workers : bac à sable complet (sonde comprise), ou refus de démarrer ;
/// processus sans isolement seulement si `insecure` (avertissement).
pub async fn build_launcher(config: &Config, insecure: bool, proxy: Arc<LlmProxy>) -> Result<SandboxLauncher> {
    let settings = config.sandbox_settings();
    if insecure {
        tracing::error!(code = "insecure_no_sandbox", "{INSECURE_WARNING}");
        let _ = writeln!(std::io::stderr(), "{INSECURE_WARNING}");
        return SandboxLauncher::new(&settings, Mode::Insecure, proxy).await.map_err(|e| Error::Config(e.to_string()));
    }
    SandboxLauncher::new(&settings, Mode::Sandboxed, proxy).await.map_err(|e| {
        Error::Config(format!(
            "{e}. Démarrage refusé : corriger l'environnement (docs/plan/10-bac-a-sable.md), ou, en développement seulement, relancer avec run --insecure-no-sandbox"
        ))
    })
}

/// Plafonds d'un worker d'après la configuration (09 §2).
#[must_use]
pub fn worker_limits(config: &Config) -> ResourceLimits {
    let l = &config.limits;
    ResourceLimits {
        memory_max_bytes: l.worker_memory_max_mib.saturating_mul(1024 * 1024),
        memory_high_bytes: l.worker_memory_high_mib.saturating_mul(1024 * 1024),
        cpu_max_percent: l.worker_cpu_percent,
        pids_max: l.worker_pids_max,
    }
}

fn init_tracing(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(format!("synco_ai_runtime={level},runtime_protocol={level},warn"))
    });
    let _ =
        tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).with_target(false).try_init();
}

/// Exécute une commande.
pub async fn execute(args: Args) -> Result<()> {
    if args.command == Command::Help {
        out(HELP);
        return Ok(());
    }
    // Mesure 8 : pas de vidage mémoire ni de fichier core, AVANT toute lecture de clé ou de secret.
    crate::hardening::harden_process()?;
    let config = Config::load(&args.config)?;
    init_tracing(&config.log_level);
    let backend = seal::backend_from_config(&config.key_sealing);
    match args.command {
        Command::Help => Ok(()),
        Command::CheckConfig => {
            let secrets = config.read_provider_secrets()?;
            seal::ensure_state_dir(&config.state_dir)?;
            let sealing = match &backend {
                seal::Backend::SystemdCreds { .. } if !seal::systemd_creds_available() => {
                    return Err(Error::KeyStore("systemd-creds demandé mais introuvable".into()));
                }
                seal::Backend::SystemdCreds { .. } => "systemd-creds",
                seal::Backend::Passphrase { .. } => "phrase de passe",
            };
            for w in config.warnings() {
                out(&format!("avertissement : {w}"));
            }
            out(&format!(
                "configuration valide : {} ; scellement : {sealing} ; fournisseurs avec clé : {}",
                args.config.display(),
                secrets.len()
            ));
            Ok(())
        }
        Command::Pair => {
            let (keys, created) = seal::load_or_create(&config.state_dir, &backend)?;
            if created {
                out("Clés du runtime générées et scellées.");
            }
            out(&format!("URL publique   : {}", config.public_url));
            out(&format!("Identifiant    : {}", keys.runtime_id()));
            out(&format!("Empreinte      : {}", keys.fingerprint_display()));
            out(&format!("Code d'appairage : {}", keys.pairing_code()));
            out("Saisir l'URL et le code dans Synco : Paramètres de l'organisation → Synco AI → Runtime.");
            Ok(())
        }
        Command::Unpair => {
            let keys = seal::load(&config.state_dir, &backend)?.ok_or_else(|| Error::KeyStore("aucune clé".into()))?;
            let api = crate::api::ApiClient::new(&config.api_url, keys.runtime_id(), Arc::new(keys.sig().clone()))?;
            api.unpair().await?;
            out("Désappairage demandé à l'API.");
            Ok(())
        }
        Command::ResetKeys { confirmed } => {
            if !confirmed {
                return Err(Error::Config(
                    "reset-keys efface les clés du runtime : un nouvel appairage sera obligatoire. Relancer avec --yes.".into(),
                ));
            }
            let removed = seal::reset(&config.state_dir)?;
            let auths = config.state_dir.join(crate::state::AUTH_FILE);
            if auths.exists() {
                std::fs::remove_file(&auths).map_err(|e| Error::Io(format!("{} : {}", auths.display(), e.kind())))?;
            }
            out(if removed {
                "Clés supprimées. Prochain démarrage : nouvelles clés, nouvel appairage."
            } else {
                "Aucune clé à supprimer."
            });
            Ok(())
        }
        Command::SandboxCheck => {
            seal::ensure_state_dir(&config.state_dir)?;
            let proxy = LlmProxy::new(Default::default(), RuntimeQuota::from_config(&config))
                .map_err(|e| Error::Config(e.into()))?;
            let launcher = build_launcher(&config, false, proxy).await?;
            out(&format!(
                "bac à sable : sonde réussie ; cgroup délégué : {}",
                launcher.cgroup_base().map(|p| p.display().to_string()).unwrap_or_default()
            ));
            let verdicts =
                crate::sandbox::selftest::battery(&launcher, &config.state_dir, &worker_limits(&config)).await;
            let failed = verdicts.iter().filter(|v| !v.ok).count();
            for v in &verdicts {
                out(&format!("{} {:<13} {}", if v.ok { "ok   " } else { "ÉCHEC" }, v.test, v.detail));
            }
            if failed > 0 {
                return Err(Error::Config(format!("{failed} tentative(s) d'évasion non bloquée(s)")));
            }
            out("toutes les tentatives d'évasion ont échoué ou tué le seul worker concerné");
            Ok(())
        }
        Command::Run => {
            // Bac à sable vérifié AVANT de desceller les clés : sans lui, refus de démarrer.
            let secrets = config.read_provider_secrets()?;
            let proxy =
                LlmProxy::new(secrets, RuntimeQuota::from_config(&config)).map_err(|e| Error::Config(e.into()))?;
            let launcher = build_launcher(&config, args.insecure_no_sandbox, proxy).await?;
            tracing::info!(code = "worker_launcher", launcher = launcher_name(&launcher), "lanceur de workers prêt");
            let (keys, created) = seal::load_or_create(&config.state_dir, &backend)?;
            if created {
                tracing::info!(code = "keys_generated", "clés du runtime générées et scellées");
            }
            // Les clés LLM sont dans le mandataire du lanceur (D1), jamais dans `init`.
            let running = crate::app::start(config, keys, Arc::new(launcher), Default::default()).await?;
            tokio::select! {
                () = crate::app::wait_for_signal() => {}
                _ = running.task => {}
            }
            crate::app::shutdown(&running.runtime).await;
            Ok(())
        }
    }
}

fn launcher_name(l: &SandboxLauncher) -> &'static str {
    crate::launcher::WorkerLauncher::name(l)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Args> {
        parse(args.iter().map(|s| (*s).to_owned()))
    }

    #[test]
    fn arguments() {
        assert_eq!(p(&[]).unwrap().command, Command::Run);
        assert_eq!(p(&["--check-config"]).unwrap().command, Command::CheckConfig);
        assert_eq!(p(&["-c", "/x.toml", "pair"]).unwrap().config, PathBuf::from("/x.toml"));
        assert_eq!(p(&["reset-keys"]).unwrap().command, Command::ResetKeys { confirmed: false });
        assert_eq!(p(&["reset-keys", "--yes"]).unwrap().command, Command::ResetKeys { confirmed: true });
        assert!(p(&["pair", "unpair"]).is_err());
        assert!(p(&["--inconnu"]).is_err());
        assert!(p(&["--config"]).is_err());
        assert!(!p(&["run"]).unwrap().insecure_no_sandbox);
        assert!(p(&["run", "--insecure-no-sandbox"]).unwrap().insecure_no_sandbox);
        assert!(p(&["--insecure-no-sandbox"]).unwrap().insecure_no_sandbox);
        assert!(p(&["pair", "--insecure-no-sandbox"]).is_err());
        assert_eq!(p(&["sandbox-check"]).unwrap().command, Command::SandboxCheck);
    }
}
