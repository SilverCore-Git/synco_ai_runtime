//! Bac à sable des workers (lot L06, P3, mesure 7) : **un processus isolé par conversation
//! active**. Justification de conception : `docs/plan/10-bac-a-sable.md`.
//!
//! - Lancement par `fork` + `exec` du binaire du superviseur (`std`/`tokio::process::Command`),
//!   environnement vidé, aucun descripteur hérité autre que le pipe (stdin de l'assistant, puis
//!   descripteur 3 du worker) ; voir [`child`].
//! - Espaces de noms user, pid, mount (racine `tmpfs` vide en lecture seule), net (aucune
//!   interface), ipc, uts, cgroup ; capacités retirées ; `no_new_privs` ; landlock ; seccomp en liste
//!   blanche ([`policy`]).
//! - cgroup v2 par worker : `memory.max`, `memory.swap.max = 0`, `memory.oom.group = 1`,
//!   `pids.max`, `cpu.max` (D6 ; `memory.high` volontairement non appliqué, docs/plan/10 §5) ;
//!   compteurs pour les métriques ([`cgroup`]).
//! - Réseau : uniquement le mandataire LLM du superviseur ([`proxy`]), qui ajoute la clé (D1).
//! - Repli : si une fonction noyau manque, [`SandboxLauncher::new`] échoue et le superviseur
//!   **refuse de démarrer** ; `--insecure-no-sandbox` (développement) lance des processus séparés
//!   sans isolement, avec un avertissement.

pub mod cgroup;
pub mod child;
pub mod policy;
pub mod proxy;
pub mod selftest;
#[allow(unsafe_code, reason = "seul module autorisé (L06) ; chaque bloc est justifié dans le fichier")]
mod sys;

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _};

pub use child::{ChildArgs, EXIT_SETUP_FAILED, Layer, child_main};

use crate::launcher::{
    BoxFuture, LaunchError, LlmRoute, ResourceLimits, ResourceUsage, SpawnedWorker, WorkerExit, WorkerLauncher,
    WorkerProcess, WorkerSpec,
};
use cgroup::{CgroupTree, WorkerCgroup};
use proxy::LlmProxy;

/// Délai de la sonde de démarrage.
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// Réglages (section `[sandbox]` de la configuration).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxSettings {
    /// Binaire relancé pour chaque worker (défaut : le binaire courant du superviseur).
    pub program: Option<PathBuf>,
    /// Base du sous-arbre cgroup délégué (défaut : le cgroup courant du superviseur).
    pub cgroup_root: Option<PathBuf>,
    /// Répertoire des sockets du mandataire LLM (un sous-répertoire `0700` par worker).
    pub run_dir: PathBuf,
}

/// Mode du lanceur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Isolement complet.
    Sandboxed,
    /// `--insecure-no-sandbox` : processus séparé, environnement vidé, mandataire LLM, mais **ni**
    /// espaces de noms, **ni** seccomp, landlock ou cgroup.
    Insecure,
}

/// Échec de préparation du bac à sable (refus de démarrer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxError {
    /// Code machine (`userns_unavailable`, `cgroup_not_delegated`, `landlock_unavailable`…).
    pub code: String,
}

impl core::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "bac à sable des workers indisponible ({}) : {}", self.code, explain(&self.code))
    }
}

/// Explication lisible d'un code d'échec (pour l'opérateur).
#[must_use]
pub fn explain(code: &str) -> &'static str {
    match code {
        "userns_unavailable" | "userns_setgroups" | "userns_uid_map" | "userns_gid_map" => {
            "espaces de noms utilisateur non permis (user.max_user_namespaces, RestrictNamespaces= de systemd, profil seccomp/AppArmor du conteneur)"
        }
        "cgroup_v2_unavailable" => "cgroups v2 introuvables (/sys/fs/cgroup)",
        "cgroup_controllers_missing" => "contrôleurs memory, pids, cpu non délégués à ce cgroup",
        "cgroup_not_delegated" | "cgroup_join" => {
            "cgroup non délégué au superviseur (systemd : Delegate=yes ; conteneur : cgroup en écriture)"
        }
        "cgroup_swap_uncontrolled" => {
            "memory.swap.max absent (noyau sans comptage du swap) alors qu'un espace d'échange est actif : désactiver le swap (swapoff -a) ou activer le comptage"
        }
        "cgroup_base_has_processes" => {
            "le cgroup du superviseur contient d'autres processus (lancer seul dans son cgroup)"
        }
        "landlock_unavailable" | "landlock_ruleset" | "landlock_restrict" => {
            "landlock absent ou désactivé (lsm=…,landlock)"
        }
        "seccomp_unavailable" => "seccomp indisponible",
        "mount_private" | "mount_tmpfs" | "pivot_root" | "umount_old_root" | "mount_root_ro" | "mount_llm_dir"
        | "mount_llm_dir_ro" => "montages interdits dans l'espace de noms (profil seccomp/AppArmor du conteneur)",
        "pidns_unavailable" => "espace de noms PID indisponible",
        "probe_timeout" => "la sonde du bac à sable n'a pas répondu",
        _ => "voir docs/plan/10-bac-a-sable.md",
    }
}

fn err(code: &str) -> SandboxError {
    SandboxError { code: code.to_owned() }
}

/// Lanceur de workers isolés.
#[derive(Debug)]
pub struct SandboxLauncher {
    mode: Mode,
    program: PathBuf,
    cgroups: Option<CgroupTree>,
    run_dir: PathBuf,
    proxy: Arc<LlmProxy>,
    next_id: AtomicU64,
}

/// Ce qu'une exécution d'autotest rapporte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseOutcome {
    /// Ligne écrite par la tentative (vide si le worker a été tué avant).
    pub line: String,
    /// Fin du processus.
    pub exit: WorkerExit,
    /// `oom_kill` du cgroup.
    pub oom_kills: u64,
}

impl SandboxLauncher {
    /// Prépare le lanceur. En mode [`Mode::Sandboxed`] : cgroup délégué, puis **sonde** (un worker
    /// vide est isolé et doit se terminer normalement). Toute fonction noyau manquante → erreur.
    pub async fn new(settings: &SandboxSettings, mode: Mode, proxy: Arc<LlmProxy>) -> Result<Self, SandboxError> {
        let program = match &settings.program {
            Some(p) => p.clone(),
            None => std::env::current_exe().map_err(|_| err("program_unknown"))?,
        };
        std::fs::create_dir_all(&settings.run_dir).map_err(|_| err("run_dir"))?;
        set_mode(&settings.run_dir, 0o700).map_err(|_| err("run_dir"))?;
        clean_run_dir(&settings.run_dir);
        let cgroups = match mode {
            Mode::Sandboxed => Some(CgroupTree::setup(settings.cgroup_root.as_deref()).map_err(err)?),
            Mode::Insecure => None,
        };
        let launcher =
            Self { mode, program, cgroups, run_dir: settings.run_dir.clone(), proxy, next_id: AtomicU64::new(1) };
        if mode == Mode::Sandboxed {
            launcher.probe().await?;
        }
        Ok(launcher)
    }

    /// Mode.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// Base cgroup (mode isolé).
    #[must_use]
    pub fn cgroup_base(&self) -> Option<&Path> {
        self.cgroups.as_ref().map(CgroupTree::base)
    }

    /// Sonde : un worker vide doit franchir toutes les étapes d'isolement et sortir avec 0.
    pub async fn probe(&self) -> Result<(), SandboxError> {
        let limits = ResourceLimits { memory_max_bytes: 64 << 20, cpu_max_percent: 100, pids_max: 16 };
        let args = ChildArgs { payload: "probe".into(), ..ChildArgs::default() };
        let mut w = self.spawn_child(args, &limits, None, Vec::new()).await.map_err(|e| err(e.0))?;
        let exit = match tokio::time::timeout(PROBE_TIMEOUT, w.process.wait()).await {
            Ok(e) => e,
            Err(_) => {
                w.process.kill();
                return Err(err("probe_timeout"));
            }
        };
        if exit.is_clean() {
            return Ok(());
        }
        let code = w.process.setup_error().await.unwrap_or_else(|| format!("probe_exit_{exit:?}"));
        Err(SandboxError { code })
    }

    /// Lance un enfant du bac à sable. `extra_without` : couches retirées (tests).
    pub async fn spawn_child(
        &self,
        mut args: ChildArgs,
        limits: &ResourceLimits,
        llm: Option<LlmRoute>,
        extra_without: Vec<Layer>,
    ) -> Result<RawWorker, LaunchError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let name = format!("{id}-{}", std::process::id());
        let dir = self.run_dir.join(format!("w-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).map_err(|_| LaunchError("run_dir"))?;
        set_mode(&dir, 0o700).map_err(|_| LaunchError("run_dir"))?;
        let proxy_task = match llm {
            Some(route) => {
                let socket = dir.join(child::LLM_SOCKET_NAME);
                let served = tokio::net::UnixListener::bind(&socket)
                    .map_err(|_| "llm_socket")
                    .and_then(|l| set_mode(&socket, 0o600).map(|()| l).map_err(|_| "llm_socket"))
                    .and_then(|l| self.proxy.serve(l, route));
                match served {
                    Ok(t) => Some(t),
                    Err(code) => {
                        let _ = std::fs::remove_dir_all(&dir);
                        return Err(LaunchError(code));
                    }
                }
            }
            None => None,
        };
        let has_llm = proxy_task.is_some();
        let cleanup_dir = |dir: &Path| {
            let _ = std::fs::remove_dir_all(dir);
        };
        let cgroup = match &self.cgroups {
            Some(tree) => match tree.create(&name, limits) {
                Ok(c) => Some(c),
                Err(code) => {
                    if let Some(t) = &proxy_task {
                        t.abort();
                    }
                    cleanup_dir(&dir);
                    return Err(LaunchError(code));
                }
            },
            None => None,
        };
        args.llm_dir = has_llm.then(|| dir.clone());
        args.without.extend(extra_without);
        let (stage, args_os) = match self.mode {
            Mode::Sandboxed => {
                args.cgroup_procs = cgroup.as_ref().map(WorkerCgroup::procs_file);
                (child::HELPER_ARG, args.to_args(true))
            }
            Mode::Insecure => {
                args.insecure = true;
                (child::WORKER_ARG, args.to_args(false))
            }
        };
        // Tout ce qui peut échouer est fait AVANT le lancement : après lui, plus aucune erreur ne
        // peut laisser un processus, un cgroup ou une tâche du mandataire orphelins (M4).
        let pair = std::os::unix::net::UnixStream::pair().and_then(|(ours, theirs)| {
            ours.set_nonblocking(true)?;
            Ok((tokio::net::UnixStream::from_std(ours)?, theirs))
        });
        let (io, theirs) = match pair {
            Ok(p) => p,
            Err(_) => {
                if let Some(t) = &proxy_task {
                    t.abort();
                }
                if let Some(c) = cgroup {
                    c.destroy().await;
                }
                cleanup_dir(&dir);
                return Err(LaunchError("socketpair"));
            }
        };
        let started = Instant::now();
        let spawned = tokio::process::Command::new(&self.program)
            .arg(stage)
            .args(args_os)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn();
        let mut child = match spawned {
            Ok(c) => c,
            Err(_) => {
                if let Some(t) = &proxy_task {
                    t.abort();
                }
                if let Some(c) = cgroup {
                    c.destroy().await;
                }
                cleanup_dir(&dir);
                return Err(LaunchError("spawn_failed"));
            }
        };
        let pid = child.id();
        let stderr = child.stderr.take().map(|e| tokio::spawn(read_setup_error(e)));
        Ok(RawWorker {
            io,
            process: SandboxProcess {
                child: Some(child),
                pid,
                cgroup,
                proxy_task,
                dir: Some(dir),
                stderr,
                started,
                exit: None,
                last_oom_kills: 0,
            },
        })
    }

    /// Exécute une tentative d'autotest et attend sa fin (≤ `timeout`).
    pub async fn run_case(
        &self,
        test: &str,
        test_args: Vec<String>,
        limits: &ResourceLimits,
        llm: Option<LlmRoute>,
        without: Vec<Layer>,
        timeout: Duration,
    ) -> Result<CaseOutcome, LaunchError> {
        let args =
            ChildArgs { payload: "selftest".into(), test: Some(test.to_owned()), test_args, ..ChildArgs::default() };
        let RawWorker { mut io, mut process } = self.spawn_child(args, limits, llm, without).await?;
        let mut line = Vec::new();
        let read = tokio::time::timeout(timeout, async {
            let mut buf = [0u8; 4096];
            loop {
                match io.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => line.extend_from_slice(buf.get(..n).unwrap_or_default()),
                }
                if line.len() > 64 * 1024 {
                    break;
                }
            }
        })
        .await;
        if read.is_err() {
            process.kill();
        }
        let oom_kills = process.cgroup.as_ref().map_or(0, WorkerCgroup::oom_kills);
        let events = process.cgroup.as_ref().map(WorkerCgroup::memory_events).unwrap_or_default();
        tracing::debug!(code = "selftest_memory_events", events = %events.replace('\n', " "), "autotest");
        let exit = match tokio::time::timeout(Duration::from_secs(10), process.wait()).await {
            Ok(e) => e,
            Err(_) => {
                process.kill();
                process.wait().await
            }
        };
        let oom_kills = oom_kills.max(process.last_oom_kills);
        Ok(CaseOutcome { line: String::from_utf8_lossy(&line).trim().to_owned(), exit, oom_kills })
    }
}

/// Worker lancé, avec ses types concrets (autotest, mesures).
#[derive(Debug)]
pub struct RawWorker {
    /// Pipe.
    pub io: tokio::net::UnixStream,
    /// Processus.
    pub process: SandboxProcess,
}

/// Processus d'un worker isolé.
#[derive(Debug)]
pub struct SandboxProcess {
    child: Option<tokio::process::Child>,
    pid: Option<u32>,
    cgroup: Option<WorkerCgroup>,
    proxy_task: Option<tokio::task::JoinHandle<()>>,
    dir: Option<PathBuf>,
    stderr: Option<tokio::task::JoinHandle<Option<String>>>,
    started: Instant,
    exit: Option<WorkerExit>,
    /// `oom_kill` relevé avant la suppression du cgroup.
    pub last_oom_kills: u64,
}

impl SandboxProcess {
    /// Instant du lancement.
    #[must_use]
    pub const fn started(&self) -> Instant {
        self.started
    }

    /// Chemin du cgroup du worker (mesures).
    #[must_use]
    pub fn cgroup_path(&self) -> Option<&Path> {
        self.cgroup.as_ref().map(WorkerCgroup::path)
    }

    /// Code d'échec de préparation (`sandbox_error:<code>`), après la fin du processus.
    pub async fn setup_error(&mut self) -> Option<String> {
        self.stderr.take()?.await.ok().flatten()
    }

    async fn cleanup(&mut self) {
        if let Some(t) = self.proxy_task.take() {
            t.abort();
        }
        if let Some(d) = self.dir.take() {
            let _ = std::fs::remove_dir_all(d);
        }
        if let Some(c) = self.cgroup.take() {
            self.last_oom_kills = c.oom_kills();
            c.destroy().await;
        }
    }
}

/// Traduit la fin de l'assistant : 128 + n = le worker a reçu le signal n.
#[must_use]
pub fn map_exit(status: std::process::ExitStatus) -> WorkerExit {
    use std::os::unix::process::ExitStatusExt as _;
    match (status.code(), status.signal()) {
        (Some(c), _) if (129..=192).contains(&c) => WorkerExit::Signaled(c.saturating_sub(128)),
        (Some(c), _) => WorkerExit::Exited(c),
        (None, Some(s)) => WorkerExit::Signaled(s),
        (None, None) => WorkerExit::Unknown,
    }
}

impl WorkerProcess for SandboxProcess {
    fn kill(&mut self) {
        if let Some(c) = &self.cgroup {
            c.kill();
        }
        if let Some(child) = &mut self.child {
            let _ = child.start_kill();
        }
    }

    fn wait(&mut self) -> BoxFuture<'_, WorkerExit> {
        Box::pin(async move {
            if let Some(e) = self.exit {
                return e;
            }
            let exit = match self.child.as_mut() {
                Some(c) => c.wait().await.map_or(WorkerExit::Unknown, map_exit),
                None => WorkerExit::Unknown,
            };
            self.exit = Some(exit);
            self.cleanup().await;
            exit
        })
    }

    fn usage(&self) -> Option<ResourceUsage> {
        self.cgroup.as_ref().and_then(WorkerCgroup::usage)
    }

    fn pid(&self) -> Option<u32> {
        self.pid
    }
}

impl Drop for SandboxProcess {
    fn drop(&mut self) {
        if let Some(t) = self.proxy_task.take() {
            t.abort();
        }
        if let Some(d) = self.dir.take() {
            let _ = std::fs::remove_dir_all(d);
        }
        if let Some(c) = self.cgroup.take() {
            c.kill();
            if let Ok(h) = tokio::runtime::Handle::try_current() {
                h.spawn(c.destroy());
            }
        }
    }
}

impl WorkerLauncher for SandboxLauncher {
    fn spawn(&self, spec: WorkerSpec) -> BoxFuture<'_, Result<SpawnedWorker, LaunchError>> {
        Box::pin(async move {
            let args = ChildArgs { payload: "worker".into(), ..ChildArgs::default() };
            let w = self.spawn_child(args, &spec.resources, spec.llm, Vec::new()).await?;
            Ok(SpawnedWorker { io: Box::new(w.io), process: Box::new(w.process) })
        })
    }

    fn name(&self) -> &'static str {
        match self.mode {
            Mode::Sandboxed => "sandbox",
            Mode::Insecure => "insecure-no-sandbox",
        }
    }

    fn injects_llm_credentials(&self) -> bool {
        true
    }
}

/// Lit le stderr d'un enfant : garde le premier code `sandbox_error:<code>` (identifiant
/// `[a-z0-9_]`, ≤ 64), ignore tout le reste (jamais journalisé).
async fn read_setup_error(stderr: tokio::process::ChildStderr) -> Option<String> {
    let mut lines = tokio::io::BufReader::new(stderr.take(64 * 1024)).lines();
    let mut found = None;
    while let Ok(Some(l)) = lines.next_line().await {
        if found.is_none()
            && let Some(code) = l.strip_prefix("sandbox_error:")
            && !code.is_empty()
            && code.len() <= 64
            && code.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            tracing::warn!(code = %code, "préparation du bac à sable en échec");
            found = Some(code.to_owned());
        }
    }
    found
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

fn clean_run_dir(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let own = format!("-{}", std::process::id());
    for e in entries.flatten() {
        if e.file_name().to_str().is_some_and(|n| n.starts_with("w-") && !n.ends_with(&own)) {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt as _;

    #[test]
    fn traduction_des_fins() {
        let st = |raw| std::process::ExitStatus::from_raw(raw);
        assert_eq!(map_exit(st(0)), WorkerExit::Exited(0));
        assert_eq!(map_exit(st(125 << 8)), WorkerExit::Exited(125));
        assert_eq!(map_exit(st(137 << 8)), WorkerExit::Signaled(9));
        assert_eq!(map_exit(st(9)), WorkerExit::Signaled(9));
    }

    #[test]
    fn codes_expliques() {
        assert!(explain("userns_unavailable").contains("utilisateur"));
        assert!(explain("cgroup_not_delegated").contains("Delegate=yes"));
        assert!(explain("inconnu").contains("10-bac-a-sable"));
    }
}
