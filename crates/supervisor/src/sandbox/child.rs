//! Côté enfant du bac à sable : deux étapes exécutées par le binaire du superviseur relancé
//! (`fork` + `exec` par `std::process::Command`, jamais un `fork` seul d'un processus qui détient
//! des clés), **avant** tout moteur asynchrone, avec un environnement vide.
//!
//! 1. `__sandbox-helper` (assistant, hors de l'espace de noms PID du worker) : vérifie qu'il n'a
//!    hérité d'aucun descripteur autre que 0, 1, 2 ; s'inscrit dans le cgroup du worker ; crée les
//!    espaces de noms user, mount, pid, net, ipc, uts, cgroup ; écrit `uid_map`/`gid_map` (une seule
//!    identité, celle du service) ; lance l'étape 2 et attend sa fin.
//! 2. `__sandbox-worker` (PID 1 de son espace de noms) : met le pipe sur le descripteur 3 ; construit
//!    une racine `tmpfs` vide en lecture seule (seul le répertoire du socket du mandataire LLM y est
//!    monté), `pivot_root`, détache l'ancienne racine (plus aucun `/proc`, `/home`, `/sys`, état du
//!    superviseur) ; retire les capacités ; `no_new_privs` ; landlock ; seccomp ; puis exécute le
//!    worker **dans ce même processus** (aucun `execve` après le filtre, qui l'interdit).
//!
//! Une erreur de préparation est signalée sur stderr par une ligne `sandbox_error:<code>` (le
//! superviseur ne lit que ces lignes) et le processus quitte avec [`EXIT_SETUP_FAILED`].

use std::ffi::OsString;
use std::io::Write as _;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use rustix::fs::{Mode, OFlags, StatVfsMountFlags};
use rustix::mount::{MountFlags, MountPropagationFlags, UnmountFlags};
use rustix::process::Signal;
use rustix::thread::UnshareFlags;

use super::{policy, selftest, sys};

/// Argument de l'étape 1.
pub const HELPER_ARG: &str = "__sandbox-helper";
/// Argument de l'étape 2.
pub const WORKER_ARG: &str = "__sandbox-worker";
/// Code de sortie d'une préparation échouée.
pub const EXIT_SETUP_FAILED: u8 = 125;
/// Répertoire du socket du mandataire LLM **dans** la racine du worker.
pub const SANDBOX_LLM_DIR: &str = "/run/synco";
/// Nom du socket du mandataire.
pub const LLM_SOCKET_NAME: &str = "llm.sock";
/// Descripteur du pipe dans le worker (06 §1).
pub const PIPE_FD: i32 = 3;

/// Couche du bac à sable qu'un test peut retirer pour prouver qu'une autre suffit
/// (`--without`, jamais utilisé par le superviseur en production).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Espace de noms réseau.
    Net,
    /// seccomp.
    Seccomp,
    /// landlock.
    Landlock,
}

impl Layer {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "net" => Some(Self::Net),
            "seccomp" => Some(Self::Seccomp),
            "landlock" => Some(Self::Landlock),
            _ => None,
        }
    }

    /// Nom en argument.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Net => "net",
            Self::Seccomp => "seccomp",
            Self::Landlock => "landlock",
        }
    }
}

/// Arguments des deux étapes (aucun secret).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChildArgs {
    /// Charge : `worker`, `probe`, `echo`, `selftest`.
    pub payload: String,
    /// Nom du test (`selftest`).
    pub test: Option<String>,
    /// Arguments du test.
    pub test_args: Vec<String>,
    /// `cgroup.procs` du worker (étape 1).
    pub cgroup_procs: Option<PathBuf>,
    /// Répertoire hôte du socket du mandataire LLM.
    pub llm_dir: Option<PathBuf>,
    /// Sans bac à sable (`--insecure-no-sandbox`) : étape 2 seule, aucune restriction.
    pub insecure: bool,
    /// Couches retirées (tests).
    pub without: Vec<Layer>,
}

impl ChildArgs {
    /// Sérialise en arguments (sans l'argument d'étape).
    #[must_use]
    pub fn to_args(&self, with_cgroup: bool) -> Vec<OsString> {
        let mut a: Vec<OsString> = vec!["--payload".into(), self.payload.clone().into()];
        if let Some(t) = &self.test {
            a.extend(["--test".into(), t.into()]);
        }
        for x in &self.test_args {
            a.extend(["--arg".into(), x.into()]);
        }
        if with_cgroup && let Some(c) = &self.cgroup_procs {
            a.extend(["--cgroup-procs".into(), c.into()]);
        }
        if let Some(d) = &self.llm_dir {
            a.extend(["--llm-dir".into(), d.into()]);
        }
        if self.insecure {
            a.push("--insecure".into());
        }
        for l in &self.without {
            a.extend(["--without".into(), l.as_str().into()]);
        }
        a
    }

    /// Analyse les arguments (sans l'argument d'étape).
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, &'static str> {
        let mut out = Self::default();
        let mut it = args.into_iter();
        while let Some(a) = it.next() {
            let a = a.into_string().map_err(|_| "bad_args")?;
            let mut value = || it.next().ok_or("bad_args");
            match a.as_str() {
                "--payload" => out.payload = value()?.into_string().map_err(|_| "bad_args")?,
                "--test" => out.test = Some(value()?.into_string().map_err(|_| "bad_args")?),
                "--arg" => out.test_args.push(value()?.into_string().map_err(|_| "bad_args")?),
                "--cgroup-procs" => out.cgroup_procs = Some(PathBuf::from(value()?)),
                "--llm-dir" => out.llm_dir = Some(PathBuf::from(value()?)),
                "--insecure" => out.insecure = true,
                "--without" => {
                    let l = value()?.into_string().map_err(|_| "bad_args")?;
                    out.without.push(Layer::parse(&l).ok_or("bad_args")?);
                }
                _ => return Err("bad_args"),
            }
        }
        if !matches!(out.payload.as_str(), "worker" | "probe" | "echo" | "selftest") {
            return Err("bad_args");
        }
        Ok(out)
    }

    fn has(&self, l: Layer) -> bool {
        !self.without.contains(&l)
    }
}

fn report(code: &str) {
    let mut e = std::io::stderr().lock();
    let _ = writeln!(e, "sandbox_error:{code}");
}

/// Point d'entrée appelé par `main` **avant** le moteur asynchrone : `Some(code)` si ce processus
/// est une étape du bac à sable, `None` sinon (superviseur normal).
#[must_use]
pub fn child_main() -> Option<ExitCode> {
    let mut args = std::env::args_os();
    let _program = args.next();
    let stage = args.next()?;
    let helper = stage == HELPER_ARG;
    if !helper && stage != WORKER_ARG {
        return None;
    }
    let result = ChildArgs::parse(args).and_then(|a| if helper { helper_stage(&a) } else { worker_stage(&a) });
    Some(match result {
        Ok(code) => code,
        Err(code) => {
            report(code);
            ExitCode::from(EXIT_SETUP_FAILED)
        }
    })
}

/// Descripteurs ouverts du processus, sauf celui qui sert à les lister.
fn open_fds() -> Result<Vec<i32>, &'static str> {
    let listed: Vec<i32> = std::fs::read_dir("/proc/self/fd")
        .map_err(|_| "fd_list")?
        .filter_map(|e| e.ok().and_then(|e| e.file_name().to_str().and_then(|n| n.parse().ok())))
        .collect();
    // Le descripteur du répertoire listé est fermé : son entrée n'existe plus.
    Ok(listed.into_iter().filter(|fd| Path::new(&format!("/proc/self/fd/{fd}")).exists()).collect())
}

/// Refuse tout descripteur hérité autre que `allowed`.
fn check_fds(allowed: &[i32]) -> Result<(), &'static str> {
    if open_fds()?.iter().all(|fd| allowed.contains(fd)) { Ok(()) } else { Err("inherited_fd") }
}

/// Étape 1.
fn helper_stage(a: &ChildArgs) -> Result<ExitCode, &'static str> {
    rustix::process::set_parent_process_death_signal(Some(Signal::KILL)).map_err(|_| "pdeathsig")?;
    check_fds(&[0, 1, 2])?;
    if let Some(procs) = &a.cgroup_procs {
        std::fs::write(procs, "0").map_err(|_| "cgroup_join")?;
    }
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    let mut flags = UnshareFlags::NEWUSER
        | UnshareFlags::NEWNS
        | UnshareFlags::NEWPID
        | UnshareFlags::NEWIPC
        | UnshareFlags::NEWUTS
        | UnshareFlags::NEWCGROUP;
    if a.has(Layer::Net) {
        flags |= UnshareFlags::NEWNET;
    }
    sys::unshare_namespaces(flags).map_err(|_| "userns_unavailable")?;
    std::fs::write("/proc/self/setgroups", "deny").map_err(|_| "userns_setgroups")?;
    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).map_err(|_| "userns_uid_map")?;
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).map_err(|_| "userns_gid_map")?;
    let status = Command::new("/proc/self/exe")
        .arg(WORKER_ARG)
        .args(a.to_args(false))
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|_| "spawn_worker")?;
    Ok(exit_code_of(status))
}

/// Code de sortie de l'assistant : celui du worker, ou 128 + signal (le superviseur le retraduit).
fn exit_code_of(status: std::process::ExitStatus) -> ExitCode {
    use std::os::unix::process::ExitStatusExt as _;
    if let Some(c) = status.code() {
        return ExitCode::from(u8::try_from(c).unwrap_or(1));
    }
    let sig = status.signal().and_then(|s| u8::try_from(s).ok()).unwrap_or(9);
    ExitCode::from(sig.saturating_add(128))
}

/// Indicateurs de montage existants à conserver lors d'un remontage (un montage hérité dans un
/// espace de noms utilisateur garde verrouillés `nosuid`, `nodev`, `noexec` et l'heure d'accès).
fn locked_flags(path: &Path) -> Result<MountFlags, &'static str> {
    let st = rustix::fs::statvfs(path).map_err(|_| "statvfs")?;
    let mut f = MountFlags::empty();
    for (vfs, mnt) in [
        (StatVfsMountFlags::NOSUID, MountFlags::NOSUID),
        (StatVfsMountFlags::NODEV, MountFlags::NODEV),
        (StatVfsMountFlags::NOEXEC, MountFlags::NOEXEC),
        (StatVfsMountFlags::NOATIME, MountFlags::NOATIME),
        (StatVfsMountFlags::NODIRATIME, MountFlags::NODIRATIME),
        (StatVfsMountFlags::RELATIME, MountFlags::RELATIME),
    ] {
        if st.f_flag.contains(vfs) {
            f |= mnt;
        }
    }
    Ok(f)
}

/// Racine minimale : `tmpfs` vide (seul le répertoire du socket LLM y est monté en lecture seule),
/// `pivot_root`, ancienne racine détachée, racine remontée en lecture seule.
fn build_root(llm_dir: Option<&Path>) -> Result<(), &'static str> {
    use rustix::mount::{mount, mount_bind, mount_change, mount_remount, unmount};
    let hard = MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC;
    mount_change("/", MountPropagationFlags::REC | MountPropagationFlags::PRIVATE).map_err(|_| "mount_private")?;
    // Le répertoire du socket est ouvert AVANT de recouvrir /tmp (il peut s'y trouver), puis monté
    // depuis ce descripteur.
    let llm_fd = match llm_dir {
        Some(dir) => Some(
            rustix::fs::open(dir, OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW, Mode::empty())
                .map_err(|_| "llm_dir_open")?,
        ),
        None => None,
    };
    // /tmp existe partout (y compris sous systemd PrivateTmp= et dans un conteneur) ; le tmpfs n'est
    // visible que dans l'espace de noms de montage du worker.
    mount("synco-worker", "/tmp", "tmpfs", hard, Some(c"size=16k,nr_inodes=16,mode=0755"))
        .map_err(|_| "mount_tmpfs")?;
    if let Some(fd) = llm_fd {
        rustix::fs::mkdir("/tmp/run", Mode::from_raw_mode(0o755)).map_err(|_| "mkdir_root")?;
        rustix::fs::mkdir("/tmp/run/synco", Mode::from_raw_mode(0o755)).map_err(|_| "mkdir_root")?;
        let source = format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&fd));
        mount_bind(source.as_str(), "/tmp/run/synco").map_err(|_| "mount_llm_dir")?;
        drop(fd);
        let keep = locked_flags(Path::new("/tmp/run/synco"))?;
        mount_remount("/tmp/run/synco", MountFlags::BIND | MountFlags::RDONLY | hard | keep, "")
            .map_err(|_| "mount_llm_dir_ro")?;
    }
    rustix::process::chdir("/tmp").map_err(|_| "chdir_root")?;
    rustix::process::pivot_root(".", ".").map_err(|_| "pivot_root")?;
    unmount(".", UnmountFlags::DETACH).map_err(|_| "umount_old_root")?;
    rustix::process::chdir("/").map_err(|_| "chdir_root")?;
    mount_remount("/", MountFlags::BIND | MountFlags::RDONLY | hard, "").map_err(|_| "mount_root_ro")?;
    Ok(())
}

/// Étape 2.
fn worker_stage(a: &ChildArgs) -> Result<ExitCode, &'static str> {
    // Le pipe arrive sur stdin ; il passe sur le descripteur 3 (06 §1), stdin devient /dev/null
    // (stdout, fourni par le superviseur).
    let stdin = std::io::stdin();
    let pipe: OwnedFd = rustix::io::fcntl_dupfd_cloexec(stdin.as_fd(), PIPE_FD).map_err(|_| "pipe_fd")?;
    if std::os::fd::AsRawFd::as_raw_fd(&pipe) != PIPE_FD {
        return Err("pipe_fd");
    }
    let stdout = std::io::stdout();
    rustix::stdio::dup2_stdin(stdout.as_fd()).map_err(|_| "stdio")?;
    let llm_socket = if a.insecure {
        a.llm_dir.as_ref().map(|d| d.join(LLM_SOCKET_NAME))
    } else {
        rustix::process::set_parent_process_death_signal(Some(Signal::KILL)).map_err(|_| "pdeathsig")?;
        if rustix::process::getpid().as_raw_nonzero().get() != 1 {
            return Err("pidns_unavailable");
        }
        check_fds(&[0, 1, 2, PIPE_FD])?;
        build_root(a.llm_dir.as_deref())?;
        // Nom d'hôte neutre dans l'espace de noms UTS du worker. Au mieux : `ProtectHostname=yes`
        // de systemd interdit `sethostname` (le worker voit alors le nom de la machine, sans autre
        // effet : il ne peut pas le changer).
        let _ = rustix::system::sethostname(b"synco-worker");
        policy::drop_capabilities()?;
        policy::no_new_privs()?;
        let socket_dir = a.llm_dir.as_ref().map(|_| SANDBOX_LLM_DIR);
        if a.has(Layer::Landlock) {
            policy::apply_landlock(socket_dir)?;
        }
        if a.has(Layer::Seccomp) {
            policy::apply_seccomp()?;
        }
        a.llm_dir.as_ref().map(|_| Path::new(SANDBOX_LLM_DIR).join(LLM_SOCKET_NAME))
    };
    // Préparation terminée : stderr part à /dev/null (un message de panique pourrait contenir du
    // contenu ; le superviseur ne lit que les lignes `sandbox_error:`).
    rustix::stdio::dup2_stderr(stdout.as_fd()).map_err(|_| "stdio")?;
    let stream = std::os::unix::net::UnixStream::from(pipe);
    let code = match a.payload.as_str() {
        "worker" => synco_ai_runtime_worker::entry::run(stream, llm_socket),
        "probe" => 0,
        "echo" => selftest::echo(stream),
        _ => selftest::run_in_sandbox(stream, a.test.as_deref().unwrap_or_default(), &a.test_args, llm_socket),
    };
    Ok(ExitCode::from(code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_aller_retour() {
        let a = ChildArgs {
            payload: "selftest".into(),
            test: Some("connect".into()),
            test_args: vec!["127.0.0.1:1".into()],
            cgroup_procs: Some("/sys/fs/cgroup/x/w-1/cgroup.procs".into()),
            llm_dir: Some("/var/lib/x/workers/w1".into()),
            insecure: false,
            without: vec![Layer::Seccomp],
        };
        assert_eq!(ChildArgs::parse(a.to_args(true)).unwrap(), a);
        let no_cg = ChildArgs::parse(a.to_args(false)).unwrap();
        assert_eq!(no_cg.cgroup_procs, None);
        assert!(ChildArgs::parse(["--payload".into(), "autre".into()]).is_err());
        assert!(ChildArgs::parse(["--payload".into(), "probe".into(), "--x".into()]).is_err());
        assert!(ChildArgs::parse(["--payload".into(), "probe".into(), "--without".into(), "caps".into()]).is_err());
    }

    #[test]
    fn processus_normal_ignore() {
        // Le binaire de test n'est pas lancé avec un argument d'étape.
        assert!(child_main().is_none());
    }
}
