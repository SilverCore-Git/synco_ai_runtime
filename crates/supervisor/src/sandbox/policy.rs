//! Restrictions appliquées par le worker à lui-même, juste avant d'exécuter son code (docs/plan/10) :
//! capacités retirées, `no_new_privs`, landlock (aucun accès au système de fichiers sauf la
//! connexion au mandataire LLM), seccomp (liste blanche).

use std::collections::BTreeMap;

use landlock::{
    ABI, Access, AccessFs, AccessNet, LandlockStatus, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus, Scope,
};
use rustix::thread::{
    CapabilitiesSecureBits, CapabilitySet, CapabilitySets, capability_is_in_bounding_set, clear_ambient_capability_set,
    remove_capability_from_bounding_set, set_capabilities, set_capabilities_secure_bits, set_no_new_privs,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule, TargetArch,
};

/// Retire toutes les capacités (dans l'espace de noms utilisateur du worker) : ensemble limitant,
/// ambiant, effectif, permis, héritable ; verrouille les bits de sécurité (pas de retour à root).
pub fn drop_capabilities() -> Result<(), &'static str> {
    let bits = CapabilitiesSecureBits::NO_ROOT
        | CapabilitiesSecureBits::NO_ROOT_LOCKED
        | CapabilitiesSecureBits::NO_SETUID_FIXUP
        | CapabilitiesSecureBits::NO_SETUID_FIXUP_LOCKED
        | CapabilitiesSecureBits::KEEP_CAPS_LOCKED
        | CapabilitiesSecureBits::NO_CAP_AMBIENT_RAISE
        | CapabilitiesSecureBits::NO_CAP_AMBIENT_RAISE_LOCKED;
    set_capabilities_secure_bits(bits).map_err(|_| "caps_securebits")?;
    for bit in 0..64u32 {
        let cap = CapabilitySet::from_bits_retain(1u64 << bit);
        match capability_is_in_bounding_set(cap) {
            Ok(true) => remove_capability_from_bounding_set(cap).map_err(|_| "caps_bounding")?,
            Ok(false) => {}
            // Au-delà de la dernière capacité connue du noyau.
            Err(_) => break,
        }
    }
    clear_ambient_capability_set().map_err(|_| "caps_ambient")?;
    let empty = CapabilitySet::empty();
    set_capabilities(None, CapabilitySets { effective: empty, permitted: empty, inheritable: empty })
        .map_err(|_| "caps_drop")?;
    Ok(())
}

/// `PR_SET_NO_NEW_PRIVS` (exigé par seccomp sans privilège et par landlock).
pub fn no_new_privs() -> Result<(), &'static str> {
    set_no_new_privs(true).map_err(|_| "no_new_privs")
}

/// Résultat de landlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LandlockReport {
    /// ABI effective (0 si landlock indisponible).
    pub abi: u8,
    /// Toutes les restrictions demandées sont appliquées.
    pub fully_enforced: bool,
}

fn abi_number(status: LandlockStatus) -> u8 {
    match status {
        LandlockStatus::Available { effective_abi, .. } => {
            [ABI::V1, ABI::V2, ABI::V3, ABI::V4, ABI::V5, ABI::V6, ABI::V7, ABI::V8, ABI::V9]
                .iter()
                .zip(1u8..)
                .find_map(|(a, n)| (*a == effective_abi).then_some(n))
                .unwrap_or(0)
        }
        _ => 0,
    }
}

/// landlock : tous les droits du système de fichiers et du réseau TCP sont « gérés » sans aucune
/// règle, sauf `ResolveUnix` (connexion au socket du mandataire) sous `socket_dir` ; portées
/// « socket abstrait » et « signal » (le worker ne joint ni socket abstrait ni processus hors de
/// son domaine). Mode « meilleur effort » : un noyau plus ancien applique ce qu'il connaît ;
/// **refus** si landlock n'est pas appliqué du tout.
pub fn apply_landlock(socket_dir: Option<&str>) -> Result<LandlockReport, &'static str> {
    let abi = ABI::V9;
    let mut created = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .and_then(|r| r.handle_access(AccessNet::from_all(abi)))
        .and_then(|r| r.scope(Scope::from_all(abi)))
        .and_then(|r| r.create())
        .map_err(|_| "landlock_ruleset")?;
    if let Some(dir) = socket_dir {
        let fd = PathFd::new(dir).map_err(|_| "landlock_socket_dir")?;
        created = created.add_rule(PathBeneath::new(fd, AccessFs::ResolveUnix)).map_err(|_| "landlock_rule")?;
    }
    let status = created.restrict_self().map_err(|_| "landlock_restrict")?;
    if status.ruleset == RulesetStatus::NotEnforced {
        return Err("landlock_unavailable");
    }
    Ok(LandlockReport {
        abi: abi_number(status.landlock),
        fully_enforced: status.ruleset == RulesetStatus::FullyEnforced,
    })
}

fn target_arch() -> Result<TargetArch, &'static str> {
    if cfg!(target_arch = "x86_64") {
        Ok(TargetArch::x86_64)
    } else if cfg!(target_arch = "aarch64") {
        Ok(TargetArch::aarch64)
    } else if cfg!(target_arch = "riscv64") {
        Ok(TargetArch::riscv64)
    } else {
        Err("seccomp_arch_unsupported")
    }
}

fn cond(arg: u8, op: SeccompCmpOp, value: u64) -> Result<SeccompCondition, &'static str> {
    SeccompCondition::new(arg, SeccompCmpArgLen::Qword, op, value).map_err(|_| "seccomp_build")
}

fn rule(conds: Vec<SeccompCondition>) -> Result<SeccompRule, &'static str> {
    SeccompRule::new(conds).map_err(|_| "seccomp_build")
}

fn to_u64(v: i32) -> u64 {
    u64::from(v.unsigned_abs())
}

/// Appels système permis sans condition : boucle `tokio` mono-fil, client HTTP sur socket Unix,
/// allocation, signaux de son propre processus, horloge, aléa. Aucun `open*`, aucun `exec*`, aucun
/// appel de montage, de trace ou d'espace de noms.
#[must_use]
pub fn allowed_syscalls() -> Vec<i64> {
    let mut v = vec![
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_close,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_shutdown,
        libc::SYS_connect,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_getsockopt,
        libc::SYS_setsockopt,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        libc::SYS_epoll_pwait2,
        libc::SYS_ppoll,
        libc::SYS_eventfd2,
        libc::SYS_futex,
        libc::SYS_set_robust_list,
        libc::SYS_rseq,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_mprotect,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_tgkill,
        libc::SYS_kill,
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_gettimeofday,
        libc::SYS_getrandom,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_restart_syscall,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_getppid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_uname,
        libc::SYS_fcntl,
        libc::SYS_fstat,
        libc::SYS_statx,
        libc::SYS_newfstatat,
        libc::SYS_dup,
        libc::SYS_dup3,
    ];
    #[cfg(target_arch = "x86_64")]
    v.extend([libc::SYS_epoll_wait, libc::SYS_poll, libc::SYS_dup2, libc::SYS_arch_prctl]);
    v
}

/// Appels système hostiles : **tuent** le processus (et rien d'autre que lui) au lieu d'échouer, pour qu'une tentative ne passe pas inaperçue.
#[must_use]
pub fn fatal_syscalls() -> Vec<i64> {
    let mut v = vec![
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_memfd_create,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        libc::SYS_fanotify_init,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_mount_setattr,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_reboot,
        libc::SYS_settimeofday,
        libc::SYS_clock_settime,
        libc::SYS_adjtimex,
        libc::SYS_personality,
        libc::SYS_quotactl,
        libc::SYS_acct,
    ];
    #[cfg(target_arch = "x86_64")]
    v.extend([libc::SYS_iopl, libc::SYS_ioperm, libc::SYS_uselib]);
    v
}

/// Filtres seccomp, dans l'ordre d'installation (chaque installation exige que les filtres déjà
/// posés permettent `prctl(PR_SET_NO_NEW_PRIVS)` et `seccomp` : la liste blanche vient donc en
/// dernier ; l'action la plus sévère l'emporte, quel que soit l'ordre) :
///
/// 1. appels hostiles → processus tué (`SIGSYS`) ;
/// 2. **liste blanche** : tout appel absent → `ENOSYS` (comme un noyau qui ne le connaît pas :
///    `clone3` fait ainsi replier la glibc sur `clone`, dont les drapeaux sont filtrables) ;
///    `socket` et `socketpair` seulement `AF_UNIX` ; `clone` seulement avec `CLONE_THREAD` (fils d'exécution,
///    jamais un nouveau processus) ; `prctl` seulement `PR_SET_NAME`/`PR_GET_NAME` ; `prlimit64` en
///    lecture ; `ioctl` `FIONBIO`/`FIOCLEX`.
pub fn seccomp_programs() -> Result<Vec<BpfProgram>, &'static str> {
    let arch = target_arch()?;
    let mut allow: BTreeMap<i64, Vec<SeccompRule>> = allowed_syscalls().into_iter().map(|s| (s, vec![])).collect();
    allow.insert(libc::SYS_socket, vec![rule(vec![cond(0, SeccompCmpOp::Eq, to_u64(libc::AF_UNIX))?])?]);
    // `tokio` crée une paire locale pour son pilote de signaux (dès que l'E/S est activée).
    allow.insert(libc::SYS_socketpair, vec![rule(vec![cond(0, SeccompCmpOp::Eq, to_u64(libc::AF_UNIX))?])?]);
    let thread = to_u64(libc::CLONE_THREAD);
    allow.insert(libc::SYS_clone, vec![rule(vec![cond(0, SeccompCmpOp::MaskedEq(thread), thread)?])?]);
    allow.insert(
        libc::SYS_prctl,
        vec![
            rule(vec![cond(0, SeccompCmpOp::Eq, to_u64(libc::PR_SET_NAME))?])?,
            rule(vec![cond(0, SeccompCmpOp::Eq, to_u64(libc::PR_GET_NAME))?])?,
        ],
    );
    allow.insert(libc::SYS_prlimit64, vec![rule(vec![cond(0, SeccompCmpOp::Eq, 0)?, cond(2, SeccompCmpOp::Eq, 0)?])?]);
    allow.insert(
        libc::SYS_ioctl,
        vec![
            rule(vec![cond(1, SeccompCmpOp::Eq, libc::FIONBIO)?])?,
            rule(vec![cond(1, SeccompCmpOp::Eq, libc::FIOCLEX)?])?,
        ],
    );
    let enosys = u32::try_from(libc::ENOSYS).map_err(|_| "seccomp_build")?;
    let fatal = SeccompFilter::new(
        fatal_syscalls().into_iter().map(|s| (s, vec![])).collect(),
        SeccompAction::Allow,
        SeccompAction::KillProcess,
        arch,
    )
    .map_err(|_| "seccomp_build")?;
    let whitelist = SeccompFilter::new(allow, SeccompAction::Errno(enosys), SeccompAction::Allow, arch)
        .map_err(|_| "seccomp_build")?;
    [fatal, whitelist].into_iter().map(|f| BpfProgram::try_from(f).map_err(|_| "seccomp_build")).collect()
}

/// Installe les filtres (après `no_new_privs`).
pub fn apply_seccomp() -> Result<(), &'static str> {
    for p in seccomp_programs()? {
        seccompiler::apply_filter(&p).map_err(|_| "seccomp_unavailable")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filtres_compilables_et_disjoints() {
        assert_eq!(seccomp_programs().unwrap().len(), 2);
        let allowed = allowed_syscalls();
        for s in fatal_syscalls() {
            assert!(!allowed.contains(&s), "appel {s} à la fois permis et fatal");
        }
        for s in [libc::SYS_openat, libc::SYS_execve, libc::SYS_clone3, libc::SYS_socketpair, libc::SYS_seccomp] {
            assert!(!allowed.contains(&s), "appel {s} ne doit pas être permis sans condition");
        }
    }
}
