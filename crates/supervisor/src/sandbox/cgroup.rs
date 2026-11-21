//! cgroups v2 : un cgroup par worker sous un sous-arbre **délégué** au superviseur (09 §2, D6).
//!
//! Disposition (règle « pas de processus dans un nœud interne » de cgroups v2) :
//!
//! ```text
//! <base>/                 cgroup du service (systemd `Delegate=yes`) ou `sandbox.cgroup_root`
//! ├── supervisor/         le superviseur s'y déplace lui-même au démarrage
//! └── w-<n>/              un par worker : memory.max, memory.swap.max = 0,
//!                         memory.oom.group = 1, pids.max, cpu.max
//! ```
//!
//! L'assistant du bac à sable s'inscrit lui-même dans `w-<n>/cgroup.procs` **avant** de créer ses
//! espaces de noms ; le worker en hérite. Arrêt : `cgroup.kill` (tout le sous-arbre d'un coup).

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::launcher::{ResourceLimits, ResourceUsage};

/// Racine du système de fichiers cgroup v2.
pub const CGROUP_FS: &str = "/sys/fs/cgroup";
/// Contrôleurs exigés.
pub const REQUIRED_CONTROLLERS: [&str; 3] = ["memory", "pids", "cpu"];
/// Préfixe des cgroups de workers.
const WORKER_PREFIX: &str = "w-";
/// Feuille du superviseur.
const SUPERVISOR_LEAF: &str = "supervisor";
/// Période de `cpu.max` (µs).
pub const CPU_PERIOD_USEC: u64 = 100_000;

/// Arbre délégué.
#[derive(Debug)]
pub struct CgroupTree {
    base: PathBuf,
}

/// Cgroup d'un worker.
#[derive(Debug)]
pub struct WorkerCgroup {
    path: PathBuf,
}

/// Chemin du cgroup courant d'après le contenu de `/proc/self/cgroup` (ligne `0::<chemin>`).
#[must_use]
pub fn own_cgroup_path(proc_self_cgroup: &str) -> Option<String> {
    proc_self_cgroup.lines().find_map(|l| l.strip_prefix("0::")).map(|p| p.trim().to_owned())
}

/// Base de l'arbre à partir du cgroup courant : si le superviseur s'est déjà placé dans sa feuille
/// `supervisor/` (second lanceur dans le même processus), la base est le parent.
#[must_use]
pub fn base_from_own(own: &str) -> PathBuf {
    let rel = own.trim_start_matches('/');
    let rel = match rel.rsplit_once('/') {
        Some((parent, SUPERVISOR_LEAF)) => parent,
        _ if rel == SUPERVISOR_LEAF => "",
        _ => rel,
    };
    if rel.is_empty() { PathBuf::from(CGROUP_FS) } else { Path::new(CGROUP_FS).join(rel) }
}

/// Valeur de `cpu.max` pour un pourcentage d'un cœur.
#[must_use]
pub fn cpu_max_value(percent: u64) -> String {
    let quota = percent.clamp(1, 100 * 1024).saturating_mul(CPU_PERIOD_USEC / 100);
    format!("{quota} {CPU_PERIOD_USEC}")
}

/// Lit `usage_usec` dans le contenu de `cpu.stat`.
#[must_use]
pub fn parse_cpu_usage(cpu_stat: &str) -> Option<u64> {
    cpu_stat.lines().find_map(|l| l.strip_prefix("usage_usec ")).and_then(|v| v.trim().parse().ok())
}

/// Somme de `oom_kill` et `oom_group_kill` dans le contenu de `memory.events`.
#[must_use]
pub fn parse_oom_kills(events: &str) -> u64 {
    events
        .lines()
        .filter_map(|l| l.strip_prefix("oom_kill ").or_else(|| l.strip_prefix("oom_group_kill ")))
        .filter_map(|v| v.trim().parse::<u64>().ok())
        .fold(0, u64::saturating_add)
}

/// Un espace d'échange est-il actif (`/proc/swaps` a une ligne après l'en-tête) ? Illisible :
/// supposé actif.
#[must_use]
pub fn system_swap_active() -> bool {
    fs::read_to_string("/proc/swaps").map_or(true, |s| swaps_active(&s))
}

/// Contenu de `/proc/swaps` : au moins une ligne après l'en-tête ?
#[must_use]
pub fn swaps_active(proc_swaps: &str) -> bool {
    proc_swaps.lines().skip(1).any(|l| !l.trim().is_empty())
}

/// Lit `populated` dans le contenu de `cgroup.events`.
#[must_use]
pub fn parse_populated(events: &str) -> Option<bool> {
    events.lines().find_map(|l| l.strip_prefix("populated ")).map(|v| v.trim() != "0")
}

fn write(path: &Path, value: &str) -> Result<(), ErrorKind> {
    fs::write(path, value).map_err(|e| e.kind())
}

fn read_u64(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok().and_then(|s| s.trim().parse().ok())
}

impl CgroupTree {
    /// Prépare l'arbre délégué : vérifie les contrôleurs, déplace le superviseur dans sa feuille,
    /// active `memory pids cpu` pour les enfants et retire les cgroups de workers d'une exécution
    /// précédente. Erreur = code machine (refus de démarrer).
    pub fn setup(explicit: Option<&Path>) -> Result<Self, &'static str> {
        let base = match explicit {
            Some(p) => p.to_path_buf(),
            None => {
                let own = fs::read_to_string("/proc/self/cgroup").map_err(|_| "cgroup_v2_unavailable")?;
                base_from_own(&own_cgroup_path(&own).ok_or("cgroup_v2_unavailable")?)
            }
        };
        let controllers = fs::read_to_string(base.join("cgroup.controllers")).map_err(|_| "cgroup_v2_unavailable")?;
        let available: Vec<&str> = controllers.split_whitespace().collect();
        if !REQUIRED_CONTROLLERS.iter().all(|c| available.contains(c)) {
            return Err("cgroup_controllers_missing");
        }
        let leaf = base.join(SUPERVISOR_LEAF);
        match fs::create_dir(&leaf) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
            Err(_) => return Err("cgroup_not_delegated"),
        }
        // « 0 » = le processus qui écrit (tous ses fils d'exécution).
        write(&leaf.join("cgroup.procs"), "0").map_err(|_| "cgroup_not_delegated")?;
        let wanted: String = REQUIRED_CONTROLLERS.iter().map(|c| format!("+{c} ")).collect();
        write(&base.join("cgroup.subtree_control"), wanted.trim_end()).map_err(|k| {
            if k == ErrorKind::ResourceBusy { "cgroup_base_has_processes" } else { "cgroup_not_delegated" }
        })?;
        let tree = Self { base };
        tree.remove_stale();
        Ok(tree)
    }

    /// Base de l'arbre.
    #[must_use]
    pub fn base(&self) -> &Path {
        &self.base
    }

    fn remove_stale(&self) {
        let Ok(entries) = fs::read_dir(&self.base) else { return };
        // Noms `w-<n>-<pid du superviseur>` : ceux de ce processus (second lanceur) sont gardés.
        let own = format!("-{}", std::process::id());
        for e in entries.flatten() {
            if e.file_name().to_str().is_some_and(|n| n.starts_with(WORKER_PREFIX) && !n.ends_with(&own)) {
                let cg = WorkerCgroup { path: e.path() };
                cg.kill();
                let _ = cg.try_remove();
            }
        }
    }

    /// Crée le cgroup d'un worker et y écrit ses plafonds.
    pub fn create(&self, name: &str, limits: &ResourceLimits) -> Result<WorkerCgroup, &'static str> {
        if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') || name.is_empty() {
            return Err("cgroup_bad_name");
        }
        let path = self.base.join(format!("{WORKER_PREFIX}{name}"));
        if path.exists() {
            let stale = WorkerCgroup { path: path.clone() };
            stale.kill();
            let _ = stale.try_remove();
        }
        fs::create_dir(&path).map_err(|_| "cgroup_create_failed")?;
        let cg = WorkerCgroup { path };
        let settings = [
            ("memory.max", limits.memory_max_bytes.to_string()),
            // `memory.high` n'est PAS appliqué (D6 révisée, docs/plan/10 §5) : sans espace
            // d'échange (exigé ci-dessous pour que les clés n'atteignent jamais le disque), la
            // mémoire anonyme n'est pas récupérable et `memory.high` ne fait que ralentir le
            // worker indéfiniment (mesuré : > 120 s bloqué sous 448 Mio, jamais tué) au lieu de
            // le laisser atteindre `memory.max` et être tué. Valeur explicite `max`.
            ("memory.high", "max".to_owned()),
            ("memory.oom.group", "1".to_owned()),
            ("pids.max", limits.pids_max.to_string()),
            ("cpu.max", cpu_max_value(limits.cpu_max_percent)),
        ];
        for (file, value) in settings {
            if write(&cg.path.join(file), &value).is_err() {
                let _ = cg.try_remove();
                return Err("cgroup_limits_failed");
            }
        }
        // Pas d'espace d'échange : un worker ne contourne pas memory.max en écrivant ses pages (et ses
        // clés) sur le disque. `memory.swap.max` absent (noyau sans comptage du swap) : refus, sauf
        // si aucun espace d'échange n'est actif sur la machine (`/proc/swaps` vide, vérifiable).
        let swap = cg.path.join("memory.swap.max");
        let swap_ok = if swap.exists() { write(&swap, "0").is_ok() } else { !system_swap_active() };
        if !swap_ok {
            let _ = cg.try_remove();
            return Err("cgroup_swap_uncontrolled");
        }
        Ok(cg)
    }
}

impl WorkerCgroup {
    /// `cgroup.procs` (passé à l'assistant, qui s'y inscrit).
    #[must_use]
    pub fn procs_file(&self) -> PathBuf {
        self.path.join("cgroup.procs")
    }

    /// Chemin du cgroup.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Tue tous les processus du cgroup (`cgroup.kill`, noyau ≥ 5.14).
    pub fn kill(&self) {
        let _ = write(&self.path.join("cgroup.kill"), "1");
    }

    /// Consommation (06 §5).
    #[must_use]
    pub fn usage(&self) -> Option<ResourceUsage> {
        let memory_current = read_u64(&self.path.join("memory.current"))?;
        let memory_peak = read_u64(&self.path.join("memory.peak")).unwrap_or(memory_current);
        let cpu_usage_usec =
            fs::read_to_string(self.path.join("cpu.stat")).ok().as_deref().and_then(parse_cpu_usage).unwrap_or(0);
        Some(ResourceUsage { memory_current, memory_peak, cpu_usage_usec })
    }

    /// Contenu brut de `memory.events` (diagnostic).
    #[must_use]
    pub fn memory_events(&self) -> String {
        fs::read_to_string(self.path.join("memory.events")).unwrap_or_default()
    }

    /// Nombre de processus tués par le manque de mémoire du cgroup (`oom_kill` + `oom_group_kill`
    /// de `memory.events`).
    #[must_use]
    pub fn oom_kills(&self) -> u64 {
        parse_oom_kills(&self.memory_events())
    }

    /// Le cgroup contient-il encore un processus ?
    #[must_use]
    pub fn populated(&self) -> bool {
        fs::read_to_string(self.path.join("cgroup.events")).ok().as_deref().and_then(parse_populated).unwrap_or(false)
    }

    /// Supprime le cgroup s'il est vide.
    pub fn try_remove(&self) -> Result<(), ErrorKind> {
        match fs::remove_dir(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.kind()),
        }
    }

    /// Tue, attend que le cgroup soit vide (≤ 5 s) puis le supprime.
    pub async fn destroy(self) {
        self.kill();
        for _ in 0..100 {
            if !self.populated() && self.try_remove().is_ok() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        tracing::warn!(code = "cgroup_not_removed", "cgroup de worker non supprimé (processus encore présents)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chemins_et_valeurs() {
        assert_eq!(own_cgroup_path("0::/user.slice/a.scope\n").as_deref(), Some("/user.slice/a.scope"));
        assert_eq!(own_cgroup_path("1:name=systemd:/x\n"), None);
        assert_eq!(base_from_own("/a/b.scope"), PathBuf::from("/sys/fs/cgroup/a/b.scope"));
        assert_eq!(base_from_own("/a/b.scope/supervisor"), PathBuf::from("/sys/fs/cgroup/a/b.scope"));
        assert_eq!(base_from_own("/"), PathBuf::from("/sys/fs/cgroup"));
        assert_eq!(cpu_max_value(100), "100000 100000");
        assert_eq!(cpu_max_value(50), "50000 100000");
        assert_eq!(cpu_max_value(0), "1000 100000");
        assert_eq!(parse_cpu_usage("usage_usec 1234\nuser_usec 1\n"), Some(1234));
        assert_eq!(parse_populated("populated 0\nfrozen 0\n"), Some(false));
        assert_eq!(parse_populated("populated 1\n"), Some(true));
        assert!(!swaps_active("Filename\tType\tSize\tUsed\tPriority\n"));
        assert!(swaps_active("Filename\tType\n/dev/zram0 partition 8388604 0 100\n"));
        assert_eq!(parse_oom_kills("low 0\noom 1\noom_kill 1\noom_group_kill 1\n"), 2);
    }

    #[test]
    fn nom_de_cgroup_controle() {
        let tree = CgroupTree { base: PathBuf::from("/nonexistent-synco") };
        let l = ResourceLimits { memory_max_bytes: 1, cpu_max_percent: 1, pids_max: 1 };
        assert_eq!(tree.create("../x", &l).unwrap_err(), "cgroup_bad_name");
        assert_eq!(tree.create("", &l).unwrap_err(), "cgroup_bad_name");
    }
}
