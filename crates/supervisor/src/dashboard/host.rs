//! Charge globale de la machine (CPU, RAM, charge), lue dans `/proc` : aucune donnée de conversation.

use std::sync::{Mutex, PoisonError};

use serde::Serialize;

/// Charge de la machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HostLoad {
    /// Cœurs disponibles.
    pub cpus: u64,
    /// Charge moyenne sur 1 minute, en centièmes.
    pub load1_centi: Option<u64>,
    /// CPU utilisé depuis la mesure précédente, en millièmes de la machine (`None` à la première).
    pub cpu_permille: Option<u64>,
    /// RAM totale (octets).
    pub mem_total: Option<u64>,
    /// RAM disponible (octets).
    pub mem_available: Option<u64>,
}

/// `(occupé, total)` en ticks depuis la ligne `cpu` de `/proc/stat`.
#[must_use]
pub fn parse_cpu_line(stat: &str) -> Option<(u64, u64)> {
    let line = stat.lines().next()?;
    let mut f = line.split_whitespace();
    if f.next()? != "cpu" {
        return None;
    }
    let v: Vec<u64> = f.filter_map(|x| x.parse().ok()).collect();
    if v.len() < 5 {
        return None;
    }
    let total = v.iter().take(8).fold(0u64, |a, x| a.saturating_add(*x));
    let idle = v.get(3).copied()?.saturating_add(v.get(4).copied()?);
    Some((total.saturating_sub(idle), total))
}

/// Charge à 1 minute en centièmes, depuis `/proc/loadavg`.
#[must_use]
pub fn parse_load1(loadavg: &str) -> Option<u64> {
    let first = loadavg.split_whitespace().next()?;
    let (int, frac) = first.split_once('.').unwrap_or((first, "0"));
    let frac: String = frac.chars().chain("00".chars()).take(2).collect();
    int.parse::<u64>().ok()?.checked_mul(100)?.checked_add(frac.parse().ok()?)
}

/// Valeur en octets d'une ligne `Clé: N kB` de `/proc/meminfo`.
#[must_use]
pub fn parse_meminfo(meminfo: &str, key: &str) -> Option<u64> {
    let line = meminfo.lines().find(|l| l.strip_prefix(key).is_some_and(|r| r.starts_with(':')))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kb.checked_mul(1024)
}

/// Échantillonneur : le CPU se calcule entre deux lectures successives.
#[derive(Debug, Default)]
pub struct HostSampler {
    last: Mutex<Option<(u64, u64)>>,
}

impl HostSampler {
    /// Lit l'état courant.
    pub fn sample(&self) -> HostLoad {
        let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
        let cpu = parse_cpu_line(&read("/proc/stat"));
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        let cpu_permille = match (cpu, *last) {
            (Some((busy, total)), Some((b0, t0))) if total > t0 => {
                Some(busy.saturating_sub(b0).saturating_mul(1000).checked_div(total.saturating_sub(t0)).unwrap_or(0))
            }
            _ => None,
        };
        if cpu.is_some() {
            *last = cpu;
        }
        let meminfo = read("/proc/meminfo");
        HostLoad {
            cpus: std::thread::available_parallelism().map_or(1, |n| u64::try_from(n.get()).unwrap_or(1)),
            load1_centi: parse_load1(&read("/proc/loadavg")),
            cpu_permille,
            mem_total: parse_meminfo(&meminfo, "MemTotal"),
            mem_available: parse_meminfo(&meminfo, "MemAvailable"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyse_de_proc() {
        assert_eq!(parse_cpu_line("cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 2"), Some((200, 1000)));
        assert_eq!(parse_cpu_line("intr 1 2"), None);
        assert_eq!(parse_load1("0.52 0.40 0.30 1/100 42"), Some(52));
        assert_eq!(parse_load1("12.5 1 1"), Some(1250));
        let mi = "MemTotal:       16000 kB\nMemAvailable:    4000 kB\nMemFree: 1 kB\n";
        assert_eq!(parse_meminfo(mi, "MemTotal"), Some(16_000 * 1024));
        assert_eq!(parse_meminfo(mi, "MemAvailable"), Some(4_000 * 1024));
        assert_eq!(parse_meminfo(mi, "Mem"), None);
    }

    #[test]
    fn deux_lectures_donnent_un_cpu() {
        let s = HostSampler::default();
        assert_eq!(s.sample().cpu_permille, None, "première lecture : pas de différence");
        assert!(s.sample().cpus >= 1);
    }
}
