//! Historique des exécutions de workers (docs/plan/11 §5, §6) : enregistrements **typés** sans
//! aucun champ libre (compteurs, états d'une liste fermée, identifiants validés), tenus en mémoire
//! et écrits en JSONL (`history-AAAA-MM-JJ.jsonl`). Aucune voie pour du texte de conversation.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use runtime_protocol::ids::is_identifier;
use runtime_protocol::pipe::Metrics;
use serde::{Deserialize, Serialize};

use crate::launcher::{ResourceUsage, WorkerExit};

/// Sous-dossier de l'historique dans le répertoire d'état.
pub const HISTORY_DIR: &str = "dashboard";
/// Entrées de chronologie conservées par exécution.
pub const MAX_TIMELINE: usize = 500;
/// Exécutions gardées en mémoire (les plus anciennes sont abandonnées au-delà).
pub const MAX_RUNS: usize = 50_000;
/// Intervalle entre deux points de reprise d'une exécution active (s).
pub const CHECKPOINT_SECS: u64 = 60;
const MAX_LINE_BYTES: u64 = 512 * 1024;
const SECS_PER_DAY: u64 = 86_400;

/// États admis (08 §1) ; tout autre est enregistré `other`.
const STATUSES: [&str; 9] = [
    "idle",
    "awaiting_confirmation",
    "awaiting_client_tool",
    "queued",
    "running",
    "awaiting_user",
    "awaiting_key",
    "failed",
    "cancelled",
];
/// Codes d'erreur admis (08 §6) ; tout autre est enregistré `other`.
const REASONS: [&str; 11] = [
    "provider_error",
    "provider_auth",
    "budget_exceeded",
    "step_limit",
    "turn_timeout",
    "confirmation_timeout",
    "key_timeout",
    "worker_crash_loop",
    "tool_failed",
    "revoked",
    "internal",
];

/// Ramène un état à la liste fermée.
#[must_use]
pub fn clean_status(s: &str) -> String {
    if STATUSES.contains(&s) { s.to_owned() } else { "other".to_owned() }
}

/// Ramène un code d'erreur à la liste fermée.
#[must_use]
pub fn clean_reason(s: &str) -> String {
    if REASONS.contains(&s) { s.to_owned() } else { "other".to_owned() }
}

fn clean_id(s: &str) -> String {
    if is_identifier(s) { s.to_owned() } else { "?".to_owned() }
}

/// Nom de fournisseur ou de modèle : caractères simples, 100 au plus (configuration, pas de contenu).
fn clean_label(s: &str) -> String {
    let ok = !s.is_empty() && s.len() <= 100 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.:/@+".contains(&b));
    if ok { s.to_owned() } else { "?".to_owned() }
}

/// Compteurs cumulés d'une exécution (dernières `metrics` du worker).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Totals {
    /// Tours.
    pub turns: u64,
    /// Étapes.
    pub steps: u64,
    /// Appels au fournisseur.
    pub llm_calls: u64,
    /// Appels d'outils.
    pub tool_calls: u64,
    /// Erreurs d'outils.
    pub tool_errors: u64,
    /// Tokens d'entrée.
    pub prompt: u64,
    /// Tokens de sortie.
    pub completion: u64,
    /// Tokens de raisonnement.
    pub reasoning: u64,
    /// Coût estimé (micro-euros).
    pub cost_micro: u64,
    /// Latence médiane du fournisseur (ms).
    pub p50_ms: u64,
    /// Latence maximale du fournisseur (ms).
    pub max_ms: u64,
    /// Durée du dernier tour (ms).
    pub turn_ms: u64,
}

/// Consommation mesurée dans le cgroup (`launcher::ResourceUsage`), échantillonnée toutes les 5 s.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Resources {
    /// Au moins un échantillon (sinon « non mesuré », ex. bouchon sans cgroup).
    pub measured: bool,
    /// Pic de mémoire (octets).
    pub mem_peak: u64,
    /// Somme des `memory.current` échantillonnés.
    pub mem_sum: u64,
    /// Nombre d'échantillons.
    pub mem_samples: u64,
    /// Dernière mémoire courante (octets).
    pub mem_last: u64,
    /// CPU consommé (µs).
    pub cpu_usec: u64,
    /// Pic de CPU entre deux échantillons, en millièmes de cœur.
    pub cpu_peak_pm: u64,
}

/// Coût et tokens attribués à un jour UTC.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DayTotals {
    /// Coût (µ€).
    pub cost_micro: u64,
    /// Tokens d'entrée et de sortie.
    pub tokens: u64,
}

/// Entrée de chronologie : jamais de texte, d'argument ni de résultat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case", rename_all_fields = "camelCase")]
pub enum Entry {
    /// Lancement.
    Start {
        /// Horodatage (s).
        t: u64,
    },
    /// Changement d'état.
    Status {
        /// Horodatage (s).
        t: u64,
        /// État (liste fermée).
        status: String,
        /// Code (liste fermée).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Mesure : écarts depuis la précédente.
    Metrics {
        /// Horodatage (s).
        t: u64,
        /// Numéro de tour.
        turn: u64,
        /// Étapes.
        steps: u64,
        /// Appels d'outils.
        tool_calls: u64,
        /// Erreurs d'outils.
        tool_errors: u64,
        /// Tokens d'entrée.
        prompt: u64,
        /// Tokens de sortie.
        completion: u64,
        /// Tokens de raisonnement.
        reasoning: u64,
        /// Coût (µ€).
        cost_micro: u64,
        /// Durée du tour (ms).
        turn_ms: u64,
    },
    /// Le worker annonce sa fin.
    Done {
        /// Horodatage (s).
        t: u64,
        /// Raison (`idle`, `awaiting`, `failed`, `cancelled`, `shutdown`).
        reason: String,
    },
    /// Fin du process.
    End {
        /// Horodatage (s).
        t: u64,
        /// Sortie (`exit:N`, `signal:N`, `unknown`).
        exit: String,
        /// Fin anormale.
        crashed: bool,
    },
}

/// Une exécution de worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    /// Version du format.
    pub v: u8,
    /// Identifiant de l'exécution.
    pub run_id: String,
    /// Conversation.
    pub session_id: String,
    /// Utilisateur (identifiant fourni par l'API ; l'API ne donne pas de nom au runtime).
    pub user_id: String,
    /// Fournisseur LLM.
    pub provider: String,
    /// Modèle.
    pub model: String,
    /// Début (s).
    pub started: u64,
    /// Dernière mise à jour (s).
    pub updated: u64,
    /// Fin (s).
    pub ended: Option<u64>,
    /// En cours.
    pub active: bool,
    /// Dernier état (liste fermée).
    pub status: String,
    /// Dernier code d'erreur (liste fermée).
    pub reason: Option<String>,
    /// Raison de `done`.
    pub done_reason: Option<String>,
    /// Sortie du process.
    pub exit: Option<String>,
    /// Fin anormale.
    pub crashed: bool,
    /// Interrompue par un arrêt du superviseur (point de reprise sans fin).
    #[serde(default)]
    pub interrupted: bool,
    /// Compteurs.
    pub totals: Totals,
    /// Consommation.
    pub res: Resources,
    /// Coût par jour UTC (numéro de jour depuis 1970).
    pub by_day: BTreeMap<u32, DayTotals>,
    /// Chronologie (absente des points de reprise).
    #[serde(default)]
    pub timeline: Vec<Entry>,
    /// Entrées de chronologie abandonnées (plafond).
    #[serde(default)]
    pub timeline_dropped: u32,
}

impl Run {
    fn sanitize(&mut self) {
        self.session_id = clean_id(&self.session_id);
        self.user_id = clean_id(&self.user_id);
        self.provider = clean_label(&self.provider);
        self.model = clean_label(&self.model);
        self.status = clean_status(&self.status);
        self.reason = self.reason.as_deref().map(clean_reason);
        self.timeline.truncate(MAX_TIMELINE);
    }
}

#[derive(Debug, Default)]
struct Live {
    last_sample: Option<(u64, u64)>,
    last_checkpoint: u64,
}

#[derive(Debug)]
struct Inner {
    runs: HashMap<String, Run>,
    live: HashMap<String, Live>,
    seq: u64,
    dir: Option<PathBuf>,
    retention_days: u32,
}

/// Historique (mémoire + fichiers).
#[derive(Debug)]
pub struct History {
    inner: Mutex<Inner>,
}

fn day_of(secs: u64) -> u32 {
    u32::try_from(secs / SECS_PER_DAY).unwrap_or(u32::MAX)
}

/// Date civile `(année, mois, jour)` d'un numéro de jour depuis 1970 (algorithme de Hinnant).
#[allow(clippy::arithmetic_side_effects, clippy::as_conversions, reason = "calcul calendaire sur un jour borné")]
fn civil_from_days(day: u32) -> (i64, i64, i64) {
    let z = i64::from(day) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Numéro de jour depuis 1970 d'une date civile.
#[allow(clippy::arithmetic_side_effects, reason = "calcul calendaire sur une date bornée")]
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<u32> {
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    u32::try_from(era * 146_097 + doe - 719_468).ok()
}

/// Nom du fichier d'un jour.
#[must_use]
pub fn file_name(day: u32) -> String {
    let (y, m, d) = civil_from_days(day);
    format!("history-{y:04}-{m:02}-{d:02}.jsonl")
}

/// Jour d'un nom de fichier d'historique (`None` pour tout autre nom : jamais supprimé).
#[must_use]
pub fn parse_file_name(name: &str) -> Option<u32> {
    let date = name.strip_prefix("history-")?.strip_suffix(".jsonl")?;
    let mut parts = date.split('-');
    let (y, m, d) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return None;
    }
    let day = days_from_civil(y.parse().ok()?, m.parse().ok()?, d.parse().ok()?)?;
    (file_name(day) == name).then_some(day)
}

fn lock(m: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn exit_label(e: WorkerExit) -> String {
    match e {
        WorkerExit::Exited(c) => format!("exit:{c}"),
        WorkerExit::Signaled(s) => format!("signal:{s}"),
        WorkerExit::Unknown => "unknown".to_owned(),
    }
}

/// Fait monter `slot` à `new` (cumul monotone) ; renvoie l'écart.
const fn rise(slot: &mut u64, new: u64) -> u64 {
    if new > *slot {
        let d = new.saturating_sub(*slot);
        *slot = new;
        d
    } else {
        0
    }
}

impl Inner {
    fn push_entry(run: &mut Run, e: Entry) {
        if run.timeline.len() < MAX_TIMELINE {
            run.timeline.push(e);
        } else {
            run.timeline_dropped = run.timeline_dropped.saturating_add(1);
        }
    }

    fn persist(&self, run: &Run, now: u64, full: bool) {
        let Some(dir) = &self.dir else { return };
        let mut copy = run.clone();
        if !full {
            copy.timeline.clear();
        }
        let Ok(mut line) = serde_json::to_string(&copy) else { return };
        line.push('\n');
        let path = dir.join(file_name(day_of(now)));
        let result = (|| {
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut f = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(&path)?;
            f.write_all(line.as_bytes())
        })();
        if let Err(e) = result {
            tracing::warn!(code = "dashboard_history_not_saved", error = %e.kind(), "historique du dashboard non écrit");
        }
    }

    fn trim(&mut self) {
        while self.runs.len() > MAX_RUNS {
            let oldest = self.runs.values().filter(|r| !r.active).min_by_key(|r| r.updated).map(|r| r.run_id.clone());
            match oldest {
                Some(id) => {
                    self.runs.remove(&id);
                }
                None => break,
            }
        }
    }
}

impl History {
    /// Historique en mémoire seulement (tests, ou dossier inutilisable).
    #[must_use]
    pub fn in_memory(retention_days: u32) -> Self {
        Self {
            inner: Mutex::new(Inner { runs: HashMap::new(), live: HashMap::new(), seq: 0, dir: None, retention_days }),
        }
    }

    /// Ouvre (et crée, 0700) `<state_dir>/dashboard`, charge les fichiers, applique la rétention.
    /// Dossier inutilisable : historique en mémoire seulement (avertissement).
    #[must_use]
    pub fn open(state_dir: &Path, retention_days: u32, now: u64) -> Self {
        use std::os::unix::fs::DirBuilderExt as _;
        let dir = state_dir.join(HISTORY_DIR);
        let created = std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir);
        let h = Self::in_memory(retention_days);
        if let Err(e) = created {
            tracing::warn!(code = "dashboard_history_dir", error = %e.kind(), "historique du dashboard en mémoire seulement");
            return h;
        }
        h.prune_dir(&dir, now);
        {
            let mut g = lock(&h.inner);
            g.runs = load_dir(&dir);
            g.dir = Some(dir);
        }
        h.prune(now);
        h
    }

    fn prune_dir(&self, dir: &Path, now: u64) {
        let retention = lock(&self.inner).retention_days;
        let cutoff = day_of(now).saturating_sub(retention);
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for entry in rd.flatten() {
            let name = entry.file_name();
            if let Some(day) = name.to_str().and_then(parse_file_name)
                && day < cutoff
            {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    /// Rétention : supprime les fichiers et les exécutions plus anciens que `retention_days`.
    pub fn prune(&self, now: u64) {
        let (dir, retention) = {
            let g = lock(&self.inner);
            (g.dir.clone(), g.retention_days)
        };
        if let Some(dir) = dir {
            self.prune_dir(&dir, now);
        }
        let cutoff = day_of(now).saturating_sub(retention);
        lock(&self.inner).runs.retain(|_, r| r.active || day_of(r.updated) >= cutoff);
    }

    /// Durée de rétention (jours).
    #[must_use]
    pub fn retention_days(&self) -> u32 {
        lock(&self.inner).retention_days
    }

    /// Exécutions connues.
    #[must_use]
    pub fn run_count(&self) -> usize {
        lock(&self.inner).runs.len()
    }

    /// Début d'une exécution ; renvoie son identifiant.
    pub fn begin_run(&self, session_id: &str, user_id: &str, provider: &str, model: &str, now: u64) -> String {
        let mut g = lock(&self.inner);
        g.seq = g.seq.saturating_add(1);
        let run_id = format!("r{now}-{}", g.seq);
        let mut run = Run {
            v: 1,
            run_id: run_id.clone(),
            session_id: clean_id(session_id),
            user_id: clean_id(user_id),
            provider: clean_label(provider),
            model: clean_label(model),
            started: now,
            updated: now,
            ended: None,
            active: true,
            status: "running".to_owned(),
            reason: None,
            done_reason: None,
            exit: None,
            crashed: false,
            interrupted: false,
            totals: Totals::default(),
            res: Resources::default(),
            by_day: BTreeMap::new(),
            timeline: Vec::new(),
            timeline_dropped: 0,
        };
        Inner::push_entry(&mut run, Entry::Start { t: now });
        g.live.insert(run_id.clone(), Live { last_sample: None, last_checkpoint: now });
        g.runs.insert(run_id.clone(), run);
        g.trim();
        run_id
    }

    /// Changement d'état annoncé par le worker (liste fermée).
    pub fn on_status(&self, run_id: &str, status: &str, reason: Option<&str>, now: u64) {
        let mut g = lock(&self.inner);
        let Some(run) = g.runs.get_mut(run_id) else { return };
        run.status = clean_status(status);
        run.reason = reason.map(clean_reason);
        run.updated = now;
        let e = Entry::Status { t: now, status: run.status.clone(), reason: run.reason.clone() };
        Inner::push_entry(run, e);
    }

    /// `metrics` du worker (cumulées depuis son lancement).
    pub fn on_metrics(&self, run_id: &str, m: &Metrics, now: u64) {
        let mut g = lock(&self.inner);
        let Some(run) = g.runs.get_mut(run_id) else { return };
        let t = &mut run.totals;
        let turn = rise(&mut t.turns, m.turn);
        let steps = rise(&mut t.steps, m.steps);
        rise(&mut t.llm_calls, m.llm_calls);
        let tool_calls = rise(&mut t.tool_calls, m.tool_calls);
        let tool_errors = rise(&mut t.tool_errors, m.tool_errors);
        let prompt = rise(&mut t.prompt, m.prompt_tokens);
        let completion = rise(&mut t.completion, m.completion_tokens);
        let reasoning = rise(&mut t.reasoning, m.reasoning_tokens);
        let cost = rise(&mut t.cost_micro, m.cost_eur_micro);
        t.p50_ms = m.llm_latency_ms.p50;
        t.max_ms = t.max_ms.max(m.llm_latency_ms.max);
        let turn_changed = t.turn_ms != m.turn_duration_ms;
        t.turn_ms = m.turn_duration_ms;
        let turn_no = t.turns;
        run.updated = now;
        if cost > 0 || prompt > 0 || completion > 0 {
            let d = run.by_day.entry(day_of(now)).or_default();
            d.cost_micro = d.cost_micro.saturating_add(cost);
            d.tokens = d.tokens.saturating_add(prompt).saturating_add(completion);
        }
        if turn > 0
            || steps > 0
            || tool_calls > 0
            || tool_errors > 0
            || prompt > 0
            || completion > 0
            || reasoning > 0
            || cost > 0
            || turn_changed
        {
            let e = Entry::Metrics {
                t: now,
                turn: turn_no,
                steps,
                tool_calls,
                tool_errors,
                prompt,
                completion,
                reasoning,
                cost_micro: cost,
                turn_ms: m.turn_duration_ms,
            };
            Inner::push_entry(run, e);
        }
    }

    /// Échantillon du cgroup du worker ; `mono_ms` : horloge monotone (ms) pour le pic de CPU.
    pub fn on_sample(&self, run_id: &str, u: ResourceUsage, now: u64, mono_ms: u64) {
        let mut g = lock(&self.inner);
        let Inner { runs, live, .. } = &mut *g;
        let (Some(run), Some(l)) = (runs.get_mut(run_id), live.get_mut(run_id)) else { return };
        let r = &mut run.res;
        r.measured = true;
        r.mem_last = u.memory_current;
        r.mem_peak = r.mem_peak.max(u.memory_peak).max(u.memory_current);
        r.mem_sum = r.mem_sum.saturating_add(u.memory_current);
        r.mem_samples = r.mem_samples.saturating_add(1);
        r.cpu_usec = r.cpu_usec.max(u.cpu_usage_usec);
        if let Some((t0, c0)) = l.last_sample {
            let dt = mono_ms.saturating_sub(t0);
            if dt > 0 {
                // µs de CPU par ms écoulée = millièmes de cœur.
                let pm = u.cpu_usage_usec.saturating_sub(c0).checked_div(dt).unwrap_or(0);
                r.cpu_peak_pm = r.cpu_peak_pm.max(pm);
            }
        }
        l.last_sample = Some((mono_ms, u.cpu_usage_usec));
        run.updated = now;
        if now.saturating_sub(l.last_checkpoint) >= CHECKPOINT_SECS {
            l.last_checkpoint = now;
            let snapshot = run.clone();
            g.persist(&snapshot, now, false);
        }
    }

    /// `done` du worker.
    pub fn on_done(&self, run_id: &str, reason: &str, now: u64) {
        let mut g = lock(&self.inner);
        let Some(run) = g.runs.get_mut(run_id) else { return };
        let reason =
            if ["idle", "awaiting", "failed", "cancelled", "shutdown"].contains(&reason) { reason } else { "other" };
        run.done_reason = Some(reason.to_owned());
        run.updated = now;
        Inner::push_entry(run, Entry::Done { t: now, reason: reason.to_owned() });
    }

    /// Fin du process : enregistrement final avec chronologie.
    pub fn end_run(&self, run_id: &str, exit: WorkerExit, crashed: bool, now: u64) {
        let mut g = lock(&self.inner);
        g.live.remove(run_id);
        let Some(run) = g.runs.get_mut(run_id) else { return };
        run.active = false;
        run.ended = Some(now);
        run.updated = now;
        run.crashed = crashed;
        run.exit = Some(exit_label(exit));
        Inner::push_entry(run, Entry::End { t: now, exit: exit_label(exit), crashed });
        let done = run.clone();
        g.persist(&done, now, true);
    }

    pub(crate) fn runs_snapshot(&self) -> Vec<Run> {
        lock(&self.inner).runs.values().cloned().collect()
    }
}

fn load_dir(dir: &Path) -> HashMap<String, Run> {
    let mut files: Vec<(u32, PathBuf)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| Some((e.file_name().to_str().and_then(parse_file_name)?, e.path())))
        .collect();
    files.sort();
    let mut runs: HashMap<String, Run> = HashMap::new();
    for (_, path) in files {
        let Ok(file) = std::fs::File::open(&path) else { continue };
        let mut reader = std::io::BufReader::new(file);
        loop {
            let mut buf = Vec::new();
            let n = std::io::Read::take(&mut reader, MAX_LINE_BYTES).read_until(b'\n', &mut buf);
            if n.is_err() || n.is_ok_and(|n| n == 0) {
                break;
            }
            let Ok(mut run) = serde_json::from_slice::<Run>(&buf) else { continue };
            if run.v != 1 || run.run_id.len() > 64 {
                continue;
            }
            run.sanitize();
            // Dernier enregistrement gagnant ; une chronologie d'un point de reprise ne remplace pas
            // celle déjà connue.
            if run.timeline.is_empty()
                && let Some(prev) = runs.get(&run.run_id)
            {
                run.timeline.clone_from(&prev.timeline);
            }
            runs.insert(run.run_id.clone(), run);
        }
    }
    for run in runs.values_mut() {
        if run.active {
            run.active = false;
            run.interrupted = true;
            run.ended = Some(run.updated);
        }
    }
    runs
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, reason = "tests")]
mod tests {
    use super::*;

    const D: u64 = SECS_PER_DAY;

    #[test]
    fn noms_de_fichiers() {
        assert_eq!(file_name(0), "history-1970-01-01.jsonl");
        assert_eq!(file_name(20_413), "history-2025-11-21.jsonl");
        for day in [0, 59, 60, 365, 11_016, 20_413, 30_000] {
            assert_eq!(parse_file_name(&file_name(day)), Some(day));
        }
        assert_eq!(parse_file_name("history-2025-13-01.jsonl"), None);
        assert_eq!(parse_file_name("history-2025-11-20.jsonl.bak"), None);
        assert_eq!(parse_file_name("dashboard.pass"), None);
    }

    fn m(steps: u64, tools: u64, p: u64, c: u64, cost: u64) -> Metrics {
        Metrics {
            turn: 1,
            steps,
            llm_calls: steps,
            tool_calls: tools,
            prompt_tokens: p,
            completion_tokens: c,
            cost_eur_micro: cost,
            ..Metrics::default()
        }
    }

    #[test]
    fn metriques_cumulees_ecarts_et_cout_par_jour() {
        let h = History::in_memory(90);
        let id = h.begin_run("s1", "u1", "openai", "gpt-x", 10 * D);
        h.on_metrics(&id, &m(1, 0, 100, 10, 500), 10 * D + 5);
        h.on_metrics(&id, &m(3, 2, 300, 40, 1_500), 11 * D + 5);
        // Un compteur qui recule (worker fautif) est ignoré.
        h.on_metrics(&id, &m(2, 1, 50, 5, 10), 11 * D + 6);
        let run = h.runs_snapshot().remove(0);
        assert_eq!((run.totals.steps, run.totals.prompt, run.totals.cost_micro), (3, 300, 1_500));
        assert_eq!(run.by_day.get(&10).map(|d| d.cost_micro), Some(500));
        assert_eq!(run.by_day.get(&11).map(|d| d.cost_micro), Some(1_000));
        let deltas: Vec<u64> = run
            .timeline
            .iter()
            .filter_map(|e| if let Entry::Metrics { steps, .. } = e { Some(*steps) } else { None })
            .collect();
        assert_eq!(deltas, vec![1, 2]);
    }

    #[test]
    fn echantillons_pic_et_moyenne() {
        let h = History::in_memory(90);
        let id = h.begin_run("s1", "u1", "openai", "gpt-x", 100);
        let u = |cur, peak, cpu| ResourceUsage { memory_current: cur, memory_peak: peak, cpu_usage_usec: cpu };
        h.on_sample(&id, u(100, 100, 0), 100, 0);
        h.on_sample(&id, u(300, 400, 2_500_000), 105, 5_000); // 2,5 s de CPU en 5 s = 500 ‰
        h.on_sample(&id, u(200, 400, 3_000_000), 110, 10_000);
        let r = h.runs_snapshot().remove(0).res;
        assert!(r.measured);
        assert_eq!((r.mem_peak, r.mem_sum / r.mem_samples, r.cpu_usec, r.cpu_peak_pm), (400, 200, 3_000_000, 500));
    }

    #[test]
    fn valeurs_hors_liste_ramenees_a_other() {
        let h = History::in_memory(90);
        let id = h.begin_run("s 1 avec espaces", "u1", "open ai", "m\u{e9}", 1);
        h.on_status(&id, "MARQUEUR-SECRET", Some("MARQUEUR-SECRET"), 2);
        h.on_done(&id, "MARQUEUR-SECRET", 3);
        let run = h.runs_snapshot().remove(0);
        assert_eq!((run.session_id.as_str(), run.provider.as_str(), run.status.as_str()), ("?", "?", "other"));
        assert_eq!(run.reason.as_deref(), Some("other"));
        assert!(!serde_json::to_string(&run).unwrap().contains("MARQUEUR"));
    }

    #[test]
    fn persistance_point_de_reprise_et_interruption() {
        let dir = tempfile::tempdir().unwrap();
        let now = 20_000 * D;
        let h = History::open(dir.path(), 90, now);
        let a = h.begin_run("s1", "u1", "openai", "gpt-x", now);
        h.on_metrics(&a, &m(1, 1, 10, 5, 7), now + 1);
        h.on_sample(&a, ResourceUsage { memory_current: 5, memory_peak: 5, cpu_usage_usec: 1 }, now + 61, 61_000);
        let b = h.begin_run("s2", "u2", "openai", "gpt-x", now);
        h.on_metrics(&b, &m(2, 0, 20, 5, 9), now + 2);
        h.end_run(&b, WorkerExit::Exited(0), false, now + 3);
        // Redémarrage : `a` n'a qu'un point de reprise (interrompue), `b` est complète avec chronologie.
        let h2 = History::open(dir.path(), 90, now + 10);
        let runs: HashMap<String, Run> = h2.runs_snapshot().into_iter().map(|r| (r.session_id.clone(), r)).collect();
        assert!(runs["s1"].interrupted && !runs["s1"].active && runs["s1"].timeline.is_empty());
        assert_eq!(runs["s1"].totals.prompt, 10);
        assert!(!runs["s2"].interrupted && runs["s2"].timeline.len() >= 3);
        assert_eq!(runs["s2"].exit.as_deref(), Some("exit:0"));
    }

    #[test]
    fn retention_supprime_fichiers_et_executions() {
        let dir = tempfile::tempdir().unwrap();
        let hd = dir.path().join(HISTORY_DIR);
        std::fs::create_dir_all(&hd).unwrap();
        let today = 20_000u32;
        for day in [today - 100, today - 31, today - 29, today] {
            let h = History::open(dir.path(), 3650, u64::from(day) * D);
            let id = h.begin_run("s", "u", "p", "m", u64::from(day) * D);
            h.end_run(&id, WorkerExit::Exited(0), false, u64::from(day) * D);
        }
        std::fs::write(hd.join("autre.txt"), "intact").unwrap();
        let names = || {
            let mut v: Vec<String> =
                std::fs::read_dir(&hd).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
            v.sort();
            v
        };
        assert_eq!(names().len(), 5);
        let h = History::open(dir.path(), 30, u64::from(today) * D + 10);
        let kept = names();
        assert!(!kept.contains(&file_name(today - 100)) && !kept.contains(&file_name(today - 31)));
        assert!(kept.contains(&file_name(today - 29)) && kept.contains(&file_name(today)));
        assert!(kept.contains(&"autre.txt".to_owned()), "un fichier étranger n'est jamais supprimé");
        assert_eq!(h.run_count(), 2);
        // Plus tard : la rétention continue de s'appliquer en cours de fonctionnement.
        h.prune(u64::from(today + 40) * D);
        assert_eq!(h.run_count(), 0);
    }

    #[test]
    fn fichier_altere_toleré() {
        let dir = tempfile::tempdir().unwrap();
        let hd = dir.path().join(HISTORY_DIR);
        std::fs::create_dir_all(&hd).unwrap();
        std::fs::write(hd.join(file_name(20_000)), "pas du json\n{\"v\":9}\n\n").unwrap();
        assert_eq!(History::open(dir.path(), 90, 20_000 * D).run_count(), 0);
    }
}
