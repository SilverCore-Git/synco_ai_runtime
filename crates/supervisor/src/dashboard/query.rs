//! Vues calculées sur l'historique : sessions (une conversation = ses exécutions agrégées), filtres,
//! tri, totaux par utilisateur ou fournisseur, coûts du jour / de la semaine / du mois.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::history::{Entry, History, Run};

const SECS_PER_DAY: u64 = 86_400;
/// Taille de page maximale.
pub const MAX_LIMIT: usize = 200;

/// Session : une conversation, agrégée sur ses exécutions de worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionView {
    /// Conversation.
    pub session_id: String,
    /// Utilisateur.
    pub user_id: String,
    /// Fournisseur (dernière exécution).
    pub provider: String,
    /// Modèle (dernière exécution).
    pub model: String,
    /// Premier lancement (s).
    pub started: u64,
    /// Dernière activité (s).
    pub updated: u64,
    /// Un worker tourne.
    pub active: bool,
    /// Dernier état.
    pub status: String,
    /// Dernier code d'erreur.
    pub reason: Option<String>,
    /// Exécutions de worker.
    pub runs: u64,
    /// Durée cumulée des exécutions (s).
    pub duration_secs: u64,
    /// Étapes.
    pub steps: u64,
    /// Appels d'outils.
    pub tool_calls: u64,
    /// Tokens d'entrée.
    pub prompt_tokens: u64,
    /// Tokens de sortie.
    pub completion_tokens: u64,
    /// Tokens de raisonnement.
    pub reasoning_tokens: u64,
    /// Coût estimé (µ€).
    pub cost_micro: u64,
    /// CPU et RAM mesurés ?
    pub measured: bool,
    /// Pic de RAM (octets).
    pub mem_peak: u64,
    /// RAM moyenne (octets).
    pub mem_avg: u64,
    /// CPU moyen (millièmes de cœur).
    pub cpu_avg_pm: u64,
    /// Pic de CPU (millièmes de cœur).
    pub cpu_peak_pm: u64,
    /// Erreurs : outils en erreur, fins anormales, échecs.
    pub errors: u64,
}

fn duration(r: &Run, now: u64) -> u64 {
    r.ended.unwrap_or(if r.active { now } else { r.updated }).saturating_sub(r.started)
}

fn aggregate(runs: &[&Run], now: u64) -> Option<SessionView> {
    let first = runs.iter().min_by_key(|r| r.started)?;
    let last = runs.iter().max_by_key(|r| (r.started, r.run_id.as_str()))?;
    let mut v = SessionView {
        session_id: first.session_id.clone(),
        user_id: last.user_id.clone(),
        provider: last.provider.clone(),
        model: last.model.clone(),
        started: first.started,
        updated: 0,
        active: false,
        status: last.status.clone(),
        reason: last.reason.clone(),
        runs: 0,
        duration_secs: 0,
        steps: 0,
        tool_calls: 0,
        prompt_tokens: 0,
        completion_tokens: 0,
        reasoning_tokens: 0,
        cost_micro: 0,
        measured: false,
        mem_peak: 0,
        mem_avg: 0,
        cpu_avg_pm: 0,
        cpu_peak_pm: 0,
        errors: 0,
    };
    let (mut mem_sum, mut mem_n, mut cpu_usec, mut cpu_wall) = (0u64, 0u64, 0u64, 0u64);
    for r in runs {
        v.updated = v.updated.max(r.updated);
        v.active |= r.active;
        v.runs = v.runs.saturating_add(1);
        let d = duration(r, now);
        v.duration_secs = v.duration_secs.saturating_add(d);
        v.steps = v.steps.saturating_add(r.totals.steps);
        v.tool_calls = v.tool_calls.saturating_add(r.totals.tool_calls);
        v.prompt_tokens = v.prompt_tokens.saturating_add(r.totals.prompt);
        v.completion_tokens = v.completion_tokens.saturating_add(r.totals.completion);
        v.reasoning_tokens = v.reasoning_tokens.saturating_add(r.totals.reasoning);
        v.cost_micro = v.cost_micro.saturating_add(r.totals.cost_micro);
        v.errors = v.errors.saturating_add(r.totals.tool_errors).saturating_add(u64::from(r.crashed));
        if r.res.measured {
            v.measured = true;
            v.mem_peak = v.mem_peak.max(r.res.mem_peak);
            v.cpu_peak_pm = v.cpu_peak_pm.max(r.res.cpu_peak_pm);
            mem_sum = mem_sum.saturating_add(r.res.mem_sum);
            mem_n = mem_n.saturating_add(r.res.mem_samples);
            cpu_usec = cpu_usec.saturating_add(r.res.cpu_usec);
            cpu_wall = cpu_wall.saturating_add(d);
        }
    }
    if v.status == "failed" && !v.active {
        v.errors = v.errors.saturating_add(1);
    }
    v.mem_avg = mem_sum.checked_div(mem_n).unwrap_or(0);
    // µs de CPU / s de mur / 1000 = millièmes de cœur.
    v.cpu_avg_pm = cpu_usec.checked_div(cpu_wall.saturating_mul(1000)).unwrap_or(0);
    Some(v)
}

/// Toutes les sessions (agrégées).
#[must_use]
pub fn sessions(h: &History, now: u64) -> Vec<SessionView> {
    let runs = h.runs_snapshot();
    let mut by: BTreeMap<&str, Vec<&Run>> = BTreeMap::new();
    for r in &runs {
        by.entry(r.session_id.as_str()).or_default().push(r);
    }
    by.values().filter_map(|g| aggregate(g, now)).collect()
}

/// Clé de tri.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum SortKey {
    /// Début.
    #[default]
    Started,
    /// Dernière activité.
    Updated,
    /// Durée.
    Duration,
    /// Utilisateur.
    User,
    /// État.
    Status,
    /// Étapes.
    Steps,
    /// Appels d'outils.
    ToolCalls,
    /// Tokens (entrée + sortie + raisonnement).
    Tokens,
    /// Coût.
    Cost,
    /// Pic de RAM.
    MemPeak,
    /// CPU moyen.
    CpuAvg,
    /// Erreurs.
    Errors,
}

/// Paramètres de la liste des sessions (tous facultatifs).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Filter {
    /// `active`, `ended` ou un état (`idle`, `failed`…).
    pub state: Option<String>,
    /// Utilisateur exact.
    pub user: Option<String>,
    /// Fournisseur exact.
    pub provider: Option<String>,
    /// Début de période (s Unix, inclus) : sessions lancées à partir de.
    pub from: Option<u64>,
    /// Fin de période (s Unix, inclus).
    pub to: Option<u64>,
    /// Seulement les sessions avec erreurs.
    pub errors_only: Option<bool>,
    /// Tri.
    #[serde(default)]
    pub sort: SortKey,
    /// Ordre décroissant (défaut : oui).
    pub desc: Option<bool>,
    /// Taille de page (1 à 200, défaut 50).
    pub limit: Option<usize>,
    /// Décalage.
    pub offset: Option<usize>,
}

impl Filter {
    fn matches(&self, s: &SessionView) -> bool {
        let state_ok = match self.state.as_deref() {
            None | Some("") => true,
            Some("active") => s.active,
            Some("ended") => !s.active,
            Some(other) => s.status == other,
        };
        state_ok
            && self.user.as_deref().is_none_or(|u| u.is_empty() || s.user_id == u)
            && self.provider.as_deref().is_none_or(|p| p.is_empty() || s.provider == p)
            && self.from.is_none_or(|f| s.started >= f)
            && self.to.is_none_or(|t| s.started <= t)
            && (self.errors_only != Some(true) || s.errors > 0)
    }
}

fn key(s: &SessionView, k: SortKey) -> (u64, &str) {
    let n = match k {
        SortKey::Started => s.started,
        SortKey::Updated => s.updated,
        SortKey::Duration => s.duration_secs,
        SortKey::Steps => s.steps,
        SortKey::ToolCalls => s.tool_calls,
        SortKey::Tokens => s.prompt_tokens.saturating_add(s.completion_tokens).saturating_add(s.reasoning_tokens),
        SortKey::Cost => s.cost_micro,
        SortKey::MemPeak => s.mem_peak,
        SortKey::CpuAvg => s.cpu_avg_pm,
        SortKey::Errors => s.errors,
        SortKey::User | SortKey::Status => 0,
    };
    let text = match k {
        SortKey::User => s.user_id.as_str(),
        SortKey::Status => s.status.as_str(),
        _ => "",
    };
    (n, text)
}

/// Page de sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    /// Nombre total après filtres.
    pub total: usize,
    /// Éléments de la page.
    pub items: Vec<SessionView>,
}

/// Filtre, trie (ordre total : égalités départagées par identifiant) et découpe.
#[must_use]
pub fn list(h: &History, f: &Filter, now: u64) -> Page {
    let mut all: Vec<SessionView> = sessions(h, now).into_iter().filter(|s| f.matches(s)).collect();
    all.sort_by(|a, b| key(a, f.sort).cmp(&key(b, f.sort)).then_with(|| a.session_id.cmp(&b.session_id)));
    if f.desc.unwrap_or(true) {
        all.reverse();
    }
    let total = all.len();
    let limit = f.limit.unwrap_or(50).clamp(1, MAX_LIMIT);
    let items = all.into_iter().skip(f.offset.unwrap_or(0)).take(limit).collect();
    Page { total, items }
}

/// Total d'un groupe (utilisateur ou fournisseur).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupTotal {
    /// Utilisateur ou fournisseur.
    pub key: String,
    /// Sessions.
    pub sessions: u64,
    /// Tokens d'entrée.
    pub prompt_tokens: u64,
    /// Tokens de sortie.
    pub completion_tokens: u64,
    /// Tokens de raisonnement.
    pub reasoning_tokens: u64,
    /// Coût (µ€).
    pub cost_micro: u64,
    /// Appels d'outils.
    pub tool_calls: u64,
    /// Erreurs.
    pub errors: u64,
}

/// Axe de regroupement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GroupBy {
    /// Par utilisateur.
    User,
    /// Par fournisseur LLM.
    Provider,
}

/// Totaux par utilisateur ou fournisseur, sur la période du filtre (`from`, `to`), du plus cher au
/// moins cher.
#[must_use]
pub fn totals(h: &History, by: GroupBy, from: Option<u64>, to: Option<u64>, now: u64) -> Vec<GroupTotal> {
    let f = Filter { from, to, ..Filter::default() };
    let mut map: BTreeMap<String, GroupTotal> = BTreeMap::new();
    for s in sessions(h, now).into_iter().filter(|s| f.matches(s)) {
        let key = match by {
            GroupBy::User => s.user_id.clone(),
            GroupBy::Provider => s.provider.clone(),
        };
        let g = map.entry(key.clone()).or_insert_with(|| GroupTotal {
            key,
            sessions: 0,
            prompt_tokens: 0,
            completion_tokens: 0,
            reasoning_tokens: 0,
            cost_micro: 0,
            tool_calls: 0,
            errors: 0,
        });
        g.sessions = g.sessions.saturating_add(1);
        g.prompt_tokens = g.prompt_tokens.saturating_add(s.prompt_tokens);
        g.completion_tokens = g.completion_tokens.saturating_add(s.completion_tokens);
        g.reasoning_tokens = g.reasoning_tokens.saturating_add(s.reasoning_tokens);
        g.cost_micro = g.cost_micro.saturating_add(s.cost_micro);
        g.tool_calls = g.tool_calls.saturating_add(s.tool_calls);
        g.errors = g.errors.saturating_add(s.errors);
    }
    let mut v: Vec<GroupTotal> = map.into_values().collect();
    v.sort_by(|a, b| b.cost_micro.cmp(&a.cost_micro).then_with(|| a.key.cmp(&b.key)));
    v
}

/// Coût estimé du jour UTC, des 7 et des 30 derniers jours (µ€).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Costs {
    /// Jour UTC courant.
    pub day: u64,
    /// 7 derniers jours (aujourd'hui compris).
    pub week: u64,
    /// 30 derniers jours (aujourd'hui compris).
    pub month: u64,
}

/// Coûts par période, attribués au jour où chaque mesure est arrivée.
#[must_use]
pub fn costs(h: &History, now: u64) -> Costs {
    let today = u32::try_from(now / SECS_PER_DAY).unwrap_or(u32::MAX);
    let mut c = Costs { day: 0, week: 0, month: 0 };
    for r in h.runs_snapshot() {
        for (d, t) in &r.by_day {
            let age = today.saturating_sub(*d);
            if *d > today {
                continue;
            }
            if age < 30 {
                c.month = c.month.saturating_add(t.cost_micro);
            }
            if age < 7 {
                c.week = c.week.saturating_add(t.cost_micro);
            }
            if age == 0 {
                c.day = c.day.saturating_add(t.cost_micro);
            }
        }
    }
    c
}

/// Exécution détaillée (chronologie sans contenu).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunDetail {
    /// Identifiant.
    pub run_id: String,
    /// Début (s).
    pub started: u64,
    /// Fin (s).
    pub ended: Option<u64>,
    /// En cours.
    pub active: bool,
    /// Interrompue (arrêt du superviseur).
    pub interrupted: bool,
    /// Sortie du process.
    pub exit: Option<String>,
    /// Fin anormale.
    pub crashed: bool,
    /// Fournisseur.
    pub provider: String,
    /// Modèle.
    pub model: String,
    /// Chronologie.
    pub timeline: Vec<Entry>,
    /// Entrées abandonnées (plafond).
    pub timeline_dropped: u32,
}

/// Détail d'une session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Detail {
    /// Agrégat.
    pub session: SessionView,
    /// Exécutions, de la plus ancienne à la plus récente.
    pub runs: Vec<RunDetail>,
}

/// Détail d'une session, ou `None`.
#[must_use]
pub fn detail(h: &History, session_id: &str, now: u64) -> Option<Detail> {
    let all = h.runs_snapshot();
    let mut mine: Vec<&Run> = all.iter().filter(|r| r.session_id == session_id).collect();
    mine.sort_by(|a, b| (a.started, &a.run_id).cmp(&(b.started, &b.run_id)));
    let session = aggregate(&mine, now)?;
    let runs = mine
        .into_iter()
        .map(|r| RunDetail {
            run_id: r.run_id.clone(),
            started: r.started,
            ended: r.ended,
            active: r.active,
            interrupted: r.interrupted,
            exit: r.exit.clone(),
            crashed: r.crashed,
            provider: r.provider.clone(),
            model: r.model.clone(),
            timeline: r.timeline.clone(),
            timeline_dropped: r.timeline_dropped,
        })
        .collect();
    Some(Detail { session, runs })
}

/// Résumé de l'activité en cours (vue d'ensemble).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    /// Exécutions actives.
    pub active_runs: u64,
    /// RAM actuelle des workers actifs (octets).
    pub workers_mem: u64,
    /// Exécutions en historique.
    pub history_runs: u64,
}

/// Activité courante.
#[must_use]
pub fn activity(h: &History) -> Activity {
    let runs = h.runs_snapshot();
    let active: Vec<&Run> = runs.iter().filter(|r| r.active).collect();
    Activity {
        active_runs: u64::try_from(active.len()).unwrap_or(u64::MAX),
        workers_mem: active.iter().fold(0u64, |a, r| a.saturating_add(r.res.mem_last)),
        history_runs: u64::try_from(runs.len()).unwrap_or(u64::MAX),
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, reason = "tests")]
mod tests {
    use runtime_protocol::pipe::Metrics;

    use super::*;
    use crate::launcher::{ResourceUsage, WorkerExit};

    const D: u64 = SECS_PER_DAY;

    fn metrics(steps: u64, tools: u64, errs: u64, p: u64, c: u64, cost: u64) -> Metrics {
        Metrics {
            turn: 1,
            steps,
            tool_calls: tools,
            tool_errors: errs,
            prompt_tokens: p,
            completion_tokens: c,
            cost_eur_micro: cost,
            ..Metrics::default()
        }
    }

    /// Trois sessions, dont une à deux exécutions.
    fn sample() -> History {
        let h = History::in_memory(90);
        let t0 = 100 * D;
        let a = h.begin_run("sa", "alice", "openai", "gpt", t0);
        h.on_metrics(&a, &metrics(2, 1, 0, 1_000, 100, 300), t0 + 10);
        h.on_sample(&a, ResourceUsage { memory_current: 100, memory_peak: 150, cpu_usage_usec: 0 }, t0 + 1, 0);
        h.on_sample(
            &a,
            ResourceUsage { memory_current: 200, memory_peak: 250, cpu_usage_usec: 1_000_000 },
            t0 + 6,
            5_000,
        );
        h.on_status(&a, "idle", None, t0 + 20);
        h.end_run(&a, WorkerExit::Exited(0), false, t0 + 20);
        let a2 = h.begin_run("sa", "alice", "openai", "gpt", t0 + 100);
        h.on_metrics(&a2, &metrics(1, 0, 0, 500, 50, 150), t0 + 110);
        h.end_run(&a2, WorkerExit::Exited(0), false, t0 + 130);
        let b = h.begin_run("sb", "bob", "mistral", "m", t0 + 200);
        h.on_metrics(&b, &metrics(5, 4, 2, 4_000, 400, 2_000), t0 + 210);
        h.on_status(&b, "failed", Some("provider_error"), t0 + 215);
        h.end_run(&b, WorkerExit::Signaled(9), true, t0 + 220);
        let c = h.begin_run("sc", "alice", "mistral", "m", t0 + 300);
        h.on_metrics(&c, &metrics(1, 0, 0, 10, 1, 5), t0 + 301);
        h
    }

    fn ids(p: &Page) -> Vec<&str> {
        p.items.iter().map(|s| s.session_id.as_str()).collect()
    }

    #[test]
    fn agregation_par_session() {
        let h = sample();
        let now = 100 * D + 400;
        let sa = detail(&h, "sa", now).unwrap();
        assert_eq!(sa.runs.len(), 2);
        let s = sa.session;
        assert_eq!((s.runs, s.steps, s.tool_calls, s.prompt_tokens, s.cost_micro), (2, 3, 1, 1_500, 450));
        assert_eq!(s.duration_secs, 20 + 30);
        assert_eq!((s.mem_peak, s.mem_avg), (250, 150));
        assert_eq!(s.cpu_peak_pm, 200, "1 s de CPU en 5 s = 200 ‰ de cœur");
        assert!(s.measured && !s.active);
        let sb = detail(&h, "sb", now).unwrap().session;
        assert_eq!(sb.errors, 2 + 1 + 1, "outils en erreur, fin anormale, état failed");
        assert!(detail(&h, "inconnue", now).is_none());
    }

    #[test]
    fn filtres() {
        let h = sample();
        let now = 100 * D + 400;
        let f = |f: Filter| ids(&list(&h, &f, now)).into_iter().map(str::to_owned).collect::<Vec<_>>();
        let sorted = |mut v: Vec<String>| {
            v.sort();
            v
        };
        assert_eq!(sorted(f(Filter { state: Some("active".into()), ..Filter::default() })), ["sc"]);
        assert_eq!(sorted(f(Filter { state: Some("ended".into()), ..Filter::default() })), ["sa", "sb"]);
        assert_eq!(f(Filter { state: Some("failed".into()), ..Filter::default() }), ["sb"]);
        assert_eq!(sorted(f(Filter { user: Some("alice".into()), ..Filter::default() })), ["sa", "sc"]);
        assert_eq!(
            f(Filter { provider: Some("mistral".into()), user: Some("alice".into()), ..Filter::default() }),
            ["sc"]
        );
        assert_eq!(f(Filter { errors_only: Some(true), ..Filter::default() }), ["sb"]);
        let t0 = 100 * D;
        assert_eq!(f(Filter { from: Some(t0 + 150), to: Some(t0 + 250), ..Filter::default() }), ["sb"]);
        assert_eq!(list(&h, &Filter::default(), now).total, 3);
    }

    #[test]
    fn tri_et_pagination() {
        let h = sample();
        let now = 100 * D + 400;
        let by = |sort, desc| ids(&list(&h, &Filter { sort, desc: Some(desc), ..Filter::default() }, now)).join(",");
        assert_eq!(by(SortKey::Cost, true), "sb,sa,sc");
        assert_eq!(by(SortKey::Cost, false), "sc,sa,sb");
        assert_eq!(by(SortKey::Started, false), "sa,sb,sc");
        assert_eq!(by(SortKey::User, false), "sa,sc,sb", "alice (sa, sc) avant bob, égalités par identifiant");
        assert_eq!(by(SortKey::Tokens, true), "sb,sa,sc");
        assert_eq!(
            by(SortKey::Errors, true),
            "sb,sc,sa",
            "ordre total : égalités départagées par identifiant, inversé en décroissant"
        );
        let page = list(
            &h,
            &Filter { sort: SortKey::Started, desc: Some(false), limit: Some(1), offset: Some(1), ..Filter::default() },
            now,
        );
        assert_eq!((page.total, ids(&page)), (3, vec!["sb"]));
        assert_eq!(
            list(&h, &Filter { limit: Some(0), ..Filter::default() }, now).items.len(),
            1,
            "limite minimale de 1"
        );
        assert_eq!(list(&h, &Filter { limit: Some(10_000), ..Filter::default() }, now).items.len(), 3);
    }

    #[test]
    fn totaux_par_utilisateur_et_fournisseur() {
        let h = sample();
        let now = 100 * D + 400;
        let u = totals(&h, GroupBy::User, None, None, now);
        assert_eq!(u.iter().map(|g| g.key.as_str()).collect::<Vec<_>>(), ["bob", "alice"]);
        let alice = u.iter().find(|g| g.key == "alice").unwrap();
        assert_eq!((alice.sessions, alice.cost_micro, alice.prompt_tokens), (2, 455, 1_510));
        let p = totals(&h, GroupBy::Provider, None, None, now);
        let mistral = p.iter().find(|g| g.key == "mistral").unwrap();
        assert_eq!((mistral.sessions, mistral.cost_micro), (2, 2_005));
        let periode = totals(&h, GroupBy::User, Some(100 * D + 250), None, now);
        assert_eq!(periode.iter().map(|g| g.key.as_str()).collect::<Vec<_>>(), ["alice"]);
    }

    #[test]
    fn couts_jour_semaine_mois() {
        let h = History::in_memory(90);
        for (day, cost) in [(100u64, 1u64), (97, 10), (80, 100), (60, 1_000)] {
            let id = h.begin_run(&format!("s{day}"), "u", "p", "m", day * D);
            h.on_metrics(&id, &metrics(1, 0, 0, 1, 1, cost), day * D + 5);
        }
        let c = costs(&h, 100 * D + 50);
        assert_eq!((c.day, c.week, c.month), (1, 11, 111));
    }
}
