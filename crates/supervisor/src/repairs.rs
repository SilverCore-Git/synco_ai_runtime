//! Réparation des enveloppes `rt1` (Q21, PC31) : trames `thread.envelope_reset`, file persistante,
//! relecture côté API.
//!
//! Le serveur n'est pas de confiance : une trame comme un item de `GET …/envelope-resets` ne fait
//! que **demander** une réparation. Rien n'est signé sans que [`Runtime::try_repair`] ait refait,
//! à chaque essai, toutes les vérifications locales :
//! 1. le salon est dans le registre des salons créés par ce runtime, pour **cet** utilisateur ;
//! 2. `delegationId` est la délégation ouverte, non expirée, non révoquée de cet utilisateur ;
//! 3. la clé du salon (entrée `thread`, version 1) est dans cette délégation.
//!
//! Une demande valide mais pas encore satisfaisable (clé ou délégation pas encore chargée) reste
//! dans la file persistante ([`crate::repair_queue`]) ; un seul travailleur la rejoue, quatre
//! réparations de front au plus, quelle que soit la rafale de trames. Les refus définitifs de l'API
//! (`envelope_exists`, `forbidden`, `not_found`…) retirent l'entrée.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use futures_util::StreamExt as _;
use runtime_protocol::ids::is_identifier;

use crate::api::ApiError;
use crate::clock::now_secs;
use crate::repair_queue::{MAX_REPAIRS, Push, Repair};
use crate::runtime::Runtime;

/// Réparations traitées de front au plus (limiteur : une rafale de trames ne lance pas une tâche
/// par trame).
pub const REPAIR_CONCURRENCY: usize = 4;
/// Éléments demandés par page de `GET …/envelope-resets`.
const REREAD_LIMIT: u32 = 100;
/// Pages lues au plus (garde-fou).
const REREAD_MAX_PAGES: usize = 100;
/// Un même code de journal est écrit une fois par fenêtre.
const LOG_WINDOW: Duration = Duration::from_secs(10);

/// Journaux à débit limité : un code, une ligne par fenêtre, avec le nombre de lignes tues.
#[derive(Debug, Default)]
pub struct LogGate {
    seen: HashMap<&'static str, (Instant, u64)>,
}

impl LogGate {
    /// `Some(tues)` si ce code peut être écrit maintenant (`tues` : lignes supprimées depuis la
    /// dernière), `None` s'il faut se taire.
    pub fn allow(&mut self, code: &'static str, now: Instant) -> Option<u64> {
        match self.seen.get_mut(code) {
            None => {
                self.seen.insert(code, (now, 0));
                Some(0)
            }
            Some((since, suppressed)) if now.saturating_duration_since(*since) >= LOG_WINDOW => {
                let n = *suppressed;
                *since = now;
                *suppressed = 0;
                Some(n)
            }
            Some((_, suppressed)) => {
                *suppressed = suppressed.saturating_add(1);
                None
            }
        }
    }
}

/// Issue d'un essai de réparation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Faite, ou refusée pour de bon par l'API : retirée de la file.
    Done,
    /// Ne sera jamais faisable (salon étranger, délégation révoquée ou expirée, signature
    /// impossible) : retirée de la file.
    Drop,
    /// Valide mais pas encore faisable (clé ou délégation pas chargée, panne réseau) : gardée.
    Pending,
    /// Déjà en cours pour ce salon : on n'y touche pas.
    Busy,
}

impl Runtime {
    /// Journal à débit limité (code, message) : jamais d'identifiant ni de contenu.
    fn warn_limited(&self, code: &'static str, message: &'static str) {
        let allowed =
            self.repair_log.lock().unwrap_or_else(std::sync::PoisonError::into_inner).allow(code, Instant::now());
        if let Some(suppressed) = allowed {
            tracing::warn!(code, suppressed, "{message}");
        }
    }

    /// Demande une réparation (trame du flux ou item de la relecture API). Contrôle **local et
    /// immédiat** : un salon qui n'est pas à ce runtime n'entre jamais dans la file. Le reste
    /// (délégation, clé, signature) est fait par le travailleur, à chaque essai.
    pub async fn submit_repair(&self, thread_id: &str, user_id: &str, delegation_id: &str) {
        let repair = Repair {
            thread_id: thread_id.to_owned(),
            user_id: user_id.to_owned(),
            delegation_id: delegation_id.to_owned(),
        };
        let pushed = {
            let mut st = self.state.lock().await;
            if st.org_id.is_none() {
                return;
            }
            if st.created_threads.get(thread_id).is_none_or(|c| c.user_id != user_id) {
                drop(st);
                self.warn_limited(
                    "envelope_reset_foreign_thread",
                    "réinitialisation d'un salon qui n'est pas à ce runtime",
                );
                return;
            }
            let pushed = st.repairs.push(repair, now_secs());
            if pushed == Push::Full && st.alerts.back().is_none_or(|(_, c)| *c != "envelope_repairs_full") {
                st.alert(now_secs(), "envelope_repairs_full");
            }
            pushed
        };
        if pushed == Push::Full {
            self.warn_limited("envelope_repairs_full", "file de réparations pleine");
            return;
        }
        self.repair_wake.notify_one();
    }

    /// Relit les réparations en attente côté API (`GET …/envelope-resets`, paginée) : à chaque
    /// reconnexion du flux. Chaque item passe par [`Self::submit_repair`], donc par le registre
    /// local : l'API ne choisit jamais seule ce qui se signe.
    pub async fn reread_envelope_resets(&self) {
        let mut cursor: Option<String> = None;
        let mut seen = 0usize;
        for _ in 0..REREAD_MAX_PAGES {
            let page = match self.api.envelope_resets(REREAD_LIMIT, cursor.as_deref()).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(
                        code = "envelope_resets_unreadable",
                        api_code = e.loggable_code(),
                        "réparations non relues"
                    );
                    return;
                }
            };
            for item in page.items {
                seen = seen.saturating_add(1);
                if seen > MAX_REPAIRS {
                    return;
                }
                if is_identifier(&item.thread_id) && is_identifier(&item.user_id) && is_identifier(&item.delegation_id)
                {
                    self.submit_repair(&item.thread_id, &item.user_id, &item.delegation_id).await;
                }
            }
            match page.next_cursor {
                Some(next) if Some(&next) != cursor.as_ref() => cursor = Some(next),
                _ => return,
            }
        }
    }

    /// Démarre le travailleur de la file (un seul par runtime). Un premier passage rejoue la file
    /// relue du disque.
    pub fn spawn_repair_worker(self: &Arc<Self>) {
        let rt = Arc::clone(self);
        tokio::spawn(async move {
            let mut shutdown = rt.shutdown.subscribe();
            loop {
                tokio::select! {
                    () = rt.repair_wake.notified() => {}
                    () = crate::runtime::stopped(&mut shutdown) => return,
                }
                rt.repair_pass().await;
            }
        });
        self.repair_wake.notify_one();
    }

    /// Un passage sur la file : chaque entrée refait toutes les vérifications.
    async fn repair_pass(self: &Arc<Self>) {
        let items = {
            let mut st = self.state.lock().await;
            if st.org_id.is_none() {
                return;
            }
            st.repairs.expire(now_secs());
            st.repairs.items()
        };
        self.save_repairs().await;
        if items.is_empty() {
            return;
        }
        // Réseau en panne constatée pendant ce passage : les suivantes n'essaient pas.
        let net_down = AtomicBool::new(false);
        let results: Vec<(Repair, Verdict)> = futures_util::stream::iter(items)
            .map(|repair| {
                let net_down = &net_down;
                async move {
                    let verdict = self.try_repair(&repair, net_down).await;
                    (repair, verdict)
                }
            })
            .buffer_unordered(REPAIR_CONCURRENCY)
            .collect()
            .await;
        {
            let mut st = self.state.lock().await;
            for (repair, verdict) in &results {
                if matches!(verdict, Verdict::Done | Verdict::Drop) {
                    st.repairs.remove(repair);
                }
            }
        }
        self.save_repairs().await;
    }

    /// Écrit la file hors du verrou d'état (`spawn_blocking`). Échec : alerte, la prochaine photo
    /// réécrira tout.
    async fn save_repairs(&self) {
        let snapshot = self.state.lock().await.repairs.snapshot();
        let saved = match snapshot {
            Ok(None) => return,
            Ok(Some(snap)) => matches!(tokio::task::spawn_blocking(move || snap.write()).await, Ok(Ok(()))),
            Err(_) => false,
        };
        if !saved {
            let mut st = self.state.lock().await;
            st.repairs.mark_unsaved();
            st.alert(now_secs(), "envelope_repairs_not_saved");
        }
    }

    /// Q21 : tente une réparation. Toutes les vérifications locales sont refaites **à chaque
    /// essai** (rejeu compris), puis la signature `rt1` par `csk` et `POST …/key-envelope/repose`
    /// (S seule, corps strict). Le `commitment` est recalculé depuis la clé réellement détenue.
    async fn try_repair(&self, repair: &Repair, net_down: &AtomicBool) -> Verdict {
        let (thread_id, user_id, delegation_id) = (&repair.thread_id, &repair.user_id, &repair.delegation_id);
        let ctx = synco_e2ee::keys::thread_context(thread_id);
        let body = {
            let mut st = self.state.lock().await;
            if st.org_id.is_none() {
                return Verdict::Drop;
            }
            // (1) Salon créé par ce runtime, pour cet utilisateur.
            if st.created_threads.get(thread_id).is_none_or(|c| c.user_id != *user_id) {
                drop(st);
                self.warn_limited(
                    "envelope_reset_foreign_thread",
                    "réinitialisation d'un salon qui n'est pas à ce runtime",
                );
                return Verdict::Drop;
            }
            // (2) Délégation ouverte, non expirée, non révoquée de cet utilisateur.
            let now = now_secs();
            if st.revoked_delegations.contains_key(delegation_id.as_str()) {
                drop(st);
                self.warn_limited("envelope_reset_unknown_delegation", "délégation révoquée");
                return Verdict::Drop;
            }
            let Some(delegation) = st.vault.get(user_id).filter(|d| d.delegation_id() == delegation_id.as_str()) else {
                // Pas (encore) chargée : la demande attend son chargement.
                drop(st);
                self.warn_limited("envelope_reset_unknown_delegation", "délégation pas encore chargée");
                return Verdict::Pending;
            };
            if delegation.exp() <= now {
                drop(st);
                self.warn_limited("envelope_reset_unknown_delegation", "délégation expirée");
                return Verdict::Drop;
            }
            // (3) Clé du salon détenue dans cette délégation.
            let Some(key) = delegation.thread_key(thread_id, 1) else {
                drop(st);
                self.warn_limited("envelope_reset_key_missing", "clé du salon non détenue");
                return Verdict::Pending;
            };
            let Ok(sig) = synco_e2ee::keys::sign_rt1_envelope(self.keys.csk(), key.as_bytes(), &ctx, 1, delegation_id)
            else {
                drop(st);
                self.warn_limited("envelope_reset_sign_failed", "signature impossible");
                return Verdict::Drop;
            };
            if !st.repose_inflight.insert(thread_id.clone()) {
                return Verdict::Busy;
            }
            serde_json::json!({
                "delegationId": delegation_id, "ctx": ctx, "version": 1,
                "commitment": sig.commitment, "signature": sig.signature,
            })
            .to_string()
            .into_bytes()
        };
        // Pannes passagères (réseau, 5xx) : jusqu'à trois essais, puis la demande reste dans la file
        // (rejouée à la reconnexion) ; tout refus de l'API est définitif (`envelope_exists`,
        // `forbidden`, `not_found`… : un humain ou une autre réparation a déjà tranché).
        let mut outcome = Err(ApiError::Network);
        if !net_down.load(Ordering::Relaxed) {
            for delay in [0u64, 1, 4] {
                if delay > 0 {
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                }
                outcome = self.api.repose_envelope(thread_id, body.clone()).await;
                if !is_transient(&outcome) || self.is_shutting_down() {
                    break;
                }
            }
        }
        self.state.lock().await.repose_inflight.remove(thread_id);
        let transient = is_transient(&outcome);
        match outcome {
            Ok(()) => {
                tracing::info!(code = "envelope_reposed", "enveloppe rt1 reposée");
                Verdict::Done
            }
            Err(_) if transient => {
                net_down.store(true, Ordering::Relaxed);
                self.warn_limited("envelope_repose_unreachable", "API injoignable : réparation gardée");
                Verdict::Pending
            }
            Err(e) => {
                tracing::debug!(
                    code = "envelope_repose_refused",
                    api_code = e.loggable_code(),
                    "enveloppe non reposée"
                );
                self.warn_limited("envelope_repose_refused", "enveloppe non reposée (refus de l'API)");
                Verdict::Done
            }
        }
    }
}

fn is_transient(outcome: &Result<(), ApiError>) -> bool {
    matches!(outcome, Err(ApiError::Network)) || matches!(outcome, Err(e) if e.status().is_some_and(|s| s >= 500))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn un_code_par_fenetre() {
        let mut gate = LogGate::default();
        let t0 = Instant::now();
        assert_eq!(gate.allow("a", t0), Some(0));
        for _ in 0..5 {
            assert_eq!(gate.allow("a", t0), None);
        }
        assert_eq!(gate.allow("b", t0), Some(0), "un autre code a sa propre fenêtre");
        assert_eq!(gate.allow("a", t0 + LOG_WINDOW), Some(5), "les lignes tues sont comptées");
        assert_eq!(gate.allow("a", t0 + LOG_WINDOW), None);
    }
}
