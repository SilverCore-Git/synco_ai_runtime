//! Métriques **sans contenu** remontées au superviseur (docs/plan/06 §5) : compteurs, tokens, coût
//! estimé, latences, durée du tour. Aucun texte, nom de fichier ni argument d'outil.

use std::time::Instant;

use runtime_protocol::pipe::{Latency, Metrics, Pricing};

use crate::provider::Usage;

/// Compteurs d'un worker.
#[derive(Debug, Default)]
pub struct Counters {
    /// Valeurs courantes.
    pub m: Metrics,
    latencies: Vec<u64>,
    turn_start: Option<Instant>,
}

impl Counters {
    /// Début d'un tour.
    pub fn start_turn(&mut self) {
        self.m.turn = self.m.turn.saturating_add(1);
        self.turn_start = Some(Instant::now());
    }

    /// Fin d'un tour.
    pub fn end_turn(&mut self) {
        if let Some(s) = self.turn_start.take() {
            self.m.turn_duration_ms = u64::try_from(s.elapsed().as_millis()).unwrap_or(u64::MAX);
        }
    }

    /// Appel au fournisseur terminé.
    pub fn llm_call(&mut self, latency_ms: u64, usage: Option<&Usage>, pricing: Option<&Pricing>) {
        self.m.llm_calls = self.m.llm_calls.saturating_add(1);
        self.m.steps = self.m.steps.saturating_add(1);
        self.latencies.push(latency_ms);
        if self.latencies.len() > 1024 {
            self.latencies.remove(0);
        }
        let mut sorted = self.latencies.clone();
        sorted.sort_unstable();
        let p50 = sorted.get(sorted.len() / 2).copied().unwrap_or(0);
        let max = sorted.last().copied().unwrap_or(0);
        self.m.llm_latency_ms = Latency { p50, max };
        if let Some(u) = usage {
            let p = u.prompt_tokens.unwrap_or(0);
            let c = u.completion_tokens.unwrap_or(0);
            self.m.prompt_tokens = self.m.prompt_tokens.saturating_add(p);
            self.m.completion_tokens = self.m.completion_tokens.saturating_add(c);
            self.m.reasoning_tokens = self.m.reasoning_tokens.saturating_add(u.reasoning_tokens.unwrap_or(0));
            if let Some(pr) = pricing {
                // € par million de tokens × tokens = micro-euros.
                self.m.cost_eur_micro = self.m.cost_eur_micro.saturating_add(cost_micro(p, pr.input_per_m_tok));
                self.m.cost_eur_micro = self.m.cost_eur_micro.saturating_add(cost_micro(c, pr.output_per_m_tok));
            }
        }
    }

    /// Appel d'outil (`error` : résultat d'erreur).
    pub fn tool(&mut self, error: bool) {
        self.m.tool_calls = self.m.tool_calls.saturating_add(1);
        if error {
            self.m.tool_errors = self.m.tool_errors.saturating_add(1);
        }
    }
}

#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "arrondi borné d'un coût positif"
)]
fn cost_micro(tokens: u64, eur_per_mtok: f64) -> u64 {
    if !eur_per_mtok.is_finite() || eur_per_mtok <= 0.0 {
        return 0;
    }
    let v = (tokens as f64) * eur_per_mtok;
    if v >= u64::MAX as f64 { u64::MAX } else { v.round() as u64 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cout_et_latences() {
        let mut c = Counters::default();
        let pr = Pricing { input_per_m_tok: 2.5, output_per_m_tok: 10.0 };
        c.llm_call(
            100,
            Some(&Usage { prompt_tokens: Some(1000), completion_tokens: Some(100), ..Usage::default() }),
            Some(&pr),
        );
        c.llm_call(300, None, Some(&pr));
        assert_eq!(c.m.cost_eur_micro, 2500 + 1000);
        assert_eq!(c.m.llm_latency_ms, Latency { p50: 300, max: 300 });
        assert_eq!(c.m.llm_calls, 2);
        assert_eq!(cost_micro(5, f64::NAN), 0);
    }
}
