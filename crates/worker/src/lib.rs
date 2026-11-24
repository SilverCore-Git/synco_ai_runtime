//! # synco-ai-runtime-worker
//!
//! Worker du Synco AI Runtime : un process isolé par conversation active (P3, docs/plan/06), lancé
//! par le bac à sable du superviseur ([`entry`], L06). Il fait tourner **une** conversation de bout
//! en bout ([`agent`], L07) : appels au fournisseur LLM par le mandataire du superviseur
//! ([`llm`], [`provider`]), outils serveur par l'API et outils E2EE avec les clés déléguées
//! ([`tools`]), enregistrement chiffré à chaque étape ([`transcript`]), évènements chiffrés vers les
//! clients ([`events`]), métriques sans contenu ([`metrics`]).
//!
//! Toutes les requêtes vers l'API passent par `signed_request` ([`link`], [`api`]) : le worker n'a
//! aucune clé du runtime (mesure 7). Le bouchon de protocole de L05 ([`stub`]) reste pour le lanceur
//! en processus des tests du superviseur.

#![forbid(unsafe_code)]

pub mod agent;
pub mod api;
pub mod artifact;
pub mod entry;
pub mod events;
pub mod keys;
pub mod link;
pub mod llm;
pub mod metrics;
pub mod plan;
pub mod prompt;
pub mod provider;
pub mod stub;
mod time;
pub mod tools;
pub mod transcript;

/// Ajoute ou remplace un champ d'un objet JSON (sans l'indexation qui panique sur un non-objet).
pub(crate) fn json_set(v: &mut serde_json::Value, key: &str, value: serde_json::Value) {
    if let Some(o) = v.as_object_mut() {
        o.insert(key.to_owned(), value);
    }
}
