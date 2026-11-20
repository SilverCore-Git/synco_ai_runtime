//! # runtime-protocol
//!
//! Types et formats partagés du Synco AI Runtime (superviseur, worker, client, API). Spécification :
//! `docs/plan/` du dépôt ; là où l'API réelle (synco_api, `vibe/features/SYNCOAI_REFONTE_FEATURE.md`)
//! s'en écarte, c'est elle qui fait foi (écarts listés dans `docs/journal.md`).
//!
//! | Module | Contenu | Spec |
//! |---|---|---|
//! | [`ticket`] | Vérification locale des tickets `srt1` | 02 |
//! | [`signing`] | Requêtes signées runtime → API (signature et vérification) | 04 §2 |
//! | [`stream`] | Flux de notifications API → runtime | 04 §6 |
//! | [`api`] | Réponses du canal interne | 04 §4 |
//! | [`client`] | WebSocket client ↔ runtime | 05 |
//! | [`pipe`] | Pipe superviseur ↔ worker | 06 |
//! | [`ids`] | Contraintes des identifiants | 00 §3.2 |
//!
//! Aucune primitive cryptographique n'est réimplémentée ici : Ed25519 vient de `ed25519-dalek`,
//! le reste de `synco-e2ee`.

#![forbid(unsafe_code)]

pub mod api;
pub mod client;
pub mod ids;
pub mod pipe;
pub mod signing;
pub mod stream;
pub mod ticket;
