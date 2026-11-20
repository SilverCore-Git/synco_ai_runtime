//! # synco-ai-runtime-worker
//!
//! Worker du Synco AI Runtime : un process isolé par conversation active (P3, docs/plan/06).
//!
//! État : un **bouchon de protocole** ([`stub`], L05) parle le pipe de 06 comme le vrai worker
//! (init → ready → clés → start, `signed_request`, évènements chiffrés par `CK`, bail, `done`) sans
//! appel LLM. L06 fournit le point d'entrée isolé ([`entry`] : pipe sur le descripteur 3, lancé
//! par le bac à sable du superviseur) et le client du mandataire LLM ([`llm`]) ; L07 remplace le
//! bouchon par la boucle d'agent.

#![forbid(unsafe_code)]

pub mod entry;
pub mod llm;
pub mod stub;
mod time;
