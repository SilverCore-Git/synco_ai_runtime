//! # synco-ai-runtime-worker
//!
//! Worker du Synco AI Runtime : un process isolé par conversation active (P3, docs/plan/06).
//!
//! État (lot L05) : seul un **bouchon de protocole** existe ([`stub`]). Il parle le pipe de 06
//! comme le vrai worker (init → ready → clés → start, `signed_request`, évènements chiffrés par
//! `CK`, bail, `done`) mais ne fait aucun appel LLM : il répond à chaque message par un texte fixe.
//! L06 (bac à sable : lancement isolé sur le descripteur 3) et L07 (boucle d'agent) le remplacent.

#![forbid(unsafe_code)]

pub mod stub;
mod time;
