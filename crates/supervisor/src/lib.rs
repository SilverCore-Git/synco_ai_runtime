//! # synco-ai-runtime (superviseur)
//!
//! Process principal du Synco AI Runtime (lot L05, docs/plan/01–06, 08, 09) : **seul détenteur**
//! des clés privées du runtime (mesure 7), scellées au repos (mesure 8) ; appairage et défi de
//! possession ; canal interne signé vers l'API et flux de notifications ; vérification locale des
//! tickets `srt1` ; ouverture des délégations (en mémoire seulement, cloisonnées par
//! utilisateur) ; routage des WebSocket des clients vers le worker de chaque conversation ;
//! arrêt propre.
//!
//! Les workers sont lancés derrière [`launcher::WorkerLauncher`] (bouchon en L05, bac à sable en
//! L06).

#![forbid(unsafe_code)]

pub mod api;
pub mod app;
pub mod cli;
pub mod client_ws;
pub mod clock;
pub mod config;
pub mod error;
pub mod keys;
pub mod launcher;
pub mod pins;
pub mod ratelimit;
pub mod runtime;
pub mod seal;
pub mod server;
pub mod state;
pub mod stream;
pub mod vault;
pub mod workers;
