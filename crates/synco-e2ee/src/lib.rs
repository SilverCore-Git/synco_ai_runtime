//! # synco-e2ee
//!
//! Formats E2EE de Synco en Rust, compatibles octet pour octet avec le client TypeScript
//! (`synco_app/src/assets/utils/`) : formats v4 existants dont le runtime a besoin, et nouveaux
//! formats de la délégation au Synco AI Runtime (`docs/plan/` du dépôt `synco_ai_runtime`).
//!
//! | Module | Contenu |
//! |---|---|
//! | [`account`] | Clé de compte AK (tests de compatibilité seulement) |
//! | [`identity`] | Clés d'identité scellées par AK (compatibilité) ; chaîne de transitions d'identité |
//! | [`device`] | Enveloppe d'AK d'un appareil, certificat d'appareil |
//! | [`keys`] | Commitments et signatures FC4 des clés distribuées ; enveloppes `rt1` |
//! | [`session`] | Champs `gcm1:` des conversations (AAD `session:message:champ`) |
//! | [`delegation`] | Enveloppe de tête `srd1`, mandat, entrées `sre1` |
//! | [`runtime_cert`] | Empreinte, code d'appairage, URL canonique, certificat, défi de possession |
//!
//! Principes : aucune entrée/sortie, aucun `async`, aucun état global ; l'aléa est injecté
//! ([`RandomSource`]) ; les secrets s'effacent à la libération et ne s'affichent pas ; chaque refus
//! est une [`Error`] typée avec un code machine stable, jamais une panique.
//!
//! La crate n'offre **aucune** fonction pour sceller AK ou une clé d'identité vers un runtime ; le
//! scellement d'AK vers un appareil n'existe que derrière la fonctionnalité `legacy-seal`, pour les
//! vecteurs de compatibilité.

#![forbid(unsafe_code)]

pub mod account;
pub mod delegation;
pub mod device;
pub mod ec;
pub mod encoding;
pub mod error;
pub mod identity;
pub mod keys;
pub mod primitives;
pub mod rng;
pub mod runtime_cert;
pub mod secret;
pub mod session;

pub use error::{Error, Result};
#[cfg(feature = "os-rng")]
pub use rng::OsRandom;
pub use rng::RandomSource;
pub use secret::SymmetricKey;
