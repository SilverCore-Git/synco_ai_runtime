//! Erreurs du superviseur. Les messages ne contiennent jamais de clé, de ticket ni de contenu.

use core::fmt;

/// Erreur du superviseur.
#[derive(Debug)]
pub enum Error {
    /// Configuration invalide (message pour l'opérateur).
    Config(String),
    /// Magasin de clés : absent, illisible, mauvaise phrase de passe, scellement impossible.
    KeyStore(String),
    /// Entrée/sortie locale.
    Io(String),
    /// Appel à l'API.
    Api(crate::api::ApiError),
    /// Primitive cryptographique (code de `synco-e2ee`).
    Crypto(&'static str),
    /// Le runtime n'est pas appairé.
    NotPaired,
    /// Lancement d'un worker impossible.
    Worker(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(m) => write!(f, "configuration : {m}"),
            Self::KeyStore(m) => write!(f, "clés du runtime : {m}"),
            Self::Io(m) => write!(f, "entrée/sortie : {m}"),
            Self::Api(e) => write!(f, "API : {e}"),
            Self::Crypto(code) => write!(f, "cryptographie : {code}"),
            Self::NotPaired => f.write_str("runtime non appairé"),
            Self::Worker(m) => write!(f, "worker : {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<synco_e2ee::Error> for Error {
    fn from(e: synco_e2ee::Error) -> Self {
        Self::Crypto(e.code())
    }
}

impl From<crate::api::ApiError> for Error {
    fn from(e: crate::api::ApiError) -> Self {
        Self::Api(e)
    }
}

/// Raccourci.
pub type Result<T> = core::result::Result<T, Error>;
