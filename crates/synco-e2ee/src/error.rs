//! Erreur unique de la crate : chaque refus porte un code machine stable (`snake_case`,
//! docs/plan/00-vue-ensemble.md §3.4), jamais la valeur reçue ni le détail interne.

use core::fmt;

/// Refus d'une opération. [`Error::code`] donne le code machine, identique à celui des vecteurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Un champ ne respecte pas sa contrainte (identifiant, entier, empreinte… 00 §3.2).
    InvalidInput,
    /// Clé publique ou privée invalide (JWK mal formée, point hors courbe, scalaire nul…).
    InvalidKey,
    /// Encodage invalide (base64, base64url, hexadécimal, JSON).
    InvalidEncoding,
    /// Générateur aléatoire du système indisponible.
    RandomUnavailable,
    /// Enveloppe E2EE v4 (identité, appareil) illisible : mauvaise clé, AAD ou forme.
    EnvelopeUnusable,
    /// Signature ECDSA invalide (certificat d'appareil, transition d'identité…).
    BadSignature,
    /// FC4 : la clé reçue ne correspond pas au commitment signé.
    KeyCommitmentMismatch,
    /// FC4 : signature d'enveloppe de clé invalide pour la clé du créateur.
    KeyBadSignature,
    /// Champ `gcm1:` : préfixe de version inconnu.
    FieldUnknownVersion,
    /// Champ `gcm1:` : base64 invalide.
    FieldInvalidBase64,
    /// Champ `gcm1:` : moins de 12 + 16 octets.
    FieldInvalidLength,
    /// Champ `gcm1:` : tag GCM invalide (mauvaise clé, AAD ou donnée altérée).
    FieldAuthenticationFailed,
    /// Champ `gcm1:` : clair qui n'est pas de l'UTF-8.
    FieldInvalidUtf8,
    /// Champ `gcm1:` : clair qui n'est pas le JSON attendu.
    FieldInvalidJson,
    /// Délégation refusée : mandat, enveloppe de tête ou contexte (03 §14). Cause jamais précisée.
    DelegationUnusable,
    /// Entrée de délégation refusée (03 §5).
    EntryUnusable,
    /// Certificat de runtime mal formé (01 §10).
    CertInvalid,
    /// Signature du certificat de runtime invalide (01 §10).
    CertBadSignature,
    /// Défi de possession mal formé (01 §5).
    ChallengeInvalid,
    /// Réponse au défi de possession invalide (`mac` ou `sig`, 01 §5).
    ChallengeFailed,
    /// Code d'appairage illisible (longueur, caractère, somme de contrôle, 01 §2.2).
    PairCodeInvalid,
    /// Code d'appairage lisible mais d'une autre empreinte (01 §2.2).
    PairCodeMismatch,
    /// URL de runtime non canonisable (01 §3).
    UrlInvalid,
    /// Plan d'action hors des règles de 12 §5 (le motif est dans [`crate::plan::PlanInvalid`]).
    PlanInvalid,
    /// Appel d'exécution refusé par le verrou de 12 §8.4 (condensat ou `refs`).
    ActionNotAccepted,
}

impl Error {
    /// Code machine stable.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::InvalidKey => "key_invalid",
            Self::InvalidEncoding => "encoding_invalid",
            Self::RandomUnavailable => "random_unavailable",
            Self::EnvelopeUnusable => "envelope_unusable",
            Self::BadSignature => "bad_signature",
            Self::KeyCommitmentMismatch => "key_commitment_mismatch",
            Self::KeyBadSignature => "key_bad_signature",
            Self::FieldUnknownVersion => "field_unknown_version",
            Self::FieldInvalidBase64 => "field_invalid_base64",
            Self::FieldInvalidLength => "field_invalid_length",
            Self::FieldAuthenticationFailed => "field_authentication_failed",
            Self::FieldInvalidUtf8 => "field_invalid_utf8",
            Self::FieldInvalidJson => "field_invalid_json",
            Self::DelegationUnusable => "delegation_unusable",
            Self::EntryUnusable => "entry_unusable",
            Self::CertInvalid => "cert_invalid",
            Self::CertBadSignature => "cert_bad_signature",
            Self::ChallengeInvalid => "challenge_invalid",
            Self::ChallengeFailed => "challenge_failed",
            Self::PairCodeInvalid => "pair_code_invalid",
            Self::PairCodeMismatch => "pair_code_mismatch",
            Self::UrlInvalid => "url_invalid",
            Self::PlanInvalid => "plan_invalid",
            Self::ActionNotAccepted => "action_not_accepted",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for Error {}

/// Raccourci de la crate.
pub type Result<T> = core::result::Result<T, Error>;
