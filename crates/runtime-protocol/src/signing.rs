//! Requêtes signées runtime → API (docs/plan/04-canal-interne.md §2), à l'identique de
//! `runtimeRequestSigning.ts` (synco_api) :
//!
//! ```text
//! "synco-rt-request-v1\0" ‖ utf8(METHOD "\n" PATH "\n" TS "\n" NONCE "\n" RUNTIME_ID "\n" AUTH "\n" b64u(SHA-256(CORPS)))
//! ```
//!
//! Côté runtime : [`sign_request`]. Côté vérificateur (API simulée des tests, vecteurs
//! `internal-requests.json`) : [`parse_headers`], [`verify_request`] et [`NonceCache`], qui suivent
//! l'ordre de 04 §2.3 et les codes de l'API.

use std::collections::{BTreeMap, VecDeque};

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use synco_e2ee::encoding::{b64u, from_b64u_array};
use synco_e2ee::primitives::sha256;

use crate::ids::is_identifier;

/// Domaine préfixé aux octets signés, octet nul compris.
pub const DOMAIN: &[u8] = b"synco-rt-request-v1\0";
/// `AUTH` quand `x-synco-auth` est absent.
pub const NO_AUTH: &str = "-";
/// Fenêtre d'horloge (04 §2.3 étape 2).
pub const MAX_CLOCK_DRIFT_SECS: u64 = 60;
/// Durée de vie d'un nonce dans le cache anti-rejeu (≥ 2 × fenêtre).
pub const NONCE_TTL_SECS: u64 = 120;

/// En-tête : `runtimeId`.
pub const HEADER_RUNTIME: &str = "x-synco-runtime";
/// En-tête : secondes Unix.
pub const HEADER_TIMESTAMP: &str = "x-synco-timestamp";
/// En-tête : `b64u` de 16 octets aléatoires.
pub const HEADER_NONCE: &str = "x-synco-nonce";
/// En-tête : `authId` de l'autorisation de session (absent pour les routes sans utilisateur).
pub const HEADER_AUTH: &str = "x-synco-auth";
/// En-tête : signature Ed25519 `b64u`.
pub const HEADER_SIGNATURE: &str = "x-synco-signature";

/// Champs d'une requête signée.
#[derive(Debug, Clone, Copy)]
pub struct RequestFields<'a> {
    /// Méthode HTTP (mise en majuscules dans la chaîne signée).
    pub method: &'a str,
    /// Chemin **et** chaîne de requête, exactement tels qu'envoyés.
    pub path: &'a str,
    /// Secondes Unix (décimal).
    pub timestamp: &'a str,
    /// Nonce `b64u` (16 octets).
    pub nonce: &'a str,
    /// `runtimeId`.
    pub runtime_id: &'a str,
    /// `authId`, ou `None` (→ `-`).
    pub auth_id: Option<&'a str>,
    /// Octets exacts du corps.
    pub body: &'a [u8],
}

/// Chaîne signée sans le domaine (champ `signedString` des vecteurs).
#[must_use]
pub fn signing_string(f: &RequestFields<'_>) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}",
        f.method.to_ascii_uppercase(),
        f.path,
        f.timestamp,
        f.nonce,
        f.runtime_id,
        f.auth_id.unwrap_or(NO_AUTH),
        b64u(&sha256(f.body))
    )
}

/// Octets signés : domaine ‖ chaîne.
#[must_use]
pub fn signed_bytes(f: &RequestFields<'_>) -> Vec<u8> {
    let s = signing_string(f);
    let mut out = Vec::with_capacity(DOMAIN.len().saturating_add(s.len()));
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(s.as_bytes());
    out
}

/// Signature `b64u` (64 octets) avec la clé `sig` du runtime.
#[must_use]
pub fn sign_request(f: &RequestFields<'_>, key: &SigningKey) -> String {
    b64u(&key.sign(&signed_bytes(f)).to_bytes())
}

/// En-têtes à poser sur une requête signée, dans l'ordre de 04 §2.1.
#[must_use]
pub fn signature_headers(f: &RequestFields<'_>, key: &SigningKey) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        (HEADER_RUNTIME, f.runtime_id.to_owned()),
        (HEADER_TIMESTAMP, f.timestamp.to_owned()),
        (HEADER_NONCE, f.nonce.to_owned()),
    ];
    if let Some(auth) = f.auth_id {
        headers.push((HEADER_AUTH, auth.to_owned()));
    }
    headers.push((HEADER_SIGNATURE, sign_request(f, key)));
    headers
}

// ---------------------------------------------------------------------------
// Vérification (même règle que l'API : API simulée des tests et vecteurs)
// ---------------------------------------------------------------------------

/// Codes de refus du canal (04 §8), sous-ensemble produit par la vérification de signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    /// En-têtes absents ou mal formés.
    SigMissing,
    /// Horodatage hors fenêtre.
    ClockSkew,
    /// Runtime inconnu.
    Unknown,
    /// Runtime désappairé.
    Revoked,
    /// Signature invalide.
    SigInvalid,
    /// Nonce déjà vu.
    Replay,
    /// Cache anti-rejeu plein pour ce runtime.
    RateLimited,
}

impl RequestError {
    /// Code machine stable.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SigMissing => "rt_sig_missing",
            Self::ClockSkew => "rt_clock_skew",
            Self::Unknown => "rt_unknown",
            Self::Revoked => "rt_revoked",
            Self::SigInvalid => "rt_sig_invalid",
            Self::Replay => "rt_replay",
            Self::RateLimited => "rt_rate_limited",
        }
    }

    /// Statut HTTP (04 §8).
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::Unknown => 404,
            Self::RateLimited => 429,
            _ => 401,
        }
    }
}

/// En-têtes analysés (étape 1 de 04 §2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHeaders {
    /// `x-synco-runtime`.
    pub runtime_id: String,
    /// `x-synco-timestamp`.
    pub timestamp: String,
    /// `x-synco-nonce`.
    pub nonce: String,
    /// `x-synco-auth`.
    pub auth_id: Option<String>,
    /// Signature brute.
    pub signature: [u8; 64],
}

/// Étape 1 : en-têtes présents et bien formés, sinon [`RequestError::SigMissing`].
/// `get` renvoie la valeur d'un en-tête (nom en minuscules), `None` s'il est absent ou multiple.
pub fn parse_headers<'a>(get: impl Fn(&str) -> Option<&'a str>) -> Result<ParsedHeaders, RequestError> {
    let fail = RequestError::SigMissing;
    let runtime_id = get(HEADER_RUNTIME).filter(|v| is_identifier(v)).ok_or(fail)?;
    let timestamp = get(HEADER_TIMESTAMP)
        .filter(|v| (1..=12).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_digit()))
        .ok_or(fail)?;
    let nonce = get(HEADER_NONCE).filter(|v| from_b64u_array::<16>(v).is_ok()).ok_or(fail)?;
    let auth_id = match get(HEADER_AUTH) {
        Some(a) if is_identifier(a) => Some(a.to_owned()),
        Some(_) => return Err(fail),
        None => None,
    };
    let signature = get(HEADER_SIGNATURE).and_then(|v| from_b64u_array::<64>(v).ok()).ok_or(fail)?;
    Ok(ParsedHeaders {
        runtime_id: runtime_id.to_owned(),
        timestamp: timestamp.to_owned(),
        nonce: nonce.to_owned(),
        auth_id,
        signature,
    })
}

/// Étape 2 : `|TS − maintenant| ≤ 60 s`.
#[must_use]
pub fn within_clock_window(timestamp: &str, now: u64) -> bool {
    timestamp.parse::<u64>().is_ok_and(|ts| ts.abs_diff(now) <= MAX_CLOCK_DRIFT_SECS)
}

/// Étape 4 : signature valide avec la clé enregistrée du runtime.
#[must_use]
pub fn verify_signature(f: &RequestFields<'_>, signature: &[u8; 64], public_key: &VerifyingKey) -> bool {
    public_key.verify_strict(&signed_bytes(f), &Signature::from_bytes(signature)).is_ok()
}

/// Résultat de l'anti-rejeu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceCheck {
    /// Nonce neuf, enregistré.
    Fresh,
    /// Déjà vu dans sa durée de vie.
    Replay,
    /// Ensemble plein pour ce runtime : rien n'est évincé.
    Full,
}

/// Anti-rejeu `(runtimeId, nonce)` (étape 5), même règle que `RuntimeNonceCache` de l'API : un
/// ensemble borné par runtime, purgé par expiration, qui n'évince jamais un nonce encore valide.
#[derive(Debug)]
pub struct NonceCache {
    capacity_per_runtime: usize,
    ttl_secs: u64,
    by_runtime: BTreeMap<String, VecDeque<(String, u64)>>,
}

impl NonceCache {
    /// Cache de `capacity_per_runtime` nonces par runtime, durée de vie `ttl_secs`.
    #[must_use]
    pub const fn new(capacity_per_runtime: usize, ttl_secs: u64) -> Self {
        Self { capacity_per_runtime, ttl_secs, by_runtime: BTreeMap::new() }
    }

    /// Vérifie puis enregistre.
    pub fn check_and_insert(&mut self, runtime_id: &str, nonce: &str, now: u64) -> NonceCheck {
        let set = self.by_runtime.entry(runtime_id.to_owned()).or_default();
        while set.front().is_some_and(|(_, exp)| *exp <= now) {
            set.pop_front();
        }
        if set.iter().any(|(n, exp)| n == nonce && *exp > now) {
            return NonceCheck::Replay;
        }
        if set.len() >= self.capacity_per_runtime {
            return NonceCheck::Full;
        }
        set.push_back((nonce.to_owned(), now.saturating_add(self.ttl_secs)));
        NonceCheck::Fresh
    }
}

/// Runtime tel qu'enregistré par l'API.
#[derive(Debug, Clone)]
pub struct RegisteredRuntime {
    /// Clé publique `sig`.
    pub sig_public_key: VerifyingKey,
    /// `active` ?
    pub active: bool,
}

/// Vérification complète (étapes 1 à 5 de 04 §2.3), dans l'ordre de l'API.
pub fn verify_request<'a>(
    method: &str,
    path: &str,
    body: &[u8],
    get_header: impl Fn(&str) -> Option<&'a str>,
    lookup: impl Fn(&str) -> Option<RegisteredRuntime>,
    nonces: &mut NonceCache,
    now: u64,
) -> Result<ParsedHeaders, RequestError> {
    let h = parse_headers(get_header)?;
    if !within_clock_window(&h.timestamp, now) {
        return Err(RequestError::ClockSkew);
    }
    let runtime = lookup(&h.runtime_id).ok_or(RequestError::Unknown)?;
    if !runtime.active {
        return Err(RequestError::Revoked);
    }
    let fields = RequestFields {
        method,
        path,
        timestamp: &h.timestamp,
        nonce: &h.nonce,
        runtime_id: &h.runtime_id,
        auth_id: h.auth_id.as_deref(),
        body,
    };
    if !verify_signature(&fields, &h.signature, &runtime.sig_public_key) {
        return Err(RequestError::SigInvalid);
    }
    match nonces.check_and_insert(&h.runtime_id, &h.nonce, now) {
        NonceCheck::Fresh => Ok(h),
        NonceCheck::Replay => Err(RequestError::Replay),
        NonceCheck::Full => Err(RequestError::RateLimited),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_cache_sans_eviction() {
        let mut c = NonceCache::new(2, 120);
        assert_eq!(c.check_and_insert("r", "a", 0), NonceCheck::Fresh);
        assert_eq!(c.check_and_insert("r", "a", 1), NonceCheck::Replay);
        assert_eq!(c.check_and_insert("r", "b", 1), NonceCheck::Fresh);
        assert_eq!(c.check_and_insert("r", "c", 1), NonceCheck::Full);
        assert_eq!(c.check_and_insert("autre", "a", 1), NonceCheck::Fresh);
        assert_eq!(c.check_and_insert("r", "c", 120), NonceCheck::Fresh, "a expiré : place libérée");
    }

    #[test]
    fn horloge() {
        assert!(within_clock_window("100", 160));
        assert!(!within_clock_window("100", 161));
        assert!(within_clock_window("160", 100));
        assert!(!within_clock_window("x", 100));
    }
}
