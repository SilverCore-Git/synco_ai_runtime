//! Tickets `srt1` (docs/plan/02-tickets.md) : vérification **locale** par le runtime, dans l'ordre
//! de 02 §5, à l'identique de `verifyAiTicket` (synco_api `runtimeTickets.ts`, implémentation de
//! référence rejouée par les vecteurs `tests/vectors/tickets-runtime.json`).
//!
//! ```text
//! srt1.<kid>.<contenu JSON b64u>.<signature Ed25519 b64u>
//! signature sur "synco-ai-runtime-ticket\0" ‖ utf8("srt1." kid "." contenu)
//! ```

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};
use synco_e2ee::encoding::{from_b64u, from_b64u_array};

use crate::ids::{MAX_SAFE_INTEGER, is_identifier, is_uuid};

/// Préfixe des tickets du runtime.
pub const PREFIX: &str = "srt1";
/// Domaine de signature (02 §2), octet nul compris.
pub const DOMAIN: &[u8] = b"synco-ai-runtime-ticket\0";
/// Longueur maximale d'un ticket, contrôlée avant tout décodage.
pub const MAX_LENGTH: usize = 2048;
/// Tolérance d'horloge (02 §6).
pub const CLOCK_SKEW_SECS: u64 = 30;
/// Durée de vie maximale acceptée (02 §6).
pub const MAX_LIFETIME_SECS: u64 = 600;

/// Codes de refus (02 §10). Le WebSocket ferme en `4401` avec ce code pour raison (05 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketError {
    /// Aucun ticket.
    Missing,
    /// Format, signature, JSON, durée ou contrainte invalide.
    Invalid,
    /// `kid` inconnu.
    UnknownKey,
    /// Expiré.
    Expired,
    /// `op` ne correspond pas à la route.
    WrongOperation,
    /// `rt` ne désigne pas ce runtime.
    WrongAudience,
    /// Org non appairée.
    WrongOrg,
    /// `conv` ≠ conversation du chemin.
    WrongConversation,
    /// Utilisateur ou conversation révoqués.
    Revoked,
}

impl TicketError {
    /// Code machine stable.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Missing => "ticket_missing",
            Self::Invalid => "ticket_invalid",
            Self::UnknownKey => "ticket_unknown_key",
            Self::Expired => "ticket_expired",
            Self::WrongOperation => "ticket_wrong_operation",
            Self::WrongAudience => "ticket_wrong_audience",
            Self::WrongOrg => "ticket_wrong_org",
            Self::WrongConversation => "ticket_wrong_conversation",
            Self::Revoked => "ticket_revoked",
        }
    }
}

impl core::fmt::Display for TicketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for TicketError {}

/// Clés publiques de l'API (`kid` → clé Ed25519), publiées par `GET /api/ai/ticket-keys` (02 §7).
#[derive(Debug, Clone, Default)]
pub struct TicketKeys {
    keys: BTreeMap<String, VerifyingKey>,
}

impl TicketKeys {
    /// Depuis `{ kid: b64u(32 octets) }`. Une clé ou un `kid` invalide est ignoré (et compté).
    #[must_use]
    pub fn from_b64u_map<'a>(entries: impl IntoIterator<Item = (&'a str, &'a str)>) -> (Self, usize) {
        let mut keys = BTreeMap::new();
        let mut rejected = 0usize;
        for (kid, key) in entries {
            match (is_kid(kid), from_b64u_array::<32>(key).ok().and_then(|b| VerifyingKey::from_bytes(&b).ok())) {
                (true, Some(vk)) => {
                    keys.insert(kid.to_owned(), vk);
                }
                _ => rejected = rejected.saturating_add(1),
            }
        }
        (Self { keys }, rejected)
    }

    /// Nombre de clés connues.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Aucune clé connue.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// `kid` connu ?
    #[must_use]
    pub fn contains(&self, kid: &str) -> bool {
        self.keys.contains_key(kid)
    }

    fn get(&self, kid: &str) -> Option<&VerifyingKey> {
        self.keys.get(kid)
    }
}

/// Révocation d'un utilisateur (`user.revoked`, 02 §8) : tout ticket émis avant `until` est refusé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedUser {
    /// Utilisateur.
    pub user_id: String,
    /// Secondes Unix.
    pub until: u64,
}

/// Ce que connaît le runtime au moment de vérifier un ticket (02 §5 étapes 7 à 9).
#[derive(Debug, Clone, Copy)]
pub struct TicketContext<'a> {
    /// Son `runtimeId`.
    pub runtime_id: &'a str,
    /// L'org appairée.
    pub org_id: &'a str,
    /// La conversation du chemin du WebSocket.
    pub conv: &'a str,
    /// Utilisateurs révoqués (liste en mémoire).
    pub revoked_users: &'a [RevokedUser],
    /// Conversations révoquées.
    pub revoked_conversations: &'a [String],
}

/// Revendications d'un ticket `srt1` vérifié.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTicketClaims {
    /// Utilisateur.
    pub sub: String,
    /// Organisation.
    pub org: String,
    /// Runtime visé.
    pub rt: String,
    /// Conversation.
    pub conv: String,
    /// Émission.
    pub iat: u64,
    /// Expiration.
    pub exp: u64,
}

fn is_kid(kid: &str) -> bool {
    (1..=32).contains(&kid.len()) && kid.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_b64u_charset(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Entier JSON sûr (`Number.isSafeInteger(v) && v >= 0`).
fn safe_uint(v: Option<&Value>) -> Option<u64> {
    let n = v?.as_u64()?;
    (n <= MAX_SAFE_INTEGER).then_some(n)
}

const REQUIRED: [&str; 7] = ["op", "sub", "org", "rt", "conv", "iat", "exp"];
const KNOWN_OPS: [&str; 2] = ["connect", "llm"];

struct Parsed {
    op: String,
    claims: RuntimeTicketClaims,
}

/// JSON strict (02 §5 étape 4) : objet, aucun champ inconnu, tous les champs, types exacts.
fn parse_claims(json: &[u8]) -> Option<Parsed> {
    let value: Value = serde_json::from_slice(json).ok()?;
    let obj: &Map<String, Value> = value.as_object()?;
    if obj.keys().any(|k| !REQUIRED.contains(&k.as_str())) || REQUIRED.iter().any(|k| !obj.contains_key(*k)) {
        return None;
    }
    let s = |name: &str| obj.get(name).and_then(Value::as_str);
    let op = s("op").filter(|op| KNOWN_OPS.contains(op))?;
    let sub = s("sub").filter(|v| is_identifier(v))?;
    let org = s("org").filter(|v| is_identifier(v))?;
    let iat = safe_uint(obj.get("iat"))?;
    let exp = safe_uint(obj.get("exp"))?;
    let rt = s("rt").filter(|v| is_uuid(v))?;
    let conv = s("conv").filter(|v| is_identifier(v))?;
    Some(Parsed {
        op: op.to_owned(),
        claims: RuntimeTicketClaims {
            sub: sub.to_owned(),
            org: org.to_owned(),
            rt: rt.to_owned(),
            conv: conv.to_owned(),
            iat,
            exp,
        },
    })
}

/// Vérifie un ticket `srt1` dans l'ordre de 02 §5. Jamais de panique sur une entrée hostile.
pub fn verify_runtime_ticket(
    ticket: &str,
    keys: &TicketKeys,
    ctx: &TicketContext<'_>,
    now: u64,
) -> Result<RuntimeTicketClaims, TicketError> {
    use TicketError as E;
    // 1. Longueur, quatre parties, préfixe.
    if ticket.is_empty() {
        return Err(E::Missing);
    }
    if ticket.len() > MAX_LENGTH {
        return Err(E::Invalid);
    }
    let mut parts = ticket.split('.');
    let (Some(prefix), Some(kid), Some(payload), Some(sig_b64u), None) =
        (parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(E::Invalid);
    };
    if prefix != PREFIX || !is_kid(kid) || !is_b64u_charset(payload) {
        return Err(E::Invalid);
    }
    // 2. kid connu.
    let key = keys.get(kid).ok_or(E::UnknownKey)?;
    // 3. Signature avec le domaine du runtime, AVANT tout décodage JSON.
    let sig = from_b64u_array::<64>(sig_b64u).map_err(|_| E::Invalid)?;
    let mut signed = Vec::with_capacity(DOMAIN.len().saturating_add(ticket.len()));
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(prefix.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(kid.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(payload.as_bytes());
    if key.verify_strict(&signed, &Signature::from_bytes(&sig)).is_err() {
        return Err(E::Invalid);
    }
    // 4. JSON strict (b64u canonique : `from_b64u` refuse remplissage et bits de fin).
    let json = from_b64u(payload).map_err(|_| E::Invalid)?;
    let Parsed { op, claims } = parse_claims(&json).ok_or(E::Invalid)?;
    // 5. Fenêtre de validité et durée maximale.
    if now.saturating_add(CLOCK_SKEW_SECS) < claims.iat {
        return Err(E::Invalid);
    }
    if now >= claims.exp.saturating_add(CLOCK_SKEW_SECS) {
        return Err(E::Expired);
    }
    // `exp < iat` est refusé (la référence TS l'admettrait : plus strict, sans effet sur l'API honnête).
    if !claims.exp.checked_sub(claims.iat).is_some_and(|lifetime| lifetime <= MAX_LIFETIME_SECS) {
        return Err(E::Invalid);
    }
    // 6. Opération.
    if op != "connect" {
        return Err(E::WrongOperation);
    }
    // 7-9. Destinataire, org appairée, conversation, révocations.
    if claims.rt != ctx.runtime_id {
        return Err(E::WrongAudience);
    }
    if claims.org != ctx.org_id {
        return Err(E::WrongOrg);
    }
    if claims.conv != ctx.conv {
        return Err(E::WrongConversation);
    }
    if ctx.revoked_conversations.contains(&claims.conv)
        || ctx.revoked_users.iter().any(|r| r.user_id == claims.sub && claims.iat < r.until)
    {
        return Err(E::Revoked);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kid() {
        assert!(is_kid("ai-2026-11"));
        assert!(!is_kid("AI"));
        assert!(!is_kid(""));
        assert!(!is_kid(&"a".repeat(33)));
    }
}
