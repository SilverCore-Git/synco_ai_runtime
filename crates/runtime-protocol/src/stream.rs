//! Flux de notifications API → runtime (docs/plan/04-canal-interne.md §6), forme réelle de
//! `runtimeStreamEvents.ts` (synco_api). Aucune trame ne porte de contenu chiffré.
//!
//! Lecture tolérante côté runtime : un `type` inconnu donne [`ApiEvent::Unknown`] (ignoré), pour
//! qu'une API plus récente ne coupe pas un runtime plus ancien. Les champs connus sont validés.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ids::is_identifier;

/// Chemin du flux.
pub const STREAM_PATH: &str = "/api/runtime/v1/stream";

/// Type de clé d'une entrée retirée.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKindName {
    /// Clé de salon.
    Thread,
    /// Clé d'espace.
    Space,
    /// Clé de conversation.
    Conv,
}

/// Entrée retirée d'une délégation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RemovedEntry {
    /// Type.
    pub kind: EntryKindName,
    /// Référence.
    #[serde(rename = "ref")]
    pub reference: String,
    /// Version.
    pub version: u64,
}

/// Raison d'un réveil.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WakeReason {
    /// Élément déposé dans la boîte.
    Inbox,
    /// Décision de l'utilisateur.
    Decision,
    /// Clé arrivée.
    Keys,
}

/// Évènement reçu de l'API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiEvent {
    /// Ouverture : contrôle d'horloge.
    Hello {
        /// Org appairée.
        org_id: String,
        /// Heure de l'API (s).
        server_time: u64,
    },
    /// Une conversation est autorisée sur ce runtime.
    ConversationAuthorized {
        /// Conversation.
        session_id: String,
        /// Propriétaire.
        user_id: String,
        /// Autorisation.
        auth_id: String,
    },
    /// Du travail attend un worker.
    ConversationWake {
        /// Conversation.
        session_id: String,
        /// Autorisation.
        auth_id: String,
        /// Raison.
        reason: WakeReason,
    },
    /// Conversation révoquée : arrêter le worker, oublier `CK`, fermer les clients (`4403`).
    ConversationRevoked {
        /// Conversation.
        session_id: String,
        /// Raison (code).
        reason: String,
    },
    /// Délégation remplacée ou créée : recharger.
    DelegationUpdated {
        /// Utilisateur.
        user_id: String,
        /// Nouvelle délégation.
        delegation_id: String,
    },
    /// Entrées ajoutées.
    DelegationEntriesAdded {
        /// Délégation.
        delegation_id: String,
        /// Curseur.
        after: String,
    },
    /// Entrées retirées : effacer ces clés.
    DelegationEntriesRemoved {
        /// Délégation.
        delegation_id: String,
        /// Clés.
        entries: Vec<RemovedEntry>,
    },
    /// Délégation révoquée : effacer `DK` et les clés, arrêter les workers de l'utilisateur.
    DelegationRevoked {
        /// Utilisateur.
        user_id: String,
        /// Délégation.
        delegation_id: String,
        /// Raison.
        reason: String,
    },
    /// Révocation des tickets d'un utilisateur émis avant `until` (02 §8).
    UserRevoked {
        /// Utilisateur.
        user_id: String,
        /// Secondes Unix.
        until: u64,
    },
    /// Désappairage (01 §9).
    RuntimeUnpaired,
    /// Maintien : répondre `pong`.
    Ping,
    /// Type inconnu (ignoré).
    Unknown,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fields {
    org_id: Option<String>,
    server_time: Option<u64>,
    session_id: Option<String>,
    user_id: Option<String>,
    auth_id: Option<String>,
    reason: Option<Value>,
    delegation_id: Option<String>,
    after: Option<String>,
    entries: Option<Vec<RemovedEntry>>,
    until: Option<u64>,
}

/// Raison de refus d'une trame du flux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidApiFrame;

fn id(v: Option<String>) -> Result<String, InvalidApiFrame> {
    v.filter(|s| is_identifier(s)).ok_or(InvalidApiFrame)
}

fn code(v: Option<Value>) -> Result<String, InvalidApiFrame> {
    match v {
        Some(Value::String(s)) if (1..=64).contains(&s.len()) => Ok(s),
        _ => Err(InvalidApiFrame),
    }
}

/// Analyse une trame texte du flux. `v` doit valoir 1.
pub fn parse_api_event(text: &str) -> Result<ApiEvent, InvalidApiFrame> {
    let mut value: Value = serde_json::from_str(text).map_err(|_| InvalidApiFrame)?;
    let obj = value.as_object_mut().ok_or(InvalidApiFrame)?;
    if obj.remove("v").and_then(|v| v.as_u64()) != Some(1) {
        return Err(InvalidApiFrame);
    }
    let Some(Value::String(kind)) = obj.remove("type") else {
        return Err(InvalidApiFrame);
    };
    let f: Fields = serde_json::from_value(value).map_err(|_| InvalidApiFrame)?;
    Ok(match kind.as_str() {
        "hello" => ApiEvent::Hello { org_id: id(f.org_id)?, server_time: f.server_time.ok_or(InvalidApiFrame)? },
        "conversation.authorized" => ApiEvent::ConversationAuthorized {
            session_id: id(f.session_id)?,
            user_id: id(f.user_id)?,
            auth_id: id(f.auth_id)?,
        },
        "conversation.wake" => {
            let reason = serde_json::from_value(f.reason.ok_or(InvalidApiFrame)?).map_err(|_| InvalidApiFrame)?;
            ApiEvent::ConversationWake { session_id: id(f.session_id)?, auth_id: id(f.auth_id)?, reason }
        }
        "conversation.revoked" => {
            ApiEvent::ConversationRevoked { session_id: id(f.session_id)?, reason: code(f.reason)? }
        }
        "delegation.updated" => {
            ApiEvent::DelegationUpdated { user_id: id(f.user_id)?, delegation_id: id(f.delegation_id)? }
        }
        "delegation.entries_added" => ApiEvent::DelegationEntriesAdded {
            delegation_id: id(f.delegation_id)?,
            after: f.after.filter(|a| (1..=200).contains(&a.len())).ok_or(InvalidApiFrame)?,
        },
        "delegation.entries_removed" => ApiEvent::DelegationEntriesRemoved {
            delegation_id: id(f.delegation_id)?,
            entries: f.entries.ok_or(InvalidApiFrame)?,
        },
        "delegation.revoked" => ApiEvent::DelegationRevoked {
            user_id: id(f.user_id)?,
            delegation_id: id(f.delegation_id)?,
            reason: code(f.reason)?,
        },
        "user.revoked" => ApiEvent::UserRevoked { user_id: id(f.user_id)?, until: f.until.ok_or(InvalidApiFrame)? },
        "runtime.unpaired" => ApiEvent::RuntimeUnpaired,
        "ping" => ApiEvent::Ping,
        _ => ApiEvent::Unknown,
    })
}

/// Trame `pong` (runtime → API).
#[must_use]
pub fn pong_frame() -> String {
    r#"{"v":1,"type":"pong"}"#.to_owned()
}

/// Trame `presence` (runtime → API, ≤ 1 / 30 s).
#[must_use]
pub fn presence_frame(workers: u64) -> String {
    format!(r#"{{"v":1,"type":"presence","workers":{workers}}}"#)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evenements() {
        assert_eq!(
            parse_api_event(r#"{"v":1,"type":"hello","orgId":"org1","serverTime":5}"#),
            Ok(ApiEvent::Hello { org_id: "org1".into(), server_time: 5 })
        );
        assert_eq!(parse_api_event(r#"{"v":1,"type":"ping"}"#), Ok(ApiEvent::Ping));
        assert_eq!(parse_api_event(r#"{"v":1,"type":"nouveau"}"#), Ok(ApiEvent::Unknown));
        assert!(parse_api_event(r#"{"v":2,"type":"ping"}"#).is_err());
        assert!(parse_api_event(r#"{"v":1,"type":"conversation.revoked","sessionId":"a|b","reason":"x"}"#).is_err());
        assert_eq!(
            parse_api_event(
                r#"{"v":1,"type":"delegation.entries_removed","delegationId":"d1","entries":[{"kind":"thread","ref":"t1","version":1}]}"#
            ),
            Ok(ApiEvent::DelegationEntriesRemoved {
                delegation_id: "d1".into(),
                entries: vec![RemovedEntry { kind: EntryKindName::Thread, reference: "t1".into(), version: 1 }]
            })
        );
        assert!(
            parse_api_event(r#"{"v":1,"type":"conversation.wake","sessionId":"s","authId":"a","reason":"x"}"#).is_err()
        );
    }
}
