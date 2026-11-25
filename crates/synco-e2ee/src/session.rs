//! Champs chiffrés des conversations : `gcm1:` + `b64(nonce(12) ‖ chiffré ‖ tag(16))`, AAD
//! `utf8(sessionId ":" messageId ":" fieldName)` — séparateur **`:`**, pas `|`
//! (docs/plan/03-delegation.md §6.3, 05-flux-client-runtime.md §4).
//!
//! Format identique à `Synco_AI_Gateway/src/crypto.rs` et à `encryptAiField` / `decryptAiField`
//! (`synco_app/src/assets/utils/crypto.ts:952-1003`) ; seule la clé change (`CK` par conversation,
//! ou `AiSessionKey` pour les conversations `gateway` historiques).

use serde_json::Value;

use crate::encoding::{b64, check_id, check_uint};
use crate::error::{Error, Result};
use crate::primitives::{self, IV_LENGTH, TAG_LENGTH};
use crate::rng::RandomSource;
use crate::secret::SymmetricKey;

/// Préfixe de version des champs chiffrés.
pub const VERSION_PREFIX: &str = "gcm1:";

/// `messageId` de `pendingToolCall.args`.
pub const PENDING_MESSAGE_ID: &str = "__pending__";
/// `messageId` du titre de la session.
pub const SESSION_TITLE_MESSAGE_ID: &str = "__session_title__";
/// `messageId` de la trame `snapshot`.
pub const SNAPSHOT_MESSAGE_ID: &str = "__snapshot__";
/// `messageId` du détail d'une trame `error`.
pub const ERROR_MESSAGE_ID: &str = "__error__";
/// `messageId` d'une trame `answer` (client).
pub const ANSWER_MESSAGE_ID: &str = "__answer__";

/// Nom de champ de l'AAD (03 §6.3, 05 §4). Les identifiants et entiers sont validés à la
/// construction de l'AAD (00 §3.2), pour qu'aucune AAD écrite ne soit ambiguë.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldName {
    /// `content`.
    Content,
    /// `thinking`.
    Thinking,
    /// `tool_result`.
    ToolResult,
    /// `tool_call_arguments:<toolCallId>`.
    ToolCallArguments(String),
    /// `pending_tool_call_args` (avec le `messageId` [`PENDING_MESSAGE_ID`]).
    PendingToolCallArgs,
    /// `title` (avec le `messageId` [`SESSION_TITLE_MESSAGE_ID`]).
    Title,
    /// `ws:text:<epoch>:<seq>`.
    WsText {
        /// Époque du bail.
        epoch: u64,
        /// Numéro de séquence.
        seq: u64,
    },
    /// `ws:thinking:<epoch>:<seq>`.
    WsThinking {
        /// Époque du bail.
        epoch: u64,
        /// Numéro de séquence.
        seq: u64,
    },
    /// `snapshot:<epoch>:<seq>`.
    Snapshot {
        /// Époque du bail.
        epoch: u64,
        /// Numéro de séquence.
        seq: u64,
    },
    /// `error:<epoch>:<seq>`.
    ErrorDetail {
        /// Époque du bail.
        epoch: u64,
        /// Numéro de séquence.
        seq: u64,
    },
    /// `answer:<toolCallId>`.
    Answer(String),
    /// `plan` (avec le `messageId` = `planId`, 12 §3.3).
    Plan,
    /// `plan_result:<k>` : résultat de la phase d'appareil `k ≥ 1` (12 §9).
    PlanResult(u64),
    /// `plan_agent_result:<k>` : résultat de la phase d'agent `k ≥ 1` (12 §9).
    PlanAgentResult(u64),
    /// `artifact_meta` : métadonnées d'un artefact (13 §3) ; le `messageId` de l'AAD est l'`artifactId`.
    ArtifactMeta,
    /// `artifact` : contenu d'un artefact (13 §3) ; le `messageId` de l'AAD est l'`artifactId`.
    Artifact,
    /// `web_guard` : motifs de confirmation d'un appel web (10 §4.4) ; le `messageId` de l'AAD est le
    /// `toolCallId`.
    WebGuard,
}

impl FieldName {
    /// Partie `fieldName` de l'AAD, après validation.
    pub fn to_aad_part(&self) -> Result<String> {
        let counters = |label: &str, epoch: u64, seq: u64| -> Result<String> {
            check_uint(epoch)?;
            check_uint(seq)?;
            Ok(format!("{label}:{epoch}:{seq}"))
        };
        match self {
            Self::Content => Ok("content".to_owned()),
            Self::Thinking => Ok("thinking".to_owned()),
            Self::ToolResult => Ok("tool_result".to_owned()),
            Self::ToolCallArguments(id) => {
                check_id(id)?;
                Ok(format!("tool_call_arguments:{id}"))
            }
            Self::PendingToolCallArgs => Ok("pending_tool_call_args".to_owned()),
            Self::Title => Ok("title".to_owned()),
            Self::WsText { epoch, seq } => counters("ws:text", *epoch, *seq),
            Self::WsThinking { epoch, seq } => counters("ws:thinking", *epoch, *seq),
            Self::Snapshot { epoch, seq } => counters("snapshot", *epoch, *seq),
            Self::ErrorDetail { epoch, seq } => counters("error", *epoch, *seq),
            Self::Answer(id) => {
                check_id(id)?;
                Ok(format!("answer:{id}"))
            }
            Self::Plan => Ok("plan".to_owned()),
            Self::ArtifactMeta => Ok("artifact_meta".to_owned()),
            Self::Artifact => Ok("artifact".to_owned()),
            Self::WebGuard => Ok("web_guard".to_owned()),
            Self::PlanResult(k) | Self::PlanAgentResult(k) => {
                check_uint(*k)?;
                if *k == 0 {
                    return Err(Error::InvalidInput);
                }
                let label = if matches!(self, Self::PlanResult(_)) { "plan_result" } else { "plan_agent_result" };
                Ok(format!("{label}:{k}"))
            }
        }
    }
}

fn build_aad(session_id: &str, message_id: &str, field_name: &str) -> String {
    format!("{session_id}:{message_id}:{field_name}")
}

/// Chiffre un champ texte. Écriture stricte : `sessionId` et `messageId` conformes à 00 §3.2.
pub fn encrypt_field(
    key: &SymmetricKey,
    session_id: &str,
    message_id: &str,
    field: &FieldName,
    plaintext: &str,
    rng: &mut impl RandomSource,
) -> Result<String> {
    let mut iv = [0u8; IV_LENGTH];
    rng.fill(&mut iv)?;
    encrypt_field_with_iv(key, session_id, message_id, field, plaintext, &iv)
}

fn encrypt_field_with_iv(
    key: &SymmetricKey,
    session_id: &str,
    message_id: &str,
    field: &FieldName,
    plaintext: &str,
    iv: &[u8; IV_LENGTH],
) -> Result<String> {
    check_id(session_id)?;
    check_id(message_id)?;
    let aad = build_aad(session_id, message_id, &field.to_aad_part()?);
    let wire = primitives::seal_with_iv(key.as_bytes(), iv, aad.as_bytes(), plaintext.as_bytes())?;
    Ok(format!("{VERSION_PREFIX}{}", b64(&wire)))
}

/// Sérialise `value` en JSON puis chiffre (`tool_result`, arguments d'outils, `snapshot`).
pub fn encrypt_json_field(
    key: &SymmetricKey,
    session_id: &str,
    message_id: &str,
    field: &FieldName,
    value: &Value,
    rng: &mut impl RandomSource,
) -> Result<String> {
    let plaintext = serde_json::to_string(value).map_err(|_| Error::FieldInvalidJson)?;
    encrypt_field(key, session_id, message_id, field, &plaintext, rng)
}

/// Déchiffre une valeur `gcm1:`. **Stricte** : `sessionId` et `messageId` conformes à 00 §3.2
/// ([`Error::InvalidInput`] avant de construire l'AAD, qu'un `:` rendrait ambiguë), puis une valeur
/// sans préfixe est une erreur ([`Error::FieldUnknownVersion`]). `field_name` est la partie brute de
/// l'AAD : la lecture reste tolérante aux noms de champ historiques.
pub fn decrypt_field(
    key: &SymmetricKey,
    session_id: &str,
    message_id: &str,
    field_name: &str,
    wire_value: &str,
) -> Result<String> {
    check_id(session_id)?;
    check_id(message_id)?;
    let encoded = wire_value.strip_prefix(VERSION_PREFIX).ok_or(Error::FieldUnknownVersion)?;
    let raw = crate::encoding::from_b64(encoded).map_err(|_| Error::FieldInvalidBase64)?;
    if raw.len() < IV_LENGTH.saturating_add(TAG_LENGTH) {
        return Err(Error::FieldInvalidLength);
    }
    let aad = build_aad(session_id, message_id, field_name);
    let plain = primitives::open(key.as_bytes(), aad.as_bytes(), &raw).ok_or(Error::FieldAuthenticationFailed)?;
    String::from_utf8(plain.to_vec()).map_err(|_| Error::FieldInvalidUtf8)
}

/// Lecture tolérante (`decrypt_field_if_encrypted` de la passerelle) : une valeur sans préfixe
/// `gcm1:` est rendue telle quelle (données écrites avant le chiffrement).
pub fn decrypt_field_if_encrypted(
    key: &SymmetricKey,
    session_id: &str,
    message_id: &str,
    field_name: &str,
    wire_value: &str,
) -> Result<String> {
    if wire_value.starts_with(VERSION_PREFIX) {
        decrypt_field(key, session_id, message_id, field_name, wire_value)
    } else {
        Ok(wire_value.to_owned())
    }
}

/// Déchiffre une valeur `gcm1:` et lit le JSON (stricte).
pub fn decrypt_json_field(
    key: &SymmetricKey,
    session_id: &str,
    message_id: &str,
    field_name: &str,
    wire_value: &str,
) -> Result<Value> {
    let plain = decrypt_field(key, session_id, message_id, field_name, wire_value)?;
    serde_json::from_str(&plain).map_err(|_| Error::FieldInvalidJson)
}

/// Lecture tolérante d'un champ JSON : une valeur qui n'est pas une chaîne `gcm1:` est rendue
/// telle quelle (`decrypt_json_field_if_encrypted` de la passerelle).
pub fn decrypt_json_field_if_encrypted(
    key: &SymmetricKey,
    session_id: &str,
    message_id: &str,
    field_name: &str,
    value: Value,
) -> Result<Value> {
    match &value {
        Value::String(s) if s.starts_with(VERSION_PREFIX) => {
            decrypt_json_field(key, session_id, message_id, field_name, s)
        }
        _ => Ok(value),
    }
}
