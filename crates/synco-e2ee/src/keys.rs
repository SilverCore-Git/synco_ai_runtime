//! Enveloppes FC4 des clés distribuées (salon, espace, DM, IA) : commitment et signature
//! (`keyPinning.ts:42-51`, `keyEnvelope.ts:28-46`), et enveloppe `rt1` des clés créées par le
//! runtime (docs/plan/03-delegation.md §10).

use crate::ec::{EcPublicKey, EcSigningKey};
use crate::encoding::{b64, check_id, check_uint, from_b64};
use crate::error::{Error, Result};
use crate::primitives::sha256;
use crate::secret::subtle_ct::ct_eq;

/// Préfixe du `creatorId` d'une clé créée par le runtime.
pub const RT1_CREATOR_PREFIX: &str = "rt1:";

/// Contexte `thread:<threadId>`.
#[must_use]
pub fn thread_context(thread_id: &str) -> String {
    format!("thread:{thread_id}")
}

/// Contexte `space:<workspaceId>`.
#[must_use]
pub fn space_context(workspace_id: &str) -> String {
    format!("space:{workspace_id}")
}

/// Contexte `aiconv:<sessionId>` de la clé de conversation `CK` (03 §6.2).
#[must_use]
pub fn conversation_context(session_id: &str) -> String {
    format!("aiconv:{session_id}")
}

/// `keyCommitment` : `b64(SHA-256(utf8("synco-key-commit-v1|" ctx "|" version "|") ‖ clé))`.
#[must_use]
pub fn key_commitment(raw_key: &[u8], ctx: &str, version: u64) -> String {
    let mut buf = zeroize::Zeroizing::new(format!("synco-key-commit-v1|{ctx}|{version}|").into_bytes());
    buf.extend_from_slice(raw_key);
    b64(&sha256(&buf))
}

fn check_commitment(raw_key: &[u8], ctx: &str, version: u64, commitment: &str) -> Result<()> {
    if ct_eq(key_commitment(raw_key, ctx, version).as_bytes(), commitment.as_bytes()) {
        Ok(())
    } else {
        Err(Error::KeyCommitmentMismatch)
    }
}

/// Commitment et signature d'une enveloppe de clé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEnvelopeSignature {
    /// Commitment `b64`.
    pub commitment: String,
    /// Signature `b64` P1363.
    pub signature: String,
}

/// Octets signés FC4 : `synco-key-envelope-v1|ctx|version|commitment`.
#[must_use]
pub fn key_envelope_bytes(ctx: &str, version: u64, commitment: &str) -> String {
    format!("synco-key-envelope-v1|{ctx}|{version}|{commitment}")
}

/// `signKeyEnvelope` avec la clé de signature d'identité du créateur.
#[must_use]
pub fn sign_key_envelope(sign_key: &EcSigningKey, raw_key: &[u8], ctx: &str, version: u64) -> KeyEnvelopeSignature {
    let commitment = key_commitment(raw_key, ctx, version);
    let signature = b64(&sign_key.sign(key_envelope_bytes(ctx, version, &commitment).as_bytes()));
    KeyEnvelopeSignature { commitment, signature }
}

/// `verifyKeyEnvelope` : commitment puis signature par la clé (déjà épinglée) du créateur.
pub fn verify_key_envelope(
    raw_key: &[u8],
    ctx: &str,
    version: u64,
    envelope: &KeyEnvelopeSignature,
    creator_sign_key: &EcPublicKey,
) -> Result<()> {
    check_commitment(raw_key, ctx, version, &envelope.commitment)?;
    let sig = from_b64(&envelope.signature).map_err(|_| Error::KeyBadSignature)?;
    let bytes = key_envelope_bytes(ctx, version, &envelope.commitment);
    if creator_sign_key.verify(bytes.as_bytes(), &sig) { Ok(()) } else { Err(Error::KeyBadSignature) }
}

// ---------------------------------------------------------------------------
// rt1 : clés créées par le runtime (03 §10)
// ---------------------------------------------------------------------------

/// `creatorId` d'une clé créée par le runtime : `rt1:<delegationId>`.
pub fn rt1_creator_id(delegation_id: &str) -> Result<String> {
    check_id(delegation_id)?;
    Ok(format!("{RT1_CREATOR_PREFIX}{delegation_id}"))
}

/// `delegationId` d'un `creatorId` `rt1:…`, ou `None` pour un créateur ordinaire.
#[must_use]
pub fn parse_rt1_creator(creator_id: &str) -> Option<&str> {
    creator_id.strip_prefix(RT1_CREATOR_PREFIX).filter(|id| crate::encoding::is_valid_id(id))
}

/// Contexte accepté pour une clé créée par le runtime : `thread:<id>` ou `space:<id>`.
fn check_rt1_context(ctx: &str) -> Result<()> {
    let id = ctx.strip_prefix("thread:").or_else(|| ctx.strip_prefix("space:")).ok_or(Error::InvalidInput)?;
    check_id(id)
}

/// Octets signés : `synco-key-envelope-rt-v1|ctx|version|commitment|delegationId`.
pub fn rt1_envelope_bytes(ctx: &str, version: u64, commitment: &str, delegation_id: &str) -> Result<String> {
    check_rt1_context(ctx)?;
    check_uint(version)?;
    check_id(delegation_id)?;
    Ok(format!("synco-key-envelope-rt-v1|{ctx}|{version}|{commitment}|{delegation_id}"))
}

/// Signe l'enveloppe `rt1` d'une clé créée par le runtime avec sa clé `csk`.
pub fn sign_rt1_envelope(
    csk: &EcSigningKey,
    raw_key: &[u8],
    ctx: &str,
    version: u64,
    delegation_id: &str,
) -> Result<KeyEnvelopeSignature> {
    let commitment = key_commitment(raw_key, ctx, version);
    let bytes = rt1_envelope_bytes(ctx, version, &commitment, delegation_id)?;
    Ok(KeyEnvelopeSignature { commitment, signature: b64(&csk.sign(bytes.as_bytes())) })
}

/// Vérifie l'enveloppe `rt1` (03 §10 étape 5) avec la `csk` du certificat. Le mandat de la
/// délégation se vérifie à part ([`crate::delegation::verify_mandate`]).
pub fn verify_rt1_envelope(
    csk_public: &EcPublicKey,
    raw_key: &[u8],
    ctx: &str,
    version: u64,
    delegation_id: &str,
    envelope: &KeyEnvelopeSignature,
) -> Result<()> {
    let bytes =
        rt1_envelope_bytes(ctx, version, &envelope.commitment, delegation_id).map_err(|_| Error::KeyBadSignature)?;
    check_commitment(raw_key, ctx, version, &envelope.commitment)?;
    let sig = from_b64(&envelope.signature).map_err(|_| Error::KeyBadSignature)?;
    if csk_public.verify(bytes.as_bytes(), &sig) { Ok(()) } else { Err(Error::KeyBadSignature) }
}
