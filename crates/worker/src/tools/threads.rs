//! `create_thread` dans le worker : même cérémonie que `createThreadHelper` (`OrgAI.vue`), plus
//! l'enveloppe `rt1` et l'entrée de délégation des clés créées par le runtime (03 §10, §10.1, Q11 = B).
//!
//! Pour chaque salon demandé :
//!
//! 1. clé de salon tirée (AES-256) ;
//! 2. scellée en RSA-OAEP-SHA256 pour chaque destinataire (`encryptThreadKeyForMember`), avec les
//!    clés publiques de `GET /e2ee/members/keys` ;
//! 3. `POST /e2ee/threads` (champs de `createThreadSchema` + `spaceId?` + `leaseEpoch`, sans
//!    `commitment` ni `signature`) → id du salon ;
//! 4. trame `created_key` au superviseur (seul détenteur de `csk` et `DK`) → engagement, signature
//!    `rt1` et entrée chiffrée ;
//! 5. `POST /e2ee/threads/:threadId/key-envelope` ;
//! 6. `POST /delegations/:delegationId/entries`.
//!
//! **Destinataires** : à l'accueil de l'org, tous les membres (comme l'app) ; dans un espace,
//! **seulement le propriétaire** de la conversation, car le canal ne donne pas les membres d'un
//! espace (l'app utilise `space.membersId`) et sceller la clé pour un non-membre la lui donnerait.
//! **Catégorie** : `categoryId` est exigé par l'API et le canal ne l'expose pas ; le worker transmet
//! celui des arguments s'il est fourni (cf. docs/journal.md L07, besoin d'API remonté).
//! Le modèle de l'app (`'voice'`) est traduit en `'vocal'` (valeur du schéma de l'API).

use rsa::rand_core::{TryCryptoRng, TryRng};
use rsa::sha2::Sha256;
use rsa::{BoxedUint, Oaep, PublicKey};
use runtime_protocol::pipe::HttpMethod;
use serde_json::{Value, json};
use synco_e2ee::encoding::{b64, from_b64u};
use synco_e2ee::{OsRandom, RandomSource, SymmetricKey};

use super::{Outcome, ToolCtx, error};
use crate::api::PREFIX;

/// Salons créés au plus par appel.
pub const MAX_THREADS_PER_CALL: usize = 10;
/// Destinataires au plus (corps du canal ≤ 256 Kio, 04 §4.3).
pub const MAX_RECIPIENTS: usize = 300;

/// Aléa du système pour `rsa` (adaptateur de [`OsRandom`]).
#[derive(Debug, Default)]
pub struct SysRng;

impl TryRng for SysRng {
    type Error = synco_e2ee::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        OsRandom.fill(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        OsRandom.fill(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        OsRandom.fill(dst)
    }
}

impl TryCryptoRng for SysRng {}

/// Clé publique RSA depuis un JWK (`{"kty":"RSA","n","e",…}`, chaîne JSON ou objet).
pub fn rsa_public_from_jwk(jwk: &Value) -> Option<PublicKey> {
    let parsed;
    let jwk = match jwk {
        Value::String(s) => {
            parsed = serde_json::from_str::<Value>(s).ok()?;
            &parsed
        }
        other => other,
    };
    if jwk.get("kty").and_then(Value::as_str) != Some("RSA") {
        return None;
    }
    let n = from_b64u(jwk.get("n")?.as_str()?).ok()?;
    let e = from_b64u(jwk.get("e")?.as_str()?).ok()?;
    PublicKey::new(BoxedUint::from_be_slice_vartime(&n), BoxedUint::from_be_slice_vartime(&e)).ok()
}

/// `encryptThreadKeyForMember` : RSA-OAEP-SHA256 de la clé brute, `b64`.
pub fn seal_for_member(public: &PublicKey, key: &SymmetricKey) -> Option<String> {
    public.encrypt(&mut SysRng, Oaep::<Sha256>::new(), key.as_bytes()).ok().map(|c| b64(&c))
}

fn unknown_with(created: Vec<Value>) -> Outcome {
    if created.is_empty() {
        return super::unknown_outcome();
    }
    Outcome::Failed(json!({ "error": "unknown_outcome", "note": super::UNKNOWN_OUTCOME_NOTE, "threads": created }))
}

fn api_failure(r: &crate::api::ApiResponse) -> Outcome {
    match r.code() {
        Some("lease_conflict") => Outcome::LeaseLost,
        Some(c) => error(c),
        None => error("tool_failed"),
    }
}

/// Exécute l'outil.
pub async fn run(ctx: &ToolCtx<'_>, args: &Value) -> Outcome {
    let Some(list) = args.get("threads").and_then(Value::as_array).filter(|l| !l.is_empty()) else {
        return error("invalid_arguments");
    };
    if list.len() > MAX_THREADS_PER_CALL {
        return error("too_many_threads");
    }
    let Ok(members) = ctx.api.call(HttpMethod::Get, &format!("{PREFIX}/e2ee/members/keys"), None).await else {
        return error("tool_failed");
    };
    if !members.ok() {
        return api_failure(&members);
    }
    let members: Vec<(String, PublicKey)> = members
        .body
        .get("members")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|m| {
            let id = m.get("userId")?.as_str()?;
            runtime_protocol::ids::is_identifier(id).then_some(())?;
            Some((id.to_owned(), rsa_public_from_jwk(m.get("publicKey")?)?))
        })
        .take(MAX_RECIPIENTS)
        .collect();
    let mut created = Vec::new();
    for t in list {
        let name = t.get("name").and_then(Value::as_str).unwrap_or_default();
        if name.is_empty() || name.chars().count() > 255 {
            return error("invalid_arguments");
        }
        let kind = match t.get("type").and_then(Value::as_str) {
            Some("voice" | "vocal") => "vocal",
            _ => "text",
        };
        let space = t.get("spaceId").and_then(Value::as_str).filter(|s| !s.is_empty() && *s != "home");
        if space.is_some_and(|s| !runtime_protocol::ids::is_identifier(s)) {
            return error("invalid_arguments");
        }
        let Ok(key) = SymmetricKey::generate(&mut OsRandom) else { return error("tool_failed") };
        let recipients: Vec<&(String, PublicKey)> =
            members.iter().filter(|(id, _)| space.is_none() || id == ctx.user_id).collect();
        let mut keys = Vec::new();
        for (id, public) in recipients {
            match seal_for_member(public, &key) {
                Some(enc) => keys.push(json!({ "userId": id, "encryptedKey": enc })),
                None => continue,
            }
        }
        if keys.is_empty() {
            return error("no_recipient_key");
        }
        let mut body = json!({ "name": name, "type": kind, "index": 0, "keys": keys, "leaseEpoch": ctx.lease_epoch });
        if let Some(s) = space {
            crate::json_set(&mut body, "spaceId", json!(s));
        }
        if let Some(c) = t.get("categoryId").and_then(Value::as_str).filter(|c| runtime_protocol::ids::is_identifier(c))
        {
            crate::json_set(&mut body, "categoryId", json!(c));
        }
        let r = match super::sent(ctx.api.call(HttpMethod::Post, &format!("{PREFIX}/e2ee/threads"), Some(&body)).await)
        {
            super::Sent::Answered(r) => r,
            super::Sent::LocallyRefused if created.is_empty() => return error("tool_failed"),
            super::Sent::LocallyRefused => {
                return Outcome::Failed(json!({ "error": "tool_failed", "threads": created }));
            }
            // Le salon a pu être créé : issue inconnue (08 §5), jamais « échec ».
            super::Sent::Unknown => {
                return unknown_with(created);
            }
        };
        if !r.ok() {
            // Salons déjà créés dans cet appel : rendus avec l'erreur.
            return if created.is_empty() {
                api_failure(&r)
            } else {
                Outcome::Failed(json!({ "error": r.code().unwrap_or("tool_failed"), "threads": created }))
            };
        }
        let Some(thread_id) =
            r.body.get("id").and_then(Value::as_str).filter(|i| runtime_protocol::ids::is_identifier(i))
        else {
            // Créé (2xx) mais sans identifiant lisible : issue inconnue.
            return unknown_with(created);
        };
        let thread_id = thread_id.to_owned();
        let warning = register_key(ctx, &thread_id, &key).await;
        if matches!(warning, Some("lease_conflict")) {
            return Outcome::LeaseLost;
        }
        ctx.api.link().with_keys(|k| k.insert_thread(&thread_id, 1, key));
        let mut out = json!({
            "id": thread_id,
            "name": r.body.get("name").cloned().unwrap_or_else(|| json!(name)),
            "type": r.body.get("type").cloned().unwrap_or_else(|| json!(kind)),
        });
        if let Some(s) = space {
            crate::json_set(&mut out, "workspaceId", json!(s));
        }
        if let Some(w) = warning {
            crate::json_set(&mut out, "warning", json!(w));
        }
        created.push(out);
    }
    Outcome::Done(json!({ "threads": created }))
}

/// Étapes 4 à 6 ; rend un code d'avertissement si l'enveloppe ou l'entrée n'a pas pu être posée
/// (le salon existe et reste accepté en TOFU par les clients, 03 §10.1).
async fn register_key(ctx: &ToolCtx<'_>, thread_id: &str, key: &SymmetricKey) -> Option<&'static str> {
    let Ok(created) = ctx.api.link().created_key(thread_id, key).await else { return Some("key_envelope_unavailable") };
    let Some(env) = created.envelope else { return Some("key_envelope_unavailable") };
    let envelope = json!({
        "leaseEpoch": ctx.lease_epoch, "ctx": synco_e2ee::keys::thread_context(thread_id), "version": 1,
        "commitment": env.commitment, "signature": env.signature,
    });
    let mut warning = None;
    match ctx
        .api
        .call(HttpMethod::Post, &format!("{PREFIX}/e2ee/threads/{thread_id}/key-envelope"), Some(&envelope))
        .await
    {
        Ok(r) if r.ok() => {}
        Ok(r) if r.code() == Some("lease_conflict") => return Some("lease_conflict"),
        _ => warning = Some("key_envelope_not_posted"),
    }
    let entries =
        json!({ "entries": [{ "kind": "thread", "ref": thread_id, "version": 1, "ciphertext": env.ciphertext }] });
    match ctx
        .api
        .call(HttpMethod::Post, &format!("{PREFIX}/delegations/{}/entries", env.delegation_id), Some(&entries))
        .await
    {
        Ok(r) if r.ok() => warning,
        _ => Some(warning.unwrap_or("delegation_entry_not_posted")),
    }
}
