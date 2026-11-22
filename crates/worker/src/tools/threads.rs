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
//! **Épinglage des clés RSA (Q25)** : le superviseur, qui relaie `GET /e2ee/members/keys`, compare
//! chaque clé à son épinglage TOFU persistant avant que le worker voie la réponse ; une clé changée
//! sans chaîne d'identité valide remplace la réponse entière par `409 member_key_changed` : refus
//! global, rien n'est scellé (`crates/supervisor/src/member_pins.rs`, 06 §4.3).
//!
//! **Destinataires** (Q23) : à l'accueil de l'org, tous les membres (`GET /e2ee/members/keys`) ;
//! dans un espace, ses membres (`GET /e2ee/members/keys?spaceId=`, même service que l'app). Les deux
//! réponses passent par le contrôle d'épinglage du superviseur avant d'arriver ici. Les annuaires
//! sont lus avant toute création.
//! **Catégorie** : `categoryId` est facultatif ; absent, l'API prend la première catégorie visible
//! de la cible, ou répond `409 no_default_category` (traduit en erreur claire pour l'agent).
//! Le modèle de l'app (`'voice'`) est traduit en `'vocal'` (valeur du schéma de l'API).

use std::collections::BTreeMap;

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
/// Annuaire refusé par le superviseur : clé d'un membre changée sans preuve (Q25, 06 §4.3).
pub const MEMBER_KEY_CHANGED: &str = "member_key_changed";
/// Taille minimale d'une clé RSA de membre.
pub const MIN_RSA_BITS: usize = 2048;

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
    // Clé de moins de 2048 bits refusée (l'app génère du 4096) ; 8192 au plus.
    PublicKey::new_with_size_limits(
        BoxedUint::from_be_slice_vartime(&n),
        BoxedUint::from_be_slice_vartime(&e),
        MIN_RSA_BITS..=PublicKey::MAX_SIZE,
    )
    .ok()
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

/// Code de l'API traduit en erreur claire pour l'agent (Q23).
pub const NO_DEFAULT_CATEGORY: &str = "no_default_category";

fn code_note(code: &str) -> Option<&'static str> {
    (code == NO_DEFAULT_CATEGORY).then_some(
        "Aucune catégorie visible dans cette cible pour y placer le salon : l'organisation ou l'espace n'a pas de catégorie accessible à l'utilisateur. Aucun salon n'a été créé pour cette entrée ; demande à l'utilisateur d'en créer une ou d'indiquer un categoryId.",
    )
}

fn failure(code: &str, threads: Option<&[Value]>) -> Value {
    let mut v = json!({ "error": code });
    if let Some(note) = code_note(code) {
        crate::json_set(&mut v, "note", json!(note));
    }
    if let Some(t) = threads {
        crate::json_set(&mut v, "threads", json!(t));
    }
    v
}

fn api_failure(r: &crate::api::ApiResponse) -> Outcome {
    match r.code() {
        Some("lease_conflict") => Outcome::LeaseLost,
        Some(c) => Outcome::Failed(failure(c, None)),
        None => error("tool_failed"),
    }
}

/// Membres à la clé lisible, et nombre d'écartés.
type Directory = (Vec<(String, PublicKey)>, usize);

/// Annuaire des destinataires possibles d'une cible : membres de l'org (accueil) ou de l'espace
/// (`?spaceId=`, Q23). Réponse déjà passée par le contrôle d'épinglage du superviseur
/// (`member_keys_gate`) : le worker ne lit jamais d'annuaire d'une autre route. Rend les membres
/// dont la clé est lisible et le nombre d'écartés ; une erreur est rendue telle quelle au modèle.
async fn directory(ctx: &ToolCtx<'_>, space: Option<&str>) -> Result<Directory, Outcome> {
    let path = match space {
        Some(s) => format!("{PREFIX}/e2ee/members/keys?spaceId={s}"),
        None => format!("{PREFIX}/e2ee/members/keys"),
    };
    let Ok(members) = ctx.api.call(HttpMethod::Get, &path, None).await else {
        return Err(error("tool_failed"));
    };
    if !members.ok() {
        if members.code() == Some(MEMBER_KEY_CHANGED) {
            // Q25 : le superviseur a refusé l'annuaire (clé d'un membre changée sans preuve) ; rien
            // n'est scellé, aucun salon n'est créé.
            return Err(Outcome::Failed(json!({ "error": MEMBER_KEY_CHANGED,
                "note": "La clé de chiffrement d'un membre a changé sans preuve : aucun salon n'a été créé. L'administrateur du runtime doit vérifier cette clé (tableau de bord) avant de réessayer." })));
        }
        return Err(api_failure(&members));
    }
    let list = members.body.get("members").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    let usable: Vec<(String, PublicKey)> = list
        .iter()
        .filter_map(|m| {
            let id = m.get("userId")?.as_str()?;
            runtime_protocol::ids::is_identifier(id).then_some(())?;
            Some((id.to_owned(), rsa_public_from_jwk(m.get("publicKey")?)?))
        })
        .collect();
    // Membres écartés (clé illisible ou trop courte) : signalés au modèle, jamais en silence.
    let skipped = list.len().saturating_sub(usable.len());
    Ok((usable, skipped))
}

/// Salon demandé, arguments validés.
struct Wanted<'a> {
    name: &'a str,
    kind: &'static str,
    space: Option<&'a str>,
    category: Option<&'a str>,
}

/// Exécute l'outil.
pub async fn run(ctx: &ToolCtx<'_>, args: &Value) -> Outcome {
    let Some(list) = args.get("threads").and_then(Value::as_array).filter(|l| !l.is_empty()) else {
        return error("invalid_arguments");
    };
    if list.len() > MAX_THREADS_PER_CALL {
        return error("too_many_threads");
    }
    // Arguments validés d'abord, puis annuaires lus **avant** toute création : un refus d'annuaire
    // n'a donc jamais créé de salon.
    let mut wanted = Vec::new();
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
        // `categoryId` est facultatif (Q23) : absent, l'API choisit la première catégorie visible.
        let category = t.get("categoryId").and_then(Value::as_str).filter(|c| runtime_protocol::ids::is_identifier(c));
        wanted.push(Wanted { name, kind, space, category });
    }
    let mut directories: BTreeMap<Option<&str>, Directory> = BTreeMap::new();
    for w in &wanted {
        if let std::collections::btree_map::Entry::Vacant(slot) = directories.entry(w.space) {
            match directory(ctx, w.space).await {
                Ok(d) => {
                    slot.insert(d);
                }
                Err(outcome) => return outcome,
            }
        }
    }
    let mut skipped = 0usize;
    let mut created = Vec::new();
    for w in &wanted {
        let Wanted { name, kind, space, category } = *w;
        let Some((members, skipped_here)) = directories.get(&space) else { return error("tool_failed") };
        skipped = skipped.saturating_add(*skipped_here);
        let Ok(key) = SymmetricKey::generate(&mut OsRandom) else { return error("tool_failed") };
        // Accueil : tous les membres de l'org ; espace : ses membres (l'API ne rend que ceux-là).
        let recipients: Vec<&(String, PublicKey)> = members.iter().collect();
        if recipients.len() > MAX_RECIPIENTS {
            // Corps du canal ≤ 256 Kio (04 §4.3) : erreur explicite plutôt qu'un écartement.
            return Outcome::Failed(
                json!({ "error": "too_many_recipients", "max": MAX_RECIPIENTS, "threads": created }),
            );
        }
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
        if let Some(c) = category {
            crate::json_set(&mut body, "categoryId", json!(c));
        }
        if let Some((plan_id, n)) = ctx.plan {
            // Verrou du plan (12 §8.4) : l'action doit être acceptée et prête.
            crate::json_set(&mut body, "plan", json!({ "planId": plan_id, "n": n }));
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
                Outcome::Failed(failure(r.code().unwrap_or("tool_failed"), Some(&created)))
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
    if skipped > 0 {
        return Outcome::Done(json!({ "threads": created, "skippedRecipients": skipped,
            "note": "Des membres n'ont pas reçu la clé (clé publique absente, illisible ou trop courte) : ils devront la recevoir depuis Synco." }));
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
