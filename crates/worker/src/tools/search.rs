//! `search_messages` dans le worker : **repli lexical** (00 §6 Q6).
//!
//! L'app cherche par vecteurs avec un modèle d'embedding exécuté dans le navigateur
//! (`Xenova/paraphrase-multilingual-MiniLM-L12-v2`). Le worker ne peut pas l'exécuter : pas de
//! fichier (racine vide), pas de réseau pour le télécharger, ~120 Mio de poids contre 512 Mio de
//! mémoire par worker et aucun moteur ONNX dans le runtime. Il lit donc les mêmes index chiffrés
//! (`GET /e2ee/search-index/workspace/:workspaceId`, 04 §4.3), les déchiffre avec les clés de salon
//! déléguées (AES-GCM, IV à part, sans AAD : `SearchSyncService.restoreWorkspaceIndexes`) et classe
//! les documents par recouvrement de termes avec la requête. Le résultat a la forme de celui de
//! l'app (`toLlmSearchHit`, `OrgAI.vue`), avec `mode: "lexical"`.
//!
//! Argument facultatif `spaceId` (absent du schéma de l'API à ce jour, cf. docs/journal.md L07) :
//! limite la recherche à cet espace ; si sa clé manque, l'outil demande la clé (`awaiting_key`).

use std::collections::BTreeSet;

use runtime_protocol::pipe::HttpMethod;
use serde_json::{Map, Value, json};
use synco_e2ee::encoding::from_b64;
use synco_e2ee::primitives;

use super::{Outcome, ToolCtx, error};

/// Résultats rendus au modèle (comme l'app).
pub const MAX_RESULTS: usize = 5;
/// Extrait maximal par résultat (`SEARCH_HIT_MAX_CHARS` de l'app).
pub const MAX_EXCERPT_CHARS: usize = 1000;
/// Espaces parcourus au plus.
pub const MAX_SPACES: usize = 20;
/// Octets déchiffrés au plus pour une recherche.
pub const MAX_DECRYPTED_BYTES: usize = 32 * 1024 * 1024;
const METADATA_KEYS: [&str; 7] =
    ["threadId", "senderName", "createdAt", "originalName", "folderId", "status", "dueDate"];

/// Minuscules sans accents courants.
#[must_use]
pub fn fold(s: &str) -> String {
    s.chars()
        .flat_map(char::to_lowercase)
        .map(|c| match c {
            'à' | 'â' | 'ä' | 'á' | 'ã' => 'a',
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'î' | 'ï' | 'í' | 'ì' => 'i',
            'ô' | 'ö' | 'ó' | 'ò' | 'õ' => 'o',
            'û' | 'ü' | 'ú' | 'ù' => 'u',
            'ç' => 'c',
            'ÿ' => 'y',
            'ñ' => 'n',
            other => other,
        })
        .collect()
}

/// Termes d'une requête (≥ 2 caractères).
#[must_use]
pub fn terms(query: &str) -> BTreeSet<String> {
    fold(query).split(|c: char| !c.is_alphanumeric()).filter(|t| t.chars().count() >= 2).map(str::to_owned).collect()
}

/// Score lexical : termes trouvés, plus un bonus si la phrase entière apparaît.
#[must_use]
pub fn score(terms: &BTreeSet<String>, phrase: &str, text: &str) -> u64 {
    let folded = fold(text);
    let found = terms.iter().filter(|t| folded.contains(t.as_str())).count();
    let mut s = u64::try_from(found).unwrap_or(0).saturating_mul(10);
    let p = fold(phrase.trim());
    if found > 0 && p.chars().count() >= 4 && folded.contains(&p) {
        s = s.saturating_add(25);
    }
    s
}

fn excerpt(text: &str) -> String {
    if text.chars().count() > MAX_EXCERPT_CHARS {
        let mut e: String = text.chars().take(MAX_EXCERPT_CHARS).collect();
        e.push_str("…[tronqué]");
        e
    } else {
        text.to_owned()
    }
}

/// Exécute la recherche.
pub async fn run(ctx: &ToolCtx<'_>, args: &Value) -> Outcome {
    let Some(query) = args.get("query").and_then(Value::as_str).filter(|q| !q.trim().is_empty()) else {
        return error("invalid_arguments");
    };
    let wanted = terms(query);
    if wanted.is_empty() {
        return Outcome::Done(json!({ "query": query, "results": [], "mode": "lexical" }));
    }
    let link = ctx.api.link();
    let spaces: Vec<String> = match args.get("spaceId").and_then(Value::as_str) {
        Some(id) => {
            if !runtime_protocol::ids::is_identifier(id) {
                return error("invalid_arguments");
            }
            if link.with_keys(|k| k.space(id).is_none()) {
                return Outcome::NeedKey { kind: "space", reference: id.to_owned() };
            }
            vec![id.to_owned()]
        }
        None => link.with_keys(|k| k.space_ids()),
    };
    let mut hits: Vec<(u64, Value)> = Vec::new();
    let mut skipped_threads = 0u64;
    let mut skipped_spaces = 0u64;
    let mut budget = MAX_DECRYPTED_BYTES;
    for space in spaces.iter().take(MAX_SPACES) {
        let Ok(r) = ctx
            .api
            .call(HttpMethod::Get, &format!("{}/e2ee/search-index/workspace/{space}", crate::api::PREFIX), None)
            .await
        else {
            return error("tool_failed");
        };
        if !r.ok() {
            skipped_spaces = skipped_spaces.saturating_add(1);
            continue;
        }
        for idx in r.body.get("indexes").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default() {
            let Some(thread) = idx.get("threadId").and_then(Value::as_str) else { continue };
            let Some(key) = link.with_keys(|k| k.thread(thread)) else {
                skipped_threads = skipped_threads.saturating_add(1);
                continue;
            };
            let (Some(iv), Some(blob)) = (
                idx.get("iv").and_then(Value::as_str).and_then(|s| from_b64(s).ok()),
                idx.get("encryptedBlob").and_then(Value::as_str).and_then(|s| from_b64(s).ok()),
            ) else {
                continue;
            };
            if blob.len() > budget {
                break;
            }
            budget = budget.saturating_sub(blob.len());
            let mut joined = iv;
            joined.extend_from_slice(&blob);
            let Some(plain) = primitives::open(key.as_bytes(), b"", &joined) else { continue };
            let Ok(doc) = serde_json::from_slice::<Value>(&plain) else { continue };
            let text = doc.get("textContent").and_then(Value::as_str).unwrap_or_default();
            let s = score(&wanted, query, text);
            if s == 0 {
                continue;
            }
            let mut hit = Map::new();
            hit.insert("id".into(), idx.get("resourceId").cloned().unwrap_or(Value::Null));
            hit.insert("type".into(), idx.get("type").cloned().unwrap_or(Value::Null));
            hit.insert("spaceId".into(), idx.get("workspaceId").cloned().unwrap_or(Value::Null));
            hit.insert("excerpt".into(), Value::String(excerpt(text)));
            hit.insert("threadId".into(), Value::String(thread.to_owned()));
            if let Some(meta) = doc.get("metadata").and_then(Value::as_object) {
                for k in METADATA_KEYS {
                    if let Some(v) = meta.get(k).filter(|v| !v.is_null()) {
                        hit.insert(k.into(), v.clone());
                    }
                }
            }
            hits.push((s, Value::Object(hit)));
        }
    }
    hits.sort_by_key(|h| core::cmp::Reverse(h.0));
    let results: Vec<Value> = hits.into_iter().take(MAX_RESULTS).map(|(_, h)| h).collect();
    Outcome::Done(json!({
        "query": query,
        "results": results,
        "mode": "lexical",
        "note": "Recherche par mots-clés (la recherche sémantique n'est pas disponible sur le runtime) : reformule avec d'autres mots si rien ne correspond.",
        "skippedThreads": skipped_threads,
        "skippedSpaces": skipped_spaces,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classement() {
        let t = terms("Mot de passe Wi-Fi");
        assert!(t.contains("passe") && t.contains("wi") && t.contains("fi") && t.contains("de"));
        assert!(score(&t, "mot de passe wi-fi", "Le MOT de PASSE du wi-fi est…") > score(&t, "x", "passe"));
        assert_eq!(score(&terms("réunion"), "réunion", "La reunion de lundi"), 35);
        assert_eq!(score(&terms("zzz"), "zzz", "rien"), 0);
        assert_eq!(excerpt(&"é".repeat(1001)).chars().count(), 1000 + "…[tronqué]".chars().count());
    }
}
