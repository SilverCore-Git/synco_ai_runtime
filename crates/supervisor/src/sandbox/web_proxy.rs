//! Proxy `web` du superviseur (docs/plan/10 §4.2, catalogue L14 §8 ; PC90 à PC93) : seule sortie web d'un
//! worker, sur le modèle du mandataire LLM ([`super::proxy`]).
//!
//! Un socket `<run_dir>/w-<n>-<pid>/web.sock` (`0600`) par worker, monté avec `llm.sock` sous `/run/synco/`,
//! **seulement** si le bail a rendu `webAllowed` et si `[web.search]` est valide. Le worker y parle
//! HTTP/1.1 clair ; deux requêtes seulement :
//!
//! - `POST /search` `{ query, freshness?, lang?, count? }` (strict) → service de recherche **configuré**
//!   (hôte fixe, clé injectée ici, jamais dans le pipe) → `{ results: [{ title, url, snippet, age? }] }`
//!   normalisés, 10 au plus, 8 Kio au plus ;
//! - `POST /fetch` `{ url, maxBytes? }` (strict) → contrôle SSRF ([`check_url`], [`addrs_allowed`]),
//!   adresse résolue **épinglée** pour la connexion (anti-rebinding), 5 redirections recontrôlées,
//!   `GET` avec `User-Agent: SyncoAI-Fetch/1`, `Accept` texte, `Accept-Encoding: identity`, sans cookie
//!   ni `Authorization` / `Referer` / `Origin` ; types texte seulement, corps compressé refusé (rien
//!   n'est décompressé), 2 Mio au plus ; octets bruts rendus avec `content-type` et `x-synco-final-url`.
//!
//! Le superviseur ne fait que borner et relayer : la conversion HTML → texte, la garde de fuite et la
//! provenance sont dans le worker (10 §4.4). Quotas par fenêtre de `maxTurnDurationSecs`, par worker et
//! par heure pour le runtime ; 2 connexions par worker, 8 pour le runtime. Une révocation
//! (`feature.revoked`) ferme le socket et coupe les requêtes en cours (`web_unavailable`).
//!
//! Journaux et métriques : aucun corps, aucune requête, aucune URL ; codes et comptes seulement (P9).

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use http_body_util::BodyExt as _;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use zeroize::Zeroizing;

use crate::launcher::BoxFuture;

/// Nom du socket, à côté de `llm.sock`.
pub const WEB_SOCKET_NAME: &str = "web.sock";
/// Corps de requête du worker (4 Kio).
pub const MAX_REQUEST_BYTES: usize = 4 * 1024;
/// Délai de lecture d'un corps de requête.
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Connexions par worker.
pub const CONNECTIONS_PER_WORKER: usize = 2;
/// Connexions pour tout le runtime.
pub const CONNECTIONS_PER_RUNTIME: usize = 8;
/// Octets lus d'une page au plus (2 Mio).
pub const MAX_FETCH_BYTES: usize = 2 * 1024 * 1024;
/// `maxBytes` minimal.
const MIN_FETCH_BYTES: usize = 1024;
/// Redirections suivies au plus.
pub const MAX_REDIRECTS: usize = 5;
/// Connexion d'une lecture.
pub const FETCH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Durée totale d'une lecture (redirections comprises).
pub const FETCH_TOTAL_TIMEOUT: Duration = Duration::from_secs(20);
/// Durée totale d'une recherche.
pub const SEARCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Réponse d'un service de recherche lue au plus.
const SEARCH_RESPONSE_MAX: usize = 1024 * 1024;
/// Résultats normalisés au plus (octets du JSON rendu).
pub const SEARCH_RESULTS_MAX_BYTES: usize = 8 * 1024;
/// `User-Agent` des lectures.
pub const FETCH_USER_AGENT: &str = "SyncoAI-Fetch/1";
/// `Accept` des lectures.
pub const FETCH_ACCEPT: &str = "text/html, text/plain, text/markdown, application/json, application/xml";
/// Types admis.
pub const ALLOWED_TYPES: [&str; 5] =
    ["text/html", "text/plain", "text/markdown", "application/json", "application/xml"];
/// Noms refusés (suffixes compris).
const PRIVATE_SUFFIXES: [&str; 6] = ["localhost", "local", "internal", "lan", "home.arpa", "localdomain"];

// ---------------------------------------------------------------------------
// Configuration (`[web]` du fichier du runtime ; aucune valeur ne vient de l'API ni du pipe)
// ---------------------------------------------------------------------------

/// Section `[web]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSettings {
    /// Service de recherche ; absent : aucun outil web.
    #[serde(default)]
    pub search: Option<WebSearchSettings>,
    /// Lecture de pages.
    #[serde(default)]
    pub fetch: WebFetchSettings,
    /// Noms refusés par `web_fetch`, en plus de ceux déduits de la configuration (API, URL publique,
    /// passerelle) : CDN, keyguard…
    #[serde(default)]
    pub synco_hosts: Vec<String>,
    /// Quotas (09 §4.2).
    #[serde(default)]
    pub quotas: WebQuotas,
}

/// `[web.search]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSearchSettings {
    /// `staan` (défaut recommandé, PC91), `mojeek` (repli), `searxng` (auto-hébergé), `brave`.
    pub provider: String,
    /// URL de base du service (`https`, port 443, nom public, sans identifiants ni requête).
    pub base_url: String,
    /// Fichier de la clé (comme `llm.providers.*`).
    pub api_key_file: Option<PathBuf>,
    /// Variable d'environnement de la clé.
    pub api_key_env: Option<String>,
    /// `searxng` seulement : instance sur le réseau de l'org (adresse privée, `http` admis).
    #[serde(default)]
    pub allow_private_host: bool,
}

/// `[web.fetch]`.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebFetchSettings {
    /// `false` retire `web_fetch` seul.
    #[serde(default = "yes")]
    pub enabled: bool,
}

const fn yes() -> bool {
    true
}

impl Default for WebFetchSettings {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Quotas du proxy (09 §4.2), réglables.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct WebQuotas {
    /// Recherches par fenêtre de `maxTurnDurationSecs` et par worker.
    pub search_per_window: u32,
    /// Recherches par worker.
    pub search_per_worker: u32,
    /// Recherches par heure, tout le runtime.
    pub search_per_hour: u32,
    /// Lectures par fenêtre et par worker.
    pub fetch_per_window: u32,
    /// Lectures par worker.
    pub fetch_per_worker: u32,
    /// Lectures par heure, tout le runtime.
    pub fetch_per_hour: u32,
}

impl Default for WebQuotas {
    fn default() -> Self {
        Self {
            search_per_window: 10,
            search_per_worker: 50,
            search_per_hour: 200,
            fetch_per_window: 20,
            fetch_per_worker: 100,
            fetch_per_hour: 500,
        }
    }
}

/// Services de recherche connus (un adaptateur chacun, [`SearchProvider`]).
pub const SEARCH_PROVIDERS: [&str; 4] = ["staan", "mojeek", "searxng", "brave"];

/// Service de recherche.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchProvider {
    /// Staan (EUSP : Qwant + Ecosia), `GET <base>/search/web`, `Authorization: Bearer`.
    Staan,
    /// Mojeek, `GET <base>/search?fmt=json&api_key=`.
    Mojeek,
    /// SearXNG auto-hébergé, `GET <base>/search?format=json`.
    Searxng,
    /// Brave Search API, `GET <base>/res/v1/web/search`, `X-Subscription-Token`.
    Brave,
}

impl SearchProvider {
    /// Depuis la configuration.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "staan" => Some(Self::Staan),
            "mojeek" => Some(Self::Mojeek),
            "searxng" => Some(Self::Searxng),
            "brave" => Some(Self::Brave),
            _ => None,
        }
    }

    /// Identifiant déclaré à l'API (`PUT /web-provider`).
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Staan => "staan",
            Self::Mojeek => "mojeek",
            Self::Searxng => "searxng",
            Self::Brave => "brave",
        }
    }

    const fn needs_key(self) -> bool {
        !matches!(self, Self::Searxng)
    }
}

/// Nom d'hôte refusé d'office : `localhost`, `.local`, `.internal`, `.lan`, `.home.arpa`, sans point.
#[must_use]
pub fn private_name(host: &str) -> bool {
    let d = host.trim_end_matches('.').to_ascii_lowercase();
    !d.contains('.') || PRIVATE_SUFFIXES.iter().any(|s| d == *s || d.ends_with(&format!(".{s}")))
}

/// URL de base d'un service de recherche (10 §4.2) : `https`, port 443, nom public, sans identifiants,
/// requête ni fragment ; `searxng` avec `allow_private_host` : `http(s)` vers tout hôte.
#[must_use]
pub fn search_base_allowed(provider: SearchProvider, url: &str, allow_private: bool) -> bool {
    let Ok(u) = reqwest::Url::parse(url) else { return false };
    let clean = u.username().is_empty() && u.password().is_none() && u.query().is_none() && u.fragment().is_none();
    if provider == SearchProvider::Searxng && allow_private {
        return clean && matches!(u.scheme(), "http" | "https") && u.host_str().is_some();
    }
    let public = match u.host() {
        Some(url::Host::Domain(d)) => !private_name(d),
        Some(url::Host::Ipv4(ip)) => !ip_refused(IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => !ip_refused(IpAddr::V6(ip)),
        None => false,
    };
    clean && public && u.scheme() == "https" && u.port().is_none_or(|p| p == 443)
}

/// Contrôles de la section `[web]` (appelés par `Config::validate`) ; `Err` = message.
pub fn validate_settings(w: &WebSettings) -> Result<(), String> {
    if let Some(s) = &w.search {
        let Some(p) = SearchProvider::parse(&s.provider) else {
            return Err(format!("web.search.provider : {} attendu", SEARCH_PROVIDERS.join(", ")));
        };
        if s.allow_private_host && p != SearchProvider::Searxng {
            return Err("web.search.allow_private_host : réservé à provider = \"searxng\"".to_owned());
        }
        if !search_base_allowed(p, &s.base_url, s.allow_private_host) {
            return Err("web.search.base_url : https (port 443), nom public, sans identifiants ni requête".to_owned());
        }
        if s.api_key_file.is_some() && s.api_key_env.is_some() {
            return Err("web.search : api_key_file OU api_key_env".to_owned());
        }
        if p.needs_key() && s.api_key_file.is_none() && s.api_key_env.is_none() {
            return Err(format!("web.search : clé obligatoire pour {}", p.id()));
        }
    }
    if w.synco_hosts.iter().any(|h| h.is_empty() || h.len() > 253 || h.contains(['/', ':', ' ', '@'])) {
        return Err("web.synco_hosts : noms d'hôte simples".to_owned());
    }
    let q = w.quotas;
    let all = [
        q.search_per_window,
        q.search_per_worker,
        q.search_per_hour,
        q.fetch_per_window,
        q.fetch_per_worker,
        q.fetch_per_hour,
    ];
    if all.iter().any(|&v| v == 0 || v > 100_000) {
        return Err("web.quotas : de 1 à 100 000".to_owned());
    }
    Ok(())
}

/// Service de recherche prêt (clé lue).
pub struct SearchService {
    /// Adaptateur.
    pub provider: SearchProvider,
    /// URL de base (sans barre finale).
    pub base_url: String,
    /// Clé (jamais journalisée).
    pub key: Option<Zeroizing<Vec<u8>>>,
    /// Instance privée admise (`searxng`).
    pub allow_private_host: bool,
}

impl core::fmt::Debug for SearchService {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SearchService").field("provider", &self.provider).finish_non_exhaustive()
    }
}

impl SearchService {
    /// Lit la clé de `s` (fichier ou variable), après [`validate_settings`].
    pub fn from_settings(s: &WebSearchSettings) -> Result<Self, String> {
        let provider = SearchProvider::parse(&s.provider).ok_or("web.search.provider inconnu")?;
        let raw = if let Some(path) = &s.api_key_file {
            Some(Zeroizing::new(
                std::fs::read(path).map_err(|e| format!("web.search.api_key_file illisible : {}", e.kind()))?,
            ))
        } else if let Some(var) = &s.api_key_env {
            Some(Zeroizing::new(
                std::env::var(var).map_err(|_| format!("web.search : variable {var} absente"))?.into_bytes(),
            ))
        } else {
            None
        };
        let key = match raw {
            Some(mut k) => {
                while k.last().is_some_and(u8::is_ascii_whitespace) {
                    k.pop();
                }
                if k.is_empty() || k.len() > 4096 || k.iter().any(|b| !b.is_ascii_graphic()) {
                    return Err("web.search : clé vide, trop longue ou non imprimable".to_owned());
                }
                Some(k)
            }
            None => None,
        };
        Ok(Self {
            provider,
            base_url: s.base_url.trim_end_matches('/').to_owned(),
            key,
            allow_private_host: s.allow_private_host,
        })
    }
}

// ---------------------------------------------------------------------------
// SSRF
// ---------------------------------------------------------------------------

/// Adresse refusée pour une lecture : non publique ([`super::proxy::ip_is_private`]) et, en plus, plages
/// qui portent ou désignent une adresse IPv4 (NAT64, 6to4, Teredo, IPv4 compatible), site-local, rejet,
/// métadonnées de nuage.
#[must_use]
pub fn ip_refused(ip: IpAddr) -> bool {
    if super::proxy::ip_is_private(ip) {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            // 192.0.0.0/24 (affectations du protocole IETF), 192.88.99.0/24 (relais 6to4 anycast, déprécié) ;
            // 169.254.169.254 est déjà en lien local.
            (a == 192 && b == 0 && c == 0) || (a == 192 && b == 88 && c == 99)
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            let s0 = seg.first().copied().unwrap_or(0);
            let s1 = seg.get(1).copied().unwrap_or(0);
            let embedded = |a: u16, b: u16| {
                let [x, y] = a.to_be_bytes();
                let [z, w] = b.to_be_bytes();
                ip_refused(IpAddr::V4(Ipv4Addr::new(x, y, z, w)))
            };
            let tail_v4 = embedded(seg.get(6).copied().unwrap_or(0), seg.get(7).copied().unwrap_or(0));
            v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)
                || (s0 & 0xffc0) == 0xfec0 // site-local
                || (s0 == 0x0064 && s1 == 0xff9b) // NAT64 (64:ff9b::/96 et /48 local)
                || s0 == 0x2002 // 6to4
                || (s0 == 0x2001 && s1 == 0) // Teredo
                || (s0 == 0x0100 && seg.get(1..4).is_some_and(|r| r.iter().all(|&x| x == 0))) // rejet 100::/64
                || (seg.get(..6).is_some_and(|r| r.iter().all(|&x| x == 0)) && tail_v4) // ::a.b.c.d
                // ::ffff:0:a.b.c.d (IPv4 traduite, SIIT) : refusée quelle que soit l'adresse IPv4 portée.
                || (seg.get(..4).is_some_and(|r| r.iter().all(|&x| x == 0)) && seg.get(4) == Some(&0xffff) && seg.get(5) == Some(&0))
        }
    }
}

/// Adresses IPv4 locales de `/proc/net/fib_trie` (entrées `/32 host LOCAL`).
#[must_use]
pub fn parse_fib_trie_local(text: &str) -> BTreeSet<IpAddr> {
    let mut out = BTreeSet::new();
    let mut last: Option<Ipv4Addr> = None;
    for line in text.lines() {
        let t = line.trim_start_matches([' ', '|', '+', '-']).trim();
        if line.contains("/32 host LOCAL") {
            if let Some(ip) = last {
                out.insert(IpAddr::V4(ip));
            }
        } else if let Ok(ip) = t.parse::<Ipv4Addr>() {
            last = Some(ip);
        }
    }
    out
}

/// Adresses IPv6 de `/proc/net/if_inet6` (premier champ : 32 chiffres hexadécimaux).
#[must_use]
pub fn parse_if_inet6(text: &str) -> BTreeSet<IpAddr> {
    text.lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|h| h.len() == 32)
        .filter_map(|h| u128::from_str_radix(h, 16).ok())
        .map(|v| IpAddr::V6(Ipv6Addr::from(v)))
        .collect()
}

/// Adresses de l'hôte : interfaces (`/proc`) et adresses source des routes par défaut (socket UDP
/// « connecté » sans envoi de paquet). Au mieux : une lecture impossible n'ajoute rien.
#[must_use]
pub fn host_local_ips() -> BTreeSet<IpAddr> {
    let mut out = BTreeSet::new();
    if let Ok(t) = std::fs::read_to_string("/proc/net/fib_trie") {
        out.extend(parse_fib_trie_local(&t));
    }
    if let Ok(t) = std::fs::read_to_string("/proc/net/if_inet6") {
        out.extend(parse_if_inet6(&t));
    }
    for (bind, probe) in [("0.0.0.0:0", "192.0.2.1:9"), ("[::]:0", "[2001:db8::1]:9")] {
        if let Ok(sock) = std::net::UdpSocket::bind(bind)
            && sock.connect(probe).is_ok()
            && let Ok(a) = sock.local_addr()
        {
            out.insert(a.ip());
        }
    }
    out
}

/// Toutes les adresses résolues doivent être publiques (une seule privée suffit à refuser).
#[must_use]
pub fn addrs_allowed(addrs: &[IpAddr]) -> bool {
    !addrs.is_empty() && addrs.iter().all(|a| !ip_refused(*a))
}

/// Raisons de refus d'une lecture (codes machine rendus au worker).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// `web_url_refused` (403).
    UrlRefused,
    /// `web_redirect_limit` (403).
    RedirectLimit,
    /// `web_too_large` (413).
    TooLarge,
    /// `web_unsupported_type` (415).
    UnsupportedType,
    /// `web_http_status` (502, statut du site).
    HttpStatus(u16),
    /// `web_timeout` (504).
    Timeout,
    /// `web_provider` (502) : site injoignable, réponse illisible.
    Unreachable,
}

impl FetchError {
    fn response(self) -> Response {
        match self {
            Self::UrlRefused => refuse(StatusCode::FORBIDDEN, "web_url_refused"),
            Self::RedirectLimit => refuse(StatusCode::FORBIDDEN, "web_redirect_limit"),
            Self::TooLarge => refuse(StatusCode::PAYLOAD_TOO_LARGE, "web_too_large"),
            Self::UnsupportedType => refuse(StatusCode::UNSUPPORTED_MEDIA_TYPE, "web_unsupported_type"),
            Self::HttpStatus(s) => (
                StatusCode::BAD_GATEWAY,
                [(header::CONTENT_TYPE, "application/json")],
                json!({ "error": "web_http_status", "status": s }).to_string(),
            )
                .into_response(),
            Self::Timeout => refuse(StatusCode::GATEWAY_TIMEOUT, "web_timeout"),
            Self::Unreachable => refuse(StatusCode::BAD_GATEWAY, "web_provider"),
        }
    }

    /// Code machine.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UrlRefused => "web_url_refused",
            Self::RedirectLimit => "web_redirect_limit",
            Self::TooLarge => "web_too_large",
            Self::UnsupportedType => "web_unsupported_type",
            Self::HttpStatus(_) => "web_http_status",
            Self::Timeout => "web_timeout",
            Self::Unreachable => "web_provider",
        }
    }
}

/// Hôte et port d'une URL admise : `https` (443) ou `http` (80) seulement, sans identifiants, nom (pas
/// d'IP littérale) public, hors des hôtes de Synco.
pub fn check_url(u: &reqwest::Url, synco_hosts: &BTreeSet<String>) -> Result<(String, u16), FetchError> {
    let port = match (u.scheme(), u.port_or_known_default()) {
        ("https", Some(443)) => 443,
        ("http", Some(80)) => 80,
        _ => return Err(FetchError::UrlRefused),
    };
    if !u.username().is_empty() || u.password().is_some() {
        return Err(FetchError::UrlRefused);
    }
    let Some(url::Host::Domain(d)) = u.host() else { return Err(FetchError::UrlRefused) };
    let host = d.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || private_name(&host) || host.parse::<IpAddr>().is_ok() {
        return Err(FetchError::UrlRefused);
    }
    if synco_hosts.iter().any(|s| host == *s || host.ends_with(&format!(".{s}"))) {
        return Err(FetchError::UrlRefused);
    }
    Ok((host, port))
}

/// Type admis (essence du `content-type`, sans paramètres).
#[must_use]
pub fn type_allowed(content_type: &str) -> bool {
    let essence = content_type.split(';').next().unwrap_or_default().trim().to_ascii_lowercase();
    ALLOWED_TYPES.contains(&essence.as_str())
}

/// `Content-Encoding` absent ou `identity` : le superviseur ne décompresse rien.
#[must_use]
pub fn encoding_allowed(content_encoding: Option<&str>) -> bool {
    content_encoding.is_none_or(|e| e.trim().is_empty() || e.trim().eq_ignore_ascii_case("identity"))
}

// ---------------------------------------------------------------------------
// Résolution et transport (injectables pour les tests : aucun appel réseau réel)
// ---------------------------------------------------------------------------

/// Résolution d'un nom (`tokio::net::lookup_host` en production).
pub trait Resolver: Send + Sync + 'static {
    /// Adresses de `host`.
    fn lookup(&self, host: &str) -> BoxFuture<'_, Result<Vec<IpAddr>, ()>>;
}

/// Résolveur du système.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn lookup(&self, host: &str) -> BoxFuture<'_, Result<Vec<IpAddr>, ()>> {
        let host = host.to_owned();
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host.as_str(), 0)).await.map_err(|_| ())?;
            Ok(addrs.map(|a| a.ip()).collect())
        })
    }
}

/// Réponse d'un saut (un `GET`, sans redirection suivie).
#[derive(Debug)]
pub struct Hop {
    /// Statut.
    pub status: u16,
    /// `Location`.
    pub location: Option<String>,
    /// `Content-Type`.
    pub content_type: Option<String>,
    /// `Content-Encoding`.
    pub content_encoding: Option<String>,
    /// Corps (lu seulement pour un `2xx`, borné à `max + 1` octets).
    pub body: Bytes,
}

/// Un saut : `GET url` vers les adresses **déjà contrôlées** `pinned`, sans nouvelle résolution.
pub trait Transport: Send + Sync + 'static {
    /// Exécute le saut (corps borné à `max + 1` octets pour détecter le dépassement).
    fn get(
        &self,
        url: reqwest::Url,
        host: String,
        pinned: Vec<SocketAddr>,
        max: usize,
        timeout: Duration,
    ) -> BoxFuture<'_, Result<Hop, FetchError>>;
}

/// Résolveur qui refuse tout : le client d'une lecture ne résout jamais lui-même (adresse épinglée).
#[derive(Debug, Clone, Copy)]
struct NoResolve;

impl reqwest::dns::Resolve for NoResolve {
    fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async { Err("web_unpinned_name".into()) })
    }
}

/// Transport de production : un client `reqwest` par saut, nom épinglé sur les adresses contrôlées.
#[derive(Debug, Default)]
pub struct ReqwestTransport {
    /// Tests seulement : connexion forcée vers cette adresse (serveur local), contrôles inchangés.
    #[cfg(test)]
    pub connect_to: Option<SocketAddr>,
}

impl Transport for ReqwestTransport {
    fn get(
        &self,
        url: reqwest::Url,
        host: String,
        pinned: Vec<SocketAddr>,
        max: usize,
        timeout: Duration,
    ) -> BoxFuture<'_, Result<Hop, FetchError>> {
        #[cfg(test)]
        let pinned = self.connect_to.map_or(pinned, |a| vec![a]);
        Box::pin(async move {
            let client = reqwest::Client::builder()
                .connect_timeout(FETCH_CONNECT_TIMEOUT)
                .timeout(timeout)
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .dns_resolver(Arc::new(NoResolve))
                .resolve_to_addrs(&host, &pinned)
                .user_agent(FETCH_USER_AGENT)
                .build()
                .map_err(|_| FetchError::Unreachable)?;
            let resp = client
                .get(url)
                .header(header::ACCEPT.as_str(), FETCH_ACCEPT)
                .header(header::ACCEPT_ENCODING.as_str(), "identity")
                .send()
                .await
                .map_err(|e| if e.is_timeout() { FetchError::Timeout } else { FetchError::Unreachable })?;
            let h =
                |n: header::HeaderName| resp.headers().get(n.as_str()).and_then(|v| v.to_str().ok()).map(str::to_owned);
            let status = resp.status().as_u16();
            let location = h(header::LOCATION);
            let content_type = h(header::CONTENT_TYPE);
            let content_encoding = h(header::CONTENT_ENCODING);
            let declared = resp.content_length().and_then(|n| usize::try_from(n).ok());
            let ok = (200..300).contains(&status);
            if !ok || declared.is_some_and(|n| n > max) || !encoding_allowed(content_encoding.as_deref()) {
                return Ok(Hop { status, location, content_type, content_encoding, body: Bytes::new() });
            }
            let mut resp = resp;
            let mut buf: Vec<u8> = Vec::new();
            while let Some(chunk) = resp
                .chunk()
                .await
                .map_err(|e| if e.is_timeout() { FetchError::Timeout } else { FetchError::Unreachable })?
            {
                if buf.len().saturating_add(chunk.len()) > max {
                    let room = max.saturating_add(1).saturating_sub(buf.len());
                    buf.extend_from_slice(chunk.get(..room.min(chunk.len())).unwrap_or_default());
                    break;
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(Hop { status, location, content_type, content_encoding, body: Bytes::from(buf) })
        })
    }
}

/// Page lue.
#[derive(Debug, PartialEq, Eq)]
pub struct Fetched {
    /// URL après redirections.
    pub final_url: String,
    /// `content-type` du site.
    pub content_type: String,
    /// Octets bruts (≤ `max`).
    pub body: Bytes,
}

/// Lecture d'une URL : contrôle complet de chaque saut, adresse épinglée, 5 redirections au plus.
pub async fn fetch(
    raw: &str,
    max: usize,
    synco_hosts: &BTreeSet<String>,
    local_ips: &BTreeSet<IpAddr>,
    resolver: &dyn Resolver,
    transport: &dyn Transport,
) -> Result<Fetched, FetchError> {
    let deadline = Instant::now().checked_add(FETCH_TOTAL_TIMEOUT).unwrap_or_else(Instant::now);
    let mut url = reqwest::Url::parse(raw).map_err(|_| FetchError::UrlRefused)?;
    let mut redirects = 0usize;
    loop {
        let (host, port) = check_url(&url, synco_hosts)?;
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(FetchError::Timeout);
        }
        let addrs = tokio::time::timeout(left, resolver.lookup(&host))
            .await
            .map_err(|_| FetchError::Timeout)?
            .map_err(|()| FetchError::UrlRefused)?;
        if !addrs_allowed(&addrs) || addrs.iter().any(|a| local_ips.contains(a)) {
            return Err(FetchError::UrlRefused);
        }
        let pinned: Vec<SocketAddr> = addrs.iter().map(|a| SocketAddr::new(*a, port)).collect();
        url.set_fragment(None);
        let left = deadline.saturating_duration_since(Instant::now());
        let hop = tokio::time::timeout(left, transport.get(url.clone(), host, pinned, max, left))
            .await
            .map_err(|_| FetchError::Timeout)??;
        if matches!(hop.status, 301 | 302 | 303 | 307 | 308) {
            let Some(loc) = hop.location else { return Err(FetchError::HttpStatus(hop.status)) };
            if redirects >= MAX_REDIRECTS {
                return Err(FetchError::RedirectLimit);
            }
            redirects = redirects.saturating_add(1);
            let next = url.join(&loc).map_err(|_| FetchError::UrlRefused)?;
            // Rétrogradation https → http refusée (le site ne peut pas faire lire en clair).
            if url.scheme() == "https" && next.scheme() != "https" {
                return Err(FetchError::UrlRefused);
            }
            url = next;
            continue;
        }
        if !(200..300).contains(&hop.status) {
            return Err(FetchError::HttpStatus(hop.status));
        }
        if !encoding_allowed(hop.content_encoding.as_deref()) {
            return Err(FetchError::UnsupportedType);
        }
        let ct = hop.content_type.unwrap_or_default();
        if !type_allowed(&ct) {
            return Err(FetchError::UnsupportedType);
        }
        if hop.body.len() > max {
            return Err(FetchError::TooLarge);
        }
        return Ok(Fetched { final_url: url.to_string(), content_type: ct, body: hop.body });
    }
}

// ---------------------------------------------------------------------------
// Recherche : un adaptateur par service derrière une interface unique
// ---------------------------------------------------------------------------

/// Requête `POST /search` (stricte).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchBody {
    /// 2 à 200 caractères.
    pub query: String,
    /// `day` | `week` | `month` | `year`.
    pub freshness: Option<String>,
    /// 2 lettres.
    pub lang: Option<String>,
    /// 1 à 10.
    pub count: Option<u8>,
}

impl SearchBody {
    /// Contrôle des bornes (corps déjà strict).
    #[must_use]
    pub fn valid(&self) -> bool {
        let n = self.query.chars().count();
        (2..=200).contains(&n)
            && !self.query.chars().any(char::is_control)
            && self.freshness.as_deref().is_none_or(|f| matches!(f, "day" | "week" | "month" | "year"))
            && self.lang.as_deref().is_none_or(|l| l.len() == 2 && l.bytes().all(|b| b.is_ascii_alphabetic()))
            && self.count.is_none_or(|c| (1..=10).contains(&c))
    }

    fn count(&self) -> usize {
        usize::from(self.count.unwrap_or(10))
    }
}

/// Date civile (AAAAMMJJ) de `days` jours après le 1970-01-01 (algorithme de Howard Hinnant).
#[must_use]
pub fn civil_yyyymmdd(days: i64) -> String {
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe.saturating_sub(doe / 1460).saturating_add(doe / 36_524).saturating_sub(doe / 146_096)) / 365;
    let y = yoe.saturating_add(era.saturating_mul(400));
    let doy = doe.saturating_sub(yoe.saturating_mul(365).saturating_add(yoe / 4).saturating_sub(yoe / 100));
    let mp = (doy.saturating_mul(5).saturating_add(2)) / 153;
    let d = doy.saturating_sub((mp.saturating_mul(153).saturating_add(2)) / 5).saturating_add(1);
    let m = if mp < 10 { mp.saturating_add(3) } else { mp.saturating_sub(9) };
    let y = if m <= 2 { y.saturating_add(1) } else { y };
    format!("{y:04}{m:02}{d:02}")
}

fn days_now() -> i64 {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    i64::try_from(secs / 86_400).unwrap_or(0)
}

/// Requête HTTP du service (méthode `GET`), sans la clé quand elle va dans un en-tête.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRequest {
    /// URL complète (paramètres compris ; pour Mojeek, la clé y figure : jamais journalisée).
    pub url: reqwest::Url,
    /// En-tête d'authentification (`Authorization` ou `X-Subscription-Token`).
    pub auth_header: Option<&'static str>,
}

/// Construit la requête du service (adaptateur). Jamais la ville ni l'IP de l'utilisateur : `lang` seulement.
pub fn provider_request(s: &SearchService, b: &SearchBody, today: i64) -> Result<ProviderRequest, &'static str> {
    let path = match s.provider {
        SearchProvider::Staan => "/search/web",
        SearchProvider::Mojeek | SearchProvider::Searxng => "/search",
        SearchProvider::Brave => "/res/v1/web/search",
    };
    let mut url = reqwest::Url::parse(&format!("{}{path}", s.base_url)).map_err(|_| "web_provider")?;
    let key = s.key.as_ref().map(|k| String::from_utf8_lossy(k).into_owned());
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("q", &b.query);
        match s.provider {
            SearchProvider::Staan => {
                // Marchés admis : fr-fr, en-us, de-de ; sinon défaut du service. Pas de fraîcheur.
                if let Some(m) = b.lang.as_deref().and_then(|l| match l {
                    "fr" => Some("fr-fr"),
                    "en" => Some("en-us"),
                    "de" => Some("de-de"),
                    _ => None,
                }) {
                    q.append_pair("market", m);
                }
            }
            SearchProvider::Mojeek => {
                q.append_pair("fmt", "json");
                q.append_pair("t", &b.count().to_string());
                if let Some(l) = &b.lang {
                    q.append_pair("lb", &l.to_ascii_uppercase());
                }
                if let Some(f) = &b.freshness {
                    // Toujours une date AAAAMMJJ (jamais un mot-clé que le service pourrait ignorer).
                    let days = match f.as_str() {
                        "day" => 1,
                        "week" => 7,
                        "month" => 30,
                        _ => 365,
                    };
                    q.append_pair("since", &civil_yyyymmdd(today.saturating_sub(days)));
                }
                if let Some(k) = &key {
                    q.append_pair("api_key", k);
                }
            }
            SearchProvider::Searxng => {
                q.append_pair("format", "json");
                if let Some(l) = &b.lang {
                    q.append_pair("language", l);
                }
                if let Some(f) = &b.freshness {
                    q.append_pair("time_range", f);
                }
            }
            SearchProvider::Brave => {
                q.append_pair("count", &b.count().to_string());
                if let Some(l) = &b.lang {
                    q.append_pair("search_lang", l);
                }
                if let Some(f) = &b.freshness {
                    let code = match f.as_str() {
                        "day" => "pd",
                        "week" => "pw",
                        "month" => "pm",
                        _ => "py",
                    };
                    q.append_pair("freshness", code);
                }
            }
        }
    }
    let auth_header = match s.provider {
        SearchProvider::Staan if key.is_some() => Some("authorization"),
        SearchProvider::Brave if key.is_some() => Some("x-subscription-token"),
        _ => None,
    };
    Ok(ProviderRequest { url, auth_header })
}

fn text_of(v: Option<&Value>, max: usize) -> String {
    v.and_then(Value::as_str)
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Lit la réponse d'un service et la normalise : `[{ title ≤ 200, url ≤ 2 000 (http/https), snippet ≤ 500,
/// age? }]`, `count` au plus, JSON ≤ 8 Kio (extraits tronqués, puis résultats retirés depuis la fin).
pub fn normalize_results(provider: SearchProvider, v: &Value, count: usize) -> Result<Vec<Value>, &'static str> {
    let (list, snippet_key, age_key) = match provider {
        SearchProvider::Staan => (v.pointer("/web/results"), "snippet", None),
        SearchProvider::Mojeek => {
            let status = v.pointer("/response/status").and_then(Value::as_str);
            if status.is_some_and(|s| s != "OK") {
                return Err("web_provider");
            }
            (v.pointer("/response/results"), "desc", Some("date"))
        }
        SearchProvider::Searxng => (v.get("results"), "content", Some("publishedDate")),
        SearchProvider::Brave => (v.pointer("/web/results"), "description", Some("age")),
    };
    let Some(list) = list.and_then(Value::as_array) else {
        // Aucune liste : réponse vide admise seulement si l'objet est un objet (recherche sans résultat).
        return if v.is_object() { Ok(Vec::new()) } else { Err("web_provider") };
    };
    let mut out = Vec::new();
    for r in list {
        if out.len() >= count.min(10) {
            break;
        }
        let url = text_of(r.get("url"), 2001);
        let ok = url.len() <= 2000
            && reqwest::Url::parse(&url)
                .is_ok_and(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some());
        if !ok {
            continue;
        }
        let mut item = json!({
            "title": text_of(r.get("title"), 200),
            "url": url,
            "snippet": text_of(r.get(snippet_key), 500),
        });
        if let Some(age) = age_key.map(|k| text_of(r.get(k), 40)).filter(|a| !a.is_empty())
            && let Some(o) = item.as_object_mut()
        {
            o.insert("age".to_owned(), json!(age));
        }
        out.push(item);
    }
    let size = |items: &[Value]| json!({ "results": items }).to_string().len();
    // Extraits raccourcis d'abord, puis résultats retirés depuis la fin.
    let mut cap = 500usize;
    while size(&out) > SEARCH_RESULTS_MAX_BYTES && cap > 100 {
        cap = cap.saturating_sub(100);
        for item in &mut out {
            if let Some(o) = item.as_object_mut()
                && let Some(Value::String(s)) = o.get_mut("snippet")
            {
                *s = s.chars().take(cap).collect();
            }
        }
    }
    while size(&out) > SEARCH_RESULTS_MAX_BYTES && !out.is_empty() {
        out.pop();
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Counters {
    window_start: Instant,
    window: u32,
    total: u32,
}

#[derive(Debug)]
struct HourCounter {
    start: Instant,
    searches: u32,
    fetches: u32,
}

/// Route d'un worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebRoute {
    /// Propriétaire de la conversation (révocation `feature.revoked`).
    pub user_id: String,
    /// Fenêtre des quotas par tour (`maxTurnDurationSecs`).
    pub window_secs: u64,
    /// Instant où l'accès a été lu (juste AVANT la prise du bail) : une révocation reçue depuis empêche
    /// le socket d'être servi (course entre `feature.revoked` et le lancement du worker).
    pub granted_at: Instant,
}

impl WebRoute {
    /// Route accordée maintenant.
    #[must_use]
    pub fn new(user_id: impl Into<String>, window_secs: u64) -> Self {
        Self { user_id: user_id.into(), window_secs, granted_at: Instant::now() }
    }
}

/// Révocations récentes gardées (par utilisateur) pour la course au lancement.
const RECENT_REVOCATIONS_MAX: usize = 10_000;
/// Au-delà, une révocation ne peut plus concerner un lancement en cours (prise du bail → `serve`).
const RECENT_REVOCATION_TTL: Duration = Duration::from_secs(600);

struct RouteCtx {
    proxy: Arc<WebProxy>,
    route: WebRoute,
    revoked: watch::Receiver<bool>,
    search: Mutex<Counters>,
    fetch: Mutex<Counters>,
}

struct Registered {
    user_id: String,
    revoke: watch::Sender<bool>,
    socket: PathBuf,
    /// Tâche du socket : terminée (worker fini, tâche abandonnée) = route oubliée.
    task: tokio::task::AbortHandle,
}

/// Proxy partagé (service de recherche, clé, quotas du runtime, routes ouvertes).
pub struct WebProxy {
    search: Option<SearchService>,
    fetch_enabled: bool,
    synco_hosts: BTreeSet<String>,
    /// Adresses de l'hôte du runtime, refusées par `web_fetch` même publiques (lues au démarrage).
    local_ips: BTreeSet<IpAddr>,
    quotas: WebQuotas,
    search_http: reqwest::Client,
    resolver: Arc<dyn Resolver>,
    transport: Arc<dyn Transport>,
    hour: Mutex<HourCounter>,
    runtime_conns: Arc<Semaphore>,
    routes: Mutex<Vec<Registered>>,
    /// Dernière révocation par utilisateur (`feature.revoked`, bail sans `webAllowed`).
    revoked_at: Mutex<std::collections::HashMap<String, Instant>>,
}

impl core::fmt::Debug for WebProxy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WebProxy")
            .field("provider", &self.search.as_ref().map(|s| s.provider.id()))
            .field("fetch", &self.fetch_enabled)
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn refuse(status: StatusCode, code: &'static str) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], format!("{{\"error\":\"{code}\"}}")).into_response()
}

fn search_client(allow_private: bool) -> Result<reqwest::Client, &'static str> {
    let mut b = reqwest::Client::builder()
        .timeout(SEARCH_TIMEOUT)
        .connect_timeout(SEARCH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .user_agent(concat!("synco-ai-runtime/", env!("CARGO_PKG_VERSION")));
    if !allow_private {
        b = b.dns_resolver(Arc::new(super::proxy::PublicOnlyResolver)).https_only(true);
    }
    b.build().map_err(|_| "web_proxy_client")
}

impl WebProxy {
    /// Proxy de production (résolveur du système, transport `reqwest`).
    pub fn new(
        search: Option<SearchService>,
        settings: &WebSettings,
        derived_synco_hosts: impl IntoIterator<Item = String>,
    ) -> Result<Arc<Self>, &'static str> {
        let proxy = Self::with_parts(
            search,
            settings,
            derived_synco_hosts,
            Arc::new(SystemResolver),
            Arc::new(ReqwestTransport::default()),
        )?;
        Ok(proxy.with_local_ips(host_local_ips()))
    }

    /// Même proxy, avec les adresses de l'hôte refusées (`Arc` encore unique : construction).
    #[must_use]
    pub fn with_local_ips(self: Arc<Self>, ips: BTreeSet<IpAddr>) -> Arc<Self> {
        match Arc::try_unwrap(self) {
            Ok(mut p) => {
                p.local_ips = ips;
                Arc::new(p)
            }
            Err(shared) => shared,
        }
    }

    /// Proxy aux pièces injectées (tests : résolveur et transport simulés, aucun appel réseau).
    pub fn with_parts(
        search: Option<SearchService>,
        settings: &WebSettings,
        derived_synco_hosts: impl IntoIterator<Item = String>,
        resolver: Arc<dyn Resolver>,
        transport: Arc<dyn Transport>,
    ) -> Result<Arc<Self>, &'static str> {
        let allow_private = search.as_ref().is_some_and(|s| s.allow_private_host);
        let synco_hosts = derived_synco_hosts
            .into_iter()
            .chain(settings.synco_hosts.iter().cloned())
            .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect();
        Ok(Arc::new(Self {
            search,
            fetch_enabled: settings.fetch.enabled,
            synco_hosts,
            local_ips: BTreeSet::new(),
            quotas: settings.quotas,
            search_http: search_client(allow_private)?,
            resolver,
            transport,
            hour: Mutex::new(HourCounter { start: Instant::now(), searches: 0, fetches: 0 }),
            runtime_conns: Arc::new(Semaphore::new(CONNECTIONS_PER_RUNTIME)),
            routes: Mutex::new(Vec::new()),
            revoked_at: Mutex::new(std::collections::HashMap::new()),
        }))
    }

    /// Service de recherche configuré (déclaré à l'API, `PUT /web-provider`).
    #[must_use]
    pub fn provider(&self) -> Option<&'static str> {
        self.search.as_ref().map(|s| s.provider.id())
    }

    /// Outils web disponibles (section `[web.search]` valide).
    #[must_use]
    pub const fn available(&self) -> bool {
        self.search.is_some()
    }

    /// `web_fetch` permis.
    #[must_use]
    pub const fn fetch_enabled(&self) -> bool {
        self.fetch_enabled
    }

    /// Sert `route` sur `listener` (socket `socket`) jusqu'à l'abandon de la tâche ou la révocation.
    pub fn serve(
        self: &Arc<Self>,
        listener: tokio::net::UnixListener,
        socket: PathBuf,
        route: WebRoute,
    ) -> tokio::task::JoinHandle<()> {
        // Révoqué depuis la lecture de l'accès : rien n'est servi, le socket disparaît.
        let revoked_since = lock(&self.revoked_at).get(&route.user_id).is_some_and(|t| *t >= route.granted_at);
        if revoked_since {
            drop(listener);
            let _ = std::fs::remove_file(&socket);
            tracing::info!(code = "web_access_revoked", "socket web non servi (accès retiré au lancement)");
            return tokio::spawn(async {});
        }
        let (tx, rx) = watch::channel(false);
        let user_id = route.user_id.clone();
        let now = Instant::now();
        let ctx = Arc::new(RouteCtx {
            proxy: Arc::clone(self),
            route,
            revoked: rx.clone(),
            search: Mutex::new(Counters { window_start: now, window: 0, total: 0 }),
            fetch: Mutex::new(Counters { window_start: now, window: 0, total: 0 }),
        });
        let app = axum::Router::new().fallback(handle).with_state(ctx);
        let listener = LimitedListener {
            inner: listener,
            worker: Arc::new(Semaphore::new(CONNECTIONS_PER_WORKER)),
            runtime: Arc::clone(&self.runtime_conns),
        };
        let mut stop = rx;
        let handle = tokio::spawn(async move {
            let shutdown = async move {
                let _ = stop.wait_for(|r| *r).await;
            };
            if axum::serve(listener, app).with_graceful_shutdown(shutdown).await.is_err() {
                tracing::debug!(code = "web_proxy_stopped", "proxy web arrêté");
            }
        });
        let mut routes = lock(&self.routes);
        routes.retain(|r| !r.task.is_finished());
        routes.push(Registered { user_id, revoke: tx, socket, task: handle.abort_handle() });
        handle
    }

    /// `feature.revoked` (12 §11.4) : ferme le socket `web` des workers de `user_id` ; requêtes en cours
    /// coupées (`web_unavailable`), connexions suivantes refusées (socket retiré). Rend le nombre fermé.
    pub fn revoke_user(&self, user_id: &str) -> usize {
        {
            let now = Instant::now();
            let mut recent = lock(&self.revoked_at);
            recent.retain(|_, t| now.saturating_duration_since(*t) < RECENT_REVOCATION_TTL);
            if recent.len() < RECENT_REVOCATIONS_MAX || recent.contains_key(user_id) {
                recent.insert(user_id.to_owned(), now);
            }
        }
        let mut routes = lock(&self.routes);
        let mut n = 0usize;
        routes.retain(|r| {
            // Route d'un worker terminé (tâche abandonnée) : oubliée.
            if r.task.is_finished() {
                return false;
            }
            if r.user_id != user_id {
                return true;
            }
            let _ = r.revoke.send(true);
            let _ = std::fs::remove_file(&r.socket);
            n = n.saturating_add(1);
            false
        });
        if n > 0 {
            tracing::info!(code = "web_access_revoked", sockets = n, "socket web fermé (accès web retiré)");
        }
        n
    }

    /// Quotas : `Err` = refus `web_quota` sans appel sortant.
    fn admit(&self, ctx: &RouteCtx, search: bool) -> Result<(), ()> {
        let now = Instant::now();
        let q = self.quotas;
        let (per_window, per_worker, per_hour) = if search {
            (q.search_per_window, q.search_per_worker, q.search_per_hour)
        } else {
            (q.fetch_per_window, q.fetch_per_worker, q.fetch_per_hour)
        };
        let mut hour = lock(&self.hour);
        if now.saturating_duration_since(hour.start) >= Duration::from_secs(3_600) {
            *hour = HourCounter { start: now, searches: 0, fetches: 0 };
        }
        let used = if search { hour.searches } else { hour.fetches };
        if used >= per_hour {
            return Err(());
        }
        let mut c = lock(if search { &ctx.search } else { &ctx.fetch });
        if now.saturating_duration_since(c.window_start) >= Duration::from_secs(ctx.route.window_secs.max(1)) {
            c.window_start = now;
            c.window = 0;
        }
        if c.window >= per_window || c.total >= per_worker {
            return Err(());
        }
        c.window = c.window.saturating_add(1);
        c.total = c.total.saturating_add(1);
        if search {
            hour.searches = hour.searches.saturating_add(1);
        } else {
            hour.fetches = hour.fetches.saturating_add(1);
        }
        Ok(())
    }

    async fn do_search(&self, body: &SearchBody) -> Response {
        let Some(s) = &self.search else { return refuse(StatusCode::SERVICE_UNAVAILABLE, "web_unavailable") };
        let Ok(req) = provider_request(s, body, days_now()) else {
            return refuse(StatusCode::BAD_GATEWAY, "web_provider");
        };
        let mut up = self
            .search_http
            .get(req.url)
            .header(header::ACCEPT.as_str(), "application/json")
            .header(header::ACCEPT_ENCODING.as_str(), "identity");
        if let (Some(name), Some(key)) = (req.auth_header, &s.key) {
            let mut raw = Zeroizing::new(Vec::with_capacity(key.len().saturating_add(7)));
            if name == "authorization" {
                raw.extend_from_slice(b"Bearer ");
            }
            raw.extend_from_slice(key);
            if let Ok(mut v) = axum::http::HeaderValue::from_bytes(&raw) {
                v.set_sensitive(true);
                up = up.header(name, v);
            }
        }
        let resp = match up.send().await {
            Ok(r) => r,
            Err(e) => {
                let code = if e.is_timeout() { "web_timeout" } else { "web_provider" };
                tracing::warn!(code, provider = s.provider.id(), "recherche en échec");
                return refuse(
                    if e.is_timeout() { StatusCode::GATEWAY_TIMEOUT } else { StatusCode::BAD_GATEWAY },
                    code,
                );
            }
        };
        if !resp.status().is_success() {
            tracing::warn!(
                code = "web_provider",
                status = resp.status().as_u16(),
                provider = s.provider.id(),
                "recherche refusée par le service"
            );
            return refuse(StatusCode::BAD_GATEWAY, "web_provider");
        }
        let mut resp = resp;
        let mut buf = Vec::new();
        loop {
            match resp.chunk().await {
                Ok(Some(c)) => {
                    if buf.len().saturating_add(c.len()) > SEARCH_RESPONSE_MAX {
                        return refuse(StatusCode::BAD_GATEWAY, "web_provider");
                    }
                    buf.extend_from_slice(&c);
                }
                Ok(None) => break,
                Err(e) => {
                    let timeout = e.is_timeout();
                    return refuse(
                        if timeout { StatusCode::GATEWAY_TIMEOUT } else { StatusCode::BAD_GATEWAY },
                        if timeout { "web_timeout" } else { "web_provider" },
                    );
                }
            }
        }
        let parsed: Value = match serde_json::from_slice(&buf) {
            Ok(v) => v,
            Err(_) => return refuse(StatusCode::BAD_GATEWAY, "web_provider"),
        };
        match normalize_results(s.provider, &parsed, body.count()) {
            Ok(results) => {
                tracing::debug!(code = "web_search_done", results = results.len(), "recherche relayée");
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    json!({ "results": results }).to_string(),
                )
                    .into_response()
            }
            Err(code) => refuse(StatusCode::BAD_GATEWAY, code),
        }
    }

    async fn do_fetch(&self, body: &FetchBody) -> Response {
        let max = body.max_bytes.unwrap_or(MAX_FETCH_BYTES);
        match fetch(&body.url, max, &self.synco_hosts, &self.local_ips, self.resolver.as_ref(), self.transport.as_ref())
            .await
        {
            Ok(f) => {
                tracing::debug!(code = "web_fetch_done", bytes = f.body.len(), "page relayée");
                let mut out = Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE.as_str(), f.content_type.as_str());
                if let Ok(v) = axum::http::HeaderValue::from_str(&f.final_url) {
                    out = out.header("x-synco-final-url", v);
                }
                out.body(Body::from(f.body)).unwrap_or_else(|_| refuse(StatusCode::BAD_GATEWAY, "web_provider"))
            }
            Err(e) => {
                tracing::info!(code = e.code(), "lecture refusée ou en échec");
                e.response()
            }
        }
    }
}

/// Requête `POST /fetch` (stricte).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FetchBody {
    /// URL (≤ 2 000).
    pub url: String,
    /// 1 024 à 2 097 152.
    pub max_bytes: Option<usize>,
}

impl FetchBody {
    /// Bornes.
    #[must_use]
    pub fn valid(&self) -> bool {
        !self.url.is_empty()
            && self.url.len() <= 2000
            && self.max_bytes.is_none_or(|m| (MIN_FETCH_BYTES..=MAX_FETCH_BYTES).contains(&m))
    }
}

async fn read_body(body: Body) -> Result<Bytes, (StatusCode, &'static str)> {
    let read = async {
        let limited = http_body_util::Limited::new(body, MAX_REQUEST_BYTES);
        limited.collect().await.map(http_body_util::Collected::to_bytes)
    };
    match tokio::time::timeout(BODY_READ_TIMEOUT, read).await {
        Ok(Ok(b)) => Ok(b),
        Ok(Err(_)) => Err((StatusCode::BAD_REQUEST, "web_bad_request")),
        Err(_) => Err((StatusCode::REQUEST_TIMEOUT, "web_bad_request")),
    }
}

async fn handle(State(ctx): State<Arc<RouteCtx>>, req: Request) -> Response {
    if *ctx.revoked.borrow() {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "web_unavailable");
    }
    let (parts, body) = req.into_parts();
    let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    let search = match path {
        "/search" => true,
        "/fetch" => false,
        _ => return refuse(StatusCode::NOT_FOUND, "web_path"),
    };
    if parts.method != Method::POST {
        return refuse(StatusCode::METHOD_NOT_ALLOWED, "web_method");
    }
    let declared =
        parts.headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > MAX_REQUEST_BYTES) {
        return refuse(StatusCode::BAD_REQUEST, "web_bad_request");
    }
    let bytes = match read_body(body).await {
        Ok(b) => b,
        Err((status, code)) => return refuse(status, code),
    };
    let proxy = Arc::clone(&ctx.proxy);
    let work = async {
        if search {
            let Ok(b) = serde_json::from_slice::<SearchBody>(&bytes) else {
                return refuse(StatusCode::BAD_REQUEST, "web_bad_request");
            };
            if !b.valid() {
                return refuse(StatusCode::BAD_REQUEST, "web_bad_request");
            }
            if proxy.admit(&ctx, true).is_err() {
                return refuse(StatusCode::TOO_MANY_REQUESTS, "web_quota");
            }
            proxy.do_search(&b).await
        } else {
            if !proxy.fetch_enabled {
                return refuse(StatusCode::SERVICE_UNAVAILABLE, "web_unavailable");
            }
            let Ok(b) = serde_json::from_slice::<FetchBody>(&bytes) else {
                return refuse(StatusCode::BAD_REQUEST, "web_bad_request");
            };
            if !b.valid() {
                return refuse(StatusCode::BAD_REQUEST, "web_bad_request");
            }
            if proxy.admit(&ctx, false).is_err() {
                return refuse(StatusCode::TOO_MANY_REQUESTS, "web_quota");
            }
            proxy.do_fetch(&b).await
        }
    };
    let mut revoked = ctx.revoked.clone();
    tokio::select! {
        r = work => r,
        _ = revoked.wait_for(|r| *r) => refuse(StatusCode::SERVICE_UNAVAILABLE, "web_unavailable"),
    }
}

/// Connexion sans place : `429 web_quota` écrit en une fois (au plus 1 s), puis fermeture.
async fn refuse_busy(mut io: tokio::net::UnixStream) {
    use tokio::io::AsyncWriteExt as _;
    const BODY: &str = r#"{"error":"web_quota"}"#;
    let resp = format!(
        "HTTP/1.1 429 Too Many Requests\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{BODY}",
        BODY.len()
    );
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        let _ = io.write_all(resp.as_bytes()).await;
        let _ = io.shutdown().await;
    })
    .await;
}

/// Connexion comptée (places du worker et du runtime rendues à la fermeture).
struct LimitedConn {
    io: tokio::net::UnixStream,
    _worker: OwnedSemaphorePermit,
    _runtime: OwnedSemaphorePermit,
}

impl AsyncRead for LimitedConn {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for LimitedConn {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Accepte d'abord, puis prend une place du worker **et** une du runtime sans attendre ; sans place, la
/// connexion reçoit `429 web_quota` et est fermée. Un worker sans connexion ouverte ne garde aucune place.
struct LimitedListener {
    inner: tokio::net::UnixListener,
    worker: Arc<Semaphore>,
    runtime: Arc<Semaphore>,
}

impl axum::serve::Listener for LimitedListener {
    type Io = LimitedConn;
    type Addr = tokio::net::unix::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (io, addr) = match self.inner.accept().await {
                Ok(c) => c,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            match (Arc::clone(&self.worker).try_acquire_owned(), Arc::clone(&self.runtime).try_acquire_owned()) {
                (Ok(w), Ok(r)) => return (LimitedConn { io, _worker: w, _runtime: r }, addr),
                // Les places éventuellement prises sont rendues ici (fin de portée).
                _ => {
                    tokio::spawn(refuse_busy(io));
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests;
