//! Mandataire LLM du superviseur (docs/plan/10 §4) : **seul accès réseau** d'un worker isolé.
//!
//! Un socket Unix par worker (`<run_dir>/w-<n>/llm.sock`, monté en lecture seule dans le bac à sable
//! sous `/run/synco/`). Le worker y parle HTTP/1.1 clair ; le mandataire relaie vers l'URL de base
//! du fournisseur **de cette conversation** (et d'aucun autre hôte), en TLS, sans suivre de
//! redirection, et :
//!
//! - n'accepte que `POST` du chemin de chat et `GET` de la liste des modèles ([`allowed_request`]),
//!   sans chaîne de requête (I2) ;
//! - pour `openai`, `mistral`, `gemini`, `custom` : retire tout `authorization` du worker et ajoute
//!   `Authorization: Bearer <clé>` depuis la configuration du runtime (D1) ; la clé ne passe jamais
//!   par le pipe ni par le worker ;
//! - pour `gateway` : relaie l'`authorization` du worker (ticket `sgt1` obtenu par
//!   `signed_request`, 02 §4), la passerelle n'ayant pas de clé.
//!
//! Aucun corps ni en-tête n'est journalisé.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use zeroize::Zeroizing;

use crate::config::ProviderSecret;
use crate::launcher::LlmRoute;

/// Corps de requête maximal (historique + images en base64).
pub const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;
/// Requêtes simultanées par worker.
pub const MAX_IN_FLIGHT_PER_WORKER: usize = 4;
/// Silence maximal de l'amont (09 §2).
pub const READ_TIMEOUT: Duration = Duration::from_secs(120);
/// Durée totale maximale d'un appel (09 §2).
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(600);

/// Mandataire partagé (clés des fournisseurs, client HTTP).
pub struct LlmProxy {
    http: reqwest::Client,
    public_http: reqwest::Client,
    secrets: BTreeMap<String, ProviderSecret>,
}

impl core::fmt::Debug for LlmProxy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LlmProxy").field("providers_with_key", &self.secrets.len()).finish_non_exhaustive()
    }
}

struct RouteCtx {
    proxy: Arc<LlmProxy>,
    route: LlmRoute,
    base: String,
    in_flight: Arc<tokio::sync::Semaphore>,
}

/// Adresse non publique (boucle locale, privée, lien local, métadonnées, ULA, non spécifiée,
/// multidiffusion, documentation…).
#[must_use]
pub fn ip_is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 (CGNAT)
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xfe00) == 0xfc00 // ULA
                || (seg[0] & 0xffc0) == 0xfe80 // lien local
                || v6.to_ipv4_mapped().is_some_and(|v4| ip_is_private(IpAddr::V4(v4)))
                || (seg[0] == 0x2001 && seg[1] == 0x0db8)
        }
    }
}

/// URL de passerelle venue de la **politique de l'org** (donc de l'API) : `https` seulement, nom
/// d'hôte public (jamais `localhost`, `.local`, `.internal`, adresse IP privée, de lien local ou de
/// métadonnées). La résolution est filtrée en plus à la connexion ([`PublicOnlyResolver`]).
#[must_use]
pub fn gateway_url_allowed(url: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(url) else { return false };
    let host = u.host_str().unwrap_or_default();
    let host_ok = match host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
        Ok(ip) => !ip_is_private(ip),
        Err(_) => {
            let d = host.trim_end_matches('.').to_ascii_lowercase();
            d.contains('.')
                && !(d == "localhost"
                    || d.ends_with(".localhost")
                    || d.ends_with(".local")
                    || d.ends_with(".internal")
                    || d.ends_with(".home.arpa")
                    || d.ends_with(".lan"))
        }
    };
    u.scheme() == "https"
        && host_ok
        && u.port().is_none_or(|p| p == 443)
        && u.username().is_empty()
        && u.password().is_none()
        && u.query().is_none()
        && u.fragment().is_none()
}

/// Résolveur qui écarte toute adresse non publique (passerelle désignée par l'API : pas de
/// requête vers le réseau interne de l'hébergeur, B1).
#[derive(Debug, Clone, Copy)]
pub struct PublicOnlyResolver;

impl reqwest::dns::Resolve for PublicOnlyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.filter(|a| !ip_is_private(a.ip())).collect();
            if addrs.is_empty() {
                return Err("proxy_private_address".into());
            }
            let addrs: reqwest::dns::Addrs = Box::new(addrs.into_iter());
            Ok(addrs)
        })
    }
}

/// URL de base admise : `https://…`, ou `http://` vers la boucle locale (développement, tests),
/// sans identifiants, requête ni fragment.
#[must_use]
pub fn base_url_allowed(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|u| {
        let loopback = matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        (u.scheme() == "https" || (u.scheme() == "http" && loopback))
            && u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none()
            && u.host_str().is_some()
    })
}

/// Couples (méthode, chemin) admis pour un fournisseur (I2) : chat et liste des modèles, chemins
/// relatifs à l'URL de base, **sans** chaîne de requête. API compatibles OpenAI : `POST
/// /chat/completions`, `GET /models` ; passerelle Synco : `POST /v1/chat/completions`, `GET /models`
/// (`Synco_AI_Gateway/src/app.rs`).
#[must_use]
pub fn allowed_request(provider: &str, method: &Method, path_and_query: &str) -> bool {
    let chat = if provider == "gateway" { "/v1/chat/completions" } else { "/chat/completions" };
    (method == Method::POST && path_and_query == chat) || (method == Method::GET && path_and_query == "/models")
}

fn refuse(status: StatusCode, code: &'static str) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], format!("{{\"error\":\"{code}\"}}")).into_response()
}

fn client(public_only: bool) -> Result<reqwest::Client, &'static str> {
    let mut b = reqwest::Client::builder()
        .timeout(TOTAL_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("synco-ai-runtime/", env!("CARGO_PKG_VERSION")));
    if public_only {
        b = b.dns_resolver(Arc::new(PublicOnlyResolver)).https_only(true).no_proxy();
    }
    b.build().map_err(|_| "llm_proxy_client")
}

impl LlmProxy {
    /// Mandataire avec les clés des fournisseurs (lues de la configuration, D1).
    pub fn new(secrets: BTreeMap<String, ProviderSecret>) -> Result<Arc<Self>, &'static str> {
        Ok(Arc::new(Self { http: client(false)?, public_http: client(true)?, secrets }))
    }

    /// Sert `route` sur `listener` jusqu'à l'abandon de la tâche rendue. Refus si l'URL de base
    /// n'est pas admise.
    pub fn serve(
        self: &Arc<Self>,
        listener: tokio::net::UnixListener,
        route: LlmRoute,
    ) -> Result<tokio::task::JoinHandle<()>, &'static str> {
        let ok = if route.provider == "gateway" {
            base_url_allowed(&route.base_url) || gateway_url_allowed(&route.base_url)
        } else {
            base_url_allowed(&route.base_url)
        };
        if !ok {
            return Err("llm_route_refused");
        }
        let ctx = Arc::new(RouteCtx {
            proxy: Arc::clone(self),
            base: route.base_url.trim_end_matches('/').to_owned(),
            route,
            in_flight: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT_PER_WORKER)),
        });
        let app = axum::Router::new().fallback(handle).layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES)).with_state(ctx);
        Ok(tokio::spawn(async move {
            if axum::serve(listener, app).await.is_err() {
                tracing::debug!(code = "llm_proxy_stopped", "mandataire LLM arrêté");
            }
        }))
    }

    fn bearer(&self, provider: &str) -> Option<HeaderValue> {
        let secret = self.secrets.get(provider)?;
        let mut raw = Zeroizing::new(Vec::with_capacity(secret.0.len().saturating_add(7)));
        raw.extend_from_slice(b"Bearer ");
        raw.extend_from_slice(&secret.0);
        let mut v = HeaderValue::from_bytes(&raw).ok()?;
        v.set_sensitive(true);
        Some(v)
    }
}

async fn handle(
    State(ctx): State<Arc<RouteCtx>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if method != Method::GET && method != Method::POST {
        return refuse(StatusCode::METHOD_NOT_ALLOWED, "proxy_method");
    }
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    if !allowed_request(&ctx.route.provider, &method, path) {
        return refuse(StatusCode::NOT_FOUND, "proxy_path");
    }
    let Ok(permit) = Arc::clone(&ctx.in_flight).try_acquire_owned() else {
        return refuse(StatusCode::TOO_MANY_REQUESTS, "proxy_busy");
    };
    let url = format!("{}{}", ctx.base, path);
    let gateway = ctx.route.provider == "gateway";
    let http = if gateway && !base_url_allowed(&ctx.route.base_url) { &ctx.proxy.public_http } else { &ctx.proxy.http };
    let mut req = http.request(if method == Method::POST { reqwest::Method::POST } else { reqwest::Method::GET }, url);
    for name in [header::CONTENT_TYPE, header::ACCEPT] {
        if let Some(v) = headers.get(&name) {
            req = req.header(name.as_str(), v.as_bytes());
        }
    }
    if gateway {
        if let Some(v) = headers.get(header::AUTHORIZATION) {
            let mut v = v.clone();
            v.set_sensitive(true);
            req = req.header(header::AUTHORIZATION.as_str(), v);
        }
    } else if let Some(v) = ctx.proxy.bearer(&ctx.route.provider) {
        req = req.header(header::AUTHORIZATION.as_str(), v);
    }
    if method == Method::POST {
        req = req.body(body);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            let code = if e.is_timeout() { "proxy_upstream_timeout" } else { "proxy_upstream_unreachable" };
            tracing::warn!(code, provider = %ctx.route.provider, "appel LLM relayé en échec");
            return refuse(StatusCode::BAD_GATEWAY, code);
        }
    };
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    tracing::debug!(code = "llm_proxy_response", status = status.as_u16(), provider = %ctx.route.provider, "appel LLM relayé");
    let mut out = Response::builder().status(status);
    for name in [header::CONTENT_TYPE, header::RETRY_AFTER] {
        if let Some(v) = resp.headers().get(name.as_str()) {
            out = out.header(name.as_str(), v.as_bytes());
        }
    }
    // Corps relayé en flux ; la place est rendue à la fin du corps.
    let stream = futures_util::stream::unfold(Some((resp, permit)), |state| async move {
        let (mut resp, permit) = state?;
        match resp.chunk().await {
            Ok(Some(b)) => Some((Ok::<Bytes, std::io::Error>(b), Some((resp, permit)))),
            Ok(None) => None,
            Err(_) => Some((Err(std::io::Error::other("proxy_upstream_body")), None)),
        }
    });
    out.body(Body::from_stream(stream)).unwrap_or_else(|_| refuse(StatusCode::BAD_GATEWAY, "proxy_response"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_de_passerelle_publique_seulement() {
        assert!(gateway_url_allowed("https://gateway.example.com"));
        assert!(gateway_url_allowed("https://gateway.example.com/"));
        for bad in [
            "http://gateway.example.com",
            "https://localhost",
            "https://127.0.0.1",
            "https://10.0.0.5",    // check-secrets:allow (adresse refusée par le test)
            "https://192.168.1.1", // check-secrets:allow (adresse refusée par le test)
            "https://172.16.0.1",  // check-secrets:allow (adresse refusée par le test)
            "https://169.254.169.254",
            "https://100.64.0.1",
            "https://[::1]",
            "https://[fd00::1]",
            "https://[fe80::1]",
            "https://[::ffff:127.0.0.1]",
            "https://metadata.google.internal", // check-secrets:allow (adresse refusée par le test)
            "https://nas.local",
            "https://intranet",
            "https://gateway.example.com:8443",
            "https://u:p@gateway.example.com",
            "https://gateway.example.com/?x=1",
        ] {
            assert!(!gateway_url_allowed(bad), "{bad}");
        }
        assert!(ip_is_private("169.254.169.254".parse().unwrap()));
        assert!(!ip_is_private("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn requetes_admises() {
        assert!(allowed_request("openai", &Method::POST, "/chat/completions"));
        assert!(allowed_request("openai", &Method::GET, "/models"));
        assert!(allowed_request("gateway", &Method::POST, "/v1/chat/completions"));
        assert!(!allowed_request("gateway", &Method::POST, "/chat/completions"));
        for (m, p) in [
            (Method::GET, "/files"),
            (Method::GET, "/files/abc/content"),
            (Method::GET, "/chat/completions?limit=100"),
            (Method::GET, "/chat/completions"),
            (Method::GET, "/organization/users"),
            (Method::GET, "/./files"),
            (Method::POST, "/models"),
            (Method::GET, "/models?x=1"),
            (Method::POST, "/chat/completions/"),
            (Method::POST, "//chat/completions"),
        ] {
            assert!(!allowed_request("openai", &m, p), "{m} {p}");
        }
    }

    #[test]
    fn urls_et_chemins() {
        assert!(base_url_allowed("https://api.openai.com/v1"));
        assert!(base_url_allowed("http://127.0.0.1:8080/v1"));
        assert!(!base_url_allowed("http://api.openai.com/v1"));
        assert!(!base_url_allowed("https://u:p@api.openai.com/v1"));
        assert!(!base_url_allowed("https://api.openai.com/v1?x=1"));
        assert!(!base_url_allowed("file:///etc/passwd"));
        assert!(!base_url_allowed(""));
    }
}
