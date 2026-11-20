//! Mandataire LLM du superviseur (docs/plan/10 §4) : **seul accès réseau** d'un worker isolé.
//!
//! Un socket Unix par worker (`<run_dir>/w-<n>/llm.sock`, monté en lecture seule dans le bac à sable
//! sous `/run/synco/`). Le worker y parle HTTP/1.1 clair ; le mandataire relaie vers l'URL de base
//! du fournisseur **de cette conversation** (et d'aucun autre hôte), en TLS, sans suivre de
//! redirection, et :
//!
//! - pour `openai`, `mistral`, `gemini`, `custom` : retire tout `authorization` du worker et ajoute
//!   `Authorization: Bearer <clé>` depuis la configuration du runtime (D1) ; la clé ne passe jamais
//!   par le pipe ni par le worker ;
//! - pour `gateway` : relaie l'`authorization` du worker (ticket `sgt1` obtenu par
//!   `signed_request`, 02 §4), la passerelle n'ayant pas de clé.
//!
//! Aucun corps ni en-tête n'est journalisé.

use std::collections::BTreeMap;
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

/// Chemin demandé par le worker (suffixe de l'URL de base) : ASCII visible, commence par `/`, sans
/// `..`, `//`, `%`, `#`, `\`.
#[must_use]
pub fn path_allowed(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 2048
        && !path.contains("..")
        && !path.contains("//")
        && path.bytes().all(|b| b.is_ascii_graphic() && !b"%#\\".contains(&b))
}

fn refuse(status: StatusCode, code: &'static str) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], format!("{{\"error\":\"{code}\"}}")).into_response()
}

impl LlmProxy {
    /// Mandataire avec les clés des fournisseurs (lues de la configuration, D1).
    pub fn new(secrets: BTreeMap<String, ProviderSecret>) -> Result<Arc<Self>, &'static str> {
        let http = reqwest::Client::builder()
            .timeout(TOTAL_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("synco-ai-runtime/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| "llm_proxy_client")?;
        Ok(Arc::new(Self { http, secrets }))
    }

    /// Sert `route` sur `listener` jusqu'à l'abandon de la tâche rendue. Refus si l'URL de base
    /// n'est pas admise.
    pub fn serve(
        self: &Arc<Self>,
        listener: tokio::net::UnixListener,
        route: LlmRoute,
    ) -> Result<tokio::task::JoinHandle<()>, &'static str> {
        if !base_url_allowed(&route.base_url) {
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
    if !path_allowed(path) {
        return refuse(StatusCode::BAD_REQUEST, "proxy_path");
    }
    let Ok(permit) = Arc::clone(&ctx.in_flight).try_acquire_owned() else {
        return refuse(StatusCode::TOO_MANY_REQUESTS, "proxy_busy");
    };
    let url = format!("{}{}", ctx.base, path);
    let mut req =
        ctx.proxy.http.request(if method == Method::POST { reqwest::Method::POST } else { reqwest::Method::GET }, url);
    for name in [header::CONTENT_TYPE, header::ACCEPT] {
        if let Some(v) = headers.get(&name) {
            req = req.header(name.as_str(), v.as_bytes());
        }
    }
    if ctx.route.provider == "gateway" {
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
    fn urls_et_chemins() {
        assert!(base_url_allowed("https://api.openai.com/v1"));
        assert!(base_url_allowed("http://127.0.0.1:8080/v1"));
        assert!(!base_url_allowed("http://api.openai.com/v1"));
        assert!(!base_url_allowed("https://u:p@api.openai.com/v1"));
        assert!(!base_url_allowed("https://api.openai.com/v1?x=1"));
        assert!(!base_url_allowed("file:///etc/passwd"));
        assert!(!base_url_allowed(""));
        assert!(path_allowed("/chat/completions"));
        assert!(path_allowed("/models?limit=10"));
        for bad in ["chat", "/../x", "//evil.example.com/x", "/a%2e%2e", "/a#b", "/a b", "/a\\b"] {
            assert!(!path_allowed(bad), "{bad}");
        }
    }
}
