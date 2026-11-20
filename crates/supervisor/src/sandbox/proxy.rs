//! Mandataire LLM du superviseur (docs/plan/10 §4) : **seul accès réseau** d'un worker isolé.
//!
//! Un socket Unix par worker (`<run_dir>/w-<n>/llm.sock`, monté en lecture seule dans le bac à sable
//! sous `/run/synco/`). Le worker y parle HTTP/1.1 clair ; le mandataire relaie vers l'URL de base
//! du fournisseur **de cette conversation** (et d'aucun autre hôte), en TLS, sans suivre de
//! redirection, et :
//!
//! - n'accepte que deux requêtes (I2) : `POST` du chemin de chat et `GET` de la liste des modèles
//!   ([`allowed_request`]), sans chaîne de requête ;
//! - pour `openai`, `mistral`, `gemini`, `custom` : retire tout `authorization` du worker et ajoute
//!   `Authorization: Bearer <clé>` depuis la configuration du runtime (D1), clé cherchée avec le même
//!   identifiant que l'URL (B1, `Runtime::build_init`) ;
//! - pour `gateway` : relaie l'`authorization` du worker (ticket `sgt1`), n'ajoute aucune clé, et ne
//!   joint qu'une adresse **publique** (résolveur [`PublicOnlyResolver`]) ;
//! - borne la mémoire qu'un worker peut lui faire consommer (I1) : 4 connexions par socket, place
//!   prise **avant** la lecture du corps, corps ≤ [`MAX_REQUEST_BYTES`] lu en 30 s au plus, octets en
//!   tampon plafonnés par worker et pour tout le runtime ;
//! - applique les quotas de D6 (I3) : débit d'appels, appels et tokens par tour (fenêtre
//!   `maxTurnDurationSecs`), tokens sur la vie du worker, débit et tokens pour tout le runtime ;
//!   tokens comptés d'après `usage` renvoyé par le fournisseur, sinon estimés (octets / 4) ; durée
//!   d'un appel ≤ min(`maxTurnDurationSecs`, 10 min).
//!
//! Refus : statut HTTP et corps `{"error":"proxy_<code>"}`, sans appel au fournisseur. Aucun corps ni
//! en-tête n'est journalisé.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use http_body_util::BodyExt as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::config::ProviderSecret;
use crate::launcher::{LlmBudget, LlmRoute};
use crate::ratelimit::TokenBucket;

/// Corps de requête maximal : l'historique d'une conversation est plafonné à 8 Mio sérialisés
/// (09 §4) ; une requête de chat (historique, définitions d'outils, résultats d'outils ≤ 256 Kio
/// chacun) n'a aucune raison légitime de le dépasser. La passerelle accepte 1 Mio.
pub const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
/// Connexions simultanées par socket de worker (une requête à la fois par connexion HTTP/1.1).
pub const MAX_CONNECTIONS_PER_WORKER: usize = 4;
/// Octets de corps de requête en tampon pour un worker.
pub const WORKER_BUFFER_BYTES: usize = 16 * 1024 * 1024;
/// Octets de corps de requête en tampon pour tout le runtime.
pub const GLOBAL_BUFFER_BYTES: usize = 64 * 1024 * 1024;
/// Délai de lecture d'un corps de requête.
pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Silence maximal de l'amont (09 §2).
pub const READ_TIMEOUT: Duration = Duration::from_secs(120);
/// Durée totale maximale d'un appel (09 §2).
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(600);
/// Débit d'appels par worker (par seconde, rafale).
pub const WORKER_CALLS_PER_SEC: (u32, u32) = (2, 5);
/// Corps de réponse JSON gardé pour y lire `usage`.
const USAGE_JSON_MAX: usize = 1024 * 1024;
/// Ligne SSE gardée pour y lire `usage`.
const USAGE_LINE_MAX: usize = 256 * 1024;

/// Quotas pour tout le runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeQuota {
    /// Appels par seconde (tous workers).
    pub calls_per_sec: u32,
    /// Rafale.
    pub calls_burst: u32,
    /// Tokens par heure (tous workers).
    pub tokens_per_hour: u64,
}

impl RuntimeQuota {
    /// Depuis la configuration : 8 workers × 300 000 tokens par tour (30 min) → 2 tours par heure
    /// pour chacun.
    #[must_use]
    pub fn from_config(config: &crate::config::Config) -> Self {
        let l = &config.limits;
        let workers = u64::try_from(l.max_workers).unwrap_or(u64::MAX);
        let turns_per_hour = 3_600u64.checked_div(l.max_turn_duration_secs).unwrap_or(1).max(1);
        Self {
            calls_per_sec: 20,
            calls_burst: 40,
            tokens_per_hour: workers.saturating_mul(l.max_tokens_per_turn).saturating_mul(turns_per_hour),
        }
    }
}

impl Default for RuntimeQuota {
    fn default() -> Self {
        Self { calls_per_sec: 20, calls_burst: 40, tokens_per_hour: 8 * 300_000 * 2 }
    }
}

#[derive(Debug)]
struct Window {
    start: Instant,
    calls: u64,
    tokens: u64,
}

impl Window {
    fn roll(&mut self, now: Instant, len: Duration) {
        if now.saturating_duration_since(self.start) >= len {
            *self = Self { start: now, calls: 0, tokens: 0 };
        }
    }
}

#[derive(Debug)]
struct RuntimeState {
    bucket: TokenBucket,
    hour: Window,
}

/// Mandataire partagé (clés des fournisseurs, clients HTTP, quotas et tampons du runtime).
pub struct LlmProxy {
    http: reqwest::Client,
    public_http: reqwest::Client,
    secrets: BTreeMap<String, ProviderSecret>,
    quota: RuntimeQuota,
    runtime: Mutex<RuntimeState>,
    global_bytes: Arc<Semaphore>,
}

impl core::fmt::Debug for LlmProxy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LlmProxy").field("providers_with_key", &self.secrets.len()).finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct WorkerQuota {
    bucket: TokenBucket,
    turn: Window,
    tokens_total: u64,
}

struct RouteCtx {
    proxy: Arc<LlmProxy>,
    route: LlmRoute,
    base: String,
    bytes: Arc<Semaphore>,
    quota: Mutex<WorkerQuota>,
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

/// URL de base admise pour un fournisseur **configuré dans le runtime** : `https://…`, ou `http://`
/// vers la boucle locale (développement, tests), sans identifiants, requête ni fragment.
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

/// Connexion comptée (sa place est rendue à la fermeture).
struct LimitedConn {
    io: tokio::net::UnixStream,
    _permit: OwnedSemaphorePermit,
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

/// Écouteur qui n'accepte une connexion que s'il reste une place (les suivantes attendent dans la
/// file du noyau).
struct LimitedListener {
    inner: tokio::net::UnixListener,
    slots: Arc<Semaphore>,
}

impl axum::serve::Listener for LimitedListener {
    type Io = LimitedConn;
    type Addr = tokio::net::unix::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Ok(permit) = Arc::clone(&self.slots).acquire_owned().await else {
                // Sémaphore jamais fermé ; par prudence, on ralentit.
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            };
            match self.inner.accept().await {
                Ok((io, addr)) => return (LimitedConn { io, _permit: permit }, addr),
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

impl LlmProxy {
    /// Mandataire avec les clés des fournisseurs (lues de la configuration, D1).
    pub fn new(secrets: BTreeMap<String, ProviderSecret>, quota: RuntimeQuota) -> Result<Arc<Self>, &'static str> {
        Ok(Arc::new(Self {
            http: client(false)?,
            public_http: client(true)?,
            secrets,
            quota,
            runtime: Mutex::new(RuntimeState {
                bucket: TokenBucket::new(quota.calls_per_sec, quota.calls_burst),
                hour: Window { start: Instant::now(), calls: 0, tokens: 0 },
            }),
            global_bytes: Arc::new(Semaphore::new(GLOBAL_BUFFER_BYTES)),
        }))
    }

    /// Sert `route` sur `listener` jusqu'à l'abandon de la tâche rendue. Refus si l'URL de base
    /// n'est pas admise (passerelle : [`gateway_url_allowed`] ou URL configurée).
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
        let (rate, burst) = WORKER_CALLS_PER_SEC;
        let ctx = Arc::new(RouteCtx {
            proxy: Arc::clone(self),
            base: route.base_url.trim_end_matches('/').to_owned(),
            route,
            bytes: Arc::new(Semaphore::new(WORKER_BUFFER_BYTES)),
            quota: Mutex::new(WorkerQuota {
                bucket: TokenBucket::new(rate, burst),
                turn: Window { start: Instant::now(), calls: 0, tokens: 0 },
                tokens_total: 0,
            }),
        });
        let app = axum::Router::new().fallback(handle).with_state(ctx);
        let listener = LimitedListener { inner: listener, slots: Arc::new(Semaphore::new(MAX_CONNECTIONS_PER_WORKER)) };
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

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn estimate_tokens(bytes: usize) -> u64 {
    u64::try_from(bytes / 4).unwrap_or(u64::MAX)
}

/// Vérifie les quotas et réserve l'appel ; `Err` = code de refus (429).
fn admit(ctx: &RouteCtx, body_len: usize) -> Result<(), &'static str> {
    let now = Instant::now();
    let b: LlmBudget = ctx.route.budget;
    let estimate = estimate_tokens(body_len).saturating_add(b.max_output_tokens_per_call);
    let mut rt = lock(&ctx.proxy.runtime);
    rt.hour.roll(now, Duration::from_secs(3_600));
    if rt.hour.tokens.saturating_add(estimate) > ctx.proxy.quota.tokens_per_hour {
        return Err("proxy_runtime_token_budget");
    }
    let mut q = lock(&ctx.quota);
    q.turn.roll(now, Duration::from_secs(b.max_turn_duration_secs.max(1)));
    if q.turn.calls >= b.max_steps_per_turn {
        return Err("proxy_call_budget");
    }
    if q.turn.tokens.saturating_add(estimate) > b.max_tokens_per_turn
        || q.tokens_total.saturating_add(estimate) > b.max_tokens_per_conversation
    {
        return Err("proxy_token_budget");
    }
    if !q.bucket.take(now) {
        return Err("proxy_rate_limited");
    }
    if !rt.bucket.take(now) {
        return Err("proxy_runtime_rate_limited");
    }
    q.turn.calls = q.turn.calls.saturating_add(1);
    rt.hour.calls = rt.hour.calls.saturating_add(1);
    Ok(())
}

fn charge(ctx: &RouteCtx, tokens: u64) {
    let mut q = lock(&ctx.quota);
    q.turn.tokens = q.turn.tokens.saturating_add(tokens);
    q.tokens_total = q.tokens_total.saturating_add(tokens);
    drop(q);
    let mut rt = lock(&ctx.proxy.runtime);
    rt.hour.tokens = rt.hour.tokens.saturating_add(tokens);
}

/// Lit `usage` (`total_tokens`, sinon `prompt_tokens + completion_tokens`) dans un objet JSON.
#[must_use]
pub fn usage_tokens(v: &serde_json::Value) -> Option<u64> {
    let u = v.get("usage")?;
    u.get("total_tokens").and_then(serde_json::Value::as_u64).or_else(|| {
        let p = u.get("prompt_tokens").and_then(serde_json::Value::as_u64)?;
        let c = u.get("completion_tokens").and_then(serde_json::Value::as_u64).unwrap_or(0);
        Some(p.saturating_add(c))
    })
}

/// Compteur d'une réponse : octets relayés et `usage` repéré (lignes SSE `data: {…}` ou corps JSON
/// entier, chacun borné). Facture à la fin du flux ou à son abandon.
struct Meter {
    ctx: Arc<RouteCtx>,
    req_bytes: usize,
    resp_bytes: usize,
    line: Vec<u8>,
    line_overflow: bool,
    json: Option<Vec<u8>>,
    usage: Option<u64>,
}

impl Meter {
    fn feed(&mut self, chunk: &[u8]) {
        self.resp_bytes = self.resp_bytes.saturating_add(chunk.len());
        if let Some(j) = &mut self.json {
            if j.len().saturating_add(chunk.len()) <= USAGE_JSON_MAX {
                j.extend_from_slice(chunk);
            } else {
                self.json = None;
            }
        }
        for &b in chunk {
            if b == b'\n' {
                if !self.line_overflow {
                    let line = std::mem::take(&mut self.line);
                    self.scan_line(&line);
                }
                self.line.clear();
                self.line_overflow = false;
            } else if self.line.len() < USAGE_LINE_MAX {
                self.line.push(b);
            } else {
                self.line_overflow = true;
            }
        }
    }

    fn scan_line(&mut self, line: &[u8]) {
        let Some(data) = line.strip_prefix(b"data:") else { return };
        if !data.windows(7).any(|w| w == b"\"usage\"") {
            return;
        }
        if let Some(t) =
            serde_json::from_slice::<serde_json::Value>(data.trim_ascii()).ok().as_ref().and_then(usage_tokens)
        {
            self.usage = Some(self.usage.map_or(t, |u| u.max(t)));
        }
    }

    fn tokens(&self) -> u64 {
        let from_json = self
            .json
            .as_deref()
            .and_then(|j| serde_json::from_slice::<serde_json::Value>(j).ok())
            .as_ref()
            .and_then(usage_tokens);
        // Estimation bornée si le fournisseur ne renvoie pas `usage` : (requête + réponse) / 4.
        self.usage.or(from_json).unwrap_or_else(|| estimate_tokens(self.req_bytes.saturating_add(self.resp_bytes)))
    }
}

impl Drop for Meter {
    fn drop(&mut self) {
        let tokens = self.tokens();
        charge(&self.ctx, tokens);
    }
}

/// Lit le corps en réservant ses octets (par worker et pour le runtime) au fil de l'eau.
async fn read_body(
    ctx: &RouteCtx,
    body: Body,
) -> Result<(Bytes, Vec<OwnedSemaphorePermit>), (StatusCode, &'static str)> {
    let mut body = body;
    let mut buf = Vec::new();
    let mut permits = Vec::new();
    let read = async {
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| (StatusCode::BAD_REQUEST, "proxy_body"))?;
            let Ok(data) = frame.into_data() else { continue };
            if buf.len().saturating_add(data.len()) > MAX_REQUEST_BYTES {
                return Err((StatusCode::PAYLOAD_TOO_LARGE, "proxy_body_too_large"));
            }
            let n = u32::try_from(data.len()).map_err(|_| (StatusCode::PAYLOAD_TOO_LARGE, "proxy_body_too_large"))?;
            if n > 0 {
                let w = Arc::clone(&ctx.bytes)
                    .try_acquire_many_owned(n)
                    .map_err(|_| (StatusCode::TOO_MANY_REQUESTS, "proxy_busy"))?;
                let g = Arc::clone(&ctx.proxy.global_bytes)
                    .try_acquire_many_owned(n)
                    .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "proxy_busy"))?;
                permits.push(w);
                permits.push(g);
            }
            buf.extend_from_slice(&data);
        }
        Ok(())
    };
    match tokio::time::timeout(BODY_READ_TIMEOUT, read).await {
        Ok(Ok(())) => Ok((Bytes::from(buf), permits)),
        Ok(Err(e)) => Err(e),
        Err(_) => Err((StatusCode::REQUEST_TIMEOUT, "proxy_body_timeout")),
    }
}

async fn handle(State(ctx): State<Arc<RouteCtx>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    if parts.method != Method::GET && parts.method != Method::POST {
        return refuse(StatusCode::METHOD_NOT_ALLOWED, "proxy_method");
    }
    if !allowed_request(&ctx.route.provider, &parts.method, path) {
        return refuse(StatusCode::NOT_FOUND, "proxy_path");
    }
    let declared =
        parts.headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > MAX_REQUEST_BYTES) {
        return refuse(StatusCode::PAYLOAD_TOO_LARGE, "proxy_body_too_large");
    }
    let (body, permits) = match read_body(&ctx, body).await {
        Ok(b) => b,
        Err((status, code)) => return refuse(status, code),
    };
    if let Err(code) = admit(&ctx, body.len()) {
        tracing::info!(code, provider = %ctx.route.provider, "appel LLM refusé (quota)");
        return refuse(StatusCode::TOO_MANY_REQUESTS, code);
    }
    let gateway = ctx.route.provider == "gateway";
    let http = if gateway && !base_url_allowed(&ctx.route.base_url) { &ctx.proxy.public_http } else { &ctx.proxy.http };
    let url = format!("{}{}", ctx.base, path);
    let method = if parts.method == Method::POST { reqwest::Method::POST } else { reqwest::Method::GET };
    let timeout = TOTAL_TIMEOUT.min(Duration::from_secs(ctx.route.budget.max_turn_duration_secs.max(1)));
    let mut up = http.request(method, url).timeout(timeout);
    for name in [header::CONTENT_TYPE, header::ACCEPT] {
        if let Some(v) = parts.headers.get(&name) {
            up = up.header(name.as_str(), v.as_bytes());
        }
    }
    if gateway {
        if let Some(v) = parts.headers.get(header::AUTHORIZATION) {
            let mut v = v.clone();
            v.set_sensitive(true);
            up = up.header(header::AUTHORIZATION.as_str(), v);
        }
    } else if let Some(v) = ctx.proxy.bearer(&ctx.route.provider) {
        up = up.header(header::AUTHORIZATION.as_str(), v);
    }
    let req_bytes = body.len();
    if parts.method == Method::POST {
        up = up.body(body);
    }
    let resp = match up.send().await {
        Ok(r) => r,
        Err(e) => {
            let code = if e.is_timeout() { "proxy_upstream_timeout" } else { "proxy_upstream_unreachable" };
            tracing::warn!(code, provider = %ctx.route.provider, "appel LLM relayé en échec");
            return refuse(StatusCode::BAD_GATEWAY, code);
        }
    };
    // Corps de la requête envoyé : ses octets ne sont plus en tampon.
    drop(permits);
    let mut meter = Meter {
        ctx: Arc::clone(&ctx),
        req_bytes,
        resp_bytes: 0,
        line: Vec::new(),
        line_overflow: false,
        json: None,
        usage: None,
    };
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    tracing::debug!(code = "llm_proxy_response", status = status.as_u16(), provider = %ctx.route.provider, "appel LLM relayé");
    let mut out = Response::builder().status(status);
    let is_json = resp
        .headers()
        .get(header::CONTENT_TYPE.as_str())
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    if is_json {
        meter.json = Some(Vec::new());
    }
    for name in [header::CONTENT_TYPE, header::RETRY_AFTER] {
        if let Some(v) = resp.headers().get(name.as_str()) {
            out = out.header(name.as_str(), v.as_bytes());
        }
    }
    // Corps relayé en flux ; tokens facturés à la fin (ou à l'abandon) par `Meter`.
    let stream = futures_util::stream::unfold(Some((resp, meter)), |state| async move {
        let (mut resp, mut meter) = state?;
        match resp.chunk().await {
            Ok(Some(b)) => {
                meter.feed(&b);
                Some((Ok::<Bytes, std::io::Error>(b), Some((resp, meter))))
            }
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
    fn urls() {
        assert!(base_url_allowed("https://api.openai.com/v1"));
        assert!(base_url_allowed("http://127.0.0.1:8080/v1"));
        assert!(!base_url_allowed("http://api.openai.com/v1"));
        assert!(!base_url_allowed("https://u:p@api.openai.com/v1"));
        assert!(!base_url_allowed("https://api.openai.com/v1?x=1"));
        assert!(!base_url_allowed("file:///etc/passwd"));
        assert!(!base_url_allowed(""));
    }

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
    fn lecture_de_usage() {
        let v: serde_json::Value = serde_json::from_str(r#"{"usage":{"total_tokens":42}}"#).unwrap();
        assert_eq!(usage_tokens(&v), Some(42));
        let v: serde_json::Value =
            serde_json::from_str(r#"{"usage":{"prompt_tokens":10,"completion_tokens":5}}"#).unwrap();
        assert_eq!(usage_tokens(&v), Some(15));
        assert_eq!(usage_tokens(&serde_json::json!({})), None);
    }
}
