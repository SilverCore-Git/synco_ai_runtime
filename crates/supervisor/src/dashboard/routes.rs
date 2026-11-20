//! Routes HTTP du dashboard (docs/plan/11). Un garde unique entoure **tout** le routeur : toute
//! route ou chemin inconnu répond `401` sans session, sauf la liste fermée [`PUBLIC`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::Json;
use axum::Router;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use runtime_protocol::ids::is_identifier;
use serde::{Deserialize, Serialize};

use super::auth::{ABSOLUTE_TIMEOUT, Auth, Login};
use super::history::History;
use super::host::{HostLoad, HostSampler};
use super::query::{self, Activity, Costs, Filter, GroupBy};
use crate::clock::now_secs;
use crate::launcher::BoxFuture;

/// Nom du cookie de session.
pub const COOKIE: &str = "synco_dash";
/// Corps maximal d'une requête (la connexion tient en quelques dizaines d'octets).
pub const MAX_BODY: usize = 1024;

/// Seules routes sans session : la page de connexion, ses deux fichiers statiques, et l'envoi du mot
/// de passe. Le test d'intégration compare cette liste à la liste attendue.
pub const PUBLIC: [(&str, &str); 4] =
    [("GET", "/login"), ("GET", "/assets/login.js"), ("GET", "/assets/style.css"), ("POST", "/api/login")];

/// Toutes les routes déclarées (méthode, chemin ; `{id}` = paramètre), pour le test d'énumération.
pub const ROUTES: [(&str, &str); 11] = [
    ("GET", "/"),
    ("GET", "/login"),
    ("GET", "/assets/login.js"),
    ("GET", "/assets/style.css"),
    ("GET", "/assets/app.js"),
    ("POST", "/api/login"),
    ("POST", "/api/logout"),
    ("GET", "/api/session"),
    ("GET", "/api/overview"),
    ("GET", "/api/sessions"),
    ("GET", "/api/totals"),
];
/// Route paramétrée supplémentaire : `GET /api/sessions/{id}`.
pub const DETAIL_ROUTE: &str = "/api/sessions/";

/// Ce que le superviseur fournit à la vue d'ensemble (aucun contenu).
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OverviewData {
    /// Version du superviseur.
    pub version: String,
    /// Identifiant du runtime.
    pub runtime_id: String,
    /// Empreinte (mesure 4), groupée par 4.
    pub fingerprint: String,
    /// Code d'appairage, tant que le runtime n'est pas appairé.
    pub pairing_code: Option<String>,
    /// Appairé.
    pub paired: bool,
    /// Organisation.
    pub org_id: Option<String>,
    /// Flux de notifications de l'API ouvert.
    pub api_connected: bool,
    /// Lanceur de workers.
    pub launcher: String,
    /// Workers actifs.
    pub active_workers: u64,
    /// Plafond de workers.
    pub max_workers: u64,
    /// Conversations en attente.
    pub queued: u64,
    /// Alertes récentes : (horodatage, code).
    pub alerts: Vec<(u64, String)>,
}

/// Source de la vue d'ensemble (le superviseur en fonctionnement ; un double dans les tests).
pub trait OverviewSource: Send + Sync + 'static {
    /// État courant.
    fn overview(&self) -> BoxFuture<'_, OverviewData>;
}

/// État partagé des routes.
pub struct DashboardState {
    /// Historique.
    pub history: Arc<History>,
    /// Authentification.
    pub auth: Arc<Auth>,
    /// Vue d'ensemble.
    pub source: Arc<dyn OverviewSource>,
    /// Hôtes admis dans `Host` (en plus de l'adresse d'écoute et de localhost).
    pub allowed_hosts: Vec<String>,
    /// Mandataires de confiance (`X-Forwarded-For`, `X-Forwarded-Proto`).
    pub trust_proxy_hops: usize,
    /// Adresse d'écoute effective.
    pub listen: SocketAddr,
    host: HostSampler,
}

impl core::fmt::Debug for DashboardState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DashboardState").field("listen", &self.listen).finish_non_exhaustive()
    }
}

impl DashboardState {
    /// Assemble l'état.
    #[must_use]
    pub fn new(
        history: Arc<History>,
        auth: Arc<Auth>,
        source: Arc<dyn OverviewSource>,
        allowed_hosts: Vec<String>,
        trust_proxy_hops: usize,
        listen: SocketAddr,
    ) -> Arc<Self> {
        Arc::new(Self { history, auth, source, allowed_hosts, trust_proxy_hops, listen, host: HostSampler::default() })
    }

    fn host_allowed(&self, host: &str) -> bool {
        let port = self.listen.port();
        let local = [format!("localhost:{port}"), format!("127.0.0.1:{port}"), format!("[::1]:{port}")];
        host == self.listen.to_string()
            || local.iter().any(|h| h == host)
            || self.allowed_hosts.iter().any(|h| h == host)
    }
}

type Shared = Arc<DashboardState>;

fn security_headers(h: &mut HeaderMap) {
    let set = |h: &mut HeaderMap, k: &'static str, v: &'static str| {
        h.insert(HeaderName::from_static(k), HeaderValue::from_static(v));
    };
    set(
        h,
        "content-security-policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; \
         form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    );
    set(h, "x-content-type-options", "nosniff");
    set(h, "x-frame-options", "DENY");
    set(h, "referrer-policy", "no-referrer");
    set(h, "cache-control", "no-store");
    set(h, "cross-origin-resource-policy", "same-origin");
    set(h, "cross-origin-opener-policy", "same-origin");
    set(h, "permissions-policy", "camera=(), microphone=(), geolocation=()");
}

fn json_error(status: StatusCode, code: &str) -> Response {
    (status, Json(serde_json::json!({ "error": code }))).into_response()
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|p| p.trim().strip_prefix(COOKIE)?.strip_prefix('='))
        .find(|t| {
            !t.is_empty() && t.len() <= 64 && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .map(str::to_owned)
}

fn is_https(state: &DashboardState, headers: &HeaderMap) -> bool {
    state.trust_proxy_hops > 0
        && headers
            .get_all("x-forwarded-proto")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .next_back()
            .is_some_and(|p| p.trim().eq_ignore_ascii_case("https"))
}

fn session_cookie(token: &str, max_age: u64, secure: bool) -> String {
    format!(
        "{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}

/// `Origin` d'une requête qui modifie quelque chose : doit être présent et égal à `Host`.
fn origin_matches(headers: &HeaderMap) -> bool {
    let (Some(origin), Some(host)) = (
        headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()),
        headers.get(header::HOST).and_then(|v| v.to_str().ok()),
    ) else {
        return false;
    };
    origin.strip_prefix("http://").or_else(|| origin.strip_prefix("https://")) == Some(host)
}

/// Garde de tout le routeur : hôte, session, origine et CSRF, puis en-têtes de sécurité.
async fn guard(State(state): State<Shared>, req: Request, next: Next) -> Response {
    let mut resp = guard_inner(&state, req, next).await;
    security_headers(resp.headers_mut());
    resp
}

async fn guard_inner(state: &Shared, req: Request, next: Next) -> Response {
    let headers = req.headers();
    let host_ok = headers.get(header::HOST).and_then(|v| v.to_str().ok()).is_some_and(|h| state.host_allowed(h));
    if !host_ok {
        return json_error(StatusCode::FORBIDDEN, "host_refused");
    }
    let public = PUBLIC.iter().any(|(m, p)| req.method().as_str() == *m && req.uri().path() == *p);
    let csrf = if public {
        None
    } else {
        match cookie_token(headers).and_then(|t| state.auth.check(&t, Instant::now())) {
            Some(c) => Some(c),
            None => return json_error(StatusCode::UNAUTHORIZED, "unauthenticated"),
        }
    };
    let mutating = !matches!(*req.method(), Method::GET | Method::HEAD);
    if mutating {
        if !origin_matches(headers) {
            return json_error(StatusCode::FORBIDDEN, "origin_refused");
        }
        if let Some(expected) = csrf
            && headers.get("x-csrf-token").and_then(|v| v.to_str().ok()) != Some(expected.as_str())
        {
            return json_error(StatusCode::FORBIDDEN, "csrf_refused");
        }
    }
    next.run(req).await
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

async fn login_page() -> Response {
    asset("text/html; charset=utf-8", include_str!("assets/login.html"))
}
async fn login_js() -> Response {
    asset("text/javascript; charset=utf-8", include_str!("assets/login.js"))
}
async fn style_css() -> Response {
    asset("text/css; charset=utf-8", include_str!("assets/style.css"))
}
async fn app_js() -> Response {
    asset("text/javascript; charset=utf-8", include_str!("assets/app.js"))
}
async fn index() -> Response {
    asset("text/html; charset=utf-8", include_str!("assets/index.html"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginBody {
    password: String,
}

async fn login(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<LoginBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(body)) = body else { return json_error(StatusCode::BAD_REQUEST, "bad_request") };
    let ip = crate::server::client_address(peer, &headers, state.trust_proxy_hops);
    match state.auth.login(&body.password, &ip, Instant::now()).await {
        Login::Ok { token, csrf } => {
            let cookie = session_cookie(&token, ABSOLUTE_TIMEOUT.as_secs(), is_https(&state, &headers));
            ([(header::SET_COOKIE, cookie)], Json(serde_json::json!({ "csrf": csrf }))).into_response()
        }
        Login::Invalid => json_error(StatusCode::UNAUTHORIZED, "invalid_credentials"),
        Login::Limited(secs) => {
            let mut r = json_error(StatusCode::TOO_MANY_REQUESTS, "too_many_attempts");
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                r.headers_mut().insert(header::RETRY_AFTER, v);
            }
            r
        }
        Login::Unavailable => json_error(StatusCode::SERVICE_UNAVAILABLE, "login_unavailable"),
    }
}

async fn logout(State(state): State<Shared>, headers: HeaderMap) -> Response {
    if let Some(t) = cookie_token(&headers) {
        state.auth.logout(&t);
    }
    let cookie = session_cookie("", 0, is_https(&state, &headers));
    ([(header::SET_COOKIE, cookie)], Json(serde_json::json!({ "ok": true }))).into_response()
}

async fn session(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let csrf = cookie_token(&headers).and_then(|t| state.auth.check(&t, Instant::now()));
    Json(serde_json::json!({ "csrf": csrf })).into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Overview {
    #[serde(flatten)]
    runtime: OverviewData,
    now: u64,
    costs: Costs,
    activity: Activity,
    host: HostLoad,
    retention_days: u32,
}

async fn overview(State(state): State<Shared>) -> Response {
    let now = now_secs();
    let o = Overview {
        runtime: state.source.overview().await,
        now,
        costs: query::costs(&state.history, now),
        activity: query::activity(&state.history),
        host: state.host.sample(),
        retention_days: state.history.retention_days(),
    };
    Json(o).into_response()
}

async fn sessions(
    State(state): State<Shared>,
    filter: Result<Query<Filter>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Ok(Query(filter)) = filter else { return json_error(StatusCode::BAD_REQUEST, "bad_query") };
    Json(query::list(&state.history, &filter, now_secs())).into_response()
}

async fn session_detail(State(state): State<Shared>, Path(id): Path<String>) -> Response {
    if !is_identifier(&id) {
        return json_error(StatusCode::NOT_FOUND, "not_found");
    }
    match query::detail(&state.history, &id, now_secs()) {
        Some(d) => Json(d).into_response(),
        None => json_error(StatusCode::NOT_FOUND, "not_found"),
    }
}

#[derive(Deserialize)]
struct TotalsQuery {
    by: GroupBy,
    from: Option<u64>,
    to: Option<u64>,
}

async fn totals(
    State(state): State<Shared>,
    q: Result<Query<TotalsQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Ok(Query(q)) = q else { return json_error(StatusCode::BAD_REQUEST, "bad_query") };
    Json(query::totals(&state.history, q.by, q.from, q.to, now_secs())).into_response()
}

async fn fallback() -> Response {
    json_error(StatusCode::NOT_FOUND, "not_found")
}

/// Construit le routeur, le garde en dernière couche (donc autour de tout, fallback compris).
pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/login", get(login_page))
        .route("/assets/login.js", get(login_js))
        .route("/assets/style.css", get(style_css))
        .route("/assets/app.js", get(app_js))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/session", get(session))
        .route("/api/overview", get(overview))
        .route("/api/sessions", get(sessions))
        .route("/api/sessions/{id}", get(session_detail))
        .route("/api/totals", get(totals))
        .fallback(fallback)
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(Arc::clone(&state), guard))
        .with_state(state)
}

/// Sert le dashboard jusqu'à la fin de `shutdown`.
pub async fn serve(
    state: Shared,
    listener: tokio::net::TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let app = router(state).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app).with_graceful_shutdown(shutdown).await
}
