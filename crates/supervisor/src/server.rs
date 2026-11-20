//! Endpoints publics du runtime (relatifs à `public_url`, servis derrière le mandataire TLS) :
//!
//! | Route | Rôle | Spec |
//! |---|---|---|
//! | `GET /v1/identity` | fiche publique (clés, empreinte, org) | 01 §4 |
//! | `POST /v1/challenge` | défi de possession (`kex` et `csk`) | 01 §5 |
//! | `GET /v1/conversations/:sessionId/ws` | WebSocket client | 05 |
//!
//! CORS limité aux origines configurées ; le WebSocket refuse (`403`) une autre origine.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State, WebSocketUpgrade};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use runtime_protocol::client::MAX_CLIENT_FRAME_BYTES;
use runtime_protocol::ids::is_identifier;
use synco_e2ee::runtime_cert::{ChallengeRequest, respond_challenge};
use tokio::sync::Mutex;

use crate::ratelimit::{KeyedWindows, Window};
use crate::runtime::Runtime;

/// Corps maximal d'un défi (01 §5).
pub const MAX_CHALLENGE_BODY: usize = 4 * 1024;

/// État des routes publiques.
pub struct ServerState {
    rt: Arc<Runtime>,
    per_ip: Mutex<KeyedWindows>,
    global: Mutex<Window>,
    unauthenticated: Arc<PreAuth>,
}

/// WebSocket non encore authentifiés (avant le `hello` vérifié) simultanés, pour tout le runtime.
pub const MAX_UNAUTHENTICATED_TOTAL: usize = 256;
/// … et par adresse.
pub const MAX_UNAUTHENTICATED_PER_IP: usize = 8;

/// Compteur des connexions non authentifiées (global et par adresse).
#[derive(Debug, Default)]
pub struct PreAuth {
    inner: std::sync::Mutex<(usize, std::collections::HashMap<String, usize>)>,
}

/// Place réservée ; libérée à la destruction (après le `hello` vérifié, ou à la fermeture).
#[derive(Debug)]
pub struct PreAuthSlot {
    owner: Arc<PreAuth>,
    ip: String,
}

impl PreAuth {
    /// Réserve une place pour `ip`, ou `None` si un plafond est atteint.
    pub fn acquire(self: &Arc<Self>, ip: &str) -> Option<PreAuthSlot> {
        let mut g = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (total, by_ip) = &mut *g;
        let current = by_ip.get(ip).copied().unwrap_or(0);
        if *total >= MAX_UNAUTHENTICATED_TOTAL || current >= MAX_UNAUTHENTICATED_PER_IP {
            return None;
        }
        *total = total.saturating_add(1);
        by_ip.insert(ip.to_owned(), current.saturating_add(1));
        Some(PreAuthSlot { owner: Arc::clone(self), ip: ip.to_owned() })
    }

    /// Places occupées.
    #[must_use]
    pub fn total(&self) -> usize {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).0
    }
}

impl Drop for PreAuthSlot {
    fn drop(&mut self) {
        let mut g = self.owner.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (total, by_ip) = &mut *g;
        *total = total.saturating_sub(1);
        if let Some(n) = by_ip.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                by_ip.remove(&self.ip);
            }
        }
    }
}

impl core::fmt::Debug for ServerState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerState").finish_non_exhaustive()
    }
}

/// Construit le routeur public.
pub fn router(rt: Arc<Runtime>) -> Router {
    let state = Arc::new(ServerState {
        rt,
        // 09 §4 : 10 / min par adresse, 60 / min au total.
        per_ip: Mutex::new(KeyedWindows::new(10, Duration::from_secs(60), 10_000)),
        global: Mutex::new(Window::new(60, Duration::from_secs(60))),
        unauthenticated: Arc::new(PreAuth::default()),
    });
    Router::new()
        .route("/v1/identity", get(identity).options(preflight))
        .route("/v1/challenge", axum::routing::post(challenge).options(preflight))
        .route("/v1/conversations/{session_id}/ws", get(conversation_ws))
        .layer(DefaultBodyLimit::max(MAX_CHALLENGE_BODY))
        .layer(middleware::from_fn_with_state(Arc::clone(&state), cors))
        .with_state(state)
}

fn allowed_origin<'a>(rt: &Runtime, headers: &'a HeaderMap) -> Option<&'a str> {
    let origin = headers.get(header::ORIGIN)?.to_str().ok()?;
    rt.config.allowed_origins.iter().any(|o| o == origin).then_some(origin)
}

async fn cors(State(state): State<Arc<ServerState>>, req: axum::extract::Request, next: Next) -> Response {
    let origin = allowed_origin(&state.rt, req.headers()).and_then(|o| HeaderValue::from_str(o).ok());
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::VARY, HeaderValue::from_static("Origin"));
    if let Some(o) = origin {
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, o);
    }
    resp
}

async fn preflight(State(state): State<Arc<ServerState>>, headers: HeaderMap) -> Response {
    if allowed_origin(&state.rt, &headers).is_none() {
        return StatusCode::FORBIDDEN.into_response();
    }
    (
        StatusCode::NO_CONTENT,
        [
            (header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS"),
            (header::ACCESS_CONTROL_ALLOW_HEADERS, "content-type"),
            (header::ACCESS_CONTROL_MAX_AGE, "600"),
        ],
    )
        .into_response()
}

fn json(status: StatusCode, value: &serde_json::Value) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "no-store")], value.to_string())
        .into_response()
}

async fn identity(State(state): State<Arc<ServerState>>) -> Response {
    let org = state.rt.org_id().await;
    json(StatusCode::OK, &state.rt.keys.identity_json(&state.rt.config.public_url, org.as_deref()))
}

/// Adresse du client : `X-Forwarded-For` lu à `trust_proxy_hops` depuis la droite (comme Express),
/// sinon l'adresse de la connexion.
#[must_use]
pub fn client_address(peer: SocketAddr, headers: &HeaderMap, trust_proxy_hops: usize) -> String {
    if trust_proxy_hops == 0 {
        return peer.ip().to_string();
    }
    let chain: Vec<IpAddr> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    // Moins d'en-têtes que de mandataires annoncés : on ne remonte jamais au-delà de l'entrée la
    // plus à droite (ajoutée par notre mandataire) — la plus à gauche peut être forgée par le client.
    let index = chain.len().checked_sub(trust_proxy_hops);
    index.and_then(|i| chain.get(i)).or_else(|| chain.last()).copied().unwrap_or_else(|| peer.ip()).to_string()
}

async fn challenge(
    State(state): State<Arc<ServerState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ip = client_address(peer, &headers, state.rt.config.listen.trust_proxy_hops);
    let now = Instant::now();
    let allowed = state.per_ip.lock().await.hit(&ip, now) && state.global.lock().await.hit(now);
    if !allowed {
        return json(StatusCode::TOO_MANY_REQUESTS, &serde_json::json!({ "error": "challenge_rate_limited" }));
    }
    let invalid = || json(StatusCode::BAD_REQUEST, &serde_json::json!({ "error": "challenge_invalid" }));
    let Ok(text) = core::str::from_utf8(&body) else { return invalid() };
    let Ok(request) = ChallengeRequest::from_json(text) else { return invalid() };
    let keys = &state.rt.keys;
    match respond_challenge(&request, keys.runtime_id(), keys.fingerprint_hex(), keys.kex(), keys.csk()) {
        Ok(r) => json(
            StatusCode::OK,
            &serde_json::json!({ "v": 1, "runtimeId": keys.runtime_id(), "mac": r.mac_b64u(), "sig": r.sig_b64u() }),
        ),
        Err(_) => invalid(),
    }
}

async fn conversation_ws(
    State(state): State<Arc<ServerState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    method: Method,
    ws: Result<WebSocketUpgrade, axum::extract::ws::rejection::WebSocketUpgradeRejection>,
) -> Response {
    // L'origine est contrôlée avant toute mise à niveau (05 §1.2).
    if allowed_origin(&state.rt, &headers).is_none() {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !is_identifier(&session_id) || method != Method::GET {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(ws) = ws else { return StatusCode::UPGRADE_REQUIRED.into_response() };
    let ip = client_address(peer, &headers, state.rt.config.listen.trust_proxy_hops);
    let Some(slot) = state.unauthenticated.acquire(&ip) else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let rt = Arc::clone(&state.rt);
    ws.max_message_size(MAX_CLIENT_FRAME_BYTES)
        .max_frame_size(MAX_CLIENT_FRAME_BYTES)
        .on_upgrade(move |socket| crate::client_ws::handle(rt, session_id, socket, slot))
}

/// Sert le routeur public jusqu'à l'arrêt.
pub async fn serve(rt: Arc<Runtime>, listener: tokio::net::TcpListener) -> std::io::Result<()> {
    let mut shutdown = rt.shutdown.subscribe();
    let app = router(rt).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            crate::runtime::stopped(&mut shutdown).await;
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adresse_du_client() {
        let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let mut h = HeaderMap::new();
        assert_eq!(client_address(peer, &h, 1), "127.0.0.1");
        h.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.9, 198.51.100.7"));
        assert_eq!(
            client_address(peer, &h, 1),
            "198.51.100.7",
            "le dernier saut ajouté par le mandataire de confiance"
        );
        assert_eq!(client_address(peer, &h, 2), "203.0.113.9");
        assert_eq!(client_address(peer, &h, 0), "127.0.0.1");
        assert_eq!(client_address(peer, &h, 5), "198.51.100.7", "jamais l'entrée la plus à gauche, forgeable");
    }

    #[test]
    fn connexions_non_authentifiees_bornees() {
        let p = Arc::new(PreAuth::default());
        let slots: Vec<_> = (0..MAX_UNAUTHENTICATED_PER_IP).map(|_| p.acquire("a").unwrap()).collect();
        assert!(p.acquire("a").is_none(), "plafond par adresse");
        let other = p.acquire("b").unwrap();
        drop(slots);
        assert_eq!(p.total(), 1);
        assert!(p.acquire("a").is_some());
        drop(other);
    }
}
