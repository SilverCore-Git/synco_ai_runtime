//! Client du canal interne runtime → API (docs/plan/04) : chaque requête vers `/api/runtime/v1`
//! est signée Ed25519 par la clé `sig` (04 §2, `runtime_protocol::signing`), avec un nonce frais.
//!
//! Journaux (04 §7) : méthode, gabarit de route, code de résultat, durée, taille. Jamais le corps,
//! une enveloppe, un mandat, une entrée, une valeur `gcm1:` ni un ticket.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use runtime_protocol::api::{self as wire, CHANNEL_PREFIX, ErrorBody};
use runtime_protocol::signing::{self, RequestFields};
use serde::de::DeserializeOwned;
use synco_e2ee::encoding::b64u;
use synco_e2ee::{OsRandom, RandomSource};

use crate::clock::now_secs;

/// Plafond d'une réponse lue (historique ≤ 8 Mio, 09 §4).
pub const MAX_RESPONSE_BYTES: usize = 9 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);

/// Échec d'un appel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// Réseau, TLS, délai.
    Network,
    /// Réponse non 2xx avec, si présent, le code machine `{ "error": … }`.
    Status {
        /// Statut HTTP.
        status: u16,
        /// Code machine.
        code: Option<String>,
    },
    /// Réponse illisible ou trop grande.
    Decode,
    /// Requête refusée localement (chemin non conforme).
    Refused,
}

impl ApiError {
    /// Code machine de l'API, s'il y en a un.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Status { code, .. } => code.as_deref(),
            _ => None,
        }
    }

    /// Code machine **sûr à journaliser** : seulement `[a-z_]`, 48 caractères au plus ; autre chose
    /// (majuscules, chiffres, ponctuation, contrôles : texte libre d'un serveur qui n'est pas de
    /// confiance) devient `-`.
    #[must_use]
    pub fn loggable_code(&self) -> &str {
        self.code()
            .filter(|c| !c.is_empty() && c.len() <= 48 && c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
            .unwrap_or("-")
    }

    /// Statut HTTP, s'il y en a un.
    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::Status { status, .. } => Some(*status),
            _ => None,
        }
    }
}

impl core::fmt::Display for ApiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Network => f.write_str("réseau"),
            Self::Status { status, code } => write!(f, "{status} {}", code.as_deref().unwrap_or("-")),
            Self::Decode => f.write_str("réponse illisible"),
            Self::Refused => f.write_str("requête refusée localement"),
        }
    }
}

/// Réponse brute.
#[derive(Debug, Clone)]
pub struct RawResponse {
    /// Statut.
    pub status: u16,
    /// `content-type`.
    pub content_type: Option<String>,
    /// `retry-after` en secondes entières (les autres formes sont ignorées).
    pub retry_after: Option<String>,
    /// Corps.
    pub body: Vec<u8>,
}

/// `Retry-After` relayé au worker : secondes entières seulement (la date HTTP est ignorée).
fn retry_after_secs(v: &str) -> Option<String> {
    let v = v.trim();
    (!v.is_empty() && v.len() <= 6 && v.bytes().all(|b| b.is_ascii_digit())).then(|| v.to_owned())
}

/// Méthodes utilisées.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// GET.
    Get,
    /// POST.
    Post,
    /// PUT.
    Put,
    /// DELETE.
    Delete,
}

impl Method {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }

    fn reqwest(self) -> reqwest::Method {
        match self {
            Self::Get => reqwest::Method::GET,
            Self::Post => reqwest::Method::POST,
            Self::Put => reqwest::Method::PUT,
            Self::Delete => reqwest::Method::DELETE,
        }
    }
}

impl From<runtime_protocol::pipe::HttpMethod> for Method {
    fn from(m: runtime_protocol::pipe::HttpMethod) -> Self {
        use runtime_protocol::pipe::HttpMethod as H;
        match m {
            H::Get => Self::Get,
            H::Post => Self::Post,
            H::Put => Self::Put,
            H::Delete => Self::Delete,
        }
    }
}

/// Caractères admis dans un chemin du canal : ce que l'API compare octet pour octet (pas
/// d'encodage pourcent ni de normalisation possible entre la signature et l'envoi).
fn path_is_plain(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains("..")
        && !path.contains("//")
        && path.bytes().all(|b| b.is_ascii_alphanumeric() || b"/-_:.?=&".contains(&b))
}

/// Gabarit de route pour le journal : identifiants remplacés.
fn route_template(path: &str) -> String {
    let path = path.split('?').next().unwrap_or_default();
    path.split('/')
        .map(|seg| if seg.len() >= 16 || seg.bytes().filter(u8::is_ascii_digit).count() >= 4 { ":id" } else { seg })
        .collect::<Vec<_>>()
        .join("/")
}

/// Client signé.
#[derive(Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    base: String,
    runtime_id: String,
    sig: Arc<SigningKey>,
}

impl core::fmt::Debug for ApiClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApiClient")
            .field("base", &self.base)
            .field("runtime_id", &self.runtime_id)
            .finish_non_exhaustive()
    }
}

impl ApiClient {
    /// `base` : origine de l'API (config `api_url`, sans barre finale).
    pub fn new(base: &str, runtime_id: &str, sig: Arc<SigningKey>) -> Result<Self, ApiError> {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("synco-ai-runtime/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| ApiError::Network)?;
        Ok(Self { http, base: base.trim_end_matches('/').to_owned(), runtime_id: runtime_id.to_owned(), sig })
    }

    /// Origine de l'API.
    #[must_use]
    pub fn base(&self) -> &str {
        &self.base
    }

    /// `runtimeId`.
    #[must_use]
    pub fn runtime_id(&self) -> &str {
        &self.runtime_id
    }

    /// En-têtes signés d'une requête (utilisés aussi pour la mise à niveau du flux).
    pub fn signed_headers(
        &self,
        method: &str,
        path_and_query: &str,
        body: &[u8],
        auth_id: Option<&str>,
    ) -> Result<Vec<(&'static str, String)>, ApiError> {
        let mut nonce = [0u8; 16];
        OsRandom.fill(&mut nonce).map_err(|_| ApiError::Refused)?;
        let nonce = b64u(&nonce);
        let timestamp = now_secs().to_string();
        let fields = RequestFields {
            method,
            path: path_and_query,
            timestamp: &timestamp,
            nonce: &nonce,
            runtime_id: &self.runtime_id,
            auth_id,
            body,
        };
        Ok(signing::signature_headers(&fields, &self.sig))
    }

    /// Requête signée vers `path_and_query` (doit commencer par `/api/runtime/v1/`).
    pub async fn signed(
        &self,
        method: Method,
        path_and_query: &str,
        body: Option<Vec<u8>>,
        auth_id: Option<&str>,
    ) -> Result<RawResponse, ApiError> {
        if !path_and_query.starts_with(CHANNEL_PREFIX) || !path_is_plain(path_and_query) {
            return Err(ApiError::Refused);
        }
        let url = reqwest::Url::parse(&format!("{}{path_and_query}", self.base)).map_err(|_| ApiError::Refused)?;
        let sent = match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_owned(),
        };
        if sent != path_and_query {
            return Err(ApiError::Refused);
        }
        let body = body.unwrap_or_default();
        let headers = self.signed_headers(method.as_str(), path_and_query, &body, auth_id)?;
        let mut req = self.http.request(method.reqwest(), url);
        for (name, value) in headers {
            req = req.header(name, value);
        }
        if !body.is_empty() {
            req = req.header("content-type", "application/json").body(body);
        }
        let started = Instant::now();
        let result = self.send(req).await;
        let route = route_template(path_and_query);
        match &result {
            Ok(r) => tracing::debug!(
                method = method.as_str(),
                route = %route,
                status = r.status,
                bytes = r.body.len(),
                ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                "api"
            ),
            Err(e) => tracing::debug!(method = method.as_str(), route = %route, error = %e, "api"),
        }
        result
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<RawResponse, ApiError> {
        let mut resp = req.send().await.map_err(|_| ApiError::Network)?;
        let status = resp.status().as_u16();
        let content_type =
            resp.headers().get("content-type").and_then(|v| v.to_str().ok()).map(|s| s.chars().take(100).collect());
        let retry_after = resp.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(retry_after_secs);
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|_| ApiError::Network)? {
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(ApiError::Decode);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(RawResponse { status, content_type, retry_after, body })
    }

    fn check(r: RawResponse) -> Result<RawResponse, ApiError> {
        if (200..300).contains(&r.status) {
            Ok(r)
        } else {
            let code = serde_json::from_slice::<ErrorBody>(&r.body).ok().map(|e| e.error).filter(|c| c.len() <= 64);
            Err(ApiError::Status { status: r.status, code })
        }
    }

    async fn json<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        auth: Option<&str>,
    ) -> Result<T, ApiError> {
        let r = Self::check(self.signed(method, path, body, auth).await?)?;
        serde_json::from_slice(&r.body).map_err(|_| ApiError::Decode)
    }

    async fn no_content(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        auth: Option<&str>,
    ) -> Result<(), ApiError> {
        Self::check(self.signed(method, path, body, auth).await?).map(|_| ())
    }

    /// `GET /api/ai/ticket-keys` (public, non signé).
    pub async fn ticket_keys(&self) -> Result<wire::TicketKeysResponse, ApiError> {
        let req = self.http.get(format!("{}{}", self.base, wire::TICKET_KEYS_PATH));
        let r = Self::check(self.send(req).await?)?;
        serde_json::from_slice(&r.body).map_err(|_| ApiError::Decode)
    }

    /// `POST /register`.
    pub async fn register(&self, url: &str) -> Result<wire::RegisterResponse, ApiError> {
        let body = serde_json::to_vec(&wire::RegisterRequest {
            url,
            software: wire::Software { version: env!("CARGO_PKG_VERSION") },
        })
        .map_err(|_| ApiError::Decode)?;
        self.json(Method::Post, "/api/runtime/v1/register", Some(body), None).await
    }

    /// `POST /unpair`.
    pub async fn unpair(&self) -> Result<(), ApiError> {
        self.no_content(Method::Post, "/api/runtime/v1/unpair", None, None).await
    }

    /// `GET /llm-policy`.
    pub async fn llm_policy(&self) -> Result<wire::LlmPolicy, ApiError> {
        self.json(Method::Get, "/api/runtime/v1/llm-policy", None, None).await
    }

    /// `GET /delegations`.
    pub async fn delegations(&self) -> Result<Vec<wire::DelegationRecord>, ApiError> {
        self.json(Method::Get, "/api/runtime/v1/delegations", None, None).await
    }

    /// `GET /authorizations?state=active` (Q18), toutes les pages. `Ok(None)` si la liste est
    /// incomplète ou incohérente (curseur qui ne progresse pas, trop de pages) : l'appelant ne doit
    /// alors rien conclure d'une absence.
    pub async fn active_authorizations(&self) -> Result<Option<Vec<wire::ActiveAuthorization>>, ApiError> {
        /// Garde-fou : 500 par page, donc 100 000 autorisations au plus.
        const MAX_PAGES: usize = 200;
        let mut all = Vec::new();
        let mut after: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let path = match &after {
                Some(a) => format!("/api/runtime/v1/authorizations?state=active&after={a}&limit=500"),
                None => "/api/runtime/v1/authorizations?state=active&limit=500".to_owned(),
            };
            let page: wire::AuthorizationsPage = self.json(Method::Get, &path, None, None).await?;
            all.extend(page.authorizations);
            match page.next {
                None => return Ok(Some(all)),
                Some(next) if Some(&next) != after.as_ref() => after = Some(next),
                Some(_) => return Ok(None),
            }
        }
        Ok(None)
    }

    /// `POST /e2ee/threads/:threadId/key-envelope/repose` (S seule, Q21, spec API §14.8) : nouvelle
    /// pose de l'enveloppe `rt1` d'un salon réinitialisé. `body` est le corps JSON strict.
    pub async fn repose_envelope(&self, thread_id: &str, body: Vec<u8>) -> Result<(), ApiError> {
        self.no_content(
            Method::Post,
            &format!("/api/runtime/v1/e2ee/threads/{thread_id}/key-envelope/repose"),
            Some(body),
            None,
        )
        .await
    }

    /// `GET /e2ee/threads/envelope-resets?limit=&cursor=` (S seule, L03f, spec API §14.8) : une page
    /// des réinitialisations d'enveloppe en attente. Le contenu n'est pas de confiance.
    pub async fn envelope_resets(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<wire::EnvelopeResetsPage, ApiError> {
        let path = match cursor {
            Some(c) => format!("/api/runtime/v1/e2ee/threads/envelope-resets?limit={limit}&cursor={c}"),
            None => format!("/api/runtime/v1/e2ee/threads/envelope-resets?limit={limit}"),
        };
        self.json(Method::Get, &path, None, None).await
    }

    /// `GET /delegations/:id/entries`.
    pub async fn entries(&self, delegation_id: &str, after: Option<&str>) -> Result<wire::EntriesPage, ApiError> {
        let path = match after {
            Some(a) => format!("/api/runtime/v1/delegations/{delegation_id}/entries?after={a}&limit=500"),
            None => format!("/api/runtime/v1/delegations/{delegation_id}/entries?limit=500"),
        };
        self.json(Method::Get, &path, None, None).await
    }

    /// `POST /delegations/:id/status` : `ok` ou `unusable`, **sans cause** (03 §12).
    pub async fn delegation_status(&self, delegation_id: &str, usable: bool) -> Result<(), ApiError> {
        let body = if usable { br#"{"status":"ok"}"#.to_vec() } else { br#"{"status":"unusable"}"#.to_vec() };
        self.no_content(Method::Post, &format!("/api/runtime/v1/delegations/{delegation_id}/status"), Some(body), None)
            .await
    }

    /// `GET /users/:userId/sign-key`.
    pub async fn sign_key(&self, user_id: &str) -> Result<wire::SignKeyResponse, ApiError> {
        self.json(Method::Get, &format!("/api/runtime/v1/users/{user_id}/sign-key"), None, None).await
    }

    /// `GET /conversations?state=pending`.
    pub async fn pending(&self) -> Result<Vec<wire::PendingConversation>, ApiError> {
        self.json(Method::Get, "/api/runtime/v1/conversations?state=pending", None, None).await
    }

    /// `GET /conversations/:sessionId` (en-tête seulement : révision, statut, bail).
    pub async fn conversation_head(&self, session_id: &str, auth_id: &str) -> Result<wire::ConversationHead, ApiError> {
        self.json(Method::Get, &format!("/api/runtime/v1/conversations/{session_id}"), None, Some(auth_id)).await
    }

    /// `POST /conversations/:sessionId/lease` (corps vide : prise du bail).
    pub async fn take_lease(&self, session_id: &str, auth_id: &str) -> Result<wire::LeaseResponse, ApiError> {
        self.json(Method::Post, &format!("/api/runtime/v1/conversations/{session_id}/lease"), None, Some(auth_id)).await
    }

    /// `DELETE /conversations/:sessionId/lease`.
    pub async fn release_lease(&self, session_id: &str, auth_id: &str, lease_epoch: u64) -> Result<(), ApiError> {
        let body = format!(r#"{{"leaseEpoch":{lease_epoch}}}"#).into_bytes();
        self.no_content(
            Method::Delete,
            &format!("/api/runtime/v1/conversations/{session_id}/lease"),
            Some(body),
            Some(auth_id),
        )
        .await
    }

    /// `POST /conversations/:sessionId/status` (garde-fou `worker_crash_loop`, 08 §5).
    pub async fn write_status(
        &self,
        session_id: &str,
        auth_id: &str,
        lease_epoch: u64,
        status: &str,
        error: Option<&str>,
    ) -> Result<(), ApiError> {
        let mut body = serde_json::json!({ "leaseEpoch": lease_epoch, "status": status });
        if let (Some(e), Some(obj)) = (error, body.as_object_mut()) {
            obj.insert("error".into(), serde_json::Value::from(e));
        }
        let bytes = serde_json::to_vec(&body).map_err(|_| ApiError::Decode)?;
        self.no_content(
            Method::Post,
            &format!("/api/runtime/v1/conversations/{session_id}/status"),
            Some(bytes),
            Some(auth_id),
        )
        .await
    }

    /// `POST /conversations/:sessionId/inbox` : dépôt durable (idempotent par `id`) **avant**
    /// l'accusé `queued` au client (05 §5.4).
    pub async fn deposit_inbox(
        &self,
        session_id: &str,
        auth_id: &str,
        frame: &serde_json::Value,
    ) -> Result<(), ApiError> {
        let body = serde_json::to_vec(frame).map_err(|_| ApiError::Decode)?;
        self.no_content(
            Method::Post,
            &format!("/api/runtime/v1/conversations/{session_id}/inbox"),
            Some(body),
            Some(auth_id),
        )
        .await
    }

    /// `POST /metrics` (≤ 1 / min).
    pub async fn metrics(&self, workers: usize, queued: usize) -> Result<(), ApiError> {
        let body = serde_json::to_vec(&serde_json::json!({
            "workers": workers, "queued": queued, "version": env!("CARGO_PKG_VERSION"),
        }))
        .map_err(|_| ApiError::Decode)?;
        self.no_content(Method::Post, "/api/runtime/v1/metrics", Some(body), None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_secondes_entieres_seulement() {
        assert_eq!(retry_after_secs(" 12 ").as_deref(), Some("12"));
        for bad in ["", "-1", "1.5", "Wed, 21 Oct 2026 07:28:00 GMT", "1234567", "1 2"] {
            assert_eq!(retry_after_secs(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn code_journalise_restreint() {
        let status = |c: &str| ApiError::Status { status: 409, code: Some(c.to_owned()) };
        assert_eq!(status("envelope_exists").loggable_code(), "envelope_exists");
        for bad in ["Envelope", "a1", "a b", "a\nb", "<script>", "", &"a".repeat(49)] {
            assert_eq!(status(bad).loggable_code(), "-", "{bad:?}");
        }
        assert_eq!(ApiError::Network.loggable_code(), "-");
    }

    #[test]
    fn chemins() {
        assert!(path_is_plain("/api/runtime/v1/conversations?state=pending"));
        assert!(path_is_plain("/api/runtime/v1/delegations/d1/entries?after=e1&limit=500"));
        for bad in ["/api/runtime/v1/../x", "/api/runtime/v1//x", "/api/runtime/v1/a%2Fb", "/api/runtime/v1/a b", "x"] {
            assert!(!path_is_plain(bad), "{bad}");
        }
        assert_eq!(
            route_template("/api/runtime/v1/conversations/0f0e0d0c-0b0a-4908-8706-050403020100/status"),
            "/api/runtime/v1/conversations/:id/status"
        );
    }
}
