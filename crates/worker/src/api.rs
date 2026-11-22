//! Appels du worker vers l'API, tous par `signed_request` (docs/plan/04 §4.2, §4.3, §5) : le
//! superviseur signe, le worker n'a aucune clé du runtime (mesure 7).

use runtime_protocol::pipe::HttpMethod;
use serde_json::Value;

use crate::link::{Link, LinkError};

/// Réponse de l'API.
#[derive(Clone)]
pub struct ApiResponse {
    /// Statut HTTP (`0` : relais en échec).
    pub status: u16,
    /// Corps JSON (`Null` s'il est vide ou illisible).
    pub body: Value,
    /// Code `relay_*` si `status = 0`.
    pub relay_error: Option<String>,
    /// `retry-after` de l'API (secondes), s'il est présent.
    pub retry_after: Option<u64>,
}

impl core::fmt::Debug for ApiResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApiResponse").field("status", &self.status).field("code", &self.code()).finish_non_exhaustive()
    }
}

impl ApiResponse {
    /// 2xx.
    #[must_use]
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Code machine : `{"error":"<code>"}` de l'API, ou code `relay_*`.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        self.relay_error.as_deref().or_else(|| self.body.get("error").and_then(Value::as_str))
    }
}

/// Client de l'API pour **la** conversation du worker.
#[derive(Debug, Clone)]
pub struct Api {
    link: Link,
    session_id: String,
}

/// Préfixe du canal.
pub const PREFIX: &str = "/api/runtime/v1";

impl Api {
    /// Client pour `session_id`.
    #[must_use]
    pub fn new(link: Link, session_id: &str) -> Self {
        Self { link, session_id: session_id.to_owned() }
    }

    /// Liaison sous-jacente.
    #[must_use]
    pub const fn link(&self) -> &Link {
        &self.link
    }

    /// Chemin d'une route de la conversation.
    #[must_use]
    pub fn conv_path(&self, suffix: &str) -> String {
        format!("{PREFIX}/conversations/{}{suffix}", self.session_id)
    }

    /// Requête brute ; `x-synco-auth` toujours présent (toutes les routes du worker sont S+A).
    pub async fn call(&self, method: HttpMethod, path: &str, body: Option<&Value>) -> Result<ApiResponse, LinkError> {
        let bytes = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
        let r = self.link.request(method, path, &bytes, true).await?;
        let body = if r.body.is_empty() { Value::Null } else { serde_json::from_slice(&r.body).unwrap_or(Value::Null) };
        Ok(ApiResponse { status: r.status, body, relay_error: r.error, retry_after: r.retry_after })
    }

    /// Requête sur une route de la conversation.
    pub async fn conv(&self, method: HttpMethod, suffix: &str, body: Option<&Value>) -> Result<ApiResponse, LinkError> {
        let path = self.conv_path(suffix);
        self.call(method, &path, body).await
    }
}
