//! Client du **mandataire LLM** du superviseur (docs/plan/10 §4), pour L07.
//!
//! Le worker n'a pas de réseau IP : ses appels au fournisseur LLM passent en HTTP/1.1 **clair**
//! sur le socket Unix de son bac à sable. Le superviseur relaie vers l'URL de base du fournisseur
//! configuré pour **cette** conversation (en TLS), ajoute lui-même la clé API (D1 : la clé ne
//! quitte jamais le superviseur) et renvoie la réponse en flux (SSE compris).
//!
//! Règles du mandataire (vérifiées côté superviseur) :
//!
//! - chemin = suffixe de l'URL de base du fournisseur (`/chat/completions`, `/models`…),
//!   méthodes `GET` et `POST` seulement, sans `..`, `//`, `%`, `#` ;
//! - en-têtes relayés : `content-type`, `accept` ; `authorization` **seulement** pour la passerelle
//!   (ticket `sgt1` obtenu par `signed_request` vers `POST /api/runtime/v1/tickets/llm`), retiré et
//!   remplacé par la clé du runtime pour les autres fournisseurs ;
//! - corps ≤ 32 Mio ; 120 s sans octet, 10 min au total ; pas de redirection suivie.
//!
//! Erreurs du mandataire : statut `4xx`/`5xx` avec un corps `{"error":"<code>"}` (`proxy_*`).

use std::path::Path;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper_util::rt::TokioIo;

/// Hôte annoncé au mandataire (ignoré par lui).
pub const PROXY_HOST: &str = "llm-proxy";

/// Requête vers le fournisseur LLM de la conversation.
#[derive(Clone)]
pub struct LlmRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl core::fmt::Debug for LlmRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Ni en-têtes (ticket) ni corps (contenu de la conversation).
        f.debug_struct("LlmRequest").field("method", &self.method).field("path", &self.path).finish_non_exhaustive()
    }
}

impl LlmRequest {
    /// `method` (`GET`, `POST`) et `path` relatif à l'URL de base du fournisseur.
    #[must_use]
    pub fn new(method: &str, path: &str) -> Self {
        Self { method: method.to_owned(), path: path.to_owned(), headers: Vec::new(), body: Vec::new() }
    }

    /// Ajoute un en-tête.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Corps.
    #[must_use]
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }
}

/// Échec d'un appel (code machine, sans contenu).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmError {
    /// Socket du mandataire injoignable.
    Connect,
    /// Requête mal formée.
    InvalidRequest,
    /// Échange HTTP interrompu.
    Protocol,
}

impl core::fmt::Display for LlmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Connect => "llm_proxy_unreachable",
            Self::InvalidRequest => "llm_invalid_request",
            Self::Protocol => "llm_protocol",
        })
    }
}

impl std::error::Error for LlmError {}

/// Réponse en flux.
pub struct LlmResponse {
    status: u16,
    headers: hyper::HeaderMap,
    body: hyper::body::Incoming,
    conn: tokio::task::JoinHandle<()>,
}

impl core::fmt::Debug for LlmResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LlmResponse").field("status", &self.status).finish_non_exhaustive()
    }
}

impl Drop for LlmResponse {
    fn drop(&mut self) {
        self.conn.abort();
    }
}

impl LlmResponse {
    /// Statut HTTP (celui du fournisseur, ou du mandataire pour ses refus `proxy_*`).
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// En-tête de réponse (`content-type`, `retry-after`).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// Prochain morceau du corps (`None` à la fin).
    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>, LlmError> {
        loop {
            match self.body.frame().await {
                None => return Ok(None),
                Some(Err(_)) => return Err(LlmError::Protocol),
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        return Ok(Some(data));
                    }
                }
            }
        }
    }
}

/// Envoie `req` au mandataire par le socket `socket` (une connexion par requête).
pub async fn send(socket: &Path, req: LlmRequest) -> Result<LlmResponse, LlmError> {
    let mut builder =
        hyper::Request::builder().method(req.method.as_str()).uri(req.path.as_str()).header("host", PROXY_HOST);
    for (k, v) in &req.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let request = builder.body(Full::new(Bytes::from(req.body))).map_err(|_| LlmError::InvalidRequest)?;
    let stream = tokio::net::UnixStream::connect(socket).await.map_err(|_| LlmError::Connect)?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|_| LlmError::Protocol)?;
    let conn = tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = match sender.send_request(request).await {
        Ok(r) => r,
        Err(_) => {
            conn.abort();
            return Err(LlmError::Protocol);
        }
    };
    let status = resp.status().as_u16();
    let (parts, body) = resp.into_parts();
    Ok(LlmResponse { status, headers: parts.headers, body, conn })
}
