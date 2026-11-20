//! Évènements runtime → client (docs/plan/05 §5), produits par le worker et diffusés par le
//! superviseur **sans être lus** : `epoch` = `leaseEpoch`, `seq` croissant à partir de 1, et tout
//! contenu chiffré par `CK` (05 §4) — deltas `ws:text:<epoch>:<seq>` / `ws:thinking:<epoch>:<seq>`,
//! arguments et résultats d'outils avec l'AAD des champs persistés, détail d'erreur `error:<e>:<s>`.

use runtime_protocol::pipe::{EventMsg, SnapshotMsg, WorkerMsg};
use serde_json::{Value, json};
use synco_e2ee::session::{self, ERROR_MESSAGE_ID, FieldName, SNAPSHOT_MESSAGE_ID};
use synco_e2ee::{OsRandom, SymmetricKey};

use crate::link::{Link, LinkError};
use crate::provider::Usage;
use crate::transcript::ToolCall;

/// Émetteur d'évènements d'une époque.
pub struct Emitter {
    link: Link,
    ck: SymmetricKey,
    sid: String,
    epoch: u64,
    seq: u64,
}

impl core::fmt::Debug for Emitter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Emitter").field("epoch", &self.epoch).field("seq", &self.seq).finish_non_exhaustive()
    }
}

/// Échec d'émission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitError {
    /// Pipe fermé.
    Closed,
    /// Chiffrement impossible (identifiant non conforme).
    Encode,
}

impl From<LinkError> for EmitError {
    fn from(_: LinkError) -> Self {
        Self::Closed
    }
}

impl Emitter {
    /// Émetteur de la conversation `sid` pour l'époque `epoch`.
    #[must_use]
    pub fn new(link: Link, ck: SymmetricKey, sid: &str, epoch: u64) -> Self {
        Self { link, ck, sid: sid.to_owned(), epoch, seq: 0 }
    }

    fn next(&mut self) -> u64 {
        self.seq = self.seq.saturating_add(1);
        self.seq
    }

    async fn send(&mut self, seq: u64, mut ev: Value) -> Result<(), EmitError> {
        if let Some(o) = ev.as_object_mut() {
            o.insert("v".into(), json!(1));
            o.insert("epoch".into(), json!(self.epoch));
            o.insert("seq".into(), json!(seq));
        }
        self.link.send(WorkerMsg::Event(EventMsg { event: ev })).await.map_err(EmitError::from)
    }

    fn enc(&self, mid: &str, field: &FieldName, text: &str) -> Result<String, EmitError> {
        session::encrypt_field(&self.ck, &self.sid, mid, field, text, &mut OsRandom).map_err(|_| EmitError::Encode)
    }

    fn enc_json(&self, mid: &str, field: &FieldName, v: &Value) -> Result<String, EmitError> {
        session::encrypt_json_field(&self.ck, &self.sid, mid, field, v, &mut OsRandom).map_err(|_| EmitError::Encode)
    }

    /// Morceau de réponse.
    pub async fn text(&mut self, message_id: &str, delta: &str) -> Result<(), EmitError> {
        let seq = self.next();
        let delta = self.enc(message_id, &FieldName::WsText { epoch: self.epoch, seq }, delta)?;
        self.send(seq, json!({ "t": "text", "messageId": message_id, "delta": delta })).await
    }

    /// Morceau de raisonnement.
    pub async fn thinking(&mut self, message_id: &str, delta: &str) -> Result<(), EmitError> {
        let seq = self.next();
        let delta = self.enc(message_id, &FieldName::WsThinking { epoch: self.epoch, seq }, delta)?;
        self.send(seq, json!({ "t": "thinking", "messageId": message_id, "delta": delta })).await
    }

    /// Appel d'outil créé ou changé d'état.
    pub async fn tool_call(&mut self, message_id: &str, tc: &ToolCall, interactive: bool) -> Result<(), EmitError> {
        let seq = self.next();
        let args = self.enc_json(message_id, &FieldName::ToolCallArguments(tc.id.clone()), &tc.arguments)?;
        self.send(
            seq,
            json!({
                "t": "tool_call", "messageId": message_id, "toolCallId": tc.id, "name": tc.name,
                "category": tc.category, "mutating": tc.mutating, "interactive": interactive,
                "status": tc.status.as_str(), "args": args,
            }),
        )
        .await
    }

    /// Résultat d'un outil (message `tool` d'id `message_id`).
    pub async fn tool_result(
        &mut self,
        message_id: &str,
        tool_call_id: &str,
        name: &str,
        result: &Value,
    ) -> Result<(), EmitError> {
        let seq = self.next();
        let result = self.enc_json(message_id, &FieldName::ToolResult, result)?;
        self.send(
            seq,
            json!({ "t": "tool_result", "messageId": message_id, "toolCallId": tool_call_id, "name": name, "result": result }),
        )
        .await
    }

    /// Changement d'état.
    pub async fn status(&mut self, status: &str, reason: Option<&str>) -> Result<(), EmitError> {
        let seq = self.next();
        let mut ev = json!({ "t": "status", "status": status });
        if let Some(r) = reason {
            crate::json_set(&mut ev, "reason", json!(r));
        }
        self.send(seq, ev).await
    }

    /// Usage d'un appel au fournisseur.
    pub async fn usage(&mut self, message_id: &str, u: &Usage) -> Result<(), EmitError> {
        let seq = self.next();
        let mut ev = json!({ "t": "usage", "messageId": message_id });
        for (k, v) in [
            ("promptTokens", u.prompt_tokens),
            ("completionTokens", u.completion_tokens),
            ("totalTokens", u.total_tokens),
            ("reasoningTokens", u.reasoning_tokens),
        ] {
            if let Some(v) = v {
                crate::json_set(&mut ev, k, json!(v));
            }
        }
        self.send(seq, ev).await
    }

    /// Erreur de la conversation (code clair, détail facultatif chiffré).
    pub async fn error(&mut self, code: &str, detail: Option<&str>) -> Result<(), EmitError> {
        let seq = self.next();
        let mut ev = json!({ "t": "error", "code": code });
        if let Some(d) = detail {
            crate::json_set(
                &mut ev,
                "detail",
                json!(self.enc(ERROR_MESSAGE_ID, &FieldName::ErrorDetail { epoch: self.epoch, seq }, d)?),
            );
        }
        self.send(seq, ev).await
    }

    /// Trame `snapshot` (05 §5.2) pour le client demandeur seulement.
    pub async fn snapshot(&mut self, request_id: &str, base_rev: u64, state: &Value) -> Result<(), EmitError> {
        let seq = self.next();
        let field = FieldName::Snapshot { epoch: self.epoch, seq };
        let enc = session::encrypt_json_field(&self.ck, &self.sid, SNAPSHOT_MESSAGE_ID, &field, state, &mut OsRandom)
            .map_err(|_| EmitError::Encode)?;
        let event =
            json!({ "v": 1, "t": "snapshot", "epoch": self.epoch, "seq": seq, "baseRev": base_rev, "state": enc });
        self.link
            .send(WorkerMsg::Snapshot(SnapshotMsg { request_id: request_id.to_owned(), event }))
            .await
            .map_err(EmitError::from)
    }
}
