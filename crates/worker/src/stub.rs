//! Bouchon de worker (L05) : parle le protocole du pipe (docs/plan/06) sans boucle d'agent.
//!
//! Déroulement : `init` → `ready` → trames de clés → `start` ; statut `running` (évènement et
//! `POST …/status`) ; lecture de la boîte (`GET …/inbox`) ; pour chaque message, un évènement
//! `text` chiffré par `CK` (AAD `ws:text:<epoch>:<seq>`) ; historique réécrit
//! (`PUT …/transcript`, éléments consommés) ; statut `idle` ; attente d'autres éléments jusqu'à
//! `idleShutdownSecs` (bail renouvelé toutes les 20 s) ; bail rendu ; `done`.
//!
//! Toutes les requêtes vers l'API passent par `signed_request` : le worker n'a aucune clé du
//! runtime (mesure 7). Aucun contenu n'est journalisé.

use std::collections::VecDeque;
use std::time::Duration;

use runtime_protocol::pipe::{
    self, DoneMsg, DoneReason, EventMsg, Frame, HttpMethod, InboxAckMsg, Init, KeyFrame, KeyKind, KeyOp,
    MAX_RELAY_RESPONSE_BYTES, Metrics, PipeError, ReadyMsg, Reassembly, SignedRequest, SnapshotMsg, StatusMsg,
    SupervisorMsg, WorkerMsg,
};
use serde_json::{Value, json};
use synco_e2ee::session::{self, FieldName, SNAPSHOT_MESSAGE_ID};
use synco_e2ee::{OsRandom, RandomSource, SymmetricKey};
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};

/// Texte fixe de la réponse du bouchon.
pub const STUB_REPLY: &str = "Réponse du bouchon de worker (L05) : la boucle d'agent arrive avec L07.";
const LEASE_RENEW: Duration = Duration::from_secs(20);

/// Réponse relayée, réassemblée.
struct Relayed {
    status: u16,
    body: Vec<u8>,
}

struct Stub<S> {
    rd: ReadHalf<S>,
    wr: WriteHalf<S>,
    init: Init,
    ck: Option<SymmetricKey>,
    seq: u64,
    next_id: u64,
    queued: VecDeque<SupervisorMsg>,
    status: &'static str,
    rev: u64,
}

fn random_id() -> String {
    let mut b = [0u8; 16];
    let _ = OsRandom.fill(&mut b);
    runtime_protocol::ids::uuid_v4_from_bytes(b)
}

/// Lance le bouchon sur le pipe `io`. Renvoie la raison de fin.
pub async fn run<S: AsyncRead + AsyncWrite + Send + Unpin>(io: S) -> Result<DoneReason, PipeError> {
    let (mut rd, mut wr) = tokio::io::split(io);
    let init = match pipe::read_frame(&mut rd).await? {
        Frame::Json(j) => match pipe::decode_json::<SupervisorMsg>(&j)? {
            SupervisorMsg::Init(init) => *init,
            _ => return Err(PipeError::BadMessage),
        },
        Frame::Keys(_) => return Err(PipeError::BadMessage),
    };
    pipe::write_json(
        &mut wr,
        &WorkerMsg::Ready(ReadyMsg { pid: std::process::id(), version: env!("CARGO_PKG_VERSION").into() }),
    )
    .await?;
    let mut stub =
        Stub { rd, wr, init, ck: None, seq: 0, next_id: 0, queued: VecDeque::new(), status: "queued", rev: 0 };
    // Clés initiales jusqu'à `start`.
    loop {
        match pipe::read_frame(&mut stub.rd).await? {
            Frame::Keys(k) => stub.apply_keys(&k)?,
            Frame::Json(j) => match pipe::decode_json::<SupervisorMsg>(&j)? {
                SupervisorMsg::Start(_) => break,
                SupervisorMsg::Shutdown(_) => return stub.finish(DoneReason::Shutdown).await,
                _ => return Err(PipeError::BadMessage),
            },
        }
    }
    if stub.ck.is_none() {
        stub.log("warn", "conv_key_missing").await?;
        return stub.finish(DoneReason::Failed).await;
    }
    stub.main().await
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> Stub<S> {
    fn apply_keys(&mut self, payload: &[u8]) -> Result<(), PipeError> {
        let frame = KeyFrame::decode(payload)?;
        for e in frame.entries {
            if e.kind == KeyKind::Conv && e.reference == self.init.session_id {
                self.ck = match frame.op {
                    KeyOp::Add => Some(SymmetricKey::from_slice(&e.key).map_err(|_| PipeError::BadKeys)?),
                    KeyOp::Remove => None,
                };
            }
        }
        Ok(())
    }

    async fn send(&mut self, msg: &WorkerMsg) -> Result<(), PipeError> {
        pipe::write_json(&mut self.wr, msg).await
    }

    async fn log(&mut self, level: &str, code: &str) -> Result<(), PipeError> {
        self.send(&WorkerMsg::Log(pipe::LogMsg { level: level.into(), code: code.into(), fields: Default::default() }))
            .await
    }

    fn next_seq(&mut self) -> u64 {
        self.seq = self.seq.saturating_add(1);
        self.seq
    }

    async fn event(&mut self, mut event: Value) -> Result<(), PipeError> {
        let seq = self.next_seq();
        if let Some(obj) = event.as_object_mut() {
            obj.insert("v".into(), Value::from(1));
            obj.insert("epoch".into(), Value::from(self.init.lease_epoch));
            obj.insert("seq".into(), Value::from(seq));
        }
        self.send(&WorkerMsg::Event(EventMsg { event })).await
    }

    /// Requête signée par le superviseur (corps et réponse en parties de ≤ 512 Kio) ; les messages
    /// reçus entre-temps sont mis de côté.
    async fn call(
        &mut self,
        method: HttpMethod,
        path: &str,
        body: Option<Value>,
        with_auth: bool,
    ) -> Result<Relayed, PipeError> {
        self.next_id = self.next_id.saturating_add(1);
        let id = format!("r{}", self.next_id);
        let bytes = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
        for part in SignedRequest::split(&id, method, path, &bytes, with_auth) {
            self.send(&WorkerMsg::SignedRequest(part)).await?;
        }
        let mut body = Reassembly::default();
        loop {
            match self.read_msg().await? {
                SupervisorMsg::SignedRequestResponse(r) if r.id == id => {
                    if body.push(r.part, &r.body, MAX_RELAY_RESPONSE_BYTES).is_err() {
                        return Ok(Relayed { status: 0, body: Vec::new() });
                    }
                    if r.last {
                        return Ok(Relayed { status: r.status, body: body.into_body() });
                    }
                }
                other => self.queued.push_back(other),
            }
        }
    }

    async fn read_msg(&mut self) -> Result<SupervisorMsg, PipeError> {
        loop {
            match pipe::read_frame(&mut self.rd).await? {
                Frame::Keys(k) => self.apply_keys(&k)?,
                Frame::Json(j) => return pipe::decode_json(&j),
            }
        }
    }

    fn conv_path(&self, suffix: &str) -> String {
        format!("/api/runtime/v1/conversations/{}{suffix}", self.init.session_id)
    }

    async fn set_status(&mut self, status: &'static str) -> Result<bool, PipeError> {
        let path = self.conv_path("/status");
        let r = self
            .call(HttpMethod::Post, &path, Some(json!({ "leaseEpoch": self.init.lease_epoch, "status": status })), true)
            .await?;
        self.status = status;
        self.event(json!({ "t": "status", "status": status })).await?;
        self.send(&WorkerMsg::Status(StatusMsg { status: status.into(), reason: None })).await?;
        Ok((200..300).contains(&r.status))
    }

    async fn main(&mut self) -> Result<DoneReason, PipeError> {
        if !self.set_status("running").await? {
            self.log("warn", "status_refused").await?;
            return self.finish(DoneReason::Shutdown).await;
        }
        let mut items = self.fetch_inbox().await?;
        let mut renew = tokio::time::interval(LEASE_RENEW);
        renew.tick().await;
        loop {
            if !items.is_empty() {
                self.handle_items(core::mem::take(&mut items)).await?;
                continue;
            }
            // Attente d'éléments jusqu'à l'inactivité (P3 : le worker ne vit que lorsqu'il travaille).
            let idle = tokio::time::sleep(Duration::from_secs(self.init.limits.idle_shutdown_secs));
            tokio::pin!(idle);
            let msg = loop {
                if let Some(m) = self.queued.pop_front() {
                    break Some(m);
                }
                tokio::select! {
                    m = self.read_msg() => break Some(m?),
                    _ = renew.tick() => self.renew_lease().await?,
                    () = &mut idle => break None,
                }
            };
            match msg {
                None => return self.finish(DoneReason::Idle).await,
                Some(SupervisorMsg::Inbox(inbox)) => items = inbox.items.into_iter().filter_map(inbox_entry).collect(),
                Some(SupervisorMsg::Shutdown(_)) => return self.finish(DoneReason::Shutdown).await,
                Some(SupervisorMsg::SnapshotRequest(req)) => self.snapshot(&req.request_id).await?,
                Some(_) => {}
            }
        }
    }

    async fn renew_lease(&mut self) -> Result<(), PipeError> {
        let path = self.conv_path("/lease");
        let r = self.call(HttpMethod::Post, &path, Some(json!({ "leaseEpoch": self.init.lease_epoch })), true).await?;
        if !(200..300).contains(&r.status) {
            self.log("warn", "lease_lost").await?;
        }
        Ok(())
    }

    async fn fetch_inbox(&mut self) -> Result<Vec<(String, Value)>, PipeError> {
        let path = self.conv_path("/inbox");
        let r = self.call(HttpMethod::Get, &path, None, true).await?;
        let body: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        Ok(body
            .get("items")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|i| {
                        let id = i.get("id")?.as_str()?.to_owned();
                        let mut payload = i.get("payload")?.clone();
                        payload.as_object_mut()?.insert("t".into(), i.get("kind")?.clone());
                        Some((id, payload))
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn handle_items(&mut self, items: Vec<(String, Value)>) -> Result<(), PipeError> {
        let Some(ck) = self.ck.clone() else { return Ok(()) };
        let sid = self.init.session_id.clone();
        if self.status != "running" {
            self.set_status("running").await?;
        }
        let head_path = self.conv_path("");
        let head = self.call(HttpMethod::Get, &head_path, None, true).await?;
        let head: Value = serde_json::from_slice(&head.body).unwrap_or(Value::Null);
        let mut messages = head.get("messages").and_then(Value::as_array).cloned().unwrap_or_default();
        self.rev = head.get("rev").and_then(Value::as_u64).unwrap_or(0);
        let mut consumed = Vec::new();
        for (id, item) in items {
            consumed.push(id);
            if item.get("t").and_then(Value::as_str) != Some("message") {
                continue;
            }
            messages.push(json!({
                "id": item.get("id").cloned().unwrap_or(Value::Null),
                "role": "user",
                "content": item.get("content").cloned().unwrap_or(Value::Null),
                "createdAt": item.get("createdAt").cloned().unwrap_or(Value::Null),
            }));
            let reply_id = random_id();
            let seq = self.seq.saturating_add(1);
            let delta = session::encrypt_field(
                &ck,
                &sid,
                &reply_id,
                &FieldName::WsText { epoch: self.init.lease_epoch, seq },
                STUB_REPLY,
                &mut OsRandom,
            )
            .map_err(|_| PipeError::BadMessage)?;
            self.event(json!({ "t": "text", "messageId": reply_id, "delta": delta })).await?;
            let content = session::encrypt_field(&ck, &sid, &reply_id, &FieldName::Content, STUB_REPLY, &mut OsRandom)
                .map_err(|_| PipeError::BadMessage)?;
            messages.push(json!({ "id": reply_id, "role": "assistant", "content": content, "createdAt": crate::time::now_iso8601() }));
        }
        let transcript = json!({
            "leaseEpoch": self.init.lease_epoch,
            "baseRev": self.rev,
            "messages": messages,
            "status": "idle",
            "pendingToolCall": null,
            "consumedInbox": consumed,
        });
        let path = self.conv_path("/transcript");
        let r = self.call(HttpMethod::Put, &path, Some(transcript), true).await?;
        if (200..300).contains(&r.status) {
            if let Some(rev) = serde_json::from_slice::<Value>(&r.body).ok().and_then(|v| v.get("rev")?.as_u64()) {
                self.rev = rev;
            }
        } else {
            self.log("warn", "transcript_refused").await?;
        }
        self.status = "idle";
        self.event(json!({ "t": "status", "status": "idle" })).await?;
        self.send(&WorkerMsg::Status(StatusMsg { status: "idle".into(), reason: None })).await?;
        self.send(&WorkerMsg::InboxAck(InboxAckMsg { ids: consumed })).await?;
        self.send(&WorkerMsg::Metrics(Box::new(Metrics { turn: 1, ..Metrics::default() }))).await
    }

    async fn snapshot(&mut self, request_id: &str) -> Result<(), PipeError> {
        let Some(ck) = self.ck.clone() else { return Ok(()) };
        let seq = self.next_seq();
        let state = json!({ "messages": [], "status": self.status, "pendingToolCall": null });
        let field = FieldName::Snapshot { epoch: self.init.lease_epoch, seq };
        let encrypted =
            session::encrypt_json_field(&ck, &self.init.session_id, SNAPSHOT_MESSAGE_ID, &field, &state, &mut OsRandom)
                .map_err(|_| PipeError::BadMessage)?;
        let event = json!({ "v": 1, "t": "snapshot", "epoch": self.init.lease_epoch, "seq": seq, "baseRev": self.rev, "state": encrypted });
        self.send(&WorkerMsg::Snapshot(SnapshotMsg { request_id: request_id.into(), event })).await
    }

    async fn finish(&mut self, reason: DoneReason) -> Result<DoneReason, PipeError> {
        let path = self.conv_path("/lease");
        let _ = self.call(HttpMethod::Delete, &path, Some(json!({ "leaseEpoch": self.init.lease_epoch })), true).await;
        self.ck = None;
        self.send(&WorkerMsg::Done(DoneMsg { reason })).await?;
        Ok(reason)
    }
}

/// Élément de boîte arrivé par WebSocket (trame `{ t, … }`) → `(id, trame)`.
fn inbox_entry(frame: Value) -> Option<(String, Value)> {
    let t = frame.get("t")?.as_str()?;
    let id = match t {
        "message" => frame.get("id")?.as_str()?.to_owned(),
        "cancel" => format!("cancel:{}", frame.get("id")?.as_str()?),
        _ => format!("{t}:{}", frame.get("toolCallId")?.as_str()?),
    };
    Some((id, frame))
}
