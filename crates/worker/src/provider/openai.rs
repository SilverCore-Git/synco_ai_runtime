//! Adaptateur **compatible OpenAI** (`/chat/completions` en SSE) : OpenAI, passerelle Synco
//! (Ollama derrière `Synco_AI_Gateway`), point d'accès `custom`. Même comportement que
//! `synco_api/src/services/ai/providerAdapters/openai.ts`, plus :
//!
//! - `max_completion_tokens` (OpenAI) ou `max_tokens` (autres) = `maxOutputTokensPerCall` ;
//! - `reasoning_effort` envoyé à la passerelle (champ de sa liste blanche) et aux modèles de
//!   raisonnement d'OpenAI (`o1`, `o3`, `o4`, `gpt-5`…), jamais aux autres (OpenAI refuse le champ
//!   pour un modèle sans raisonnement ; un `custom` peut ne pas le connaître) ; la consigne du prompt
//!   système s'applique à tous ;
//! - raisonnement lu dans `delta.reasoning_content` / `delta.reasoning` quand le serveur l'expose
//!   (vLLM, DeepSeek, Ollama), sinon extrait des balises `<think>` ;
//! - appels d'outils réassemblés par `index` ; un appel présent alors que `finish_reason` vaut
//!   `stop` (certains serveurs compatibles) est quand même rendu, avec `ToolCalls` comme fin.

use serde_json::{Value, json};

use super::think::ThinkTagSplitter;
use super::{ChatMessage, ChatRequest, FinishReason, HttpCall, LlmAdapter, LlmError, LlmEvent, StreamDecoder, Usage};
use runtime_protocol::pipe::ReasoningEffort;

/// Variante du dialecte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flavor {
    OpenAi,
    Gateway,
    Custom,
}

/// Adaptateur compatible OpenAI.
#[derive(Debug, Clone)]
pub struct OpenAiCompatible {
    flavor: Flavor,
    id: &'static str,
}

impl OpenAiCompatible {
    /// OpenAI.
    #[must_use]
    pub const fn openai() -> Self {
        Self { flavor: Flavor::OpenAi, id: "openai" }
    }

    /// Passerelle Synco (`/v1/chat/completions`, ticket `sgt1`).
    #[must_use]
    pub const fn gateway() -> Self {
        Self { flavor: Flavor::Gateway, id: "gateway" }
    }

    /// Point d'accès compatible configuré dans le runtime.
    #[must_use]
    pub const fn custom() -> Self {
        Self { flavor: Flavor::Custom, id: "custom" }
    }

    /// Dialecte `custom` sous un autre identifiant (repli avant L07b).
    #[must_use]
    pub const fn custom_named(id: &'static str) -> Self {
        Self { flavor: Flavor::Custom, id }
    }
}

/// Modèle OpenAI à raisonnement (accepte `reasoning_effort`).
#[must_use]
pub fn is_openai_reasoning_model(model: &str) -> bool {
    let m = model.rsplit('/').next().unwrap_or(model);
    ["o1", "o3", "o4", "gpt-5"].iter().any(|p| m == *p || m.starts_with(&format!("{p}-")))
}

const fn effort_str(e: ReasoningEffort) -> &'static str {
    match e {
        ReasoningEffort::Low => "low",
        ReasoningEffort::Medium => "medium",
        ReasoningEffort::High => "high",
    }
}

/// Messages au format de l'API (`toWireMessages` de `openai.ts`).
#[must_use]
pub fn wire_messages(system: &str, messages: &[ChatMessage]) -> Vec<Value> {
    let mut wire = vec![json!({ "role": "system", "content": system })];
    for m in messages {
        wire.push(match m {
            ChatMessage::User { content } => json!({ "role": "user", "content": content }),
            ChatMessage::Tool { tool_call_id, content } => {
                json!({ "role": "tool", "tool_call_id": tool_call_id, "content": content })
            }
            ChatMessage::Assistant { content, tool_calls } if tool_calls.is_empty() => {
                json!({ "role": "assistant", "content": content.clone().unwrap_or_default() })
            }
            ChatMessage::Assistant { content, tool_calls } => json!({
                "role": "assistant",
                "content": content,
                "tool_calls": tool_calls.iter().map(|tc| json!({
                    "id": tc.id, "type": "function",
                    "function": { "name": tc.name, "arguments": tc.arguments },
                })).collect::<Vec<_>>(),
            }),
        });
    }
    wire
}

impl LlmAdapter for OpenAiCompatible {
    fn id(&self) -> &'static str {
        self.id
    }

    fn build(&self, req: &ChatRequest) -> Result<HttpCall, LlmError> {
        let mut body = json!({
            "model": req.model,
            "messages": wire_messages(&req.system, &req.messages),
            "stream": true,
            "stream_options": { "include_usage": true },
            "temperature": 0.5,
        });
        let max_key = if self.flavor == Flavor::OpenAi { "max_completion_tokens" } else { "max_tokens" };
        crate::json_set(&mut body, max_key, json!(req.max_output_tokens));
        let effort = match self.flavor {
            Flavor::Gateway => true,
            Flavor::OpenAi => is_openai_reasoning_model(&req.model),
            Flavor::Custom => false,
        };
        if effort {
            crate::json_set(&mut body, "reasoning_effort", json!(effort_str(req.reasoning_effort)));
            if self.flavor == Flavor::OpenAi {
                // Les modèles de raisonnement d'OpenAI refusent une température ≠ 1.
                if let Some(o) = body.as_object_mut() {
                    o.remove("temperature");
                }
            }
        }
        if !req.tools.is_empty() {
            crate::json_set(
                &mut body,
                "tools",
                Value::Array(
                    req.tools
                        .iter()
                        .map(|t| {
                            json!({ "type": "function", "function": {
                            "name": t.name, "description": t.description, "parameters": t.parameters } })
                        })
                        .collect(),
                ),
            );
            crate::json_set(&mut body, "tool_choice", json!("auto"));
            if self.flavor != Flavor::Gateway {
                // Absent de la liste blanche de la passerelle (elle le retirerait de toute façon).
                crate::json_set(&mut body, "parallel_tool_calls", json!(false));
            }
        }
        let mut headers = vec![
            ("content-type".to_owned(), "application/json".to_owned()),
            ("accept".into(), "text/event-stream".into()),
        ];
        if self.flavor == Flavor::Gateway {
            let ticket = req.bearer.as_deref().ok_or(LlmError::Auth)?;
            headers.push(("authorization".into(), format!("Bearer {ticket}")));
        }
        let path = if self.flavor == Flavor::Gateway { "/v1/chat/completions" } else { "/chat/completions" };
        let body = serde_json::to_vec(&body).map_err(|_| LlmError::Rejected { status: 0 })?;
        Ok(HttpCall { method: "POST", path, headers, body })
    }

    fn decoder(&self) -> Box<dyn StreamDecoder> {
        Box::new(SseDecoder::default())
    }
}

/// Ligne SSE maximale (protège la mémoire du worker contre un flux sans fin de ligne).
pub const MAX_SSE_LINE: usize = 4 * 1024 * 1024;

#[derive(Default)]
struct PartialCall {
    id: String,
    name: String,
    arguments: String,
}

/// Décodeur SSE `data: {…}` d'un flux `chat.completion.chunk`.
#[derive(Default)]
pub struct SseDecoder {
    line: Vec<u8>,
    splitter: ThinkTagSplitter,
    calls: Vec<PartialCall>,
    finish: Option<String>,
    usage: Option<Usage>,
    done: bool,
}

impl core::fmt::Debug for SseDecoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SseDecoder").field("calls", &self.calls.len()).finish_non_exhaustive()
    }
}

fn u(v: &Value, k: &str) -> Option<u64> {
    v.get(k).and_then(Value::as_u64)
}

impl SseDecoder {
    fn line(&mut self, line: &[u8], out: &mut Vec<LlmEvent>) -> Result<(), LlmError> {
        let text = String::from_utf8_lossy(line);
        let trimmed = text.trim();
        let Some(payload) = trimmed.strip_prefix("data:").map(str::trim) else { return Ok(()) };
        if payload == "[DONE]" || payload.is_empty() {
            return Ok(());
        }
        let Ok(json) = serde_json::from_str::<Value>(payload) else { return Ok(()) };
        if json.get("error").is_some_and(|e| !e.is_null()) {
            return Err(LlmError::BadStream);
        }
        if let Some(us) = json.get("usage").filter(|u| u.is_object()) {
            self.usage = Some(Usage {
                prompt_tokens: u(us, "prompt_tokens"),
                completion_tokens: u(us, "completion_tokens"),
                total_tokens: u(us, "total_tokens"),
                reasoning_tokens: us.get("completion_tokens_details").and_then(|d| u(d, "reasoning_tokens")),
            });
        }
        let Some(choice) = json.get("choices").and_then(|c| c.get(0)) else { return Ok(()) };
        let empty = Value::Null;
        let delta = choice.get("delta").unwrap_or(&empty);
        for key in ["reasoning_content", "reasoning"] {
            if let Some(r) = delta.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()) {
                out.push(LlmEvent::Thinking(r.to_owned()));
            }
        }
        if let Some(c) = delta.get("content").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            let s = self.splitter.push(c);
            if !s.thinking.is_empty() {
                out.push(LlmEvent::Thinking(s.thinking));
            }
            if !s.text.is_empty() {
                out.push(LlmEvent::Text(s.text));
            }
        }
        if let Some(tcs) = delta.get("tool_calls").and_then(Value::as_array) {
            for (pos, tc) in tcs.iter().enumerate() {
                let index =
                    tc.get("index").and_then(Value::as_u64).and_then(|i| usize::try_from(i).ok()).unwrap_or(pos);
                if index >= 16 {
                    continue;
                }
                while self.calls.len() <= index {
                    self.calls.push(PartialCall::default());
                }
                let Some(call) = self.calls.get_mut(index) else { continue };
                if let Some(id) = tc.get("id").and_then(Value::as_str) {
                    call.id = id.to_owned();
                }
                if let Some(f) = tc.get("function") {
                    if let Some(n) = f.get("name").and_then(Value::as_str) {
                        call.name.push_str(n);
                    }
                    match f.get("arguments") {
                        Some(Value::String(a)) => call.arguments.push_str(a),
                        // Certains serveurs (Ollama) donnent un objet déjà décodé.
                        Some(v @ Value::Object(_)) => call.arguments.push_str(&v.to_string()),
                        _ => {}
                    }
                }
            }
        }
        if let Some(r) = choice.get("finish_reason").and_then(Value::as_str) {
            self.finish = Some(r.to_owned());
        }
        Ok(())
    }
}

impl StreamDecoder for SseDecoder {
    fn push(&mut self, chunk: &[u8], out: &mut Vec<LlmEvent>) -> Result<(), LlmError> {
        for &b in chunk {
            if b == b'\n' {
                let line = core::mem::take(&mut self.line);
                self.line(&line, out)?;
            } else {
                if self.line.len() >= MAX_SSE_LINE {
                    return Err(LlmError::BadStream);
                }
                self.line.push(b);
            }
        }
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<LlmEvent>) -> Result<(), LlmError> {
        if self.done {
            return Ok(());
        }
        self.done = true;
        let rest = core::mem::take(&mut self.line);
        self.line(&rest, out)?;
        let s = self.splitter.flush();
        if !s.thinking.is_empty() {
            out.push(LlmEvent::Thinking(s.thinking));
        }
        if !s.text.is_empty() {
            out.push(LlmEvent::Text(s.text));
        }
        let calls: Vec<_> = self.calls.drain(..).filter(|c| !c.name.is_empty()).collect();
        let has_calls = !calls.is_empty();
        for c in calls {
            out.push(LlmEvent::ToolCall(super::ChatToolCall {
                id: c.id,
                name: c.name,
                arguments: if c.arguments.trim().is_empty() { "{}".to_owned() } else { c.arguments },
            }));
        }
        if let Some(us) = self.usage.take() {
            out.push(LlmEvent::Usage(us));
        }
        let reason = match self.finish.take().as_deref() {
            _ if has_calls => FinishReason::ToolCalls,
            Some("stop") | None => FinishReason::Stop,
            Some("length") => FinishReason::Length,
            Some("tool_calls") => FinishReason::Stop,
            Some(other) => FinishReason::Other(other.chars().filter(char::is_ascii_alphanumeric).take(32).collect()),
        };
        out.push(LlmEvent::Done(reason));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{ChatToolCall, ToolDef};
    use super::*;

    fn req(model: &str) -> ChatRequest {
        ChatRequest {
            model: model.into(),
            system: "sys".into(),
            messages: vec![
                ChatMessage::User { content: "Bonjour".into() },
                ChatMessage::Assistant {
                    content: None,
                    tool_calls: vec![ChatToolCall {
                        id: "c1".into(),
                        name: "list_spaces".into(),
                        arguments: "{}".into(),
                    }],
                },
                ChatMessage::Tool { tool_call_id: "c1".into(), content: "[]".into() },
            ],
            tools: vec![ToolDef { name: "list_spaces".into(), description: "d".into(), parameters: json!({}) }],
            reasoning_effort: ReasoningEffort::High,
            max_output_tokens: 4096,
            bearer: Some("sgt1.ticket".into()),
        }
    }

    fn body(call: &HttpCall) -> Value {
        serde_json::from_slice(&call.body).unwrap()
    }

    #[test]
    fn requetes() {
        let o = OpenAiCompatible::openai().build(&req("gpt-4o")).unwrap();
        assert_eq!(o.path, "/chat/completions");
        let b = body(&o);
        assert_eq!(b["messages"][0], json!({ "role": "system", "content": "sys" }));
        assert_eq!(b["messages"][2]["tool_calls"][0]["function"]["name"], "list_spaces");
        assert_eq!(b["messages"][3], json!({ "role": "tool", "tool_call_id": "c1", "content": "[]" }));
        assert_eq!(b["stream_options"]["include_usage"], true);
        assert_eq!(b["max_completion_tokens"], 4096);
        assert_eq!(b["parallel_tool_calls"], false);
        assert!(b.get("reasoning_effort").is_none(), "gpt-4o refuserait le champ");
        assert!(!o.headers.iter().any(|(k, _)| k == "authorization"), "jamais de clé ni de ticket");
        let r = body(&OpenAiCompatible::openai().build(&req("o3-mini")).unwrap());
        assert_eq!(r["reasoning_effort"], "high");
        assert!(r.get("temperature").is_none());
        let g = OpenAiCompatible::gateway().build(&req("llama3")).unwrap();
        assert_eq!(g.path, "/v1/chat/completions");
        assert!(g.headers.contains(&("authorization".into(), "Bearer sgt1.ticket".into())));
        let gb = body(&g);
        assert_eq!(gb["reasoning_effort"], "high");
        assert_eq!(gb["max_tokens"], 4096);
        assert!(gb.get("parallel_tool_calls").is_none());
        let mut no_ticket = req("llama3");
        no_ticket.bearer = None;
        assert_eq!(OpenAiCompatible::gateway().build(&no_ticket).unwrap_err(), LlmError::Auth);
        let c = body(&OpenAiCompatible::custom().build(&req("qwen")).unwrap());
        assert!(c.get("reasoning_effort").is_none());
        assert!(is_openai_reasoning_model("gpt-5-mini") && !is_openai_reasoning_model("gpt-4o-mini"));
    }

    fn decode(chunks: &[&str]) -> Vec<LlmEvent> {
        let mut d = SseDecoder::default();
        let mut out = Vec::new();
        for c in chunks {
            d.push(c.as_bytes(), &mut out).unwrap();
        }
        d.finish(&mut out).unwrap();
        out
    }

    #[test]
    fn flux_texte_raisonnement_usage() {
        let ev = decode(&[
            "data: {\"choices\":[{\"delta\":{\"content\":\"<think>hm\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"</think>Bon\"}}]}\n",
            "\ndata: {\"choices\":[{\"delta\":{\"content\":\"jour\"},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2,\"total_tokens\":7,\"completion_tokens_details\":{\"reasoning_tokens\":1}}}\n\n",
            "data: [DONE]\n\n",
        ]);
        assert_eq!(
            ev,
            vec![
                LlmEvent::Thinking("hm".into()),
                LlmEvent::Text("Bon".into()),
                LlmEvent::Text("jour".into()),
                LlmEvent::Usage(Usage {
                    prompt_tokens: Some(5),
                    completion_tokens: Some(2),
                    total_tokens: Some(7),
                    reasoning_tokens: Some(1)
                }),
                LlmEvent::Done(FinishReason::Stop),
            ]
        );
    }

    #[test]
    fn flux_appel_d_outil_coupe() {
        // Ligne SSE coupée au milieu, arguments en plusieurs morceaux, champ de raisonnement dédié.
        let ev = decode(&[
            "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"je cherche\"}}]}\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_9\",\"function\":{\"name\":\"search_messages\",\"argu",
            "ments\":\"{\\\"query\\\":\"}}]}}]}\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"wifi\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n",
        ]);
        assert_eq!(
            ev,
            vec![
                LlmEvent::Thinking("je cherche".into()),
                LlmEvent::ToolCall(ChatToolCall {
                    id: "call_9".into(),
                    name: "search_messages".into(),
                    arguments: r#"{"query":"wifi"}"#.into()
                }),
                LlmEvent::Done(FinishReason::ToolCalls),
            ]
        );
        // Erreur annoncée dans le flux.
        let mut d = SseDecoder::default();
        assert_eq!(
            d.push(b"data: {\"error\":{\"message\":\"x\"}}\n", &mut Vec::new()).unwrap_err(),
            LlmError::BadStream
        );
    }
}
