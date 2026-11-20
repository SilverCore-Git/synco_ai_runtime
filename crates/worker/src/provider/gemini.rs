//! Adaptateur **Gemini par l'endpoint compatible OpenAI** (`POST /chat/completions`, base
//! `https://generativelanguage.googleapis.com/v1beta/openai` configurée dans le runtime). Le mandataire
//! du superviseur n'admet que `POST /chat/completions` et `GET /models` : l'API native
//! (`:streamGenerateContent`) de `gemini.ts` n'est pas atteignable (écarts : docs/journal.md, L07b).
//!
//! Particularités reprises de la documentation et des retours publiés (docs/journal.md) :
//!
//! - `reasoning_effort` (`low|medium|high`) pour les modèles à raisonnement (`gemini-2.5`, `-3`, `-4`),
//!   jamais combiné à `thinking_config` ; `include_thoughts` n'est pas demandé (comme `gemini.ts`,
//!   où `includeThoughts` n'est jamais envoyé) ;
//! - raisonnement, s'il est rendu : `delta.extra_content.google.thought == true`, ou balises
//!   `<thought>…</thought>` dans le contenu ;
//! - appels d'outils rendus **entiers** et **sans `index`** (parfois sans identifiant) : rangés par
//!   identifiant, un nouveau nom ouvre un nouvel appel ;
//! - le message `tool` porte `name` (comme `functionResponse.name` de `gemini.ts`) ;
//! - ni `parallel_tool_calls` (non documenté) ni `max_completion_tokens` : `max_tokens` ;
//! - erreurs classées par le champ `status` de Google (`UNAUTHENTICATED`…), jamais par le message.

use serde_json::{Value, json};

use super::openai::{DecodeOptions, SseDecoder, add_tool_names, effort_str, wire_messages, wire_tools};
use super::{ChatRequest, HttpCall, LlmAdapter, LlmError, StreamDecoder, classify_http_error};

/// Adaptateur Gemini (endpoint compatible OpenAI).
#[derive(Debug, Clone, Copy, Default)]
pub struct Gemini;

/// Modèle à raisonnement qui accepte `reasoning_effort`.
fn accepts_effort(model: &str) -> bool {
    let m = model.rsplit('/').next().unwrap_or(model);
    ["gemini-2.5", "gemini-3", "gemini-4"].iter().any(|p| m.starts_with(p))
}

impl LlmAdapter for Gemini {
    fn id(&self) -> &'static str {
        "gemini"
    }

    fn build(&self, req: &ChatRequest) -> Result<HttpCall, LlmError> {
        let mut wire = wire_messages(&req.system, &req.messages);
        add_tool_names(&mut wire, &req.messages);
        let mut body = json!({
            "model": req.model,
            "messages": wire,
            "stream": true,
            "stream_options": { "include_usage": true },
            "temperature": 0.5,
            "max_tokens": req.max_output_tokens,
        });
        if accepts_effort(&req.model) {
            crate::json_set(&mut body, "reasoning_effort", json!(effort_str(req.reasoning_effort)));
        }
        if !req.tools.is_empty() {
            crate::json_set(&mut body, "tools", wire_tools(req));
            crate::json_set(&mut body, "tool_choice", json!("auto"));
        }
        let headers = vec![
            ("content-type".to_owned(), "application/json".to_owned()),
            ("accept".into(), "text/event-stream".into()),
        ];
        let body = serde_json::to_vec(&body).map_err(|_| LlmError::Rejected { status: 0 })?;
        Ok(HttpCall { method: "POST", path: "/chat/completions", headers, body })
    }

    fn decoder(&self) -> Box<dyn StreamDecoder> {
        Box::new(SseDecoder::with_options(DecodeOptions {
            thought_tags: true,
            thought_flag: true,
            calls_by_id: true,
            strict_end: true,
            list_content: false,
        }))
    }

    fn classify_error(&self, status: u16, retry_after_secs: Option<u64>, body: &[u8]) -> LlmError {
        let base = classify_http_error(status, retry_after_secs, body);
        if !matches!(base, LlmError::Rejected { .. } | LlmError::Provider { .. }) {
            return base;
        }
        // Le corps est un objet ou un tableau d'un objet : seul le code `status` de Google est lu.
        let v = serde_json::from_slice::<Value>(body).unwrap_or(Value::Null);
        let err = v.get(0).unwrap_or(&v).get("error");
        let code = err.and_then(|e| e.get("status")).and_then(Value::as_str).unwrap_or_default();
        let invalid_key = String::from_utf8_lossy(body).contains("API_KEY_INVALID");
        match code {
            "UNAUTHENTICATED" | "PERMISSION_DENIED" => LlmError::Auth,
            _ if invalid_key => LlmError::Auth,
            "RESOURCE_EXHAUSTED" => LlmError::RateLimited { retry_after_secs },
            "DEADLINE_EXCEEDED" => LlmError::Timeout,
            _ => base,
        }
    }
}

#[cfg(test)]
mod tests {
    use runtime_protocol::pipe::ReasoningEffort;

    use super::super::{ChatMessage, ChatToolCall, FinishReason, LlmEvent, ToolDef, Usage};
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
                        id: "call_ab".into(),
                        name: "list_spaces".into(),
                        arguments: "{}".into(),
                    }],
                },
                ChatMessage::Tool { tool_call_id: "call_ab".into(), content: "[]".into() },
            ],
            tools: vec![ToolDef { name: "list_spaces".into(), description: "d".into(), parameters: json!({}) }],
            reasoning_effort: ReasoningEffort::Low,
            max_output_tokens: 1024,
            bearer: Some("ne-doit-jamais-sortir".into()),
        }
    }

    fn body(c: &HttpCall) -> Value {
        serde_json::from_slice(&c.body).unwrap()
    }

    #[test]
    fn requete_gemini() {
        let c = Gemini.build(&req("gemini-2.5-flash")).unwrap();
        assert_eq!((c.method, c.path), ("POST", "/chat/completions"));
        assert!(!c.headers.iter().any(|(k, _)| k == "authorization"));
        let b = body(&c);
        assert_eq!(b["reasoning_effort"], "low");
        assert!(b.get("extra_body").is_none(), "jamais thinking_config avec reasoning_effort");
        assert_eq!(b["max_tokens"], 1024);
        assert_eq!(b["stream_options"]["include_usage"], true);
        assert!(b.get("parallel_tool_calls").is_none());
        assert_eq!(b["messages"][3]["name"], "list_spaces");
        assert_eq!(b["messages"][2]["tool_calls"][0]["id"], "call_ab");
        assert!(body(&Gemini.build(&req("gemini-2.0-flash")).unwrap()).get("reasoning_effort").is_none());
        assert!(body(&Gemini.build(&req("models/gemini-3-pro")).unwrap()).get("reasoning_effort").is_some());
    }

    fn sse(v: &Value) -> String {
        format!("data: {v}\n\n")
    }

    fn decode(chunks: &[String]) -> Result<Vec<LlmEvent>, LlmError> {
        let mut d = Gemini.decoder();
        let mut out = Vec::new();
        for c in chunks {
            d.push(c.as_bytes(), &mut out)?;
        }
        d.finish(&mut out)?;
        Ok(out)
    }

    #[test]
    fn texte_et_usage_avec_raisonnement() {
        let ev = decode(&[
            sse(&json!({"choices":[{"delta":{"role":"assistant","content":"plan","extra_content":{"google":{"thought":true}}}}]})),
            sse(&json!({"choices":[{"delta":{"content":"<thought>b</thought>Bon"}}]})),
            sse(&json!({"choices":[{"delta":{"content":"jour"},"finish_reason":"stop"}],
                "usage":{"prompt_tokens":4,"completion_tokens":6,"total_tokens":15,"completion_tokens_details":{"reasoning_tokens":5}}})),
            "data: [DONE]\n\n".into(),
        ])
        .unwrap();
        assert_eq!(
            ev,
            vec![
                LlmEvent::Thinking("plan".into()),
                LlmEvent::Thinking("b".into()),
                LlmEvent::Text("Bon".into()),
                LlmEvent::Text("jour".into()),
                LlmEvent::Usage(Usage {
                    prompt_tokens: Some(4),
                    completion_tokens: Some(6),
                    total_tokens: Some(15),
                    reasoning_tokens: Some(5)
                }),
                LlmEvent::Done(FinishReason::Stop),
            ]
        );
    }

    #[test]
    fn plusieurs_appels_sans_index_et_finish_stop() {
        // Deux appels entiers, sans `index`, le second sans identifiant ; fin `stop` malgré les appels.
        let ev = decode(&[
            sse(&json!({"choices":[{"delta":{"tool_calls":[{"id":"a1","function":{"name":"list_spaces","arguments":"{}"}}]}}]})),
            sse(&json!({"choices":[{"delta":{"tool_calls":[{"id":"","function":{"name":"search_messages","arguments":"{\"query\":\"x\"}"}}]},"finish_reason":"stop"}]})),
            "data: [DONE]\n\n".into(),
        ])
        .unwrap();
        assert_eq!(
            ev,
            vec![
                LlmEvent::ToolCall(ChatToolCall {
                    id: "a1".into(),
                    name: "list_spaces".into(),
                    arguments: "{}".into()
                }),
                LlmEvent::ToolCall(ChatToolCall {
                    id: String::new(),
                    name: "search_messages".into(),
                    arguments: r#"{"query":"x"}"#.into()
                }),
                LlmEvent::Done(FinishReason::ToolCalls),
            ]
        );
    }

    #[test]
    fn appel_en_plusieurs_morceaux_rattache_par_identifiant_puis_au_dernier() {
        let ev = decode(&[
            sse(&json!({"choices":[{"delta":{"tool_calls":[{"id":"c9","function":{"name":"search_messages","arguments":"{\"qu"}}]}}]})),
            sse(&json!({"choices":[{"delta":{"tool_calls":[{"id":"c9","function":{"arguments":"ery\":"}}]}}]})),
            sse(&json!({"choices":[{"delta":{"tool_calls":[{"function":{"arguments":"\"a\"}"}}]},"finish_reason":"tool_calls"}]})),
        ])
        .unwrap();
        assert_eq!(
            ev[0],
            LlmEvent::ToolCall(ChatToolCall {
                id: "c9".into(),
                name: "search_messages".into(),
                arguments: r#"{"query":"a"}"#.into()
            })
        );
        assert_eq!(ev.len(), 2);
    }

    #[test]
    fn coupe_trop_grand_erreur_dans_le_flux() {
        assert_eq!(decode(&[sse(&json!({"choices":[{"delta":{"content":"a"}}]}))]).unwrap_err(), LlmError::BadStream);
        let mut d = Gemini.decoder();
        let mut out = Vec::new();
        let big = sse(&json!({"choices":[{"delta":{"content":"y".repeat(1024 * 1024)}}]}));
        let mut res = Ok(());
        for _ in 0..5 {
            res = d.push(big.as_bytes(), &mut out);
        }
        assert_eq!(res.unwrap_err(), LlmError::TooLarge);
        let mut d = Gemini.decoder();
        let args = sse(
            &json!({"choices":[{"delta":{"tool_calls":[{"id":"k","function":{"name":"n","arguments":"z".repeat(600 * 1024)}}]}}]}),
        );
        d.push(args.as_bytes(), &mut out).unwrap();
        let more = args.replace("\"k\"", "\"k2\"");
        assert_eq!(d.push(more.as_bytes(), &mut out).unwrap_err(), LlmError::TooLarge);
        assert_eq!(
            decode(&["data: {\"error\":{\"code\":500,\"message\":\"secret\"}}\n\n".into()]).unwrap_err(),
            LlmError::BadStream
        );
    }

    #[test]
    fn erreurs_du_fournisseur_sans_texte() {
        let a = Gemini;
        let b = |status: &str| format!(r#"[{{"error":{{"code":0,"message":"secret","status":"{status}"}}}}]"#);
        assert_eq!(a.classify_error(401, None, b("UNAUTHENTICATED").as_bytes()), LlmError::Auth);
        assert_eq!(a.classify_error(403, None, b("PERMISSION_DENIED").as_bytes()), LlmError::Auth);
        assert_eq!(
            a.classify_error(
                400,
                None,
                br#"{"error":{"message":"API key not valid","details":[{"reason":"API_KEY_INVALID"}]}}"#
            ),
            LlmError::Auth
        );
        assert_eq!(
            a.classify_error(429, Some(7), b("RESOURCE_EXHAUSTED").as_bytes()),
            LlmError::RateLimited { retry_after_secs: Some(7) }
        );
        assert_eq!(a.classify_error(400, None, b("INVALID_ARGUMENT").as_bytes()), LlmError::Rejected { status: 400 });
        assert_eq!(a.classify_error(503, None, b("UNAVAILABLE").as_bytes()), LlmError::Provider { status: 503 });
        assert_eq!(a.classify_error(429, None, br#"{"error":"proxy_call_budget"}"#), LlmError::CallBudget);
    }
}
