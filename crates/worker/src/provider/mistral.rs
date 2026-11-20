//! Adaptateur **Mistral** (`POST /chat/completions`, base `https://api.mistral.ai/v1` configurée dans
//! le runtime). Même comportement que `synco_api/.../mistral.ts` (le format est celui d'OpenAI, outils
//! compris), avec les particularités de la documentation de Mistral (docs/journal.md, L07b) :
//!
//! - **identifiants d'appel** : Mistral n'accepte que `^[a-zA-Z0-9]{9}$` (sinon `400`, code `3280`).
//!   Les identifiants tirés par le worker (`call_<hex>`) sont donc traduits, de façon déterministe et
//!   sans collision, **dans la requête seulement** (l'appel et son résultat reçoivent le même) ;
//! - le message `tool` porte `name` (exemple de la documentation) ;
//! - ni `stream_options` (non documenté ; Mistral rend `usage` dans le dernier morceau) ni
//!   `max_completion_tokens` : `max_tokens` ; `parallel_tool_calls: false` (documenté) ;
//! - `reasoning_effort` seulement pour les modèles dont la documentation donne les valeurs
//!   `low|medium|high` (`mistral-large-4…`) : les autres refusent ou n'acceptent que `high|none` ;
//! - raisonnement : `delta.content` en liste (`thinking` / `text`, Magistral récent), ou `<think>` en
//!   ligne (Magistral ancien), via [`super::think::ThinkTagSplitter`].

use std::collections::HashSet;

use runtime_protocol::pipe::ReasoningEffort;
use serde_json::json;

use super::openai::{DecodeOptions, SseDecoder, add_tool_names, effort_str, wire_messages, wire_tools};
use super::{ChatMessage, ChatRequest, HttpCall, LlmAdapter, LlmError, StreamDecoder};

/// Adaptateur Mistral.
#[derive(Debug, Clone, Copy, Default)]
pub struct Mistral;

const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// `^[a-zA-Z0-9]{9}$`.
fn is_mistral_id(id: &str) -> bool {
    id.len() == 9 && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn fnv1a(data: &[u8], salt: u64) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325_u64 ^ salt.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn base62_9(mut n: u64) -> String {
    let mut out = [b'0'; 9];
    for slot in &mut out {
        *slot = ALPHABET.get(usize::try_from(n % 62).unwrap_or(0)).copied().unwrap_or(b'0');
        n /= 62;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Traduit les identifiants d'appel de l'historique (premier passage : ceux déjà conformes sont
/// gardés ; second : les autres reçoivent un hachage en base 62, réessayé en cas de collision).
fn map_ids(messages: &[ChatMessage]) -> Vec<ChatMessage> {
    let mut all: Vec<&str> = Vec::new();
    for m in messages {
        match m {
            ChatMessage::Assistant { tool_calls, .. } => all.extend(tool_calls.iter().map(|t| t.id.as_str())),
            ChatMessage::Tool { tool_call_id, .. } => all.push(tool_call_id),
            ChatMessage::User { .. } => {}
        }
    }
    let mut used: HashSet<String> = all.iter().filter(|i| is_mistral_id(i)).map(|i| (*i).to_owned()).collect();
    let mut map: std::collections::HashMap<&str, String> = std::collections::HashMap::new();
    for id in all {
        if is_mistral_id(id) || map.contains_key(id) {
            continue;
        }
        let mut salt = 0u64;
        let mapped = loop {
            let c = base62_9(fnv1a(id.as_bytes(), salt));
            if used.insert(c.clone()) {
                break c;
            }
            salt = salt.saturating_add(1);
        };
        map.insert(id, mapped);
    }
    let tr = |id: &str| map.get(id).cloned().unwrap_or_else(|| id.to_owned());
    messages
        .iter()
        .map(|m| match m {
            ChatMessage::Assistant { content, tool_calls } => ChatMessage::Assistant {
                content: content.clone(),
                tool_calls: tool_calls.iter().map(|t| super::ChatToolCall { id: tr(&t.id), ..t.clone() }).collect(),
            },
            ChatMessage::Tool { tool_call_id, content } => {
                ChatMessage::Tool { tool_call_id: tr(tool_call_id), content: content.clone() }
            }
            other @ ChatMessage::User { .. } => other.clone(),
        })
        .collect()
}

/// Modèle dont la documentation donne `reasoning_effort` ∈ `low|medium|high`.
fn accepts_effort(model: &str) -> bool {
    model.starts_with("mistral-large-4")
}

impl LlmAdapter for Mistral {
    fn id(&self) -> &'static str {
        "mistral"
    }

    fn build(&self, req: &ChatRequest) -> Result<HttpCall, LlmError> {
        let mapped = map_ids(&req.messages);
        let mut wire = wire_messages(&req.system, &mapped);
        add_tool_names(&mut wire, &mapped);
        let mut body = json!({
            "model": req.model,
            "messages": wire,
            "stream": true,
            "temperature": 0.5,
            "max_tokens": req.max_output_tokens,
        });
        if accepts_effort(&req.model) {
            let e: ReasoningEffort = req.reasoning_effort;
            crate::json_set(&mut body, "reasoning_effort", json!(effort_str(e)));
        }
        if !req.tools.is_empty() {
            crate::json_set(&mut body, "tools", wire_tools(req));
            crate::json_set(&mut body, "tool_choice", json!("auto"));
            crate::json_set(&mut body, "parallel_tool_calls", json!(false));
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
            list_content: true,
            strict_end: true,
            ..DecodeOptions::default()
        }))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::super::{ChatToolCall, FinishReason, LlmEvent, ToolDef, Usage};
    use super::*;

    fn req(model: &str, ids: &[&str]) -> ChatRequest {
        let mut messages = vec![ChatMessage::User { content: "Bonjour".into() }];
        for id in ids {
            messages.push(ChatMessage::Assistant {
                content: None,
                tool_calls: vec![ChatToolCall { id: (*id).into(), name: "list_spaces".into(), arguments: "{}".into() }],
            });
            messages.push(ChatMessage::Tool { tool_call_id: (*id).into(), content: "[]".into() });
        }
        ChatRequest {
            model: model.into(),
            system: "sys".into(),
            messages,
            tools: vec![ToolDef { name: "list_spaces".into(), description: "d".into(), parameters: json!({}) }],
            reasoning_effort: ReasoningEffort::Medium,
            max_output_tokens: 2048,
            bearer: Some("ne-doit-jamais-sortir".into()),
        }
    }

    fn body(c: &HttpCall) -> Value {
        serde_json::from_slice(&c.body).unwrap()
    }

    #[test]
    fn requete_mistral() {
        let c = Mistral.build(&req("mistral-small-latest", &["call_0123456789abcdef01234567"])).unwrap();
        assert_eq!((c.method, c.path), ("POST", "/chat/completions"));
        assert!(!c.headers.iter().any(|(k, _)| k == "authorization"), "ni clé ni ticket");
        let b = body(&c);
        assert_eq!(b["max_tokens"], 2048);
        assert_eq!(b["stream"], true);
        assert!(b.get("stream_options").is_none() && b.get("max_completion_tokens").is_none());
        assert_eq!(b["parallel_tool_calls"], false);
        assert_eq!(b["tool_choice"], "auto");
        assert_eq!(b["tools"][0]["function"]["name"], "list_spaces");
        assert!(b.get("reasoning_effort").is_none(), "modèle sans valeurs documentées");
        assert_eq!(b["messages"][0], json!({ "role": "system", "content": "sys" }));
        assert_eq!(b["messages"][3]["name"], "list_spaces", "le message tool porte le nom de l'outil");
        let r = body(&Mistral.build(&req("mistral-large-4-0", &[])).unwrap());
        assert_eq!(r["reasoning_effort"], "medium");
        let mut no_tools = req("mistral-small-latest", &[]);
        no_tools.tools.clear();
        let n = body(&Mistral.build(&no_tools).unwrap());
        assert!(n.get("tools").is_none() && n.get("parallel_tool_calls").is_none());
    }

    #[test]
    fn identifiants_d_appel_traduits_sans_collision() {
        let a = "call_0123456789abcdef01234567";
        let b = "call_89abcdef0123456789abcdef";
        let b1 = body(&Mistral.build(&req("m", &[a, b, "AbC123xyZ"])).unwrap());
        let b2 = body(&Mistral.build(&req("m", &[a, b, "AbC123xyZ"])).unwrap());
        assert_eq!(b1, b2, "déterministe");
        let msgs = b1["messages"].as_array().unwrap();
        let mut seen = HashSet::new();
        for pair in msgs[2..].chunks(2) {
            let call = pair[0]["tool_calls"][0]["id"].as_str().unwrap();
            assert_eq!(pair[1]["tool_call_id"], call, "l'appel et son résultat gardent le même identifiant");
            assert!(is_mistral_id(call), "{call}");
            assert!(seen.insert(call.to_owned()), "collision");
        }
        assert_eq!(msgs[6]["tool_calls"][0]["id"], "AbC123xyZ", "un identifiant conforme est gardé");
        // Une traduction ne doit pas entrer en collision avec un identifiant conforme déjà présent.
        let taken = base62_9(fnv1a(a.as_bytes(), 0));
        let m = map_ids(&req("m", &[taken.as_str(), a]).messages);
        let ids: HashSet<String> = m
            .iter()
            .filter_map(|x| match x {
                ChatMessage::Tool { tool_call_id, .. } => Some(tool_call_id.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(ids.len(), 2);
    }

    fn decode(chunks: &[&str]) -> Result<Vec<LlmEvent>, LlmError> {
        let mut d = Mistral.decoder();
        let mut out = Vec::new();
        for c in chunks {
            d.push(c.as_bytes(), &mut out)?;
        }
        d.finish(&mut out)?;
        Ok(out)
    }

    fn sse(v: &Value) -> String {
        format!("data: {v}\n\n")
    }

    #[test]
    fn flux_texte_usage_dans_le_dernier_morceau() {
        let ev = decode(&[
            &sse(&json!({"choices":[{"index":0,"delta":{"role":"assistant","content":"Bon"}}]})),
            &sse(&json!({"choices":[{"index":0,"delta":{"content":"jour"},"finish_reason":"stop"}],
                "usage":{"prompt_tokens":9,"completion_tokens":3,"total_tokens":12}})),
            "data: [DONE]\n\n",
        ])
        .unwrap();
        assert_eq!(
            ev,
            vec![
                LlmEvent::Text("Bon".into()),
                LlmEvent::Text("jour".into()),
                LlmEvent::Usage(Usage {
                    prompt_tokens: Some(9),
                    completion_tokens: Some(3),
                    total_tokens: Some(12),
                    reasoning_tokens: None
                }),
                LlmEvent::Done(FinishReason::Stop),
            ]
        );
    }

    #[test]
    fn raisonnement_en_contenu_structure_puis_texte() {
        let ev = decode(&[
            &sse(&json!({"choices":[{"delta":{"content":[{"type":"thinking","thinking":[{"type":"text","text":"je "}]}]}}]})),
            &sse(&json!({"choices":[{"delta":{"content":[
                {"type":"thinking","thinking":[{"type":"text","text":"réfléchis"}]},
                {"type":"text","text":"Voilà"}]}}]})),
            &sse(&json!({"choices":[{"delta":{"content":" fini"},"finish_reason":"stop"}],
                "usage":{"prompt_tokens":1,"completion_tokens":8,"total_tokens":9,"completion_tokens_details":{"reasoning_tokens":5}}})),
        ])
        .unwrap();
        assert_eq!(
            ev,
            vec![
                LlmEvent::Thinking("je ".into()),
                LlmEvent::Thinking("réfléchis".into()),
                LlmEvent::Text("Voilà".into()),
                LlmEvent::Text(" fini".into()),
                LlmEvent::Usage(Usage {
                    prompt_tokens: Some(1),
                    completion_tokens: Some(8),
                    total_tokens: Some(9),
                    reasoning_tokens: Some(5)
                }),
                LlmEvent::Done(FinishReason::Stop),
            ]
        );
    }

    #[test]
    fn raisonnement_think_en_ligne() {
        let ev = decode(&[
            &sse(&json!({"choices":[{"delta":{"content":"<thi"}}]})),
            &sse(&json!({"choices":[{"delta":{"content":"nk>hm</think>Oui"},"finish_reason":"stop"}]})),
        ])
        .unwrap();
        assert_eq!(
            ev,
            vec![LlmEvent::Thinking("hm".into()), LlmEvent::Text("Oui".into()), LlmEvent::Done(FinishReason::Stop)]
        );
    }

    #[test]
    fn appel_d_outil_entier_dans_un_morceau_puis_plusieurs_appels() {
        // Mistral rend chaque appel entier (id de 9 caractères, arguments complets) ; plusieurs appels
        // arrivent avec `index` 0, 1.
        let ev = decode(&[
            &sse(&json!({"choices":[{"delta":{"content":"","tool_calls":[
                {"id":"D681PevKs","index":0,"function":{"name":"list_spaces","arguments":"{}"}},
                {"id":"Xy7Zq0aBc","index":1,"function":{"name":"search_messages","arguments":"{\"query\":\"wifi\"}"}}]},
                "finish_reason":"tool_calls"}],
                "usage":{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30}})),
            "data: [DONE]\n\n",
        ])
        .unwrap();
        assert_eq!(
            ev,
            vec![
                LlmEvent::ToolCall(ChatToolCall {
                    id: "D681PevKs".into(),
                    name: "list_spaces".into(),
                    arguments: "{}".into()
                }),
                LlmEvent::ToolCall(ChatToolCall {
                    id: "Xy7Zq0aBc".into(),
                    name: "search_messages".into(),
                    arguments: r#"{"query":"wifi"}"#.into()
                }),
                LlmEvent::Usage(Usage {
                    prompt_tokens: Some(20),
                    completion_tokens: Some(10),
                    total_tokens: Some(30),
                    reasoning_tokens: None
                }),
                LlmEvent::Done(FinishReason::ToolCalls),
            ]
        );
    }

    #[test]
    fn appel_d_outil_en_plusieurs_morceaux() {
        let ev = decode(&[
            &sse(&json!({"choices":[{"delta":{"tool_calls":[{"id":"abcDEF123","index":0,"function":{"name":"search_messages","arguments":"{\"que"}}]}}]})),
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"ry\\\":\\\"a\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n",
        ])
        .unwrap();
        assert_eq!(
            ev[0],
            LlmEvent::ToolCall(ChatToolCall {
                id: "abcDEF123".into(),
                name: "search_messages".into(),
                arguments: r#"{"query":"a"}"#.into()
            })
        );
        assert_eq!(ev[1], LlmEvent::Done(FinishReason::ToolCalls));
    }

    #[test]
    fn flux_coupe_trop_grand_et_erreur_dans_le_flux() {
        // Flux fermé sans finish_reason ni [DONE] : coupé.
        let cut = decode(&[&sse(&json!({"choices":[{"delta":{"content":"Bon"}}]}))]);
        assert_eq!(cut.unwrap_err(), LlmError::BadStream);
        assert!(LlmError::BadStream.retryable());
        // Longueur atteinte.
        let l = decode(&[&sse(&json!({"choices":[{"delta":{"content":"x"},"finish_reason":"length"}]}))]).unwrap();
        assert_eq!(l.last(), Some(&LlmEvent::Done(FinishReason::Length)));
        // M4 : texte (y compris en contenu structuré) et arguments au-delà des bornes.
        let mut d = Mistral.decoder();
        let big = sse(
            &json!({"choices":[{"delta":{"content":[{"type":"thinking","thinking":[{"type":"text","text":"y".repeat(1024 * 1024)}]}]}}]}),
        );
        let mut out = Vec::new();
        let mut res = Ok(());
        for _ in 0..5 {
            res = d.push(big.as_bytes(), &mut out);
        }
        assert_eq!(res.unwrap_err(), LlmError::TooLarge);
        let mut d = Mistral.decoder();
        let args = sse(
            &json!({"choices":[{"delta":{"tool_calls":[{"id":"abcDEF123","index":0,"function":{"name":"n","arguments":"z".repeat(600 * 1024)}}]}}]}),
        );
        d.push(args.as_bytes(), &mut out).unwrap();
        assert_eq!(d.push(args.as_bytes(), &mut out).unwrap_err(), LlmError::TooLarge);
        // Erreur annoncée dans le flux (forme Mistral : `object: "error"`).
        let e =
            decode(&["data: {\"object\":\"error\",\"message\":\"texte secret\",\"type\":\"x\",\"code\":\"1\"}\n\n"]);
        assert_eq!(e.unwrap_err(), LlmError::BadStream);
    }

    #[test]
    fn erreurs_du_fournisseur_sans_texte() {
        let a = Mistral;
        assert_eq!(a.classify_error(401, None, br#"{"message":"Unauthorized"}"#), LlmError::Auth);
        assert_eq!(
            a.classify_error(429, Some(4), br#"{"message":"Rate limit exceeded"}"#),
            LlmError::RateLimited { retry_after_secs: Some(4) }
        );
        assert_eq!(
            a.classify_error(422, None, b"{\"detail\":[{\"msg\":\"secret\"}]}"),
            LlmError::Rejected { status: 422 }
        );
        assert_eq!(
            a.classify_error(400, None, br#"{"object":"error","message":"Tool call id was call_x","code":"3280"}"#),
            LlmError::Rejected { status: 400 }
        );
        assert_eq!(a.classify_error(503, None, b""), LlmError::Provider { status: 503 });
        assert_eq!(a.classify_error(429, None, br#"{"error":"proxy_token_budget"}"#), LlmError::TokenBudget);
        let shown = format!("{:?}", a.classify_error(400, None, b"texte secret du fournisseur"));
        assert!(!shown.contains("secret"));
    }
}
