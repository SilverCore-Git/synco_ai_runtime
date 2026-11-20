//! Séparation du raisonnement entouré de `<think>…</think>` émis en ligne par les modèles
//! « raisonneurs » sans champ dédié (DeepSeek-R1, QwQ, Magistral, Ollama). Équivalent de
//! `ThinkTagSplitter` (`synco_api/src/services/ai/providerAdapters/thinkTagSplitter.ts`, et sa copie
//! de `synco_app` qui ajoute `flush`) : morceau par morceau, en gardant juste assez de texte en
//! réserve pour ne jamais couper une balise à cheval sur deux morceaux.

const OPEN: &str = "<think>";
const CLOSE: &str = "</think>";
/// Balises de raisonnement de l'endpoint compatible OpenAI de Gemini (`include_thoughts`).
const GEMINI_OPEN: &str = "<thought>";
const GEMINI_CLOSE: &str = "</thought>";

/// Texte et raisonnement extraits d'un morceau.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Split {
    /// Texte de la réponse.
    pub text: String,
    /// Raisonnement.
    pub thinking: String,
}

/// Séparateur à état.
#[derive(Debug, Clone)]
pub struct ThinkTagSplitter {
    carry: String,
    in_thinking: bool,
    open: &'static str,
    close: &'static str,
}

impl Default for ThinkTagSplitter {
    fn default() -> Self {
        Self { carry: String::new(), in_thinking: false, open: OPEN, close: CLOSE }
    }
}

/// Plus long suffixe de `s` qui est un préfixe strict de `tag` (en octets, sur une frontière de
/// caractère : les balises sont ASCII).
fn tail_prefix_len(s: &str, tag: &str) -> usize {
    let max = s.len().min(tag.len().saturating_sub(1));
    (1..=max)
        .rev()
        .find(|&len| s.get(s.len().saturating_sub(len)..).is_some_and(|tail| tag.starts_with(tail)))
        .unwrap_or(0)
}

impl ThinkTagSplitter {
    /// Séparateur des balises `<thought>…</thought>` (Gemini).
    #[must_use]
    pub fn thought_tags() -> Self {
        Self { open: GEMINI_OPEN, close: GEMINI_CLOSE, ..Self::default() }
    }

    /// Ajoute un morceau.
    pub fn push(&mut self, chunk: &str) -> Split {
        let mut buf = core::mem::take(&mut self.carry);
        buf.push_str(chunk);
        let mut out = Split::default();
        let mut rest: &str = &buf;
        loop {
            let tag = if self.in_thinking { self.close } else { self.open };
            match rest.find(tag) {
                None => {
                    let keep = tail_prefix_len(rest, tag);
                    let cut = rest.len().saturating_sub(keep);
                    let (safe, tail) = rest.split_at_checked(cut).unwrap_or((rest, ""));
                    self.target(&mut out).push_str(safe);
                    self.carry = tail.to_owned();
                    return out;
                }
                Some(at) => {
                    let (before, after) = rest.split_at_checked(at).unwrap_or((rest, ""));
                    self.target(&mut out).push_str(before);
                    rest = after.get(tag.len()..).unwrap_or("");
                    self.in_thinking = !self.in_thinking;
                }
            }
        }
    }

    /// Fin du flux : rend ce qui restait en réserve (un début de balise jamais complété).
    pub fn flush(&mut self) -> Split {
        let carry = core::mem::take(&mut self.carry);
        let mut out = Split::default();
        self.target(&mut out).push_str(&carry);
        out
    }

    fn target<'a>(&self, out: &'a mut Split) -> &'a mut String {
        if self.in_thinking { &mut out.thinking } else { &mut out.text }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(chunks: &[&str]) -> (String, String) {
        let mut s = ThinkTagSplitter::default();
        let (mut t, mut th) = (String::new(), String::new());
        for c in chunks {
            let o = s.push(c);
            t.push_str(&o.text);
            th.push_str(&o.thinking);
        }
        let o = s.flush();
        t.push_str(&o.text);
        th.push_str(&o.thinking);
        (t, th)
    }

    // Mêmes cas que thinkTagSplitter.test.ts.
    #[test]
    fn cas_de_l_api() {
        assert_eq!(run(&["Bonjour"]), ("Bonjour".into(), String::new()));
        assert_eq!(run(&["<think>je pense</think>Réponse"]), ("Réponse".into(), "je pense".into()));
        assert_eq!(run(&["<thi", "nk>abc</th", "ink>déf"]), ("déf".into(), "abc".into()));
        assert_eq!(run(&["a<", "b"]), ("a<b".into(), String::new()));
        assert_eq!(run(&["x</think>y"]), ("x</think>y".into(), String::new()));
        assert_eq!(
            run(&["<think>un", "</think>", "deux<think>trois</think>quatre"]),
            ("deuxquatre".into(), "untrois".into())
        );
        // Accents et balise coupée au milieu d'un caractère multi-octets voisin.
        assert_eq!(run(&["é<thi", "nk>ü</think>à"]), ("éà".into(), "ü".into()));
        // Balise jamais fermée : la réserve est rendue à la fin.
        assert_eq!(run(&["<think>pas fini</thi"]), (String::new(), "pas fini</thi".into()));
    }

    #[test]
    fn balises_thought_de_gemini() {
        let mut s = ThinkTagSplitter::thought_tags();
        let a = s.push("<thou");
        let b = s.push("ght>je vois</thought>Salut <think>ok</think>");
        assert_eq!((a.text.as_str(), b.thinking.as_str()), ("", "je vois"));
        assert_eq!(b.text, "Salut <think>ok</think>");
    }
}
