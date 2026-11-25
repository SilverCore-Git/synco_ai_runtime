//! Conversion d'une page lue par `web_fetch` en texte, **dans le bac à sable** du worker (10 §4.2) : un
//! HTML hostile n'est jamais analysé par le superviseur. Analyseur volontairement simple et tolérant,
//! en un seul passage borné, sans récursion ni allocation proportionnelle à autre chose que l'entrée :
//!
//! - `<script>`, `<style>`, `<noscript>`, `<template>`, `<svg>`, `<math>`, `<iframe>`, `<object>`,
//!   `<head>` (sauf `<title>`) et les commentaires disparaissent avec leur contenu ;
//! - les balises de bloc deviennent des sauts de ligne, les autres disparaissent (le texte des liens
//!   reste, **jamais** leur adresse : les liens d'une page ne deviennent pas des URL « issues d'une
//!   recherche ») ;
//! - entités nommées courantes et numériques décodées ; caractères de contrôle retirés ; blancs
//!   resserrés.

/// Balises dont le contenu est jeté.
const SKIP: [&str; 9] = ["script", "style", "noscript", "template", "svg", "math", "iframe", "object", "head"];
/// Balises qui coupent une ligne.
const BLOCK: [&str; 30] = [
    "p",
    "div",
    "br",
    "li",
    "ul",
    "ol",
    "tr",
    "table",
    "section",
    "article",
    "header",
    "footer",
    "nav",
    "aside",
    "main",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "pre",
    "blockquote",
    "hr",
    "dd",
    "dt",
    "dl",
    "figcaption",
    "form",
    "title",
];

/// Texte d'un document HTML et son titre.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Page {
    /// `<title>`, s'il existe (≤ 200 caractères).
    pub title: Option<String>,
    /// Texte.
    pub text: String,
}

fn entity(name: &str) -> Option<char> {
    if let Some(num) = name.strip_prefix('#') {
        let n = match num.strip_prefix(['x', 'X']) {
            Some(hex) => u32::from_str_radix(hex, 16).ok()?,
            None => num.parse::<u32>().ok()?,
        };
        return char::from_u32(n).filter(|c| !c.is_control() || *c == '\n' || *c == '\t');
    }
    Some(match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => ' ',
        "eacute" => 'é',
        "egrave" => 'è',
        "ecirc" => 'ê',
        "agrave" => 'à',
        "acirc" => 'â',
        "ccedil" => 'ç',
        "ocirc" => 'ô',
        "ucirc" => 'û',
        "ugrave" => 'ù',
        "icirc" => 'î',
        "iuml" => 'ï',
        "euml" => 'ë',
        "laquo" => '«',
        "raquo" => '»',
        "hellip" => '…',
        "mdash" => '—',
        "ndash" => '–',
        "rsquo" => '\u{2019}',
        "lsquo" => '\u{2018}',
        "rdquo" => '\u{201D}',
        "ldquo" => '\u{201C}',
        "copy" => '©',
        "euro" => '€',
        _ => return None,
    })
}

/// Décode les entités de `s` (une entité inconnue reste telle quelle).
#[must_use]
pub fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(rest.get(..i).unwrap_or_default());
        let tail = rest.get(i..).unwrap_or_default();
        let end = tail.get(1..).and_then(|t| t.find(';')).filter(|&e| e > 0 && e <= 10);
        match end.and_then(|e| tail.get(1..=e).map(|n| (e, n))).and_then(|(e, n)| entity(n).map(|c| (e, c))) {
            Some((e, c)) => {
                out.push(c);
                rest = tail.get(e.saturating_add(2)..).unwrap_or_default();
            }
            None => {
                out.push('&');
                rest = tail.get(1..).unwrap_or_default();
            }
        }
    }
    out.push_str(rest);
    out
}

/// Nom de balise en minuscules (`/p` → `p`) et sa forme (ouverture ou fermeture).
fn tag_name(inner: &str) -> (String, bool) {
    let closing = inner.starts_with('/');
    let name: String = inner
        .trim_start_matches('/')
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .take(16)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    (name, closing)
}

/// Resserre les blancs : une espace entre mots, un saut de ligne entre blocs.
fn tidy(raw: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut count = 0usize;
    let mut newlines = 0u8;
    let mut space = false;
    for c in raw.chars() {
        if count >= max_chars {
            break;
        }
        if c == '\n' {
            newlines = newlines.saturating_add(1);
            space = false;
            continue;
        }
        if c.is_whitespace() {
            space = true;
            continue;
        }
        if c.is_control() || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}') {
            continue;
        }
        if !out.is_empty() {
            if newlines > 0 {
                out.push('\n');
                count = count.saturating_add(1);
            } else if space {
                out.push(' ');
                count = count.saturating_add(1);
            }
        }
        newlines = 0;
        space = false;
        out.push(c);
        count = count.saturating_add(1);
    }
    out
}

/// Convertit `html` en texte (au plus `max_chars` caractères).
#[must_use]
pub fn html_to_text(html: &str, max_chars: usize) -> Page {
    let mut raw = String::new();
    let mut title = String::new();
    let mut in_title = false;
    let mut skip: Option<String> = None;
    let mut rest = html;
    // Borne de travail : le texte brut ne dépasse jamais 4 × le plafond (le reste ne serait pas rendu).
    let budget = max_chars.saturating_mul(4).max(4096);
    while !rest.is_empty() && raw.len() < budget {
        let Some(lt) = rest.find('<') else {
            if skip.is_none() {
                raw.push_str(rest);
            }
            break;
        };
        let text = rest.get(..lt).unwrap_or_default();
        if skip.is_none() {
            if in_title {
                title.push_str(text);
            } else {
                raw.push_str(text);
            }
        }
        let tail = rest.get(lt..).unwrap_or_default();
        if tail.starts_with("<!--") {
            rest = tail.find("-->").and_then(|e| tail.get(e.saturating_add(3)..)).unwrap_or_default();
            continue;
        }
        let Some(gt) = tail.find('>') else { break };
        let inner = tail.get(1..gt).unwrap_or_default();
        rest = tail.get(gt.saturating_add(1)..).unwrap_or_default();
        let (name, closing) = tag_name(inner);
        if let Some(s) = &skip {
            if closing && *s == name {
                skip = None;
            }
            continue;
        }
        if name == "title" {
            in_title = !closing;
            continue;
        }
        if !closing && SKIP.contains(&name.as_str()) && !inner.trim_end().ends_with('/') {
            // `<head>` : on garde `<title>`, qui y vit ; le reste de l'en-tête n'a pas de texte utile.
            if name != "head" {
                skip = Some(name);
            }
            continue;
        }
        if BLOCK.contains(&name.as_str()) {
            raw.push('\n');
        } else if matches!(name.as_str(), "td" | "th") {
            raw.push(' ');
        }
    }
    let title = tidy(&decode_entities(&title), 200);
    Page { title: (!title.is_empty()).then_some(title), text: tidy(&decode_entities(&raw), max_chars) }
}

/// Texte d'un corps non HTML (texte, Markdown, JSON, XML) : caractères de contrôle retirés, borné.
#[must_use]
pub fn plain_text(body: &str, max_chars: usize) -> String {
    body.chars().filter(|c| !c.is_control() || matches!(c, '\n' | '\t')).take(max_chars).collect()
}

/// Décode un corps selon le `charset` du `content-type` (UTF-8 par défaut, Latin-1 / windows-1252
/// lus octet pour octet).
#[must_use]
pub fn decode_body(bytes: &[u8], content_type: &str) -> String {
    let ct = content_type.to_ascii_lowercase();
    let latin1 =
        ["iso-8859-1", "latin1", "windows-1252", "cp1252"].iter().any(|c| ct.contains(&format!("charset={c}")));
    if latin1 { bytes.iter().map(|&b| char::from(b)).collect() } else { String::from_utf8_lossy(bytes).into_owned() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn texte_titre_et_blocs() {
        let p = html_to_text(
            "<html><head><title>Ma &amp; page</title><script>alert('x')</script><style>p{}</style></head>\
             <body><h1>Titre</h1><p>Un <b>mot</b> et <a href=\"https://piege.example/?d=1\">un lien</a>.</p>\
             <!-- secret --><ul><li>a</li><li>b</li></ul><p>caf&eacute; &#233;t&#xE9;</p></body></html>",
            1000,
        );
        assert_eq!(p.title.as_deref(), Some("Ma & page"));
        assert_eq!(p.text, "Titre\nUn mot et un lien.\na\nb\ncafé été");
        assert!(!p.text.contains("piege"), "jamais l'adresse d'un lien");
        assert!(!p.text.contains("alert") && !p.text.contains("secret"));
    }

    #[test]
    fn html_hostile_borne() {
        // Balises jamais fermées, entités géantes, contrôles et caractères bidirectionnels.
        let evil = format!("<script>{}", "x".repeat(10_000));
        assert_eq!(html_to_text(&evil, 100).text, "");
        let p = html_to_text("<p>a\u{202E}b\u{0}c &#0; &#xFFFFFFFF; &bogus;</p><div", 100);
        assert_eq!(p.text, "abc &#0; &#xFFFFFFFF; &bogus;");
        let long = "mot ".repeat(10_000);
        assert_eq!(html_to_text(&long, 50).text.chars().count(), 50);
        assert_eq!(html_to_text("<<<>>>", 10).text, ">>");
    }

    #[test]
    fn corps_non_html() {
        assert_eq!(plain_text("{\"a\":1}\u{7}", 100), "{\"a\":1}");
        assert_eq!(decode_body(&[0x63, 0x61, 0x66, 0xe9], "text/plain; charset=ISO-8859-1"), "café");
        assert_eq!(decode_body("été".as_bytes(), "text/html"), "été");
    }
}
