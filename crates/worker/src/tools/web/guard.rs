//! Garde de fuite et provenance de `web_search` / `web_fetch` (docs/plan/10 §4.4, PC93).
//!
//! Faites **avant** toute requête au proxy `web`. Elles ne bloquent ni ne réécrivent jamais : elles
//! désignent ce qui demande confirmation à l'utilisateur, avec le texte exact qui partirait.
//!
//! - Normalisation `N(t)` : NFKC, NFD, retrait des marques combinantes (`Mn`), minuscules. Mots :
//!   suites maximales de caractères `Alphabetic` ou `Numeric` (`char::is_alphanumeric`).
//! - `G5` : HMAC-SHA-256 (clé aléatoire du worker) tronqué à 8 octets de chaque suite de 5 mots des
//!   textes de tiers lus par un outil ; 500 000 entrées au plus, au-delà toute requête demande
//!   confirmation (`guard_saturated`).
//! - `R` : jetons rares (e-mails, numéros d'au moins 6 chiffres, CUID, UUID, URL réduites à hôte + chemin).
//! - `M` : noms des membres (un nom d'un seul mot de moins de 4 caractères est ignoré).
//!
//! Rien de tout cela n'est écrit ni journalisé : empreintes en mémoire du worker seulement.

use std::collections::HashSet;

use icu_normalizer::{ComposingNormalizerBorrowed, DecomposingNormalizerBorrowed};
use icu_properties::CodePointMapData;
use icu_properties::props::GeneralCategory;

/// Nombre maximal d'empreintes de 5 mots (09 §4.2).
pub const G5_MAX: usize = 500_000;
/// Noms de membres gardés au plus (09 §4.2).
pub const NAMES_MAX: usize = 10_000;
/// Longueur d'une suite de mots comparée.
const PASSAGE: usize = 5;

/// Motifs de confirmation (10 §4.4), dans l'ordre où ils sont rapportés.
pub const E2EE_PASSAGE: &str = "e2ee_passage";
/// Jeton rare d'un texte lu.
pub const E2EE_TOKEN: &str = "e2ee_token";
/// Nom d'un membre.
pub const MEMBER_NAME: &str = "member_name";
/// Empreintes saturées.
pub const GUARD_SATURATED: &str = "guard_saturated";
/// URL ni issue d'une recherche ni écrite par l'utilisateur.
pub const URL_PROVENANCE: &str = "url_provenance";

/// Mot normalisé et sa position dans la chaîne d'origine (unités UTF-16, fin exclue).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word {
    /// Mot normalisé.
    pub text: String,
    /// Début (UTF-16).
    pub start: usize,
    /// Fin (UTF-16, exclue).
    pub end: usize,
}

fn lower(c: char) -> char {
    // Correspondance simple : premier caractère de la correspondance complète (`İ` → `i`).
    c.to_lowercase().next().unwrap_or(c)
}

/// Mots de `N(t)` avec leurs positions dans `t`. Chaque caractère d'origine est normalisé seul :
/// les marques combinantes disparaissent sans couper le mot (`nai\u{308}ve` → `naive`).
#[must_use]
pub fn words_with_spans(t: &str) -> Vec<Word> {
    let nfkc = ComposingNormalizerBorrowed::new_nfkc();
    let nfd = DecomposingNormalizerBorrowed::new_nfd();
    let gc = CodePointMapData::<GeneralCategory>::new();
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut start, mut end, mut pos) = (0usize, 0usize, 0usize);
    let mut buf = [0u8; 4];
    for c in t.chars() {
        let width = c.len_utf16();
        let k = nfkc.normalize(c.encode_utf8(&mut buf));
        let d = nfd.normalize(&k);
        for n in d.chars() {
            if gc.get(n) == GeneralCategory::NonspacingMark {
                continue;
            }
            if n.is_alphanumeric() {
                if cur.is_empty() {
                    start = pos;
                }
                cur.push(lower(n));
                end = pos.saturating_add(width);
            } else if !cur.is_empty() {
                out.push(Word { text: std::mem::take(&mut cur), start, end });
            }
        }
        pos = pos.saturating_add(width);
    }
    if !cur.is_empty() {
        out.push(Word { text: cur, start, end });
    }
    out
}

/// Mots de `N(t)`.
#[must_use]
pub fn words(t: &str) -> Vec<String> {
    words_with_spans(t).into_iter().map(|w| w.text).collect()
}

// ---------------------------------------------------------------------------
// Jetons rares
// ---------------------------------------------------------------------------

/// Jeton rare et sa position (UTF-16) dans le texte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// Forme comparée.
    pub value: String,
    /// Début (UTF-16).
    pub start: usize,
    /// Fin (UTF-16, exclue).
    pub end: usize,
}

const fn email_local(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-')
}

const fn email_domain(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
}

/// `X+\.[A-Za-z]{2,}` : plus longue tête de `d` qui en a la forme.
fn email_domain_len(d: &[u8]) -> Option<usize> {
    let mut k = d.len();
    while k > 0 {
        let head = d.get(..k)?;
        let letters = head.iter().rev().take_while(|b| b.is_ascii_alphabetic()).count();
        let dot = k.checked_sub(letters)?.checked_sub(1);
        if letters >= 2
            && let Some(dot) = dot
            && dot > 0
            && head.get(dot) == Some(&b'.')
        {
            return Some(k);
        }
        k = k.saturating_sub(1);
    }
    None
}

/// Positions UTF-16 de chaque octet de début de caractère (octet → position).
fn utf16_index(t: &str) -> Vec<usize> {
    let mut idx = vec![0usize; t.len().saturating_add(1)];
    let mut pos = 0usize;
    for (i, c) in t.char_indices() {
        for j in i..i.saturating_add(c.len_utf8()) {
            if let Some(slot) = idx.get_mut(j) {
                *slot = pos;
            }
        }
        pos = pos.saturating_add(c.len_utf16());
    }
    if let Some(last) = idx.last_mut() {
        *last = pos;
    }
    idx
}

fn span(idx: &[usize], a: usize, b: usize) -> (usize, usize) {
    (idx.get(a).copied().unwrap_or(0), idx.get(b).copied().unwrap_or(0))
}

fn emails(t: &str, idx: &[usize], out: &mut Vec<Token>) {
    let b = t.as_bytes();
    let mut from = 0usize;
    for (at, _) in t.match_indices('@') {
        if at < from {
            continue;
        }
        let local = b.get(..at).unwrap_or_default().iter().rev().take_while(|&&c| email_local(c)).count();
        let rest = b.get(at.saturating_add(1)..).unwrap_or_default();
        let run = rest.iter().take_while(|&&c| email_domain(c)).count();
        if local == 0 {
            continue;
        }
        let Some(len) = email_domain_len(rest.get(..run).unwrap_or_default()) else { continue };
        let start = at.saturating_sub(local);
        let end = at.saturating_add(1).saturating_add(len);
        if let Some(s) = t.get(start..end) {
            let (a, z) = span(idx, start, end);
            out.push(Token { value: s.to_ascii_lowercase(), start: a, end: z });
        }
        from = end;
    }
}

fn digits(t: &str, idx: &[usize], out: &mut Vec<Token>) {
    let b = t.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        let at_digit = b.get(i).is_some_and(u8::is_ascii_digit);
        let after_digit = i > 0 && b.get(i.saturating_sub(1)).is_some_and(u8::is_ascii_digit);
        if !at_digit || after_digit {
            i = i.saturating_add(1);
            continue;
        }
        let start = i;
        let mut value = String::new();
        let mut j = i;
        let mut end = i;
        loop {
            match b.get(j) {
                Some(c) if c.is_ascii_digit() => {
                    value.push(char::from(*c));
                    j = j.saturating_add(1);
                    end = j;
                }
                Some(b' ' | b'.' | b'-') if b.get(j.saturating_add(1)).is_some_and(u8::is_ascii_digit) => {
                    j = j.saturating_add(1);
                }
                _ => break,
            }
        }
        if value.len() >= 6 {
            let (a, z) = span(idx, start, end);
            out.push(Token { value, start: a, end: z });
        }
        i = end.max(start.saturating_add(1));
    }
}

fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .zip([8usize, 4, 4, 4, 12])
            .all(|(p, n)| p.len() == n && p.bytes().all(|c| c.is_ascii_hexdigit()))
}

fn identifiers(t: &str, idx: &[usize], out: &mut Vec<Token>) {
    // Suites maximales de `[A-Za-z0-9-]` : un UUID entier, ou un CUID (`c` + au moins 24 `[a-z0-9]`).
    let b = t.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        let ok = |c: &u8| c.is_ascii_alphanumeric() || *c == b'-';
        if !b.get(i).is_some_and(ok) {
            i = i.saturating_add(1);
            continue;
        }
        let start = i;
        while b.get(i).is_some_and(ok) {
            i = i.saturating_add(1);
        }
        let Some(run) = t.get(start..i) else { continue };
        if is_uuid(run) {
            let (a, z) = span(idx, start, i);
            out.push(Token { value: run.to_ascii_lowercase(), start: a, end: z });
            continue;
        }
        // Morceaux sans tiret : CUID en minuscules.
        let mut off = start;
        for piece in run.split('-') {
            let cuid = piece.len() >= 25
                && piece.starts_with('c')
                && piece.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
            if cuid {
                let (a, z) = span(idx, off, off.saturating_add(piece.len()));
                out.push(Token { value: piece.to_owned(), start: a, end: z });
            }
            off = off.saturating_add(piece.len()).saturating_add(1);
        }
    }
}

/// Fin d'une URL écrite dans un texte : premier blanc ou chevron, ponctuation finale retirée.
pub(crate) fn url_extent(rest: &str) -> usize {
    let raw = rest.find(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '`')).unwrap_or(rest.len());
    let head = rest.get(..raw).unwrap_or_default();
    head.trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '}', '\'', '»', '…']).len()
}

/// URL `http(s)://` écrites dans `t` (positions en octets).
pub(crate) fn urls_in(t: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let lower = t.to_ascii_lowercase();
    let mut from = 0usize;
    while let Some(rel) = lower.get(from..).and_then(|s| s.find("http")) {
        let start = from.saturating_add(rel);
        let tail = lower.get(start..).unwrap_or_default();
        let scheme = if tail.starts_with("https://") {
            8
        } else if tail.starts_with("http://") {
            7
        } else {
            from = start.saturating_add(4);
            continue;
        };
        let len = url_extent(t.get(start..).unwrap_or_default());
        if len > scheme {
            out.push((start, start.saturating_add(len)));
        }
        from = start.saturating_add(len.max(4));
    }
    out
}

fn url_tokens(t: &str, idx: &[usize], out: &mut Vec<Token>) {
    for (a, b) in urls_in(t) {
        let Some(raw) = t.get(a..b) else { continue };
        let Ok(u) = url::Url::parse(raw) else { continue };
        let Some(host) = u.host_str() else { continue };
        let (s, e) = span(idx, a, b);
        out.push(Token { value: format!("{}{}", host.to_ascii_lowercase(), u.path()), start: s, end: e });
    }
}

/// Jetons rares de `t` (mêmes règles pour les textes lus et la requête).
#[must_use]
pub fn rare_tokens(t: &str) -> Vec<Token> {
    let idx = utf16_index(t);
    let mut out = Vec::new();
    emails(t, &idx, &mut out);
    digits(t, &idx, &mut out);
    identifiers(t, &idx, &mut out);
    url_tokens(t, &idx, &mut out);
    out
}

// ---------------------------------------------------------------------------
// Garde
// ---------------------------------------------------------------------------

/// Résultat d'un contrôle : motifs (ordre de 10 §4.4) et passages à souligner (UTF-16, triés).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Motifs, sans doublon.
    pub reasons: Vec<&'static str>,
    /// Passages `(début, fin)`.
    pub spans: Vec<(usize, usize)>,
}

impl Report {
    /// Rien à confirmer.
    #[must_use]
    pub fn is_clear(&self) -> bool {
        self.reasons.is_empty()
    }

    fn add(&mut self, reason: &'static str) {
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }
}

/// Empreintes d'une conversation (mémoire du worker seulement).
pub struct Guard {
    key: zeroize::Zeroizing<[u8; 32]>,
    g5: HashSet<[u8; 8]>,
    rare: HashSet<String>,
    names: Vec<Vec<String>>,
    saturated: bool,
    cap: usize,
}

impl core::fmt::Debug for Guard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Guard").field("g5", &self.g5.len()).field("saturated", &self.saturated).finish_non_exhaustive()
    }
}

impl Guard {
    /// Garde vide, clé tirée par `rng`.
    pub fn new(rng: &mut impl synco_e2ee::RandomSource) -> Result<Self, synco_e2ee::Error> {
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        rng.fill(key.as_mut())?;
        Ok(Self { key, g5: HashSet::new(), rare: HashSet::new(), names: Vec::new(), saturated: false, cap: G5_MAX })
    }

    /// Plafond d'empreintes réduit (tests : jamais 500 000 calculs pour éprouver la saturation).
    #[doc(hidden)]
    #[must_use]
    pub const fn with_cap(mut self, cap: usize) -> Self {
        self.cap = cap;
        self
    }

    /// Garde vide avec une clé du système.
    pub fn with_os_key() -> Result<Self, synco_e2ee::Error> {
        Self::new(&mut synco_e2ee::OsRandom)
    }

    fn fingerprint(&self, words: &[String]) -> Option<[u8; 8]> {
        let tag = synco_e2ee::primitives::hmac_sha256(self.key.as_ref(), words.join(" ").as_bytes()).ok()?;
        let mut out = [0u8; 8];
        out.copy_from_slice(tag.get(..8)?);
        Some(out)
    }

    /// Ajoute un texte lu (message, fichier, ticket…).
    pub fn add_text(&mut self, text: &str) {
        let w = words(text);
        for win in w.windows(PASSAGE) {
            if self.g5.len() >= self.cap {
                self.saturated = true;
                break;
            }
            if let Some(fp) = self.fingerprint(win) {
                self.g5.insert(fp);
            }
        }
        if self.g5.len() >= self.cap {
            self.saturated = true;
        }
        for t in rare_tokens(text) {
            self.rare.insert(t.value);
        }
    }

    /// Ajoute des noms de membres (au plus [`NAMES_MAX`] en tout).
    pub fn add_names<'a>(&mut self, names: impl IntoIterator<Item = &'a str>) {
        for n in names {
            if self.names.len() >= NAMES_MAX {
                break;
            }
            let w = words(n);
            let short_single = w.len() == 1 && w.first().is_some_and(|x| x.chars().count() < 4);
            if w.is_empty() || short_single || self.names.contains(&w) {
                continue;
            }
            self.names.push(w);
        }
    }

    /// Empreintes saturées.
    #[must_use]
    pub const fn saturated(&self) -> bool {
        self.saturated
    }

    /// Force l'état saturé (tests).
    #[doc(hidden)]
    pub fn force_saturated(&mut self) {
        self.saturated = true;
    }

    /// Contrôle une chaîne `q` (requête, ou chemin et requête décodés d'une URL).
    #[must_use]
    pub fn check(&self, q: &str) -> Report {
        let mut r = Report::default();
        let w = words_with_spans(q);
        let texts: Vec<String> = w.iter().map(|x| x.text.clone()).collect();
        for (i, win) in texts.windows(PASSAGE).enumerate() {
            if self.fingerprint(win).is_some_and(|fp| self.g5.contains(&fp)) {
                r.add(E2EE_PASSAGE);
                let a = w.get(i).map_or(0, |x| x.start);
                let z = w.get(i.saturating_add(PASSAGE.saturating_sub(1))).map_or(0, |x| x.end);
                r.spans.push((a, z));
            }
        }
        for t in rare_tokens(q) {
            if self.rare.contains(&t.value) {
                r.add(E2EE_TOKEN);
                r.spans.push((t.start, t.end));
            }
        }
        for name in &self.names {
            let n = name.len();
            if n == 0 || n > texts.len() {
                continue;
            }
            for (i, win) in texts.windows(n).enumerate() {
                if win == name.as_slice() {
                    r.add(MEMBER_NAME);
                    let a = w.get(i).map_or(0, |x| x.start);
                    let z = w.get(i.saturating_add(n.saturating_sub(1))).map_or(0, |x| x.end);
                    r.spans.push((a, z));
                }
            }
        }
        if self.saturated {
            r.add(GUARD_SATURATED);
        }
        r.spans = merge(r.spans);
        r
    }
}

/// Passages triés, ceux qui se chevauchent ou se touchent fusionnés.
fn merge(mut spans: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    spans.sort_unstable();
    let mut out: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (s, e) in spans {
        match out.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/// Forme canonique `C(u)` : analyse WHATWG (schéma et hôte en minuscules, hôte en punycode, port par
/// défaut retiré), fragment retiré, chemin et requête inchangés. `None` : URL illisible.
#[must_use]
pub fn canonical(u: &str) -> Option<String> {
    let mut url = url::Url::parse(u.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    url.set_fragment(None);
    Some(url.to_string())
}

/// URL canoniques écrites dans un texte (messages de l'utilisateur).
#[must_use]
pub fn urls_written(t: &str) -> Vec<String> {
    urls_in(t).into_iter().filter_map(|(a, b)| t.get(a..b)).filter_map(canonical).collect()
}

/// Chaîne contrôlée par la garde pour `web_fetch` : chemin et requête décodés du pourcentage
/// (décodage avec remplacement des octets non UTF-8).
#[must_use]
pub fn fetch_guard_text(u: &url::Url) -> String {
    let mut pq = u.path().to_owned();
    if let Some(q) = u.query() {
        pq.push('?');
        pq.push_str(q);
    }
    percent_encoding::percent_decode_str(&pq).decode_utf8_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        let raw = include_str!("../../../../../docs/plan/vectors/web-guard.json");
        serde_json::from_str(raw).expect("vecteurs")
    }

    fn strings(v: &Value) -> Vec<String> {
        v.as_array().expect("tableau").iter().map(|x| x.as_str().expect("chaîne").to_owned()).collect()
    }

    fn guard(v: &Value) -> Guard {
        let mut g = Guard::new(&mut synco_e2ee::OsRandom).expect("clé");
        for t in strings(&v["guardContext"]["e2eeTexts"]) {
            g.add_text(&t);
        }
        let names = strings(&v["guardContext"]["memberNames"]);
        g.add_names(names.iter().map(String::as_str));
        g
    }

    #[test]
    fn normalisation_des_vecteurs() {
        let v = vectors();
        for case in v["normalization"].as_array().expect("cas") {
            let input = case["input"].as_str().expect("entrée");
            assert_eq!(words(input), strings(&case["words"]), "{input}");
        }
        // Marque combinante séparée dans l'original : le mot n'est pas coupé.
        assert_eq!(words("nai\u{308}ve"), ["naive"]);
    }

    #[test]
    fn garde_des_vecteurs() {
        let v = vectors();
        let g = guard(&v);
        for case in v["guardCases"].as_array().expect("cas") {
            let name = case["name"].as_str().expect("nom");
            let q = case["query"].as_str().expect("requête");
            let report = if case["saturated"].as_bool() == Some(true) {
                let mut s = guard(&v);
                s.force_saturated();
                s.check(q)
            } else {
                g.check(q)
            };
            let want = strings(&case["expectReasons"]);
            assert_eq!(report.reasons, want, "{name}");
            assert_eq!(report.is_clear(), case["expect"] == "ok", "{name}");
            if !report.reasons.is_empty() && report.reasons != [GUARD_SATURATED] {
                assert!(!report.spans.is_empty(), "{name}");
            }
        }
    }

    #[test]
    fn garde_des_url_des_vecteurs() {
        let v = vectors();
        let g = guard(&v);
        for case in v["fetchGuardCases"].as_array().expect("cas") {
            let name = case["name"].as_str().expect("nom");
            let u = url::Url::parse(&format!("https://site.example{}", case["pathAndQuery"].as_str().expect("chemin")))
                .expect("url");
            let decoded = fetch_guard_text(&u);
            assert_eq!(decoded, case["decoded"].as_str().expect("décodé"), "{name}");
            assert_eq!(g.check(&decoded).reasons, strings(&case["expectReasons"]), "{name}");
        }
    }

    #[test]
    fn provenance_des_vecteurs() {
        let v = vectors();
        let p = &v["provenance"];
        let known: HashSet<String> = strings(&p["searchUrls"])
            .iter()
            .chain(strings(&p["userUrls"]).iter())
            .filter_map(|u| canonical(u))
            .collect();
        for case in p["cases"].as_array().expect("cas") {
            let name = case["name"].as_str().expect("nom");
            let c = canonical(case["url"].as_str().expect("url")).expect("canonique");
            assert_eq!(c, case["canonical"].as_str().expect("forme"), "{name}");
            assert_eq!(known.contains(&c), case["expect"] == "ok", "{name}");
        }
    }

    #[test]
    fn positions_utf16_des_passages() {
        let mut g = Guard::new(&mut synco_e2ee::OsRandom).expect("clé");
        g.add_names(["Claire Martin"]);
        let q = "😀 avis Claire Martin";
        let r = g.check(q);
        assert_eq!(r.reasons, [MEMBER_NAME]);
        // 😀 = 2 unités UTF-16, espace, « avis », espace : « Claire » commence à 8.
        assert_eq!(r.spans, [(8, 21)]);
    }

    #[test]
    fn jetons_rares() {
        let t: Vec<String> =
            rare_tokens("Écrire à A.B@Ex.org, tél. 01-23-45-67-89 ; id 123e4567-e89b-12d3-a456-426614174000.")
                .into_iter()
                .map(|t| t.value)
                .collect();
        // La fin de l'UUID contient aussi une suite de plus de 6 chiffres : même règle des deux côtés.
        assert_eq!(t, ["a.b@ex.org", "0123456789", "456426614174000", "123e4567-e89b-12d3-a456-426614174000"]);
        assert!(rare_tokens("12345").is_empty());
        assert!(rare_tokens("pas@arobase").is_empty());
        assert_eq!(urls_written("voir https://Ex.org/a?b=1#f, merci"), ["https://ex.org/a?b=1"]);
    }

    #[test]
    fn saturation_au_plafond() {
        let mut g = Guard::new(&mut synco_e2ee::OsRandom).expect("clé").with_cap(10);
        g.add_text("un deux trois quatre cinq six sept huit neuf dix onze douze treize");
        assert!(!g.saturated(), "9 fenêtres : sous le plafond");
        g.add_text("alpha beta gamma delta epsilon");
        assert!(g.saturated(), "10 entrées : plafond atteint");
        assert!(g.saturated());
        assert_eq!(g.check("meteo paris demain").reasons, [GUARD_SATURATED]);
    }
}
