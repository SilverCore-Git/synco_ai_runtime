//! `unsafe` n'est permis que dans `crates/supervisor/src/sandbox/sys.rs` (03 §5, L06) : ce test
//! parcourt toutes les sources Rust du dépôt et échoue sur tout autre usage, quelle que soit la mise
//! en forme (`unsafe{`, `unsafe fn`, `unsafe impl`, `unsafe extern`, `unsafe trait`, attribut
//! `allow`/`expect`/`warn` sur `unsafe_code`, même réparti sur plusieurs lignes). Il vérifie aussi
//! que chaque racine de crate (`src/lib.rs`, `src/main.rs`) porte `#![forbid(unsafe_code)]`, sauf
//! la bibliothèque du superviseur (`#![deny(unsafe_code)]`).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::string_slice,
    missing_docs,
    reason = "tests"
)]

use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        let name = e.file_name();
        if p.is_dir() {
            if name != "target" && name != ".git" {
                rust_files(&p, out);
            }
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Retire commentaires (`//`, `/* */`), chaînes et caractères, puis tout blanc : il ne reste que
/// des jetons collés, insensibles à la mise en forme.
fn normalize(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
            }
            b'r' if b.get(i + 1) == Some(&b'#') || (b.get(i + 1) == Some(&b'"')) => {
                // Chaîne brute r"…" ou r#"…"#.
                let mut j = i + 1;
                let mut hashes = 0;
                while b.get(j) == Some(&b'#') {
                    hashes += 1;
                    j += 1;
                }
                if b.get(j) == Some(&b'"') {
                    let close: Vec<u8> = std::iter::once(b'"').chain(std::iter::repeat_n(b'#', hashes)).collect();
                    j += 1;
                    while j < b.len() && !b[j..].starts_with(&close) {
                        j += 1;
                    }
                    i = j + close.len();
                } else {
                    out.push('r');
                    i += 1;
                }
            }
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
            }
            b'\'' if b.get(i + 2) == Some(&b'\'') => i += 3,
            b'\'' if b.get(i + 1) == Some(&b'\\') => {
                // Caractère échappé : '\n', '\'', '\u{…}'.
                let mut j = i + 3;
                while j < b.len() && b[j] != b'\'' {
                    j += 1;
                }
                i = j + 1;
            }
            c if c.is_ascii_whitespace() => i += 1,
            _ => {
                let ch = src[i..].chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    out
}

/// Usages interdits dans un texte normalisé.
fn offenses(norm: &str) -> Vec<&'static str> {
    let mut found = Vec::new();
    for kw in ["unsafe{", "unsafefn", "unsafeimpl", "unsafeextern", "unsafetrait"] {
        if norm.contains(kw) {
            found.push(kw);
        }
    }
    // Tout attribut qui RELÂCHE `unsafe_code` : allow, expect, warn (forbid et deny sont permis).
    let mut rest = norm;
    while let Some(pos) = rest.find("unsafe_code") {
        let before = &rest[..pos];
        let attr = before.rfind("#[").max(before.rfind("#!["));
        if let Some(a) = attr {
            let head = &before[a..];
            if ["allow(", "expect(", "warn("].iter().any(|l| head.contains(l)) {
                found.push("attribut qui relâche unsafe_code");
            }
        }
        rest = &rest[pos + "unsafe_code".len()..];
    }
    found
}

#[test]
fn detection_robuste() {
    for bad in [
        "fn f(){ unsafe{ x() } }",
        "fn f(){ unsafe\n{ x() } }",
        "unsafe  fn g(){}",
        "unsafe impl Send for X {}",
        "#[expect(unsafe_code)] mod m;",
        "#[allow(\n  clippy::x,\n  unsafe_code,\n)] mod m;",
        "#![warn(unsafe_code)]",
    ] {
        assert!(!offenses(&normalize(bad)).is_empty(), "non détecté : {bad}");
    }
    for ok in [
        "let q = b'\"'; let s = \"x\"; #![forbid(unsafe_code)]",
        "#![deny(unsafe_code)]",
        "// unsafe { }",
        "let s = \"unsafe { }\";",
        "/* unsafe fn */",
    ] {
        assert!(offenses(&normalize(ok)).is_empty(), "faux positif : {ok}");
    }
}

#[test]
fn unsafe_limite_au_module_sys() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    assert!(files.len() > 20, "sources introuvables");
    let me = Path::new(file!()).file_name().unwrap();
    let mut offenders = Vec::new();
    for f in &files {
        if f.file_name() == Some(me) {
            continue;
        }
        let rel = f.strip_prefix(&root).unwrap().display().to_string();
        let found = offenses(&normalize(&std::fs::read_to_string(f).unwrap()));
        let allowed: &[&str] = if rel.ends_with("supervisor/src/sandbox/sys.rs") {
            &["unsafe{"]
        } else if rel.ends_with("supervisor/src/sandbox/mod.rs") {
            &["attribut qui relâche unsafe_code"]
        } else {
            &[]
        };
        for o in found {
            if !allowed.contains(&o) {
                offenders.push(format!("{rel} : {o}"));
            }
        }
    }
    assert!(offenders.is_empty(), "unsafe hors du module sys : {offenders:?}");
    let sys = normalize(&std::fs::read_to_string(root.join("crates/supervisor/src/sandbox/sys.rs")).unwrap());
    assert_eq!(sys.matches("unsafe{").count(), 1, "un seul bloc dans sys.rs");
    let module = normalize(&std::fs::read_to_string(root.join("crates/supervisor/src/sandbox/mod.rs")).unwrap());
    assert_eq!(module.matches("unsafe_code").count(), 1, "une seule levée, sur `mod sys`");
    assert!(module.contains("unsafe_code,reason=") && module.contains(")]modsys;"));
}

#[test]
fn racines_de_crate_interdisent_unsafe() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut missing = Vec::new();
    for e in std::fs::read_dir(root.join("crates")).unwrap().flatten() {
        for file in ["src/lib.rs", "src/main.rs"] {
            let p = e.path().join(file);
            let Ok(src) = std::fs::read_to_string(&p) else { continue };
            let norm = normalize(&src);
            let rel = p.strip_prefix(&root).unwrap().display().to_string();
            let ok = if rel == "crates/supervisor/src/lib.rs" {
                norm.contains("#![deny(unsafe_code)]")
            } else {
                norm.contains("#![forbid(unsafe_code)]")
            };
            if !ok {
                missing.push(rel);
            }
        }
    }
    assert!(missing.is_empty(), "racines sans interdiction : {missing:?}");
}
