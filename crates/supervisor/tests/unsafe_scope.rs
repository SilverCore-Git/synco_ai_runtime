//! `unsafe` n'est permis que dans `crates/supervisor/src/sandbox/sys.rs` (03 §5, L06) : ce test
//! parcourt toutes les sources Rust du dépôt et échoue sur tout autre usage.

#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects, missing_docs, reason = "tests")]

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

#[test]
fn unsafe_limite_au_module_sys() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    assert!(files.len() > 20, "sources introuvables");
    let me = Path::new(file!()).file_name().unwrap();
    let markers = ["unsafe {", "unsafe fn", "unsafe impl", "unsafe extern", "allow(unsafe_code"];
    let mut offenders = Vec::new();
    for f in &files {
        if f.file_name() == Some(me) {
            continue;
        }
        let text = std::fs::read_to_string(f).unwrap();
        let rel = f.strip_prefix(&root).unwrap().display().to_string();
        for (i, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or_default();
            if markers.iter().any(|m| code.contains(m)) {
                let allowed = (rel.ends_with("supervisor/src/sandbox/sys.rs") && code.contains("unsafe {"))
                    || (rel.ends_with("supervisor/src/sandbox/mod.rs") && code.contains("allow(unsafe_code"));
                if !allowed {
                    offenders.push(format!("{rel}:{}", i + 1));
                }
            }
        }
    }
    assert!(offenders.is_empty(), "unsafe hors du module sys : {offenders:?}");
    // Le module sys contient bien le seul bloc (sinon ce test ne prouve rien).
    let sys = std::fs::read_to_string(root.join("crates/supervisor/src/sandbox/sys.rs")).unwrap();
    assert_eq!(sys.matches("unsafe {").count(), 1);
}
