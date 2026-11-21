//! Q25 : les journaux de l'épinglage RSA des membres ne portent que des codes : ni clé, ni empreinte,
//! ni identifiant d'utilisateur. Binaire de test à part (un seul test) : la capture `tracing` n'est
//! pas perturbée par des tests parallèles qui partagent les mêmes sites de journalisation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, missing_docs, reason = "tests")]

use std::sync::{Arc, Mutex};

use serde_json::Value;
use synco_ai_runtime::member_pins::{MemberKey, MemberPinStore};
use synco_e2ee::encoding::b64u;

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn jwk(seed: u8) -> String {
    let mut n = vec![seed; 256];
    n[0] |= 0x80;
    format!(r#"{{"kty":"RSA","n":"{}","e":"AQAB"}}"#, b64u(&n))
}

fn key(seed: u8) -> MemberKey {
    MemberKey::from_jwk_str(&jwk(seed)).unwrap()
}

#[test]
fn journaux_sans_cle_ni_empreinte() {
    let buf = Buf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let dir = tempfile::tempdir().unwrap();
    let user = "cm3userconfidentiel000001";
    tracing::subscriber::with_default(subscriber, || {
        let mut s = MemberPinStore::open(dir.path()).unwrap();
        s.check("o1", user, &key(1), 1);
        s.check("o1", user, &key(2), 2);
        s.refuse("o1", user, &key(2), 2);
        assert!(s.accept_pending("o1", user, &key(2).fingerprint));
        assert!(s.rotate("o1", user, &key(2).fingerprint, &key(3)));
    });
    let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    for code in ["member_rsa_key_changed", "member_rsa_key_accepted", "member_rsa_key_rotated"] {
        assert!(logs.contains(code), "{code} absent : {logs}");
    }
    for seed in 1..=3 {
        let k = key(seed);
        let n = serde_json::from_str::<Value>(&jwk(seed)).unwrap()["n"].as_str().unwrap().to_owned();
        for secret in [k.fingerprint.get(..16), k.thumbprint.get(..16), n.get(..16)].map(Option::unwrap) {
            assert!(!logs.contains(secret), "journal sans clé ni empreinte : {logs}");
        }
    }
    assert!(!logs.contains(user), "journal sans identifiant d'utilisateur");
}
