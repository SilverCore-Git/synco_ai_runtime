//! Attaques contre le mandataire LLM lui-même (I1, I2, I3), sans bac à sable : un client hostile
//! parle directement au socket d'un worker. Tournent partout (flatpak compris).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs,
    reason = "tests"
)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use synco_ai_runtime::launcher::{LlmBudget, LlmRoute};
use synco_ai_runtime::sandbox::proxy::{LlmProxy, MAX_CONNECTIONS_PER_WORKER, MAX_REQUEST_BYTES};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

/// Fournisseur simulé : compte les appels reçus.
async fn provider(usage: Option<u64>) -> (String, Arc<Mutex<u32>>) {
    let calls = Arc::new(Mutex::new(0u32));
    let c2 = Arc::clone(&calls);
    let app = axum::Router::new().fallback(move || {
        let calls = Arc::clone(&c2);
        async move {
            *calls.lock().unwrap() += 1;
            let body = match usage {
                Some(t) => format!("{{\"usage\":{{\"total_tokens\":{t}}}}}"),
                None => "{}".to_owned(),
            };
            ([("content-type", "application/json")], body)
        }
    });
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (format!("http://{addr}/v1"), calls)
}

struct Served {
    _dir: tempfile::TempDir,
    socket: std::path::PathBuf,
    _task: tokio::task::JoinHandle<()>,
}

fn serve(proxy: &Arc<LlmProxy>, base: &str, budget: LlmBudget) -> Served {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("llm.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let route = LlmRoute { provider: "openai".into(), base_url: base.into(), budget };
    let task = proxy.serve(listener, route).unwrap();
    Served { _dir: dir, socket, _task: task }
}

/// Ligne de statut (vide si rien en 10 s : un mandataire sans borne ne doit pas bloquer le test).
async fn status_line(s: &mut UnixStream) -> String {
    let mut buf = Vec::new();
    let read = async {
        let mut b = [0u8; 1];
        while !buf.ends_with(b"\r\n") {
            if s.read(&mut b).await.unwrap_or(0) == 0 {
                break;
            }
            buf.push(b[0]);
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(10), read).await;
    String::from_utf8_lossy(&buf).trim().to_owned()
}

async fn response(s: &mut UnixStream) -> String {
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

async fn simple(socket: &std::path::Path, method: &str, path: &str, body: &str) -> String {
    let mut s = UnixStream::connect(socket).await.unwrap();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    response(&mut s).await
}

/// Commence une requête au corps « chunked » sans la finir.
async fn start_chunked(socket: &std::path::Path) -> UnixStream {
    let mut s = UnixStream::connect(socket).await.unwrap();
    s.write_all(b"POST /chat/completions HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
    s
}

async fn send_chunk(s: &mut UnixStream, n: usize) -> std::io::Result<()> {
    s.write_all(format!("{n:x}\r\n").as_bytes()).await?;
    s.write_all(&vec![b'a'; n]).await?;
    s.write_all(b"\r\n").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn corps_trop_grand_refuse_sans_appel() {
    let (base, calls) = provider(None).await;
    let proxy = LlmProxy::new(BTreeMap::new()).unwrap();
    let srv = serve(&proxy, &base, LlmBudget::default());
    // Taille annoncée au-delà du plafond : refus immédiat.
    let mut s = UnixStream::connect(&srv.socket).await.unwrap();
    let req = format!("POST /chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n", 31 * 1024 * 1024);
    s.write_all(req.as_bytes()).await.unwrap();
    assert!(status_line(&mut s).await.contains("413"));
    // Corps « chunked » qui dépasse en cours de route.
    let mut s = start_chunked(&srv.socket).await;
    let mut sent = 0;
    while sent <= MAX_REQUEST_BYTES {
        if send_chunk(&mut s, 1024 * 1024).await.is_err() {
            break;
        }
        sent += 1024 * 1024;
    }
    let _ = s.write_all(b"0\r\n\r\n").await;
    assert!(status_line(&mut s).await.contains("413"));
    assert_eq!(*calls.lock().unwrap(), 0);
}

/// Au plus 4 connexions servies par socket : une cinquième attend que l'une se ferme.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connexions_bornees() {
    let (base, _calls) = provider(Some(10)).await;
    let proxy = LlmProxy::new(BTreeMap::new()).unwrap();
    let srv = serve(&proxy, &base, LlmBudget::default());
    let mut holders = Vec::new();
    for _ in 0..MAX_CONNECTIONS_PER_WORKER {
        let mut s = start_chunked(&srv.socket).await;
        send_chunk(&mut s, 1024).await.unwrap();
        holders.push(s);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut fifth = UnixStream::connect(&srv.socket).await.unwrap();
    fifth.write_all(b"GET /models HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut b = [0u8; 1];
    assert!(tokio::time::timeout(Duration::from_millis(500), fifth.read(&mut b)).await.is_err(), "5e connexion servie");
    drop(holders);
    let rest = response(&mut fifth).await;
    assert!(rest.starts_with("HTTP/1.1 200"), "{rest}");
}

/// Octets en tampon d'un worker plafonnés : 4 corps de 7 Mio (chacun sous le plafond de 8 Mio) ne
/// tiennent pas dans 16 Mio ; les refusés le sont en `429 proxy_busy`, pas par saturation mémoire.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampons_bornes() {
    let (base, _calls) = provider(Some(10)).await;
    let proxy = LlmProxy::new(BTreeMap::new()).unwrap();
    let srv = serve(&proxy, &base, LlmBudget::default());
    let mut tasks = Vec::new();
    for _ in 0..MAX_CONNECTIONS_PER_WORKER {
        let socket = srv.socket.clone();
        tasks.push(tokio::spawn(async move {
            let mut s = start_chunked(&socket).await;
            // Un corps refusé en cours de route fait fermer la connexion : écriture tolérée.
            for _ in 0..7 {
                if send_chunk(&mut s, 1024 * 1024).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let _ = s.write_all(b"0\r\n\r\n").await;
            status_line(&mut s).await
        }));
    }
    let mut lines = Vec::new();
    for t in tasks {
        lines.push(t.await.unwrap());
    }
    assert!(lines.iter().any(|l| l.contains("429")), "{lines:?}");
}

/// I2 : chemins hors liste refusés sans appel au fournisseur.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chemins_hors_liste() {
    let (base, calls) = provider(None).await;
    let proxy = LlmProxy::new(BTreeMap::new()).unwrap();
    let srv = serve(&proxy, &base, LlmBudget::default());
    for (m, p) in [
        ("GET", "/files"),
        ("GET", "/files/file-1/content"),
        ("GET", "/chat/completions?limit=100"),
        ("GET", "/organization/users"),
        ("GET", "/./files"),
        ("DELETE", "/models"),
    ] {
        let r = simple(&srv.socket, m, p, "").await;
        assert!(r.starts_with("HTTP/1.1 404") || r.starts_with("HTTP/1.1 405"), "{m} {p} : {r}");
    }
    assert_eq!(*calls.lock().unwrap(), 0);
}
