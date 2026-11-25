//! Bac à sable des workers (L06). Les tests marqués `#[ignore]` exigent le noyau de l'hôte
//! (espaces de noms utilisateur, landlock, seccomp) et un cgroup v2 délégué : ils se lancent par
//! `crates/supervisor/tests/sandbox-host.sh` (`host-spawn` depuis le flatpak, `systemd-run --user
//! --scope -p Delegate=yes`). Les autres tournent partout.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    missing_docs,
    reason = "tests"
)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use runtime_protocol::pipe::{
    self, Frame, Init, LlmConfig, LlmProvider, ReasoningEffort, ShutdownMsg, ShutdownReason, SignedResponse,
    SupervisorMsg, WorkerLimits, WorkerMsg,
};
use synco_ai_runtime::config::{Config, ProviderSecret};
use synco_ai_runtime::launcher::{
    LlmBudget, LlmRoute, ResourceLimits, WorkerExit, WorkerLauncher, WorkerProcess, WorkerSpec,
};
use synco_ai_runtime::sandbox::proxy::LlmProxy;
use synco_ai_runtime::sandbox::{Layer, Mode, RawWorker, SandboxLauncher, SandboxSettings};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use zeroize::Zeroizing;

fn limits() -> ResourceLimits {
    ResourceLimits { memory_max_bytes: 512 << 20, cpu_max_percent: 100, pids_max: 64 }
}

fn settings(run: &tempfile::TempDir) -> SandboxSettings {
    SandboxSettings {
        program: Some(env!("CARGO_BIN_EXE_synco-ai-runtime").into()),
        cgroup_root: None,
        run_dir: run.path().join("w"),
    }
}

fn run_dir() -> tempfile::TempDir {
    tempfile::Builder::new().prefix("l06").tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap()
}

async fn launcher(run: &tempfile::TempDir, mode: Mode, proxy: Arc<LlmProxy>) -> SandboxLauncher {
    SandboxLauncher::new(&settings(run), mode, proxy).await.unwrap()
}

fn no_proxy() -> Arc<LlmProxy> {
    LlmProxy::new(BTreeMap::new(), Default::default()).unwrap()
}

fn init() -> Init {
    Init {
        session_id: "sess1".into(),
        user_id: "user1".into(),
        org_id: "org1".into(),
        runtime_id: "rt1".into(),
        auth_id: "auth1".into(),
        lease_epoch: 1,
        api_base_url: "https://api.example.com".into(),
        llm: LlmConfig {
            provider: LlmProvider::Custom,
            model: "m".into(),
            base_url: String::new(),
            reasoning_effort: ReasoningEffort::Medium,
            pricing: None,
        },
        limits: WorkerLimits {
            max_steps_per_turn: 25,
            max_tokens_per_conversation: 2_000_000,
            max_tokens_per_turn: 300_000,
            max_turn_duration_secs: 1_800,
            max_output_tokens_per_call: 4_096,
            max_tool_result_bytes: 262_144,
            idle_shutdown_secs: 60,
        },
        tool_policy: BTreeMap::new(),
        log_level: "info".into(),
        plan: None,
        web: None,
    }
}

async fn read_worker(io: &mut (impl tokio::io::AsyncRead + Unpin)) -> WorkerMsg {
    match tokio::time::timeout(Duration::from_secs(10), pipe::read_frame(io)).await.unwrap().unwrap() {
        Frame::Json(j) => pipe::decode_json(&j).unwrap(),
        Frame::Keys(_) => panic!("le worker n'envoie pas de clés"),
    }
}

/// `init` → `ready` ; rend le PID annoncé et la durée lancement → `ready`.
async fn handshake(io: &mut tokio::net::UnixStream, started: Instant) -> (u32, Duration) {
    pipe::write_json(io, &SupervisorMsg::Init(Box::new(init()))).await.unwrap();
    match read_worker(io).await {
        WorkerMsg::Ready(r) => (r.pid, started.elapsed()),
        other => panic!("attendu ready : {other:?}"),
    }
}

/// `shutdown` → répond aux `signed_request` (bail rendu) → `done` ; rend la fin du processus.
async fn shutdown(mut w: RawWorker) -> WorkerExit {
    pipe::write_json(&mut w.io, &SupervisorMsg::Shutdown(ShutdownMsg { grace_ms: 0, reason: ShutdownReason::Idle }))
        .await
        .unwrap();
    loop {
        match read_worker(&mut w.io).await {
            WorkerMsg::SignedRequest(r) => {
                for part in SignedResponse::split(&r.id, 200, &BTreeMap::new(), b"{}") {
                    pipe::write_json(&mut w.io, &SupervisorMsg::SignedRequestResponse(part)).await.unwrap();
                }
            }
            WorkerMsg::Done(_) => break,
            _ => {}
        }
    }
    drop(w.io);
    tokio::time::timeout(Duration::from_secs(10), w.process.wait()).await.unwrap()
}

// ───────────────────────────── partout ─────────────────────────────

/// Repli : sans fonction noyau (ici un cgroup inexistant), le superviseur REFUSE de démarrer, avant
/// d'avoir créé ou descellé la moindre clé ; `--insecure-no-sandbox` démarre avec avertissement.
#[tokio::test]
async fn refus_de_demarrer_sans_bac_a_sable() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("etat");
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
public_url = "https://runtime.example.com"
api_url = "https://api.example.com"
state_dir = "{}"
allowed_origins = ["https://app.example.com"]
[key_sealing]
mode = "passphrase"
passphrase_file = "/nonexistent/phrase"
[sandbox]
cgroup_root = "/sys/fs/cgroup/synco-l06-inexistant"
"#,
            state.display()
        ),
    )
    .unwrap();
    let args =
        synco_ai_runtime::cli::parse(["--config".into(), config_path.display().to_string(), "run".into()]).unwrap();
    let err = synco_ai_runtime::cli::execute(args).await.unwrap_err().to_string();
    assert!(err.contains("cgroup_v2_unavailable"), "{err}");
    assert!(err.contains("Démarrage refusé"), "{err}");
    assert!(err.contains("--insecure-no-sandbox"), "{err}");
    // Aucune clé générée : le refus précède le descellement.
    assert!(!state.join(synco_ai_runtime::seal::PASSPHRASE_FILE).exists());
    assert!(!state.join(synco_ai_runtime::seal::CRED_FILE).exists());

    // Le même environnement en mode développement : lanceur sans isolement.
    let config = Config::load(&config_path).unwrap();
    let l = synco_ai_runtime::cli::build_launcher(&config, true, no_proxy()).await.unwrap();
    assert_eq!(l.mode(), Mode::Insecure);
    assert_eq!(l.name(), "insecure-no-sandbox");
    assert!(synco_ai_runtime::cli::INSECURE_WARNING.contains("JAMAIS en production"));
}

/// Mode développement : processus séparé (fork + exec), environnement vidé, pipe sur le
/// descripteur 3 ; le protocole fonctionne.
#[tokio::test]
async fn mode_insecure_processus_separe() {
    let run = run_dir();
    let l = launcher(&run, Mode::Insecure, no_proxy()).await;
    let spec =
        WorkerSpec { session_id: "sess1".into(), user_id: "user1".into(), resources: limits(), llm: None, web: None };
    let args = synco_ai_runtime::sandbox::ChildArgs { payload: "worker".into(), ..Default::default() };
    let started = Instant::now();
    let mut w = l.spawn_child(args, &spec.resources, None, vec![]).await.unwrap();
    let (pid, _) = handshake(&mut w.io, started).await;
    assert_eq!(Some(pid), w.process.pid(), "le worker est le processus lancé, pas une tâche");
    assert_ne!(pid, std::process::id());
    assert_eq!(shutdown(w).await, WorkerExit::Exited(0));
    assert!(l.injects_llm_credentials());
}

// ─────────────────────────── sur l'hôte ────────────────────────────

/// Batterie complète (celle de `sandbox-check`) : chaque tentative échoue ou tue son worker.
#[tokio::test]
#[ignore = "noyau : espaces de noms, cgroup délégué (tests/sandbox-host.sh)"]
async fn tentatives_d_evasion() {
    let run = run_dir();
    let l = launcher(&run, Mode::Sandboxed, no_proxy()).await;
    // État du superviseur simulé : un fichier « clé » dans un répertoire d'état.
    let state = run.path().join("etat");
    std::fs::create_dir(&state).unwrap();
    std::fs::write(state.join("keys.cred"), b"secret").unwrap();
    let verdicts = synco_ai_runtime::sandbox::selftest::battery(&l, &state, &limits()).await;
    for v in &verdicts {
        eprintln!("{} {:<13} {}", if v.ok { "ok   " } else { "ÉCHEC" }, v.test, v.detail);
    }
    assert_eq!(verdicts.len(), 7);
    assert!(verdicts.iter().all(|v| v.ok), "{verdicts:#?}");
}

/// Un second worker qui tourne pendant les tentatives (mémoire, processus en boucle, appel
/// hostile) n'est pas affecté : il répond toujours, sa mémoire est intacte.
#[tokio::test]
#[ignore = "noyau : espaces de noms, cgroup délégué (tests/sandbox-host.sh)"]
async fn un_worker_tue_n_affecte_pas_l_autre() {
    let run = run_dir();
    let l = launcher(&run, Mode::Sandboxed, no_proxy()).await;
    let args = synco_ai_runtime::sandbox::ChildArgs { payload: "echo".into(), ..Default::default() };
    let mut witness = l.spawn_child(args, &limits(), None, vec![]).await.unwrap();
    ping(&mut witness.io).await;
    let before = witness.process.usage().unwrap();
    let t = Duration::from_secs(60);
    let oom = l.run_case("oom", vec!["2048".into()], &limits(), None, vec![], t).await.unwrap();
    assert_eq!(oom.exit, WorkerExit::Signaled(libc::SIGKILL));
    assert!(oom.oom_kills >= 1);
    ping(&mut witness.io).await;
    let threads = l.run_case("threads", vec!["64".into()], &limits(), None, vec![], t).await.unwrap();
    assert!(threads.line.starts_with("blocked"), "{}", threads.line);
    ping(&mut witness.io).await;
    let kill = l.run_case("seccomp_kill", vec![], &limits(), None, vec![], t).await.unwrap();
    assert_eq!(kill.exit, WorkerExit::Signaled(libc::SIGSYS));
    ping(&mut witness.io).await;
    let after = witness.process.usage().unwrap();
    assert!(after.memory_current < 64 << 20, "témoin : {after:?}");
    assert!(after.memory_peak < 64 << 20, "témoin : pic {after:?} (avant {before:?})");
    witness.process.kill();
    assert_eq!(witness.process.wait().await, WorkerExit::Signaled(libc::SIGKILL));
}

/// Chaque couche réseau suffit seule, et le test détecte l'évasion quand toutes sont retirées.
#[tokio::test]
#[ignore = "noyau : espaces de noms, cgroup délégué (tests/sandbox-host.sh)"]
async fn couches_reseau_independantes() {
    let run = run_dir();
    let l = launcher(&run, Mode::Sandboxed, no_proxy()).await;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let target = vec![format!("127.0.0.1:{}", listener.local_addr().unwrap().port())];
    let t = Duration::from_secs(30);
    let lim = limits();
    let case = |without: Vec<Layer>| l.run_case("connect", target.clone(), &lim, None, without, t);
    // Tout : seccomp répond ENOSYS (38) dès socket(AF_INET).
    let all = case(vec![]).await.unwrap();
    assert!(all.line.starts_with("blocked") && all.line.contains("errno38"), "{}", all.line);
    // Sans seccomp : landlock (TCP) et l'espace de noms réseau (ENETUNREACH 101) bloquent.
    let no_seccomp = case(vec![Layer::Seccomp]).await.unwrap();
    assert!(no_seccomp.line.starts_with("blocked"), "{}", no_seccomp.line);
    // Sans seccomp ni landlock : l'espace de noms réseau seul (aucune interface active).
    let ns_only = case(vec![Layer::Seccomp, Layer::Landlock]).await.unwrap();
    assert!(ns_only.line.starts_with("blocked") && ns_only.line.contains("tcp:errno101"), "{}", ns_only.line);
    // Sans espace de noms réseau mais avec seccomp : bloqué.
    let seccomp_only = case(vec![Layer::Net, Layer::Landlock]).await.unwrap();
    assert!(seccomp_only.line.starts_with("blocked"), "{}", seccomp_only.line);
    // Toutes les couches réseau retirées : le test DOIT constater l'évasion (témoin du test).
    let none = case(vec![Layer::Net, Layer::Seccomp, Layer::Landlock]).await.unwrap();
    assert!(none.line.starts_with("escaped") && none.line.contains("tcp_ok"), "{}", none.line);
}

/// Les fichiers de l'hôte restent invisibles sans seccomp (racine vide) ; le test détecte une
/// lecture quand on la permet (témoin : le répertoire du socket monté est lisible sans seccomp).
#[tokio::test]
#[ignore = "noyau : espaces de noms, cgroup délégué (tests/sandbox-host.sh)"]
async fn racine_vide_sans_seccomp() {
    let run = run_dir();
    let l = launcher(&run, Mode::Sandboxed, no_proxy()).await;
    let t = Duration::from_secs(30);
    let files = vec!["/etc/passwd".to_owned(), format!("/proc/{}/status", std::process::id()), "/home".into()];
    let r = l.run_case("read_files", files.clone(), &limits(), None, vec![Layer::Seccomp], t).await.unwrap();
    assert!(r.line.starts_with("blocked") && r.line.contains("errno2"), "{}", r.line);
    let r = l.run_case("read_files", files, &limits(), None, vec![Layer::Seccomp, Layer::Landlock], t).await.unwrap();
    assert!(r.line.starts_with("blocked") && r.line.contains("root=[]"), "{}", r.line);
    let pid = vec![std::process::id().to_string()];
    let p = l.run_case("list_procs", pid, &limits(), None, vec![Layer::Seccomp], t).await.unwrap();
    assert!(p.line.starts_with("blocked") && p.line.contains("pid=1") && p.line.contains("kill0_failed"), "{}", p.line);
    assert!(p.line.contains("kill_all_esrch"), "{}", p.line);
}

/// Superviseur PID 1 (conteneur) : le PID passé est celui du worker lui-même (1 dans son espace de noms) ;
/// `kill(1, 0)` réussit trivialement et ne doit pas être pris pour une évasion (`kill0_same_pid`).
#[tokio::test]
#[ignore = "noyau : espaces de noms, cgroup délégué (tests/sandbox-host.sh)"]
async fn superviseur_pid_1_pas_de_faux_positif() {
    let run = run_dir();
    let l = launcher(&run, Mode::Sandboxed, no_proxy()).await;
    let t = Duration::from_secs(30);
    let p = l.run_case("list_procs", vec!["1".to_owned()], &limits(), None, vec![Layer::Seccomp], t).await.unwrap();
    assert!(
        p.line.starts_with("blocked") && p.line.contains("kill0_same_pid") && p.line.contains("kill_all_esrch"),
        "{}",
        p.line
    );
}

async fn ping(io: &mut tokio::net::UnixStream) {
    io.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf, b"ping");
}

async fn fake_provider() -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
    use axum::http::HeaderMap;
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let s2 = Arc::clone(&seen);
    let app = axum::Router::new().fallback(move |headers: HeaderMap, uri: axum::http::Uri| {
        let seen = Arc::clone(&s2);
        async move {
            let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("-").to_owned();
            seen.lock().unwrap().push(format!("{} {auth}", uri.path()));
            ([("content-type", "text/event-stream")], format!("data: {auth}\n\ndata: [DONE]\n\n"))
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/v1"), seen)
}

/// Mandataire LLM : le worker isolé joint SON fournisseur par le socket ; la clé est ajoutée par le
/// superviseur (celle forgée par le worker est retirée) ; la passerelle reçoit le ticket du
/// worker ; un chemin hors de l'URL de base est refusé.
#[tokio::test]
#[ignore = "noyau : espaces de noms, cgroup délégué (tests/sandbox-host.sh)"]
async fn mandataire_llm_injecte_la_cle() {
    let (base, seen) = fake_provider().await;
    let secrets = BTreeMap::from([("openai".to_owned(), ProviderSecret(Zeroizing::new(b"sk-runtime".to_vec())))]);
    let run = run_dir();
    let l = launcher(&run, Mode::Sandboxed, LlmProxy::new(secrets, Default::default()).unwrap()).await;
    let t = Duration::from_secs(30);
    let route = |provider: &str| {
        Some(LlmRoute { provider: provider.into(), base_url: base.clone(), budget: LlmBudget::default() })
    };
    let args = |m: &str, p: &str| vec![m.to_owned(), p.to_owned(), "Bearer forge-par-le-worker".to_owned()];
    let r =
        l.run_case("proxy", args("POST", "/chat/completions"), &limits(), route("openai"), vec![], t).await.unwrap();
    assert!(r.line.contains("status=200") && r.line.contains("data: Bearer sk-runtime"), "{r:?}");
    assert!(!r.line.contains("forge"), "{}", r.line);
    let g = l.run_case("proxy", args("GET", "/models"), &limits(), route("gateway"), vec![], t).await.unwrap();
    assert!(g.line.contains("data: Bearer forge-par-le-worker"), "{}", g.line);
    // I2 : hors de la liste (méthode, chemin), refus sans appel au fournisseur.
    for (m, p) in [
        ("GET", "/files"),
        ("GET", "/files/file-abc/content"),
        ("GET", "/chat/completions?limit=100"),
        ("POST", "/chat/completions?x=1"),
        ("GET", "/organization/users"),
        ("GET", "/./files"),
        ("GET", "/v1/../admin"),
        ("POST", "/models"),
    ] {
        let bad = l.run_case("proxy", args(m, p), &limits(), route("openai"), vec![], t).await.unwrap();
        assert!(bad.line.contains("status=404") && bad.line.contains("proxy_path"), "{m} {p} : {}", bad.line);
    }
    let delete = l.run_case("proxy", args("DELETE", "/models"), &limits(), route("openai"), vec![], t).await.unwrap();
    assert!(delete.line.contains("status=405"), "{}", delete.line);
    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec!["/v1/chat/completions Bearer sk-runtime".to_owned(), "/v1/models Bearer forge-par-le-worker".into()]
    );
    // Sans route : aucun socket dans le bac à sable.
    let none = l.run_case("proxy", args("GET", "/models"), &limits(), None, vec![], t).await.unwrap();
    assert!(none.line.contains("no_llm_socket"), "{}", none.line);
}

/// Proxy `web` (L15-web, 10 §4.2) : le worker isolé joint `web.sock` (monté avec `llm.sock`) ; la
/// recherche part vers le service configuré (faux SearXNG local) ; sans route web, aucun socket ; une
/// révocation ferme le socket.
#[tokio::test]
#[ignore = "noyau : espaces de noms, cgroup délégué (tests/sandbox-host.sh)"]
async fn proxy_web_joint_depuis_le_bac_a_sable() {
    use synco_ai_runtime::sandbox::web_proxy::{SearchProvider, SearchService, WebProxy, WebRoute, WebSettings};
    let app = axum::Router::new().route(
        "/search",
        axum::routing::get(|| async {
            axum::Json(
                serde_json::json!({ "results": [{ "title": "T", "url": "https://e.example/", "content": "C" }] }),
            )
        }),
    );
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(tcp, app).await.unwrap() });
    let search = SearchService {
        provider: SearchProvider::Searxng,
        base_url: format!("http://{addr}"),
        key: None,
        allow_private_host: true,
    };
    let web = WebProxy::new(Some(search), &WebSettings::default(), Vec::new()).unwrap();
    let run = run_dir();
    let l = launcher(&run, Mode::Sandboxed, no_proxy()).await.with_web(Arc::clone(&web));
    let llm = Some(LlmRoute {
        provider: "openai".into(),
        base_url: "https://api.example.com/v1".into(),
        budget: LlmBudget::default(),
    });
    let case = |route: Option<WebRoute>| {
        let l = &l;
        let llm = llm.clone();
        async move {
            let args = synco_ai_runtime::sandbox::ChildArgs {
                payload: "selftest".into(),
                test: Some("web".into()),
                test_args: vec!["/search".into(), r#"{"query":"meteo"}"#.into()],
                ..Default::default()
            };
            let RawWorker { mut io, mut process } =
                l.spawn_child_with_web(args, &limits(), llm, route, vec![]).await.unwrap();
            let mut line = String::new();
            let _ = tokio::time::timeout(Duration::from_secs(30), io.read_to_string(&mut line)).await;
            let _ = process.wait().await;
            line
        }
    };
    let ok = case(Some(WebRoute::new("u1", 1800))).await;
    assert!(ok.contains("status=200") && ok.contains("https://e.example/"), "{ok}");
    let none = case(None).await;
    assert!(none.contains("error="), "sans route web, aucun socket : {none}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(web.revoke_user("u1"), 0, "socket déjà fermé avec son worker");
}

/// Vrai worker (bouchon de protocole) par `WorkerLauncher::spawn` : PID 1 de son espace de noms,
/// protocole complet ; mesure du coût (lancement → `ready`, mémoire d'un worker vide).
#[tokio::test]
#[ignore = "noyau : espaces de noms, cgroup délégué (tests/sandbox-host.sh)"]
async fn vrai_worker_et_cout() {
    let run = run_dir();
    let l = launcher(&run, Mode::Sandboxed, no_proxy()).await;
    let n = 10;
    let mut times = Vec::new();
    let mut mems = Vec::new();
    let mut rss_pss = Vec::new();
    for _ in 0..n {
        let args = synco_ai_runtime::sandbox::ChildArgs { payload: "worker".into(), ..Default::default() };
        let started = Instant::now();
        let mut w = l.spawn_child(args, &limits(), None, vec![]).await.unwrap();
        let (pid, elapsed) = handshake(&mut w.io, started).await;
        assert_eq!(pid, 1, "le worker est le PID 1 de son espace de noms");
        times.push(elapsed);
        mems.push(w.process.usage().unwrap().memory_current);
        // RSS et PSS (proportionnelle : pages partagées divisées) de chaque processus du cgroup.
        let procs = std::fs::read_to_string(w.process.cgroup_path().unwrap().join("cgroup.procs")).unwrap();
        let (mut rss, mut pss) = (0u64, 0u64);
        for pid in procs.split_whitespace() {
            let roll = std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup")).unwrap_or_default();
            let field = |name: &str| {
                roll.lines()
                    .find_map(|l| l.strip_prefix(name))
                    .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
                    .unwrap_or(0)
            };
            rss += field("Rss:");
            pss += field("Pss:");
        }
        rss_pss.push((rss, pss, procs.split_whitespace().count()));
        assert_eq!(shutdown(w).await, WorkerExit::Exited(0));
    }
    times.sort();
    mems.sort_unstable();
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    eprintln!(
        "COUT lancement→ready : médiane {:.1} ms, min {:.1} ms, max {:.1} ms ; mémoire (cgroup, assistant + worker) : médiane {} Kio, max {} Kio",
        ms(times[n / 2]),
        ms(times[0]),
        ms(times[n - 1]),
        mems[n / 2] / 1024,
        mems[n - 1] / 1024
    );
    let (rss, pss, nprocs) = rss_pss[n / 2];
    eprintln!("COUT processus par worker : {nprocs} (assistant + worker) ; RSS {rss} Kio, PSS {pss} Kio");
    // Interface du superviseur.
    let spec =
        WorkerSpec { session_id: "sess1".into(), user_id: "user1".into(), resources: limits(), llm: None, web: None };
    let mut spawned = l.spawn(spec).await.unwrap();
    pipe::write_json(&mut spawned.io, &SupervisorMsg::Init(Box::new(init()))).await.unwrap();
    assert!(matches!(read_worker(&mut spawned.io).await, WorkerMsg::Ready(_)));
    assert!(spawned.process.usage().is_some());
    spawned.process.kill();
    assert_eq!(spawned.process.wait().await, WorkerExit::Signaled(libc::SIGKILL));
}

/// M4 : un lancement refusé après la création du répertoire du worker (route LLM refusée) ne
/// laisse ni répertoire ni socket.
#[tokio::test]
async fn lancement_refuse_sans_reste() {
    // Chemin court : le socket du mandataire est bien créé avant le refus de la route.
    let run = tempfile::tempdir().unwrap();
    let l = launcher(&run, Mode::Insecure, no_proxy()).await;
    let route = LlmRoute {
        provider: "openai".into(),
        base_url: "http://evil.example.com/v1".into(),
        budget: LlmBudget::default(),
    };
    let args = synco_ai_runtime::sandbox::ChildArgs { payload: "worker".into(), ..Default::default() };
    let err = l.spawn_child(args, &limits(), Some(route), vec![]).await.unwrap_err();
    assert_eq!(err.0, "llm_route_refused");
    let left: Vec<_> = std::fs::read_dir(run.path().join("w")).unwrap().flatten().map(|e| e.file_name()).collect();
    assert!(left.is_empty(), "restes : {left:?}");
}

/// M5 : un descripteur hérité par erreur (sans `O_CLOEXEC`) fait échouer le lancement
/// (`inherited_fd`) au lieu d'entrer dans le bac à sable.
#[tokio::test]
#[ignore = "noyau : espaces de noms, cgroup délégué (tests/sandbox-host.sh)"]
async fn descripteur_herite_refuse() {
    let run = run_dir();
    let l = launcher(&run, Mode::Sandboxed, no_proxy()).await;
    let leak = std::fs::File::open("/dev/null").unwrap();
    rustix::io::fcntl_setfd(&leak, rustix::io::FdFlags::empty()).unwrap();
    let args = synco_ai_runtime::sandbox::ChildArgs { payload: "probe".into(), ..Default::default() };
    let mut w = l.spawn_child(args, &limits(), None, vec![]).await.unwrap();
    let exit = tokio::time::timeout(Duration::from_secs(10), w.process.wait()).await.unwrap();
    assert_eq!(exit, WorkerExit::Exited(i32::from(synco_ai_runtime::sandbox::EXIT_SETUP_FAILED)));
    assert_eq!(w.process.setup_error().await.as_deref(), Some("inherited_fd"));
    drop(leak);
    // Sans la fuite, la même sonde passe.
    let args = synco_ai_runtime::sandbox::ChildArgs { payload: "probe".into(), ..Default::default() };
    let mut w = l.spawn_child(args, &limits(), None, vec![]).await.unwrap();
    assert_eq!(tokio::time::timeout(Duration::from_secs(10), w.process.wait()).await.unwrap(), WorkerExit::Exited(0));
}
