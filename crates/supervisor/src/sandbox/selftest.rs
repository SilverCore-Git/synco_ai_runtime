//! Autotest du bac à sable : tentatives d'évasion exécutées **dans** un worker isolé
//! (`synco-ai-runtime sandbox-check`, tests d'intégration `tests/sandbox.rs`).
//!
//! Chaque tentative écrit une ligne sur le pipe : `blocked <détail>` (la protection a tenu) ou
//! `escaped <détail>` (échec du bac à sable), et quitte avec 0 ou 1. Certaines tentatives doivent
//! **tuer** le worker (mémoire, appel système hostile) : le superviseur constate alors un signal et
//! aucune ligne. Le détail ne contient que des codes d'erreur et des compteurs.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

/// Tentatives disponibles.
pub const TESTS: [&str; 8] =
    ["read_files", "list_procs", "connect", "oom", "threads", "seccomp_kill", "write_fs", "proxy"];

fn finish(mut stream: UnixStream, escaped: bool, detail: &str) -> u8 {
    let verdict = if escaped { "escaped" } else { "blocked" };
    let _ = writeln!(stream, "{verdict} {detail}");
    let _ = stream.flush();
    u8::from(escaped)
}

fn errno_of(e: &std::io::Error) -> String {
    e.raw_os_error().map_or_else(|| format!("{:?}", e.kind()), |c| format!("errno{c}"))
}

/// Écho du pipe (worker « témoin » qui doit survivre aux tentatives d'un autre worker).
#[must_use]
pub fn echo(mut stream: UnixStream) -> u8 {
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return 0,
            Ok(n) => {
                let Some(chunk) = buf.get(..n) else { return 2 };
                if stream.write_all(chunk).is_err() {
                    return 0;
                }
            }
        }
    }
}

/// Exécute la tentative `test` dans le worker.
#[must_use]
pub fn run_in_sandbox(stream: UnixStream, test: &str, args: &[String], llm_socket: Option<PathBuf>) -> u8 {
    match test {
        "read_files" => read_files(stream, args),
        "list_procs" => list_procs(stream, args),
        "connect" => connect(stream, args),
        "oom" => oom(stream, args),
        "threads" => threads(stream, args),
        "seccomp_kill" => seccomp_kill(stream),
        "write_fs" => write_fs(stream),
        "proxy" => proxy(stream, args, llm_socket),
        _ => finish(stream, true, "unknown_test"),
    }
}

/// Lecture de fichiers hors de la racine (état du superviseur, `/etc/passwd`, `/home`…) et
/// contenu de la racine.
fn read_files(stream: UnixStream, paths: &[String]) -> u8 {
    let mut detail = Vec::new();
    let mut escaped = false;
    for p in paths {
        match std::fs::File::open(p) {
            Ok(_) => {
                escaped = true;
                detail.push(format!("open_ok:{p}"));
            }
            Err(e) => detail.push(errno_of(&e)),
        }
    }
    match std::fs::read_dir("/") {
        Ok(entries) => {
            let names: Vec<String> = entries.flatten().filter_map(|e| e.file_name().into_string().ok()).collect();
            if names.iter().any(|n| n != "run") {
                escaped = true;
            }
            detail.push(format!("root=[{}]", names.join(",")));
        }
        Err(e) => detail.push(format!("root:{}", errno_of(&e))),
    }
    finish(stream, escaped, &detail.join(" "))
}

/// Liste des processus et accès au superviseur (`args[0]` = son PID sur l'hôte).
fn list_procs(stream: UnixStream, args: &[String]) -> u8 {
    let mut detail = vec![format!("pid={}", std::process::id())];
    let mut escaped = false;
    match std::fs::read_dir("/proc") {
        Ok(_) => {
            escaped = true;
            detail.push("proc_listed".into());
        }
        Err(e) => detail.push(format!("proc:{}", errno_of(&e))),
    }
    for pid in args {
        for file in ["status", "environ", "mem"] {
            if std::fs::File::open(format!("/proc/{pid}/{file}")).is_ok() {
                escaped = true;
                detail.push(format!("open_ok:/proc/{pid}/{file}"));
            }
        }
        // Superviseur processus 1 d'un conteneur : dans son propre espace de noms de PID, le worker est
        // lui-même le PID 1, donc `kill(1, 0)` réussit trivialement et ne prouve rien (faux positif).
        if *pid == std::process::id().to_string() {
            detail.push("kill0_same_pid".into());
            continue;
        }
        let signalled = pid
            .parse::<i32>()
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .map(|p| rustix::process::test_kill_process(p).is_ok());
        match signalled {
            Some(true) => {
                escaped = true;
                detail.push(format!("kill0_ok:{pid}"));
            }
            Some(false) => detail.push("kill0_failed".into()),
            None => detail.push("bad_pid".into()),
        }
    }
    // `kill(-1, 0)` vise tous les processus visibles (hors PID 1 et soi) : dans l'espace de noms de PID
    // du worker, il n'y en a aucun (ESRCH attendu). Tout autre résultat montre un processus voisin.
    // (`test_kill_process_group` avec le PID 1 envoie `kill(-1, 0)`.)
    match rustix::process::Pid::from_raw(1).map(rustix::process::test_kill_process_group) {
        Some(Err(rustix::io::Errno::SRCH)) => detail.push("kill_all_esrch".into()),
        Some(Ok(())) => {
            escaped = true;
            detail.push("kill_all_ok".into());
        }
        Some(Err(e)) => {
            escaped = true;
            detail.push(format!("kill_all:errno{}", e.raw_os_error()));
        }
        None => detail.push("bad_pid".into()),
    }
    finish(stream, escaped, &detail.join(" "))
}

/// Connexions vers des hôtes non autorisés : TCP (`hôte:port`), UDP, socket Unix abstrait
/// (`@nom`).
fn connect(stream: UnixStream, targets: &[String]) -> u8 {
    let mut detail = Vec::new();
    let mut escaped = false;
    for t in targets {
        if let Some(name) = t.strip_prefix('@') {
            use std::os::linux::net::SocketAddrExt as _;
            let res =
                std::os::unix::net::SocketAddr::from_abstract_name(name).and_then(|a| UnixStream::connect_addr(&a));
            match res {
                Ok(_) => {
                    escaped = true;
                    detail.push(format!("abstract_ok:{name}"));
                }
                Err(e) => detail.push(format!("abstract:{}", errno_of(&e))),
            }
            continue;
        }
        let Ok(addr) = t.parse::<SocketAddr>() else {
            detail.push("bad_addr".into());
            continue;
        };
        match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
            Ok(_) => {
                escaped = true;
                detail.push(format!("tcp_ok:{t}"));
            }
            Err(e) => detail.push(format!("tcp:{}", errno_of(&e))),
        }
        let udp = UdpSocket::bind("0.0.0.0:0").and_then(|s| s.send_to(b"x", addr));
        match udp {
            Ok(_) => {
                escaped = true;
                detail.push(format!("udp_ok:{t}"));
            }
            Err(e) => detail.push(format!("udp:{}", errno_of(&e))),
        }
    }
    finish(stream, escaped, &detail.join(" "))
}

/// Dépassement de mémoire : touche `args[0]` Mio (défaut 2 048). Le noyau doit tuer le worker
/// (OOM de **son** cgroup) avant la fin.
fn oom(stream: UnixStream, args: &[String]) -> u8 {
    let target_mib: usize = args.first().and_then(|a| a.parse().ok()).unwrap_or(2048);
    let mut blocks: Vec<Vec<u8>> = Vec::new();
    for _ in 0..target_mib / 16 {
        // `vec![1; n]` écrit chaque page : la mémoire est réellement consommée.
        blocks.push(vec![1u8; 16 * 1024 * 1024]);
    }
    let total: usize = blocks.iter().map(Vec::len).fold(0, usize::saturating_add);
    finish(stream, true, &format!("allocated_mib={}", total / (1024 * 1024)))
}

/// Création de processus et de fils d'exécution en boucle. `args[0]` = `pids.max`.
fn threads(stream: UnixStream, args: &[String]) -> u8 {
    let pids_max: usize = args.first().and_then(|a| a.parse().ok()).unwrap_or(64);
    let mut detail = Vec::new();
    let mut escaped = false;
    // Nouveau processus (clone sans CLONE_THREAD) : refusé par seccomp, sinon par l'absence de
    // binaire dans la racine.
    match std::process::Command::new("/proc/self/exe").spawn() {
        Ok(mut c) => {
            let _ = c.kill();
            escaped = true;
            detail.push("process_spawned".into());
        }
        Err(e) => detail.push(format!("process:{}", errno_of(&e))),
    }
    let mut handles = Vec::new();
    let mut count = 0usize;
    for _ in 0..10_000 {
        match std::thread::Builder::new().stack_size(64 * 1024).spawn(std::thread::park) {
            Ok(h) => {
                count = count.saturating_add(1);
                handles.push(h);
            }
            Err(e) => {
                detail.push(format!("thread:{}", errno_of(&e)));
                break;
            }
        }
    }
    if count >= pids_max {
        escaped = true;
    }
    detail.push(format!("threads={count}"));
    // Le retour de `main` termine le processus (exit_group) sans attendre les fils parqués.
    drop(handles);
    finish(stream, escaped, &detail.join(" "))
}

/// Appel système hostile (`mount`) : le filtre doit tuer le processus.
fn seccomp_kill(stream: UnixStream) -> u8 {
    let res = rustix::mount::mount_change("/", rustix::mount::MountPropagationFlags::SHARED);
    finish(stream, true, &format!("mount_returned:{}", res.is_ok()))
}

/// Écriture sur le système de fichiers (racine, répertoire du socket).
fn write_fs(stream: UnixStream) -> u8 {
    let mut detail = Vec::new();
    let mut escaped = false;
    for p in ["/x", "/run/synco/x", "/tmp/x"] {
        match std::fs::write(p, b"x") {
            Ok(()) => {
                escaped = true;
                detail.push(format!("write_ok:{p}"));
            }
            Err(e) => detail.push(errno_of(&e)),
        }
    }
    finish(stream, escaped, &detail.join(" "))
}

/// Requête au mandataire LLM (`args[0]` = méthode, `args[1]` = chemin, `args[2]` = en-tête
/// `Authorization` envoyé par le worker, facultatif). Ligne : `blocked status=<n> body=<corps>`.
fn proxy(stream: UnixStream, args: &[String], llm_socket: Option<PathBuf>) -> u8 {
    let Some(socket) = llm_socket else { return finish(stream, true, "no_llm_socket") };
    let method = args.first().map_or("GET", String::as_str);
    let path = args.get(1).map_or("/models", String::as_str);
    let auth = args.get(2).cloned();
    let mut req = synco_ai_runtime_worker::llm::LlmRequest::new(method, path);
    if let Some(a) = auth {
        req = req.header("authorization", &a);
    }
    if method == "POST" {
        req = req.header("content-type", "application/json").body(br#"{"model":"m","stream":true}"#.to_vec());
    }
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => return finish(stream, true, &format!("runtime:{}", errno_of(&e))),
    };
    let res = rt.block_on(async move {
        let mut resp = synco_ai_runtime_worker::llm::send(&socket, req).await?;
        let mut body = Vec::new();
        while let Some(chunk) = resp.next_chunk().await? {
            body.extend_from_slice(&chunk);
        }
        Ok::<_, synco_ai_runtime_worker::llm::LlmError>((resp.status(), body))
    });
    match res {
        Ok((status, body)) => {
            let text = String::from_utf8_lossy(&body).replace('\n', "\\n");
            finish(stream, false, &format!("status={status} body={text}"))
        }
        Err(e) => finish(stream, false, &format!("error={e}")),
    }
}

/// Verdict d'une tentative, côté superviseur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// Tentative.
    pub test: &'static str,
    /// La protection a tenu.
    pub ok: bool,
    /// Détail (codes, compteurs, fin du processus).
    pub detail: String,
}

/// Tentatives d'évasion contre le lanceur `launcher` (mode isolé), avec les plafonds `limits` :
/// fichiers de l'hôte et de `state_dir`, processus, réseau, écriture, processus en boucle, appel
/// système hostile, mémoire. Utilisé par `sandbox-check` et les tests sur l'hôte.
pub async fn battery(
    launcher: &super::SandboxLauncher,
    state_dir: &std::path::Path,
    limits: &crate::launcher::ResourceLimits,
) -> Vec<Verdict> {
    use crate::launcher::WorkerExit;
    let mut out = Vec::new();
    let t = Duration::from_secs(30);
    let pid = std::process::id().to_string();
    let mut files = vec![state_dir.display().to_string()];
    if let Ok(entries) = std::fs::read_dir(state_dir) {
        files.extend(entries.flatten().map(|e| e.path().display().to_string()).take(8));
    }
    files.extend(
        ["/etc/passwd", "/etc/hostname", "/home", "/proc/self/status", "/sys/fs/cgroup/cgroup.procs", "/"]
            .map(str::to_owned),
    );
    files.push(format!("/proc/{pid}/environ"));
    let simple = |test: &'static str, r: Result<super::CaseOutcome, crate::launcher::LaunchError>| match r {
        Ok(o) => Verdict {
            test,
            ok: o.line.starts_with("blocked") && o.exit == WorkerExit::Exited(0),
            detail: format!("{} ; fin {:?}", o.line, o.exit),
        },
        Err(e) => Verdict { test, ok: false, detail: format!("lancement : {}", e.0) },
    };
    out.push(simple("read_files", launcher.run_case("read_files", files, limits, None, vec![], t).await));
    out.push(simple("list_procs", launcher.run_case("list_procs", vec![pid.clone()], limits, None, vec![], t).await));
    out.push(simple("write_fs", launcher.run_case("write_fs", vec![], limits, None, vec![], t).await));
    // Réseau : un écouteur TCP local et un socket abstrait du superviseur ne doivent rien recevoir.
    let tcp = std::net::TcpListener::bind("127.0.0.1:0");
    let abstract_name = format!("synco-selftest-{pid}");
    let unix = {
        use std::os::linux::net::SocketAddrExt as _;
        std::os::unix::net::SocketAddr::from_abstract_name(&abstract_name)
            .and_then(|a| std::os::unix::net::UnixListener::bind_addr(&a))
    };
    match (tcp, unix) {
        (Ok(tcp), Ok(unix)) => {
            let _ = tcp.set_nonblocking(true);
            let _ = unix.set_nonblocking(true);
            let port = tcp.local_addr().map(|a| a.port()).unwrap_or(0);
            let targets = vec!["1.1.1.1:443".to_owned(), format!("127.0.0.1:{port}"), format!("@{abstract_name}")];
            let mut v = simple("connect", launcher.run_case("connect", targets, limits, None, vec![], t).await);
            if tcp.accept().is_ok() || unix.accept().is_ok() {
                v.ok = false;
                v.detail.push_str(" ; connexion reçue par le superviseur");
            }
            out.push(v);
        }
        _ => out.push(Verdict { test: "connect", ok: false, detail: "écouteurs de test impossibles".into() }),
    }
    out.push(simple(
        "threads",
        launcher.run_case("threads", vec![limits.pids_max.to_string()], limits, None, vec![], t).await,
    ));
    match launcher.run_case("seccomp_kill", vec![], limits, None, vec![], t).await {
        Ok(o) => out.push(Verdict {
            test: "seccomp_kill",
            ok: o.exit == WorkerExit::Signaled(libc::SIGSYS) && !o.line.starts_with("escaped"),
            detail: format!("fin {:?}", o.exit),
        }),
        Err(e) => out.push(Verdict { test: "seccomp_kill", ok: false, detail: format!("lancement : {}", e.0) }),
    }
    let oom_mib = limits.memory_max_bytes.saturating_mul(4) / (1024 * 1024);
    match launcher.run_case("oom", vec![oom_mib.to_string()], limits, None, vec![], Duration::from_secs(120)).await {
        Ok(o) => out.push(Verdict {
            test: "oom",
            ok: o.exit == WorkerExit::Signaled(libc::SIGKILL) && o.oom_kills >= 1 && o.line.is_empty(),
            detail: format!("fin {:?} ; oom_kill {}", o.exit, o.oom_kills),
        }),
        Err(e) => out.push(Verdict { test: "oom", ok: false, detail: format!("lancement : {}", e.0) }),
    }
    out
}
