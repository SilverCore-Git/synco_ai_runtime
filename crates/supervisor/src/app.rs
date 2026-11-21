//! Orchestration : serveur public, enregistrement auprès de l'API jusqu'à l'appairage, session
//! appairée (flux, délégations, conversations en attente, maintenance), arrêt propre (`SIGTERM`).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use runtime_protocol::client::CloseCode;
use runtime_protocol::pipe::{ShutdownMsg, ShutdownReason, SupervisorMsg};
use synco_e2ee::runtime_cert::{SignedRuntimeCertificate, UrlPolicy};

use crate::api::ApiClient;
use crate::clock::now_secs;
use crate::config::{Config, ProviderSecret};
use crate::error::{Error, Result};
use crate::keys::RuntimeKeys;
use crate::launcher::WorkerLauncher;
use crate::pins::PinStore;
use crate::runtime::Runtime;
use crate::state::{AuthStore, State, ToWorker, WorkerState};
use crate::stream::StreamEnd;

/// Intervalle d'enregistrement tant que le runtime n'est pas appairé (01 §7).
pub const REGISTER_INTERVAL: Duration = Duration::from_secs(15);

/// Superviseur démarré.
#[derive(Debug)]
pub struct Running {
    /// Le superviseur.
    pub runtime: Arc<Runtime>,
    /// Adresse d'écoute publique effective.
    pub public_addr: SocketAddr,
    /// Adresse du dashboard, s'il est démarré (mot de passe défini, docs/plan/11).
    pub dashboard_addr: Option<SocketAddr>,
    /// Fin de la boucle principale.
    pub task: tokio::task::JoinHandle<()>,
}

/// Assemble le superviseur, ouvre l'écoute publique et lance la boucle principale.
pub async fn start(
    config: Config,
    keys: RuntimeKeys,
    launcher: Arc<dyn WorkerLauncher>,
    provider_secrets: BTreeMap<String, ProviderSecret>,
) -> Result<Running> {
    let keys = Arc::new(keys);
    let api = ApiClient::new(&config.api_url, keys.runtime_id(), Arc::new(keys.sig().clone()))
        .map_err(|_| Error::Config("client HTTP impossible".into()))?;
    let pins = PinStore::open(&config.state_dir)?;
    let auths = AuthStore::open(&config.state_dir)?;
    let listener = tokio::net::TcpListener::bind(config.listen.public)
        .await
        .map_err(|e| Error::Io(format!("écoute {} : {}", config.listen.public, e.kind())))?;
    let public_addr = listener.local_addr().map_err(|e| Error::Io(format!("adresse d'écoute : {}", e.kind())))?;
    let mut state = State::new(pins, auths);
    state.member_pins = crate::member_pins::MemberPinStore::open(&config.state_dir)?;
    let runtime = Runtime::new(Arc::new(config), keys, api, launcher, provider_secrets, state);
    {
        let rt = Arc::clone(&runtime);
        tokio::spawn(async move {
            if let Err(e) = crate::server::serve(rt, listener).await {
                tracing::error!(error = %e.kind(), "serveur public arrêté");
            }
        });
    }
    let dashboard_addr = crate::dashboard::start(&runtime)
        .await
        .map_err(|e| Error::Io(format!("écoute du dashboard : {}", e.kind())))?
        .map(|d| d.addr);
    tracing::info!(
        code = "runtime_started",
        runtime_id = runtime.keys.runtime_id(),
        fingerprint = runtime.keys.fingerprint_hex(),
        public = %public_addr,
        launcher = runtime.launcher.name(),
        "superviseur démarré"
    );
    let task = tokio::spawn(main_loop(Arc::clone(&runtime)));
    Ok(Running { runtime, public_addr, dashboard_addr, task })
}

async fn main_loop(rt: Arc<Runtime>) {
    rt.refresh_ticket_keys(false).await;
    let ticket_refresher = tokio::spawn(ticket_key_loop(Arc::clone(&rt)));
    loop {
        if !wait_paired(&rt).await {
            break;
        }
        match run_paired(&rt).await {
            StreamEnd::Shutdown => break,
            StreamEnd::Unpaired => {
                tracing::warn!(code = "runtime_unpaired", "désappairé : effacement des clés déléguées");
                rt.forget_org().await;
            }
        }
    }
    ticket_refresher.abort();
}

async fn ticket_key_loop(rt: Arc<Runtime>) {
    let mut shutdown = rt.shutdown.subscribe();
    loop {
        let stale = rt.state.lock().await.tickets.refreshed.is_none_or(|t| t.elapsed() >= Duration::from_secs(600));
        if stale {
            rt.refresh_ticket_keys(false).await;
        }
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(60)) => {}
            () = crate::runtime::stopped(&mut shutdown) => return,
        }
    }
}

/// `POST /register` toutes les 15 s jusqu'à l'appairage ; le certificat doit porter **nos**
/// clés, notre `runtimeId` et notre URL (01 §7). `false` : arrêt demandé.
async fn wait_paired(rt: &Arc<Runtime>) -> bool {
    let mut shutdown = rt.shutdown.subscribe();
    loop {
        if rt.is_shutting_down() {
            return false;
        }
        match rt.api.register(&rt.config.public_url).await {
            Ok(resp) => match check_certificate(rt, &resp.org_id, &resp.certificate) {
                Ok(()) => {
                    let mut st = rt.state.lock().await;
                    st.org_id = Some(resp.org_id.clone());
                    st.generation = st.generation.saturating_add(1);
                    drop(st);
                    tracing::info!(code = "runtime_paired", "runtime appairé");
                    return true;
                }
                Err(code) => rt.state.lock().await.alert(now_secs(), code),
            },
            Err(e) if matches!(e.code(), Some("rt_unknown" | "rt_revoked")) => {
                tracing::info!(code = "waiting_for_pairing", "en attente d'appairage");
            }
            Err(e) => tracing::warn!(error = %e, "enregistrement impossible"),
        }
        tokio::select! {
            () = tokio::time::sleep(REGISTER_INTERVAL) => {}
            () = crate::runtime::stopped(&mut shutdown) => return false,
        }
    }
}

fn check_certificate(
    rt: &Runtime,
    org_id: &str,
    certificate: &serde_json::Value,
) -> core::result::Result<(), &'static str> {
    let policy = if rt.config.dev_allow_http_public_url { UrlPolicy::DevelopmentHttp } else { UrlPolicy::Production };
    let cert =
        SignedRuntimeCertificate::from_json(&certificate.to_string(), policy).map_err(|_| "certificate_invalid")?;
    let c = &cert.certificate;
    if c.runtime_id != rt.keys.runtime_id()
        || &c.keys != rt.keys.public()
        || c.url != rt.config.public_url
        || c.org_id != org_id
    {
        return Err("certificate_mismatch");
    }
    Ok(())
}

async fn run_paired(rt: &Arc<Runtime>) -> StreamEnd {
    refresh_policy(rt).await;
    let stream = tokio::spawn(crate::stream::run(Arc::clone(rt)));
    let pending = tokio::spawn(pending_loop(Arc::clone(rt)));
    let maintenance = tokio::spawn(maintenance_loop(Arc::clone(rt)));
    let mut shutdown = rt.shutdown.subscribe();
    let end = tokio::select! {
        r = stream => r.unwrap_or(StreamEnd::Unpaired),
        () = rt.unpaired.notified() => StreamEnd::Unpaired,
        () = crate::runtime::stopped(&mut shutdown) => StreamEnd::Shutdown,
    };
    pending.abort();
    maintenance.abort();
    end
}

async fn refresh_policy(rt: &Arc<Runtime>) {
    match rt.api.llm_policy().await {
        Ok(p) => rt.state.lock().await.policy = Some(p),
        Err(e) if e.code() == Some("rt_revoked") => rt.unpaired.notify_one(),
        Err(e) => tracing::warn!(error = %e, "politique de l'org non lue"),
    }
}

async fn pending_loop(rt: Arc<Runtime>) {
    loop {
        tokio::select! {
            () = rt.wake.notified() => {}
            () = tokio::time::sleep(Duration::from_secs(60)) => {}
        }
        if let Err(e) = rt.scan_pending().await
            && e.code() == Some("rt_revoked")
        {
            rt.unpaired.notify_one();
        }
    }
}

/// Toutes les 15 s : délégations expirées effacées (double verrou côté runtime, 03 §8), liste de
/// révocation purgée ; toutes les 5 min : politique ; chaque minute : métriques à l'API.
async fn maintenance_loop(rt: Arc<Runtime>) {
    let mut last_policy = Instant::now();
    let mut last_metrics: Option<Instant> = None;
    loop {
        tokio::time::sleep(Duration::from_secs(15)).await;
        let now = now_secs();
        let expired = {
            let mut st = rt.state.lock().await;
            st.tickets.prune(now);
            st.vault.expire(now)
        };
        for user in expired {
            rt.revoke_user_delegation(&user, "delegation_expired").await;
        }
        if last_policy.elapsed() >= Duration::from_secs(300) {
            refresh_policy(&rt).await;
            last_policy = Instant::now();
        }
        if last_metrics.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
            let (workers, queued) = {
                let st = rt.state.lock().await;
                (st.active_workers(), st.queued_seen)
            };
            let _ = rt.api.metrics(workers, queued).await;
            last_metrics = Some(Instant::now());
        }
    }
}

/// Arrêt propre (`SIGTERM`) : plus de lancement ni de client, `shutdown` aux workers (ils
/// terminent l'étape en cours et enregistrent), délai de grâce, puis arrêt forcé ; les clients
/// reçoivent `4503`.
pub async fn shutdown(rt: &Arc<Runtime>) {
    let grace = Duration::from_secs(rt.config.limits.shutdown_grace_secs);
    let grace_ms = u64::try_from(grace.as_millis()).unwrap_or(u64::MAX);
    {
        let mut st = rt.state.lock().await;
        st.shutting_down = true;
        for conv in st.convs.values() {
            if let WorkerState::Running(w) = &conv.worker {
                let _ = w.tx.try_send(ToWorker::Json(SupervisorMsg::Shutdown(ShutdownMsg {
                    grace_ms,
                    reason: ShutdownReason::Sigterm,
                })));
            }
        }
    }
    let _ = rt.shutdown.send(true);
    let deadline = Instant::now().checked_add(grace).unwrap_or_else(Instant::now);
    while Instant::now() < deadline && rt.state.lock().await.active_workers() > 0 {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    {
        let st = rt.state.lock().await;
        for conv in st.convs.values() {
            if let WorkerState::Running(w) = &conv.worker {
                let _ = w.kill.send(true);
            }
        }
    }
    rt.close_all_clients(CloseCode::ShuttingDown).await;
    tracing::info!(code = "runtime_stopped", "superviseur arrêté");
}

/// Attend `SIGTERM` ou `SIGINT`.
pub async fn wait_for_signal() {
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        () = term => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}
