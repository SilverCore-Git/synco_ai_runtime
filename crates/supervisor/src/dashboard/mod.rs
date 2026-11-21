//! Dashboard web du superviseur (L08, docs/plan/11) : authentification par mot de passe local,
//! historique sans contenu, interface HTML/CSS/JS embarquée (aucun CDN).
//!
//! Le dashboard ne connaît que ce que le superviseur reçoit déjà sans contenu : les `metrics` du
//! pipe, des états de liste fermée, la consommation du cgroup. Voir `history` pour le stockage.

pub mod auth;
pub mod history;
pub mod host;
pub mod query;
pub mod routes;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::launcher::BoxFuture;
use crate::runtime::Runtime;
use routes::{DashboardState, MemberKeyChange, OverviewData, OverviewSource};

/// Alertes montrées à la vue d'ensemble.
const ALERTS_SHOWN: usize = 20;

impl OverviewSource for Runtime {
    fn overview(&self) -> BoxFuture<'_, OverviewData> {
        Box::pin(async move {
            let st = self.state.lock().await;
            let paired = st.org_id.is_some();
            OverviewData {
                version: env!("CARGO_PKG_VERSION").to_owned(),
                runtime_id: self.keys.runtime_id().to_owned(),
                fingerprint: self.keys.fingerprint_display(),
                pairing_code: (!paired).then(|| self.keys.pairing_code()),
                paired,
                org_id: st.org_id.clone(),
                api_connected: self.api_connected.load(Ordering::Relaxed),
                launcher: self.launcher.name().to_owned(),
                active_workers: u64::try_from(st.active_workers()).unwrap_or(u64::MAX),
                max_workers: u64::try_from(self.config.limits.max_workers).unwrap_or(u64::MAX),
                queued: u64::try_from(st.queued_seen).unwrap_or(u64::MAX),
                alerts: st
                    .alerts
                    .iter()
                    .rev()
                    .take(ALERTS_SHOWN)
                    .rev()
                    .map(|(t, code)| (*t, (*code).to_owned()))
                    .collect(),
                member_key_changes: st
                    .org_id
                    .as_deref()
                    .map(|org| {
                        st.member_pins
                            .pending(org)
                            .into_iter()
                            .filter_map(|(user, pin)| {
                                let p = pin.pending.as_ref()?;
                                Some(MemberKeyChange {
                                    user_id: user.to_owned(),
                                    pinned: pin.thumbprint.clone(),
                                    presented: p.thumbprint.clone(),
                                    fingerprint: p.fingerprint.clone(),
                                    seen: p.seen,
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            }
        })
    }

    fn accept_member_key(&self, user_id: String, fingerprint: String) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            let mut st = self.state.lock().await;
            let Some(org) = st.org_id.clone() else { return false };
            st.member_pins.accept_pending(&org, &user_id, &fingerprint)
        })
    }
}

/// Dashboard démarré.
#[derive(Debug)]
pub struct Started {
    /// Adresse d'écoute effective.
    pub addr: SocketAddr,
    /// Authentification (tests).
    pub auth: Arc<auth::Auth>,
}

/// Démarre le dashboard sur `listen.dashboard` s'**il y a un mot de passe** ; sinon journalise
/// comment en définir un et ne démarre pas.
pub async fn start(rt: &Arc<Runtime>) -> std::io::Result<Option<Started>> {
    let state_dir = &rt.config.state_dir;
    if !auth::password_is_set(state_dir) {
        tracing::warn!(
            code = "dashboard_disabled",
            "dashboard désactivé : aucun mot de passe (synco-ai-runtime dashboard-password)"
        );
        return Ok(None);
    }
    if !auth::password_file_usable(state_dir) {
        tracing::warn!(
            code = "dashboard_password_unreadable",
            "dashboard désactivé : fichier du mot de passe illisible ou invalide (synco-ai-runtime dashboard-password)"
        );
        return Ok(None);
    }
    let listener = tokio::net::TcpListener::bind(rt.config.listen.dashboard).await?;
    let addr = listener.local_addr()?;
    let auth = Arc::new(auth::Auth::new(state_dir));
    let rt_for_source: Arc<Runtime> = Arc::clone(rt);
    let source: Arc<dyn OverviewSource> = rt_for_source;
    let state = DashboardState::new(
        Arc::clone(&rt.history),
        Arc::clone(&auth),
        source,
        rt.config.dashboard.allowed_hosts.clone(),
        rt.config.dashboard.trust_proxy_hops,
        addr,
    );
    let mut shutdown = rt.shutdown.subscribe();
    tokio::spawn(async move {
        let stop = async move { crate::runtime::stopped(&mut shutdown).await };
        if let Err(e) = routes::serve(state, listener, stop).await {
            tracing::error!(error = %e.kind(), "dashboard arrêté");
        }
    });
    // Rétention : une passe par heure.
    let history = Arc::clone(&rt.history);
    let mut stop = rt.shutdown.subscribe();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = tokio::time::sleep(std::time::Duration::from_secs(3600)) => history.prune(crate::clock::now_secs()),
                () = crate::runtime::stopped(&mut stop) => return,
            }
        }
    });
    tracing::info!(code = "dashboard_started", listen = %addr, "dashboard démarré");
    Ok(Some(Started { addr, auth }))
}
