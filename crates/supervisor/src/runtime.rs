//! Le superviseur en fonctionnement : délégations, révocations, lancement des workers,
//! diffusion aux clients. Le verrou d'état n'est jamais tenu pendant un appel réseau.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

use runtime_protocol::api::{DelegationRecord, PendingConversation};
use runtime_protocol::client::CloseCode;
use runtime_protocol::pipe::{
    Init, KeyEntry, KeyFrame, KeyKind, KeyOp, LlmConfig, LlmProvider, Pricing, ReasoningEffort, ShutdownMsg,
    ShutdownReason, SupervisorMsg, WorkerLimits,
};
use runtime_protocol::stream::{ApiEvent, EntryKindName};
use runtime_protocol::ticket::RevokedUser;
use synco_e2ee::delegation::{DelegationContext, RuntimeSelf, Scope};
use synco_e2ee::identity::IdentityTransition;
use tokio::sync::{Mutex, Notify, watch};
use zeroize::Zeroizing;

use crate::api::ApiClient;
use crate::clock::now_secs;
use crate::config::{Config, ProviderSecret};
use crate::keys::RuntimeKeys;
use crate::launcher::{LlmRoute, WorkerLauncher};
use crate::state::{Authorization, ClientOut, Conv, ReplayBuffer, State, ToWorker, WorkerState};
use crate::vault::{KeyId, OpenDelegation};

/// Durée de vie d'une entrée de la liste de révocation des tickets : durée maximale d'un ticket
/// plus la tolérance d'horloge (02 §8).
const REVOCATION_TTL_SECS: u64 =
    runtime_protocol::ticket::MAX_LIFETIME_SECS + runtime_protocol::ticket::CLOCK_SKEW_SECS;
/// Fenêtre et seuil du garde-fou de plantages (08 §5).
const CRASH_WINDOW_SECS: u64 = 600;
const CRASH_LIMIT: usize = 3;

/// Attend que l'arrêt soit demandé (sans garder d'emprunt du canal au travers d'un `await`).
pub async fn stopped(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|v| *v).await.map(|_| ());
}

/// Le superviseur.
pub struct Runtime {
    /// Configuration.
    pub config: Arc<Config>,
    /// Clés du runtime (seul détenteur, mesure 7).
    pub keys: Arc<RuntimeKeys>,
    /// Canal interne.
    pub api: ApiClient,
    /// Lanceur de workers (bouchon L05, bac à sable L06).
    pub launcher: Arc<dyn WorkerLauncher>,
    provider_secrets: BTreeMap<String, ProviderSecret>,
    /// État.
    pub state: Mutex<State>,
    /// Arrêt demandé (`SIGTERM`).
    pub shutdown: watch::Sender<bool>,
    /// Désappairage constaté.
    pub unpaired: Notify,
    /// Relire les conversations en attente.
    pub wake: Notify,
    /// Requêtes relayées en vol pour tout le runtime.
    pub relay_permits: Arc<tokio::sync::Semaphore>,
    /// Historique du dashboard (L08) : compteurs sans contenu.
    pub history: Arc<crate::dashboard::history::History>,
    /// Flux de notifications de l'API ouvert.
    pub api_connected: std::sync::atomic::AtomicBool,
}

impl core::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Runtime").field("runtime_id", &self.keys.runtime_id()).finish_non_exhaustive()
    }
}

/// Erreur de chargement d'une délégation (cause **jamais** transmise à l'API, 03 §12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationFailure {
    /// API injoignable : réessayer plus tard.
    Transient,
    /// Mandat, épinglage, enveloppe ou contexte refusés : `unusable`.
    Unusable(&'static str),
    /// Révoquée, ou désappairage / réappairage pendant le chargement : rien n'est installé.
    Stale,
}

impl Runtime {
    /// Assemble le superviseur.
    #[must_use]
    pub fn new(
        config: Arc<Config>,
        keys: Arc<RuntimeKeys>,
        api: ApiClient,
        launcher: Arc<dyn WorkerLauncher>,
        provider_secrets: BTreeMap<String, ProviderSecret>,
        state: State,
    ) -> Arc<Self> {
        let (shutdown, _) = watch::channel(false);
        let history = Arc::new(crate::dashboard::history::History::open(
            &config.state_dir,
            config.dashboard.retention_days,
            now_secs(),
        ));
        Arc::new(Self {
            config,
            keys,
            api,
            launcher,
            provider_secrets,
            state: Mutex::new(state),
            shutdown,
            unpaired: Notify::new(),
            wake: Notify::new(),
            relay_permits: Arc::new(tokio::sync::Semaphore::new(crate::state::RELAY_IN_FLIGHT_TOTAL)),
            history,
            api_connected: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Org appairée.
    pub async fn org_id(&self) -> Option<String> {
        self.state.lock().await.org_id.clone()
    }

    /// Arrêt en cours ?
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        *self.shutdown.borrow()
    }

    // -----------------------------------------------------------------------
    // Délégations (03 §9)
    // -----------------------------------------------------------------------

    /// Relit toutes les délégations actives (démarrage, reconnexion du flux) : ouvre les nouvelles,
    /// efface celles qui ne sont plus listées (révoquées ou expirées pendant une coupure).
    pub async fn load_delegations(self: &Arc<Self>) -> Result<(), crate::api::ApiError> {
        let records = self.api.delegations().await?;
        let listed: BTreeSet<String> = records.iter().map(|r| r.delegation_id.clone()).collect();
        let stale: Vec<String> = {
            let st = self.state.lock().await;
            st.vault
                .users()
                .into_iter()
                .filter(|u| st.vault.get(u).is_some_and(|d| !listed.contains(d.delegation_id())))
                .collect()
        };
        for user in stale {
            self.revoke_user_delegation(&user, "delegation_gone").await;
        }
        for record in records {
            let known = self
                .state
                .lock()
                .await
                .vault
                .get(&record.user_id)
                .is_some_and(|d| d.delegation_id() == record.delegation_id);
            if known {
                self.fetch_entries(&record.delegation_id).await;
            } else {
                let _ = self.open_delegation(&record).await;
            }
        }
        Ok(())
    }

    /// Écrit une photo des épingles RSA des membres **hors** du verrou d'état (`spawn_blocking`).
    /// Échec : alerte `member_pins_not_saved` au dashboard et `false` (l'appelant refuse, fermé).
    pub async fn save_member_pins(
        &self,
        snapshot: crate::error::Result<Option<crate::member_pins::PinSnapshot>>,
    ) -> bool {
        let saved = match snapshot {
            Ok(None) => return true,
            Ok(Some(snap)) => matches!(tokio::task::spawn_blocking(move || snap.write()).await, Ok(Ok(()))),
            Err(_) => false,
        };
        if !saved {
            self.state.lock().await.alert(now_secs(), "member_pins_not_saved");
        }
        saved
    }

    /// Ouvre une délégation : mandat (clé épinglée TOFU, 03 §4) → enveloppe de tête (03 §3), par
    /// `accept_delegation` uniquement → entrées (03 §5). Puis `status` à l'API (sans cause).
    pub async fn open_delegation(self: &Arc<Self>, record: &DelegationRecord) -> Result<(), DelegationFailure> {
        let result = self.open_delegation_inner(record).await;
        match result {
            Ok(()) => {
                let _ = self.api.delegation_status(&record.delegation_id, true).await;
            }
            Err(DelegationFailure::Unusable(code)) => {
                self.state.lock().await.alert(now_secs(), code);
                let _ = self.api.delegation_status(&record.delegation_id, false).await;
            }
            Err(DelegationFailure::Transient | DelegationFailure::Stale) => {}
        }
        result
    }

    async fn open_delegation_inner(self: &Arc<Self>, record: &DelegationRecord) -> Result<(), DelegationFailure> {
        let unusable = DelegationFailure::Unusable("delegation_unusable");
        let generation = {
            let st = self.state.lock().await;
            if st.org_id.is_none() || st.revoked_delegations.contains_key(&record.delegation_id) {
                return Err(DelegationFailure::Stale);
            }
            st.generation
        };
        let scope = Scope::parse(&record.scope).map_err(|_| unusable)?;
        let ctx = DelegationContext {
            user_id: record.user_id.clone(),
            org_id: String::new(),
            runtime_id: self.keys.runtime_id().to_owned(),
            delegation_id: record.delegation_id.clone(),
            scope,
            iat: record.iat,
            exp: record.exp,
        };
        let sign_key = self.api.sign_key(&record.user_id).await.map_err(|_| DelegationFailure::Transient)?;
        let chain: Vec<IdentityTransition> = crate::pins::chain_from(&sign_key.transitions);
        let (org_id, trusted) = {
            let mut st = self.state.lock().await;
            if st.generation != generation {
                return Err(DelegationFailure::Stale);
            }
            let org = st.org_id.clone().ok_or(DelegationFailure::Stale)?;
            let trusted = st
                .pins
                .check_or_pin(&record.user_id, sign_key.public_sign_key.as_deref(), &chain, now_secs())
                .map_err(|e| DelegationFailure::Unusable(e.code()))?;
            (org, trusted)
        };
        let ctx = DelegationContext { org_id: org_id.clone(), ..ctx };
        let me = RuntimeSelf {
            runtime_id: self.keys.runtime_id(),
            org_id: &org_id,
            fpr_hex: self.keys.fingerprint_hex(),
            kex: self.keys.kex(),
            max_lifetime_secs: self.config.delegation.max_lifetime_secs(),
        };
        let mut opened =
            OpenDelegation::accept(&me, now_secs(), ctx, &trusted.0, &record.wrap, &record.mandate_signature)
                .map_err(|_| unusable)?;
        // Entrées, page par page.
        let mut after: Option<String> = None;
        loop {
            let page = self
                .api
                .entries(&record.delegation_id, after.as_deref())
                .await
                .map_err(|_| DelegationFailure::Transient)?;
            let last = page.entries.last().map(|e| e.id.clone());
            for e in &page.entries {
                opened.add_entry(&e.kind, &e.reference, e.version, &e.ciphertext);
            }
            opened.set_cursor(last.clone());
            match page.next {
                Some(next) if Some(&next) != after.as_ref() => after = Some(next),
                _ => break,
            }
        }
        if opened.entries_rejected() > 0 {
            tracing::warn!(code = "entry_unusable", count = opened.entries_rejected(), "entrées refusées");
        }
        tracing::info!(code = "delegation_opened", keys = opened.key_count(), "délégation ouverte");
        let user = record.user_id.clone();
        let new_ids: BTreeSet<KeyId> = opened.key_ids().into_iter().collect();
        let old_ids: BTreeSet<KeyId> = {
            let mut st = self.state.lock().await;
            // Vérifié sous le même verrou que l'installation : une révocation ou un désappairage
            // survenus pendant les appels réseau ci-dessus l'emportent (la délégation est effacée).
            if st.generation != generation
                || st.org_id.is_none()
                || st.revoked_delegations.contains_key(&record.delegation_id)
            {
                return Err(DelegationFailure::Stale);
            }
            st.vault.install(opened).into_iter().collect()
        };
        // Délégation remplacée : les workers de l'utilisateur suivent (retraits puis ajouts).
        let removed: Vec<KeyId> = old_ids.difference(&new_ids).cloned().collect();
        let added: Vec<KeyId> = new_ids.difference(&old_ids).cloned().collect();
        self.push_key_changes(&user, &removed, &added).await;
        Ok(())
    }

    /// Lit les nouvelles entrées d'une délégation ouverte (synchro P11) et les transmet aux
    /// workers de **son** utilisateur.
    pub async fn fetch_entries(self: &Arc<Self>, delegation_id: &str) {
        let (mut after, generation) = {
            let mut st = self.state.lock().await;
            let generation = st.generation;
            match st.vault.by_delegation_mut(delegation_id) {
                Some(d) => (d.cursor().map(str::to_owned), generation),
                None => return,
            }
        };
        let mut added = Vec::new();
        let mut user = None;
        loop {
            let Ok(page) = self.api.entries(delegation_id, after.as_deref()).await else { break };
            let mut st = self.state.lock().await;
            if st.generation != generation {
                return;
            }
            let Some(d) = st.vault.by_delegation_mut(delegation_id) else { return };
            user = Some(d.user_id().to_owned());
            for e in &page.entries {
                if let Some(id) = d.add_entry(&e.kind, &e.reference, e.version, &e.ciphertext) {
                    added.push(id);
                }
            }
            d.set_cursor(page.entries.last().map(|e| e.id.clone()));
            drop(st);
            match page.next {
                Some(next) if Some(&next) != after.as_ref() => after = Some(next),
                _ => break,
            }
        }
        if let Some(user) = user {
            self.push_key_changes(&user, &[], &added).await;
            if added.iter().any(|k| k.kind == KeyKind::Conv) {
                self.wake.notify_one();
            }
        }
    }

    /// Envoie aux workers en cours de `user` les clés retirées et ajoutées (thread/space). Une
    /// conversation dont la `conv` disparaît est arrêtée.
    async fn push_key_changes(self: &Arc<Self>, user: &str, removed: &[KeyId], added: &[KeyId]) {
        if removed.is_empty() && added.is_empty() {
            return;
        }
        let mut to_stop = Vec::new();
        {
            let st = self.state.lock().await;
            let adds = st.vault.org_keys(user, added, now_secs());
            let removes: Vec<KeyEntry> = removed
                .iter()
                .filter(|k| matches!(k.kind, KeyKind::Thread | KeyKind::Space))
                .filter_map(|k| {
                    Some(KeyEntry {
                        kind: k.kind,
                        reference: k.reference.clone(),
                        version: u32::try_from(k.version).ok()?,
                        key: Zeroizing::new(vec![]),
                    })
                })
                .collect();
            let frames_add = KeyFrame::split(KeyOp::Add, adds).unwrap_or_default();
            let frames_remove = KeyFrame::split(KeyOp::Remove, removes).unwrap_or_default();
            for (session, conv) in &st.convs {
                if conv.user_id != user {
                    continue;
                }
                if removed.iter().any(|k| k.kind == KeyKind::Conv && k.reference == *session) {
                    to_stop.push(session.clone());
                    continue;
                }
                if let WorkerState::Running(w) = &conv.worker {
                    for f in frames_remove.iter().chain(frames_add.iter()) {
                        let _ = w.tx.try_send(ToWorker::Keys(f.clone()));
                    }
                }
            }
        }
        for s in to_stop {
            self.stop_conversation(&s, ShutdownReason::Revoked, "revoked").await;
        }
    }

    /// Efface la délégation d'un utilisateur et arrête ses conversations (révocation, expiration).
    pub async fn revoke_user_delegation(self: &Arc<Self>, user: &str, code: &'static str) {
        let sessions: Vec<String> = {
            let mut st = self.state.lock().await;
            if let Some(id) = st.vault.get(user).map(|d| d.delegation_id().to_owned()) {
                st.mark_delegation_revoked(&id, now_secs());
            }
            st.vault.remove_user(user);
            st.auths.remove_user(user);
            st.alert(now_secs(), code);
            st.convs.iter().filter(|(_, c)| c.user_id == user).map(|(s, _)| s.clone()).collect()
        };
        for s in sessions {
            self.stop_conversation(&s, ShutdownReason::Revoked, "revoked").await;
        }
    }

    // -----------------------------------------------------------------------
    // Notifications de l'API (04 §6)
    // -----------------------------------------------------------------------

    /// Applique un évènement du flux.
    pub async fn on_api_event(self: &Arc<Self>, event: ApiEvent) {
        match event {
            ApiEvent::Hello { org_id, server_time } => {
                let mut st = self.state.lock().await;
                if st.org_id.as_deref() != Some(org_id.as_str()) {
                    st.alert(now_secs(), "stream_org_mismatch");
                }
                if server_time.abs_diff(now_secs()) > 30 {
                    st.alert(now_secs(), "clock_skew");
                }
            }
            ApiEvent::ConversationAuthorized { session_id, user_id, auth_id } => {
                self.remember_authorization(&session_id, &user_id, &auth_id).await;
            }
            ApiEvent::ConversationWake { session_id, auth_id, .. } => {
                let user = {
                    let st = self.state.lock().await;
                    st.auths.get(&session_id).map(|a| a.user_id.clone())
                };
                match user {
                    Some(user) => {
                        self.remember_authorization(&session_id, &user, &auth_id).await;
                        self.ensure_worker(&session_id);
                    }
                    // Propriétaire inconnu : la liste des conversations en attente le donne.
                    None => self.wake.notify_one(),
                }
            }
            ApiEvent::ConversationRevoked { session_id, .. } => {
                {
                    let mut st = self.state.lock().await;
                    st.tickets
                        .revoked_conversations
                        .push((session_id.clone(), now_secs().saturating_add(REVOCATION_TTL_SECS)));
                    st.auths.remove(&session_id);
                }
                self.stop_conversation(&session_id, ShutdownReason::Revoked, "revoked").await;
            }
            ApiEvent::DelegationUpdated { delegation_id, .. } => {
                if let Ok(records) = self.api.delegations().await
                    && let Some(r) = records.iter().find(|r| r.delegation_id == delegation_id)
                {
                    let _ = self.open_delegation(r).await;
                }
            }
            ApiEvent::DelegationEntriesAdded { delegation_id, .. } => self.fetch_entries(&delegation_id).await,
            ApiEvent::DelegationEntriesRemoved { delegation_id, entries } => {
                let ids: Vec<KeyId> = entries
                    .iter()
                    .map(|e| KeyId {
                        kind: match e.kind {
                            EntryKindName::Thread => KeyKind::Thread,
                            EntryKindName::Space => KeyKind::Space,
                            EntryKindName::Conv => KeyKind::Conv,
                        },
                        reference: e.reference.clone(),
                        version: e.version,
                    })
                    .collect();
                let user = self.state.lock().await.vault.remove_entries(&delegation_id, &ids);
                if let Some(user) = user {
                    self.push_key_changes(&user, &ids, &[]).await;
                }
            }
            ApiEvent::DelegationRevoked { user_id, delegation_id, .. } => {
                let owner = {
                    let mut st = self.state.lock().await;
                    st.mark_delegation_revoked(&delegation_id, now_secs());
                    st.vault.get(&user_id).map(|d| d.delegation_id() == delegation_id)
                };
                if owner != Some(false) {
                    self.revoke_user_delegation(&user_id, "delegation_revoked").await;
                }
            }
            ApiEvent::UserRevoked { user_id, until } => {
                let sessions: Vec<String> = {
                    let mut st = self.state.lock().await;
                    st.auths.remove_user(&user_id);
                    st.tickets.revoked_users.push((
                        RevokedUser { user_id: user_id.clone(), until },
                        until.max(now_secs()).saturating_add(REVOCATION_TTL_SECS),
                    ));
                    st.convs
                        .iter()
                        .filter(|(_, c)| c.clients.iter().any(|cl| cl.user_id == user_id))
                        .map(|(s, _)| s.clone())
                        .collect()
                };
                let mut st = self.state.lock().await;
                for s in sessions {
                    if let Some(conv) = st.convs.get_mut(&s) {
                        conv.clients.retain(|c| {
                            if c.user_id == user_id {
                                let _ = c.tx.try_send(ClientOut::Close(CloseCode::Forbidden.code(), "revoked".into()));
                                false
                            } else {
                                true
                            }
                        });
                    }
                }
            }
            ApiEvent::RuntimeUnpaired => self.unpaired.notify_one(),
            ApiEvent::Ping | ApiEvent::Unknown => {}
        }
    }

    /// Mémorise une autorisation de session.
    pub async fn remember_authorization(&self, session_id: &str, user_id: &str, auth_id: &str) {
        let mut st = self.state.lock().await;
        st.auths.insert(session_id, Authorization { user_id: user_id.to_owned(), auth_id: auth_id.to_owned() });
        if let Some(conv) = st.convs.get_mut(session_id)
            && conv.user_id == user_id
        {
            auth_id.clone_into(&mut conv.auth_id);
        }
    }

    /// Réconcilie les autorisations persistées avec l'API (démarrage, reconnexion du flux) : aucune
    /// route ne liste les autorisations actives de l'org ; la plus proche est
    /// `GET /conversations/:sessionId` (S+A), qui refuse une autorisation révoquée, expirée ou d'une
    /// délégation inactive. Une erreur réseau garde l'entrée.
    pub async fn reconcile_authorizations(self: &Arc<Self>) {
        let entries = self.state.lock().await.auths.entries();
        for (session, auth) in entries {
            let gone = match self.api.conversation_head(&session, &auth.auth_id).await {
                Ok(_) => false,
                Err(e) => {
                    e.status() == Some(404)
                        || matches!(
                            e.code(),
                            Some(
                                "auth_invalid"
                                    | "auth_revoked"
                                    | "auth_expired"
                                    | "delegation_expired"
                                    | "delegation_revoked"
                                    | "out_of_scope"
                            )
                        )
                }
            };
            if gone {
                let mut st = self.state.lock().await;
                if st.auths.get(&session).is_some_and(|a| a.auth_id == auth.auth_id) {
                    st.auths.remove(&session);
                }
            }
        }
    }

    /// Conversations en attente d'un worker (04 §4.1) : mémorise les autorisations et lance.
    pub async fn scan_pending(self: &Arc<Self>) -> Result<(), crate::api::ApiError> {
        let pending: Vec<PendingConversation> = self.api.pending().await?;
        self.state.lock().await.queued_seen = pending.len();
        for p in pending {
            self.remember_authorization(&p.session_id, &p.user_id, &p.auth_id).await;
            self.ensure_worker(&p.session_id);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Conversations et workers
    // -----------------------------------------------------------------------

    /// Entrée d'une conversation (créée au besoin).
    pub(crate) fn conv_entry<'a>(&self, st: &'a mut State, session_id: &str, auth: &Authorization) -> &'a mut Conv {
        let limits = &self.config.limits;
        st.convs.entry(session_id.to_owned()).or_insert_with(|| Conv {
            user_id: auth.user_id.clone(),
            auth_id: auth.auth_id.clone(),
            clients: Vec::new(),
            buffer: ReplayBuffer::new(limits.replay_buffer_events, limits.replay_buffer_bytes),
            worker: WorkerState::None,
            status: "idle".to_owned(),
            snapshots: Default::default(),
        })
    }

    /// Lance le worker d'une conversation s'il n'en a pas (tâche de fond).
    pub fn ensure_worker(self: &Arc<Self>, session_id: &str) {
        let rt = Arc::clone(self);
        let session = session_id.to_owned();
        tokio::spawn(async move {
            if let Err(code) = crate::workers::launch(&rt, &session).await {
                tracing::debug!(code, "worker non lancé");
            }
        });
    }

    /// Paramètres d'`init`, clés initiales et route du mandataire LLM d'une conversation (sous
    /// verrou). Erreur = code machine.
    ///
    /// Route LLM (B1) : l'identifiant du fournisseur vient de la politique de l'org, mais l'**URL**
    /// et la **clé** viennent de la configuration du runtime, cherchées avec ce même identifiant.
    /// `gateway_url` de la politique ne sert qu'au fournisseur `gateway` (aucune clé injectée), et
    /// seulement si c'est une URL publique en `https` (`proxy::gateway_url_allowed`). Un
    /// fournisseur absent de la configuration est refusé : aucune URL fournie par le serveur ne
    /// reçoit jamais une clé du runtime.
    pub(crate) fn build_init(
        &self,
        st: &State,
        session_id: &str,
        user_id: &str,
        auth_id: &str,
        lease_epoch: u64,
    ) -> Result<(Init, Vec<KeyEntry>, Option<LlmRoute>), &'static str> {
        let org_id = st.org_id.clone().ok_or("init_unavailable")?;
        let mut keys = st.vault.keys_for_conversation(user_id, session_id, now_secs()).ok_or("init_unavailable")?;
        let policy = st.policy.as_ref();
        let provider_id = policy.and_then(|p| p.default_provider.clone()).unwrap_or_else(|| "custom".to_owned());
        let provider = match provider_id.as_str() {
            "openai" => LlmProvider::Openai,
            "mistral" => LlmProvider::Mistral,
            "gemini" => LlmProvider::Gemini,
            "gateway" => LlmProvider::Gateway,
            "custom" => LlmProvider::Custom,
            _ => return Err("llm_provider_not_configured"),
        };
        let entry = policy.and_then(|p| p.providers.iter().find(|x| x.id == provider_id));
        let configured = self.config.llm.providers.get(&provider_id);
        let base_url = if provider == LlmProvider::Gateway {
            let url = configured
                .and_then(|c| c.base_url.clone())
                .or_else(|| entry.and_then(|e| e.gateway_url.clone()))
                .ok_or("llm_provider_not_configured")?;
            if configured.and_then(|c| c.base_url.as_ref()).is_none()
                && !crate::sandbox::proxy::gateway_url_allowed(&url)
            {
                return Err("llm_gateway_url_refused");
            }
            url
        } else {
            configured.and_then(|c| c.base_url.clone()).ok_or("llm_provider_not_configured")?
        };
        let route = Some(LlmRoute {
            provider: provider_id.clone(),
            base_url: base_url.clone(),
            budget: crate::launcher::LlmBudget::default(),
        });
        let pricing = configured.and_then(|c| match (c.input_eur_per_mtok, c.output_eur_per_mtok) {
            (Some(i), Some(o)) => Some(Pricing { input_per_m_tok: i, output_per_m_tok: o }),
            _ => None,
        });
        let effort = match policy.and_then(|p| p.reasoning_effort.as_deref()) {
            Some("low") => ReasoningEffort::Low,
            Some("high") => ReasoningEffort::High,
            _ => ReasoningEffort::Medium,
        };
        let l = &self.config.limits;
        let org = policy.map(|p| p.runtime.limits);
        let low = |runtime: u64, org: Option<u64>| org.map_or(runtime, |o| o.clamp(1, runtime));
        let limits = WorkerLimits {
            max_steps_per_turn: low(l.max_steps_per_turn, org.map(|o| o.max_steps_per_turn)),
            max_tokens_per_conversation: low(l.max_tokens_per_conversation, org.map(|o| o.max_tokens_per_conversation)),
            max_tokens_per_turn: low(l.max_tokens_per_turn, org.map(|o| o.max_tokens_per_turn)),
            max_turn_duration_secs: low(l.max_turn_duration_secs, org.map(|o| o.max_turn_duration_secs)),
            max_output_tokens_per_call: low(l.max_output_tokens_per_call, org.map(|o| o.max_output_tokens_per_call)),
            max_tool_result_bytes: l.max_tool_result_bytes,
            idle_shutdown_secs: l.idle_shutdown_secs,
        };
        // D1 : le secret du fournisseur choisi, depuis la configuration du runtime, en trame 0x02.
        // Avec le bac à sable (L06), le mandataire LLM ajoute la clé lui-même : rien ne part au worker.
        if let Some(secret) =
            self.provider_secrets.get(&provider_id).filter(|_| !self.launcher.injects_llm_credentials())
        {
            keys.push(KeyEntry {
                kind: KeyKind::LlmCredential,
                reference: provider_id.clone(),
                version: 1,
                key: Zeroizing::new(secret.0.to_vec()),
            });
        }
        let init = Init {
            session_id: session_id.to_owned(),
            user_id: user_id.to_owned(),
            org_id,
            runtime_id: self.keys.runtime_id().to_owned(),
            auth_id: auth_id.to_owned(),
            lease_epoch,
            api_base_url: self.config.api_url.clone(),
            llm: LlmConfig {
                provider,
                model: entry.and_then(|e| e.model_id.clone()).unwrap_or_default(),
                base_url,
                reasoning_effort: effort,
                pricing,
            },
            limits,
            tool_policy: policy.map(|p| p.runtime.tool_policy.clone()).unwrap_or_default(),
            log_level: self.config.log_level.clone(),
        };
        let route = route.map(|r| LlmRoute { budget: crate::launcher::LlmBudget::from_limits(&init.limits), ..r });
        Ok((init, keys, route))
    }

    /// Arrête le worker d'une conversation, ferme ses clients (`4403`) et l'oublie.
    pub async fn stop_conversation(self: &Arc<Self>, session_id: &str, reason: ShutdownReason, close_reason: &str) {
        let mut st = self.state.lock().await;
        let Some(conv) = st.convs.remove(session_id) else { return };
        for c in &conv.clients {
            let _ = c.tx.try_send(ClientOut::Close(CloseCode::Forbidden.code(), close_reason.to_owned()));
        }
        if let WorkerState::Running(w) = &conv.worker {
            let _ = w.tx.try_send(ToWorker::Json(SupervisorMsg::Shutdown(ShutdownMsg { grace_ms: 0, reason })));
            crate::workers::kill_after(w.kill.clone(), std::time::Duration::from_secs(2));
        }
        tracing::info!(code = "conversation_stopped", "conversation arrêtée");
    }

    /// Désappairage (01 §9) : arrêt des workers sans attendre, effacement des clés déléguées,
    /// oubli de l'org et des autorisations. Les clés du runtime sont conservées.
    pub async fn forget_org(self: &Arc<Self>) {
        let sessions: Vec<String> = self.state.lock().await.convs.keys().cloned().collect();
        for s in sessions {
            self.stop_conversation(&s, ShutdownReason::Unpaired, "revoked").await;
        }
        let mut st = self.state.lock().await;
        st.generation = st.generation.saturating_add(1);
        st.vault.clear();
        st.auths.clear();
        st.policy = None;
        st.org_id = None;
        st.tickets.revoked_users.clear();
        st.tickets.revoked_conversations.clear();
        st.alert(now_secs(), "runtime_unpaired");
    }

    /// Diffuse une trame à tous les clients d'une conversation ; un client trop lent est coupé.
    pub(crate) fn broadcast(conv: &mut Conv, frame: &Arc<str>) {
        conv.clients.retain(|c| match c.tx.try_send(ClientOut::Text(Arc::clone(frame))) {
            Ok(()) => true,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                let _ = c.tx.try_send(ClientOut::Close(CloseCode::Internal.code(), "slow_consumer".into()));
                false
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
        });
    }

    /// Plantage d'un worker : garde-fou de 08 §5 (3 en 10 minutes → `failed`).
    pub(crate) async fn record_crash(self: &Arc<Self>, session_id: &str, user_id: &str, auth_id: &str) {
        let now = now_secs();
        let tripped = {
            let mut st = self.state.lock().await;
            let list = st.crashes.entry(session_id.to_owned()).or_default();
            list.retain(|t| now.saturating_sub(*t) < CRASH_WINDOW_SECS);
            list.push(now);
            let tripped = list.len() >= CRASH_LIMIT;
            if tripped {
                st.alert(now, "worker_crash_loop");
            }
            tripped
        };
        if tripped {
            let _ = user_id;
            if let Ok(lease) = self.api.take_lease(session_id, auth_id).await {
                let _ = self
                    .api
                    .write_status(session_id, auth_id, lease.lease_epoch, "failed", Some("worker_crash_loop"))
                    .await;
                let _ = self.api.release_lease(session_id, auth_id, lease.lease_epoch).await;
            }
        }
    }

    /// Conversation marquée en boucle de plantages (pas de relance automatique).
    pub(crate) async fn in_crash_loop(&self, session_id: &str) -> bool {
        let now = now_secs();
        self.state
            .lock()
            .await
            .crashes
            .get(session_id)
            .is_some_and(|l| l.iter().filter(|t| now.saturating_sub(**t) < CRASH_WINDOW_SECS).count() >= CRASH_LIMIT)
    }

    /// Relit les clés des tickets (démarrage, toutes les 10 min, `kid` inconnu ≤ 1 / min).
    pub async fn refresh_ticket_keys(&self, because_unknown_kid: bool) -> bool {
        if because_unknown_kid {
            let mut st = self.state.lock().await;
            if st.tickets.unknown_kid_refresh.is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(60)) {
                return false;
            }
            st.tickets.unknown_kid_refresh = Some(Instant::now());
        }
        match self.api.ticket_keys().await {
            Ok(resp) if resp.v == 1 => {
                let (keys, rejected) = runtime_protocol::ticket::TicketKeys::from_b64u_map(
                    resp.keys.iter().map(|(k, v)| (k.as_str(), v.as_str())),
                );
                let mut st = self.state.lock().await;
                if rejected > 0 {
                    st.alert(now_secs(), "ticket_key_rejected");
                }
                st.tickets.keys = keys;
                st.tickets.refreshed = Some(Instant::now());
                true
            }
            _ => false,
        }
    }

    /// Ferme tous les clients (arrêt : `4503`).
    pub async fn close_all_clients(&self, code: CloseCode) {
        let mut st = self.state.lock().await;
        for conv in st.convs.values_mut() {
            for c in conv.clients.drain(..) {
                let _ = c.tx.try_send(ClientOut::Close(code.code(), code.default_reason().to_owned()));
            }
        }
    }
}
