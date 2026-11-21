//! État partagé du superviseur (sous un seul verrou, jamais tenu pendant un appel réseau).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use runtime_protocol::api::LlmPolicy;
use runtime_protocol::pipe::{Metrics, SupervisorMsg};
use runtime_protocol::ticket::{RevokedUser, TicketKeys};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::pins::PinStore;
use crate::ratelimit::TokenBucket;
use crate::vault::Vault;

/// Message vers un client WebSocket.
#[derive(Debug, Clone)]
pub enum ClientOut {
    /// Trame texte.
    Text(Arc<str>),
    /// Fermeture (code, raison).
    Close(u16, String),
}

/// Client connecté à une conversation.
#[derive(Debug)]
pub struct ClientSlot {
    /// Identifiant local.
    pub id: u64,
    /// Utilisateur du ticket.
    pub user_id: String,
    /// Émission vers la tâche du WebSocket.
    pub tx: mpsc::Sender<ClientOut>,
}

/// Message vers la tâche d'écriture d'un worker.
pub enum ToWorker {
    /// Trame JSON.
    Json(SupervisorMsg),
    /// Trame de clés déjà encodée (effacée à la libération).
    Keys(Zeroizing<Vec<u8>>),
}

impl core::fmt::Debug for ToWorker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Json(_) => f.write_str("ToWorker::Json"),
            Self::Keys(_) => f.write_str("ToWorker::Keys(***)"),
        }
    }
}

/// Worker en cours d'une conversation.
#[derive(Debug)]
pub struct WorkerHandle {
    /// Vers le worker.
    pub tx: mpsc::Sender<ToWorker>,
    /// Arrêt forcé (`true` : tuer).
    pub kill: watch::Sender<bool>,
    /// `leaseEpoch` = `epoch` des évènements.
    pub epoch: u64,
    /// Dernier `seq` diffusé.
    pub last_seq: u64,
    /// Le worker a annoncé `ready` et reçu `start`.
    pub started: bool,
    /// Dernières métriques (dashboard).
    pub metrics: Option<Metrics>,
    /// Débit des `signed_request`.
    pub requests: TokenBucket,
    /// Requêtes relayées en vol pour ce worker (au plus [`RELAY_IN_FLIGHT_PER_WORKER`]).
    pub in_flight: Arc<tokio::sync::Semaphore>,
    /// Requêtes en cours de réassemblage (corps en plusieurs parties).
    pub uploads: HashMap<String, (runtime_protocol::pipe::SignedRequest, runtime_protocol::pipe::Reassembly)>,
    /// Clés de salon créées par ce worker et scellées par le superviseur (`created_key`, L07).
    pub created_keys: u32,
    /// Salons dont ce worker a relayé la création réussie, en attente de leur clé (`created_key`).
    pub created_threads: std::collections::HashSet<String>,
}

/// Requêtes relayées en vol par worker.
pub const RELAY_IN_FLIGHT_PER_WORKER: usize = 4;
/// Requêtes relayées en vol pour tout le runtime : avec des réponses ≤ 9 Mio, la mémoire des
/// relais reste sous ~ 8 × 9 Mio (plus une partie `b64` à la fois par relais).
pub const RELAY_IN_FLIGHT_TOTAL: usize = 8;
/// Corps en réassemblage simultanés par worker.
pub const RELAY_UPLOADS_PER_WORKER: usize = 2;

/// État du worker d'une conversation.
#[derive(Debug)]
pub enum WorkerState {
    /// Aucun.
    None,
    /// Lancement en cours (bail, process).
    Launching,
    /// En cours.
    Running(Box<WorkerHandle>),
}

impl WorkerState {
    /// Un worker occupe-t-il une place ?
    #[must_use]
    pub const fn is_active(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Tampon de reprise (05 §3) : derniers évènements, bornés en nombre et en octets.
#[derive(Debug)]
pub struct ReplayBuffer {
    events: VecDeque<(u64, u64, Arc<str>)>,
    bytes: usize,
    max_events: usize,
    max_bytes: usize,
}

impl ReplayBuffer {
    /// Tampon vide.
    #[must_use]
    pub const fn new(max_events: usize, max_bytes: usize) -> Self {
        Self { events: VecDeque::new(), bytes: 0, max_events, max_bytes }
    }

    /// Ajoute un évènement (`epoch`, `seq`).
    pub fn push(&mut self, epoch: u64, seq: u64, frame: Arc<str>) {
        self.bytes = self.bytes.saturating_add(frame.len());
        self.events.push_back((epoch, seq, frame));
        while self.events.len() > self.max_events || self.bytes > self.max_bytes {
            match self.events.pop_front() {
                Some((_, _, f)) => self.bytes = self.bytes.saturating_sub(f.len()),
                None => break,
            }
        }
    }

    /// Évènements après `seq` dans `epoch`, si le tampon contient **toute** la suite (`seq + 1`
    /// présent, ou `seq` = dernier). `None` sinon (→ `snapshot`).
    #[must_use]
    pub fn replay_after(&self, epoch: u64, seq: u64) -> Option<Vec<Arc<str>>> {
        let in_epoch: Vec<&(u64, u64, Arc<str>)> = self.events.iter().filter(|(e, _, _)| *e == epoch).collect();
        let last = in_epoch.last().map_or(0, |(_, s, _)| *s);
        if seq == last {
            return Some(vec![]);
        }
        let first = in_epoch.first().map(|(_, s, _)| *s)?;
        if seq.checked_add(1).is_none_or(|next| next < first) || seq > last {
            return None;
        }
        Some(in_epoch.into_iter().filter(|(_, s, _)| *s > seq).map(|(_, _, f)| Arc::clone(f)).collect())
    }

    /// Vide.
    pub fn clear(&mut self) {
        self.events.clear();
        self.bytes = 0;
    }
}

/// Conversation suivie par le superviseur.
#[derive(Debug)]
pub struct Conv {
    /// Propriétaire.
    pub user_id: String,
    /// Autorisation de session.
    pub auth_id: String,
    /// Clients connectés.
    pub clients: Vec<ClientSlot>,
    /// Tampon de reprise.
    pub buffer: ReplayBuffer,
    /// Worker.
    pub worker: WorkerState,
    /// Dernier statut connu (08).
    pub status: String,
    /// Demandes de `snapshot` en attente : identifiant → client.
    pub snapshots: HashMap<String, u64>,
}

/// Autorisation de session connue (04 §3.1) : données **publiques** (l'`authId` n'est pas un secret).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    /// Propriétaire.
    pub user_id: String,
    /// `authId`.
    pub auth_id: String,
}

/// Autorisations, persistées dans `authorizations.json` (un redémarrage ne doit pas refuser un
/// client d'une conversation `idle` dont l'autorisation a été notifiée avant).
#[derive(Debug)]
pub struct AuthStore {
    path: Option<PathBuf>,
    map: BTreeMap<String, Authorization>,
}

/// Nom du fichier des autorisations.
pub const AUTH_FILE: &str = "authorizations.json";

impl AuthStore {
    /// En mémoire seulement.
    #[must_use]
    pub const fn in_memory() -> Self {
        Self { path: None, map: BTreeMap::new() }
    }

    /// Ouvre le fichier (absent : vide).
    pub fn open(state_dir: &Path) -> Result<Self> {
        let path = state_dir.join(AUTH_FILE);
        let map = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|_| Error::Io(format!("{AUTH_FILE} illisible")))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(Error::Io(format!("{AUTH_FILE} : {}", e.kind()))),
        };
        Ok(Self { path: Some(path), map })
    }

    fn save(&self) {
        if let Some(path) = &self.path {
            let res = serde_json::to_vec_pretty(&self.map)
                .map_err(|_| Error::Io("sérialisation".into()))
                .and_then(|b| crate::seal::write_atomic(path, &b));
            if let Err(e) = res {
                tracing::warn!(code = "authorizations_not_saved", error = %e, "autorisations non enregistrées");
            }
        }
    }

    /// Ajoute ou remplace.
    pub fn insert(&mut self, session_id: &str, auth: Authorization) {
        if self.map.get(session_id) != Some(&auth) {
            self.map.insert(session_id.to_owned(), auth);
            self.save();
        }
    }

    /// Retire.
    pub fn remove(&mut self, session_id: &str) {
        if self.map.remove(session_id).is_some() {
            self.save();
        }
    }

    /// Retire celles d'un utilisateur ; renvoie les conversations.
    pub fn remove_user(&mut self, user_id: &str) -> Vec<String> {
        let sessions: Vec<String> =
            self.map.iter().filter(|(_, a)| a.user_id == user_id).map(|(s, _)| s.clone()).collect();
        for s in &sessions {
            self.map.remove(s);
        }
        if !sessions.is_empty() {
            self.save();
        }
        sessions
    }

    /// Tout oublier (désappairage).
    pub fn clear(&mut self) {
        if !self.map.is_empty() {
            self.map.clear();
            self.save();
        }
    }

    /// Copie de toutes les autorisations (réconciliation).
    #[must_use]
    pub fn entries(&self) -> Vec<(String, Authorization)> {
        self.map.iter().map(|(s, a)| (s.clone(), a.clone())).collect()
    }

    /// Lecture.
    #[must_use]
    pub fn get(&self, session_id: &str) -> Option<&Authorization> {
        self.map.get(session_id)
    }
}

/// Clés des tickets et liste de révocation (02 §7, §8).
#[derive(Debug, Default)]
pub struct TicketState {
    /// Clés publiques de l'API.
    pub keys: TicketKeys,
    /// Dernière relecture réussie.
    pub refreshed: Option<Instant>,
    /// Dernière relecture déclenchée par un `kid` inconnu (≤ 1 / min).
    pub unknown_kid_refresh: Option<Instant>,
    /// Utilisateurs révoqués (avec expiration de l'entrée, s).
    pub revoked_users: Vec<(RevokedUser, u64)>,
    /// Conversations révoquées (avec expiration de l'entrée, s).
    pub revoked_conversations: Vec<(String, u64)>,
}

impl TicketState {
    /// Purge les entrées de révocation expirées.
    pub fn prune(&mut self, now: u64) {
        self.revoked_users.retain(|(_, exp)| *exp > now);
        self.revoked_conversations.retain(|(_, exp)| *exp > now);
    }
}

/// État complet.
#[derive(Debug)]
pub struct State {
    /// Org appairée.
    pub org_id: Option<String>,
    /// Délégations ouvertes.
    pub vault: Vault,
    /// Épingles TOFU des utilisateurs.
    pub pins: PinStore,
    /// Épingles TOFU des clés RSA des membres (Q25) ; en mémoire tant que `app` n'a pas ouvert le
    /// fichier d'état.
    pub member_pins: crate::member_pins::MemberPinStore,
    /// Tickets.
    pub tickets: TicketState,
    /// Autorisations connues.
    pub auths: AuthStore,
    /// Conversations suivies.
    pub convs: HashMap<String, Conv>,
    /// Politique de l'org (D1 : sans secret).
    pub policy: Option<LlmPolicy>,
    /// Plantages récents par conversation (s), garde-fou de 08 §5.
    pub crashes: HashMap<String, Vec<u64>>,
    /// Arrêt en cours.
    pub shutting_down: bool,
    /// Prochain identifiant de client.
    pub next_client: u64,
    /// Alertes récentes (codes, pour le dashboard L08).
    pub alerts: VecDeque<(u64, &'static str)>,
    /// Conversations en attente vues au dernier relevé.
    pub queued_seen: usize,
    /// Génération d'appairage : augmentée à chaque appairage et désappairage. Un chargement de
    /// délégation commencé dans une génération n'installe rien dans une autre.
    pub generation: u64,
    /// Délégations révoquées (identifiant → expiration de l'entrée, s) : jamais réinstallées, même
    /// par un chargement commencé avant la révocation.
    pub revoked_delegations: HashMap<String, u64>,
    /// Noms d'affichage des délégants (PC17) : identifiant → nom, tels que listés par l'API à la
    /// dernière relecture. Affichage seulement, jamais une décision.
    pub display_names: HashMap<String, String>,
}

impl State {
    /// État initial.
    #[must_use]
    pub fn new(pins: PinStore, auths: AuthStore) -> Self {
        Self {
            org_id: None,
            vault: Vault::default(),
            pins,
            member_pins: crate::member_pins::MemberPinStore::in_memory(),
            tickets: TicketState::default(),
            auths,
            convs: HashMap::new(),
            policy: None,
            crashes: HashMap::new(),
            shutting_down: false,
            next_client: 1,
            alerts: VecDeque::new(),
            queued_seen: 0,
            generation: 0,
            revoked_delegations: HashMap::new(),
            display_names: HashMap::new(),
        }
    }

    /// Enregistre une alerte (code machine, sans détail) et la journalise.
    pub fn alert(&mut self, now: u64, code: &'static str) {
        tracing::warn!(code, "alerte");
        self.alerts.push_back((now, code));
        while self.alerts.len() > 100 {
            self.alerts.pop_front();
        }
    }

    /// Marque une délégation révoquée (gardée 31 jours, au-delà de toute expiration possible).
    pub fn mark_delegation_revoked(&mut self, delegation_id: &str, now: u64) {
        self.revoked_delegations.insert(delegation_id.to_owned(), now.saturating_add(31 * 86_400));
        self.revoked_delegations.retain(|_, exp| *exp > now);
    }

    /// Workers occupant une place (en cours ou en lancement).
    #[must_use]
    pub fn active_workers(&self) -> usize {
        self.convs.values().filter(|c| c.worker.is_active()).count()
    }

    /// Workers d'un utilisateur.
    #[must_use]
    pub fn active_workers_of(&self, user_id: &str) -> usize {
        self.convs.values().filter(|c| c.user_id == user_id && c.worker.is_active()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(s: &str) -> Arc<str> {
        Arc::from(s)
    }

    #[test]
    fn tampon_de_reprise() {
        let mut b = ReplayBuffer::new(3, 1 << 20);
        for seq in 1..=5 {
            b.push(2, seq, f(&format!("e{seq}")));
        }
        // Le tampon garde 3, 4, 5.
        assert_eq!(b.replay_after(2, 2).unwrap().len(), 3);
        assert_eq!(b.replay_after(2, 4).unwrap().len(), 1);
        assert_eq!(b.replay_after(2, 5).unwrap().len(), 0);
        assert!(b.replay_after(2, 1).is_none(), "2 perdu : snapshot");
        assert!(b.replay_after(2, 9).is_none(), "seq inconnu");
        assert!(b.replay_after(1, 3).is_none(), "autre époque");
        let mut small = ReplayBuffer::new(100, 4);
        small.push(1, 1, f("abc"));
        small.push(1, 2, f("de"));
        assert!(small.replay_after(1, 0).is_none(), "borné en octets");
    }
}
