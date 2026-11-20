//! Interface de lancement des workers : **le point de branchement de L06** (bac à sable).
//!
//! Le superviseur ne sait pas *comment* un worker est lancé ni isolé ; il demande à un
//! [`WorkerLauncher`] un [`SpawnedWorker`] = un canal d'octets bidirectionnel (le pipe de 06 §1,
//! cadré par `runtime_protocol::pipe`) et une poignée de contrôle du process ([`WorkerProcess`]).
//! Tout le reste (protocole, clés, bail, routage des WebSocket, arrêt) est indépendant du lanceur.
//!
//! - L05 fournit [`InProcessStubLauncher`] : le bouchon de `synco-ai-runtime-worker` tourne dans
//!   une tâche du superviseur, relié par un `tokio::io::duplex`. **Aucune isolation** : réservé aux
//!   tests et au développement.
//! - L06 : [`crate::sandbox::SandboxLauncher`] lance un vrai processus isolé (`socketpair` sur le
//!   descripteur 3, espaces de noms, seccomp, landlock, cgroup v2 avec [`ResourceLimits`], réseau
//!   réduit au mandataire LLM de [`WorkerSpec::llm`]) ; `cli.rs` le branche à la place du bouchon.

use std::future::Future;
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

/// Futur envoyable et boxé (traits compatibles `dyn`).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Canal d'octets vers le worker (pipe de 06 §1).
pub trait WorkerIo: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> WorkerIo for T {}

/// Plafonds du process (09 §2), appliqués par le cgroup du worker (L06).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    /// `memory.max` (octets).
    pub memory_max_bytes: u64,
    /// `memory.high` (octets).
    pub memory_high_bytes: u64,
    /// `cpu.max` en pour cent d'un cœur (100 = `100000 100000`).
    pub cpu_max_percent: u64,
    /// `pids.max`.
    pub pids_max: u64,
}

/// Ce que le lanceur doit savoir pour lancer **un** worker. Aucun secret : les clés passent
/// ensuite par le pipe (trames `0x02`), jamais par l'environnement, les arguments ou le disque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerSpec {
    /// Conversation (nom du cgroup, journal).
    pub session_id: String,
    /// Propriétaire (journal, comptage).
    pub user_id: String,
    /// Plafonds.
    pub resources: ResourceLimits,
    /// Fournisseur LLM joignable par le worker, **seul** accès réseau (mandataire du superviseur,
    /// docs/plan/10 §4). L'API n'est jointe que par `signed_request` (06 §4). `None` : aucun.
    pub llm: Option<LlmRoute>,
}

/// Route du mandataire LLM d'un worker. Aucun secret : la clé du fournisseur reste dans le
/// mandataire (D1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmRoute {
    /// Identifiant du fournisseur (`openai`, `mistral`, `gemini`, `custom`, `gateway`).
    pub provider: String,
    /// URL de base (`https://…`), celle d'`init.llm.baseUrl` : configuration du runtime, ou, pour
    /// `gateway` seulement, URL publique de la politique de l'org.
    pub base_url: String,
    /// Quotas appliqués par le mandataire (D6, `init.limits`).
    pub budget: LlmBudget,
}

/// Quotas d'appels LLM d'un worker, appliqués par le mandataire (D6 ; valeurs d'`init.limits`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LlmBudget {
    /// Appels au fournisseur par fenêtre de `max_turn_duration_secs` (≈ par tour).
    pub max_steps_per_turn: u64,
    /// Tokens par fenêtre de `max_turn_duration_secs` (≈ par tour).
    pub max_tokens_per_turn: u64,
    /// Tokens sur toute la vie du worker (borne de la conversation).
    pub max_tokens_per_conversation: u64,
    /// Fenêtre (s) ; aussi durée maximale d'un appel (avec le plafond de 10 min).
    pub max_turn_duration_secs: u64,
    /// Tokens de sortie par appel (estimation avant l'appel).
    pub max_output_tokens_per_call: u64,
}

impl Default for LlmBudget {
    /// Valeurs de 09 §2.
    fn default() -> Self {
        Self {
            max_steps_per_turn: 25,
            max_tokens_per_turn: 300_000,
            max_tokens_per_conversation: 2_000_000,
            max_turn_duration_secs: 1_800,
            max_output_tokens_per_call: 4_096,
        }
    }
}

impl LlmBudget {
    /// Depuis les plafonds transmis au worker.
    #[must_use]
    pub const fn from_limits(l: &runtime_protocol::pipe::WorkerLimits) -> Self {
        Self {
            max_steps_per_turn: l.max_steps_per_turn,
            max_tokens_per_turn: l.max_tokens_per_turn,
            max_tokens_per_conversation: l.max_tokens_per_conversation,
            max_turn_duration_secs: l.max_turn_duration_secs,
            max_output_tokens_per_call: l.max_output_tokens_per_call,
        }
    }
}

/// Fin d'un worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerExit {
    /// Code de sortie (0 = normal).
    Exited(i32),
    /// Tué par un signal.
    Signaled(i32),
    /// Inconnue (tâche interrompue, process perdu).
    Unknown,
}

impl WorkerExit {
    /// Sortie normale ?
    #[must_use]
    pub const fn is_clean(self) -> bool {
        matches!(self, Self::Exited(0))
    }
}

/// Consommation lue dans le cgroup du worker (06 §5) ; aucun contenu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceUsage {
    /// `memory.current`.
    pub memory_current: u64,
    /// `memory.peak`.
    pub memory_peak: u64,
    /// `cpu.stat` `usage_usec`.
    pub cpu_usage_usec: u64,
}

/// Contrôle du process d'un worker.
pub trait WorkerProcess: Send {
    /// Tue immédiatement (`SIGKILL`). Idempotent.
    fn kill(&mut self);
    /// Attend la fin.
    fn wait(&mut self) -> BoxFuture<'_, WorkerExit>;
    /// Consommation courante (cgroup), si le lanceur la mesure.
    fn usage(&self) -> Option<ResourceUsage>;
    /// PID, si c'est un process.
    fn pid(&self) -> Option<u32>;
}

/// Worker lancé.
pub struct SpawnedWorker {
    /// Pipe.
    pub io: Box<dyn WorkerIo>,
    /// Process.
    pub process: Box<dyn WorkerProcess>,
}

impl core::fmt::Debug for SpawnedWorker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SpawnedWorker").field("pid", &self.process.pid()).finish_non_exhaustive()
    }
}

/// Échec du lancement (code machine pour le journal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchError(pub &'static str);

/// Lanceur de workers (implémenté par L06 pour le vrai bac à sable).
pub trait WorkerLauncher: Send + Sync + 'static {
    /// Lance un worker pour `spec` et rend son pipe et son contrôle. Le superviseur envoie
    /// ensuite `init`, attend `ready`, envoie les clés puis `start` (06 §8).
    fn spawn(&self, spec: WorkerSpec) -> BoxFuture<'_, Result<SpawnedWorker, LaunchError>>;

    /// Nom du lanceur (journal, dashboard).
    fn name(&self) -> &'static str;

    /// Le lanceur ajoute-t-il lui-même la clé du fournisseur LLM aux appels du worker (mandataire,
    /// D1) ? Si oui, `init` ne transmet **aucune** clé LLM au worker.
    fn injects_llm_credentials(&self) -> bool {
        false
    }
}

/// Bouchon de L05 : le worker de `synco-ai-runtime-worker` dans une tâche, sans isolation.
#[derive(Debug, Default, Clone, Copy)]
pub struct InProcessStubLauncher;

struct StubProcess {
    task: Option<tokio::task::JoinHandle<()>>,
}

impl WorkerProcess for StubProcess {
    fn kill(&mut self) {
        if let Some(t) = &self.task {
            t.abort();
        }
    }

    fn wait(&mut self) -> BoxFuture<'_, WorkerExit> {
        Box::pin(async move {
            match self.task.take() {
                Some(t) => match t.await {
                    Ok(()) => WorkerExit::Exited(0),
                    Err(e) if e.is_cancelled() => WorkerExit::Signaled(9),
                    Err(_) => WorkerExit::Unknown,
                },
                None => WorkerExit::Unknown,
            }
        })
    }

    fn usage(&self) -> Option<ResourceUsage> {
        None
    }

    fn pid(&self) -> Option<u32> {
        None
    }
}

impl WorkerLauncher for InProcessStubLauncher {
    fn spawn(&self, _spec: WorkerSpec) -> BoxFuture<'_, Result<SpawnedWorker, LaunchError>> {
        Box::pin(async move {
            let (ours, theirs) = tokio::io::duplex(2 * 1024 * 1024);
            let task = tokio::spawn(async move {
                if let Err(e) = synco_ai_runtime_worker::stub::run(theirs).await {
                    tracing::debug!(code = %e, "bouchon de worker terminé sur erreur");
                }
            });
            Ok(SpawnedWorker { io: Box::new(ours), process: Box::new(StubProcess { task: Some(task) }) })
        })
    }

    fn name(&self) -> &'static str {
        "in-process-stub"
    }
}
