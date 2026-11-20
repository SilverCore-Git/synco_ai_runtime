//! Configuration du runtime : fichier TOML commenté (exemple : `synco-ai-runtime.example.toml`),
//! validé entièrement au démarrage et par `--check-config`.
//!
//! D1 : les secrets des fournisseurs LLM sont **dans la configuration du runtime**, jamais demandés
//! à l'API ; ils sont lus depuis un fichier (`api_key_file`, idéalement un identifiant systemd) ou
//! une variable d'environnement (`api_key_env`), jamais écrits en clair dans ce fichier.
//! D6 : plafonds de 09 §2, réglables ici ; l'org peut seulement les abaisser.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use synco_e2ee::runtime_cert::canonical_runtime_url;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Configuration complète, validée.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// URL publique canonique du runtime (01 §3), joignable en `wss://` par les navigateurs (D10).
    pub public_url: String,
    /// Origine de l'API Synco (`https://…`, sans chemin). `http://` admis seulement en boucle locale.
    pub api_url: String,
    /// Répertoire d'état (clés scellées, épinglages, autorisations). Aucun secret en clair.
    pub state_dir: PathBuf,
    /// Origines admises pour le WebSocket et la fiche publique (app web, Capacitor, Tauri).
    pub allowed_origins: Vec<String>,
    /// Écoute.
    #[serde(default)]
    pub listen: Listen,
    /// Scellement de la clé privée au repos (mesure 8).
    #[serde(default)]
    pub key_sealing: KeySealing,
    /// Délégations (D4).
    #[serde(default)]
    pub delegation: Delegation,
    /// Plafonds (D6).
    #[serde(default)]
    pub limits: Limits,
    /// Fournisseurs LLM (D1).
    #[serde(default)]
    pub llm: Llm,
    /// Bac à sable des workers (L06, docs/plan/10).
    #[serde(default)]
    pub sandbox: Sandbox,
    /// Journal : `error`, `warn`, `info`, `debug`.
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Développement uniquement : accepte une `public_url` en `http://localhost|127.0.0.1`.
    #[serde(default)]
    pub dev_allow_http_public_url: bool,
}

fn default_log_level() -> String {
    "info".to_owned()
}

/// Adresses d'écoute.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    /// Endpoints publics (`/v1/…`), en HTTP derrière le mandataire TLS qui sert `public_url`.
    pub public: SocketAddr,
    /// Dashboard (L08).
    pub dashboard: SocketAddr,
    /// Mandataires de confiance devant `public` (adresse du client lue dans `X-Forwarded-For`).
    pub trust_proxy_hops: usize,
    /// Accepte une adresse d'écoute non locale, en HTTP sans chiffrement (mandataire TLS sur une
    /// autre machine d'un réseau de confiance). Refusé par défaut : le runtime ne termine pas TLS.
    #[serde(default)]
    pub allow_non_loopback_plain_http: bool,
}

impl Default for Listen {
    fn default() -> Self {
        Self {
            public: SocketAddr::from(([127, 0, 0, 1], 8790)),
            dashboard: SocketAddr::from(([127, 0, 0, 1], 8791)),
            trust_proxy_hops: 1,
            allow_non_loopback_plain_http: false,
        }
    }
}

/// Mode de scellement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SealingMode {
    /// `systemd-creds` s'il est disponible, sinon phrase de passe.
    #[default]
    Auto,
    /// `systemd-creds` (TPM2 et/ou clé de l'hôte) obligatoire.
    SystemdCreds,
    /// Phrase de passe (Argon2id + AES-256-GCM).
    Passphrase,
}

/// Scellement de la clé privée (mesure 8).
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct KeySealing {
    /// Mode.
    #[serde(default)]
    pub mode: SealingMode,
    /// `systemd-creds --user` (runtime lancé par un service utilisateur).
    #[serde(default)]
    pub systemd_creds_user: bool,
    /// Fichier contenant la phrase de passe (ex. identifiant systemd dans `$CREDENTIALS_DIRECTORY`).
    /// Absent : demandée sur le terminal au démarrage.
    pub passphrase_file: Option<PathBuf>,
}

/// Délégations.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    /// Plafond du runtime sur `exp − iat` (jours, 1 h à 30 j ; 09 §1).
    pub max_days: f64,
}

impl Default for Delegation {
    fn default() -> Self {
        Self { max_days: 30.0 }
    }
}

impl Delegation {
    /// Plafond en secondes.
    #[must_use]
    pub fn max_lifetime_secs(&self) -> u64 {
        let secs = (self.max_days * 86_400.0).round();
        if secs.is_finite() && (3_600.0..=30.0 * 86_400.0).contains(&secs) {
            // Borné ci-dessus : conversion sans perte.
            #[allow(clippy::as_conversions, reason = "valeur bornée à [3 600, 2 592 000]")]
            let s = secs as u64;
            s
        } else {
            30 * 86_400
        }
    }
}

/// Plafonds (09 §2). Valeurs par défaut = propositions adoptées (D6).
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Appels au fournisseur par tour.
    pub max_steps_per_turn: u64,
    /// Tokens cumulés par conversation.
    pub max_tokens_per_conversation: u64,
    /// Tokens par tour.
    pub max_tokens_per_turn: u64,
    /// Durée d'un tour (s).
    pub max_turn_duration_secs: u64,
    /// Tokens de sortie par appel.
    pub max_output_tokens_per_call: u64,
    /// Taille d'un résultat d'outil (octets).
    pub max_tool_result_bytes: u64,
    /// Arrêt du worker après inactivité (s).
    pub idle_shutdown_secs: u64,
    /// Workers simultanés par utilisateur.
    pub max_workers_per_user: usize,
    /// Workers simultanés par runtime.
    pub max_workers: usize,
    /// RAM par worker, `memory.max` (Mio) — appliqué par le bac à sable (L06).
    pub worker_memory_max_mib: u64,
    /// `memory.high` (Mio).
    pub worker_memory_high_mib: u64,
    /// CPU par worker en pour cent d'un cœur (`cpu.max`).
    pub worker_cpu_percent: u64,
    /// `pids.max`.
    pub worker_pids_max: u64,
    /// Tampon de reprise : évènements par conversation.
    pub replay_buffer_events: usize,
    /// Tampon de reprise : octets par conversation.
    pub replay_buffer_bytes: usize,
    /// `signed_request` du worker : débit par seconde.
    pub worker_signed_requests_per_sec: u32,
    /// `signed_request` du worker : rafale.
    pub worker_signed_requests_burst: u32,
    /// Délai laissé aux workers pour finir l'étape en cours à l'arrêt (`SIGTERM`), en secondes.
    pub shutdown_grace_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_steps_per_turn: 25,
            max_tokens_per_conversation: 2_000_000,
            max_tokens_per_turn: 300_000,
            max_turn_duration_secs: 1_800,
            max_output_tokens_per_call: 4_096,
            max_tool_result_bytes: 256 * 1024,
            idle_shutdown_secs: 60,
            max_workers_per_user: 3,
            max_workers: 8,
            worker_memory_max_mib: 512,
            worker_memory_high_mib: 448,
            worker_cpu_percent: 100,
            worker_pids_max: 64,
            replay_buffer_events: 2_000,
            replay_buffer_bytes: 4 * 1024 * 1024,
            worker_signed_requests_per_sec: 20,
            worker_signed_requests_burst: 50,
            shutdown_grace_secs: 30,
        }
    }
}

/// Bac à sable des workers (L06).
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Sandbox {
    /// Base du sous-arbre cgroup v2 délégué (défaut : le cgroup du service, `Delegate=yes`).
    pub cgroup_root: Option<PathBuf>,
    /// Répertoire des sockets du mandataire LLM (défaut : `<state_dir>/workers`).
    pub run_dir: Option<PathBuf>,
}

impl Config {
    /// Réglages effectifs du bac à sable.
    #[must_use]
    pub fn sandbox_settings(&self) -> crate::sandbox::SandboxSettings {
        crate::sandbox::SandboxSettings {
            program: None,
            cgroup_root: self.sandbox.cgroup_root.clone(),
            run_dir: self.sandbox.run_dir.clone().unwrap_or_else(|| self.state_dir.join("workers")),
        }
    }
}

/// Fournisseurs LLM.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Llm {
    /// Par identifiant de fournisseur (`openai`, `mistral`, `gemini`, `custom`, `gateway`), celui de la
    /// politique de l'org (`GET /llm-policy`).
    #[serde(default)]
    pub providers: BTreeMap<String, Provider>,
}

/// Un fournisseur LLM configuré dans le runtime.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    /// URL de base de l'API du fournisseur (compatible OpenAI). Pour `gateway`, l'URL vient de la
    /// politique de l'org.
    pub base_url: Option<String>,
    /// Fichier contenant la clé API (lu au démarrage, gardé en mémoire effacée à la libération).
    pub api_key_file: Option<PathBuf>,
    /// Variable d'environnement contenant la clé API. Elle reste dans l'environnement du processus
    /// (la retirer exige `unsafe` en Rust 2024) : préférer `api_key_file` ; L06 vide
    /// l'environnement des workers (`env_clear`).
    pub api_key_env: Option<String>,
    /// Tarif indicatif (€ / million de tokens d'entrée), pour le dashboard.
    pub input_eur_per_mtok: Option<f64>,
    /// Tarif indicatif (€ / million de tokens de sortie).
    pub output_eur_per_mtok: Option<f64>,
}

const KNOWN_PROVIDERS: [&str; 5] = ["openai", "mistral", "gemini", "gateway", "custom"];

/// Secret d'un fournisseur, en mémoire seulement.
pub struct ProviderSecret(pub Zeroizing<Vec<u8>>);

impl core::fmt::Debug for ProviderSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProviderSecret(***)")
    }
}

fn invalid(msg: impl Into<String>) -> Error {
    Error::Config(msg.into())
}

/// `http://` admis seulement vers une adresse de boucle locale (tests, développement).
fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

impl Config {
    /// Lit et valide un fichier.
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).map_err(|e| invalid(format!("lecture de {} : {e}", path.display())))?;
        Self::parse(&text)
    }

    /// Lit et valide un texte TOML.
    pub fn parse(text: &str) -> Result<Self> {
        let config: Self = toml::from_str(text).map_err(|e| invalid(format!("TOML invalide : {e}")))?;
        config.validate()?;
        Ok(config)
    }

    /// Contrôles de cohérence (sans effet de bord ni lecture de secret).
    pub fn validate(&self) -> Result<()> {
        // Un socket Unix tient en 108 octets : `<run_dir>/w-<n>-<pid>/llm.sock` doit y entrer.
        let run_dir = self.sandbox_settings().run_dir;
        if !run_dir.is_absolute() || run_dir.as_os_str().len() > 72 {
            return Err(invalid("sandbox.run_dir (ou state_dir) : chemin absolu de 72 octets au plus"));
        }
        if self.sandbox.cgroup_root.as_ref().is_some_and(|p| !p.starts_with(crate::sandbox::cgroup::CGROUP_FS)) {
            return Err(invalid("sandbox.cgroup_root : sous /sys/fs/cgroup attendu"));
        }
        let canonical = canonical_runtime_url(&self.public_url, self.dev_allow_http_public_url)
            .map_err(|_| invalid("public_url : URL https canonique attendue (01 §3)"))?;
        if canonical != self.public_url {
            return Err(invalid(format!("public_url : écrire la forme canonique « {canonical} »")));
        }
        let api = reqwest::Url::parse(&self.api_url).map_err(|_| invalid("api_url : URL invalide"))?;
        let host = api.host_str().unwrap_or_default();
        let scheme_ok = api.scheme() == "https" || (api.scheme() == "http" && is_loopback_host(host));
        if !scheme_ok
            || !api.username().is_empty()
            || api.password().is_some()
            || api.query().is_some()
            || api.fragment().is_some()
            || !matches!(api.path(), "" | "/")
            || self.api_url.ends_with('/')
        {
            return Err(invalid(
                "api_url : origine https sans chemin ni barre finale (http seulement en boucle locale)",
            ));
        }
        for (name, addr) in [("listen.public", self.listen.public), ("listen.dashboard", self.listen.dashboard)] {
            if !addr.ip().is_loopback() && !self.listen.allow_non_loopback_plain_http {
                return Err(invalid(format!(
                    "{name} : adresse de boucle locale attendue (HTTP sans TLS derrière le mandataire) ; \
                     sinon listen.allow_non_loopback_plain_http = true"
                )));
            }
        }
        if self.listen.trust_proxy_hops > 4 {
            return Err(invalid("listen.trust_proxy_hops : au plus 4"));
        }
        if !self.state_dir.is_absolute() {
            return Err(invalid("state_dir : chemin absolu attendu"));
        }
        if self.allowed_origins.is_empty() {
            return Err(invalid("allowed_origins : au moins l'origine de l'app"));
        }
        for origin in &self.allowed_origins {
            let ok = !origin.ends_with('/')
                && !origin.contains(['*', ' ', '|'])
                && reqwest::Url::parse(origin).is_ok_and(|u| matches!(u.path(), "" | "/") && u.query().is_none());
            if !ok {
                return Err(invalid(format!("allowed_origins : origine invalide « {origin} » (ni joker ni chemin)")));
            }
        }
        if !matches!(self.log_level.as_str(), "error" | "warn" | "info" | "debug") {
            return Err(invalid("log_level : error, warn, info ou debug"));
        }
        let days = self.delegation.max_days;
        if !(days.is_finite() && (1.0 / 24.0..=30.0).contains(&days)) {
            return Err(invalid("delegation.max_days : entre 1/24 (1 h) et 30"));
        }
        self.limits.validate()?;
        for (id, p) in &self.llm.providers {
            if !KNOWN_PROVIDERS.contains(&id.as_str()) {
                return Err(invalid(format!("llm.providers.{id} : fournisseur inconnu")));
            }
            if p.api_key_file.is_some() && p.api_key_env.is_some() {
                return Err(invalid(format!("llm.providers.{id} : api_key_file OU api_key_env")));
            }
            if id == "gateway" && (p.api_key_file.is_some() || p.api_key_env.is_some()) {
                return Err(invalid("llm.providers.gateway : pas de clé, la passerelle reçoit un ticket sgt1"));
            }
            if let Some(url) = &p.base_url {
                let ok = reqwest::Url::parse(url).is_ok_and(|u| {
                    u.scheme() == "https"
                        || (u.scheme() == "http" && is_loopback_host(u.host_str().unwrap_or_default()))
                });
                if !ok {
                    return Err(invalid(format!("llm.providers.{id}.base_url : https attendu")));
                }
            }
            for price in [p.input_eur_per_mtok, p.output_eur_per_mtok].into_iter().flatten() {
                if !(price.is_finite() && price >= 0.0) {
                    return Err(invalid(format!("llm.providers.{id} : tarif invalide")));
                }
            }
        }
        Ok(())
    }

    /// Avertissements de `--check-config` (configuration valide mais probablement incohérente).
    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.listen.trust_proxy_hops == 0 {
            out.push(
                "listen.trust_proxy_hops = 0 : derrière un mandataire, toutes les connexions sembleront venir de lui \
                 (limites par adresse partagées) ; mettre 1 pour un mandataire"
                    .to_owned(),
            );
        }
        if self.listen.allow_non_loopback_plain_http {
            out.push(
                "listen.allow_non_loopback_plain_http : le trafic entre le mandataire et le runtime n'est pas chiffré"
                    .to_owned(),
            );
            if !self.listen.public.ip().is_loopback() && self.listen.trust_proxy_hops == 0 {
                out.push("écoute non locale sans mandataire déclaré : le runtime serait exposé sans TLS".to_owned());
            }
        }
        if self.dev_allow_http_public_url {
            out.push("dev_allow_http_public_url : réservé au développement".to_owned());
        }
        out
    }

    /// Lit les secrets des fournisseurs (D1). Jamais journalisés.
    pub fn read_provider_secrets(&self) -> Result<BTreeMap<String, ProviderSecret>> {
        let mut out = BTreeMap::new();
        for (id, p) in &self.llm.providers {
            let raw: Option<Zeroizing<Vec<u8>>> = if let Some(path) = &p.api_key_file {
                let bytes = std::fs::read(path)
                    .map_err(|e| invalid(format!("llm.providers.{id}.api_key_file illisible : {}", e.kind())))?;
                Some(Zeroizing::new(bytes))
            } else if let Some(var) = &p.api_key_env {
                let value =
                    std::env::var(var).map_err(|_| invalid(format!("llm.providers.{id} : variable {var} absente")))?;
                Some(Zeroizing::new(value.into_bytes()))
            } else {
                None
            };
            if let Some(mut bytes) = raw {
                while bytes.last().is_some_and(u8::is_ascii_whitespace) {
                    bytes.pop();
                }
                if bytes.is_empty() || bytes.len() > runtime_protocol::pipe::MAX_CREDENTIAL_LEN {
                    return Err(invalid(format!("llm.providers.{id} : clé vide ou trop longue")));
                }
                out.insert(id.clone(), ProviderSecret(bytes));
            }
        }
        Ok(out)
    }
}

impl Limits {
    fn validate(&self) -> Result<()> {
        let positive = [
            ("max_steps_per_turn", self.max_steps_per_turn),
            ("max_tokens_per_conversation", self.max_tokens_per_conversation),
            ("max_tokens_per_turn", self.max_tokens_per_turn),
            ("max_turn_duration_secs", self.max_turn_duration_secs),
            ("max_output_tokens_per_call", self.max_output_tokens_per_call),
            ("max_tool_result_bytes", self.max_tool_result_bytes),
            ("idle_shutdown_secs", self.idle_shutdown_secs),
            ("worker_memory_max_mib", self.worker_memory_max_mib),
            ("worker_memory_high_mib", self.worker_memory_high_mib),
            ("worker_cpu_percent", self.worker_cpu_percent),
            ("worker_pids_max", self.worker_pids_max),
        ];
        for (name, v) in positive {
            if v == 0 {
                return Err(invalid(format!("limits.{name} : ≥ 1")));
            }
        }
        if self.max_workers == 0 || self.max_workers_per_user == 0 {
            return Err(invalid("limits.max_workers et max_workers_per_user : ≥ 1"));
        }
        if self.worker_memory_high_mib > self.worker_memory_max_mib {
            return Err(invalid("limits.worker_memory_high_mib ≤ worker_memory_max_mib"));
        }
        if self.replay_buffer_events == 0
            || self.replay_buffer_bytes < runtime_protocol::client::MAX_RUNTIME_FRAME_BYTES
        {
            return Err(invalid("limits.replay_buffer_* : au moins 1 évènement et 1 Mio"));
        }
        if self.worker_signed_requests_per_sec == 0 || self.worker_signed_requests_burst == 0 {
            return Err(invalid("limits.worker_signed_requests_* : ≥ 1"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: &str = r#"
public_url = "https://runtime.example.com"
api_url = "https://api.example.com"
state_dir = "/var/lib/synco-ai-runtime"
allowed_origins = ["https://app.example.com"]
"#;

    #[test]
    fn minimale() {
        let c = Config::parse(MIN).unwrap();
        assert_eq!(c.limits, Limits::default());
        assert_eq!(c.delegation.max_lifetime_secs(), 30 * 86_400);
        assert_eq!(c.key_sealing.mode, SealingMode::Auto);
    }

    #[test]
    fn exemple_du_depot_valide() {
        let text = include_str!("../synco-ai-runtime.example.toml");
        let c = Config::parse(text).unwrap();
        assert!(c.llm.providers.contains_key("openai"));
    }

    #[test]
    fn refus() {
        for (from, to) in [
            ("https://runtime.example.com", "http://runtime.example.com"),
            ("https://runtime.example.com", "https://Runtime.example.com/"),
            ("https://api.example.com", "http://api.example.com"),
            ("https://api.example.com", "https://api.example.com/synco"),
            ("/var/lib/synco-ai-runtime", "relatif"),
            (r#"["https://app.example.com"]"#, r#"["*"]"#),
            (r#"["https://app.example.com"]"#, "[]"),
        ] {
            assert!(Config::parse(&MIN.replace(from, to)).is_err(), "{to}");
        }
        assert!(Config::parse(&format!("{MIN}\ninconnu = 1\n")).is_err(), "champ inconnu");
        assert!(Config::parse(&format!("{MIN}\n[delegation]\nmax_days = 31\n")).is_err());
        assert!(Config::parse(&format!("{MIN}\n[limits]\nmax_workers = 0\n")).is_err());
        assert!(
            Config::parse(&format!("{MIN}\n[llm.providers.gateway]\napi_key_env = \"X\"\n")).is_err(),
            "pas de clé pour la passerelle"
        );
        assert!(Config::parse(&format!("{MIN}\n[llm.providers.inconnu]\n")).is_err());
        let open = "[listen]\npublic = \"0.0.0.0:8790\"\ndashboard = \"127.0.0.1:8791\"\ntrust_proxy_hops = 1\n";
        assert!(Config::parse(&format!("{MIN}\n{open}")).is_err(), "écoute non locale refusée");
        let c = Config::parse(&format!("{MIN}\n{open}allow_non_loopback_plain_http = true\n")).unwrap();
        assert!(!c.warnings().is_empty());
        assert!(Config::parse(MIN).unwrap().warnings().is_empty());
    }

    #[test]
    fn boucle_locale_pour_les_tests() {
        let c = Config::parse(&MIN.replace("https://api.example.com", "http://127.0.0.1:4000")).unwrap();
        assert_eq!(c.api_url, "http://127.0.0.1:4000");
    }
}
