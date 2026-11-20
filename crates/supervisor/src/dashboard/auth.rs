//! Authentification du dashboard (docs/plan/11 §1–§3) : mot de passe local haché (Argon2id),
//! sessions à jeton aléatoire (seul le SHA-256 est gardé), protection contre la force brute.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use synco_e2ee::encoding::{b64u, from_b64u};
use synco_e2ee::primitives::sha256;
use synco_e2ee::{OsRandom, RandomSource};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::seal::{self, KdfParams};

/// Fichier du mot de passe, dans le répertoire d'état.
pub const PASSWORD_FILE: &str = "dashboard.pass";
/// Longueur minimale d'un mot de passe.
pub const MIN_PASSWORD_CHARS: usize = 12;
/// Longueur maximale acceptée à la connexion (borne le travail d'Argon2).
pub const MAX_PASSWORD_BYTES: usize = 256;
/// Inactivité maximale d'une session.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Durée de vie absolue d'une session.
pub const ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(12 * 3600);
/// Sessions simultanées.
pub const MAX_SESSIONS: usize = 16;
/// Fenêtre de comptage des échecs de connexion.
pub const FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Échecs tolérés par adresse dans la fenêtre.
pub const MAX_FAILURES_PER_IP: u32 = 5;
/// Échecs tolérés au total dans la fenêtre.
pub const MAX_FAILURES_TOTAL: u32 = 20;
const MAX_TRACKED_IPS: usize = 10_000;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PasswordDoc {
    v: u8,
    alg: String,
    m_kib: u32,
    t: u32,
    p: u32,
    salt: String,
    hash: String,
}

fn cfg(msg: &str) -> Error {
    Error::Config(msg.to_owned())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Écrit `<state_dir>/dashboard.pass` (0600) : Argon2id, sel aléatoire.
pub fn set_password(state_dir: &Path, password: &str, params: KdfParams) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(cfg("mot de passe trop court (12 caractères au moins)"));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(cfg("mot de passe trop long (256 octets au plus)"));
    }
    let mut salt = [0u8; 16];
    OsRandom.fill(&mut salt)?;
    let hash = seal::derive(password.as_bytes(), &salt, params)?;
    let doc = PasswordDoc {
        v: 1,
        alg: "argon2id".into(),
        m_kib: params.m_kib,
        t: params.t,
        p: params.p,
        salt: b64u(&salt),
        hash: b64u(hash.as_ref()),
    };
    let bytes = serde_json::to_vec_pretty(&doc).map_err(|_| cfg("sérialisation impossible"))?;
    seal::ensure_state_dir(state_dir)?;
    seal::write_atomic(&state_dir.join(PASSWORD_FILE), &bytes)
}

/// Un mot de passe est-il défini ?
#[must_use]
pub fn password_is_set(state_dir: &Path) -> bool {
    state_dir.join(PASSWORD_FILE).is_file()
}

/// Demande le mot de passe deux fois sur le terminal (sans écho) puis l'enregistre.
pub fn set_password_interactive(state_dir: &Path) -> Result<()> {
    let first = seal::prompt_hidden("Nouveau mot de passe du dashboard : ")?;
    let second = seal::prompt_hidden("Confirmer le mot de passe : ")?;
    if *first != *second {
        return Err(cfg("les deux saisies diffèrent"));
    }
    set_password(state_dir, &first, KdfParams::default())
}

struct Cred {
    stamp: (SystemTime, u64),
    doc: PasswordDoc,
}

struct Session {
    created: Instant,
    last_seen: Instant,
    csrf: String,
}

/// Compteurs d'échecs de connexion, par adresse et au total.
#[derive(Debug, Default)]
struct Failures {
    per_ip: HashMap<String, (Instant, u32)>,
    total: Option<(Instant, u32)>,
}

impl Failures {
    fn fresh(start: Instant, now: Instant) -> bool {
        now.saturating_duration_since(start) < FAILURE_WINDOW
    }

    /// Attente avant un nouvel essai, si une limite est atteinte.
    fn blocked(&self, ip: &str, now: Instant) -> Option<Duration> {
        let wait = |(start, n): &(Instant, u32), max: u32| {
            (Self::fresh(*start, now) && *n >= max)
                .then(|| FAILURE_WINDOW.saturating_sub(now.saturating_duration_since(*start)))
        };
        let a = self.per_ip.get(ip).and_then(|e| wait(e, MAX_FAILURES_PER_IP));
        let b = self.total.as_ref().and_then(|e| wait(e, MAX_FAILURES_TOTAL));
        a.max(b)
    }

    fn record(&mut self, ip: &str, now: Instant) {
        if self.per_ip.len() >= MAX_TRACKED_IPS && !self.per_ip.contains_key(ip) {
            self.per_ip.retain(|_, (s, _)| Self::fresh(*s, now));
        }
        let key = if self.per_ip.len() >= MAX_TRACKED_IPS && !self.per_ip.contains_key(ip) { "*" } else { ip };
        let bump = |e: &mut (Instant, u32)| {
            if !Self::fresh(e.0, now) {
                *e = (now, 0);
            }
            e.1 = e.1.saturating_add(1);
        };
        bump(self.per_ip.entry(key.to_owned()).or_insert((now, 0)));
        bump(self.total.get_or_insert((now, 0)));
    }
}

/// Résultat d'une tentative de connexion.
#[derive(Debug, PartialEq, Eq)]
pub enum Login {
    /// Connecté : jeton du cookie et jeton CSRF.
    Ok {
        /// Valeur du cookie.
        token: String,
        /// Jeton CSRF de la session.
        csrf: String,
    },
    /// Mot de passe incorrect.
    Invalid,
    /// Trop d'échecs : réessayer dans `n` secondes.
    Limited(u64),
    /// Aucun mot de passe défini ou fichier illisible.
    Unavailable,
}

/// Authentification : mot de passe, sessions, limiteur.
pub struct Auth {
    path: PathBuf,
    cred: Mutex<Option<Cred>>,
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    failures: Mutex<Failures>,
    verify: Semaphore,
}

impl core::fmt::Debug for Auth {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Auth").finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn random_token(bytes: usize) -> Option<String> {
    let mut buf = Zeroizing::new(vec![0u8; bytes]);
    OsRandom.fill(&mut buf).ok()?;
    Some(b64u(&buf))
}

fn hash_token(token: &str) -> [u8; 32] {
    sha256(token.as_bytes())
}

impl Auth {
    /// Authentification lisant `<state_dir>/dashboard.pass`.
    #[must_use]
    pub fn new(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join(PASSWORD_FILE),
            cred: Mutex::new(None),
            sessions: Mutex::new(HashMap::new()),
            failures: Mutex::new(Failures::default()),
            verify: Semaphore::new(1),
        }
    }

    /// Relit le fichier s'il a changé (date ou taille) ; un changement ferme toutes les sessions.
    fn refresh(&self) -> bool {
        let stamp = std::fs::metadata(&self.path).and_then(|m| Ok((m.modified()?, m.len()))).ok();
        let mut cred = lock(&self.cred);
        match (stamp, cred.as_ref()) {
            (None, _) => {
                *cred = None;
                lock(&self.sessions).clear();
                false
            }
            (Some(s), Some(c)) if c.stamp == s => true,
            (Some(s), _) => {
                let doc = std::fs::read(&self.path)
                    .ok()
                    .and_then(|b| serde_json::from_slice::<PasswordDoc>(&b).ok())
                    .filter(|d| d.v == 1 && d.alg == "argon2id");
                lock(&self.sessions).clear();
                *cred = doc.map(|doc| Cred { stamp: s, doc });
                cred.is_some()
            }
        }
    }

    /// Tentative de connexion de `ip`. Les échecs sont comptés **avant** que le travail d'Argon2 ne
    /// soit fait (une vérification à la fois), si bien qu'une rafale parallèle ne contourne pas la
    /// limite.
    pub async fn login(&self, password: &str, ip: &str, now: Instant) -> Login {
        if !self.refresh() {
            return Login::Unavailable;
        }
        let Ok(_permit) = self.verify.acquire().await else { return Login::Unavailable };
        if let Some(wait) = lock(&self.failures).blocked(ip, now) {
            return Login::Limited(wait.as_secs().max(1));
        }
        let ok = password.len() <= MAX_PASSWORD_BYTES && self.check_password(password).await;
        if !ok {
            lock(&self.failures).record(ip, now);
            return Login::Invalid;
        }
        lock(&self.failures).per_ip.remove(ip);
        let (Some(token), Some(csrf)) = (random_token(32), random_token(16)) else { return Login::Unavailable };
        let mut sessions = lock(&self.sessions);
        sessions.retain(|_, s| Self::alive(s, now));
        if sessions.len() >= MAX_SESSIONS {
            let oldest = sessions.iter().min_by_key(|(_, s)| s.last_seen).map(|(k, _)| *k);
            if let Some(k) = oldest {
                sessions.remove(&k);
            }
        }
        sessions.insert(hash_token(&token), Session { created: now, last_seen: now, csrf: csrf.clone() });
        Login::Ok { token, csrf }
    }

    async fn check_password(&self, password: &str) -> bool {
        let Some((params, salt, expected)) = ({
            let cred = lock(&self.cred);
            cred.as_ref().and_then(|c| {
                Some((
                    KdfParams { m_kib: c.doc.m_kib, t: c.doc.t, p: c.doc.p },
                    from_b64u(&c.doc.salt).ok()?,
                    from_b64u(&c.doc.hash).ok()?,
                ))
            })
        }) else {
            return false;
        };
        let password = Zeroizing::new(password.as_bytes().to_vec());
        tokio::task::spawn_blocking(move || {
            seal::derive(&password, &salt, params).is_ok_and(|h| ct_eq(h.as_ref(), &expected))
        })
        .await
        .unwrap_or(false)
    }

    fn alive(s: &Session, now: Instant) -> bool {
        now.saturating_duration_since(s.last_seen) < IDLE_TIMEOUT
            && now.saturating_duration_since(s.created) < ABSOLUTE_TIMEOUT
    }

    /// Session valide pour ce jeton ? Renvoie le jeton CSRF et prolonge l'inactivité.
    pub fn check(&self, token: &str, now: Instant) -> Option<String> {
        if !self.refresh() {
            return None;
        }
        let key = hash_token(token);
        let mut sessions = lock(&self.sessions);
        let s = sessions.get_mut(&key)?;
        if !Self::alive(s, now) {
            sessions.remove(&key);
            return None;
        }
        s.last_seen = now;
        Some(s.csrf.clone())
    }

    /// Ferme une session.
    pub fn logout(&self, token: &str) {
        lock(&self.sessions).remove(&hash_token(token));
    }

    /// Sessions ouvertes (tests).
    #[must_use]
    pub fn session_count(&self) -> usize {
        lock(&self.sessions).len()
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, reason = "tests")]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams { m_kib: 256, t: 1, p: 1 };
    const PW: &str = "un mot de passe de test";

    fn setup() -> (tempfile::TempDir, Auth) {
        let dir = tempfile::tempdir().unwrap();
        set_password(dir.path(), PW, FAST).unwrap();
        let auth = Auth::new(dir.path());
        (dir, auth)
    }

    #[tokio::test]
    async fn connexion_et_session() {
        let (_d, a) = setup();
        let t0 = Instant::now();
        let Login::Ok { token, csrf } = a.login(PW, "1.1.1.1", t0).await else { panic!("connexion refusée") };
        assert_eq!(a.check(&token, t0), Some(csrf));
        assert_eq!(a.check("autre", t0), None);
        a.logout(&token);
        assert_eq!(a.check(&token, t0), None);
    }

    #[tokio::test]
    async fn jetons_neufs_a_chaque_connexion_sans_fixation() {
        let (_d, a) = setup();
        let t0 = Instant::now();
        let Login::Ok { token: t1, .. } = a.login(PW, "1.1.1.1", t0).await else { panic!() };
        let Login::Ok { token: t2, .. } = a.login(PW, "1.1.1.1", t0).await else { panic!() };
        assert_ne!(t1, t2);
        // Un jeton choisi par un tiers n'existe pas côté serveur : il n'ouvre rien.
        assert_eq!(a.check("jeton-impose-par-l-attaquant", t0), None);
        assert_eq!(a.session_count(), 2);
    }

    #[tokio::test]
    async fn expiration_inactivite_et_duree_absolue() {
        let (_d, a) = setup();
        let t0 = Instant::now();
        let Login::Ok { token, .. } = a.login(PW, "1.1.1.1", t0).await else { panic!() };
        assert!(a.check(&token, t0 + IDLE_TIMEOUT - Duration::from_secs(1)).is_some());
        assert!(a.check(&token, t0 + IDLE_TIMEOUT * 2).is_none(), "inactif trop longtemps");
        let Login::Ok { token, .. } = a.login(PW, "1.1.1.1", t0).await else { panic!() };
        let mut t = t0;
        while t < t0 + ABSOLUTE_TIMEOUT {
            t += Duration::from_secs(20 * 60);
            if t < t0 + ABSOLUTE_TIMEOUT {
                assert!(a.check(&token, t).is_some());
            }
        }
        assert!(a.check(&token, t0 + ABSOLUTE_TIMEOUT).is_none(), "durée absolue");
    }

    #[tokio::test]
    async fn force_brute_par_adresse_puis_global() {
        let (_d, a) = setup();
        let t0 = Instant::now();
        for _ in 0..MAX_FAILURES_PER_IP {
            assert_eq!(a.login("mauvais mot de passe", "9.9.9.9", t0).await, Login::Invalid);
        }
        // Verrouillé : même le bon mot de passe est refusé sans être vérifié.
        assert!(matches!(a.login(PW, "9.9.9.9", t0).await, Login::Limited(n) if n > 0 && n <= 900));
        // Une autre adresse n'est pas touchée.
        assert!(matches!(a.login(PW, "8.8.8.8", t0).await, Login::Ok { .. }));
        // La fenêtre passée, l'adresse est de nouveau admise.
        assert!(matches!(a.login(PW, "9.9.9.9", t0 + FAILURE_WINDOW).await, Login::Ok { .. }));
        // Fenêtre globale : de nombreuses adresses, chacune sous sa limite.
        let (_d, a) = setup();
        for i in 0..MAX_FAILURES_TOTAL {
            assert_eq!(a.login("non", &format!("203.0.113.{i}"), t0).await, Login::Invalid);
        }
        assert!(matches!(a.login(PW, "203.0.114.9", t0).await, Login::Limited(_)));
    }

    #[tokio::test]
    async fn rafale_parallele_ne_contourne_pas_la_limite() {
        let (_d, a) = setup();
        let a = std::sync::Arc::new(a);
        let t0 = Instant::now();
        let tasks: Vec<_> = (0..30)
            .map(|_| {
                let a = a.clone();
                tokio::spawn(async move { a.login("faux", "7.7.7.7", t0).await })
            })
            .collect();
        let mut invalid = 0;
        for t in tasks {
            if t.await.unwrap() == Login::Invalid {
                invalid += 1;
            }
        }
        assert_eq!(invalid, MAX_FAILURES_PER_IP, "pas plus de 5 vérifications pour une adresse");
    }

    #[tokio::test]
    async fn succes_remet_le_compteur_de_l_adresse_a_zero() {
        let (_d, a) = setup();
        let t0 = Instant::now();
        for _ in 0..MAX_FAILURES_PER_IP - 1 {
            a.login("faux", "5.5.5.5", t0).await;
        }
        assert!(matches!(a.login(PW, "5.5.5.5", t0).await, Login::Ok { .. }));
        for _ in 0..MAX_FAILURES_PER_IP {
            assert_eq!(a.login("faux", "5.5.5.5", t0).await, Login::Invalid);
        }
    }

    #[tokio::test]
    async fn changement_de_mot_de_passe_ferme_les_sessions() {
        let (d, a) = setup();
        let t0 = Instant::now();
        let Login::Ok { token, .. } = a.login(PW, "1.1.1.1", t0).await else { panic!() };
        std::thread::sleep(Duration::from_millis(20));
        set_password(d.path(), "un autre mot de passe", FAST).unwrap();
        assert_eq!(a.check(&token, t0), None);
        assert_eq!(a.login(PW, "1.1.1.1", t0).await, Login::Invalid);
        assert!(matches!(a.login("un autre mot de passe", "1.1.1.1", t0).await, Login::Ok { .. }));
    }

    #[tokio::test]
    async fn sans_fichier_indisponible_et_sessions_plafonnees() {
        let dir = tempfile::tempdir().unwrap();
        let a = Auth::new(dir.path());
        let t0 = Instant::now();
        assert_eq!(a.login(PW, "1.1.1.1", t0).await, Login::Unavailable);
        assert!(!password_is_set(dir.path()));
        set_password(dir.path(), PW, FAST).unwrap();
        for _ in 0..MAX_SESSIONS + 3 {
            assert!(matches!(a.login(PW, "1.1.1.1", t0).await, Login::Ok { .. }));
        }
        assert_eq!(a.session_count(), MAX_SESSIONS);
    }

    #[test]
    fn mot_de_passe_court_ou_trop_long_refuse_et_fichier_sans_clair() {
        let dir = tempfile::tempdir().unwrap();
        assert!(set_password(dir.path(), "court", FAST).is_err());
        assert!(set_password(dir.path(), &"x".repeat(300), FAST).is_err());
        set_password(dir.path(), PW, FAST).unwrap();
        let text = std::fs::read_to_string(dir.path().join(PASSWORD_FILE)).unwrap();
        assert!(!text.contains(PW) && text.contains("argon2id"));
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(dir.path().join(PASSWORD_FILE)).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
    }
}
