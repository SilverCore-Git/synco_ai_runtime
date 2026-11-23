//! Clé privée du runtime **scellée au repos** (mesure 8, docs/plan/01 §1) : jamais en clair sur
//! disque.
//!
//! | Backend | Fichier | Ouverture |
//! |---|---|---|
//! | `systemd-creds` (TPM2 et/ou clé de l'hôte) | `keys.cred` (format `systemd-creds`) | `$CREDENTIALS_DIRECTORY/synco-ai-runtime-keys` si le service le charge (`LoadCredentialEncrypted=`), sinon `systemd-creds decrypt` vers un tube |
//! | phrase de passe | `keys.sealed` (JSON : Argon2id + AES-256-GCM) | phrase lue sur le terminal (sans écho) ou dans `passphrase_file` |
//!
//! Le clair ne transite que par la mémoire (tampons effacés) et par des tubes vers
//! `systemd-creds` ; aucun fichier temporaire en clair.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use synco_e2ee::encoding::{b64u, from_b64u};
use synco_e2ee::primitives;
use synco_e2ee::{OsRandom, RandomSource};
use zeroize::Zeroizing;

use crate::config::{KeySealing, SealingMode};
use crate::error::{Error, Result};
use crate::keys::RuntimeKeys;

/// Fichier scellé par phrase de passe.
pub const PASSPHRASE_FILE: &str = "keys.sealed";
/// Fichier scellé par `systemd-creds`.
pub const CRED_FILE: &str = "keys.cred";
/// Nom de l'identifiant systemd (`--name`, `LoadCredentialEncrypted=`).
pub const CRED_NAME: &str = "synco-ai-runtime-keys";
/// Longueur minimale d'une phrase de passe.
pub const MIN_PASSPHRASE_CHARS: usize = 12;
const AAD_LABEL: &str = "synco-rt-keystore-v1";
/// Tampon fixe des secrets lus (clés déscellées, phrase de passe).
const SECRET_BUFFER: usize = 4096;

/// Paramètres Argon2id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KdfParams {
    /// Mémoire (Kio).
    pub m_kib: u32,
    /// Itérations.
    pub t: u32,
    /// Parallélisme.
    pub p: u32,
}

impl Default for KdfParams {
    /// 64 Mio, 3 passes, 1 voie (recommandation OWASP pour Argon2id).
    fn default() -> Self {
        Self { m_kib: 64 * 1024, t: 3, p: 1 }
    }
}

/// Source de la phrase de passe.
pub enum PassphraseSource {
    /// Terminal, sans écho (demandée deux fois à la création).
    Terminal,
    /// Fichier (identifiant systemd, tmpfs…).
    File(PathBuf),
    /// Fournie par l'appelant (tests, outils).
    Provided(Zeroizing<String>),
}

impl core::fmt::Debug for PassphraseSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Terminal => f.write_str("Terminal"),
            Self::File(p) => f.debug_tuple("File").field(p).finish(),
            Self::Provided(_) => f.write_str("Provided(***)"),
        }
    }
}

/// Backend choisi.
#[derive(Debug)]
pub enum Backend {
    /// `systemd-creds` (`--user` si demandé).
    SystemdCreds {
        /// Mode utilisateur.
        user: bool,
    },
    /// Phrase de passe.
    Passphrase {
        /// Source.
        source: PassphraseSource,
        /// Paramètres (création seulement ; à l'ouverture, ceux du fichier).
        kdf: KdfParams,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SealedFile {
    v: u8,
    backend: String,
    kdf: KdfDoc,
    blob: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KdfDoc {
    alg: String,
    m_kib: u32,
    t: u32,
    p: u32,
    salt: String,
}

impl KdfDoc {
    const fn params(&self) -> KdfParams {
        KdfParams { m_kib: self.m_kib, t: self.t, p: self.p }
    }
}

fn ks(msg: impl Into<String>) -> Error {
    Error::KeyStore(msg.into())
}

/// `systemd-creds` est-il utilisable ?
#[must_use]
pub fn systemd_creds_available() -> bool {
    Command::new("systemd-creds")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Backend selon la configuration (mode `auto` : `systemd-creds` si disponible).
#[must_use]
pub fn backend_from_config(cfg: &KeySealing) -> Backend {
    let passphrase = || Backend::Passphrase {
        source: cfg.passphrase_file.clone().map_or(PassphraseSource::Terminal, PassphraseSource::File),
        kdf: KdfParams::default(),
    };
    match cfg.mode {
        SealingMode::SystemdCreds => Backend::SystemdCreds { user: cfg.systemd_creds_user },
        SealingMode::Passphrase => passphrase(),
        SealingMode::Auto if systemd_creds_available() => Backend::SystemdCreds { user: cfg.systemd_creds_user },
        SealingMode::Auto => passphrase(),
    }
}

/// Crée le répertoire d'état (0700) s'il manque.
pub fn ensure_state_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| Error::Io(format!("création de {} : {}", dir.display(), e.kind())))?;
    }
    let meta = std::fs::metadata(dir).map_err(|e| Error::Io(format!("{} : {}", dir.display(), e.kind())))?;
    if !meta.is_dir() {
        return Err(Error::Io(format!("{} n'est pas un répertoire", dir.display())));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        tracing::warn!(
            code = "state_dir_permissions",
            "répertoire d'état accessible à d'autres utilisateurs (0700 conseillé)"
        );
    }
    Ok(())
}

/// Écriture atomique (fichier temporaire 0600 puis renommage). Pour des données **non secrètes**
/// ou déjà scellées uniquement.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let tmp = path.with_extension("tmp");
    let io = |e: std::io::Error| Error::Io(format!("écriture de {} : {}", path.display(), e.kind()));
    {
        let mut f =
            std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp).map_err(io)?;
        // `mode` ne vaut qu'à la création : un `.tmp` déjà présent garde ses droits, on les force.
        f.set_permissions(std::fs::Permissions::from_mode(0o600)).map_err(io)?;
        f.write_all(bytes).map_err(io)?;
        f.sync_all().map_err(io)?;
    }
    std::fs::rename(&tmp, path).map_err(io)?;
    // Le renommage n'est durable qu'après un fsync du répertoire.
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(io)
}

/// Fichiers de clés présents dans le répertoire d'état.
fn existing(dir: &Path) -> (Option<PathBuf>, Option<PathBuf>) {
    let p = dir.join(PASSPHRASE_FILE);
    let c = dir.join(CRED_FILE);
    (p.exists().then_some(p), c.exists().then_some(c))
}

/// Ouvre les clés existantes, ou `None` s'il n'y en a pas.
pub fn load(dir: &Path, backend: &Backend) -> Result<Option<RuntimeKeys>> {
    match existing(dir) {
        (Some(_), Some(_)) => Err(ks(format!("{PASSPHRASE_FILE} et {CRED_FILE} coexistent : en garder un seul"))),
        (None, None) => Ok(None),
        (Some(path), None) => {
            let source = match backend {
                Backend::Passphrase { source, .. } => source,
                Backend::SystemdCreds { .. } => &PassphraseSource::Terminal,
            };
            let secret = open_passphrase_file(&path, source)?;
            Ok(Some(RuntimeKeys::from_secret_bytes(&secret)?))
        }
        (None, Some(path)) => {
            let user = matches!(backend, Backend::SystemdCreds { user: true });
            let secret = systemd_decrypt(&path, user)?;
            Ok(Some(RuntimeKeys::from_secret_bytes(&secret)?))
        }
    }
}

/// Génère les clés (premier démarrage) et les scelle.
pub fn create(dir: &Path, backend: &Backend) -> Result<RuntimeKeys> {
    ensure_state_dir(dir)?;
    if existing(dir) != (None, None) {
        return Err(ks("des clés existent déjà (reset-keys pour en changer)"));
    }
    let keys = crate::keys::generate()?;
    let secret = keys.to_secret_bytes();
    match backend {
        Backend::Passphrase { source, kdf } => {
            let passphrase = read_passphrase(source, true)?;
            let doc = seal_with_passphrase(&secret, &passphrase, *kdf, &mut OsRandom)?;
            write_atomic(&dir.join(PASSPHRASE_FILE), &doc)?;
        }
        Backend::SystemdCreds { user } => systemd_encrypt(&secret, &dir.join(CRED_FILE), *user)?,
    }
    Ok(keys)
}

/// Ouvre ou, au premier démarrage, crée. Renvoie aussi `true` si les clés viennent d'être créées.
pub fn load_or_create(dir: &Path, backend: &Backend) -> Result<(RuntimeKeys, bool)> {
    match load(dir, backend)? {
        Some(k) => Ok((k, false)),
        None => Ok((create(dir, backend)?, true)),
    }
}

/// `reset-keys` : supprime les clés scellées (un nouvel appairage sera nécessaire).
pub fn reset(dir: &Path) -> Result<bool> {
    let mut removed = false;
    for name in [PASSPHRASE_FILE, CRED_FILE] {
        let p = dir.join(name);
        if p.exists() {
            std::fs::remove_file(&p).map_err(|e| Error::Io(format!("{} : {}", p.display(), e.kind())))?;
            removed = true;
        }
    }
    Ok(removed)
}

// ---------------------------------------------------------------------------
// Phrase de passe
// ---------------------------------------------------------------------------

fn aad(params: KdfParams, salt: &str) -> String {
    format!("{AAD_LABEL}|passphrase|argon2id|{}|{}|{}|{salt}", params.m_kib, params.t, params.p)
}

pub(crate) fn derive(passphrase: &[u8], salt: &[u8], params: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    // Bornes : un fichier altéré ne doit pas faire allouer 1 Tio au démarrage.
    if params.m_kib > 1024 * 1024 || params.t == 0 || params.t > 16 || params.p == 0 || params.p > 8 || salt.len() < 16
    {
        return Err(ks("paramètres Argon2id hors bornes"));
    }
    let p = Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|_| ks("paramètres Argon2id invalides"))?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(passphrase, salt, out.as_mut())
        .map_err(|_| ks("dérivation Argon2id impossible"))?;
    Ok(out)
}

/// Scelle par phrase de passe ; renvoie le document JSON à écrire.
pub fn seal_with_passphrase(
    secret: &[u8],
    passphrase: &str,
    params: KdfParams,
    rng: &mut impl RandomSource,
) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    rng.fill(&mut salt)?;
    let salt_b64u = b64u(&salt);
    let key = derive(passphrase.as_bytes(), &salt, params)?;
    let blob = primitives::seal(&key, aad(params, &salt_b64u).as_bytes(), secret, rng)?;
    let doc = SealedFile {
        v: 1,
        backend: "passphrase".into(),
        kdf: KdfDoc { alg: "argon2id".into(), m_kib: params.m_kib, t: params.t, p: params.p, salt: salt_b64u },
        blob: b64u(&blob),
    };
    serde_json::to_vec_pretty(&doc).map_err(|_| ks("sérialisation impossible"))
}

/// Ouvre un document scellé par phrase de passe.
pub fn open_with_passphrase(doc: &[u8], passphrase: &str) -> Result<Zeroizing<Vec<u8>>> {
    let file: SealedFile = serde_json::from_slice(doc).map_err(|_| ks(format!("{PASSPHRASE_FILE} illisible")))?;
    if file.v != 1 || file.backend != "passphrase" || file.kdf.alg != "argon2id" {
        return Err(ks(format!("{PASSPHRASE_FILE} : version ou algorithme inconnu")));
    }
    let salt = from_b64u(&file.kdf.salt).map_err(|_| ks("sel illisible"))?;
    let blob = from_b64u(&file.blob).map_err(|_| ks("blob illisible"))?;
    let params = file.kdf.params();
    let key = derive(passphrase.as_bytes(), &salt, params)?;
    primitives::open(&key, aad(params, &file.kdf.salt).as_bytes(), &blob)
        .ok_or_else(|| ks("phrase de passe incorrecte ou fichier altéré"))
}

fn open_passphrase_file(path: &Path, source: &PassphraseSource) -> Result<Zeroizing<Vec<u8>>> {
    let doc = std::fs::read(path).map_err(|e| Error::Io(format!("{} : {}", path.display(), e.kind())))?;
    let passphrase = read_passphrase(source, false)?;
    open_with_passphrase(&doc, &passphrase)
}

/// Fichier secret (phrase de passe) : fichier ordinaire, propriétaire = utilisateur du processus,
/// droits `0600` ou `0400` (aucun accès pour le groupe ni les autres).
pub fn check_secret_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let meta = std::fs::metadata(path).map_err(|e| ks(format!("passphrase_file : {}", e.kind())))?;
    if !meta.is_file() {
        return Err(ks("passphrase_file n'est pas un fichier ordinaire"));
    }
    if meta.uid() != rustix::process::getuid().as_raw() {
        return Err(ks("passphrase_file doit appartenir à l'utilisateur du runtime"));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(ks("passphrase_file : droits 0600 ou 0400 attendus"));
    }
    if meta.len() >= u64::try_from(SECRET_BUFFER).unwrap_or(4096) {
        return Err(ks("passphrase_file trop long"));
    }
    Ok(())
}

fn read_passphrase(source: &PassphraseSource, creating: bool) -> Result<Zeroizing<String>> {
    let value = match source {
        PassphraseSource::Provided(p) => p.clone(),
        PassphraseSource::File(path) => {
            check_secret_file(path)?;
            // Capacité réservée d'avance (fichier ≤ 4 Kio) : pas de réallocation.
            let mut s = Zeroizing::new(String::with_capacity(SECRET_BUFFER));
            std::fs::File::open(path)
                .and_then(|f| {
                    f.take(u64::try_from(SECRET_BUFFER).unwrap_or(4096).saturating_sub(1)).read_to_string(&mut s)
                })
                .map_err(|e| ks(format!("passphrase_file illisible : {}", e.kind())))?;
            let end = s.trim_end_matches(['\n', '\r']).len();
            s.truncate(end);
            s
        }
        PassphraseSource::Terminal => {
            let first = prompt_hidden("Phrase de passe des clés du runtime : ")?;
            if creating {
                let second = prompt_hidden("Confirmer la phrase de passe : ")?;
                if *first != *second {
                    return Err(ks("les deux saisies diffèrent"));
                }
            }
            first
        }
    };
    if creating && value.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(ks(format!("phrase de passe trop courte (au moins {MIN_PASSPHRASE_CHARS} caractères)")));
    }
    if value.is_empty() {
        return Err(ks("phrase de passe vide"));
    }
    Ok(value)
}

/// Lit une ligne sur le terminal sans écho (stdin doit être un terminal).
pub(crate) fn prompt_hidden(prompt: &str) -> Result<Zeroizing<String>> {
    use rustix::termios::{LocalModes, OptionalActions, isatty, tcgetattr, tcsetattr};
    let stdin = std::io::stdin();
    if !isatty(&stdin) {
        return Err(ks("phrase de passe demandée mais l'entrée n'est pas un terminal (passphrase_file ?)"));
    }
    let original = tcgetattr(&stdin).map_err(|_| ks("terminal illisible"))?;
    let mut hidden = original.clone();
    hidden.local_modes.remove(LocalModes::ECHO);
    hidden.local_modes.insert(LocalModes::ECHONL);
    let mut err = std::io::stderr();
    let _ = err.write_all(prompt.as_bytes());
    let _ = err.flush();
    tcsetattr(&stdin, OptionalActions::Flush, &hidden).map_err(|_| ks("terminal non configurable"))?;
    // Capacité réservée : une ligne de moins de 4 Kio ne provoque aucune réallocation.
    let mut line = Zeroizing::new(String::with_capacity(SECRET_BUFFER));
    let read = stdin.read_line(&mut line);
    let _ = tcsetattr(&stdin, OptionalActions::Flush, &original);
    read.map_err(|_| ks("lecture du terminal impossible"))?;
    let end = line.trim_end_matches(['\n', '\r']).len();
    line.truncate(end);
    Ok(line)
}

// ---------------------------------------------------------------------------
// systemd-creds
// ---------------------------------------------------------------------------

fn systemd_command(user: bool) -> Command {
    let mut c = Command::new("systemd-creds");
    if user {
        c.arg("--user");
    }
    c
}

fn systemd_encrypt(secret: &[u8], path: &Path, user: bool) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut child = systemd_command(user)
        .arg("encrypt")
        .arg(format!("--name={CRED_NAME}"))
        .arg("-")
        .arg(&tmp)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ks(format!("systemd-creds introuvable : {}", e.kind())))?;
    let written = child.stdin.take().map(|mut stdin| stdin.write_all(secret));
    let out = child.wait_with_output().map_err(|e| ks(format!("systemd-creds : {}", e.kind())))?;
    if !matches!(written, Some(Ok(()))) || !out.status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(ks(format!(
            "systemd-creds encrypt a échoué : {}",
            String::from_utf8_lossy(&out.stderr).trim().chars().take(200).collect::<String>()
        )));
    }
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::Io(format!("{} : {}", tmp.display(), e.kind())))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| Error::Io(format!("{} : {}", path.display(), e.kind())))
}

fn systemd_decrypt(path: &Path, user: bool) -> Result<Zeroizing<Vec<u8>>> {
    // Chargé par systemd (`LoadCredentialEncrypted=synco-ai-runtime-keys:<keys.cred>`) : déjà
    // déchiffré dans un ramfs propre au service.
    if let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY") {
        let p = Path::new(&dir).join(CRED_NAME);
        if p.exists() {
            return std::fs::read(&p)
                .map(Zeroizing::new)
                .map_err(|e| ks(format!("identifiant systemd : {}", e.kind())));
        }
    }
    let mut child = systemd_command(user)
        .arg("decrypt")
        .arg(format!("--name={CRED_NAME}"))
        .arg(path)
        .arg("-")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ks(format!("systemd-creds introuvable : {}", e.kind())))?;
    // Lecture dans un tampon effacé de taille fixe (aucune réallocation qui laisserait une copie).
    let mut secret = Zeroizing::new(vec![0u8; SECRET_BUFFER]);
    let mut filled = 0usize;
    if let Some(mut stdout) = child.stdout.take() {
        while let Some(rest) = secret.get_mut(filled..) {
            if rest.is_empty() {
                let _ = child.kill();
                return Err(ks("sortie de systemd-creds trop longue"));
            }
            match stdout.read(rest) {
                Ok(0) => break,
                Ok(n) => filled = filled.saturating_add(n),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(ks(format!("systemd-creds : {}", e.kind()))),
            }
        }
    }
    secret.truncate(filled);
    let out = child.wait_with_output().map_err(|e| ks(format!("systemd-creds : {}", e.kind())))?;
    if !out.status.success() {
        return Err(ks(format!(
            "systemd-creds decrypt a échoué : {}",
            String::from_utf8_lossy(&out.stderr).trim().chars().take(200).collect::<String>()
        )));
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Paramètres réduits : la vitesse d'Argon2id n'est pas l'objet de ces tests.
    const FAST: KdfParams = KdfParams { m_kib: 256, t: 1, p: 1 };

    fn provided(p: &str) -> Backend {
        Backend::Passphrase { source: PassphraseSource::Provided(Zeroizing::new(p.into())), kdf: FAST }
    }

    #[test]
    fn ecriture_atomique_force_0600_sur_un_tmp_existant() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.json");
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, b"vieux").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic(&path, b"neuf").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"neuf");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        // Chemin relatif sans répertoire : le fsync vise « . ».
        assert!(!tmp.exists());
    }

    #[test]
    fn phrase_de_passe_aller_retour() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("etat");
        let created = create(&state, &provided("une phrase assez longue")).unwrap();
        let loaded = load(&state, &provided("une phrase assez longue")).unwrap().unwrap();
        assert_eq!(loaded.fingerprint_hex(), created.fingerprint_hex());
        assert!(load(&state, &provided("mauvaise phrase de passe")).is_err());
        assert!(create(&state, &provided("une phrase assez longue")).is_err(), "pas d'écrasement");
        assert!(reset(&state).unwrap());
        assert!(load(&state, &provided("x")).unwrap().is_none());
    }

    #[test]
    fn fichier_de_phrase_de_passe_controle() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("pp");
        std::fs::write(&file, "une phrase assez longue\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(check_secret_file(&file).is_err(), "lisible par les autres : refusé");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        check_secret_file(&file).unwrap();
        let src = PassphraseSource::File(file);
        assert_eq!(read_passphrase(&src, false).unwrap().as_str(), "une phrase assez longue");
        assert!(check_secret_file(dir.path()).is_err(), "répertoire refusé");
    }

    #[test]
    fn bornes_argon2_a_la_lecture() {
        let doc = seal_with_passphrase(b"secret", "une phrase assez longue", FAST, &mut OsRandom).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&doc).unwrap();
        v["kdf"]["mKib"] = serde_json::Value::from(4u64 * 1024 * 1024);
        assert!(open_with_passphrase(&serde_json::to_vec(&v).unwrap(), "une phrase assez longue").is_err());
    }

    #[test]
    fn phrase_trop_courte_refusee() {
        let dir = tempfile::tempdir().unwrap();
        assert!(create(dir.path(), &provided("court")).is_err());
        assert!(existing(dir.path()) == (None, None));
    }

    #[test]
    fn parametres_lies_a_l_aad() {
        let doc = seal_with_passphrase(b"secret", "une phrase assez longue", FAST, &mut OsRandom).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&doc).unwrap();
        assert_eq!(open_with_passphrase(&doc, "une phrase assez longue").unwrap().as_slice(), b"secret");
        v["kdf"]["t"] = serde_json::Value::from(2);
        let altered = serde_json::to_vec(&v).unwrap();
        assert!(open_with_passphrase(&altered, "une phrase assez longue").is_err());
    }

    /// Clés **jamais** en clair dans le répertoire d'état : on cherche chaque clé privée (brute,
    /// hexadécimale, base64, base64url) dans tous les fichiers.
    #[test]
    fn aucune_cle_privee_en_clair_sur_disque() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("etat");
        let keys = create(&state, &provided("une phrase assez longue")).unwrap();
        let secret = keys.to_secret_bytes();
        let (_, rest) = secret.split_at(4 + 1 + 36);
        let privates: Vec<&[u8]> = rest.chunks(32).collect();
        assert_eq!(privates.len(), 3);
        let mut needles: Vec<Vec<u8>> = Vec::new();
        for p in &privates {
            needles.push(p.to_vec());
            needles.push(synco_e2ee::encoding::hex(p).into_bytes());
            needles.push(synco_e2ee::encoding::hex(p).to_ascii_uppercase().into_bytes());
            needles.push(synco_e2ee::encoding::b64(p).into_bytes());
            needles.push(b64u(p).into_bytes());
            needles.push(p.get(..12).unwrap().to_vec());
        }
        let mut files = 0;
        for entry in std::fs::read_dir(&state).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            files += 1;
            for n in &needles {
                assert!(!bytes.windows(n.len()).any(|w| w == n.as_slice()), "clé privée trouvée en clair");
            }
        }
        assert!(files >= 1);
        // Le test échoue bien sans scellement : le format en clair contient les clés.
        assert!(secret.windows(32).any(|w| w == privates[0]));
    }

    /// systemd-creds : seulement là où il existe (hôte, pas le flatpak de développement).
    /// `host-spawn sh -c 'cd <dépôt> && cargo test -p synco-ai-runtime -- --ignored systemd'`.
    #[test]
    #[ignore = "nécessite systemd-creds (hôte)"]
    fn systemd_creds_aller_retour() {
        let dir = tempfile::tempdir().unwrap();
        let backend = Backend::SystemdCreds { user: true };
        let created = create(dir.path(), &backend).unwrap();
        let loaded = load(dir.path(), &backend).unwrap().unwrap();
        assert_eq!(created.fingerprint_hex(), loaded.fingerprint_hex());
        let on_disk = std::fs::read(dir.path().join(CRED_FILE)).unwrap();
        let secret = created.to_secret_bytes();
        assert!(!on_disk.windows(32).any(|w| secret.windows(32).any(|s| s == w)), "clé en clair dans keys.cred");
    }
}
