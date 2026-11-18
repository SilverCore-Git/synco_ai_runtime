//! Identité du runtime (docs/plan/01-appairage-et-certificat.md) : empreinte, code d'appairage,
//! URL canonique, certificat signé par un admin et défi de possession.

use serde_json::{Map, Value};

use crate::ec::{EcPublicKey, EcSigningKey, EcdhSecret};
use crate::encoding::{b64, b64u, check_fpr_hex, check_id, check_uint, from_b64, from_b64u, from_b64u_array, hex};
use crate::error::{Error, Result};
use crate::primitives::{self, sha256};

// ---------------------------------------------------------------------------
// Clés publiques et empreinte (01 §1, §2.1)
// ---------------------------------------------------------------------------

/// Clés publiques du runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePublicKeys {
    sig: [u8; 32],
    /// Clé ECDH `kex` (reçoit les délégations).
    pub kex: EcPublicKey,
    /// Clé ECDSA `csk` (défi, enveloppes `rt1`).
    pub csk: EcPublicKey,
}

impl RuntimePublicKeys {
    /// `sig` : 32 octets bruts de la clé publique Ed25519.
    #[must_use]
    pub const fn new(sig: [u8; 32], kex: EcPublicKey, csk: EcPublicKey) -> Self {
        Self { sig, kex, csk }
    }

    /// `sig` en `b64u` (32 octets).
    pub fn from_parts(sig_b64u: &str, kex: EcPublicKey, csk: EcPublicKey) -> Result<Self> {
        Ok(Self { sig: from_b64u_array::<32>(sig_b64u).map_err(|_| Error::InvalidKey)?, kex, csk })
    }

    /// Clé publique Ed25519 `sig` brute.
    #[must_use]
    pub const fn sig(&self) -> &[u8; 32] {
        &self.sig
    }

    /// `sig` en `b64u`.
    #[must_use]
    pub fn sig_b64u(&self) -> String {
        b64u(&self.sig)
    }
}

/// `fprInput = "synco-rt-fpr-v1|" runtimeId "|" sig "|" kex "|" csk`.
pub fn fingerprint_input(runtime_id: &str, keys: &RuntimePublicKeys) -> Result<String> {
    check_id(runtime_id)?;
    Ok(format!(
        "synco-rt-fpr-v1|{runtime_id}|{}|{}|{}",
        keys.sig_b64u(),
        keys.kex.to_canonical(),
        keys.csk.to_canonical()
    ))
}

/// Empreinte : SHA-256 de [`fingerprint_input`].
pub fn fingerprint(runtime_id: &str, keys: &RuntimePublicKeys) -> Result<[u8; 32]> {
    Ok(sha256(fingerprint_input(runtime_id, keys)?.as_bytes()))
}

/// `fprHex` (64 caractères minuscules).
pub fn fingerprint_hex(runtime_id: &str, keys: &RuntimePublicKeys) -> Result<String> {
    Ok(hex(&fingerprint(runtime_id, keys)?))
}

/// Affichage : majuscules, groupes de 4 séparés par une espace (`computeKeyFingerprint`).
pub fn display_fingerprint(fpr_hex: &str) -> Result<String> {
    check_fpr_hex(fpr_hex)?;
    let upper = fpr_hex.to_ascii_uppercase();
    let groups: Vec<&str> = upper.as_bytes().chunks(4).filter_map(|c| core::str::from_utf8(c).ok()).collect();
    Ok(groups.join(" "))
}

// ---------------------------------------------------------------------------
// Code d'appairage (01 §2.2) : format de `formatLinkSecret` / `parseLinkSecret`
// ---------------------------------------------------------------------------

const B32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const PAIR_BODY_CHARS: usize = 26;
const PAIR_CHECK_CHARS: usize = 2;
const PAIR_HEAD_BYTES: usize = 16;

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut value: u32 = 0;
    let mut bits: u32 = 0;
    let mut push = |index: u32| {
        if let Some(c) = usize::try_from(index & 31).ok().and_then(|i| B32.get(i)) {
            out.push(char::from(*c));
        }
    };
    for b in bytes {
        value = (value << 8) | u32::from(*b);
        bits = bits.wrapping_add(8);
        while bits >= 5 {
            bits = bits.wrapping_sub(5);
            push(value >> bits);
        }
        value &= (1u32 << bits).wrapping_sub(1);
    }
    if bits > 0 {
        push(value << 5u32.wrapping_sub(bits));
    }
    out
}

fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut value: u32 = 0;
    let mut bits: u32 = 0;
    for ch in text.bytes() {
        let idx = B32.iter().position(|c| *c == ch)?;
        value = (value << 5) | u32::try_from(idx).ok()?;
        bits = bits.wrapping_add(5);
        if bits >= 8 {
            bits = bits.wrapping_sub(8);
            out.push(u8::try_from((value >> bits) & 0xff).ok()?);
        }
        value &= (1u32 << bits).wrapping_sub(1);
    }
    Some(out)
}

fn pair_checksum(head: &[u8]) -> String {
    base32_encode(sha256(head).get(..3).unwrap_or_default()).chars().take(PAIR_CHECK_CHARS).collect()
}

/// Code d'appairage : 128 premiers bits de l'empreinte, base32 Crockford + 2 caractères de
/// contrôle, 7 groupes de 4 séparés par `-`.
#[must_use]
pub fn pairing_code(fpr: &[u8; 32]) -> String {
    let head = fpr.get(..PAIR_HEAD_BYTES).unwrap_or_default();
    let mut text: String = base32_encode(head).chars().take(PAIR_BODY_CHARS).collect();
    text.push_str(&pair_checksum(head));
    let groups: Vec<String> = text.as_bytes().chunks(4).map(|c| c.iter().map(|b| char::from(*b)).collect()).collect();
    groups.join("-")
}

/// Lit un code saisi (casse, espaces, tirets, `O→0`, `I/L→1` tolérés) et vérifie la somme de
/// contrôle. Renvoie les 16 octets engagés. Erreur : [`Error::PairCodeInvalid`].
pub fn parse_pairing_code(input: &str) -> Result<[u8; PAIR_HEAD_BYTES]> {
    let text: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_uppercase)
        .map(|c| match c {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect();
    if text.chars().count() != PAIR_BODY_CHARS.saturating_add(PAIR_CHECK_CHARS) || !text.is_ascii() {
        return Err(Error::PairCodeInvalid);
    }
    let (body, check) = text.split_at_checked(PAIR_BODY_CHARS).ok_or(Error::PairCodeInvalid)?;
    let decoded = base32_decode(body).ok_or(Error::PairCodeInvalid)?;
    let head: [u8; PAIR_HEAD_BYTES] =
        decoded.get(..PAIR_HEAD_BYTES).and_then(|h| h.try_into().ok()).ok_or(Error::PairCodeInvalid)?;
    if pair_checksum(&head) != check {
        return Err(Error::PairCodeInvalid);
    }
    Ok(head)
}

/// Compare un code saisi à l'empreinte calculée : [`Error::PairCodeInvalid`] si illisible,
/// [`Error::PairCodeMismatch`] s'il désigne une autre empreinte.
pub fn check_pairing_code(input: &str, fpr: &[u8; 32]) -> Result<()> {
    let head = parse_pairing_code(input)?;
    if fpr.get(..PAIR_HEAD_BYTES) == Some(&head[..]) { Ok(()) } else { Err(Error::PairCodeMismatch) }
}

// ---------------------------------------------------------------------------
// URL canonique (01 §3)
// ---------------------------------------------------------------------------

/// Longueur maximale d'une URL canonique.
pub const MAX_URL_LENGTH: usize = 255;

fn is_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '/')
}

fn is_host_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// Canonise l'URL d'un runtime : `https` seulement (sauf `http://localhost:<port>` et
/// `http://127.0.0.1:<port>` si `allow_dev_http`), sans identifiants, requête ni fragment, hôte en
/// minuscules, port 443 omis, chemin sans `/` final et limité à `[A-Za-z0-9-._~/]`, ≤ 255
/// caractères. Erreur : [`Error::UrlInvalid`].
pub fn canonical_runtime_url(input: &str, allow_dev_http: bool) -> Result<String> {
    let err = Error::UrlInvalid;
    if input.len() > 2048 || input.contains(['?', '#', '@', '\\']) || input.chars().any(char::is_whitespace) {
        return Err(err);
    }
    let (scheme, rest) = input.split_once("://").ok_or(err)?;
    let scheme = scheme.to_ascii_lowercase();
    let (authority, path) = match rest.find('/') {
        Some(i) => rest.split_at_checked(i).ok_or(err)?,
        None => (rest, ""),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(err);
            }
            let port: u16 = p.parse().map_err(|_| err)?;
            if port == 0 {
                return Err(err);
            }
            (h, Some(port))
        }
        None => (authority, None),
    };
    let host = host.to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 || !host.split('.').all(is_host_label) {
        return Err(err);
    }
    let port = match (scheme.as_str(), port) {
        ("https", Some(443) | None) => None,
        ("https", Some(p)) => Some(p),
        ("http", Some(p)) if allow_dev_http && (host == "localhost" || host == "127.0.0.1") => Some(p),
        _ => return Err(err),
    };
    let path = path.strip_suffix('/').unwrap_or(path);
    if !path.chars().all(is_path_char) || path.ends_with('/') || path.contains("//") {
        return Err(err);
    }
    let url = match port {
        Some(p) => format!("{scheme}://{host}:{p}{path}"),
        None => format!("{scheme}://{host}{path}"),
    };
    if url.len() > MAX_URL_LENGTH {
        return Err(err);
    }
    Ok(url)
}

fn check_canonical_url(url: &str) -> Result<()> {
    let canonical = canonical_runtime_url(url, false).or_else(|_| canonical_runtime_url(url, true))?;
    if canonical == url { Ok(()) } else { Err(Error::UrlInvalid) }
}

// ---------------------------------------------------------------------------
// Certificat (01 §6)
// ---------------------------------------------------------------------------

/// Contenu signé d'un certificat de runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCertificate {
    /// Organisation.
    pub org_id: String,
    /// Runtime certifié.
    pub runtime_id: String,
    /// URL canonique (01 §3).
    pub url: String,
    /// Clés publiques certifiées.
    pub keys: RuntimePublicKeys,
    /// Admin signataire.
    pub admin_id: String,
    /// Émission (secondes Unix).
    pub issued_at: u64,
    /// Numéro de certification (≥ 1).
    pub serial: u64,
}

/// Certificat tel que stocké et servi par l'API, avec sa signature `b64`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRuntimeCertificate {
    /// Contenu signé.
    pub certificate: RuntimeCertificate,
    /// Signature ECDSA P1363 `b64` de l'admin.
    pub signature: String,
}

impl RuntimeCertificate {
    /// Contrôle de forme (00 §3.2) → [`Error::CertInvalid`].
    pub fn validate(&self) -> Result<()> {
        let ok = check_id(&self.org_id).is_ok()
            && check_id(&self.runtime_id).is_ok()
            && check_id(&self.admin_id).is_ok()
            && check_canonical_url(&self.url).is_ok()
            && check_uint(self.issued_at).is_ok()
            && check_uint(self.serial).is_ok()
            && self.serial >= 1;
        if ok { Ok(()) } else { Err(Error::CertInvalid) }
    }

    /// `certBytes` (01 §6.1).
    pub fn cert_bytes(&self) -> Result<String> {
        self.validate()?;
        Ok(format!(
            "synco-rt-cert-v1|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.org_id,
            self.runtime_id,
            self.url,
            self.keys.sig_b64u(),
            self.keys.kex.to_canonical(),
            self.keys.csk.to_canonical(),
            self.admin_id,
            self.issued_at,
            self.serial
        ))
    }

    /// Signe avec la clé de signature d'identité de l'admin (`b64` P1363).
    pub fn sign(&self, admin_sign_key: &EcSigningKey) -> Result<String> {
        Ok(b64(&admin_sign_key.sign(self.cert_bytes()?.as_bytes())))
    }

    /// Vérifie la signature avec une clé de l'admin (01 §6.3 étape 3) → [`Error::CertBadSignature`].
    pub fn verify(&self, admin_sign_public: &EcPublicKey, signature: &str) -> Result<()> {
        let bytes = self.cert_bytes()?;
        let sig = from_b64(signature).map_err(|_| Error::CertBadSignature)?;
        if admin_sign_public.verify(bytes.as_bytes(), &sig) { Ok(()) } else { Err(Error::CertBadSignature) }
    }

    /// Empreinte `fprHex` des clés certifiées.
    pub fn fingerprint_hex(&self) -> Result<String> {
        fingerprint_hex(&self.runtime_id, &self.keys)
    }
}

fn get_str<'a>(obj: &'a Map<String, Value>, name: &str) -> Result<&'a str> {
    obj.get(name).and_then(Value::as_str).ok_or(Error::CertInvalid)
}

fn get_u64(obj: &Map<String, Value>, name: &str) -> Result<u64> {
    obj.get(name).and_then(Value::as_u64).ok_or(Error::CertInvalid)
}

impl SignedRuntimeCertificate {
    /// Lit la forme JSON de 01 §6.2 (`v` = 1, champs exacts, aucun champ inconnu).
    pub fn from_json(json: &str) -> Result<Self> {
        let value: Value = serde_json::from_str(json).map_err(|_| Error::CertInvalid)?;
        let obj = value.as_object().ok_or(Error::CertInvalid)?;
        const FIELDS: [&str; 9] =
            ["v", "orgId", "runtimeId", "url", "keys", "adminId", "issuedAt", "serial", "signature"];
        if obj.len() != FIELDS.len() || obj.keys().any(|k| !FIELDS.contains(&k.as_str())) || get_u64(obj, "v")? != 1 {
            return Err(Error::CertInvalid);
        }
        let keys = obj.get("keys").and_then(Value::as_object).ok_or(Error::CertInvalid)?;
        if keys.len() != 3 {
            return Err(Error::CertInvalid);
        }
        let ec = |name: &str| {
            keys.get(name)
                .ok_or(Error::CertInvalid)
                .and_then(|v| EcPublicKey::from_jwk_value(v).map_err(|_| Error::CertInvalid))
        };
        let keys = RuntimePublicKeys::from_parts(get_str(keys, "sig")?, ec("kex")?, ec("csk")?)
            .map_err(|_| Error::CertInvalid)?;
        let certificate = RuntimeCertificate {
            org_id: get_str(obj, "orgId")?.to_owned(),
            runtime_id: get_str(obj, "runtimeId")?.to_owned(),
            url: get_str(obj, "url")?.to_owned(),
            keys,
            admin_id: get_str(obj, "adminId")?.to_owned(),
            issued_at: get_u64(obj, "issuedAt")?,
            serial: get_u64(obj, "serial")?,
        };
        certificate.validate()?;
        let signature = get_str(obj, "signature")?.to_owned();
        Ok(Self { certificate, signature })
    }
}

// ---------------------------------------------------------------------------
// Défi de possession (01 §5)
// ---------------------------------------------------------------------------

/// Étiquette (et sel HKDF) du défi.
pub const CHALLENGE_LABEL: &str = "synco-rt-challenge-v1";

/// Raison du défi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengePurpose {
    /// Appairage par un admin.
    Pair,
    /// Avant une délégation.
    Delegate,
}

impl ChallengePurpose {
    /// Valeur du transcript.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pair => "pair",
            Self::Delegate => "delegate",
        }
    }

    /// Lecture stricte.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "pair" => Ok(Self::Pair),
            "delegate" => Ok(Self::Delegate),
            _ => Err(Error::ChallengeInvalid),
        }
    }
}

/// Requête de défi (corps de `POST <url>/v1/challenge`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeRequest {
    /// Raison.
    pub purpose: ChallengePurpose,
    /// Organisation de l'appelant (non vérifiée : lie seulement la réponse à son contexte).
    pub org_id: String,
    /// Utilisateur appelant (idem).
    pub user_id: String,
    /// 32 octets aléatoires du client.
    pub nonce: [u8; 32],
    /// Clé ECDH éphémère du client.
    pub client_eph: EcPublicKey,
}

/// Réponse du runtime : `mac` (preuve de `kex_priv`) et `sig` (preuve de `csk_priv`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeResponse {
    /// HMAC-SHA256(K_ch, transcript).
    pub mac: [u8; 32],
    /// ECDSA P1363 de `csk` sur le transcript.
    pub sig: [u8; 64],
}

impl ChallengeResponse {
    /// `mac` en `b64u`.
    #[must_use]
    pub fn mac_b64u(&self) -> String {
        b64u(&self.mac)
    }

    /// `sig` en `b64u`.
    #[must_use]
    pub fn sig_b64u(&self) -> String {
        b64u(&self.sig)
    }
}

impl ChallengeRequest {
    /// Lit le corps JSON (`v` = 1, champs exacts) → [`Error::ChallengeInvalid`].
    pub fn from_json(json: &str) -> Result<Self> {
        let err = Error::ChallengeInvalid;
        let value: Value = serde_json::from_str(json).map_err(|_| err)?;
        let obj = value.as_object().ok_or(err)?;
        const FIELDS: [&str; 6] = ["v", "purpose", "orgId", "userId", "nonce", "clientEph"];
        if obj.len() != FIELDS.len() || obj.keys().any(|k| !FIELDS.contains(&k.as_str())) {
            return Err(err);
        }
        if obj.get("v").and_then(Value::as_u64) != Some(1) {
            return Err(err);
        }
        let s = |name: &str| obj.get(name).and_then(Value::as_str).ok_or(err);
        let request = Self {
            purpose: ChallengePurpose::parse(s("purpose")?)?,
            org_id: s("orgId")?.to_owned(),
            user_id: s("userId")?.to_owned(),
            nonce: from_b64u_array::<32>(s("nonce")?).map_err(|_| err)?,
            client_eph: obj
                .get("clientEph")
                .ok_or(err)
                .and_then(|v| EcPublicKey::from_jwk_value(v).map_err(|_| err))?,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<()> {
        if check_id(&self.org_id).is_ok() && check_id(&self.user_id).is_ok() {
            Ok(())
        } else {
            Err(Error::ChallengeInvalid)
        }
    }

    /// `transcript` (01 §5).
    pub fn transcript(&self, runtime_id: &str, fpr_hex: &str) -> Result<String> {
        self.validate()?;
        if check_id(runtime_id).is_err() || check_fpr_hex(fpr_hex).is_err() {
            return Err(Error::ChallengeInvalid);
        }
        Ok(format!(
            "{CHALLENGE_LABEL}|{}|{runtime_id}|{}|{}|{}|{}|{fpr_hex}",
            self.purpose.as_str(),
            self.org_id,
            self.user_id,
            b64u(&self.nonce),
            self.client_eph.to_canonical()
        ))
    }
}

fn challenge_key(shared: &[u8; 32], transcript: &str) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    primitives::hkdf32(shared, CHALLENGE_LABEL.as_bytes(), transcript.as_bytes())
}

/// Côté runtime : calcule la réponse avec ses clés privées `kex` et `csk`.
pub fn respond_challenge(
    request: &ChallengeRequest,
    runtime_id: &str,
    fpr_hex: &str,
    kex: &EcdhSecret,
    csk: &EcSigningKey,
) -> Result<ChallengeResponse> {
    let transcript = request.transcript(runtime_id, fpr_hex)?;
    let k_ch = challenge_key(&kex.shared_secret(&request.client_eph), &transcript)?;
    let mac = primitives::hmac_sha256(k_ch.as_ref(), transcript.as_bytes())?;
    Ok(ChallengeResponse { mac, sig: csk.sign(transcript.as_bytes()) })
}

/// Côté client : vérifie `mac` (avec sa clé éphémère et la `kex` certifiée) **et** `sig` (avec la
/// `csk` certifiée). `fpr_hex` est l'empreinte que le client a calculée lui-même.
pub fn verify_challenge_response(
    request: &ChallengeRequest,
    runtime_id: &str,
    fpr_hex: &str,
    client_eph_secret: &EcdhSecret,
    keys: &RuntimePublicKeys,
    mac_b64u: &str,
    sig_b64u: &str,
) -> Result<()> {
    let fail = Error::ChallengeFailed;
    let transcript = request.transcript(runtime_id, fpr_hex).map_err(|_| fail)?;
    let k_ch = challenge_key(&client_eph_secret.shared_secret(&keys.kex), &transcript).map_err(|_| fail)?;
    let mac = from_b64u(mac_b64u).map_err(|_| fail)?;
    let sig = from_b64u(sig_b64u).map_err(|_| fail)?;
    let mac_ok = primitives::hmac_sha256_verify(k_ch.as_ref(), transcript.as_bytes(), &mac);
    let sig_ok = keys.csk.verify(transcript.as_bytes(), &sig);
    if mac_ok && sig_ok { Ok(()) } else { Err(fail) }
}
