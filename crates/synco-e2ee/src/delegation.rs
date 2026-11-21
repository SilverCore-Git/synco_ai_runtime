//! Délégation des clés au runtime (docs/plan/03-delegation.md) : enveloppe de tête `srd1`, mandat
//! signé par l'utilisateur (v1, et v2 avec l'empreinte RSA du propriétaire et le mode, 03 §4.1) et
//! entrées `sre1`.
//!
//! Ordre de vérification côté runtime (03 §9) : mandat ([`verify_mandate`]) → enveloppe de tête
//! ([`open_delegation`]) → entrées ([`open_entry`]). Tout refus est [`Error::DelegationUnusable`]
//! ou [`Error::EntryUnusable`], sans cause (03 §12).

use core::fmt;

use crate::ec::{EcPublicKey, EcSigningKey, EcdhSecret};
use crate::encoding::{b64, b64u, check_fpr_hex, check_id, check_uint, from_b64, from_b64u};
use crate::error::{Error, Result};
use crate::primitives::{self, IV_LENGTH, TAG_LENGTH, sha256};
use crate::rng::RandomSource;
use crate::secret::{KEY_LENGTH, SymmetricKey};

/// Préfixe de l'enveloppe de tête.
pub const WRAP_PREFIX: &str = "srd1";
/// Préfixe d'une entrée.
pub const ENTRY_PREFIX: &str = "sre1";
/// Étiquette (et sel HKDF) de l'enveloppe de tête.
pub const WRAP_LABEL: &str = "synco-rt-delegation-v1";
/// Tolérance d'horloge sur `iat` (03 §4 étape 1).
pub const IAT_SKEW_SECS: u64 = 300;

/// Périmètre d'une délégation. v1 : toujours `org`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Scope {
    /// Toute l'organisation.
    Org,
}

impl Scope {
    /// Valeur de la chaîne signée.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Org => "org",
        }
    }

    /// Lecture ; toute autre valeur est refusée.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "org" => Ok(Self::Org),
            _ => Err(Error::InvalidInput),
        }
    }
}

/// Champs communs d'une délégation, tels qu'enregistrés par l'API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationContext {
    /// Utilisateur qui délègue.
    pub user_id: String,
    /// Organisation.
    pub org_id: String,
    /// Runtime destinataire.
    pub runtime_id: String,
    /// Identifiant de la délégation (UUID v4 tiré par le client).
    pub delegation_id: String,
    /// Périmètre.
    pub scope: Scope,
    /// Émission (secondes Unix).
    pub iat: u64,
    /// Expiration (secondes Unix).
    pub exp: u64,
}

impl DelegationContext {
    /// Valide chaque champ (00 §3.2) et `iat < exp`.
    pub fn validate(&self) -> Result<()> {
        for id in [&self.user_id, &self.org_id, &self.runtime_id, &self.delegation_id] {
            check_id(id)?;
        }
        check_uint(self.iat)?;
        check_uint(self.exp)?;
        if self.iat < self.exp { Ok(()) } else { Err(Error::InvalidInput) }
    }

    /// Contrôles d'horloge du runtime (03 §4 étape 1) : `iat ≤ now + 300`, `now < exp`,
    /// `exp − iat ≤ max_lifetime_secs`.
    pub fn check_time(&self, now: u64, max_lifetime_secs: u64) -> Result<()> {
        let fresh = self.iat <= now.saturating_add(IAT_SKEW_SECS);
        let alive = now < self.exp;
        let bounded = self.exp.checked_sub(self.iat).is_some_and(|d| d <= max_lifetime_secs);
        if fresh && alive && bounded { Ok(()) } else { Err(Error::DelegationUnusable) }
    }

    /// `ctx` de l'enveloppe de tête (03 §3).
    pub fn wrap_context(&self, kex: &EcPublicKey, epk: &EcPublicKey) -> Result<String> {
        self.validate()?;
        Ok(format!(
            "{WRAP_LABEL}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.user_id,
            self.org_id,
            self.runtime_id,
            self.delegation_id,
            self.scope.as_str(),
            self.iat,
            self.exp,
            kex.to_canonical(),
            epk.to_canonical()
        ))
    }

    /// `mandateBytes` (03 §4) ; `wrap_hash` = [`wrap_hash`] de l'enveloppe de tête.
    pub fn mandate_bytes(&self, fpr_hex: &str, wrap_hash: &str) -> Result<String> {
        self.validate()?;
        check_fpr_hex(fpr_hex)?;
        if crate::encoding::from_b64u_array::<32>(wrap_hash).is_err() {
            return Err(Error::InvalidInput);
        }
        Ok(format!(
            "synco-rt-mandate-v1|{}|{}|{}|{}|{}|{}|{}|{fpr_hex}|{wrap_hash}",
            self.user_id,
            self.org_id,
            self.runtime_id,
            self.delegation_id,
            self.scope.as_str(),
            self.iat,
            self.exp
        ))
    }

    /// AAD d'une entrée (03 §5).
    pub fn entry_aad(&self, kind: EntryKind, reference: &str, version: u64) -> Result<String> {
        self.validate()?;
        check_id(reference)?;
        check_uint(version)?;
        if version == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(format!(
            "synco-rt-entry-v1|{}|{}|{}|{}|{}|{reference}|{version}",
            self.delegation_id,
            self.user_id,
            self.org_id,
            self.runtime_id,
            kind.as_str()
        ))
    }
}

/// Clé de délégation `DK` (32 octets propres à la délégation), effacée à la libération.
#[derive(Clone, PartialEq, Eq)]
pub struct DelegationKey(SymmetricKey);

impl fmt::Debug for DelegationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DelegationKey(***)")
    }
}

impl DelegationKey {
    /// Prend possession de 32 octets.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LENGTH]) -> Self {
        Self(SymmetricKey::from_bytes(bytes))
    }

    /// Tire une `DK` aléatoire.
    pub fn generate(rng: &mut impl RandomSource) -> Result<Self> {
        Ok(Self(SymmetricKey::generate(rng)?))
    }

    /// Octets bruts (à ne jamais journaliser).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LENGTH] {
        self.0.as_bytes()
    }
}

fn wrap_kek(shared: &[u8; 32], ctx: &str) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    primitives::hkdf32(shared, WRAP_LABEL.as_bytes(), ctx.as_bytes())
}

/// Produit l'enveloppe de tête `srd1.<b64u(epk)>.<b64u(iv ‖ GCM(KEK, DK))>` vers la `kex` du
/// runtime (côté client ; présent ici pour les vecteurs et les outils).
pub fn seal_delegation(
    ctx: &DelegationContext,
    runtime_kex: &EcPublicKey,
    dk: &DelegationKey,
    rng: &mut impl RandomSource,
) -> Result<String> {
    let eph = EcdhSecret::generate(rng)?;
    let epk = eph.public_key()?;
    let context = ctx.wrap_context(runtime_kex, &epk)?;
    let kek = wrap_kek(&eph.shared_secret(runtime_kex), &context)?;
    let blob = primitives::seal(&kek, context.as_bytes(), dk.as_bytes(), rng)?;
    Ok(format!("{WRAP_PREFIX}.{}.{}", b64u(epk.to_canonical().as_bytes()), b64u(&blob)))
}

/// Ouvre l'enveloppe de tête avec la clé privée `kex` du runtime, en recalculant `ctx` à partir de
/// l'enregistrement de délégation et de **sa propre** `kex` (03 §3).
pub fn open_delegation(ctx: &DelegationContext, kex: &EcdhSecret, wrap: &str) -> Result<DelegationKey> {
    open_delegation_inner(ctx, kex, wrap).ok_or(Error::DelegationUnusable)
}

fn open_delegation_inner(ctx: &DelegationContext, kex: &EcdhSecret, wrap: &str) -> Option<DelegationKey> {
    let mut parts = wrap.split('.');
    let (Some(WRAP_PREFIX), Some(epk_b64u), Some(blob_b64u), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let epk_json = from_b64u(epk_b64u).ok()?;
    let epk = EcPublicKey::from_canonical(core::str::from_utf8(&epk_json).ok()?).ok()?;
    let blob = from_b64u(blob_b64u).ok()?;
    if blob.len() < IV_LENGTH.saturating_add(KEY_LENGTH).saturating_add(TAG_LENGTH) {
        return None;
    }
    let own_kex = kex.public_key().ok()?;
    let context = ctx.wrap_context(&own_kex, &epk).ok()?;
    let kek = wrap_kek(&kex.shared_secret(&epk), &context).ok()?;
    let dk = primitives::open(&kek, context.as_bytes(), &blob)?;
    let arr: [u8; KEY_LENGTH] = dk.as_slice().try_into().ok()?;
    Some(DelegationKey::from_bytes(arr))
}

/// `wrapHash` = `b64u(SHA-256(utf8(wrap)))`, engagé par le mandat.
#[must_use]
pub fn wrap_hash(wrap: &str) -> String {
    b64u(&sha256(wrap.as_bytes()))
}

/// Signe le mandat avec la clé de signature d'identité de l'utilisateur (`b64` P1363).
pub fn sign_mandate(
    user_sign_key: &EcSigningKey,
    ctx: &DelegationContext,
    fpr_hex: &str,
    wrap: &str,
) -> Result<String> {
    let bytes = ctx.mandate_bytes(fpr_hex, &wrap_hash(wrap))?;
    Ok(b64(&user_sign_key.sign(bytes.as_bytes())))
}

/// Vérifie le mandat (03 §4 étape 3) sur l'enveloppe de tête **elle-même** : le hash engagé est
/// recalculé ici à partir de `wrap`, jamais lu d'une valeur servie. C'est la variante à utiliser
/// avant d'ouvrir `wrap` (de préférence via [`accept_delegation`]). `fpr_hex` = empreinte du runtime ;
/// la clé de l'utilisateur doit venir de l'épinglage TOFU (03 §4 étape 2).
pub fn verify_mandate(
    user_sign_key: &EcPublicKey,
    ctx: &DelegationContext,
    fpr_hex: &str,
    wrap: &str,
    signature: &str,
) -> Result<()> {
    verify_mandate_offline_from_wrap_hash(user_sign_key, ctx, fpr_hex, &wrap_hash(wrap), signature)
}

/// Vérification **hors ligne** du mandat à partir d'un `wrapHash` servi (client à jour qui vérifie
/// une enveloppe `rt1`, 03 §10 étape 3 : l'API sert le hash, pas l'enveloppe).
///
/// Ne prouve rien sur une enveloppe de tête particulière : ne **jamais** l'utiliser pour décider
/// d'ouvrir une enveloppe (une API malveillante peut garder le mandat authentique et son hash, et
/// servir une autre enveloppe scellée vers `kex` avec une `DK` qu'elle connaît). Le runtime utilise
/// [`verify_mandate`] ou [`accept_delegation`].
pub fn verify_mandate_offline_from_wrap_hash(
    user_sign_key: &EcPublicKey,
    ctx: &DelegationContext,
    fpr_hex: &str,
    wrap_hash: &str,
    signature: &str,
) -> Result<()> {
    let bytes = ctx.mandate_bytes(fpr_hex, wrap_hash).map_err(|_| Error::DelegationUnusable)?;
    let sig = from_b64(signature).map_err(|_| Error::DelegationUnusable)?;
    if user_sign_key.verify(bytes.as_bytes(), &sig) { Ok(()) } else { Err(Error::DelegationUnusable) }
}

/// Identité et politique du runtime qui reçoit une délégation.
#[derive(Debug)]
pub struct RuntimeSelf<'a> {
    /// Son `runtimeId`.
    pub runtime_id: &'a str,
    /// L'org à laquelle il est appairé.
    pub org_id: &'a str,
    /// Sa propre empreinte `fprHex` (calculée depuis ses clés, jamais reçue).
    pub fpr_hex: &'a str,
    /// Sa clé privée `kex`.
    pub kex: &'a EcdhSecret,
    /// Durée maximale d'une délégation selon sa configuration (09 §1).
    pub max_lifetime_secs: u64,
}

/// Chemin complet côté runtime (03 §4 étapes 1 à 3, puis 03 §3) :
/// 1. `runtimeId` = le sien, `orgId` = son org, `scope` connu, champs valides, horloge
///    (`iat ≤ now + 300`, `now < exp`, `exp − iat ≤ max_lifetime_secs`), `fprHex` = la sienne ;
/// 2. (l'appelant fournit la clé de signature de l'utilisateur issue de son épinglage TOFU) ;
/// 3. mandat vérifié sur le hash de **l'enveloppe effectivement ouverte** ;
///
/// puis ouverture de l'enveloppe de tête. Tout refus : [`Error::DelegationUnusable`].
pub fn accept_delegation(
    me: &RuntimeSelf<'_>,
    now: u64,
    ctx: &DelegationContext,
    user_sign_key: &EcPublicKey,
    wrap: &str,
    mandate_signature: &str,
) -> Result<DelegationKey> {
    let fail = Error::DelegationUnusable;
    ctx.validate().map_err(|_| fail)?;
    if ctx.runtime_id != me.runtime_id || ctx.org_id != me.org_id || ctx.scope != Scope::Org {
        return Err(fail);
    }
    ctx.check_time(now, me.max_lifetime_secs)?;
    verify_mandate(user_sign_key, ctx, me.fpr_hex, wrap, mandate_signature)?;
    open_delegation(ctx, me.kex, wrap)
}

/// Mode signé par un mandat v2 (03 §4.1, 12 §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MandateMode {
    /// Plan d'action (défaut ; tout mandat v1 est lu ainsi).
    Plan,
    /// Mode autonome.
    Auto,
}

impl MandateMode {
    /// Valeur signée.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Auto => "auto",
        }
    }

    /// Lecture stricte : `plan` ou `auto`.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "plan" => Ok(Self::Plan),
            "auto" => Ok(Self::Auto),
            _ => Err(Error::InvalidInput),
        }
    }
}

/// Version des octets signés d'un mandat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MandateVersion {
    /// `synco-rt-mandate-v1` (03 §4), lu comme [`MandateMode::Plan`].
    V1,
    /// `synco-rt-mandate-v2` (03 §4.1).
    V2,
}

/// `ownerRsaSpkiHex` = `hex(SHA-256(SPKI DER))` de la clé RSA d'identité du propriétaire (03 §4.1).
#[must_use]
pub fn owner_rsa_spki_hex(spki_der: &[u8]) -> String {
    crate::encoding::hex(&sha256(spki_der))
}

impl DelegationContext {
    /// `mandateBytes v2` (03 §4.1) : les neuf champs du v1, puis `ownerRsaSpkiHex` (64 caractères
    /// `[0-9a-f]`) et le mode.
    pub fn mandate_bytes_v2(
        &self,
        fpr_hex: &str,
        wrap_hash: &str,
        owner_rsa_spki_hex: &str,
        mode: MandateMode,
    ) -> Result<String> {
        let v1 = self.mandate_bytes(fpr_hex, wrap_hash)?;
        check_fpr_hex(owner_rsa_spki_hex)?;
        let tail = v1.strip_prefix("synco-rt-mandate-v1|").ok_or(Error::InvalidInput)?;
        Ok(format!("synco-rt-mandate-v2|{tail}|{owner_rsa_spki_hex}|{}", mode.as_str()))
    }
}

/// Signe un mandat v2 (seule version écrite par les clients, 03 §4.1).
pub fn sign_mandate_v2(
    user_sign_key: &EcSigningKey,
    ctx: &DelegationContext,
    fpr_hex: &str,
    wrap: &str,
    owner_rsa_spki_hex: &str,
    mode: MandateMode,
) -> Result<String> {
    let bytes = ctx.mandate_bytes_v2(fpr_hex, &wrap_hash(wrap), owner_rsa_spki_hex, mode)?;
    Ok(b64(&user_sign_key.sign(bytes.as_bytes())))
}

/// Champs servis avec la délégation (03 §4.1, tableau « Lecture ») : `mandateVersion` (absent = 1),
/// `mode` et `ownerRsaSpkiHex`. Ils ne valent rien tant que la signature n'est pas vérifiée.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServedMandate<'a> {
    /// `mandateVersion` servi.
    pub version: Option<u64>,
    /// `mode` servi (ignoré pour un v1).
    pub mode: Option<&'a str>,
    /// `ownerRsaSpkiHex` servi (ignoré pour un v1).
    pub owner_rsa_spki_hex: Option<&'a str>,
}

/// Mandat dont la signature a été vérifiée : seule source du mode retenu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMandate {
    /// Version des octets vérifiés.
    pub version: MandateVersion,
    /// Mode signé (`plan` pour un v1 : échec fermé).
    pub mode: MandateMode,
    /// Empreinte RSA signée du propriétaire (v2 seulement), épingle de 12 §10.3 (PC46).
    pub owner_rsa_spki_hex: Option<String>,
}

/// Vérification d'un mandat v1 ou v2 (03 §4.1) sur l'enveloppe de tête **elle-même** (hash recalculé
/// depuis `wrap`). Le mode rendu est celui des octets vérifiés, jamais le champ servi seul.
pub fn verify_mandate_versioned(
    user_sign_key: &EcPublicKey,
    ctx: &DelegationContext,
    fpr_hex: &str,
    wrap: &str,
    signature: &str,
    served: &ServedMandate<'_>,
) -> Result<VerifiedMandate> {
    verify_mandate_versioned_offline_from_wrap_hash(user_sign_key, ctx, fpr_hex, &wrap_hash(wrap), signature, served)
}

/// Variante **hors ligne** de [`verify_mandate_versioned`] à partir d'un `wrapHash` servi (client qui
/// vérifie une enveloppe `rt1`, 12 §10.2). Mêmes réserves que
/// [`verify_mandate_offline_from_wrap_hash`] : ne conditionne jamais l'ouverture d'une enveloppe.
pub fn verify_mandate_versioned_offline_from_wrap_hash(
    user_sign_key: &EcPublicKey,
    ctx: &DelegationContext,
    fpr_hex: &str,
    wrap_hash: &str,
    signature: &str,
    served: &ServedMandate<'_>,
) -> Result<VerifiedMandate> {
    let fail = Error::DelegationUnusable;
    let (bytes, verified) = match served.version {
        None | Some(1) => {
            // Mode et empreinte servis ignorés : une délégation v1 ne devient jamais autonome.
            let bytes = ctx.mandate_bytes(fpr_hex, wrap_hash).map_err(|_| fail)?;
            (bytes, VerifiedMandate { version: MandateVersion::V1, mode: MandateMode::Plan, owner_rsa_spki_hex: None })
        }
        Some(2) => {
            let owner = served.owner_rsa_spki_hex.ok_or(fail)?;
            let mode = MandateMode::parse(served.mode.ok_or(fail)?).map_err(|_| fail)?;
            let bytes = ctx.mandate_bytes_v2(fpr_hex, wrap_hash, owner, mode).map_err(|_| fail)?;
            (bytes, VerifiedMandate { version: MandateVersion::V2, mode, owner_rsa_spki_hex: Some(owner.to_owned()) })
        }
        Some(_) => return Err(fail),
    };
    let sig = from_b64(signature).map_err(|_| fail)?;
    if user_sign_key.verify(bytes.as_bytes(), &sig) { Ok(verified) } else { Err(fail) }
}

/// [`accept_delegation`] pour un mandat v1 ou v2 : mêmes contrôles et même ordre, puis ouverture ;
/// rend aussi le mandat vérifié (mode signé, empreinte RSA du propriétaire).
pub fn accept_delegation_versioned(
    me: &RuntimeSelf<'_>,
    now: u64,
    ctx: &DelegationContext,
    user_sign_key: &EcPublicKey,
    wrap: &str,
    mandate_signature: &str,
    served: &ServedMandate<'_>,
) -> Result<(DelegationKey, VerifiedMandate)> {
    let fail = Error::DelegationUnusable;
    ctx.validate().map_err(|_| fail)?;
    if ctx.runtime_id != me.runtime_id || ctx.org_id != me.org_id || ctx.scope != Scope::Org {
        return Err(fail);
    }
    ctx.check_time(now, me.max_lifetime_secs)?;
    let mandate = verify_mandate_versioned(user_sign_key, ctx, me.fpr_hex, wrap, mandate_signature, served)?;
    Ok((open_delegation(ctx, me.kex, wrap)?, mandate))
}

/// Sort d'une enveloppe `rt1` chez un client à jour (12 §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rt1Verdict {
    /// Mandat v2 `auto` et enveloppe valide.
    Verified,
    /// Enveloppe fausse, mandat illisible, ou mandat v2 `plan`.
    Rejected,
    /// Mandat v1 (hors production, PC32) et enveloppe valide : acceptée avec avertissement.
    TofuWarning,
}

impl Rt1Verdict {
    /// Valeur des vecteurs (`verified`, `rejected`, `tofu_warning`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Rejected => "rejected",
            Self::TofuWarning => "tofu_warning",
        }
    }
}

/// Règle de 12 §10.2 : `mandate` = mandat **vérifié** (`None` s'il est illisible).
#[must_use]
pub fn rt1_verdict(mandate: Option<&VerifiedMandate>, envelope_valid: bool) -> Rt1Verdict {
    match (mandate, envelope_valid) {
        (Some(m), true) => match (m.version, m.mode) {
            (MandateVersion::V2, MandateMode::Auto) => Rt1Verdict::Verified,
            (MandateVersion::V2, MandateMode::Plan) => Rt1Verdict::Rejected,
            (MandateVersion::V1, _) => Rt1Verdict::TofuWarning,
        },
        _ => Rt1Verdict::Rejected,
    }
}

/// Type de clé délégable (03 §2). Toute autre valeur (`dm`, `support`, `ai`, `org`, `account`,
/// `identity`…) est refusée **avant** tout déchiffrement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryKind {
    /// Clé de salon.
    Thread,
    /// Clé d'espace (versionnée).
    Space,
    /// Clé de conversation `CK`.
    Conv,
}

impl EntryKind {
    /// Valeur de l'AAD.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Thread => "thread",
            Self::Space => "space",
            Self::Conv => "conv",
        }
    }

    /// Lecture stricte de la liste fermée.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "thread" => Ok(Self::Thread),
            "space" => Ok(Self::Space),
            "conv" => Ok(Self::Conv),
            _ => Err(Error::EntryUnusable),
        }
    }
}

/// Chiffre une clé de l'org sous `DK` : `sre1.<b64u(iv ‖ GCM(DK, clé))>`.
pub fn seal_entry(
    dk: &DelegationKey,
    ctx: &DelegationContext,
    kind: EntryKind,
    reference: &str,
    version: u64,
    key: &SymmetricKey,
    rng: &mut impl RandomSource,
) -> Result<String> {
    let aad = ctx.entry_aad(kind, reference, version)?;
    let blob = primitives::seal(dk.as_bytes(), aad.as_bytes(), key.as_bytes(), rng)?;
    Ok(format!("{ENTRY_PREFIX}.{}", b64u(&blob)))
}

/// Ouvre une entrée à partir de ses métadonnées en clair `{ kind, ref, version }` : l'AAD est
/// recalculée depuis la délégation (03 §5). Refus : [`Error::EntryUnusable`].
pub fn open_entry(
    dk: &DelegationKey,
    ctx: &DelegationContext,
    kind: &str,
    reference: &str,
    version: u64,
    ciphertext: &str,
) -> Result<SymmetricKey> {
    let kind = EntryKind::parse(kind)?;
    let aad = ctx.entry_aad(kind, reference, version).map_err(|_| Error::EntryUnusable)?;
    let mut parts = ciphertext.split('.');
    let (Some(ENTRY_PREFIX), Some(blob_b64u), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(Error::EntryUnusable);
    };
    let blob = from_b64u(blob_b64u).map_err(|_| Error::EntryUnusable)?;
    let plain = primitives::open(dk.as_bytes(), aad.as_bytes(), &blob).ok_or(Error::EntryUnusable)?;
    SymmetricKey::from_slice(&plain).map_err(|_| Error::EntryUnusable)
}
