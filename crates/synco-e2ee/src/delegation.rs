//! Délégation des clés au runtime (docs/plan/03-delegation.md) : enveloppe de tête `srd1`, mandat
//! signé par l'utilisateur et entrées `sre1`.
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
