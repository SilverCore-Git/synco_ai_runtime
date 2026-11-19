//! Clés P-256 : JWK, ECDH (coordonnée x, comme WebCrypto `deriveBits(256)`) et ECDSA SHA-256 au
//! format IEEE P1363 (`r ‖ s`, 64 octets), celui que produit et attend WebCrypto.
//!
//! Deux sérialisations JSON coexistent (00 §3.1) :
//! - [`EcPublicKey::to_canonical`] : RFC 7638 `{"crv","kty","x","y"}`, pour les nouveaux formats et
//!   `ecCanonical` (`e2eeV4.ts:473`) ;
//! - [`EcPublicKey::to_legacy_json`] : `{"kty","crv","x","y"}`, ordre de `canonicalJwk`
//!   (`e2eeV4.ts:322`) conservé par l'enveloppe et le certificat d'appareil.

use core::fmt;

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey as EcdsaSigningKey, VerifyingKey};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::encoding::{b64u, from_b64u_array};
use crate::error::{Error, Result};
use crate::rng::RandomSource;

/// Longueur d'une signature ECDSA P-256 au format P1363.
pub const SIGNATURE_LENGTH: usize = 64;

/// Clé publique P-256 validée (point sur la courbe, différent de l'infini).
#[derive(Clone, PartialEq, Eq)]
pub struct EcPublicKey {
    key: p256::PublicKey,
    x: [u8; 32],
    y: [u8; 32],
}

impl fmt::Debug for EcPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EcPublicKey").field(&self.to_canonical()).finish()
    }
}

impl EcPublicKey {
    /// Depuis les coordonnées affines (32 octets chacune).
    pub fn from_coordinates(x: [u8; 32], y: [u8; 32]) -> Result<Self> {
        let mut sec1 = [0u8; 65];
        let (tag, rest) = sec1.split_at_mut(1);
        let (xs, ys) = rest.split_at_mut(32);
        tag.copy_from_slice(&[0x04]);
        xs.copy_from_slice(&x);
        ys.copy_from_slice(&y);
        let key = p256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| Error::InvalidKey)?;
        Ok(Self { key, x, y })
    }

    fn from_inner(key: p256::PublicKey) -> Result<Self> {
        let sec1 = key.to_sec1_bytes();
        match sec1.split_first() {
            Some((0x04, rest)) if rest.len() == 64 => {
                let (xs, ys) = rest.split_at(32);
                let x: [u8; 32] = xs.try_into().map_err(|_| Error::InvalidKey)?;
                let y: [u8; 32] = ys.try_into().map_err(|_| Error::InvalidKey)?;
                Ok(Self { key, x, y })
            }
            _ => Err(Error::InvalidKey),
        }
    }

    /// Lecture tolérante d'une JWK (champs dans n'importe quel ordre, champs en plus ignorés, comme
    /// `canonicalJwk` / `canonicalEcJwk` côté TS) ; `x` et `y` doivent être des `b64u` de 32 octets
    /// d'un point de la courbe.
    pub fn from_jwk_value(jwk: &Value) -> Result<Self> {
        let obj = jwk.as_object().ok_or(Error::InvalidKey)?;
        let field = |name: &str| obj.get(name).and_then(Value::as_str).ok_or(Error::InvalidKey);
        if field("kty")? != "EC" || field("crv")? != "P-256" {
            return Err(Error::InvalidKey);
        }
        let x = from_b64u_array::<32>(field("x")?).map_err(|_| Error::InvalidKey)?;
        let y = from_b64u_array::<32>(field("y")?).map_err(|_| Error::InvalidKey)?;
        Self::from_coordinates(x, y)
    }

    /// Lecture tolérante d'une JWK sérialisée (cf. [`Self::from_jwk_value`]).
    pub fn from_jwk(jwk: &str) -> Result<Self> {
        let value: Value = serde_json::from_str(jwk).map_err(|_| Error::InvalidKey)?;
        Self::from_jwk_value(&value)
    }

    /// Lecture stricte : la chaîne doit être **exactement** la forme canonique RFC 7638 (`JWK-EC`,
    /// 00 §3.1). Sert aux valeurs transportées telles quelles dans un format (clé éphémère `epk`).
    pub fn from_canonical(jwk: &str) -> Result<Self> {
        let key = Self::from_jwk(jwk)?;
        if key.to_canonical() == jwk { Ok(key) } else { Err(Error::InvalidKey) }
    }

    /// JSON canonique RFC 7638 : `{"crv":"P-256","kty":"EC","x":"…","y":"…"}`.
    #[must_use]
    pub fn to_canonical(&self) -> String {
        format!(r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#, b64u(&self.x), b64u(&self.y))
    }

    /// JSON dans l'ordre historique de `canonicalJwk` (`e2eeV4.ts:322`) : `{"kty","crv","x","y"}`.
    #[must_use]
    pub fn to_legacy_json(&self) -> String {
        format!(r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}"#, b64u(&self.x), b64u(&self.y))
    }

    /// Point SEC1 non compressé (65 octets).
    #[must_use]
    pub fn to_sec1(&self) -> Vec<u8> {
        self.key.to_sec1_bytes().into_vec()
    }

    /// Vérifie une signature ECDSA P-256 / SHA-256 au format P1363 (64 octets). Toute autre forme
    /// (DER notamment) est refusée. Les signatures « S haut » de WebCrypto sont acceptées.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != SIGNATURE_LENGTH {
            return false;
        }
        let Ok(sig) = Signature::from_slice(signature) else {
            return false;
        };
        VerifyingKey::from(&self.key).verify(message, &sig).is_ok()
    }
}

/// Lit **exactement** 32 octets en scalaire P-256 valide (non nul, inférieur à l'ordre).
/// (`SecretKey::from_slice` accepte des tranches plus courtes : refusées ici.)
fn secret_from_scalar(bytes: &[u8]) -> Result<p256::SecretKey> {
    if bytes.len() != 32 {
        return Err(Error::InvalidKey);
    }
    p256::SecretKey::from_slice(bytes).map_err(|_| Error::InvalidKey)
}

/// Tire un scalaire P-256 valide ; rejette les rares valeurs hors intervalle.
fn random_secret(rng: &mut impl RandomSource) -> Result<p256::SecretKey> {
    for _ in 0..16 {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rng.fill(bytes.as_mut())?;
        if let Ok(secret) = p256::SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
    Err(Error::RandomUnavailable)
}

/// Clé privée ECDH P-256 (clé `kex` du runtime, clé d'appareil, clé éphémère).
#[derive(Clone)]
pub struct EcdhSecret {
    secret: p256::SecretKey,
}

impl fmt::Debug for EcdhSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EcdhSecret(***)")
    }
}

impl EcdhSecret {
    /// Depuis un scalaire de 32 octets (big-endian).
    pub fn from_scalar(bytes: &[u8]) -> Result<Self> {
        Ok(Self { secret: secret_from_scalar(bytes)? })
    }

    /// Nouvelle paire aléatoire.
    pub fn generate(rng: &mut impl RandomSource) -> Result<Self> {
        Ok(Self { secret: random_secret(rng)? })
    }

    /// Scalaire (à sceller avant tout stockage, jamais journalisé).
    #[must_use]
    pub fn to_scalar(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes().into())
    }

    /// Clé publique associée.
    pub fn public_key(&self) -> Result<EcPublicKey> {
        EcPublicKey::from_inner(self.secret.public_key())
    }

    /// Secret partagé : coordonnée x du point commun (32 octets), comme `deriveBits(…, 256)`.
    #[must_use]
    pub fn shared_secret(&self, peer: &EcPublicKey) -> Zeroizing<[u8; 32]> {
        let shared = p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer.key.as_affine());
        Zeroizing::new((*shared.raw_secret_bytes()).into())
    }
}

/// Clé privée de signature ECDSA P-256 / SHA-256 (clé de signature d'identité, `csk` du runtime).
#[derive(Clone)]
pub struct EcSigningKey {
    key: EcdsaSigningKey,
}

impl fmt::Debug for EcSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EcSigningKey(***)")
    }
}

impl EcSigningKey {
    /// Depuis un scalaire de 32 octets (big-endian).
    pub fn from_scalar(bytes: &[u8]) -> Result<Self> {
        let secret = secret_from_scalar(bytes)?;
        Ok(Self { key: EcdsaSigningKey::from(secret) })
    }

    /// Nouvelle paire aléatoire.
    pub fn generate(rng: &mut impl RandomSource) -> Result<Self> {
        Ok(Self { key: EcdsaSigningKey::from(random_secret(rng)?) })
    }

    /// Scalaire (à sceller avant tout stockage, jamais journalisé).
    #[must_use]
    pub fn to_scalar(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.key.to_bytes().into())
    }

    /// Clé publique associée.
    pub fn public_key(&self) -> Result<EcPublicKey> {
        EcPublicKey::from_inner(p256::PublicKey::from(self.key.verifying_key()))
    }

    /// Signature P1363 (64 octets). Nonce déterministe (RFC 6979) : aucune source d'aléa requise.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LENGTH] {
        let sig: Signature = self.key.sign(message);
        sig.to_bytes().into()
    }
}
