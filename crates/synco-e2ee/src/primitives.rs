//! AES-256-GCM « iv ‖ chiffré ‖ tag », HKDF-SHA256, HMAC-SHA256 et SHA-256.

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::rng::RandomSource;

/// Longueur de l'IV AES-GCM.
pub const IV_LENGTH: usize = 12;
/// Longueur du tag AES-GCM.
pub const TAG_LENGTH: usize = 16;

/// SHA-256.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// HKDF-SHA256 avec une sortie de 32 octets.
pub fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut okm = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, okm.as_mut()).map_err(|_| Error::InvalidInput)?;
    Ok(okm)
}

/// HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).map_err(|_| Error::InvalidKey)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

/// Vérifie un HMAC-SHA256 en temps constant.
#[must_use]
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let Ok(mut mac) = <Hmac<Sha256>>::new_from_slice(key) else {
        return false;
    };
    mac.update(data);
    mac.verify_slice(tag).is_ok()
}

/// Chiffre avec un IV donné : `iv ‖ chiffré ‖ tag`.
pub fn seal_with_iv(key: &[u8; 32], iv: &[u8; IV_LENGTH], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidKey)?;
    let nonce = Nonce::try_from(&iv[..]).map_err(|_| Error::InvalidInput)?;
    let ct = cipher.encrypt(&nonce, Payload { msg: plain, aad }).map_err(|_| Error::InvalidInput)?;
    let mut out = Vec::with_capacity(IV_LENGTH.saturating_add(ct.len()));
    out.extend_from_slice(iv);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Chiffre avec un IV tiré de `rng` : `iv ‖ chiffré ‖ tag`.
pub fn seal(key: &[u8; 32], aad: &[u8], plain: &[u8], rng: &mut impl RandomSource) -> Result<Vec<u8>> {
    let mut iv = [0u8; IV_LENGTH];
    rng.fill(&mut iv)?;
    seal_with_iv(key, &iv, aad, plain)
}

/// Ouvre `iv ‖ chiffré ‖ tag`. `None` si trop court ou si le tag est invalide.
#[must_use]
pub fn open(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if blob.len() < IV_LENGTH.saturating_add(TAG_LENGTH) {
        return None;
    }
    let (iv, ct) = blob.split_at_checked(IV_LENGTH)?;
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let nonce = Nonce::try_from(iv).ok()?;
    cipher.decrypt(&nonce, Payload { msg: ct, aad }).ok().map(Zeroizing::new)
}
