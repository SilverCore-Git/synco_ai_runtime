//! Appareil E2EE v4 : enveloppe d'AK vers la clé ECDH d'un appareil et certificat d'appareil
//! (`e2eeV4.ts:149-185`, `:423-457`).
//!
//! Ces formats gardent l'ordre JSON historique `{"kty","crv","x","y"}` de `canonicalJwk`
//! (docs/plan/00-vue-ensemble.md §3.1, piège L01). L'ouverture d'une enveloppe sert aux tests de
//! compatibilité : le runtime n'est pas un appareil et ne reçoit jamais AK.

use crate::account::AccountKey;
use crate::ec::{EcPublicKey, EcSigningKey, EcdhSecret};
use crate::encoding::{b64, from_b64};
use crate::error::{Error, Result};
use crate::primitives;
use zeroize::Zeroizing;

fn envelope_aad(user_id: &str, device_id: &str) -> String {
    format!("synco-e4-device-envelope|{user_id}|{device_id}")
}

/// `deviceEnvelopeKey` : HKDF(ECDH, sel `synco-e4-device-v1`, info avec les deux clés publiques).
fn envelope_key(
    shared: &[u8; 32],
    user_id: &str,
    device_id: &str,
    device_public: &EcPublicKey,
    ephemeral_public: &EcPublicKey,
) -> Result<Zeroizing<[u8; 32]>> {
    let info = format!(
        "synco-e4-device-envelope|{user_id}|{device_id}|{}|{}",
        device_public.to_legacy_json(),
        ephemeral_public.to_legacy_json()
    );
    primitives::hkdf32(shared, b"synco-e4-device-v1", info.as_bytes())
}

/// Ouvre l'enveloppe d'AK d'un appareil (`openDeviceEnvelope`) avec sa clé privée ECDH.
/// Toute erreur donne [`Error::EnvelopeUnusable`].
pub fn open_device_envelope(
    device_secret: &EcdhSecret,
    envelope: &str,
    user_id: &str,
    device_id: &str,
) -> Result<AccountKey> {
    let mut parts = envelope.split('.');
    let (Some(eph_b64), Some(blob_b64), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(Error::EnvelopeUnusable);
    };
    let eph_json = from_b64(eph_b64).map_err(|_| Error::EnvelopeUnusable)?;
    let eph_json = core::str::from_utf8(&eph_json).map_err(|_| Error::EnvelopeUnusable)?;
    let ephemeral = EcPublicKey::from_jwk(eph_json).map_err(|_| Error::EnvelopeUnusable)?;
    let device_public = device_secret.public_key().map_err(|_| Error::EnvelopeUnusable)?;
    let shared = device_secret.shared_secret(&ephemeral);
    let key = envelope_key(&shared, user_id, device_id, &device_public, &ephemeral)?;
    let blob = from_b64(blob_b64).map_err(|_| Error::EnvelopeUnusable)?;
    let ak =
        primitives::open(&key, envelope_aad(user_id, device_id).as_bytes(), &blob).ok_or(Error::EnvelopeUnusable)?;
    AccountKey::from_slice(&ak).map_err(|_| Error::EnvelopeUnusable)
}

/// Enveloppe AK vers la clé publique d'un appareil (`createDeviceEnvelope`).
///
/// Réservé aux vecteurs de compatibilité (fonctionnalité `legacy-seal`) : le runtime ne scelle
/// jamais AK.
#[cfg(feature = "legacy-seal")]
pub fn seal_device_envelope(
    device_public: &EcPublicKey,
    ak: &AccountKey,
    user_id: &str,
    device_id: &str,
    rng: &mut impl crate::RandomSource,
) -> Result<String> {
    let eph = EcdhSecret::generate(rng)?;
    let eph_public = eph.public_key()?;
    let shared = eph.shared_secret(device_public);
    let key = envelope_key(&shared, user_id, device_id, device_public, &eph_public)?;
    let blob = primitives::seal(&key, envelope_aad(user_id, device_id).as_bytes(), ak.as_bytes(), rng)?;
    Ok(format!("{}.{}", b64(eph_public.to_legacy_json().as_bytes()), b64(&blob)))
}

/// Octets signés d'un certificat d'appareil (`deviceCertBytes`).
#[must_use]
pub fn device_cert_bytes(user_id: &str, device_id: &str, platform: &str, device_public: &EcPublicKey) -> String {
    format!("synco-e4-device-cert|{user_id}|{device_id}|{platform}|{}", device_public.to_legacy_json())
}

/// Signe un certificat d'appareil avec la clé de signature d'identité (`b64` P1363).
#[must_use]
pub fn sign_device_certificate(
    identity_sign_key: &EcSigningKey,
    user_id: &str,
    device_id: &str,
    platform: &str,
    device_public: &EcPublicKey,
) -> String {
    b64(&identity_sign_key.sign(device_cert_bytes(user_id, device_id, platform, device_public).as_bytes()))
}

/// Vérifie un certificat d'appareil avec la clé de signature d'identité **épinglée**.
pub fn verify_device_certificate(
    identity_sign_public: &EcPublicKey,
    certificate: &str,
    user_id: &str,
    device_id: &str,
    platform: &str,
    device_public: &EcPublicKey,
) -> Result<()> {
    let sig = from_b64(certificate).map_err(|_| Error::BadSignature)?;
    let bytes = device_cert_bytes(user_id, device_id, platform, device_public);
    if identity_sign_public.verify(bytes.as_bytes(), &sig) { Ok(()) } else { Err(Error::BadSignature) }
}
