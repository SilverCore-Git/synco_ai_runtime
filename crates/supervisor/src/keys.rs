//! Clés du runtime (docs/plan/01 §1) : `sig` (Ed25519, canal interne), `kex` (ECDH P-256,
//! délégations), `csk` (ECDSA P-256, défi et enveloppes `rt1`), et `runtimeId`.
//!
//! Le superviseur est le **seul** détenteur de ces clés privées (mesure 7) ; elles ne sont écrites
//! sur disque que scellées ([`crate::seal`], mesure 8).

use core::fmt;

use ed25519_dalek::SigningKey;
use runtime_protocol::ids::{is_uuid, uuid_v4_from_bytes};
use synco_e2ee::ec::{EcSigningKey, EcdhSecret};
use synco_e2ee::runtime_cert::{self, RuntimePublicKeys};
use synco_e2ee::{OsRandom, RandomSource};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Étiquette du format binaire des clés privées (avant scellement).
const SECRET_MAGIC: &[u8; 4] = b"SRK1";

/// Les trois paires de clés et l'identifiant du runtime.
pub struct RuntimeKeys {
    runtime_id: String,
    sig: SigningKey,
    kex: EcdhSecret,
    csk: EcSigningKey,
    public: RuntimePublicKeys,
    fpr: [u8; 32],
    fpr_hex: String,
}

impl fmt::Debug for RuntimeKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeKeys")
            .field("runtime_id", &self.runtime_id)
            .field("fpr", &self.fpr_hex)
            .finish_non_exhaustive()
    }
}

impl RuntimeKeys {
    /// Premier démarrage : tire `runtimeId` et les trois paires.
    pub fn generate(rng: &mut impl RandomSource) -> Result<Self> {
        let mut id = [0u8; 16];
        rng.fill(&mut id)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill(seed.as_mut())?;
        Self::assemble(
            uuid_v4_from_bytes(id),
            SigningKey::from_bytes(&seed),
            EcdhSecret::generate(rng)?,
            EcSigningKey::generate(rng)?,
        )
    }

    fn assemble(runtime_id: String, sig: SigningKey, kex: EcdhSecret, csk: EcSigningKey) -> Result<Self> {
        if !is_uuid(&runtime_id) {
            return Err(Error::KeyStore("runtimeId invalide".into()));
        }
        let public = RuntimePublicKeys::new(sig.verifying_key().to_bytes(), kex.public_key()?, csk.public_key()?);
        let fpr = runtime_cert::fingerprint(&runtime_id, &public)?;
        let fpr_hex = synco_e2ee::encoding::hex(&fpr);
        Ok(Self { runtime_id, sig, kex, csk, public, fpr, fpr_hex })
    }

    /// Format binaire des clés privées, à sceller immédiatement :
    /// `"SRK1" ‖ len(runtimeId) (u8) ‖ runtimeId ‖ graine sig (32) ‖ scalaire kex (32) ‖ scalaire csk (32)`.
    #[must_use]
    pub fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(140));
        out.extend_from_slice(SECRET_MAGIC);
        // `runtimeId` est un UUID (36 octets) : tient dans un u8.
        out.push(u8::try_from(self.runtime_id.len()).unwrap_or(0));
        out.extend_from_slice(self.runtime_id.as_bytes());
        out.extend_from_slice(Zeroizing::new(self.sig.to_bytes()).as_ref());
        out.extend_from_slice(self.kex.to_scalar().as_ref());
        out.extend_from_slice(self.csk.to_scalar().as_ref());
        out
    }

    /// Relit le format de [`Self::to_secret_bytes`].
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        let bad = || Error::KeyStore("clés déscellées illisibles".into());
        let rest = bytes.strip_prefix(SECRET_MAGIC.as_slice()).ok_or_else(bad)?;
        let (len, rest) = rest.split_first().ok_or_else(bad)?;
        let (id, rest) = rest.split_at_checked(usize::from(*len)).ok_or_else(bad)?;
        let (seed, rest) = rest.split_at_checked(32).ok_or_else(bad)?;
        let (kex, csk) = rest.split_at_checked(32).ok_or_else(bad)?;
        if csk.len() != 32 {
            return Err(bad());
        }
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(seed.try_into().map_err(|_| bad())?);
        let runtime_id = core::str::from_utf8(id).map_err(|_| bad())?.to_owned();
        Self::assemble(
            runtime_id,
            SigningKey::from_bytes(&seed),
            EcdhSecret::from_scalar(kex).map_err(|_| bad())?,
            EcSigningKey::from_scalar(csk).map_err(|_| bad())?,
        )
    }

    /// `runtimeId`.
    #[must_use]
    pub fn runtime_id(&self) -> &str {
        &self.runtime_id
    }

    /// Clé Ed25519 `sig` (signature des requêtes internes).
    #[must_use]
    pub const fn sig(&self) -> &SigningKey {
        &self.sig
    }

    /// Clé ECDH `kex` (ouverture des délégations).
    #[must_use]
    pub const fn kex(&self) -> &EcdhSecret {
        &self.kex
    }

    /// Clé ECDSA `csk` (défi, enveloppes `rt1`).
    #[must_use]
    pub const fn csk(&self) -> &EcSigningKey {
        &self.csk
    }

    /// Clés publiques.
    #[must_use]
    pub const fn public(&self) -> &RuntimePublicKeys {
        &self.public
    }

    /// Empreinte `fprHex` (01 §2.1).
    #[must_use]
    pub fn fingerprint_hex(&self) -> &str {
        &self.fpr_hex
    }

    /// Empreinte groupée par 4 en majuscules (affichage).
    #[must_use]
    pub fn fingerprint_display(&self) -> String {
        runtime_cert::display_fingerprint(&self.fpr_hex).unwrap_or_default()
    }

    /// Code d'appairage (01 §2.2).
    #[must_use]
    pub fn pairing_code(&self) -> String {
        runtime_cert::pairing_code(&self.fpr)
    }

    /// Fiche publique `GET /v1/identity` (01 §4).
    #[must_use]
    pub fn identity_json(&self, url: &str, org_id: Option<&str>) -> serde_json::Value {
        let jwk = |k: &synco_e2ee::ec::EcPublicKey| {
            serde_json::from_str::<serde_json::Value>(&k.to_canonical()).unwrap_or(serde_json::Value::Null)
        };
        serde_json::json!({
            "v": 1,
            "runtimeId": self.runtime_id,
            "url": url,
            "keys": { "sig": self.public.sig_b64u(), "kex": jwk(&self.public.kex), "csk": jwk(&self.public.csk) },
            "fingerprint": self.fpr_hex,
            "orgId": org_id,
            "software": { "name": "synco-ai-runtime", "version": env!("CARGO_PKG_VERSION") },
        })
    }
}

/// Clés tirées avec le générateur du système.
pub fn generate() -> Result<RuntimeKeys> {
    RuntimeKeys::generate(&mut OsRandom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aller_retour_secret() {
        let k = generate().unwrap();
        let bytes = k.to_secret_bytes();
        let back = RuntimeKeys::from_secret_bytes(&bytes).unwrap();
        assert_eq!(back.runtime_id(), k.runtime_id());
        assert_eq!(back.fingerprint_hex(), k.fingerprint_hex());
        assert!(RuntimeKeys::from_secret_bytes(&bytes[..bytes.len() - 1]).is_err());
        assert!(!format!("{k:?}").contains("sig"), "Debug sans clé privée");
        assert_eq!(k.pairing_code().len(), 34);
        let id = k.identity_json("https://runtime.example.com", None);
        assert_eq!(id["orgId"], serde_json::Value::Null);
        assert_eq!(id["fingerprint"], k.fingerprint_hex());
    }
}
