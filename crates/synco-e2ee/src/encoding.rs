//! Encodages et contraintes de champs communs (docs/plan/00-vue-ensemble.md §3.1, §3.2).

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

use crate::error::{Error, Result};

/// Plus grand entier accepté dans une chaîne signée : 2⁵³ − 1 (entiers sûrs en JavaScript).
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Base64 standard avec remplissage (famille E2EE existante, `btoa`).
#[must_use]
pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Décodage base64 standard strict (remplissage obligatoire, bits de fin nuls).
pub fn from_b64(text: &str) -> Result<Vec<u8>> {
    STANDARD.decode(text).map_err(|_| Error::InvalidEncoding)
}

/// Base64 URL sans remplissage (nouveaux formats).
#[must_use]
pub fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Décodage base64 URL strict (sans remplissage, forme canonique).
pub fn from_b64u(text: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).map_err(|_| Error::InvalidEncoding)
}

/// Décode exactement `N` octets en base64 URL.
pub fn from_b64u_array<const N: usize>(text: &str) -> Result<[u8; N]> {
    from_b64u(text)?.try_into().map_err(|_| Error::InvalidEncoding)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Hexadécimal minuscule.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            if let Some(c) = HEX.get(usize::from(nibble)) {
                out.push(char::from(*c));
            }
        }
    }
    out
}

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

/// Décode un hexadécimal **minuscule** de longueur paire.
pub fn from_hex(text: &str) -> Result<Vec<u8>> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return Err(Error::InvalidEncoding);
    }
    pairs
        .iter()
        .map(|[hi, lo]| match (hex_value(*hi), hex_value(*lo)) {
            (Some(h), Some(l)) => Ok((h << 4) | l),
            _ => Err(Error::InvalidEncoding),
        })
        .collect()
}

/// Identifiant d'une chaîne signée ou d'une AAD : `^[A-Za-z0-9_-]{1,64}$` (00 §3.2).
#[must_use]
pub fn is_valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Refuse un identifiant non conforme (jamais d'échappement).
pub fn check_id(id: &str) -> Result<()> {
    if is_valid_id(id) { Ok(()) } else { Err(Error::InvalidInput) }
}

/// Refuse un entier au-delà de 2⁵³ − 1.
pub fn check_uint(value: u64) -> Result<()> {
    if value <= MAX_SAFE_INTEGER { Ok(()) } else { Err(Error::InvalidInput) }
}

/// Empreinte de runtime `fprHex` : 64 caractères hexadécimaux minuscules.
pub fn check_fpr_hex(fpr_hex: &str) -> Result<()> {
    if fpr_hex.len() == 64 && from_hex(fpr_hex).is_ok() { Ok(()) } else { Err(Error::InvalidInput) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiants() {
        assert!(is_valid_id("7d3f2c1e-8a4b-4c6d-9e0f-1a2b3c4d5e6f"));
        assert!(is_valid_id("cm3orgexample0000000000001"));
        assert!(is_valid_id("__pending__"));
        for bad in ["", "a|b", "a:b", "../x", "é", &"a".repeat(65)] {
            assert!(!is_valid_id(bad), "{bad}");
        }
    }

    #[test]
    fn hexadecimal() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(from_hex("00abff").unwrap(), vec![0x00, 0xab, 0xff]);
        assert!(from_hex("00ABFF").is_err());
        assert!(from_hex("0").is_err());
    }

    #[test]
    fn base64_strict() {
        assert!(from_b64u("AA").is_ok());
        assert!(from_b64u("AB").is_err(), "bits de fin non nuls");
        assert!(from_b64u("AA==").is_err(), "remplissage refusé en b64u");
        assert!(from_b64("AA").is_err(), "remplissage obligatoire en b64");
    }
}
