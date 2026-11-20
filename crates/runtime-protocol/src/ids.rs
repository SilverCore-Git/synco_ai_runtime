//! Contraintes des identifiants (docs/plan/00-vue-ensemble.md §3.2, 01 §1).
//!
//! Une valeur non conforme est **refusée**, jamais échappée.

pub use synco_e2ee::encoding::{MAX_SAFE_INTEGER, is_valid_id as is_identifier};

/// `runtimeId` : UUID en minuscules `8-4-4-4-12` (01 §1), comme `UUID_PATTERN` de l'API.
#[must_use]
pub fn is_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(b),
        })
}

/// Tire un UUID v4 en minuscules à partir de 16 octets aléatoires.
#[must_use]
pub fn uuid_v4_from_bytes(mut bytes: [u8; 16]) -> String {
    if let Some(b) = bytes.get_mut(6) {
        *b = (*b & 0x0f) | 0x40;
    }
    if let Some(b) = bytes.get_mut(8) {
        *b = (*b & 0x3f) | 0x80;
    }
    let hex = synco_e2ee::encoding::hex(&bytes);
    let mut out = String::with_capacity(36);
    for (i, c) in hex.chars().enumerate() {
        if matches!(i, 8 | 12 | 16 | 20) {
            out.push('-');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid() {
        assert!(is_uuid("7d3f2c1e-8a4b-4c6d-9e0f-1a2b3c4d5e6f"));
        assert!(!is_uuid("7D3F2C1E-8A4B-4C6D-9E0F-1A2B3C4D5E6F"));
        assert!(!is_uuid("7d3f2c1e8a4b4c6d9e0f1a2b3c4d5e6f"));
        assert!(!is_uuid("cm3orgexample0000000000001"));
        let id = uuid_v4_from_bytes([0xff; 16]);
        assert!(is_uuid(&id), "{id}");
        assert_eq!(id.as_bytes()[14], b'4');
    }
}
