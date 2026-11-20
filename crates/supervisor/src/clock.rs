//! Horloge (secondes Unix, docs/plan/00 §3.3).

use std::time::{SystemTime, UNIX_EPOCH};

/// Secondes Unix courantes (0 si l'horloge est avant 1970).
#[must_use]
pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}
