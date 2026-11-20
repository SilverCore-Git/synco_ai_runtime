//! Horodatage ISO 8601 (UTC, millisecondes) sans dépendance.

use std::time::{SystemTime, UNIX_EPOCH};

/// Date civile depuis un nombre de jours depuis 1970-01-01 (algorithme de H. Hinnant).
#[allow(clippy::arithmetic_side_effects, reason = "jours d'une date réelle : aucun dépassement possible")]
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, u32::try_from(month).unwrap_or(1), u32::try_from(day).unwrap_or(1))
}

/// `AAAA-MM-JJTHH:MM:SS.mmmZ` à partir de millisecondes Unix.
#[must_use]
#[allow(clippy::arithmetic_side_effects, reason = "bornes : millisecondes d'une date réelle, divisions par constantes")]
pub fn iso8601(ms: u64) -> String {
    let secs = i64::try_from(ms / 1_000).unwrap_or(0);
    let millis = ms % 1_000;
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z", rem / 3_600, (rem % 3_600) / 60, rem % 60)
}

/// Maintenant, en ISO 8601.
#[must_use]
pub fn now_iso8601() -> String {
    let ms = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));
    iso8601(ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(1_795_000_400_123), "2026-11-18T11:13:20.123Z");
        assert_eq!(iso8601(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }
}
