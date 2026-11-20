//! Limiteurs de débit en mémoire (09 §2, §4).

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Seau à jetons : `rate` jetons par seconde, au plus `burst`.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// Seau plein.
    #[must_use]
    pub fn new(rate_per_sec: u32, burst: u32) -> Self {
        let burst = f64::from(burst.max(1));
        Self { rate: f64::from(rate_per_sec.max(1)), burst, tokens: burst, last: Instant::now() }
    }

    /// Prend un jeton si possible.
    pub fn take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Fenêtre fixe : au plus `max` évènements par fenêtre de `window`.
#[derive(Debug, Clone)]
pub struct Window {
    max: u32,
    window: Duration,
    start: Option<Instant>,
    count: u32,
}

impl Window {
    /// Nouvelle fenêtre.
    #[must_use]
    pub fn new(max: u32, window: Duration) -> Self {
        Self { max, window, start: None, count: 0 }
    }

    /// Compte un évènement ; `false` au-delà du plafond.
    pub fn hit(&mut self, now: Instant) -> bool {
        if self.start.is_none_or(|start| now.saturating_duration_since(start) >= self.window) {
            self.start = Some(now);
            self.count = 0;
        }
        self.count = self.count.saturating_add(1);
        self.count <= self.max
    }
}

/// Fenêtres par clé (adresse IP…), bornées en nombre.
#[derive(Debug)]
pub struct KeyedWindows {
    max: u32,
    window: Duration,
    capacity: usize,
    map: HashMap<String, Window>,
}

impl KeyedWindows {
    /// `max` évènements par `window` et par clé ; au plus `capacity` clés suivies.
    #[must_use]
    pub fn new(max: u32, window: Duration, capacity: usize) -> Self {
        Self { max, window, capacity, map: HashMap::new() }
    }

    /// Compte un évènement pour `key`.
    pub fn hit(&mut self, key: &str, now: Instant) -> bool {
        if self.map.len() >= self.capacity && !self.map.contains_key(key) {
            let window = self.window;
            self.map.retain(|_, w| w.start.is_some_and(|start| now.saturating_duration_since(start) < window));
            if self.map.len() >= self.capacity {
                // Table pleine de clés actives : refus (pas d'éviction qui remettrait un compteur à zéro).
                return false;
            }
        }
        self.map.entry(key.to_owned()).or_insert_with(|| Window::new(self.max, self.window)).hit(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seau() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(20, 3);
        assert!(b.take(t0) && b.take(t0) && b.take(t0));
        assert!(!b.take(t0));
        assert!(b.take(t0 + Duration::from_millis(60)));
    }

    #[test]
    fn fenetres() {
        let t0 = Instant::now();
        let mut w = KeyedWindows::new(2, Duration::from_secs(60), 2);
        assert!(w.hit("a", t0) && w.hit("a", t0));
        assert!(!w.hit("a", t0));
        assert!(w.hit("b", t0));
        assert!(!w.hit("c", t0), "table pleine");
        assert!(w.hit("a", t0 + Duration::from_secs(60)));
    }
}
