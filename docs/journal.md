# Journal du dépôt synco_ai_runtime

Entrées les plus récentes en bas. Chaque lot de la refonte Synco AI y note ce qu'il a fait, vérifié,
et ce qui reste.

## 2026-11-18 — L00 : spécification figée des protocoles et formats

**Branche** : `syncoai/L00-specification` (depuis `feature/syncoai-refonte`).

**Fait** : spécification complète dans `docs/plan/` :

- `00-vue-ensemble.md` : architecture, glossaire, conventions d'encodage, rattachement des invariants
  de sécurité aux lots, décisions ouvertes D1, D2, D3, D5, D7, D10 avec leurs options et leur impact,
  questions Q1–Q10 pour la porte A ;
- `01` appairage et certificat ; `02` tickets `srt1`/`sgt1` ; `03` délégation (mandat signé,
  enveloppe de tête, entrées, clé de conversation `CK`, clés créées par le runtime `rt1`) ;
  `04` canal interne (signature Ed25519, autorisation de session, liste fermée des routes, flux de
  notifications) ; `05` WebSocket client ↔ runtime ; `06` pipe superviseur ↔ worker ;
  `07` modèle Prisma ; `08` machine à états ; `09` limites (D4, D6) ;
- `vectors/README.md` : vecteurs à produire par L01 et L02 ;
- `exemples/` : script `node:crypto` indépendant et sa sortie, qui calculent un exemple de chaque
  format (non normatif).

**Vérifié** : le script d'exemples s'exécute (`bun docs/plan/exemples/exemples.mjs`) ; les
signatures ECDSA (certificat, défi, mandat, `rt1`) se vérifient, les deux côtés du défi ECDH
obtiennent le même secret ; une seconde exécution redonne exactement les parties déterministes
(Ed25519, HKDF, HMAC, AES-GCM) ; les valeurs citées dans les documents sont celles du fichier.
Affirmations sur l'existant vérifiées dans le code (citations `fichier:ligne` dans les documents).

**Non vérifié** : aucun code de production ; les formats seront éprouvés par les vecteurs de L01/L02.

**Suite** : porte A (décisions D1–D7, D10 et questions Q1–Q10), puis L01, L02, L03.

## 2026-11-19 — L01 : crate `synco-e2ee` et vecteurs croisés

**Branche** : `syncoai/L01-synco-e2ee` (depuis `feature/syncoai-refonte`).

**Fait** :

- workspace Cargo racine (toolchain 1.98.1 épinglée, `clippy.toml` et `rustfmt.toml` repris de
  synco_cdn, `Cargo.lock` commité, toutes les versions verrouillées publiées depuis ≥ 7 jours) ;
- `crates/synco-e2ee` : crate pure (sans I/O, async ni état global, aléa injecté), `publish = false`,
  `license-file` vers la `LICENSE` du dépôt. Modules `account`, `identity` (dont le portage de
  `identityChainPath`), `device`, `keys` (FC4 et `rt1`), `session` (`gcm1:`, séparateur `:`),
  `delegation` (`srd1`, mandat, `sre1`), `runtime_cert` (empreinte, code d'appairage, URL
  canonique, certificat, défi). Secrets effacés et masqués, erreurs typées à code machine stable,
  lints « zéro panique » de synco_cdn. Scellement d'AK seulement derrière `legacy-seal` ;
- vecteurs TS → Rust (`tests/vectors/*.json`, 7 fichiers) produits par le code réel de synco_app
  (`scripts/e2ee-vectors/generate.ts`) et rejoués par `tests/vectors.rs` ; sens Rust → TS par
  `examples/emit_ts_vectors.rs`, ouvert par `synco_app/scripts/e2ee-vectors/from-rust.test.ts` ;
- README de la crate (import par dépendance git, exemples compilés en doctests).

**Vérifié** : `cargo test --all-features` (3 unitaires, 12 allers-retours/refus, 8 suites de
vecteurs, 2 doctests) et `cargo test` ; `cargo clippy --all-targets [--all-features] -- -D warnings` ;
`cargo fmt --check`. Le générateur contrôle que le code TS reproduit les exemples de
`docs/plan/exemples/` (empreinte, code, `mac`, KEK, `srd1`, `sre1`, `gcm1`). La crate reproduit à
l'octet près l'enveloppe `srd1`, les entrées, les champs `gcm1` et l'enveloppe d'appareil du TS.
Mutations témoins (AAD avec `|`, ordre JWK historique changé) : les vecteurs échouent.

**Non vérifié** : aucun usage réel (runtime L05/L07, client L10) ; les signatures ECDSA ne sont pas
reproductibles (WebCrypto non déterministe), seulement vérifiées.

**Suite** : L05 (superviseur : mandat, enveloppe, entrées, défi), L07 (champs `gcm1`, `rt1`), L10
(client : fonctions TS `runtimeCert.ts`/`runtimeDelegation.ts`). Tickets `srt1`/`sgt1` et signature
des requêtes internes : L02 (`crates/runtime-protocol`, hors de cette crate).

### 2026-11-19 — L01, corrections après revue cryptographique

`zeroize` activé sur aes-gcm/hmac/sha2 ; `verify_mandate` vérifie le mandat sur le wrap ouvert
(scénario « mandat authentique + enveloppe forgée par l'API » testé), variante
`verify_mandate_offline_from_wrap_hash` réservée au contrôle `rt1`, nouvelle `accept_delegation`
(03 §4 étapes 1–3 puis §3) ; `UrlPolicy` explicite pour l'URL du certificat ; URL canonique unique
(segments `.`/`..`, hôtes numériques ou `0x…` refusés sauf IPv4 décimal pointé canonique) ; cas
négatifs renforcés (kind hors liste déchiffrable mais refusé, rt1, scope) ; `seal_with_iv` interne.
Remarques consignées au README : malléabilité ECDSA, `legacy-seal` additive (contrôle CI, L09).
