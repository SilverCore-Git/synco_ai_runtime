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

## 2026-11-20 — L05 : superviseur du runtime

**Branche** : `syncoai/L05-superviseur` (depuis `feature/syncoai-refonte` à `4e3e1aa`).

**Fait** :

- `crates/runtime-protocol` : tickets `srt1` (02 §5), requêtes signées (04 §2, signature et
  vérificateur à la règle de l'API), flux de notifications (04 §6, forme réelle de l'API), trames du
  WebSocket client (05, désérialisation stricte), pipe superviseur ↔ worker (06 : cadrage, trames de
  clés binaires `Zeroizing`, messages JSON stricts), réponses du canal. Vecteurs de synco_api
  (`tickets-runtime.json`, `internal-requests.json`) copiés sans modification et rejoués.
- `crates/supervisor` (binaire `synco-ai-runtime`) : clés `sig`/`kex`/`csk` générées au premier
  démarrage et scellées (systemd-creds, `--user` possible, ou Argon2id + AES-256-GCM par phrase de
  passe), configuration TOML commentée (`synco-ai-runtime.example.toml`, `--check-config`), commandes
  `pair`, `unpair`, `reset-keys --yes` ; `/v1/identity`, `/v1/challenge` ; enregistrement toutes les
  15 s jusqu'à l'appairage ; flux sortant signé (backoff 1 → 60 s, codes 4xxx) ; délégations ouvertes
  par `accept_delegation` seulement, épinglage TOFU des clés de signature (Q3), clés en mémoire
  cloisonnées par utilisateur et effacées à `exp`, révocation, remplacement, désappairage ;
  WebSocket client (ticket vérifié localement, liste de révocation alimentée par `user.revoked` —
  Q13 — et `conversation.revoked`, dépôt durable avant `queued`, rejeu / snapshot) ; lancement des
  workers derrière `WorkerLauncher` (bail pris avant, `init` → `ready` → clés → `start`, relais
  `signed_request` en liste fermée, débit borné, garde-fou de plantages) ; arrêt propre sur `SIGTERM`.
- `crates/worker` : bouchon de protocole (aucun LLM) ; binaire inactif jusqu'à L06.

**Interface pour L06** (`crates/supervisor/src/launcher.rs`) : implémenter
`WorkerLauncher::spawn(WorkerSpec) -> SpawnedWorker { io, process }` — `io` = pipe d'octets (fd 3 du
worker), `process` = `WorkerProcess { kill, wait, usage (cgroup), pid }` ; `WorkerSpec` porte
`resources` (memory.max/high, cpu.max, pids.max) et `allowed_hosts`. Aucun secret ne passe par le
lanceur. Brancher le lanceur dans `cli.rs` (`Command::Run`) à la place de `InProcessStubLauncher`.

**Dépendances ajoutées** (épinglées, dates crates.io) : axum 0.8.9 (2026-04-14), tokio 1.54.1
(2026-10-21), reqwest 0.13.4 (2026-05-25), tokio-tungstenite/tungstenite 0.29.0 (2026-03-17),
tokio-rustls 0.26.5 (2026-09-04), rustls 0.23.44 (2026-09-07), rustls-platform-verifier 0.7.0
(2026-04-12), ed25519-dalek 3.0.0 (2026-07-06), argon2 0.6.0 (2026-08-27), rustix 1.1.5
(2026-09-16), toml 1.1.6 (2026-09-10), futures-util 0.3.34 (2026-08-11), tracing 0.1.44,
tracing-subscriber 0.3.23 (2026-03-13), tempfile 3.27.0 (dev). Les 200 versions ajoutées au
`Cargo.lock` ont toutes ≥ 7 jours (bumpalo, bytes, cc, mio, rand, rand_pcg, regex-automata,
regex-syntax, smallvec ramenées à une version antérieure).

**Vérifié** : `cargo test --workspace` (dont 3 tests d'intégration contre une API simulée qui vérifie
chaque signature), `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check` ;
test systemd-creds `--user` rejoué sur l'hôte (`host-spawn`). Mutations témoins : signature sur un
autre chemin, org du ticket non vérifiée, propriétaire de l'autorisation non vérifié, clés non
effacées au désappairage, `AUTH` mal formé dans la chaîne signée → tests en échec.

**Écarts avec docs/plan (à reporter)** :
1. 06 §1 : la longueur compte genre + charge ; les plafonds (1 Mio / 64 Kio) portent sur la charge.
2. 06 §3–§4 : messages ajoutés `snapshot_request { requestId }` / `snapshot { requestId, event }`
   (reprise hors tampon, 05 §3 : seul le worker peut produire le `snapshot` chiffré).
3. 06 §3.2 : `limits` porte aussi `maxTokensPerTurn` et `maxOutputTokensPerCall` (09 §2).
4. 06 §4 : `signed_request_response.status = 0` si le superviseur refuse ou si le réseau échoue ;
   `headers` réduit à `content-type`. Débit dépassé → 429 `rt_rate_limited` sans appel.
5. Autorisations connues persistées (`authorizations.json`, données publiques) : sans elles, après
   un redémarrage, un client d'une conversation `idle` serait refusé (`pending` ne liste pas `idle`).
6. 05 : un dépôt de boîte refusé par l'API ferme le WebSocket (`4429`, `4403`, `4404`, `4500`) faute
   d'évènement `error` sans `epoch` ; inactivité de 60 s → fermeture `1000 idle_timeout` ;
   `ready.rev` vaut 0 quand un worker tourne, `mode: reload` si l'API ne répond pas.
7. 02 §5 : `exp < iat` refusé (la référence TS l'admettrait).
8. D10 : endpoints servis en HTTP local derrière un mandataire TLS (pas de TLS natif) ; `api_url`
   doit être une origine sans chemin (chemin signé = chemin envoyé).
9. Mandat vérifié avec la clé courante puis les clés précédentes de la chaîne d'identité.
10. Un élément de boîte peut arriver deux fois au worker (`GET …/inbox` + `inbox` en direct) : L07
    déduplique par `id`.

**Non vérifié (recette manuelle)** : vraie API (`AI_TICKET_*`) et vrai appairage depuis l'app (L10/L11) ;
`wss://` derrière un mandataire avec certificat reconnu ; unité systemd avec
`LoadCredentialEncrypted=` ; saisie de la phrase de passe au terminal ; reconnexion et `4409` avec deux
instances ; arrêt `SIGTERM` avec un vrai worker (L06/L07) ; TPM2 sans `--user`.

### 2026-11-20 — L05, corrections après relecture indépendante

**Corrigé** (un commit par point, chacun avec son test) :

1. Mandat vérifié **uniquement** avec la clé de signature épinglée courante (ou l'aboutissement
   d'une chaîne valide partant d'elle), jamais une clé précédente. Une délégation ouverte avant une
   rotation reste en mémoire jusqu'à `exp` ; après redémarrage elle est `unusable` et le client la
   renouvelle (P11).
2. Relais `signed_request` : corps de requête et de réponse en parties de ≤ 512 Kio (`part`,
   `last`), ≤ 4 requêtes en vol par worker et 8 pour le runtime (`status = 0`, code `relay_busy`),
   pipe jamais fermé sur une trame refusée.
3. Délégation révoquée ou d'un appairage précédent jamais réinstallée : génération d'appairage et
   ensemble des délégations révoquées vérifiés sous le verrou de l'installation, rechargements du
   flux annulés en fin de session.
4. `PR_SET_DUMPABLE=0` et `RLIMIT_CORE=0` avant le chargement des clés ; `mlock` impossible sans
   `unsafe` (documenté : `MemorySwapMax=0` ou swap chiffré) ; unité systemd d'exemple durcie
   (`crates/supervisor/systemd/`) et README du superviseur.
5. Secrets lus sans réallocation (trames de clés, `systemd-creds decrypt`, phrase de passe) ;
   `api_key_env` reste dans l'environnement (retrait = `unsafe` en Rust 2024) : préférer
   `api_key_file`.
6. Au plus 8 WebSocket sans `hello` vérifié par adresse et 256 au total ; `hello` en 5 s ;
   `X-Forwarded-For` jamais lu au-delà de l'entrée la plus à droite.
7. Écoute HTTP limitée à la boucle locale sauf `listen.allow_non_loopback_plain_http` ;
   `--check-config` avertit des incohérences avec `trust_proxy_hops`.
8. Clés remises seulement si la délégation n'est pas expirée ; `hello` du flux d'une autre org →
   flux fermé ; aucun ticket accepté sans relecture réussie des clés depuis 1 h.
9. `authorizations.json` purgé (`user.revoked`, `delegation.revoked`, expiration) et réconcilié à
   chaque ouverture du flux par `GET /conversations/:sessionId`. **Besoin API** : une route
   « autorisations actives de l'org pour ce runtime » éviterait un appel par conversation.
10. `snapshot` annoncé seulement si la demande est partie (sinon `reload`), ≤ 1 Mio (sinon
    `ready reload`) ; sans `resume`, rejeu depuis le début de l'époque.
11. `passphrase_file` : fichier ordinaire, même propriétaire, `0600`/`0400` ; bornes Argon2id
    (≤ 1 Gio, t ≤ 16, p ≤ 8) ; entrée de conversation retirée sur refus.

**Décisions de l'orchestrateur** : pas de TLS natif en v1, mandataire inverse obligatoire (exemples
Caddy et nginx dans `crates/supervisor/README.md`) ; persistance des autorisations acceptée avec la
réconciliation du point 9 ; `snapshot_request` / `snapshot` acceptés.

**Rappels pour L06** : lancer chaque worker par `fork` + `exec`, jamais un `fork` seul d'un processus
tokio qui détient des clés ; vider l'environnement des workers (`env_clear`) ; l'unité systemd
d'exemple n'a ni `RestrictNamespaces=` ni `SystemCallFilter=` (à décider avec le bac à sable),
`Delegate=` sera nécessaire pour les cgroups.

**Écarts à reporter dans docs/plan (liste à jour)** : ceux de l'entrée L05 ci-dessus, plus :
06 §4 relais en parties (`part`, `last`, `error` quand `status = 0` : `relay_refused`,
`relay_busy`, `relay_too_large`, `relay_bad_part`, `relay_network`, `relay_rate_limited`), bornes
4 / 8 en vol ; 05 §1 délai du `hello` 5 s et plafonds de connexions non authentifiées (429) ;
05 §3 ordre `snapshot` / évènements en direct et repli `reload` ; 03 §4 vérification du mandat avec
la seule clé courante (remplace le point 9 de la liste précédente).

## 2026-11-20 — L06 : bac à sable des workers

**Branche** : `syncoai/L06-bac-a-sable` (depuis `feature/syncoai-refonte` à `30f2fbc`).

**Fait** (conception : `docs/plan/10-bac-a-sable.md`) :

- `crates/supervisor/src/sandbox/` : `SandboxLauncher` (implémente `WorkerLauncher`), lancement par
  `fork` + `exec` du binaire du superviseur en deux étapes (`__sandbox-helper`, `__sandbox-worker`),
  environnement vidé, pipe seul (stdin → descripteur 3), espaces de noms user/pid/mount/net/ipc/
  uts/cgroup, racine `tmpfs` vide en lecture seule, capacités retirées, `no_new_privs`, landlock,
  seccomp (fatals + liste blanche, défaut `ENOSYS`), cgroup v2 par worker (`memory.max`,
  `memory.swap.max = 0`, `memory.oom.group`, `pids.max`, `cpu.max`, `cgroup.kill`, compteurs) ;
  mandataire LLM par worker (socket Unix, clé ajoutée par le superviseur, sans redirection) ;
  autotest (`sandbox-check`) ; sonde au démarrage et refus de démarrer, `--insecure-no-sandbox`.
- `unsafe` : un seul bloc (`unshare_unsafe`) dans `sandbox/sys.rs` ; workspace en `deny`, chaque
  autre crate garde `#![forbid(unsafe_code)]`, `tests/unsafe_scope.rs` le vérifie.
- `crates/worker` : `entry::run` (point d'entrée isolé, fd 3) et `llm` (client `hyper` du
  mandataire, pour L07) ; le binaire autonome n'est plus utilisé.
- `WorkerSpec.allowed_hosts` remplacé par `llm: Option<LlmRoute>` ; `WorkerLauncher::
  injects_llm_credentials` : avec le bac à sable, aucune clé LLM ne passe par le pipe.
- Configuration `[sandbox]` (`cgroup_root`, `run_dir`) ; unité systemd : `Delegate=yes`,
  `ProtectControlGroups=private`, `RestrictNamespaces=`, `SystemCallFilter=`.

**Dépendances ajoutées** (épinglées, dates crates.io) : landlock 0.4.7 (2026-07-27), seccompiler
0.5.0 (2025-03-07), enumflags2 / enumflags2_derive 0.7.12 (2025-06-09, transitive de landlock).
Déjà au `Cargo.lock`, désormais directes : libc 0.2.191, hyper 1.12.0, hyper-util 0.1.21,
http-body-util 0.1.5, bytes 1.12.1. Fonctions `rustix` ajoutées : `mount`, `thread`, `system`,
`stdio`, `fs`, `net`.

**Vérifié** : `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo fmt --check` (flatpak) ; sur l'hôte (`host-spawn sh crates/supervisor/tests/sandbox-host.sh`,
noyau 7.2.15) : 8 tests de `tests/sandbox.rs` (tentatives d'évasion, témoin qui survit à l'OOM, à la
boucle de fils et à l'appel fatal d'un autre worker, couches indépendantes, mandataire, coût) et
l'aller-retour complet avec un worker isolé ; `sandbox-check` en scope délégué et dans une unité
utilisateur transitoire avec tout le durcissement de l'unité d'exemple. Mutations : `memory.max` /
`pids.max` non écrits → `sandbox-check` en échec ; couches retirées → évasion constatée.
Coût (`--release`) : 3,9 ms du lancement à `ready`, ≈ 1,3 Mio facturés au cgroup, PSS 4,6 Mio.

**Écarts avec docs/plan (à reporter)** :
1. 09 §2 : `memory.high` non appliqué (sans swap, il bloque le worker au lieu de le laisser être
   tué) ; `worker_memory_high_mib` ignoré.
2. 06 §2–§3.1 (D1) : la trame `llm_credential` n'est plus envoyée ; le mandataire ajoute la clé.
   `net_request` / `net_response` n'existent pas : le réseau passe par le socket du mandataire.
3. 06 §1 : le pipe arrive par stdin de l'assistant puis sur le descripteur 3 du worker ; le worker
   est le binaire du superviseur, pas `synco-ai-runtime-worker`.
4. 06 §6 : l'API n'est jamais jointe directement par le worker (seulement `signed_request`).
5. Workers simultanés : comptage inchangé (L05) ; 2 processus par worker (assistant + worker) dans
   `pids.max`.

**Non vérifié (recette manuelle)** : unité systemd **système** (root) avec `Delegate=yes` et
`ProtectControlGroups=private` ; conteneur Docker/Podman (L09) ; aarch64 ; vrai fournisseur LLM
derrière le mandataire (L07) ; noyau sans landlock ou avec ABI < 6.
