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

### 2026-11-20 — L06, corrections après relecture indépendante

**Corrigé** (un commit par point, chacun avec son test qui échoue sans lui) :

1. **B1** (`c141d17`) : l'URL et la clé d'un fournisseur LLM viennent de la seule configuration du
   runtime, cherchées avec le même identifiant (`base_url` obligatoire sauf `gateway`) ;
   `gatewayUrl` de la politique ne sert qu'à `gateway` (sans clé), `https` vers un nom public,
   résolution filtrée (`PublicOnlyResolver`) ; fournisseur non configuré → pas de worker, `failed`
   `provider_error`, bail rendu. Test : `integration.rs` `fournisseur_non_configure_refuse` (mutation
   vers l'ancien repli : échec).
2. **I2** (`682048c`) : mandataire limité à `POST /chat/completions` (`/v1/chat/completions` pour la
   passerelle) et `GET /models`, sans chaîne de requête.
3. **I1** (`7e1e23e`) : 4 connexions par socket, place prise avant la lecture, corps ≤ 8 Mio lu en
   30 s, tampons 16 Mio par worker et 64 Mio pour le runtime. Tests `tests/proxy.rs` (sans borne :
   blocage, puis échec).
4. **I3** (`e00d4fa`) : quotas D6 par le mandataire (appels et tokens par tour, tokens de la vie du
   worker, débit par worker et du runtime, tokens du runtime par heure, durée d'un appel), décompte
   par `usage` ou estimation bornée.
5. **M1** (`026ce55`) : sans `memory.swap.max`, refus de démarrer tant qu'un swap est actif.
6. **M4** (`61bb201`, `99e7168`) : aucun reste si le lancement échoue.
7. `worker_memory_high_mib` : avertissement de `--check-config` (`66230d4`).
8. **M3** (`bce19af`) et **M2** (`f979991`, `aa61ae4`) : `forbid(unsafe_code)` sur le binaire du
   worker ; contrôle de `unsafe` insensible à la mise en forme et racines de crate vérifiées.
   Racines restantes sans `forbid` propre (couvertes par `unsafe_code = "deny"` du workspace et le
   balayage) : `crates/synco-e2ee/examples/*.rs` et les fichiers `tests/*.rs`.
9. **M5** (`207a626`) : descripteur hérité sans `O_CLOEXEC` → `inherited_fd`.

**Vérifié** : `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo fmt --check`, check-secrets ; hôte : `host-spawn sh crates/supervisor/tests/sandbox-host.sh`
(10/10 + aller-retour isolé). Aucune version nouvelle au `Cargo.lock` (http-body-util devient
dépendance directe du superviseur, version déjà présente).

**Écart à reporter** : code d'erreur dédié `provider_not_configured` absent de la liste de l'API
(08 §6, `CONVERSATION_ERROR_CODES`) ; `provider_error` utilisé en attendant.

## 2026-11-20 — L07 : worker et boucle d'agent

**Branche** : `syncoai/L07-worker-agent` (depuis `feature/syncoai-refonte` à `46a5f77`).

**Fait** (`crates/worker`, plus une extension minimale du pipe dans `runtime-protocol` et le
superviseur) :

- `agent` : boucle d'agent durable qui remplace le bouchon dans `entry::run` (le bouchon reste pour
  `InProcessStubLauncher` des tests du superviseur). Lecture de la conversation, du manifeste
  (`GET …/tools`, source unique) et de la boîte (paginée) ; boîte **dédupliquée par `id`** (API +
  WebSocket) ; messages pris en compte à l'étape suivante ; `confirm` / `answer` / `upload` ;
  annulation (flux interrompu, texte déjà vu gardé, appel en attente `rejected`) ; D5 (`auto` /
  `ask` / `deny`, défaut `ask` pour un outil mutant, `auto` sinon ; un outil `deny` n'est même pas
  proposé au modèle) ; `awaiting_user` ; `awaiting_key` (`need_key` au superviseur, 2 s d'attente,
  puis `awaitingKey`, reprise : l'appel reste `accepted` et est relancé) ; **écriture anticipée
  `executing`** avant tout outil mutant ; **reprise** : outil mutant `executing` jamais relancé
  (`unknown_outcome` avec le texte de 08 §5, `events: tool_unknown_outcome` + `code` = nom de
  l'outil, puis le modèle est rappelé), lecture relancée, `lease_lost` écrit par le worker suivant
  (conversation trouvée `running`) ; plafonds D6 ; 3 nouveaux essais (1 s, 4 s, 16 s) ; bail
  renouvelé toutes les 20 s (bail perdu → plus aucune écriture) ; `snapshot` ; `shutdown` (état
  `running` enregistré, reprise par le worker suivant) ; push `AI_*` des transitions écrites par le
  worker ; métriques sans contenu (tokens, coût estimé en µ€ depuis `pricing`, latences p50/max,
  durée du tour, outils, erreurs) en fin de tour, en fin de worker et toutes les 10 s pendant un flux.
- `transcript` : `StoredMessage[]` en clair en mémoire, chiffré champ par champ sous `CK` à
  l'écriture (03 §6.3), lecture tolérante (clair ancien, champ illisible remplacé, champs inconnus
  conservés) ; le message de l'utilisateur garde son chiffré d'origine.
- `events` : trames 05 §5 chiffrées (`ws:text|thinking:<epoch>:<seq>`, arguments et résultats avec
  l'AAD des champs persistés, `error:<e>:<s>`, `snapshot:<e>:<s>`).
- `link` / `api` : liaison au superviseur (tâches lectrice/rédactrice, réassemblage des réponses en
  parties, contrôle) ; toutes les requêtes par `signed_request`, `x-synco-auth` toujours.
- `provider` : **interface des adaptateurs LLM** (ci-dessous) et adaptateur compatible OpenAI
  (`openai`, `gateway` avec ticket `sgt1` obtenu par `POST /tickets/llm` et réutilisé 4 min,
  `custom`) ; `think` = `ThinkTagSplitter` (avec `flush`).
- `tools` : manifeste, décision D5, outils `server` (`POST …/tools/:name/execute { leaseEpoch, args }`,
  `409 lease_conflict` → arrêt), `create_thread` E2EE, `search_messages` en **repli lexical**, refus
  explicite `tool_unavailable_in_runtime` pour `create_file`, `create_folder`, documentation.
- `create_thread` : clé tirée, scellée RSA-OAEP-SHA256 pour les destinataires
  (`GET /e2ee/members/keys`), `POST /e2ee/threads` sans `commitment`, puis **`created_key`** (voir
  écart 1), `POST /e2ee/threads/:id/key-envelope`, `POST /delegations/:d/entries`. `voice` → `vocal`.
- Superviseur : trame `0x02` d'un worker admise **seulement** pour une clé de salon créée (une entrée,
  ajout, `thread`, version 1), au plus 32 par worker ; le superviseur calcule l'engagement, signe
  `rt1` avec `csk`, chiffre l'entrée sous `DK` du propriétaire et répond `created_key` ; il
  n'installe pas la clé dans son coffre (elle y entre par `delegation.entries_added`).

**Interface LLM (pour L07b)** — `crates/worker/src/provider/mod.rs` :

```rust
pub trait LlmAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn build(&self, req: &ChatRequest) -> Result<HttpCall, LlmError>;      // aucune clé
    fn decoder(&self) -> Box<dyn StreamDecoder>;                             // réponse 2xx
    fn classify_error(&self, status: u16, retry_after_secs: Option<u64>, body: &[u8]) -> LlmError; // défaut fourni
}
pub trait StreamDecoder: Send {
    fn push(&mut self, chunk: &[u8], out: &mut Vec<LlmEvent>) -> Result<(), LlmError>;
    fn finish(&mut self, out: &mut Vec<LlmEvent>) -> Result<(), LlmError>; // appels d'outils, usage, puis UN Done
}
// ChatRequest { model, system, messages: Vec<ChatMessage>, tools: Vec<ToolDef>, reasoning_effort,
//               max_output_tokens, bearer: Option<String> }
// ChatMessage::{User{content}, Assistant{content, tool_calls}, Tool{tool_call_id, content}}
// LlmEvent::{Text, Thinking, ToolCall(ChatToolCall{id,name,arguments}), Usage(Usage), Done(FinishReason)}
// LlmError::{Transport, Auth, RateLimited{retry_after_secs}, CallBudget, TokenBudget, Timeout,
//            Rejected{status}, Provider{status}, BadStream}
```

Transport commun : `provider::stream_completion(socket, adapter, req, on_event)` par le mandataire.
Choix de l'adaptateur : `provider::adapter_for(LlmProvider)`.

**Brief L07b (Gemini, Mistral)** : ajouter `provider/mistral.rs` et `provider/gemini.rs`, chacun un
`LlmAdapter` + `StreamDecoder`, et ne modifier **que** les deux branches `Mistral` / `Gemini` de
`adapter_for` (aujourd'hui repli sur le dialecte OpenAI `custom_named`). Contraintes :

1. Le mandataire n'admet que `POST /chat/completions` et `GET /models` (sans requête) relatifs à
   l'URL de base configurée dans le runtime (`docs/plan/10` §4). **Gemini** : l'API native
   (`models/{m}:streamGenerateContent`) est refusée ; soit utiliser l'endpoint compatible OpenAI
   (`base_url = https://generativelanguage.googleapis.com/v1beta/openai`) avec un décodeur qui lit
   le raisonnement (`delta.reasoning_content` / `extra_content` selon la doc à la date) et
   `reasoning_effort` (`low|medium|high`, accepté par cet endpoint), soit proposer une extension de
   la liste blanche du mandataire (L06, superviseur) — à arbitrer par l'orchestrateur. **Mistral** :
   `POST /chat/completions` natif ; ne pas envoyer `stream_options` ni `parallel_tool_calls` s'ils
   sont refusés (vérifier la doc à la date), `max_tokens`, outils au format OpenAI ; raisonnement
   Magistral en ligne `<think>` (`think::ThinkTagSplitter`) ou en `content` structuré
   (`[{type:"thinking",…}]`) selon le modèle ; usage dans le dernier morceau.
2. Comportement commun (cf. `openai.rs`) : un seul appel d'outil traité ; arguments réassemblés ;
   `finish` émet appels d'outils, `Usage`, puis exactement un `Done` ; identifiant d'appel non
   conforme à `^[A-Za-z0-9_-]{1,64}$` laissé tel quel (la boucle le remplace) ; aucune erreur ne
   recopie de texte du fournisseur ; `classify_error` : garder les codes `proxy_*` du défaut.
3. Tests : requêtes construites (corps, chemin, en-têtes, jamais d'`authorization`), flux
   enregistrés (texte, raisonnement, outil coupé, usage, erreur dans le flux), comme
   `openai.rs::tests` ; un test d'agent (`tests/agent.rs`, `FakeLlm`) avec `init.llm.provider`
   réglé sur le fournisseur.
4. Ne pas toucher à `agent.rs`, `tools`, `transcript`, `events`, ni au pipe.

**Dépendances ajoutées** (épinglées, dates crates.io relevées le 2026-11-20) : `rsa` 0.10.0
(2026-11-08), `crypto-primes` 0.7.2 (2026-06-10, transitive). Aucune autre version nouvelle au
`Cargo.lock` (rand_core 0.10.1, crypto-bigint 0.7.11, sha2 0.11, hmac 0.13 y étaient). Aucun appel
système ajouté au filtre seccomp (le vrai worker passe le test hôte sans changement).

**Vérifié** :

- flatpak : `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo fmt --check`, check-secrets ;
- `crates/worker/tests/agent.rs` (LLM simulé sur socket Unix qui rejoue des flux SSE, API simulée
  avec contrôles de bail, de `rev` et de format `gcm1:`) : tour simple, outil serveur (lecture,
  écriture anticipée avant l'outil mutant), confirmation acceptée / refusée / `deny`, message en
  file pendant un tour et doublon, plafonds (étapes, budget, quota du mandataire, 5xx avec
  nouveaux essais, clé refusée), annulation, `ask_question` + `stale_decision`, `awaiting_key` et
  reprise, outils hors d'atteinte, `snapshot` et arrêt, outil E2EE `create_thread` (scellés RSA
  ouverts, `rt1` vérifiée, entrée ouverte par `DK`), passerelle (`sgt1`), bail perdu, **aucun
  contenu en clair** (marqueurs absents des trames du pipe et des corps vers l'API hors arguments
  d'outil serveur) ;
- `crates/worker/tests/crash.rs` : **vrai `SIGKILL`** d'un worker enfant (ce binaire de test relancé
  sur `entry::run`) pendant `create_task` : outil jamais relancé, `unknown_outcome`, `events` ;
  mutation (relance autorisée) → test en échec ;
- test croisé : `SYNCO_APP=…/synco_app bun crates/worker/tests/ts/read-from-worker.ts` → le code réel
  de synco_app (`decryptAiField`, `decryptGatewaySessionMessages`, `convertStoredMessagesToChatMessages`
  extraits d'`AIService.ts`, `decryptThreadKeyWithRsa`, `verifyRt1Envelope`) relit le fixture
  `tests/fixtures/transcript-from-worker.json` produit par le worker : 11/11 ; synco_app non modifié ;
- hôte : `host-spawn sh -c 'CARGO_TARGET_DIR=$HOME/.cache/synco-l07-host-target sh
  crates/supervisor/tests/sandbox-host.sh'` → 10/10 + `aller_retour_avec_bac_a_sable`, désormais avec
  la vraie boucle d'agent dans le bac à sable : appel au fournisseur simulé par le mandataire (clé
  `Bearer` ajoutée par le superviseur), deltas chiffrés reçus par le client, historique écrit.

**Écarts avec docs/plan (à reporter)** :

1. 06 §3–§4 : message **`created_key`** (superviseur → worker) et trame `0x02` **worker →
   superviseur** restreinte (une clé de salon créée). Raison : 03 §10/§10.1 exigent la signature
   `csk` et l'entrée sous `DK`, que le worker n'a pas (mesure 7) ; aucune trame ne le permettait.
2. 04 §4.3 / API : `POST /e2ee/threads` exige `categoryId` (cuid) que le canal n'expose pas, et
   le canal ne donne pas les membres d'un **espace** : le worker transmet `categoryId` s'il figure
   dans les arguments (absent du schéma de l'outil) et ne scelle la clé d'un salon d'espace que pour
   le propriétaire (sceller pour toute l'org donnerait la clé à des non-membres). **Besoin d'API
   (L14/L15)** : catégorie par défaut de la cible côté API et membres d'un espace sur le canal ;
   sinon `create_thread` échoue (`invalid_body`) en réel.
3. Q6 : `search_messages` en **repli lexical** sur les index déchiffrés (le modèle d'embedding ne
   peut pas tourner dans le bac à sable : pas de fichier, pas de réseau, ~120 Mio de poids, aucun
   moteur ONNX) ; argument facultatif `spaceId` (hors schéma) qui seul déclenche `awaiting_key`.
4. `create_file` (CDN injoignable du worker), `create_folder` (aucune route du canal),
   documentation (embarquée dans synco_app) : non exécutables, retirés de la liste donnée au
   modèle, refus explicite s'ils sont appelés.
5. 09 §2 : `maxTokensPerTurn` atteint → `idle` + `step_limit` (relance possible), comme
   `maxStepsPerTurn` ; `proxy_call_budget` → `step_limit`, `proxy_token_budget` →
   `budget_exceeded`.
6. 08 §5 : `events.code` de `tool_unknown_outcome` = nom de l'outil ; `lease_lost` sans `code`.
7. Clés RSA des membres non épinglées en TOFU par le runtime (le worker n'a pas de disque ;
   à confier au superviseur, comme `pins.rs`) : clé illisible écartée.
8. `reasoning_effort` envoyé à la passerelle et aux modèles de raisonnement d'OpenAI seulement
   (OpenAI le refuse pour les autres) ; la consigne d'effort du prompt s'applique à tous.
9. `answer` / `upload` acceptés même si l'état lu est `queued` (l'API passe `queued` au dépôt) :
   le contrôle porte sur l'appel en attente (`pendingToolCall`).

**Non vérifié (recette manuelle)** : vraie API (L03) et vrai fournisseur (OpenAI, passerelle avec
un vrai `sgt1`) ; affichage dans OrgAI.vue du flux en direct (L12 adapte la source d'évènements) ;
`create_thread` réel (bloqué par l'écart 2) ; push reçus sur mobile ; métriques au dashboard (L08).

### 2026-11-20 — L07, corrections après relecture indépendante

**Corrigé** (un commit par point, chacun avec un test qui échoue sans la protection) :

- **I1** (`2cec9ec`) : historique `conv-gcm1-v1` lu **strictement** (`transcript::Read::Strict`,
  seul mode de la boucle) : un champ de contenu qui n'est pas `gcm1:` est illisible (jamais repris
  en clair), un appel aux arguments illisibles passe en `error`, un `pendingToolCall` aux arguments
  en clair est ignoré. Reprise : mutant d'après le **manifeste** (pas le drapeau en clair) ; un appel
  mutant `accepted` n'est relancé que s'il correspond au `pendingToolCall` déchiffré, sinon clos
  (`tool_call_unverified`). Test `crash.rs::historique_en_clair_jamais_repris_ni_execute`
  (mutation « lecture tolérante » → l'outil forgé s'exécute).
- **I2** (`d5ef171`, `65f8901`) : après l'envoi d'une action mutante (`tools/:name/execute`,
  `POST /e2ee/threads`), délai, pipe fermé, `relay_network`, réponse illisible ou trop grande, `5xx`
  → `unknown_outcome` + `tool_unknown_outcome` ; erreur explicite de l'API → échec ; refus **local**
  du relais (`relay_busy`, `relay_rate_limited`, `relay_refused`, `relay_bad_part` : rien n'est parti)
  → échec. Un 2xx de création de salon sans id lisible → issue inconnue. (`65f8901` : correctif
  clippy, le commit I2 avait été fait sans que clippy passe.)
- **I3** (`62cac36`, `2fdb5a4`) : `created_key` réservé aux salons dont le superviseur a lui-même
  relayé la création réussie pour **ce** worker (réponse 2xx, id lu dans la réponse, noté avant que
  le worker la voie), une clé par salon (`created_key_unknown_thread`), plafond de 32 sur les clés
  signées. Coffre : une seconde entrée ne remplace jamais une clé différente déjà ouverte (la
  première est gardée, rejet compté). Délégation : le superviseur ne connaît que la délégation
  courante du propriétaire, pas le `delegationId` de l'autorisation ; un écart échoue **fermé** côté
  API (signature vérifiée avec la délégation de l'autorisation → `400` ; entrée → `out_of_scope`),
  aucune enveloppe fausse n'est posée (documenté dans `workers.rs`).
- **I4** (`2fdb5a4`, `42e6d14`) : test `integration.rs::created_key_reserve_aux_salons_crees_par_ce_worker`
  avec le **vrai** code du superviseur et un worker scripté (salon inconnu, signature `rt1` vérifiée
  avec la `csk` du runtime, seconde clé, plafond 32, délégation retirée, trame `0x02` interdite qui
  tue le worker) ; tests `stale_decision` pour une confirmation d'un autre appel et `deny` revérifié
  à l'exécution. Correctif trouvé par ces tests : une décision périmée était consommée en mémoire
  mais jamais écrite (le worker quittait l'attente sans écrire) ; l'état d'attente est réécrit.
- **I5** (`986ea65`) : clés RSA de membre < 2048 bits écartées et membres écartés signalés au modèle
  (`skippedRecipients`) ; plus de 300 destinataires → `too_many_recipients`, aucun salon créé.
- **M1** (`22db38d`) : un délai du renouvellement de bail ne l'arrête plus. **M3/M5** (`4d87c6c`) :
  identifiant d'appel toujours tiré par le worker ; arguments illisibles (dont `finish_reason:
  length`) → `invalid_tool_arguments`, sans exécution. **M4** (`cd339e9`) : texte (4 Mio) et
  arguments d'outils (1 Mio) d'une réponse bornés, `LlmError::TooLarge` (nouvelle variante de
  l'interface, sans nouvel essai). Remarques (`068a839`) : identifiants de boîte validés en entier
  (`<id>` ou `confirm|answer|upload|cancel:<id>`), donc sûrs dans `?after=` (un encodage pourcent
  est impossible : le relais refuse `%`) ; `upload.ref` recopié seulement si c'est un identifiant.
- Fixture croisé régénéré (`test(runtime)` suivant) ; test TS : 11/11.

**Vérifié** : `cargo test --workspace`, clippy `-D warnings`, `cargo fmt --check`, check-secrets
(flatpak) ; hôte (`sandbox-host.sh`, cible `~/.cache/synco-l07-host-target` supprimée ensuite) :
10/10 + aller-retour avec le vrai worker isolé ; test croisé TS 11/11. Aucune dépendance nouvelle.

**Écarts déclarés (à reporter, décisions remontées)** : épinglage TOFU des clés RSA des membres
toujours absent (le worker n'a pas de disque ; à confier au superviseur comme `pins.rs`, décision à
prendre) ; `LlmError::TooLarge` ajouté à l'interface L07b ; codes `created_key_unknown_thread`,
`tool_call_unverified`, `invalid_tool_arguments`, `invalid_upload_ref`, `too_many_recipients`.

**Non vérifié** : renouvellement du bail après un vrai délai de 150 s (seule la décision est testée,
`agent::tests::renouvellement_du_bail`) ; délégation **expirée** (et non retirée) au moment de
`created_key` (même branche que la délégation retirée).

## 2026-11-20 — L07b : adaptateurs LLM Mistral et Gemini

Fichiers : `crates/worker/src/provider/{mistral,gemini}.rs` (nouveaux), `openai.rs` (décodeur SSE
paramétrable `DecodeOptions`, aides `add_tool_names` / `wire_tools`), `think.rs`
(`ThinkTagSplitter::thought_tags`), `mod.rs` (seules les branches `Mistral` / `Gemini` de `adapter_for`
changent ; `custom_named` supprimé), `tests/agent.rs` (2 tests d'agent). **L'interface (`LlmAdapter`,
`StreamDecoder`, `ChatRequest`, `LlmEvent`, `LlmError`, bornes M4) n'est pas modifiée.** Le mandataire et
le superviseur ne sont pas touchés.

### Sources consultées (à la date du lot)

- Gemini, compatibilité OpenAI : <https://ai.google.dev/gemini-api/docs/openai> (redirigé vers
  <https://aistudio.google.com/docs/openai>) : base `https://generativelanguage.googleapis.com/v1beta/openai/` ;
  `reasoning_effort` ∈ `minimal|low|medium|high|xhigh` (`xhigh` seulement Gemini 4, `none` seulement 2.5),
  non combinable avec `thinking_level` / `thinking_budget` ; `include_thoughts` seulement par
  `extra_body.google.thinking_config` ; `stream_options.include_usage` utilisé dans l'exemple. **Non
  documenté** : forme des pensées en flux, `index`/`id` des appels en flux, champs d'usage détaillés,
  `max_tokens`/`max_completion_tokens`, `parallel_tool_calls`, format d'erreur.
- Complément (retours publiés, non officiels) : forum Google
  <https://discuss.ai.google.dev/t/gemini-openai-compatibility-issue-with-tool-call-streaming/59886>
  (appels sans `index`), <https://github.com/openai/openai-agents-js/issues/2116>,
  <https://github.com/simonw/llm/pull/1826> (appels parallèles entiers, `index` absent ou 0, identifiant
  parfois vide) ; pensées : <https://discuss.ai.google.dev/t/how-can-i-get-thinking-content-from-gemini-2-5-pro-or-flash-with-openai-sdk/93130>,
  <https://github.com/NousResearch/hermes-agent/issues/147482> (`delta.extra_content.google.thought: true`,
  balises `<thought>`) ; <https://github.com/zy1233/pi-python/pull/138> (`reasoning_effort` avec
  `thinking_config` refusé en 400).
- Mistral : <https://docs.mistral.ai/api/endpoint/chat> (`POST /v1/chat/completions`, `max_tokens`,
  `parallel_tool_calls` booléen, `reasoning_effort` `none…xhigh`, pas de `stream_options` documenté),
  <https://docs.mistral.ai/capabilities/reasoning/> (`delta.content` en liste `thinking` / `text`,
  `reasoning_effort` : `mistral-large-4-0` = low/medium/high ; `mistral-small-2603` et
  `mistral-medium-3-5` = high/none), <https://docs.mistral.ai/capabilities/function_calling/> (exemple
  d'identifiant `D681PevKs`, message `tool` avec `name`). Identifiants `^[a-zA-Z0-9]{9}$` : exigence
  rapportée par plusieurs dépôts (Zed #53034, mistral-vibe #1075, vLLM #59212…), erreur 400 code 3280.

### Comportements repris de `providerAdapters/*.ts` (un test chacun)

| Comportement TS | Mistral | Gemini |
|---|---|---|
| requête, outils, `tool_choice auto`, une température de 0,5 | `requete_mistral` | `requete_gemini` |
| flux de texte, usage | `flux_texte_usage_dans_le_dernier_morceau` | `texte_et_usage_avec_raisonnement` |
| raisonnement (`<think>` / champ dédié / `part.thought`) | `raisonnement_think_en_ligne`, `raisonnement_en_contenu_structure_puis_texte` | `texte_et_usage_avec_raisonnement` (drapeau `thought`, `<thought>`) |
| usage entrée / sortie / raisonnement | idem (`reasoning_tokens`) | idem |
| appel d'outil réassemblé, plusieurs appels | `appel_d_outil_*` | `plusieurs_appels_sans_index_et_finish_stop`, `appel_en_plusieurs_morceaux_*` |
| fin `tool_calls` même si le fournisseur dit `stop` | — | idem |
| erreurs sans texte du fournisseur | `erreurs_du_fournisseur_sans_texte` | idem |
| bornes M4, erreur dans le flux, flux coupé | `flux_coupe_trop_grand_et_erreur_dans_le_flux` | `coupe_trop_grand_erreur_dans_le_flux` |
| nom de l'outil dans le résultat (`functionResponse.name`) | `name` du message `tool` | idem |

Tests d'agent avec `FakeLlm` : `fournisseur_mistral_outil_et_identifiants_de_neuf_caracteres`,
`fournisseur_gemini_tour_simple`. Les flux sont **écrits d'après la documentation et les retours
publiés, pas enregistrés sur les fournisseurs réels** (aucune clé disponible).

### Décisions et écarts

1. **Identifiants Mistral** : le worker tire `call_<24 hex>` (L07, M3), que Mistral refuse (9 caractères
   alphanumériques). L'adaptateur les traduit dans la requête seulement (hachage FNV-1a en base 62,
   déterministe, sans collision dans la requête) ; l'historique garde l'identifiant du worker.
2. **Un flux fermé sans `finish_reason` ni `[DONE]` est `BadStream`** (réessayable) pour Mistral et
   Gemini, au lieu d'une fin `stop` silencieuse comme dans `openai.rs` et le TS. Un flux coupé ne doit pas
   passer pour une réponse complète. Non appliqué à OpenAI / `custom` / passerelle (comportement L07
   inchangé) : à décider.
3. **Gemini, écarts avec `gemini.ts` (API native, inatteignable)** :
   - `include_thoughts` n'est pas demandé : le TS ne l'envoie pas non plus (`includeThoughts` « Phase 4 »)
     et Google refuserait (selon un retour tiers) `reasoning_effort` combiné à `thinking_config`. Le
     décodeur lit quand même `extra_content.google.thought` et `<thought>` si un serveur les rend ;
   - `reasoning_effort` (absent du TS natif) est envoyé pour `gemini-2.5*`, `-3*`, `-4*` seulement ;
     `minimal`, `none`, `xhigh` ne sont jamais envoyés ;
   - `thoughtsTokenCount` natif : seul `completion_tokens_details.reasoning_tokens` est lu, présence
     **non documentée** ; sinon `reasoning_tokens` reste `None` ;
   - le TS n'envoie pas `max_output_tokens` ; ici `max_tokens` = `maxOutputTokensPerCall` (nom de champ
     non documenté pour Gemini, `max_tokens` est le plus courant) ;
   - `parallel_tool_calls` non envoyé (non documenté) ; le worker n'exécute de toute façon que le
     premier appel (`agent.rs`, inchangé) ;
   - le schéma des outils est transmis tel quel comme dans `gemini.ts` (`$schema`, `additionalProperties`
     peuvent être refusés par l'endpoint : à vérifier en réel).
   `base_url` du runtime : `https://generativelanguage.googleapis.com/v1beta/openai` ; Mistral :
   `https://api.mistral.ai/v1`.
4. **Mistral** : `reasoning_effort` seulement pour `mistral-large-4*` (valeurs `low|medium|high`) ; les
   autres modèles n'acceptent que `high|none`, la correspondance avec l'effort de l'org est une décision
   produit non prise (le TS n'envoie rien). `stream_options` non envoyé ; `usage` attendu dans le dernier
   morceau (non garanti par la documentation lue) : sans usage, la boucle estime déjà les tokens.
5. `classify_error` Gemini lit seulement le code `status` de Google (`UNAUTHENTICATED`, `RESOURCE_EXHAUSTED`…)
   et `API_KEY_INVALID`, jamais le message.

### Non vérifié

Aucun appel réel à Mistral ni à Gemini : formats d'appels en flux, usage, pensées, refus de schémas ou de
champs sont à vérifier en recette manuelle avec de vraies clés (une réponse texte, un outil, plusieurs
outils, un modèle raisonnant par fournisseur).

## 2026-11-20 — L08 : dashboard web du superviseur

**Branche** : `syncoai/L08-dashboard` (depuis `feature/syncoai-refonte` à `f9c9aad`). Conception :
`docs/plan/11-dashboard.md`.

**Fait** (`crates/supervisor/src/dashboard/`, aucun changement dans `crates/worker`) :

- `history` : enregistrement **typé** par exécution de worker (compteurs des `metrics` du pipe, coût
  en µ€ venu du worker, états et codes en liste fermée 08 §1 / §6, sinon `other`, relevés du cgroup),
  JSONL `<state_dir>/dashboard/history-AAAA-MM-JJ.jsonl` (0600), point de reprise toutes les 60 s,
  enregistrement final avec chronologie ; exécution sans fin = « interrompue » ; rétention
  (`dashboard.retention_days`, 1 à 3650, défaut 90) appliquée au démarrage puis chaque heure, sans
  jamais supprimer un fichier au nom inattendu.
- `query` : sessions (une conversation = ses exécutions agrégées), filtres (état, utilisateur,
  fournisseur, période, erreurs), tri sur 11 colonnes (ordre total), pagination, totaux par
  utilisateur / fournisseur, coût jour / 7 j / 30 j, détail avec chronologie.
- `auth` : mot de passe local (Argon2id 64 Mio, `dashboard.pass` 0600, commande
  `synco-ai-runtime dashboard-password`), sessions à jeton aléatoire neuf à chaque connexion (SHA-256
  seul gardé), 30 min d'inactivité / 12 h, 16 sessions ; force brute : 5 échecs / 15 min par adresse
  et 20 au total, comptés avant le calcul Argon2, une vérification à la fois.
- `routes` : garde unique autour de tout le routeur (hôte, session, `Origin`, jeton CSRF), 401 partout
  sauf `GET /login`, `/assets/login.js`, `/assets/style.css`, `POST /api/login` ; cookie `HttpOnly;
  SameSite=Strict` (+ `Secure` derrière un mandataire de confiance en HTTPS) ; CSP stricte sans
  inline ; `Host` contrôlé (DNS rebinding) ; interface HTML/CSS/JS embarquée, en français, sans CDN,
  texte inséré par `textContent`.
- Branchements : `Runtime.history`, `Runtime.api_connected` (flux de notifications), relevé du cgroup
  toutes les 5 s et au dernier instant dans `workers::drive`, hooks `on_metrics` / `on_status` /
  `on_done` / `end_run`. Le dashboard ne démarre que si un mot de passe existe.

**Dépendances** : aucune nouvelle (Argon2, axum, SHA-256 et aléa déjà dans le dépôt ; JSONL au lieu
de SQLite pour éviter une bibliothèque C).

**Vérifié** (flatpak, `CARGO_TARGET_DIR=$HOME/.cache/synco-l08-target`) : `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (21 binaires de
tests, tous verts) ; `node --check` des deux fichiers JS (via `host-spawn`). Tests propres au lot :
- `tests/integration.rs::dashboard_sans_contenu_de_conversation` : un worker scripté envoie le
  marqueur dans un `log`, un `status.reason`, trois `event` (texte, arguments, résultat) et un
  historique relayé ; aucune réponse du dashboard (14 chemins, plusieurs filtres) ni aucun fichier
  du répertoire d'état ne le contient, alors que l'API simulée l'a reçu. Contrôle négatif fait : en
  désactivant le filtre des codes, le test échoue.
- `tests/dashboard.rs` (12 tests) : énumération de toutes les routes × 7 méthodes + chemins inconnus →
  401 sauf la liste fermée ; en-têtes ; pas de script ni style en ligne ; cookie ; CSRF et origine ;
  fixation ; hôte ; force brute HTTP (429 + `Retry-After`) ; corps invalide ou > 1 Kio ; filtres et
  tri de bout en bout.
- unitaires : rétention (fichiers et mémoire), points de reprise, valeurs hors liste, agrégation,
  filtres, tri, totaux, coûts par période, force brute (par adresse, globale, rafale parallèle,
  remise à zéro), expiration des sessions, changement de mot de passe.

**Corrections après revue Opus légère** (commits `7bc8b18`, `d8cada6`, `44f34d3`, `3ae6455`, `4ed692b`) :

- **I1** : le dashboard avait repris `listen.trust_proxy_hops` (défaut 1) et croyait `X-Forwarded-For` /
  `X-Forwarded-Proto` sur une connexion directe (contournement de la limite par adresse, blocage de
  l'admin par la limite globale). Réglage propre `dashboard.trust_proxy_hops`, **défaut 0** (en-têtes
  ignorés), borné à 4. La limite globale n'est plus un refus : au-delà de 20 échecs / 15 min, une
  adresse inconnue ne déclenche qu'une vérification toutes les 5 s ; les 8 dernières adresses ayant
  ouvert une session en sont exemptées (jamais de la limite par adresse stricte) ; IPv6 compté par /64.
  `docs/plan/11-dashboard.md` §3 et README (blocs nginx / Caddy) mis à jour. Tests : XFF ignoré par
  défaut et lu à 1, `Secure` non posé sur un `X-Forwarded-Proto` forgé à 0, admin connecté pendant une
  attaque continue (adresse connue sans attente, adresse nouvelle après ≤ 5 s), IPv6 /64.
- **I2** : plafond `MAX_RUNS` appliqué après le chargement ; élagage amorti (jusqu'à 90 % du plafond,
  une passe O(n log n) tous les 5 000 ajouts) au lieu d'une passe quadratique à chaque ajout. Test :
  75 000 enregistrements chargés → plafond respecté, plus récentes gardées, 2 000 ajouts rapides.
- **M1** (marqueur dans `status.status`, mutation de `clean_status` vérifiée : le test échoue),
  **M2** (listes, totaux, coûts sur des exécutions **sans chronologie** ; seul le détail clone celles
  d'une session), **M4** (identifiant d'exécution avec aléa : unique à travers les redémarrages),
  **M5** (rechargement : `done_reason`, `exit`, `run_id` et chaînes de la chronologie refiltrés ;
  enregistrement à identifiant invalide ignoré), **M6** (page HTML sans session : 401 avec un court
  corps renvoyant vers `/login` ; `/api` reste en JSON ; `decodeURIComponent` protégé), **M7**
  (fichier du mot de passe illisible ou invalide : dashboard non démarré, journal
  `dashboard_password_unreadable`), **M8** (`Host` insensible à la casse).
- **M3** laissé : les écritures JSONL (points de reprise toutes les 60 s, fin d'exécution) se font sous
  le verrou de l'historique ; volume faible (quelques centaines d'octets), non critique.
- I2, M2, M4, M5 sont dans un seul commit (mêmes fichiers, impossibles à séparer proprement).

**Écarts / décisions remontées** :

1. **Authentification** : mot de passe local retenu. La connexion par ticket Synco (admins de l'org)
   demande une nouvelle route API et un rôle : **remontée** (évolution possible en plus, jamais à la
   place : l'empreinte doit rester lisible si Synco est compromis ou hors ligne).
2. **Chronologie sans nom d'outil ni type d'étape** : les `metrics` du pipe n'ont que des compteurs
   globaux (06 §5 prévoyait un compteur par outil, que le worker n'émet pas). La chronologie montre
   lancement, états, écarts de mesures (étapes, outils, tokens, coût, durée du tour), fin. Un compteur
   par outil demande une évolution de `crates/worker` (L07b ou suivant) : **remontée**.
3. **Noms d'utilisateur** : l'API ne fournit au superviseur que l'identifiant ; le dashboard affiche
   l'identifiant (aucune route ajoutée).
4. Durée d'une exécution = process du worker ; une conversation relancée = plusieurs exécutions
   agrégées dans la session. Les compteurs du worker repartent de zéro à chaque lancement ; le
   dashboard les additionne.
5. Une exécution en cours lors d'un arrêt brutal du superviseur garde ses totaux au dernier point
   de reprise (≤ 60 s de retard) mais perd sa chronologie.
6. Le coût est un coût **estimé** par le worker depuis `pricing` (absent : 0). Jour / semaine / mois
   = jours UTC ; coût attribué au jour d'arrivée de la mesure.
7. Mot de passe défini après le démarrage : le dashboard ne démarre qu'au redémarrage suivant
   (changement de mot de passe ensuite pris en compte à chaud).
8. CPU / RAM des workers : « non mesuré » avec le lanceur de test ou `--insecure-no-sandbox` si le
   cgroup n'est pas disponible (`usage()` renvoie `None`).

**Non vérifié** : rendu réel dans Firefox (aucune capture produite : pas de navigateur pilotable
depuis le flatpak sans outil externe) ; mesure CPU/RAM avec un vrai cgroup (le test envoie des
`ResourceUsage` synthétiques) ; comportement derrière un vrai mandataire TLS (`Secure`, `Host`).

**Checklist de recette manuelle** (sur l'hôte, runtime lancé avec le bac à sable) :

1. `synco-ai-runtime dashboard-password` : saisie masquée ; refus d'un mot de passe de moins de 12
   caractères ; `ls -l <state_dir>/dashboard.pass` en `-rw-------`.
2. Redémarrer le runtime : le journal indique `dashboard_started` ; sans le fichier,
   `dashboard_disabled`.
3. Ouvrir `http://127.0.0.1:8791/` dans Firefox : réponse 401 (JSON) ; `/login` affiche le formulaire.
4. Mauvais mot de passe : « Mot de passe incorrect » ; au 6e essai : message de patience (429).
5. Bon mot de passe : vue d'ensemble ; l'empreinte est identique à `synco-ai-runtime pair` et à
   celle affichée par Synco (mesure 4) ; état d'appairage et « API Synco connectée » corrects.
6. Lancer une conversation en mode runtime : une ligne « En cours » apparaît dans Sessions, RAM et
   CPU non nuls, tokens et coût croissants ; fin : état « Terminé », durée figée.
7. Détail d'une session : chronologie sans aucun texte de conversation (ni arguments, ni résultats).
8. Filtres (état, utilisateur, fournisseur, période, erreurs) et tri par clic sur les colonnes ;
   pagination ; Totaux par utilisateur puis par fournisseur.
9. Provoquer une erreur (clé du fournisseur invalide) : la session apparaît avec erreur et état
   « Échec ».
10. Redémarrer le runtime : l'historique est conservé ; régler `retention_days = 1`, attendre ou
    redémarrer : les fichiers `history-*.jsonl` plus vieux sont supprimés.
11. Se déconnecter, puis rejouer l'ancien cookie (`curl -b`) : 401.
12. Derrière le mandataire TLS : `allowed_hosts` contient le nom ; le cookie porte `Secure` ;
    `Host` inconnu → 403.
13. Console du navigateur : aucune violation de CSP, aucune requête externe.

## 2026-11-20 — L00d : report dans docs/plan des écarts acceptés de L06, L07, L07b et L08

**Branche** : `syncoai/L00d-spec-ecarts-d` (depuis `285d433`). Documentation seule : aucun code, test,
`Cargo.*` ni README touché.

**Fait** (chaque forme relue dans le code avant d'être écrite) :

- `06-superviseur-worker.md` : pipe par stdin puis descripteur 3, worker = binaire du superviseur ;
  `llm_credential` plus envoyée (clé injectée par le mandataire), `net_request` / `net_response`
  non retenus ; §2.1 trame `0x02` du worker restreinte à l'annonce d'une clé de salon créée ;
  §3.3 message `created_key` (forme, codes `created_key_unknown_thread`, `created_key_limit`,
  `delegation_unavailable`, `created_key_failed`) ; §4.1 lecture côté worker des refus locaux du relais
  (échec simple) ; §5 absence de compteur par outil ; §9 codes machine du worker (`tool_call_unverified`,
  `invalid_tool_arguments`, `invalid_upload_ref`, `too_many_recipients`, outils retirés), `LlmError`
  avec `TooLarge`, adaptateurs Mistral et Gemini (identifiants traduits, flux coupé, `reasoning_effort`).
- `03-delegation.md` §10.1 et `04-canal-interne.md` §4.3 : signature `rt1` par le superviseur,
  `create_file` / `create_folder` retirés, `create_thread` bloqué en réel, clés RSA des membres non
  épinglées (bornes ≥ 2048 bits et 300 destinataires).
- `10-bac-a-sable.md` : `memory.high` marqué question ouverte à la porte C, `provider_not_configured`,
  raison de Gemini par l'endpoint compatible OpenAI. `11-dashboard.md` : `MAX_RUNS`, reprise après arrêt
  brutal, §7 questions ouvertes. `08` / `09` : codes et limites ajoutés (`step_limit` / `budget_exceeded`
  du mandataire, `events.code`, limites du mandataire, de la réponse LLM, de `create_thread`, du dashboard).
- `00-vue-ensemble.md` : réalisation de D1 et D6, Q6 mise à jour, **Q22 à Q30** (questions ouvertes,
  non tranchées, avec renvois).

**Constat** : `10-bac-a-sable.md` et `11-dashboard.md` avaient déjà été écrits à jour par L06 et L08
(mandataire, quotas, `dashboard.trust_proxy_hops`, Argon2id, JSONL 90 j, limite globale = ralentissement) ;
le gros du report concernait `06`, `04`, `03` et `00`.

**Vérifié** : `cargo fmt --all --check` avant chaque commit, `check-secrets` du hook, `git diff --cached
--name-only` limité à `docs/plan/` et `docs/journal.md`. Pas de compilation ni de test.

## 2026-11-20 — L09 : packaging, déploiement, CI

**Fait** : `Dockerfile` (multi-étapes, images de base épinglées par digest d'index, utilisateur 10001, `HEALTHCHECK`,
volume d'état, `ENTRYPOINT` exec sans script), `compose.example.yml` (profil `gateway` : passerelle + Ollama), Quadlet Podman
rootless, variante Docker (profil seccomp dérivé de moby, profil AppArmor), vhosts nginx et Caddy, unité systemd de référence
complétée (pas de doublon), CI, `README.md`, `docs/deploiement.md`, `docs/recette-porte-c.md`.

**Images de base** (digests de l'index multi-architectures, relevés par `skopeo inspect --raw | sha256sum` et recoupés avec
l'API Docker Hub) :
`rust:1.98.1-slim-bookworm` → `sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730` (publié le 2026-09-19) ;
`debian:bookworm-20261027-slim` → `sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3` (2026-10-28) ;
`ollama/ollama:0.40.16` → `sha256:910d0d8107b538fb0894e63163eb195de0cc7aefcbc666dc62d3b18f71124592` (2026-11-09, 11 jours : > 7).
CI : `actions/checkout` v7.0.1 (2026-07-20) par SHA `3d3c42e5aac5ba805825da76410c181273ba90b1` ; `cargo-audit` 0.22.2 (2026-06-05).
Aucune dépendance Rust ajoutée.

**Constats du bac à sable sous Podman rootless (tous mesurés)** :

1. SELinux (Fedora) : `container_t` n'a pas le droit d'écrire dans cgroupfs, même en root du conteneur (`mkdir` refusé) →
   `--security-opt label=disable` (testé). Le booléen `container_manage_cgroup` serait plus étroit : **non testé** (root requis).
2. Le cgroup du conteneur appartient au root du conteneur, même avec `--userns=keep-id` : l'uid 10001 ne peut pas y écrire.
3. Lancer en uid 0 ne convient pas : `uid_map` d'un espace de noms imbriqué mappant l'uid 0 exige `CAP_SETFCAP`
   (`Operation not permitted` avec `--cap-drop=all`).
   → **uid 10001 + `--cap-add=DAC_OVERRIDE`** (seule capacité ; DAC pour le cgroup) + `unmask=/sys/fs/cgroup`. Le profil seccomp
   par défaut de Podman suffit (testé) ; sous le profil moby brut, `userns_unavailable` (testé) ; profil dérivé : OK sous Podman.
4. `sandbox-check` lancé sur le volume d'un runtime en marche **supprimerait** les répertoires de sockets des workers
   (`clean_run_dir`) : la doc impose un volume anonyme jetable.

**Correctif de code (commit séparé, `28476d6`)** : `sandbox-check` signalait `list_procs : escaped` quand le superviseur est le
processus 1 du conteneur : dans son espace de noms de PID, le worker est lui-même le PID 1, donc `kill(1, 0)` réussit sur
lui-même (faux positif). Le test est ignoré quand le PID du superviseur égale celui du worker (`kill0_same_pid`). Sur l'hôte
(`sandbox-host.sh` : 10/10, aller-retour OK) et dans le conteneur, plus de faux positif ; la couche réelle n'est pas affaiblie
(le test `tests/sandbox.rs` attend toujours `kill0_failed` avec un PID différent).

**Écarts** :

- Image « non root » : oui (10001), mais en Podman rootless le superviseur a besoin de `DAC_OVERRIDE` (point 2) ; documenté.
- Compose ignore `uid`/`gid`/`mode` des secrets hors Swarm : la phrase de passe doit appartenir à l'uid 10001 sur l'hôte
  (`podman unshare chown`, `chown` en Docker), documenté dans le fichier. `podman run --secret` et Quadlet gèrent `uid`/`mode`.
- `systemd-creds encrypt` refuse à un utilisateur non root : la première commande `pair` du mode systemd se lance en root
  (documenté dans l'unité et le guide).
- Quadlet utilise un volume nommé qui hérite uid 10001 / mode 0700 de l'image ; un `podman volume import` laisse la racine en
  root 0755 (restauration : `chown`, documentée).
- Audit : `cargo audit` (0.22.2) échoue aujourd'hui sur **5 avis `rustls` 0.23.44** (RUSTSEC-2026-0285, -0346, -0347, -0348,
  -0349 ; corrigés en ≥ 0.23.46, publié le 2026-10-14) et 1 avis `unsound` sur `rustix` 1.1.5 (RUSTSEC-2026-0486 ; 1.1.6 du
  2026-10-27). La montée des versions épinglées est une modification de dépendances que je n'ai pas faite (hors lot) : l'étape
  d'audit de la CI est en `continue-on-error` en attendant (commentaire explicite) : **à retirer après la montée**.
- Pas de `rust-toolchain.toml` dans le contexte d'image : la toolchain est celle de l'image `rust:1.98.1` (même version).

**Non vérifié** : Docker (socket inaccessible : permission refusée) — recette, profil AppArmor, `--cgroupns=host` + cgroup délégué
et l'option `--security-opt writable-cgroups=true` (présente dans les sources de moby 29.9.2) ; unité systemd **système** ;
SELinux avec le booléen ; mandataire en conditions réelles (seuls `nginx -t` et `caddy validate` ont été exécutés) ; appairage
contre une vraie API de dev ; bascule d'une conversation (recette manuelle `docs/recette-porte-c.md`).

**Questions** : (1) Docker : garder le sous-arbre délégué + `cgroup_root` (décision actuelle, plus lourde) ou adopter
`writable-cgroups=true` (cgroup du conteneur inscriptible, plus simple, incompatible `userns-remap`/rootless) ? (2) Accepter
`DAC_OVERRIDE` en Podman, ou faire écrire au superviseur dans un cgroup qui n'appartient pas au root du conteneur (changement de
code hors lot) ? (3) Monter `rustls` ≥ 0.23.46 et `rustix` 1.1.6 (autre lot).

## 2026-11-20 — L09 : corrections après revue

- **I1** : la phrase de passe est affichée une fois à la création (à noter dans un coffre). Le pilote de secrets Podman `file`
  la stocke en base64 sous le même `$HOME` que `keys.sealed` : documenté honnêtement (modèle de menace, `--showsecret`),
  alternatives citées (pilotes `pass`/`shell`, saisie au démarrage vérifiée dans `seal.rs` : terminal sans écho si
  `passphrase_file` est absent, donc `-it`, sans redémarrage automatique ; `systemd-creds`). **Question de fond non tranchée,
  posée à l'utilisateur.**
- **I2** : config, phrase de passe et sauvegardes se créent hors du dépôt (`~/.config/synco-ai-runtime/`, `~/sauvegardes/`) ;
  `.gitignore` et `.dockerignore` couvrent les noms de secrets et d'archives.
- **I3** : variante Docker marquée « non testée, non prise en charge en l'état » ; limites établies **par lecture** (capacité
  ambiante, ancêtre commun du cgroup, délégation limitée à quatre entrées, plafonds posés par l'hôte, fuite de
  `--cgroupns=host`) ; recette corrigée mais qui ne résout pas l'ancêtre commun ; `writable-cgroups=true` présenté comme piste
  avec le même problème de propriété. Aucun code modifié.
- **I4** : l'audit de la CI est bloquant ; six `--ignore` nommés (rustls 0.23.44 ×5, rustix 1.1.5), à retirer après la montée.
  Commande vérifiée avec cargo-audit 0.22.2 (rc 0 ; rc 1 si un avis n'est pas ignoré). J'ai ajouté `--deny unsound`.
- **M1** : `sandbox-check` essaie `kill(-1, 0)` (via `test_kill_process_group(1)`) : `ESRCH` constaté (`kill_all_esrch`) ;
  `kill` est bien dans la liste blanche seccomp. Nouveau test `superviseur_pid_1_pas_de_faux_positif` (hôte) ; mutation
  (contrôle `kill0_same_pid` retiré) : le test échoue (`escaped … kill0_ok:1`), restauré.
- **M2** : `label=disable` désactive tout le confinement SELinux (`spc_t`) ; `:Z` nécessaire sans lui ;
  `container_manage_cgroup` non testé. **M3** : sept lignes `ok`. **M4** : réseaux séparés ; passerelle `read_only` +
  `cap_drop: ALL` + `no-new-privileges` (vérifié avec l'image de la passerelle existante `localhost/synco-ai-gateway:l04`, pas
  reconstruite : `/health` répond) ; Ollama : seulement `no-new-privileges` (root, non testé). **M5** : limite de
  `trust_proxy_hops = 1` sur hôte partagé. **M6** : profil AppArmor en `abi <abi/4.0>` + `unix,` (non testé).

## 2026-11-21 — L07c : ajustements des adaptateurs LLM et de D6 (décisions de la porte C)

Fichiers : `crates/worker/src/provider/{openai,mistral,gemini}.rs`, `crates/worker/tests/agent.rs`,
`docs/plan/09`, `docs/plan/10`. `agent.rs` **non modifié** : la politique existante (nouvel essai seulement si
rien n'a été diffusé, 1 essai + 3 nouveaux essais) suffit.

- **PC9, flux coupé** : le décodeur OpenAI / `custom` / passerelle est désormais strict (`strict_end`), comme
  Mistral et Gemini : un flux fermé sans `finish_reason` ni `[DONE]` donne `BadStream` (réessayable). Écart
  volontaire avec le TS. Tests : `flux_coupe_est_une_erreur_reessayable_pour_tous_les_dialectes` (openai,
  passerelle, custom ; échoue sans le changement, vérifié) et `flux_coupe_reessaye_pour_tous_les_fournisseurs`
  (agent ; openai, custom, mistral, gemini : coupé sans contenu puis réponse = 2 requêtes ; coupé après du texte =
  pas de nouvel essai, `provider_error`, aucune réponse enregistrée ; toujours coupé = 4 requêtes puis
  `provider_error`). La passerelle n'est testée qu'au niveau du décodeur (le test d'agent exige un ticket).
- **PC10, Mistral** : `mistral-large-4*` : effort transmis tel quel ; `mistral-small-2603*` et
  `mistral-medium-3-5*` : `reasoning_effort = high` si l'effort est `medium` ou `high`, rien sinon ; les autres
  modèles (dont les alias `*-latest`, dont le modèle réel n'est pas connu) : rien. Test
  `effort_mistral_table_de_correspondance`.
- **PC11, Gemini** : rien d'activé ; `include_thoughts` reste non demandé. Documenté dans l'en-tête de
  `gemini.rs` : raisonnement Gemini désactivé jusqu'à un test réel avec une clé. `reasoning_effort` (L07b)
  est inchangé.
- **PC12, D6 révisée** : `memory.high` retiré, `memory.max` seul (09 §2, 10 §5). **Code restant hors périmètre**
  (`crates/supervisor`) : `sandbox/cgroup.rs` écrit encore `memory.high = max`, `launcher.rs`
  (`memory_high_bytes`), `cli.rs`, `config.rs` (`worker_memory_high_mib`, avertissement, validation),
  `workers.rs`, `sandbox/mod.rs`, `tests/sandbox.rs`, `synco-ai-runtime.example.toml`. Aucun code ne pose une
  limite `memory.high` effective (la valeur écrite est `max`), mais le nettoyage reste à faire dans un lot du superviseur.

### À reporter dans `docs/plan/00` et `06` (touchés par un autre lot)

- 00 : D6 (ligne 207) : retirer l'« écart L06 » et la question ouverte, écrire « `memory.max` seul, révisée le
  2026-11-21 ». **Q22 tranchée** : `memory.high` retiré. **Q26 tranchée** : flux coupé = `BadStream` réessayable pour
  tous les fournisseurs. **Q27 tranchée** : `high` si effort ≥ `medium`, rien sinon (modèles `high|none`).
  **Q28 tranchée** : raisonnement Gemini désactivé jusqu'à un essai réel avec une clé.
- 06 §9 : « Flux coupé » : `BadStream` pour **tous** les adaptateurs (supprimer « fin silencieuse `stop` comme
  le TS » et la question ouverte) ; paragraphe `reasoning_effort` : Mistral `high|none` selon la table ci-dessus
  (supprimer « question ouverte ») ; Gemini : mention « raisonnement désactivé jusqu'à un test réel ».

### Non vérifié

Aucun appel réel aux fournisseurs. Recette manuelle : un flux coupé réel (coupure réseau en cours de réponse) ;
`reasoning_effort: high` accepté par `mistral-small-2603` et `mistral-medium-3-5`.

## 2026-11-21 — L09b : rustls 0.23.46, rustix 1.1.6, audit CI sans `--ignore`

- `Cargo.toml` : les pins exacts (`=0.23.44`, `=1.1.5`) empêchaient `cargo update --precise` ; ils passent à `=0.23.46` et
  `=1.1.6` (modification indispensable). Dates crates.io vérifiées par l'API : rustls 0.23.46 publiée le 2026-10-14,
  rustix 1.1.6 le 2026-10-27, aucune retirée.
- `Cargo.lock` : seules ces deux crates changent, plus le rattachement de dépendances Windows de `windows-sys` 0.61.2 vers
  0.52.0 (version déjà présente dans le fichier, aucune nouvelle version).
- `.github/workflows/ci.yml` : les six `--ignore` (RUSTSEC-2026-0285, -0346, -0347, -0348, -0349, -0486) et leur commentaire
  sont retirés ; `cargo audit --deny yanked --deny unsound` (cargo-audit 0.22.2) sort en code 0.
- Vérifié : fmt, clippy `-D warnings`, `cargo test --workspace` (21 suites), `sandbox-host.sh` sur l'hôte (11/11 et
  `aller_retour_avec_bac_a_sable`), `podman build` de l'image.
- Test intermittent observé une fois : `fournisseur_non_configure_refuse` (`crates/supervisor/tests/integration.rs:1011`,
  `assertion failed: c.lease_released`) ; 5 relances isolées puis la suite complète passent. À investiguer (course de temps
  probable), non masqué.

## 2026-11-21 — L05b : épinglage TOFU des clés RSA des membres (I5, Q25)

Décision PC8 (2026-11-21) : épinglage persistant par le superviseur, lot dédié, bloquant avant production.

**Ce qui existe réellement (lu dans `synco_api` et `synco_app`, branche `feature/syncoai-refonte`, sans modification)** :
- `POST /api/e2ee/v4/rotate-identity` crée une `IdentityTransition` signée par l'**ancienne** clé de signature, qui porte la
  **nouvelle clé RSA** et la nouvelle clé de signature : c'est une preuve signée de rotation RSA. L'app l'emploie déjà pour
  ses propres épingles (`keyTrust.ts`, `acceptedByTransitionChain`, bout de chaîne exigé).
- `POST /api/e2ee/v4/reset` (dernier recours), `/users/me/resetE2EE`, `PATCH /users/me/publicKey` (v3) changent la clé RSA
  **sans** transition : aucune preuve possible.
- Le canal du runtime ne sert la chaîne (`GET /users/:userId/sign-key`) que pour un utilisateur qui a délégué à **ce**
  runtime ; `GET /e2ee/members/keys` donne `publicKey` et `publicSignKey`, pas les transitions.
- Aucune signature ne lie la clé RSA **initiale** à la clé de signature (les certificats d'appareil ne portent pas la clé
  RSA) ; le mandat (`synco-rt-mandate-v1|…`) ne contient pas la clé RSA du propriétaire.

**Conception retenue** :
- **Où** : le superviseur relaie déjà `GET /e2ee/members/keys` ; il compare chaque clé à son épinglage **avant** que le
  worker voie la réponse (`workers.rs:member_keys_gate`). Aucun message de pipe nouveau (forme la plus simple), et le
  contrôle ne dépend pas du code du worker.
- **Format** : `<state_dir>/member-rsa-pins.json` v1, par org puis utilisateur : `fingerprint` = `hex(SHA-256(SPKI DER))`
  recalculé depuis `n`/`e` (vecteur WebCrypto `exportKey('spki')` en test), `thumbprint` = RFC 7638 (comme
  `computeKeyFingerprint` de l'app, pour l'affichage), `firstSeen`, `previous`, `pending?`. Fichier absent : vide ;
  illisible : le superviseur ne démarre pas. Mêmes bornes que le worker (2048 à 8192 bits) : une clé hors bornes n'est pas
  épinglée (le worker l'écarte).
- **Refus** : **global** (recommandation de l'orchestrateur suivie) : la réponse entière devient `409 member_key_changed`,
  `create_thread` ne crée ni ne scelle rien, même pour un salon d'espace (propriétaire seul). Alerte
  `member_rsa_key_changed` (vue d'ensemble), clé mise en attente ; journal sans clé, empreinte ni identifiant.
- **Rotation** : acceptée automatiquement seulement si la chaîne de `sign-key`, suivie depuis la plus ancienne clé de
  signature épinglée de l'utilisateur (`user-pins.json`) et **passant par la courante**, aboutit exactement à la clé RSA
  présentée (au plus 8 vérifications par réponse). Suivre depuis la plus ancienne est nécessaire : l'épingle de signature
  avance à la réouverture d'une délégation alors que l'épingle RSA peut être restée en arrière. **Erroné, corrigé après
  revue (I1)** : exiger seulement le passage par la clé courante n'écarte PAS une branche signée par une clé retirée qui
  rejoint ensuite la courante ; voir « L05b : corrections après revue ». Sinon : **acceptation manuelle** au dashboard
  (`POST /api/member-keys/accept`, la seule clé affichée, session + origine + CSRF, confirmation en deux temps). Pas de
  commande en ligne : le superviseur garde le fichier en mémoire et l'écraserait.

**Commits** : `8f92f76` (magasin), `8230adf` (dashboard), `80bf257` (relais), `9ad2e13` (worker), `75bcbfe` (docs/plan :
04 §4.3, 06 §4.3 et §9, 03 §10.1, 00 Q25, 11 §5).

**Vérifié** : `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings`, `cargo test --workspace` (22 suites
vertes). Tests : `member_pins::tests` (empreintes = WebCrypto, première vue, même clé, substitution, acceptation de la seule
clé affichée, rotation par chaîne dont branche et clé intermédiaire refusées, persistance par réouverture, fichier sans clé),
`tests/member_pins_logs.rs` (journaux : codes seulement), `integration.rs::cles_rsa_des_membres_epinglees_par_le_superviseur`
(vrai superviseur : première vue, même clé, substitution → 409 + alerte + épingle inchangée, rotation prouvée, substitution
malgré une chaîne, acceptation admin, aucun salon, persistance relue après arrêt), `dashboard.rs::acceptation_d_une_cle_de_membre`,
`agent.rs::create_thread_refuse_si_une_cle_de_membre_a_change`. **Mutation** : contrôle retiré au relais (`if false && …`) →
le test d'intégration échoue à l'étape « clé substituée » (`left: (200, …)`, `right: (409, member_key_changed)`) ; restauré,
vert. Hôte : `sandbox-host.sh` vert + `aller_retour_avec_bac_a_sable`. Test croisé Rust → TS : OK ; `synco_app` inchangé.

**Écarts** : `crates/worker/tests/common/mod.rs` et `crates/worker/tests/agent.rs` touchés (tests du worker, hors
`src/tools/**`) ; `docs/plan/11-dashboard.md` mis à jour. La persistance « à travers un redémarrage » est testée par
réouverture du fichier d'état (unitaire et après `app::shutdown`), pas par un second démarrage complet du superviseur.

**Questions pour l'utilisateur** :
1. **Clé RSA du propriétaire liée au mandat** : faisable seulement par un mandat v2 (`synco-rt-mandate-v2|…|hex(SHA-256(SPKI))`)
   signé par l'app (L10) ; le runtime lirait v1 (sans liaison) et v2. Changement app (et champ de version côté API) : non fait.
2. **Rotation d'un membre qui n'a jamais délégué** : aujourd'hui seul l'admin du runtime peut l'accepter. Ajouter au canal
   une route S+A « chaîne de transitions d'un membre de l'org » permettrait l'acceptation automatique (changement API).
3. **Réinitialisation E2EE sans transition** (`/e2ee/v4/reset`, v3) : toujours un refus jusqu'à l'acceptation par l'admin.
   Convient-il, ou faut-il une autre voie (par exemple une acceptation par un admin de l'org dans Synco) ?
4. **Refus global** même pour un salon d'espace scellé pour le seul propriétaire : confirmer (plus sûr) ou restreindre le
   refus aux destinataires réels de l'appel (le superviseur ne connaît pas les arguments de l'outil).

## 2026-11-21 — L05b : corrections après revue

Verdict : intégrable après corrections. Un commit par correction ; contrôles (`fmt`, `clippy -D warnings`, `cargo test
--workspace`, 22 suites) avant chacun.

- **I1** (`4e4bfe5`) : une branche signée par une clé de signature retirée (k1 → kA → k2 courante) était acceptée, la règle
  « passer par la clé courante » ne suffisant pas. **Règle retenue, la plus stricte justifiable** : la chaîne suivie depuis
  la plus ancienne clé épinglée doit (1) reproduire **exactement** l'historique de signature épinglé (`previous` puis
  `sign_key`, que `pins.rs` remplit dans l'ordre avec chaque clé traversée) ; (2) aboutir à la clé RSA présentée, introduite
  une seule fois ; (3) et cette clé doit être garantie par une clé **non retirée** : le maillon qui l'introduit est signé
  par la clé courante ou une successeure, ou la chaîne s'arrête sur la clé courante et la clé RSA est celle que `pins.rs`
  a liée à cette clé **au moment où il l'a acceptée** (nouveau champ optionnel `UserPin.rsaFingerprint` ; anciens fichiers
  relus, `None` → acceptation par l'admin). Pourquoi (3) : un maillon servi aujourd'hui et signé par une clé retirée
  (peut-être compromise) peut porter n'importe quelle clé RSA, même avec les bonnes clés de signature ; la liaison
  enregistrée date d'une vérification faite quand cette clé n'était pas retirée. Sans le second cas, la rotation
  ordinaire (l'utilisateur renouvelle sa délégation, donc l'épingle de signature avance avant l'épingle RSA) tomberait
  toujours à l'admin.
- **I2** (`80df1f6`) : `rotate` refuse une clé égale à l'épinglée ou présente dans `previous` ; `chain_vouches` refuse une
  chaîne qui aboutit à la clé épinglée (elle la précède forcément si la chaîne la contient, la nouvelle étant introduite
  une seule fois, au bout).
- **I3** (`2a824d5`) : photo de l'état prise sous le verrou, écrite hors de lui (`spawn_blocking`), une fois par étape,
  photos ordonnées (une plus ancienne n'écrase jamais une plus récente), réponse rendue après l'écriture ; échec →
  refus fermé `member_pins_unavailable`. Bornes : 2 000 épingles par org (`member_pins_limit`, refus fermé), 16 précédentes,
  100 clés en attente. **Mesure** (`cles_rsa_charge_et_plafond`) : 2 000 premières vues dans une réponse en ~0,12 s,
  attente maximale du verrou d'état ~16-18 ms (contre 49 s de gel pour 3 000 avant).
- **I4** (`c3ddf3f`) : l'app ne montre pas au membre l'empreinte de sa propre clé (réglages : `n` brut, servi par l'API).
  Dashboard, 06 §4.3 et 11 ne promettent plus de comparaison : l'admin demande au membre, hors de Synco, s'il a
  réinitialisé ou renouvelé son chiffrement et quand, et n'accepte que sur confirmation.
- **I5** (`eff6b0f`) : injection d'un destinataire inconnu (ou d'une clé de l'API pour un membre jamais vu) à la première
  vue : inhérent au TOFU, écrit dans 06 §4.3 « Limites » et 00 Q25.
- **M1** (`a643325`) : variantes du chemin de l'annuaire (casse, `/` final, `//`, segment `.`) → `relay_refused`, sans
  appel à l'API. **M3** (`40bb233`) : corps illisible → `502 member_keys_unreadable`. **M4** (`3ab07c0`) : `refuse` ne
  mémorise rien si l'épingle a changé entre-temps ou si la clé est l'épinglée. **M5** (`9e8fa31`) : `v` ≠ 1 → refus de
  démarrer ; échec d'écriture → alerte `member_pins_not_saved` au dashboard, refus fermé, réécriture complète à la photo
  suivante. **M6** (`53a0362`) : empreinte affichée calculée sur le JWK minimal (`n`, `e` sans zéros de tête) ; l'app
  hache le JWK servi, issu de `exportKey('jwk')` (forme minimale), donc identique sur une clé légitime.
- **Tests** (`afd3056` et ceux des commits ci-dessus) : branche qui finit sur la courante ; maillon forgé par une clé
  retirée avec une autre clé RSA ; retour arrière ; `e = 1` ; variantes du chemin (unitaire et au relais) ; au plus
  8 vérifications `sign-key` par réponse ; org revérifiée après l'appel `sign-key` (désappairage pendant l'appel) ; deux
  réponses concurrentes pour un membre jamais vu (une seule clé épinglée) ; écriture impossible ; plafond.
- **Mutations faites** (sortie dans le compte rendu) : I1 (reproduction exacte retirée) → `rotation_par_chaine_d_identite`
  échoue « branche qui finit sur la courante » ; I2 (`previous.contains` retiré) → échoue « retour arrière » ; org non
  revérifiée → `cles_rsa_bornes_org_et_concurrence` échoue « rotation non installée » ; borne retirée → « vérifications de
  rotation bornées » (11 ≠ 8). Restaurées, vertes.
- La phrase de la première entrée L05b sur « le passage par la clé courante » est marquée erronée.

**Questions (en plus de celles de L05b)** : afficher dans l'app l'empreinte RFC 7638 de sa propre clé (sans quoi l'admin du
runtime ne peut rien comparer) ; le plafond de 2 000 épingles par org convient-il ?

**Vérifié à la fin** : hôte, `sandbox-host.sh` vert (11 tests) puis `aller_retour_avec_bac_a_sable ... ok` ; test croisé
Rust → TS : OK ; `synco_app` et `synco_api` non modifiés.

## 2026-11-21 — L00e : report dans docs/plan de L03d, L05b, L07c, PC27 et des décisions de la porte C

**Branche** : `syncoai/L00e-report-docs-plan` (depuis `feature/syncoai-refonte` à `f6c6a6e`). Documentation seule :
`docs/plan/**` et ce journal ; aucun code, test, `Cargo.*` ni README touché. Sources : `SYNCOAI_REFONTE_FEATURE.md`
§14 (surtout §14.9), `docs/journal.md`, `suivi.md` (PC1 à PC27). Le code du dépôt a été relu pour chaque point ;
l'état du runtime (non adopté) est écrit à côté de chaque ajout de l'API.

### Reporté (une ligne par point)

| Source | Point | Reporté dans |
|---|---|---|
| §14.9 | `GET /authorizations?state=active` (§14.1), `displayName` de `GET /delegations` | 04 §4.1 |
| §14.9 | `POST …/push` : état courant, une par entrée, 6 / min, `{ sent }` ; `notification:push` | 04 §4.2, 07 §7 |
| §14.9 | « push 1 / 30 s » remplacé ; limiteur de la synchro des clés (§14.5) | 09 §4 (tableau court et §4.1), 04 §8 (`rt_rate_limited`) |
| §14.9 | `categoryId` facultatif + `no_default_category` ; `GET /e2ee/members/keys?spaceId=` | 04 §4.3 |
| §14.9 | route S `POST …/key-envelope/repose` ; la route S+A refuse les `ThreadKey` réinitialisées | 04 §4.3 |
| §14.9 | 03 §10.1 : « aucune voie de reprise » retiré, §14.8 décrite (reset, repose, ce que le runtime doit faire, choix) | 03 §10.1 |
| §14.9 | trame `thread.envelope_reset` (`delegationId` = délégation active à signer) | 04 §6 |
| §14.9 | codes `no_default_category`, `envelope_not_set`, `repose_unavailable` | 04 §8, 03 §14 |
| §14.9 | `provider_not_configured` | 08 §6, 10 §4 |
| §14.9 | `ThreadKey.envelopeResetAt`, `envelopeResetBy`, `envelopeDelegationId` ; modèle `AiThreadEnvelopeEvent` | 07 §3.1 (nouvelle sous-section) |
| §14.9 | rétention 90 j des `AiChatSessionEvent` (§14.7) | 07 §5, 04 §4.2 |
| §14.9 | délais `awaiting_*` dans [1 h, 7 j] (§14.6) | 07 §6, 09 §3 |
| §14.9 | `displayName` dans le dashboard (PC17) | 11 §5 et §7 |
| §14.9 | 00 §6 : Q18, Q19, Q20, Q21, Q23, Q30 tranchées par L03d ; `user.revoked` non émis à l'expiration (PC24) | 00 §6 |
| L05, correction 9 | « besoin API » : route des autorisations actives, désormais livrée | 03 §9 |
| L07c, PC12 | D6 révisée, Q22 tranchée (la ligne D6 de 00 et 09 / 10 étaient déjà à jour) | 00 §5 (D6), 00 §6 (Q22) |
| L07c, PC9, PC10, PC11 | Q26, Q27, Q28 tranchées ; flux coupé = `BadStream` pour tous, table d'effort Mistral, Gemini désactivé jusqu'à un test réel | 06 §9, 00 §6 |
| L07, écart 9 | `answer` / `upload` acceptés si l'état lu est `queued` (non encore dans la spec) | 06 §9 |
| L05b, PC8 | Q25 réalisée : déjà reportée par L05b (04 §4.3, 06 §4.3, 03 §10.1, 11 §5) ; non refaite | — (vérifié) |
| PC27 | (a) empreinte RFC 7638 par l'app, (b) mandat v2 (SPKI du propriétaire, runtime lit v1 et v2), (d) blocage après reset sans transition, (e) refus global v1 + `scope=owner` plus tard, (c) reporté ; bornes de `member-rsa-pins.json` et purge d'`AiThreadEnvelopeEvent` **ouvertes** | 03 §10.1, 06 §4.3, 00 §6 (Q25) |

### Déjà reportés avant ce lot (non refaits)

Écarts de L05 (1 à 10 et corrections 1 à 11), L06, L07 (sauf l'écart 9 ci-dessus), L07b et L08 : repris par L00d et
les lots précédents. Vérifié par recherche de marqueurs dans `docs/plan` (`snapshot_request`, `relay_busy`,
`relay_too_large`, `status = 0`, `idle_timeout`, `authorizations.json`, `created_key_unknown_thread`,
`tool_call_unverified`, `TooLarge`, `skippedRecipients`, `maxTokensPerTurn`, `exp < iat`) ; chaque marqueur est présent.
Les 11 corrections de L05 et les 6 de L07 n'ont **pas** été relues une à une dans ce lot : seule cette vérification
par marqueurs a été faite.

### Volontairement non reporté, avec la raison

- **Items de §14.9** : aucun non reporté.
- **PC1 à PC4, PC6, PC20, PC25** : hors périmètre du lot L00e (PC1 à PC4 : packaging et CI, L09 / L09b ; PC6 : lot
  L07d « à définir » ; PC20 : correctif de l'app, L11 ; PC25 : lot API + app à créer).
- **PC7 (Q24), PC13 à PC15 (Q29)** : décisions de la porte C sur la recherche lexicale et le dashboard. Le lot demande
  au moins D6, Q22, Q26 à Q28 et PC27 ; ces points n'ont pas été reportés. **Q24 et Q29 restent écrites « non tranchées »
  en 00 §6 et 11 §7, alors que `suivi.md` les donne tranchées : écart signalé, non corrigé ici.**
- **L05b, questions 1 à 4** (liaison RSA au mandat, route de chaîne, reset sans transition, refus global) : répondues par
  PC27 ; reportées sous cette forme, sans fixer le format du mandat v2 ni le sens exact de `scope=owner`.
- **L05b, question « 2 000 épingles par org »** : **ouverte** (PC27 : bornes non tranchées, Synco doit tenir au moins
  1 000 membres par org).

### Doutes signalés, non tranchés

1. **Adoption par le runtime** : le code intégré n'appelle pas `GET /authorizations`, ne lit pas `displayName`, ne traite
   pas `thread.envelope_reset` (`ApiEvent::Unknown`), n'appelle pas `repose` et n'écrit pas `provider_not_configured`
   (`workers.rs:130` écrit `provider_error`) ; le worker n'utilise ni `categoryId` par défaut ni `?spaceId=`. Les documents
   le disent explicitement ; aucun lot d'adoption n'est planifié (**ouvert**).
2. **`repose` est S seule** alors que le relais du worker signe toujours avec `x-synco-auth` (`crates/worker/src/api.rs`) :
   la voie (superviseur ou worker) n'est pas tranchée (04 §4.3).
3. **`GET /e2ee/members/keys?spaceId=`** : le garde d'épinglage compare le chemin coupé avant `?` ; il s'appliquerait donc
   aussi à cette variante ; non testé.
4. **Vérification client d'une clé `rt1` reposée** : 03 §10.1 déduit de §14.8 et du schéma (`envelopeDelegationId`) que le
   `delegationId` signé est `envelopeDelegationId` quand il est non nul ; le code de l'app n'a pas été relu (L10 à confirmer).
5. **Q27 et Q28** : deux questions de l'orchestrateur (alias `mistral-*-latest`, lecture de PC11) restent ouvertes (`suivi.md`).
6. **Limite d'ajout d'entrées** : 09 §4 (table courte) garde « 1 requête / 5 s » ; 09 §4.1 donne la valeur réelle 3 / 15 s
   (Q16 c) : incohérence préexistante, non modifiée.

### Vérifié

`cargo fmt --all --check` et `git diff --cached --name-only` limité à `docs/` avant chaque commit ; `check-secrets` du hook
actif à chaque commit. Relecture du code (`crates/`) pour chaque état « côté runtime ». Aucune compilation ni aucun test :
documentation seule.

### 2026-11-21 — L00e, suite : PC28 à PC30, Q24 et Q29, limite d'ajout d'entrées

PC28 (épingles RSA hybrides : 50 000 par org réglable, archivage compact après 180 j, éviction de la plus ancienne archive, alerte à 80 % ; décidé, implémentation au lot L05c, le code applique encore 2 000) en 03 §10.1, 06 §4.3, 00 Q25 ; PC29 (`AiThreadEnvelopeEvent` 1 an, purge L03e en cours) en 07 §3.1, 03, 00 ; PC30 (1 000 membres par org) en 00 Q25 seulement ; PC7 (Q24) et PC13 à PC15 (Q29) en 00 §6 et 11 §7 ; 09 §4 : ajout d'entrées 3 req/15 s. Ni nettoyage `memory.high` ni adoption runtime (lot L08b). Le point (c) de Q29 reste non tranché.
## 2026-11-21 — L08b : consommation des compléments API de L03d

Forme des routes et trames : spec API §14 (lecture seule). Un commit par point ; `fmt`, `clippy -D warnings` et
`cargo test --workspace` (22 suites) avant chacun.

- **PC17** (`b8a4e83`) : `DelegationRecord.display_name` (optionnel) ; le superviseur garde `userId → nom` (`State.display_names`,
  remplacé à chaque relecture de `GET /delegations`, nettoyé : contrôles → espace, 128 caractères, bords retirés). Nouvelle
  route `GET /api/names` du dashboard ; le JS (`userCell`, `who`) insère le nom par `textContent` (info-bulle = identifiant),
  repli sur l'identifiant. Sessions, détail, totaux par utilisateur, clés de membres refusées.
- **Q18** (`443cb47`) : `reconcile_authorizations` fait un seul `GET /authorizations?state=active` paginé (curseur `after`, `limit=500`)
  au lieu d'un `GET /conversations/:id` par conversation. Absente de la réponse = retirée. Erreur, curseur qui ne progresse pas
  ou plus de 200 pages : tout est gardé. Seules les autorisations connues **avant** l'appel sont candidates (une autorisation
  notifiée pendant l'appel n'est jamais retirée).
- **Q23** (`a1fed02`) : `create_thread` valide les arguments, puis lit les annuaires **avant toute création** (accueil :
  `members/keys` ; espace : `members/keys?spaceId=`) ; un espace refusé ou une clé changée ne laisse créer aucun salon. Le relais
  applique déjà `member_keys_gate` à tout `…/members/keys?…` (test ajouté pour `?spaceId=`) : aucun contournement. Destinataires
  d'un espace = ses membres (le refus provisoire « propriétaire seul » est retiré). `categoryId` reste facultatif ;
  `no_default_category` (409) devient une erreur claire avec `note` pour l'agent.
- **Q30** (`95a7b3d`) : `provider_not_configured` écrit par le superviseur quand le fournisseur n'est pas utilisable (avant :
  `provider_error`) ; reconnu par le worker (`LlmError::NotConfigured`, code `provider_not_configured` ou `gateway_not_configured`
  dans une réponse, ou ticket `gateway_not_configured` refusé), sans nouvel essai ; conservé par l'historique du dashboard
  (liste fermée) et affiché distinctement.
- **Q21** (`e9f9bc6`) : trame `thread.envelope_reset` (`ApiEvent::ThreadEnvelopeReset`) et `Runtime::repose_envelope`. **Vérifications
  locales avant de signer** : (1) le salon est dans le **registre des salons créés par ce runtime** (nouveau,
  `created_threads.json`, rempli par `created_key`, borné à 10 000, vidé au désappairage) et pour **ce `userId`** ;
  (2) `delegationId` de la trame = délégation ouverte, non expirée, non révoquée de cet utilisateur ; (3) la clé du salon
  (entrée `thread`, version 1) est dans cette délégation. `commitment` recalculé depuis la clé, signature `rt1` par `csk`,
  `POST …/key-envelope/repose` (S seule, corps strict). Un salon à la fois (`repose_inflight`) ; trois essais seulement sur
  panne réseau/5xx ; tout refus de l'API (`envelope_exists`, `forbidden`…) est définitif. Journalisation par code seulement.
- **PC12** (`24eed3f`) : `memory_high_bytes` retiré de `ResourceLimits` (launcher, cli, workers, sandbox) ; `limits.worker_memory_high_mib`
  devient `Option<u64>` ignoré, plus validé (un ancien fichier avec 0 ou une valeur > max reste lu), `--check-config` avertit
  toujours. `cgroup.rs` écrit toujours `memory.high = max` (explicite).

**Écarts et limites à reporter (docs/plan, géré par L00e)** :
1. La spec (§14.8) et le lot parlent d'un « registre local des salons créés » ; il n'existait pas (seul un ensemble transitoire par
   worker). Créé ici. Les salons créés **avant** L08b ne sont pas dans le registre : leur réinitialisation est ignorée (journal
   `envelope_reset_foreign_thread`). Aucun déploiement ne les concerne à ce jour.
2. Le lot décrit le contrôle comme « ThreadKey `rt1:<délégation>` de ce runtime et de ce `userId` ». Le runtime ne reçoit pas le
   `creatorId` (trame sans lui, aucune route pour le lire) : le contrôle repose sur le registre + la délégation de la trame.
3. Contrainte de §14.8 : si la clé n'est plus dans le coffre (délégation renouvelée sans l'entrée, redémarrage avant
   synchro), la trame est ignorée (`envelope_reset_key_missing`). *Reprise automatique ajoutée par L08c (PC31), voir plus bas.*
4. L'API compare « même enveloppe » (200 `updated: 0`). *Correction L08c : la signature ECDSA `rt1` du runtime est
   **déterministe** (RFC 6979), pas aléatoire ; un rejeu avec la même délégation envoie donc exactement la même signature et
   reçoit 200 `updated: 0`. Seule une délégation différente change la signature (elle est dans les octets signés) et reçoit
   `envelope_exists`, géré sans boucle. Le mock compare désormais aussi la signature.*
5. `GET /authorizations` renvoie aussi `displayName` : non exploité (PC17 s'appuie sur `GET /delegations`).

**Mutations faites** : registre ignoré → `enveloppe_rt1_reposee_apres_reinitialisation` échoue ; utilisateur du registre non
comparé → échoue ; `delegationId` de la trame non comparé → échoue. La vérification `revoked_delegations` du coffre est
redondante avec l'effacement du coffre à la révocation (défense en profondeur, non couverte seule).

**Vérifié à la fin** : hôte, `sandbox-host.sh` vert (11 tests) puis `aller_retour_avec_bac_a_sable ... ok` ; test croisé
Rust → TS : OK ; `synco_app` et `synco_api` non modifiés.

## 2026-11-21 — L08c : suites de la revue L08b (PC31 à PC33, constats mineurs)

À la suite de `77e98ce`. `fmt`, `clippy -D warnings` et `cargo test --workspace` avant chaque commit.

- **PC31, file persistante** (`be09900`, `repair_queue.rs`, `repairs.rs`) : `thread.envelope_reset` ne lance plus une tâche par trame.
  La trame est contrôlée tout de suite contre le registre (salon étranger : jamais dans la file) puis rangée dans
  `envelope_repairs.json` (salon, utilisateur, délégation ; 10 000 au plus, dédupliquée sur (salon, utilisateur) avec la dernière délégation reçue, abandonnée après 30 jours). Un
  travailleur unique la rejoue, quatre réparations de front au plus (`REPAIR_CONCURRENCY`), à l'arrivée d'entrées, à l'ouverture
  d'une délégation, au rechargement des délégations et à chaque reconnexion. **Chaque essai refait toutes les vérifications locales**
  (`Runtime::try_repair` : registre + utilisateur, délégation ouverte non expirée non révoquée, clé détenue) ; une délégation
  pas encore chargée ou une clé absente laisse l'entrée en file, une panne réseau aussi (rejeu à la reconnexion), un refus
  définitif de l'API (`envelope_exists`, `forbidden`, `not_found`…) la retire.
- **PC31, relecture API** : à chaque reconnexion, `GET /api/runtime/v1/e2ee/threads/envelope-resets?limit=&cursor=` (S seule,
  100 par page, 100 pages au plus, curseur qui ne progresse pas = arrêt). Chaque item passe par `submit_repair`, donc par le registre
  local, puis par `try_repair` : l'API ne choisit jamais seule ce qui se signe. Route absente (L03f en cours) : relecture silencieuse
  (journal `debug`). Testée avec un mock, **pas contre la vraie route L03f**.
- **PC33, MAC** (`c66678b`, `sealed_file.rs`) : `created_threads.json` et `envelope_repairs.json` sont scellés
  (`{ "v": 2, "org": "<org>", "body": "<JSON en texte>", "mac": "<base64url HMAC-SHA256(longueur(org) ‖ org ‖ body)>" }`).
  Le MAC est lié à l'**org** (revue : retour en arrière) : un fichier scellé pour une autre org est rejeté (alerte, contenu vide, `.rejected`)
  dès que l'org est connue, à l'appairage (`bind_org`) ;. Clé : HKDF-SHA256 (`hkdf32` de `synco-e2ee`, sel
  `synco-ai-runtime/state-mac/v1`, info `file:<nom>`) du matériel de `keys.sealed` (`RuntimeKeys::to_secret_bytes`) : une clé par
  fichier, jamais écrite. Aucune dépendance nouvelle (`hmac`/`hkdf` étaient déjà derrière `synco-e2ee`). MAC invalide, fichier modifié
  ou illisible : registre/file **vide**, fichier mis de côté en `.rejected`, alerte `created_threads_tampered` /
  `envelope_repairs_tampered`, le runtime continue. Fichier sans MAC (ancien
  format de L08b) : refusé comme altéré, **pas de lecture de l'ancien format** (PC43, décision de l'utilisateur : L08b n'a jamais
  été livré, la règle de rétrocompatibilité ne s'applique pas ; sinon qui écrit dans `state_dir` ferait adopter un fichier nu).
- **Constat 5** (`c66678b`) : l'écriture du registre ne tient plus le verrou d'état (photo `Snapshot` sous le verrou, écriture par
  `spawn_blocking`, comme `member_pins` ; échec : alerte `created_threads_not_saved`).
- **Constat 7** (`c66678b`, revu) : au désappairage, la mémoire est oubliée **d'abord** (org, coffre, autorisations, registre et file
  en mémoire : cela ne peut pas échouer), puis les fichiers sont effacés ; seul cet effacement est retenté toutes les 5 s
  (`erase_state_files`). Une seule alerte `unpair_erase_failed` tant que l'échec persiste (ré-armée au succès) et un
  `tracing::error` à débit limité (`LogGate`) : l'anneau de 100 alertes n'est pas saturé.
- **Constat 4** : une rafale de trames est bornée (une seule file, un travailleur, quatre appels de front) ; journaux à débit limité
  (une ligne par code et par fenêtre de 10 s, avec le nombre de lignes tues : `LogGate`).
- **Constat 8** (`4fcd10d`) : `api_code` journalisé restreint à `[a-z_]`, 48 caractères (`ApiError::loggable_code`).
- **Constats 2 et 3** (`d9182d9`) : vecteur « repose avec délégation renouvelée » (`crates/supervisor/tests/fixtures/repose-delegation-renouvelee.json`),
  relu par `verifyRt1Envelope` de synco_app (section 4 de `read-from-worker.ts`) et par un test Rust ; le mock de l'API compare la signature.
- **Constat (c)** : commentaire du journal L08b corrigé (écart 4 ci-dessus).

**PC32 — salons créés avant L08b : non réparables, à ne pas corriger.** Le registre n'existe que depuis L08b : un salon créé par
ce runtime avant L08b n'y figure pas, et sa réinitialisation est ignorée (`envelope_reset_foreign_thread`) ; la file ne les accepte
pas non plus. Aucun mécanisme de rattrapage n'est prévu (décision de l'utilisateur, 2026-11-21) ; aucun déploiement n'est concerné
à ce jour. PC35 : ce mécanisme servira au « mode autonome » ; la politique de mode viendra d'un lot ultérieur, le comportement par défaut est inchangé.

**Mutations faites** : MAC non vérifié (`valid = true`) → `registre_altere_ne_fait_rien_signer` échoue ; concurrence non bornée
(`buffer_unordered(64)`) → `rafale_de_trames_bornee` échoue. Le contrôle du registre dans `submit_repair` n'est qu'un filtre d'entrée.
Celui de `try_repair` est **la seule barrière** pour une file relue du disque, ou quand le registre est déclaré altéré au
redémarrage alors que la file scellée est valide : testé par `file_valide_mais_registre_altere_ou_sans_entree_ne_signe_pas`.

**Non vérifié / recette manuelle** : la relecture contre la **vraie** route L03f (forme `{ items, nextCursor }` prise du lot) ; le
comportement de la file sur un vrai redémarrage de service systemd.

## 2026-11-21 — L08c bis : corrections de la revue de sécurité de L08c

À la suite de `0899667`. `fmt`, `clippy -D warnings` et `cargo test --workspace` avant chaque commit.

- **PC43** : plus aucune lecture de l'ancien format non scellé de `created_threads.json` (`Loaded::Legacy` retiré, paramètre `legacy`
  de `load` supprimé) ; un fichier sans MAC est rejeté comme altéré (alerte, registre vide, aucune signature). L08b n'ayant jamais été
  livré, la rétrocompatibilité ne s'applique pas. Le test de migration est remplacé.
- **Garde de `try_repair`** : seule barrière pour une file relue du disque ; testée (file valide, registre altéré ou sans l'entrée).
- **File non saturable** : dédupliquée sur (salon, utilisateur), dernière délégation reçue ; une délégation différente de celle du
  coffre pour cet utilisateur est abandonnée.
- **Désappairage** : mémoire oubliée d'abord, seul l'effacement des fichiers est retenté ; une alerte `unpair_erase_failed`, journal limité.
- **MAC lié à l'org** : l'org est dans le fichier et couverte par le MAC ; rejet à l'appairage si elle diffère.
- **Relecture API** : plafond sur les items entrés dans la file (pas les refusés), borne de 1 000 pages ; page vide suivie.
- **Limite connue** : une trame à délégation inventée reçue en dernier remplace la vraie dans la file ; la relecture API à la
  reconnexion la redonne.

## 2026-11-21 — L00f : spec figée du plan d'action, du mandat v2, du mode autonome et des politiques d'org

Source : conception C1 (validée par l'utilisateur) et PC34 à PC43. Documentation et vecteurs seulement ; aucun code dans
`crates/`, aucune dépendance. Code lu pour ancrer routes et modèles : `synco_api` (`aiRuntimeDelegations.ts`,
`runtimeInternal/e2ee.ts`, `threadEnvelopeReset.ts`, `conversationTools.ts`, `runtimePolicy.ts`, `toolRegistry.ts`,
`validators/index.ts`, `schema.prisma`), `synco_app` (`runtimeDelegation.ts`, `crypto.ts`, `OrgAI.vue`, `fileActions.ts`),
`crates/worker/src/tools/mod.rs`.

- **Nouveau document** `docs/plan/12-plan-action.md` : format du plan (JCS, `gcm1:` sous `CK`, AAD `sessionId:planId:plan`,
  stockage dans `pendingToolCall`), types d'action v1 (`thread.create`, `folder.create`, `file.create_text`, `server.call`)
  avec `args` stricts et exécutant par mode, validation (`plan_invalid`), cascade (PC37), états et délais, exécution par
  l'appareil puis par l'agent, verrou `action_not_accepted` (PC38), éléments `plan_decision` / `plan_result`, conditions
  `auto`, politiques v1 (PC39, PC40, PC42), routes utilisateur, du canal et des politiques, codes, répartition par lot.
- **Mis à jour** : 00 (décisions PC34 à PC43, glossaire), 03 (§4.1 mandat v2 et lecture du v1, mandat servi, raison
  `autonomy_withdrawn`), 04 (routes des plans, verrou, conditions `auto`, route `envelope-resets` de L03f désormais
  documentée), 07 (champs du mandat v2, `AiActionPlan`, `AiFeaturePolicy*`, `AiFeatureOptIn`, `AiFeaturePolicyEvent`,
  passes de maintenance), 08 (transitions du plan, pause au retrait, `plan_limit`), 09 (limites), `vectors/README.md` (§4).
- **Vecteurs** `docs/plan/vectors/mandate-v2.json` (21 cas de mandat, 6 cas `rt1Policy`) et `action-plan.json` (10 cas de
  chiffrement, 29 de validation, 6 de cascade, 2 d'échec, 1 condensat). Code jetable hors du dépôt (`~/.cache`, supprimé) :
  signatures (RFC 6979) et chiffrés produits par la crate `synco-e2ee` ; octets signés et JSON canonique écrits en TS.
  **Revérifiés des deux côtés** : TS (WebCrypto, `verifyMandateOfflineFromWrapHash`, `decryptAiField` de `synco_app`,
  validateur de référence pour validation, cascade et échec) et Rust (relecture du fichier final : 23 et 13 vérifications,
  `verify_mandate_offline_from_wrap_hash`, `EcPublicKey::verify`, `decrypt_field`, `serde_json` = JCS). Clés de test
  générées pour l'occasion ; hook `check-secrets` passé.
- **Lecture de C1** : ses propositions marquées « on propose » (fusion du mode dans le mandat v2, route d'enveloppe du
  créateur, `autonomy.allowed`) sont prises comme validées avec C1, comme l'indique le lot.
- **Questions ouvertes** (12 §15) : QP1 ordre d'exécution d'un plan mixte appareil / agent ; QP2 condensat `serverDigests`
  et `argsRefs` ; QP3 mécanique de la pause au retrait (PC40) ; QP4 écart entre la clé RSA servie du propriétaire et
  `ownerRsaSpkiHex` ; QP5 détails fixés par analogie (JCS entiers, AAD de `plan_result`, sens d'« activé » par
  fonctionnalité, actions sensibles avant L14, journal sans purge…). Le texte qui en dépend est marqué « provisoire ».
- **Non vérifié** : aucun code n'implémente encore ces formats ; les cas de validation, de cascade et d'échec ne sont
  contrôlés que par un validateur jetable. Lots débloqués après validation par l'utilisateur : L01c, L03g, L03h (en
  parallèle), puis L08d.

## 2026-11-21 — L00f, amendement : questions QP1 à QP5 tranchées (PC44 à PC48)

Décisions de l'utilisateur prises après la livraison de L00f. Documentation et vecteurs seulement ; aucun code dans
`crates/`, aucune dépendance. À la suite de `3968a8d`.

- **PC44 (QP1) : ordre libre**, contraire de la recommandation « appareil d'abord ». 12 §8.1 : phases calculées de façon
  déterministe (phases impaires d'appareil, paires d'agent ; une action se place dans la première phase de son exécutant
  qui suit toutes ses dépendances ; à égalité l'appareil commence ; renumérotation si aucune action n'est en phase 1),
  sur le plan entier avant décision ; phase vide sautée. Phase d'appareil : claim `{ deviceId, phase }` (un seul
  appareil), `plan_result:<k>` partiel (id `plan:<planId>:<k>`, AAD `sessionId:planId:plan_result:<k>`). Phase d'agent :
  le worker exécute puis dépose `plan_agent_result:<k>` (AAD `…:plan_agent_result:<k>`) par la nouvelle route
  `POST …/plans/:planId/agent-result` ; la conversation repasse `awaiting_confirmation` avec push. Expiration du plan
  entier : aucune phase ne démarre après `expiresAt`. Échec ou `unknown_outcome` : toute la suite `skipped`, toutes
  phases. Nouveaux codes `plan_phase_mismatch`, `action_output_missing`. `PlanView` porte exécutant, phase, état et
  sortie par action, `currentPhase` et `agentResults`.
- **PC47 (QP2)** : condensat de `JCS({tool, args, argsRefs})`, `argsRefs` omis s'il est absent ; appel avec `args` non
  résolus, `argsRefs` et `refs`. **Références vers l'appareil** (12 §8.5) : l'API enregistre elle-même la sortie
  (`id`, `spaceId`) quand sa route de création reçoit `X-Synco-Plan: <planId>/<n>` pour une action en cours sous claim ;
  `progress done` l'exige. Rien de chiffré n'est lu ; fuite résiduelle assumée : le lien objet ↔ action de plan.
  Double contrôle : le worker et l'appareil comparent les résultats de phase déchiffrés aux sorties enregistrées.
- **PC45 (QP3)**, **PC46 (QP4)** : recommandations adoptées (12 §11.4, §10.3 ; 03, 07, 08). **PC48 (QP5)** : détails
  ratifiés, sauf `AiFeaturePolicyEvent` conservé 1 an avec purge bornée (07 §9, passe `purgeFeaturePolicyEvents`).
- **Mis à jour** : 12 (§1, §4 à §9, §10.3, §11, §12, §14 à §16 ; marques « provisoire » retirées), 00 (PC44 à PC48,
  glossaire), 03, 04, 07, 08, 09, `vectors/README.md`.
- **Vecteurs** `action-plan.json` complétés : `plan_result` partiel de phase 1, `mixedPlan` (deux phases d'appareil,
  deux d'agent, avec `plan_result:1`, `plan_agent_result:2`, `plan_result:3`), condensats PC47, `executeCases` (10),
  `phaseCases` (9), `runCases` (7), 18 cas de chiffrement, 31 de validation. Code jetable (`~/.cache`, supprimé) :
  chiffrés par `primitives::seal` de `synco-e2ee` (IV figé). **Revérifiés** : Rust, fichier final relu, 47 vérifications
  (`session::decrypt_field`, `serde_json` = JCS, condensats, phases, verrou) ; TS, 94 vérifications (`decryptAiField` de
  `synco_app`, WebCrypto, validateur de référence pour validation, phases, cascade, échec, déroulé). CK de test.
- **Choix d'interprétation à confirmer** : « un échec propage la cascade » est lu comme l'arrêt de toute la suite (règle
  existante du §7.3, plus strict que les seules dépendantes) ; un message de l'utilisateur entre deux phases clôt le plan
  (`rejected`, ce qui est fait reste fait) ; un plan expiré en attente d'appareil donne `confirmation_timeout`.
- **Reste ouvert** (12 §15) : `thread.create` du runtime en mode autonome n'a pas de condensat (C1), ses références ne
  sont donc pas recontrôlées par l'API.

## 2026-11-21 — L00f, second amendement : graphe, parallélisme, échec limité, arrêt du plan (PC54 à PC58)

Documentation et vecteurs seulement ; aucun code dans `crates/`, aucune dépendance. À la suite de `9867ebc`.

- **PC54** : un échec (ou `unknown_outcome`) n'ignore que les dépendantes transitives (`after`, qui couvre `argsRefs`) ;
  le reste continue, sur les deux exécutants. Statut final calculé : `failed`, sinon `interrupted`, sinon `done`.
- **PC55** : après l'acceptation, un message ne change pas l'état de la conversation et il est traité au tour qui suit
  la clôture de `propose_actions`, pas à la phase d'agent suivante (le `tool_result` doit précéder le nouveau message).
  Arrêt : `POST …/plans/:planId/stop`, statut `stopped`, élément `plan_decision` `stop`. Expiration d'un plan accepté :
  `queued` et clôture avec le bilan ; `failTimedOutWaits` ne s'en charge plus.
- **PC56** : `AiActionPlanAction.output` (lien objet ← action) effacé dans la transaction de clôture, passe de
  rattrapage `purgeClosedPlanLinks` ; doublon journalisé sans identifiant d'objet ; catalogue RGPD en 07 §11 (aucun
  catalogue général n'existait).
- **PC57** : risque accepté, 12 §10.6 et §15.
- **PC58** : `after` = `needs` (nom gardé), `groups` / `group`, `category.create` et `categoryId` pour le cas de
  l'utilisateur ; niveaux ; actions prêtes en parallèle (concurrence 4, maximum 8, des deux côtés), plus petite `n`
  d'abord ; `progress` rejouable ; `429` : 3 nouveaux essais, concurrence divisée par 2 ; une ligne
  `AiActionPlanAction` par action (transitions concurrentes sans perte) ; consigne de l'outil `propose_actions` (12 §3.1) ;
  présentation en graphe pour L12 (12 §17). **Ajustement signalé de PC44** : les phases précalculées alternées
  sérialisaient des branches indépendantes ; elles deviennent dynamiques (une séance par exécutant, numérotée par
  exécutant, qui peut chevaucher celle de l'autre). L'API reçoit `executor` et `after` (graphe sans contenu).
- **Vecteurs** : `categoryPlan` (3 catégories puis 9 salons : niveaux, vagues, ordre valide avec concurrence 4, échec de
  la catégorie 2 → ses 3 salons seuls ignorés), `levelCases`, `runCases` simulés, `failureCases` selon PC54, résultats de
  phase renumérotés par exécutant, 7 cas de validation. Code jetable supprimé ; revérifiés en Rust (66, dont
  `session::decrypt_field`) et en TS (104, dont `decryptAiField` de `synco_app`).
- **À valider par l'utilisateur** : le nouveau `kind` `category.create` (non listé jusqu'ici, nécessaire au cas
  demandé) ; les valeurs de concurrence et de nouveaux essais.

## 2026-11-21 — L00f, dernier ajustement (PC59 à PC62)

PC59 (`category.create`, `categoryId`), PC60 (concurrence 4 / 8, 3 nouveaux essais sur `429`) et PC62 (bilan à
l'expiration d'un plan accepté) validés tels quels. **PC61** : plan de 100 actions au plus (était 20), 2 000 entrées
d'`after`, clair ≤ 256 Kio, corps de `POST …/plans` ≤ 1 Mio, `plan_too_large` rendu au modèle qui découpe (consigne de
12 §3.1), groupes 1 à 50 repliés par défaut au-delà de 30 actions (12 §17). Vecteurs : cas à 100 / 101 actions,
2 000 / 2 001 dépendances, 65 Kio / > 256 Kio ; revérifiés en Rust (71) et en TS (107), code jetable supprimé.

## 2026-11-22 — L01c, mandat v2 et fonctions pures du plan d'action (Rust et TS)

- **Rust** (`synco-e2ee`) : `delegation` lit le mandat v1 (comme `plan`) et v2 (`verify_mandate_versioned*`,
  `accept_delegation_versioned`, `rt1_verdict`) ; nouveau module `plan` : `jcs` (tri UTF-16, entiers sûrs), AAD
  `plan` / `plan_result:<k>` / `plan_agent_result:<k>` (`FieldName::Plan`, `PlanResult`, `PlanAgentResult`),
  chiffrement sous `CK` avec recontrôle du clair, `server_digest` et `check_server_call` (verrou de 12 §8.4),
  `validate_plan` (règles 1 à 6, bornes PC61, motif `detail`), `PlanGraph` (niveaux, cascade, règle 8) et `PlanRun`
  (actions prêtes, échec limité aux dépendantes, arrêt, expiration, statut). Codes `plan_invalid`,
  `action_not_accepted`.
- **TS** (`synco_app`) : mêmes fonctions dans `runtimeDelegation.ts` (mandat v2) et `aiActionPlan.ts` ; vecteurs
  copiés à l'identique dans `scripts/e2ee-vectors/`.
- **Vecteurs** : `mandate-v2.json` (21 cas de mandat, 6 `rt1Policy`) et `action-plan.json` (107 vérifications)
  rejoués des deux côtés ; le test croisé `read-from-worker.ts` relit aussi le plan, `plan_result` et le mandat v2
  avec le code de l'app.
- **Interprétations** : délai de l'org fourni par l'appelant (vecteurs : 604 800 s) ; longueurs de chaînes en points
  de code ; manifeste lu en JSON Schema ou sous la forme abrégée des vecteurs ; extensions de `file.create_text`
  recopiées de `textFileFormats.ts` (à garder synchronisées) ; la règle 7 (annuaire local) reste à L10.

## 2026-11-22 — L01c, constats mineurs de la revue cryptographique

Rust et TS rendent le même verdict sur les mêmes octets ; règle la plus stricte retenue à chaque écart.

- **Nombres** : `decrypt_plan` / `decrypt_phase_result` refusent (`field_invalid_json`) un clair que JCS refuserait
  (`1.0`, `1e2`, `-0`, entier hors de 2⁵³ − 1) ; l'app a un parseur strict (`parseJsonStrict`).
- **Unicode** : demi-paires (`"\ud800"`, `"\udc00"`) et BOM initial refusés des deux côtés.
- **`__proto__`** : clé ordinaire dans les arguments exécutés de `check_server_call` / `checkServerCall`.
- **Extension** de `file.create_text` : pliée en minuscules ASCII seulement des deux côtés.
- **PC61** : valeur `gcm1:` bornée à `MAX_PLAN_VALUE_LEN` = 5 + 4·⌈(12 + 262 144 + 16) / 3⌉ = 349 569 octets
  avant base64, AES-GCM et JSON ; actions (> 100) et dépendances (> 2 000) comptées avant JCS.
- **Résultats de phase** : `encrypt_phase_result` / `decrypt_phase_result` prennent le `PlanGraph` ; chaque `n`
  appartient au plan et à l'exécutant de l'AAD, état final exigé.
- **`rt1_verdict`** : paramètre `production` (défaut `true` côté app) ; un mandat v1 y est `rejected`,
  `tofu_warning` hors production seulement.
- **Identifiants** : `check_id` en tête de `decrypt_field`, `decrypt_plan`, `decrypt_phase_result`
  (`invalid_input` avant l'AAD) ; le cas « séparateur | » de `conversation-fields.json` attend `invalid_input`.
- **Vecteurs** : `action-plan.json` passe de 107 à 143 vérifications (sections `clearCases`, `boundCases`, plus
  des cas de validation, de chiffrement et du verrou) ; `mandate-v2.json` à 8 cas `rt1Policy`. Rejoués en Rust et en
  TS, test croisé OK.

## 2026-11-22 — L08d, plans d'action côté runtime (superviseur et worker)

- **Superviseur** : le coffre garde le mandat **vérifié** (`accept_delegation_versioned`, champs servis
  `mandateVersion` / `mode` / `ownerRsaSpkiHex` de `DelegationRecord` utilisés seulement pour reconstruire les
  octets signés). `init.plan` (`PlanInit`) donne au worker le mode effectif (`auto` seulement pour un mandat v2
  `auto` et `autonomy.allowed`), `plan.concurrency` ([1, 8], défaut 4, refus au démarrage hors intervalle) et
  `confirmationTimeoutSecs` de l'org (borné [1 h, 7 j]). `created_key` et la réparation `repose` exigent un mandat
  v2 `auto` vérifié (`autonomy_required` ; la réparation reste dans la file) ; `autonomy.allowed = false` traite
  tout `auto` comme `plan` et lève l'alerte `autonomy_disabled_by_config`. PC46 : pour un mandat v2,
  `ownerRsaSpkiHex` prime sur l'épingle TOFU de `member-rsa-pins.json` (clé servie différente : `member_key_changed`
  et alerte `member_rsa_key_changed`, sans rotation par chaîne). Trame client `plan_result` (WebSocket).
- **Worker** : `propose_actions` (description de 12 §3.1 reprise telle quelle) ; plan construit, validé (règles 1 à 6,
  bornes PC61, outils `deny` refusés) et chiffré avec les fonctions de `synco-e2ee` ; écriture par `POST …/plans`
  (corps : dates ISO 8601, `actions: [{ n, executor, after }]`, `serverDigests`) ; `pendingToolCall.planId` et
  plan chiffré sous l'AAD du plan (lecture stricte, rejoué sous un autre `planId` refusé). En mode `plan`, le modèle
  ne voit plus les outils mutants `ask` ni ceux d'appareil. Reprise : l'état se relit **toujours** dans `PlanView` ;
  phase d'agent en parallèle (`JoinSet`, plus petite `n` d'abord, place reprise aussitôt), `429` réessayé 3 fois
  (1, 2, 4 s ± 20 %) avec concurrence divisée par 2, `refs` résolues depuis les sorties des `plan_result`
  déchiffrés (authentifiées par `CK` pour l'appareil) et des `plan_agent_result` relus, comparées à celles de l'API ;
  les `refs` venues d'une action d'**agent** ne sont pas authentifiées : elles reposent sur les réponses de l'API
  (§8.5), le chiffrement sous `CK` ne protège que le contenu au repos. `plan_agent_result:<k>`,
  fermeture avec le bilan (état, sortie, code), message reçu pendant un plan accepté différé jusqu'à la fermeture,
  `confirm` visant `propose_actions` ignoré, arrêt (`stopped`) et expiration (aucune action ne démarre), 3 plans par
  tour (`plan_limit`), `thread.create` du mode autonome par `POST /e2ee/threads` avec `plan`.
- **Tests** : 13 tests `crates/worker/tests/plan.rs` (API simulée qui tient le graphe, les états, les sorties et le
  verrou avec les vraies `check_server_call` / `plan_server_digests`), 3 tests de superviseur (`created_key`, réparation,
  épingle PC46), config, trame client, transcript, `with_local`, identifiants de boîte. Test croisé TS : OK.
- **Écarts et ambiguïtés de la spec (choix provisoires)** :
  1. **Aucune route ne permet au worker de faire échouer une action d'agent qui n'est pas partie** (`429`
     épuisé, issue inconnue, `refs` incohérentes, refus du verrou) : l'API la garde `pending` et refuse
     `agent-result` (action prête). Choix : issue **locale** (`PlanView::with_local`, dépendantes `skipped`, PC54) ;
     si le plan est fini ainsi, `propose_actions` est clos avec ce bilan, sinon il est clos `plan_aborted` (détail :
     `refs_inconsistent`, `action_not_accepted`…). Le plan reste côté API jusqu'à `expiresAt`. À trancher avec L03g
     (route ou tolérance d'`agent-result`).
  2. Aucun en-tête `Retry-After` n'arrive au worker (le relais ne rend que `content-type`) : délais 1, 2, 4 s.
  3. Le worker pousse `AI_AWAITING_CONFIRMATION` après `POST …/plans` ; si l'API le fait déjà, doublon à retirer.
  4. `refs` ou plan incohérent à la reprise (résultat de phase illisible, graphe servi différent) : `tool_call_unverified`.
  5. Le mode (`init.plan.mode`) est celui de la délégation au lancement du worker ; un changement en cours de
     route n'est vu qu'au prochain lancement (une action `thread.create` d'agent hors `auto` échoue `autonomy_required`).

## 2026-11-22 — L03g, revue de sécurité : décisions PC69 et PC70 reportées dans la spec

Docs seulement (aucun code runtime).

- **PC69** : la décision de l'utilisateur porte, pour chaque action `server.call` acceptée, l'empreinte recalculée par
  l'app depuis le plan déchiffré (`JCS({tool,args,argsRefs})`) ; l'API refuse toute empreinte différente de
  `serverDigests` par `409 plan_digest_mismatch` ; `serverDigests` est exposé dans la vue du plan. Reporté en
  `12-plan-action.md` §8.4, §12.1, §14, §15 et dans la liste des décisions de `00-vue-ensemble.md`.
- **PC70** : un `cancel` de la conversation pendant un plan accepté vaut `stop` du plan (§7.1, §8.6) ; les actions
  d'appareil `executing` d'un plan `stopped` passent `unknown_outcome` par la maintenance de l'API après le délai des
  actions d'agent.
- Conséquence pour L01c / L08 / L12 : l'app (L12) doit recalculer et envoyer les empreintes à la décision.

## 2026-11-22 — L08d, corrections de la revue de sécurité et abandons (PC74)

Un commit par point, chacun avec un test qui échoue sans lui.

- **Bloquants** : (1) `agent_phase` part de la vue superposée dès l'entrée : une action déjà `failed` /
  `unknown_outcome` sur place ne repart plus après un `Retry` (08 §5) ; (2) le résultat d'agent reprend toutes les
  actions d'agent devenues finales et absentes des `plan_agent_result` déjà déposés (relus à chaque reprise), et le bilan
  retrouve leurs sorties (celles de la vue de l'API pour une action exécutée juste avant une reprise) ; (3) PC70 : un
  `cancel` arrivé pendant un plan non `proposed` est consommé (la conversation n'est pas annulée), la vue (`stopped`)
  est relue et `propose_actions` est clos avec le bilan.
- **Importants** : (4) `plan_result` d'un autre `planId` consommé et ignoré (`stale_decision`), seule une AAD fausse sur
  le même plan donne `tool_call_unverified` ; (5) cascade `skipped` locale jusqu'au point fixe, dans l'ordre de `n` ;
  (6) un outil `ask` masqué par le plan (ou d'appareil) que le modèle appelle quand même est refusé
  (`use_propose_actions`), jamais de confirmation outil par outil.
- **Mineurs** : (7) `created_key` refuse (`autonomy_required`) sans délégation vérifiée avant de consommer
  `created_threads` (`is_none_or`) ; `delegation_unavailable` n'y est plus atteint dans ce cas ; (8) `graph_from` : l'exécutant
  de `thread.create` est `device` en mode `plan`, `agent` seulement en `auto` (le mode est celui de `init.plan`, vu au
  lancement ; un plan `auto` repris par un worker `plan` devient `tool_call_unverified`, plus `autonomy_required`) ;
  (9) formulation corrigée plus haut : les `refs` d'une action d'agent reposent sur les réponses de l'API (§8.5) ;
  (10) `Retry-After` : le superviseur le relaie (secondes entières seulement, en-tête `retry-after` de
  `signed_request_response`), le worker l'attend plafonné à 30 s (sinon 1, 2, 4 s ± 20 %) pour les `429` de
  `server.call` ; le `429` de `thread.create` (route `/e2ee/threads`, passe par `tools::threads`) garde 1, 2, 4 s.
- **Abandons (PC74)** : spec amendée (12 §8.3 étape 3, §8.7, §9, §12.2, §14, §15 ; 00 : ligne PC74). Choix de
  rédaction : les abandons figurent dans `outcomes` du `plan_agent_result` chiffré sous la forme `{ n, state, code }`
  (`code` accepté par `check_phase_result`, seulement avec `failed` / `unknown_outcome`, jamais avec `output`) ;
  `value` est facultatif seulement si les abandons rendent le plan terminal, et rangée si elle est donnée. Vecteurs :
  `abandonCases` (8 cas, rejoués par `PlanRun::abandon`, nouvelle fonction pure de `synco-e2ee`) dans
  `action-plan.json`. **Runtime** : `agent-result` porte `abandoned` ; sont abandonnées les actions locales
  `failed` / `unknown_outcome` que l'API garde `pending` : `rate_limited`, `refs_inconsistent`, `autonomy_required`,
  `action_not_accepted` (verrou refusé, ou erreur de préparation hors liste), `key_unavailable` ; une issue inconnue
  sans code propre est déclarée `unknown_outcome` avec `action_not_accepted` (la liste fermée n'a pas de code adapté) ;
  `tool_call_unverified` abandonne toutes les actions d'agent `pending` (`action_not_accepted`) avant la clôture.
  La fin du plan ne se décide plus que sur la vue de l'API (`with_local` ne sert plus qu'à ne jamais relancer une
  action et au bilan) ; réponse `200 { status }` terminale : relecture puis bilan. `plan_aborted` reste pour un
  plan introuvable ou expiré, une incohérence d'état de l'API (`plan_phase_mismatch`…) et une issue locale sans code
  déclarable. Les écarts 1, 2 et 4 de l'entrée L08d précédente sont ainsi levés (API à adapter : faux serveur
  de `tests/common/mod.rs` en attendant).
- **Ouvert** : l'API (`abandoned`, `code` dans `outcomes`) et synco_app (`aiActionPlan.ts` : `code` accepté dans les
  résultats de phase) doivent suivre ; plan non terminal après `tool_call_unverified` (branche d'appareil `pending`) :
  il reste jusqu'à `expiresAt` ; le `429` de `thread.create` ne relaie pas `Retry-After`.
- **Vérifié** : `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace` : 305 réussis, 10 ignorés (hôte) ; test croisé TS `read-from-worker.ts` : OK.
