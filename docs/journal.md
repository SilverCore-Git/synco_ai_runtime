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
