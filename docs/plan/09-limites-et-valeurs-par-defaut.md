# 09 — Limites et valeurs par défaut

Propositions chiffrées pour les décisions ouvertes **D4** (durée des délégations) et **D6** (plafonds),
plus les autres bornes de la spécification. Toutes les valeurs sont réglables dans la configuration du
runtime (L05) ; celles marquées « org » peuvent aussi être **abaissées** par l'org (`aiConfig.runtime`,
07 §6), jamais relevées au-delà de la configuration du runtime.

## 1. D4 — Durée d'une délégation

| Option | Défaut | Maximum | Conséquence |
|---|---|---|---|
| **A. 7 jours, renouvelée à l'ouverture** (recommandée) | 7 j | réglable par l'admin de 1 h à 30 j (`maxDelegationDays`, org) ; plafond du runtime 30 j | Une conversation lancée le vendredi continue le week-end. Un utilisateur qui n'ouvre plus Synco pendant 7 jours perd l'arrière-plan (ses conversations repassent en local, 08 §3). |
| B. 24 heures | 24 h | 7 j | Fenêtre d'exposition plus courte ; mais une absence d'un jour arrête les conversations de fond, ce qui va contre l'objectif « fermer Synco, revenir plus tard ». |
| C. 30 jours | 30 j | 90 j | Confort maximal ; un appareil temporaire qui garde un mois de clés (et de capacité d'agir) sans contrôle. |

Règles communes, quelle que soit l'option :

- **Renouvellement** (03 §7.2) : à l'ouverture de l'app déverrouillée et toutes les 6 h tant qu'elle
  reste ouverte, si la durée restante est inférieure à **50 %** de la durée ; nouvelle délégation
  complète (nouvelle `DK`, nouvel `exp`).
- **Durée minimale** : 1 h (en dessous, l'API refuse : `delegation_invalid`).
- **Horloge** : `|iat − maintenant| ≤ 300 s` au dépôt.
- Ce que fixe la spec selon l'option : la valeur par défaut de `maxDelegationDays` (07 §6), le
  plafond du runtime (`max_delegation_days`), le contrôle `exp − iat` (API au dépôt, runtime à
  l'ouverture, 03 §4), et `AiSessionAuthorization.expiresAt` (= expiration de la délégation).

**Recommandation** : A (7 jours, admin libre entre 1 h et 30 jours).

**Effet d'une baisse de `maxDelegationDays` (révisé après L03c, 2026-11-20 ; Q14 b = B, 00 §5)** : le
maximum est contrôlé **au dépôt** (API) et à l'ouverture (runtime) ; abaisser `maxDelegationDays`
**n'écourte pas** les délégations existantes, qui courent jusqu'à leur `exp` (≤ 30 j). Pour couper
tout de suite : révoquer une délégation ou toutes (03 §8.1). À documenter dans l'écran admin (L11).
Source : `SYNCOAI_REFONTE_FEATURE.md` §13.5, §13.7.

## 2. D6 — Plafonds du worker et du runtime

| Plafond | Valeur proposée | Portée | Où appliqué | Justification |
|---|---|---|---|---|
| `maxStepsPerTurn` | **25** appels au fournisseur par tour | org | worker | La boucle locale s'arrête à 8 (`clientAgent.ts:46`) : trop court pour un travail de fond ; 25 couvre une recherche + plusieurs outils. Atteint → `idle` + `step_limit`. |
| `maxTokensPerConversation` | **2 000 000** tokens (entrée + sortie, cumulés) | org | worker | Garde-fou de coût ; ~ quelques euros sur un modèle cloud courant. Atteint → `failed` `budget_exceeded`. |
| `maxTokensPerTurn` | **300 000** | org | worker | Évite qu'un seul tour consomme tout le budget. |
| `maxTurnDurationSecs` | **1 800** (30 min) | org | worker | Au-delà → `failed` `turn_timeout`. |
| `maxOutputTokensPerCall` | **4 096** | org | worker | Comme le plafond du relais de l'API (`aiProxy.ts:144`). |
| `maxToolResultBytes` | **256 Kio** (tronqué au-delà, avec mention) | runtime | worker | Protège le contexte du modèle et la taille de l'historique. |
| `idleShutdownSecs` | **60 s** | runtime | superviseur | Le worker ne vit que lorsqu'il travaille (P3) ; 60 s évitent de relancer pour un message tapé juste après. |
| Workers simultanés par utilisateur | **3** | org | superviseur | Au-delà, la conversation reste `queued`. |
| Workers simultanés par runtime | **8** par défaut ; recommandé : ⌊RAM libre × 0,6 / 512 Mio⌋ | runtime | superviseur | Dimensionnement à ajuster avec la mesure de L06. |
| RAM par worker (`memory.max`) | **512 Mio**, `memory.max` seul (**D6 révisée le 2026-11-21** : `memory.high` retiré, Q22 tranchée ; 10 §5) | runtime | cgroup (L06) | Un worker = boucle + client HTTP + historique en mémoire ; la recherche sémantique locale (Q6) peut demander plus : à mesurer. Dépassement → OOM de **ce** worker seul. |
| CPU par worker (`cpu.max`) | **1 CPU** (`100000 100000`) | runtime | cgroup | Le travail est surtout de l'attente réseau. |
| Process par worker (`pids.max`) | **64** | runtime | cgroup | Empêche les bombes de fork. |
| Durée d'un appel au fournisseur | 120 s sans octet reçu ; 10 min au total | runtime | worker | |
| Bail (`LEASE_MS`) | **60 s**, renouvelé toutes les 20 s | — | API / worker | Relance après plantage en ≤ 60 s. |
| Tampon de reprise (05 §3) | **2 000** évènements ou **4 Mio** par conversation | runtime | superviseur | |
| `signed_request` du worker | 20 / s, rafale 50 | runtime | superviseur | |
| Mandataire LLM (L06) | corps ≤ 8 Mio ; 4 connexions par worker ; 2 appels / s (rafale 5) par worker, 20 / s (rafale 40) pour le runtime ; quotas d'appels et de tokens par tour et par conversation | runtime | superviseur | Application de D6 par le mandataire, détail et codes `proxy_*` en 10 §4 |
| Réponse du fournisseur (L07) | texte + raisonnement ≤ **4 Mio**, arguments d'outils ≤ **1 Mio** (`LlmError::TooLarge`, sans nouvel essai, `failed` `provider_error`) | runtime | worker | 06 §9 |
| `create_thread` (L07) | 10 salons par appel, **300** destinataires de clé RSA par salon (`too_many_recipients`), clé RSA ≥ 2048 bits ; 32 clés signées par worker (`created_key_limit`) | runtime | worker, superviseur | 04 §4.3 (corps ≤ 256 Kio), 06 §3.3 |

**Recommandation** : ces valeurs, à revoir après les mesures de L06 (coût d'un worker vide, temps de
lancement) et les premiers essais de L07.

## 3. Délais d'attente (révisé après L03c/L05, 2026-11-20 ; après L03d, 2026-11-21)

| Attente | Délai | Au-delà |
|---|---|---|
| `awaiting_confirmation`, `awaiting_user` | **7 jours** par défaut, abaissable par l'org (`limits.confirmationTimeoutSecs`), **dans [1 h, 7 j]** | `failed` `confirmation_timeout` (08 §2) — dépend aussi de D5 |
| `awaiting_key` | **7 jours** par défaut, abaissable par l'org (`limits.keyTimeoutSecs`), **dans [1 h, 7 j]** | `failed` `key_timeout` |
| `queued` (runtime hors ligne) | aucun | reste `queued` ; affiché « runtime injoignable » |
| `hello` du WebSocket client | **5 s** (la spec proposait 10 s ; raccourci par L05 pour limiter les connexions inoccupées, `client_ws.rs:HELLO_TIMEOUT`) | fermeture `4408` |
| Inactivité du WebSocket client | 60 s sans trame reçue | fermeture `1000` `idle_timeout` (05 §6.3, §7) |

Réalisation (révisé après L03c, 2026-11-20 ; Q14 a = A) : l'API lit, pour chaque org,
`aiConfig.runtime.limits.confirmationTimeoutSecs` et `keyTimeoutSecs` (entiers, défaut **604 800**,
**abaissables seulement**, **plancher de 3 600 s**, même normalisation que les autres `limits`, 07 §6) ; la maintenance les
compare strictement à `statusChangedAt` par une passe toutes les 60 s (résolution = une passe, 07 §9) ;
politique illisible ou ancien format sans ces champs : 7 jours. Les champs figurent aussi dans
`GET /api/runtime/v1/llm-policy` (`runtime.limits`, 04 §4.1). Source :
`synco_api/src/services/aiRuntime/runtimeMaintenance.ts`, `runtimePolicy.ts`,
`SYNCOAI_REFONTE_FEATURE.md` §13.5. Les 7 jours de `WAIT_TIMEOUT_MS` ne sont plus que la valeur par
défaut. **Q19 tranchée par L03d (2026-11-21, PC21)** : une valeur valide sous 3 600 est **ramenée à 3 600**
(`RUNTIME_WAIT_TIMEOUT_MIN_SECS`), à l'écriture (`normalizeStoredRuntimePolicy`) **et** à l'application (la
maintenance reborne [1 h, 7 j] toute valeur lue, y compris une ancienne valeur en base) ; une valeur invalide
(< 1, non entière) donne le défaut de 7 jours. Source : `SYNCOAI_REFONTE_FEATURE.md` §14.6.

## 4. Débits et tailles

| Élément | Limite |
|---|---|
| Ticket | 2 048 octets ; `srt1` 300 s émis / 600 s max ; `sgt1` 300 s / 900 s max ; tolérance 30 s |
| `POST <url>/v1/challenge` | 10 / min par adresse IP, 60 / min au total |
| Canal interne (par runtime) | 50 requêtes / s, rafale 200 ; corps 256 Kio (8 Mio pour `PUT …/transcript`, 1 Mio pour `POST …/plans`, PC61) |
| Fenêtre des requêtes internes | ±60 s ; nonces gardés 120 s |
| Historique d'une conversation (`messages`) | 8 Mio sérialisés ; au-delà, refus d'écriture (`invalid_body`) et `failed` `internal` — compaction hors v1 |
| Entrées par délégation | 5 000 |
| Dépôt de délégations | 10 / h par utilisateur |
| Ajout d'entrées (client) | **3 requêtes / 15 s** par utilisateur (Q16 c, valeur réelle ; remplace « 1 / 5 s »), ≤ 500 entrées par requête |
| Trames WebSocket client | 256 Kio (client → runtime), 1 Mio (runtime → client) ; 20 trames / 10 s par connexion ; 5 connexions par conversation |
| Boîte de réception | 100 éléments non consommés par conversation ; 20 dépôts / 10 s |
| Notifications push | une par **entrée** dans l'état annoncé ; plafond de **6 / min** par conversation (`429 rt_rate_limited`) ; état non courant ou doublon : `202 { sent: false }` (04 §4.2 ; L03d) |
| `POST /metrics` | 1 / min |
| Trames du pipe | charge de 1 Mio (JSON), 64 Kio (clés) ; la longueur en tête compte le genre en plus (06 §1) |
| Synchro P11 (client) | regroupement 5 s ; backoff 30 s → 30 min ; 5 tentatives par session de l'app |
| Plan d'action (L00f, 12) | **100 actions**, 2 000 entrées d'`after` au total, clair canonique ≤ 256 Kio (262 144 octets), corps de `POST …/plans` ≤ 1 Mio ; au-delà `plan_too_large`, l'agent découpe (PC61) ; groupes : 1 à 50, repliés par défaut au-delà de 30 actions ; 3 plans consécutifs par tour (`plan_limit`) ; expiration = `confirmationTimeoutSecs` de l'org (7 j par défaut, [1 h, 7 j]) ; claim 5 min **par phase d'appareil**, prolongé par `progress` ; phases dynamiques, au plus 20 par exécutant, expiration commune au plan entier (PC44, PC58) ; concurrence : 4 actions en cours par défaut, 8 au plus, sur l'appareil (constante de l'app) comme chez l'agent (`plan.concurrency`, [1, 8]) ; `429` : 3 nouveaux essais au plus (`Retry-After` plafonné à 30 s, sinon 1, 2, 4 s ± 20 %), concurrence divisée par 2 ; `label` de groupe ≤ 100 (PC58) ; lien objet ↔ action effacé à la clôture, rattrapage de 1 000 lignes par passe (PC56) ; `expiresAt` contrôlé par l'API à `maintenant + délai + 300 s` au plus |
| Politiques d'org (L00f, 12 §11) | ajouts et retraits de membres : 1 à 100 par requête ; pages de 1 à 100 ; liste ≤ 1 000 membres (PC30) ; `AiFeaturePolicyEvent` conservé 1 an, purge bornée à 1 000 lignes par passe (PC48) |

### 4.1 Valeurs réelles après la vague B (révisé après la vague B, 2026-11-19 ; complété après L05, 2026-11-20)

Valeurs appliquées par le code (L02, L03, L03b, L04). Elles précisent ou remplacent la table
ci-dessus quand elles diffèrent ; un écart de fond est signalé en dernière colonne.

| Élément | Valeur réelle | Source | Écart avec la table |
|---|---|---|---|
| Échecs d'authentification du canal | 60 / min par adresse IP, avant vérification → `429 rt_rate_limited` | `runtimeAuth.ts:166`, `:321-350` | ajout |
| Lectures de corps non authentifiées | 8 simultanées par adresse IP ; 30 s par corps | `runtimeAuth.ts:169-170` | ajout |
| Débit par runtime | 50 / s, rafale 200 (seau à jetons, après signature) | `runtimeAuth.ts:167-168`, `:176-186` | — |
| Nonces | 120 s ; **8 000 par runtime**, jamais évincés (plein → `429 rt_rate_limited`) | `runtimeRequestSigning.ts:112-163` | remplace le cache global de 100 000 (04 §2.3) |
| Corps du canal | 256 Kio ; 8 Mio pour `PUT …/transcript` ; `POST /e2ee/threads` ≈ 300 destinataires RSA-4096 dans 256 Kio (le schéma HTTP en admet 500) | `runtimeAuthContract.ts:36-38`, `runtimeAuth.ts:88-93` | précision |
| Caches de l'API | runtime (`findRuntime`) et état IA de l'org : 5 s | `runtimeStore.ts:135-148` | ajout |
| Flux de notifications | trames ≤ 4 Kio ; ping 25 s, `pong` sous 60 s ; `presence` ≤ 1 / 30 s (sinon ignorée) ; 30 échecs de mise à niveau / min par adresse client ; `lastSeenAt` ≤ 1 / min sur `pong` | `runtimeStream.ts:90-104`, `:125-147` | précision |
| `POST /metrics` | 1 / min par runtime | `runtimeRouteDeps.ts:23-30` | — |
| Certificat | `issuedAt ≤ maintenant + 300 s` ; `1 ≤ serial ≤ 2³¹ − 1` | `runtimeRegistry.ts:40`, `:60-61` | ajout |
| Dépôt de délégations | 10 / h par utilisateur ; durée 1 h ≤ `exp − iat` ≤ `maxDelegationDays` ; horloge ±300 s ; `wrap` ≤ 4 096 caractères, entrée ≤ 256, signature du mandat 64 à 256 | `conversationRateLimit.ts:32`, `conversationValidation.ts:142-165` | — |
| Ajout d'entrées (client) | **3 requêtes / 15 s** par utilisateur, 1 à 500 entrées par requête ; 5 000 entrées par délégation | `conversationRateLimit.ts:34`, `conversationValidation.ts:142-143` | remplace « 1 requête / 5 s » (fenêtre glissante plus tolérante, même débit moyen) |
| Pagination | entrées de délégation : 1 à 500, 500 par défaut ; boîte : 100 par page ; messages d'un salon : 1 à 100, 50 par défaut ; clés manquantes : 5 000 au plus | `runtimeInternal/delegations.ts:42-45`, `conversationLease.ts:352-381`, `runtimeInternal/e2ee.ts:39-42` | ajout |
| Historique écrit par le worker | ≤ 20 000 messages, ≤ 8 Mio sérialisés ; titre `gcm1:` ≤ 1 024 caractères ; `consumedInbox` ≤ 200 | `conversationValidation.ts:128-129`, `conversationLease.ts:179-193` | précision |
| Boîte de réception | 100 éléments non consommés (`429 inbox_full`) ; dépôts : 20 / 10 s par conversation **pour le runtime** (`rt_rate_limited`) et 20 / 10 s **pour l'API** (`rate_limited`), compteurs distincts | `conversationValidation.ts:249`, `conversationRateLimit.ts:36` | précision |
| Push | **remplace « 1 / 30 s »** (L03d, Q19) : une notification par entrée dans l'état annoncé, plafond de sécurité **6 / min** par conversation (`429 rt_rate_limited`), `202 { sent: true \| false }` ; ordre : plafond, puis jeton « une fois » (un doublon rend sa place ; échec d'envoi : jeton et place rendus) | `SYNCOAI_REFONTE_FEATURE.md` §14.6 | remplace la limite de 1 / 30 s, qui perdait la notification d'une question posée moins de 30 s après une autre |
| Synchro des clés (L03d, PC19) | routes `GET …/ai/runtime/delegations/current`, `GET …/current/missing`, `POST …/delegations/:delegationId/entries`, `POST …/delegations` (renouvellement à l'ouverture) **exemptées du limiteur global `/api`** (300 / 15 min / IP) ; à la place, échecs d'authentification (**401 seulement** : un 403 métier d'un utilisateur authentifié ne compte pas) **par IP** 300 / 15 min avant `authMiddleware`, puis **par utilisateur** 300 / 15 min après. Raison : une ouverture coûte 2 à 4 requêtes, un évènement de clé 2, et l'IP d'un bureau derrière un NAT n'est plus partagée. Les limites des services (dépôts 10 / h, ajout d'entrées 3 / 15 s, `aiLimiter` 120 / min) restent | `runtimeHttpPolicy.ts` (`isAiKeySyncRequest`), `index.ts` (`createAiKeySyncLimiters`) ; `SYNCOAI_REFONTE_FEATURE.md` §14.5 | ajout |
| Routes utilisateur du mode runtime | compteur propre de 120 / min par utilisateur (séparé des 30 / min du chat), limiteur global `/api` inchangé | `runtimeHttpPolicy.ts:211-217` | ajout |
| Maintenance | toutes les 60 s ; boîte consommée gardée 7 jours | `runtimeMaintenance.ts:24-26` | — |
| Passerelle : corps | `SYNCO_MAX_BODY_BYTES`, **1 Mio** par défaut, configurable (`413 body_too_large`) ; lecture ≤ 30 s (`408`) ; l'app doit s'y aligner (images en base64) | `Synco_AI_Gateway/src/config.rs:6`, `src/app.rs:140` | ajout |
| Passerelle : concurrence | **16** requêtes de chat simultanées au total, **4** par utilisateur (`sub`) → `429`, `Retry-After: 1` | `src/config.rs:9-10`, `src/limits.rs` | ajout |
| Passerelle : jetons | `max_tokens` plafonné à 4 096 (`SYNCO_MAX_TOKENS`), `n = 1` | `src/config.rs:7`, `src/relay.rs:80-90` | ajout |
| Passerelle : clés publiques | relecture 600 s ; `kid` inconnu ≤ 1 / 60 s ; plus aucune clé utilisée après 1 h sans relecture réussie ; réponse ≤ 64 Kio, ≤ 16 clés | `src/keys.rs:10-28` | ajout |
| Délais d'attente (§3) | 7 jours par défaut, **abaissables** par l'org (`limits.confirmationTimeoutSecs`, `keyTimeoutSecs`) — révisé après L03c | `runtimeMaintenance.ts`, `runtimePolicy.ts` | écart résolu (Q14 a = A) |

Valeurs appliquées par le superviseur (L05, `crates/supervisor/src/`, `crates/runtime-protocol/src/pipe.rs`) :

| Élément | Valeur réelle | Source | Écart avec la table |
|---|---|---|---|
| `hello` du WebSocket client | 5 s (`4408`) | `client_ws.rs:HELLO_TIMEOUT` | remplace 10 s (§3) |
| WebSocket sans `hello` vérifié | **8 par adresse, 256 au total** ; au-delà : réponse HTTP `429` avant la mise à niveau ; place rendue dès le ticket vérifié ; `X-Forwarded-For` lu à `trust_proxy_hops` depuis la **droite**, jamais au-delà de l'entrée la plus à droite | `server.rs:MAX_UNAUTHENTICATED_*`, `client_address` | ajout |
| Inactivité du WebSocket client | 60 s sans trame reçue → fermeture `1000` `idle_timeout` (toute trame, `ping` compris, remet le compteur à zéro) | `client::IDLE_TIMEOUT_SECS`, `client_ws.rs` | précision |
| Clés publiques des tickets (runtime) | sans relecture réussie depuis 1 h, aucun ticket accepté (échec fermé, comme la passerelle) | `client_ws.rs:TICKET_KEYS_MAX_AGE` | ajout |
| Relais `signed_request` | requêtes et réponses découpées en parties de ≤ 512 Kio bruts ; ≤ **4** requêtes en vol par worker et **8** pour le runtime (`relay_busy`) ; 2 corps en réassemblage par worker ; corps ≤ 8 Mio + 64 Kio (requête), 9 Mio (réponse) ; débit 20 / s, rafale 50 par worker (`429` `rt_rate_limited`, `relay_rate_limited`) | `pipe.rs:RELAY_*`, `state.rs:RELAY_*`, `config.rs:203-204` | précision (06 §4) |
| `snapshot` | ≤ 1 Mio, sinon `ready { mode: "reload" }` | `client_ws.rs`, `runtime.rs` | précision (05 §2) |
| Dashboard (L08, 11) | `dashboard.retention_days` 1 à 3 650, défaut **90** ; `MAX_RUNS` **50 000** exécutions en mémoire (élagage jusqu'à 90 %) ; chronologie ≤ 500 entrées ; 16 sessions, 30 min d'inactivité, 12 h ; 5 échecs / 15 min par adresse, ralentissement global à 20 échecs / 15 min (1 vérification / 5 s) ; `dashboard.trust_proxy_hops` défaut **0**, au plus 4, **distinct** de `listen.trust_proxy_hops` (défaut 1) | `dashboard/history.rs`, `dashboard/auth.rs`, `config.rs` | ajout (11 §2, §3, §6) |

Sauf mention, les chemins sont relatifs à `synco_api/src/services/aiRuntime/` ou `synco_api/src/routes/`.
