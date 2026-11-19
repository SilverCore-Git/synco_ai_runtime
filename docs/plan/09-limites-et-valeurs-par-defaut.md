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
| RAM par worker (`memory.max`) | **512 Mio** (`memory.high` 448 Mio) | runtime | cgroup (L06) | Un worker = boucle + client HTTP + historique en mémoire ; la recherche sémantique locale (Q6) peut demander plus : à mesurer. Dépassement → OOM de **ce** worker seul. |
| CPU par worker (`cpu.max`) | **1 CPU** (`100000 100000`) | runtime | cgroup | Le travail est surtout de l'attente réseau. |
| Process par worker (`pids.max`) | **64** | runtime | cgroup | Empêche les bombes de fork. |
| Durée d'un appel au fournisseur | 120 s sans octet reçu ; 10 min au total | runtime | worker | |
| Bail (`LEASE_MS`) | **60 s**, renouvelé toutes les 20 s | — | API / worker | Relance après plantage en ≤ 60 s. |
| Tampon de reprise (05 §3) | **2 000** évènements ou **4 Mio** par conversation | runtime | superviseur | |
| `signed_request` du worker | 20 / s, rafale 50 | runtime | superviseur | |

**Recommandation** : ces valeurs, à revoir après les mesures de L06 (coût d'un worker vide, temps de
lancement) et les premiers essais de L07.

## 3. Délais d'attente

| Attente | Délai | Au-delà |
|---|---|---|
| `awaiting_confirmation`, `awaiting_user` | **7 jours** (org) | `failed` `confirmation_timeout` (08 §2) — dépend aussi de D5 |
| `awaiting_key` | **7 jours** | `failed` `key_timeout` |
| `queued` (runtime hors ligne) | aucun | reste `queued` ; affiché « runtime injoignable » |
| `hello` du WebSocket client | 10 s | fermeture `4408` |

Réalisation (révisé après la vague B, 2026-11-19) : les deux délais de 7 jours sont **fixes** dans
l'API (`WAIT_TIMEOUT_MS`, `synco_api/src/services/aiRuntime/runtimeMaintenance.ts:25`), comparés à
`statusChangedAt` par une passe toutes les 60 s (07 §9) ; l'org ne peut pas encore les abaisser
(00 §6 Q14).

## 4. Débits et tailles

| Élément | Limite |
|---|---|
| Ticket | 2 048 octets ; `srt1` 300 s émis / 600 s max ; `sgt1` 300 s / 900 s max ; tolérance 30 s |
| `POST <url>/v1/challenge` | 10 / min par adresse IP, 60 / min au total |
| Canal interne (par runtime) | 50 requêtes / s, rafale 200 ; corps 256 Kio (8 Mio pour `PUT …/transcript`) |
| Fenêtre des requêtes internes | ±60 s ; nonces gardés 120 s |
| Historique d'une conversation (`messages`) | 8 Mio sérialisés ; au-delà, refus d'écriture (`invalid_body`) et `failed` `internal` — compaction hors v1 |
| Entrées par délégation | 5 000 |
| Dépôt de délégations | 10 / h par utilisateur |
| Ajout d'entrées (client) | 1 requête / 5 s, ≤ 500 entrées par requête |
| Trames WebSocket client | 256 Kio (client → runtime), 1 Mio (runtime → client) ; 20 trames / 10 s par connexion ; 5 connexions par conversation |
| Boîte de réception | 100 éléments non consommés par conversation ; 20 dépôts / 10 s |
| Notifications push | 1 / 30 s par conversation |
| `POST /metrics` | 1 / min |
| Trames du pipe | 1 Mio (JSON), 64 Kio (clés) |
| Synchro P11 (client) | regroupement 5 s ; backoff 30 s → 30 min ; 5 tentatives par session de l'app |

### 4.1 Valeurs réelles après la vague B (révisé après la vague B, 2026-11-19)

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
| Push | 1 / 30 s par conversation (`429 rt_rate_limited`) | `conversationRateLimit.ts:38` | — |
| Routes utilisateur du mode runtime | compteur propre de 120 / min par utilisateur (séparé des 30 / min du chat), limiteur global `/api` inchangé | `runtimeHttpPolicy.ts:211-217` | ajout |
| Maintenance | toutes les 60 s ; boîte consommée gardée 7 jours | `runtimeMaintenance.ts:24-26` | — |
| Passerelle : corps | `SYNCO_MAX_BODY_BYTES`, **1 Mio** par défaut, configurable (`413 body_too_large`) ; lecture ≤ 30 s (`408`) ; l'app doit s'y aligner (images en base64) | `Synco_AI_Gateway/src/config.rs:6`, `src/app.rs:140` | ajout |
| Passerelle : concurrence | **16** requêtes de chat simultanées au total, **4** par utilisateur (`sub`) → `429`, `Retry-After: 1` | `src/config.rs:9-10`, `src/limits.rs` | ajout |
| Passerelle : jetons | `max_tokens` plafonné à 4 096 (`SYNCO_MAX_TOKENS`), `n = 1` | `src/config.rs:7`, `src/relay.rs:80-90` | ajout |
| Passerelle : clés publiques | relecture 600 s ; `kid` inconnu ≤ 1 / 60 s ; plus aucune clé utilisée après 1 h sans relecture réussie ; réponse ≤ 64 Kio, ≤ 16 clés | `src/keys.rs:10-28` | ajout |
| Délais d'attente (§3) | 7 jours fixes, non réglables par l'org | `runtimeMaintenance.ts:25` | écart, 00 §6 Q14 |

Sauf mention, les chemins sont relatifs à `synco_api/src/services/aiRuntime/` ou `synco_api/src/routes/`.
