# 04 — Canal interne runtime → API

Le runtime est chez le client : il joint synco_api **par Internet**, sur l'API publique (préfixe
`/api/runtime/v1`), et non sur un port privé comme le CDN (`cdnInternalServer.ts`). L'authentification
repose donc entièrement sur la signature Ed25519 de chaque requête par la clé `sig` du runtime,
enregistrée à l'appairage (01). Conventions : [00 §3](00-vue-ensemble.md).

## 1. Montage côté API

- Routeur dédié monté sur `/api/runtime/v1`, **hors** `authMiddleware` (pas de jeton Keycloak), avec
  son propre limiteur de débit par `runtimeId` (09 §4) et un corps brut lu tel quel (les octets
  signés), plafonné à 8 Mio (`PUT …/transcript`) et 256 Kio ailleurs.
- Le module IA (`features` contient `ai`, `activeModules.ai === true`) et l'absence de bannissement de
  l'org (`orgBanMiddleware`) sont vérifiés à chaque requête, comme pour les routes `/ai`.

Montage réel (révisé après la vague B, 2026-11-19 ; `synco_api/src/services/aiRuntime/runtimeAuth.ts:160-172`,
`:245-350`, `synco_api/src/routes/runtimeInternal/index.ts`) : chaîne `runtimeChannelGuards` =
limiteur d'**échecs** d'authentification par adresse IP (60 / min, avant toute vérification ; au-delà
`429 rt_rate_limited` avec `Retry-After`) puis `requireRuntimeSignature` (§2.3), puis les routeurs
des lots, puis `404 not_found`. Aucun analyseur de corps n'est monté avant : le corps brut est lu par
`requireRuntimeSignature` lui-même, **après** les étapes 1 à 3 de §2.3 (aucun octet lu pour une
requête sans en-têtes valides, hors fenêtre ou d'un runtime inconnu ou révoqué), avec au plus
8 lectures de corps simultanées non encore authentifiées par adresse IP (`429 rt_rate_limited`) et
30 s de lecture au plus (`400 invalid_body`). Un refus avant lecture du corps ferme la connexion
(`Connection: close`). Le module runtime non configuré (02 §2) → `503 runtime_disabled` partout.

## 2. Signature des requêtes

### 2.1 En-têtes

| En-tête | Valeur |
|---|---|
| `x-synco-runtime` | `runtimeId` |
| `x-synco-timestamp` | secondes Unix, `^\d{1,12}$` |
| `x-synco-nonce` | `b64u` de 16 octets aléatoires (22 caractères) |
| `x-synco-auth` | `authId` de l'autorisation de session (§3), **absent** pour les routes sans utilisateur |
| `x-synco-signature` | `b64u` de la signature Ed25519 (64 octets) |

### 2.2 Octets signés

```
"synco-rt-request-v1\0" ‖ utf8( METHOD "\n" PATH "\n" TIMESTAMP "\n" NONCE "\n" RUNTIME_ID "\n" AUTH "\n" b64u(SHA-256(CORPS)) )
```

- `METHOD` en majuscules ; `PATH` = chemin **et** chaîne de requête exactement tels qu'envoyés
  (`req.originalUrl`, encodage pourcent conservé), contrairement au CDN qui ignore la requête
  (`internalAuth.ts:7-10`) : certaines routes du runtime sont paginées ;
- côté runtime (révisé après L05, 2026-11-20) : le chemin signé est le chemin **envoyé**, ce qui impose
  que `api_url` soit une origine sans chemin ni barre finale (01 §3) ;
- `AUTH` = valeur de `x-synco-auth`, ou `-` si absent ;
- `CORPS` = octets exacts du corps (vide → SHA-256 de la chaîne vide).

### 2.3 Vérification (ordre) (révisé après la vague B, 2026-11-19)

Ordre réel (`createRuntimeChannelAuth`, `synco_api/src/services/aiRuntime/runtimeAuth.ts:188-241`) :

1. En-têtes présents et bien formés → `401 rt_sig_missing`.
2. `|TIMESTAMP − maintenant| ≤ 60 s` (comme `MAX_CLOCK_DRIFT_SECS`, `internalAuth.ts:15`) →
   `401 rt_clock_skew`.
3. `AiRuntime` trouvé par `runtimeId` → sinon `404 rt_unknown` ; statut `active` → sinon
   `401 rt_revoked`. Lecture en cache 5 s, invalidé par l'instance qui désappaire
   (`runtimeStore.ts:143-148`).
   — **Lecture du corps** (plafonds de §1), seulement maintenant.
4. Signature Ed25519 valide avec `AiRuntime.sigPublicKey` → `401 rt_sig_invalid`.
4 bis. **Débit par runtime** (seau à jetons, 50 / s, rafale 200, 09 §4) → `429 rt_rate_limited`.
   Consulté **après** la signature et **avant** l'anti-rejeu : une requête refusée pour débit
   n'occupe pas de place dans l'ensemble des nonces (`:213-214`).
5. Anti-rejeu : `(runtimeId, NONCE)` absent, puis inséré avec une durée de vie de 120 s
   (≥ 2 × fenêtre) → sinon `401 rt_replay`. **Un ensemble par runtime, borné à 8 000 nonces, qui
   n'évince jamais un nonce encore valide** : plein → `429 rt_rate_limited`
   (`RuntimeNonceCache`, `synco_api/src/services/aiRuntime/runtimeRequestSigning.ts:112-163` ;
   8 000 = 50 / s × 120 s + rafale, arrondi). Un runtime, même malveillant, ne peut donc ni évincer
   les nonces d'un autre runtime ni les siens pour faire réaccepter une requête capturée dans sa
   fenêtre ; l'insertion après la signature empêche un tiers de « brûler » un nonce légitime. Le
   cache LRU global de 100 000 entrées de la première version est abandonné. Ensemble propre à
   l'instance (01 §11).
5 bis. Module IA actif et org non bannie (cache 5 s de l'état IA, invalidé par
   `onOrgAiStateChanged`, 03 §8.1) → `403 ai_disabled`.
5 ter. Corps non vide : JSON valide → sinon `400 invalid_body` (le corps reste à valider par
   chaque route ; `req.body` n'est pas rempli sur ce canal).
6. **Si `x-synco-auth` est présent, sur n'importe quelle route, « S » comprise** : vérifications
   de §3.2, jamais ignorées (relecture M1, `:233-239`). Une route **S+A** sans `x-synco-auth` →
   `403 auth_invalid`.

Les codes `rt_sig_missing`, `rt_clock_skew`, `rt_unknown`, `rt_revoked`, `rt_sig_invalid`,
`rt_replay` et `invalid_body` comptent comme échecs pour le limiteur par adresse IP de §1.

Exemple (requête `POST /api/runtime/v1/conversations/0f0e…0100/status`, corps
`{"baseRev":12,"status":"running"}`, graine `sig` = `0x11` × 32) :

```
POST
/api/runtime/v1/conversations/0f0e0d0c-0b0a-4908-8706-050403020100/status
1795000400
WlpaWlpaWlpaWlpaWlpaWg
7d3f2c1e-8a4b-4c6d-9e0f-1a2b3c4d5e6f
9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a
UvOjs3du6XMq1sU_UIFE_rVWfOC6WjzKx__91hqbcfw
→ x-synco-signature: sPPFa6e54n7Vdg4HZSV8SZiqRkb8L3_xoihfgyqKKUG5-JGBySBhgBnbVRwHtBuy6RDvmgYWi2w76Nm7QPbhBg
```

(Ed25519 est déterministe : valeur reproductible. Fichier : [exemples/exemples.json](exemples/exemples.json), clé `request`.)

## 3. Autorisation de session

### 3.1 Forme

Créée par l'API à la **bascule** d'une conversation vers le runtime (§5, `switch-to-runtime`), une par
conversation active. Enregistrement `AiSessionAuthorization` (07 §3) :

| Champ | Sens |
|---|---|
| `id` (`authId`) | UUID v4 tiré par l'API. **Pas un secret** : l'authentification est la signature du runtime ; l'`authId` lie explicitement la requête à un contexte (utilisateur, org, conversation) au lieu de le déduire du chemin. |
| `userId`, `orgId`, `sessionId`, `runtimeId` | Contexte |
| `delegationId` | Délégation active de (utilisateur, runtime) au moment de la création ; mise à jour quand la délégation est remplacée |
| `expiresAt` | = `expiresAt` de la délégation active, mis à jour à chaque renouvellement |
| `revokedAt`, `revokedReason` | Révocation |

Le runtime apprend l'`authId` par le flux de notifications (`conversation.authorized`, §6) ou par
`GET /api/runtime/v1/conversations?state=pending`.

### 3.2 Vérifications à chaque requête portant `x-synco-auth` (second verrou, mesure 6) (révisé après L03c, 2026-11-20)

1. Autorisation trouvée, `runtimeId` = signataire → sinon `403 auth_invalid`.
2. Non révoquée → `403 auth_revoked` ; `expiresAt > maintenant` → `403 auth_expired`.
3. Délégation `delegationId` au statut `active`, `expiresAt > maintenant` → `403 delegation_expired` /
   `delegation_revoked`.
4. L'utilisateur est **toujours** membre de l'org (`getPermission(userId, { orgId })`), org non bannie,
   politique runtime de l'org l'autorise (07 §6), **et l'utilisateur n'est pas banni de la plateforme**
   (`User.bannedAt`, `RuntimeStore.isUserBanned`, cache de 15 s partagé avec `banMiddleware` et
   invalidé par la route de bannissement ; révisé après L03c, Q17 = C) → `403 auth_invalid`.
5. Conversation : propriétaire = `userId`, org = `orgId`, régime `runtime`, `runtimeId` = signataire ;
   si la route porte un `:sessionId`, il doit être celui de l'autorisation → `403 out_of_scope`.

Toute route qui renvoie un contenu chiffré ou agit au nom d'un utilisateur **exige** `x-synco-auth`.
Ces contrôles sont faits **avant** toute lecture de données.

Précisions (révisé après la vague B, 2026-11-19 ; `checkSessionAuthorization`,
`runtimeAuth.ts:365-413`) :

- étape 1 : l'autorisation doit aussi appartenir à l'org du runtime ; étape 3 : la délégation doit
  concorder (même utilisateur, org, runtime), sinon `auth_invalid` ; une délégation au statut
  `expired` → `delegation_expired`, tout autre statut non actif → `delegation_revoked` ;
- les expirations sont comparées à la **borne haute** de la seconde courante (on expire au plus
  1 s trop tôt, jamais trop tard, `:372-376`) ;
- **règle `:sessionId`** (relecture M2, `routeSessionScope`, `:140-156`) : l'identifiant de
  conversation ne se lit **que** dans l'autorisation, jamais dans le chemin ni le corps. Le paramètre
  de chemin, s'il existe, s'appelle exactement `:sessionId` et ne sert qu'à **refuser** s'il diffère.
  Une route dont le paramètre de conversation porte un autre nom (`id`, `session`, `conversation`,
  `conversationId`, `convId`, `conv`, `sid`), ou un chemin `/conversations/<x>` sans `:sessionId`, est
  refusée `403 out_of_scope` (erreur de montage fermée par défaut) ;
- après ce second verrou, chaque route S+A refait le contrôle métier `loadAuthorizedConversation`
  (`synco_api/src/services/aiRuntime/conversationLease.ts:53-103`) : mêmes conditions relues en base,
  plus « l'autorisation est l'autorisation **active** de la conversation » (`activeSessionId`),
  sinon `auth_revoked`. Toutes les routes qui servent des données par runtime filtrent aussi par
  l'org du runtime. **Utilisateur banni (révisé après L03c, 2026-11-20)** : `loadAuthorizedConversation`
  relit aussi `User.bannedAt` **en base, sans cache** (compte absent → refusé) : `403 auth_invalid`,
  au second verrou **et** dans le contrôle métier (`SYNCOAI_REFONTE_FEATURE.md` §13.1). Limite :
  `POST /tickets/llm` ne passe que par le second verrou (03 §8.1).

## 4. Liste fermée des routes du runtime

Préfixe `/api/runtime/v1`. Toute route absente de cette liste n'existe pas pour le runtime ; en
ajouter une (L14/L15) = modifier ce document. Colonne « Auth » : **S** = signature seule ;
**S+A** = signature + autorisation de session (§3.2).

### 4.1 Runtime (sans utilisateur) (révisé après L03c, 2026-11-20)

| Méthode et chemin | Auth | Rôle | Lot |
|---|---|---|---|
| `POST /register` | S | Corps `{ url, software: { version } }` (`url` ≤ 255, `version` `^[0-9A-Za-z.+-]{1,64}$`, sinon `invalid_body`). Appairage terminé ? → `{ orgId, certificate }`, sinon `404 rt_unknown` (01 §7). Met à jour `registeredAt` (premier appel), `lastSeenAt`, version. | L02 |
| `POST /unpair` | S | Désappairage demandé par l'opérateur (01 §9) | L02 |
| `GET /stream` | S | Mise à niveau WebSocket du flux de notifications (§6) ; sans `Upgrade` → `426 upgrade_required` | L02 |
| `GET /llm-policy` | S | Politique IA de l'org pour le runtime : fournisseurs et modèles autorisés, `reasoningEffort`, `toolPolicy` (D5), plafonds de l'org (D4/D6) et délais `awaiting_*` (`limits.confirmationTimeoutSecs`, `limits.keyTimeoutSecs`, 09 §3 ; révisé après L03c). **Aucun secret** (D1 = A). Forme réelle : `{ v: 1, orgId, defaultProvider, reasoningEffort, providers: [{ id, modelId?, gatewayUrl? }], runtime: { enabled, maxDelegationDays, toolPolicy, limits } }` (fournisseurs activés seulement ; ni clé, ni `hasApiKey`, ni liste des membres autorisés ; `runtime.ts:86-108`) | L02 |
| ~~`GET /llm-credentials`~~ | — | **N'existe pas** (D1 = A, 00 §5) | — |
| `GET /delegations` | S | Délégations `active` **et non expirées** de l'org pour ce runtime : `{ delegationId, userId, scope, iat, exp, wrap, mandateSignature, displayName }[]` ; **`displayName: string \| null`** ajouté par L03d (PC17, voir ci-dessous) | L03, L03d |
| `GET /delegations/:delegationId/entries?after=<curseur>&limit=<≤500>` | S | `{ "entries": [{ id, kind, ref, version, ciphertext }], "next": <id> \| null }` (03 §9) | L03 |
| `POST /delegations/:delegationId/status` | S | `{ "status": "ok" \| "unusable" }`, sans cause (03 §12) → `204` | L03 |
| `GET /users/:userId/sign-key` | S | `{ publicSignKey, transitions: [{ seq, oldPublicSignKey, newPublicKey, newPublicSignKey, signature, createdAt }] }` d'un utilisateur ayant une délégation (active ou non) vers ce runtime dans son org ; sinon `404 not_found` | L03 |
| `GET /conversations?state=pending` | S | Conversations de l'org en régime runtime sur ce runtime qui demandent un worker : `queued`, `running` à bail expiré, `awaiting_key` dont la clé est désormais déléguée, **et `idle` avec un élément `message` non consommé** (filet contre la course dépôt / fin de tour, révisé après la vague B ; `conversationLease.ts:383-431`). `{ sessionId, userId, authId, status }[]`, seulement les conversations qui ont une autorisation active. Autre valeur de `state` → `400 invalid_body` | L03 |
| `GET /authorizations?state=active&after=<authId>&limit=<1 à 500>` | S | **Ajoutée par L03d (Q18, PC18).** Autorisations de session actives de l'org **et** de ce runtime : `{ "authorizations": [{ authId, sessionId, userId, delegationId, exp, displayName }], "next": "<authId>" \| null }` (`exp` en secondes Unix). `state=active` obligatoire ; tout autre paramètre ou valeur, ou curseur hors liste (autre runtime, autre org) → `400 invalid_body`. Pour le superviseur : un appel par (re)connexion du flux au lieu d'un `GET /conversations/:sessionId` par conversation connue (03 §9) | L03d |
| `POST /metrics` | S | État du runtime sans contenu pour l'écran de Synco : corps `{ workers, queued, version? }` (entiers 0 à 1 000 000) → `{ ok: true }` ; ≤ 1 / min, sinon `429 rt_rate_limited` | L02 |
| `GET /e2ee/threads/envelope-resets?limit=<1 à 500>&cursor=` | S | **Livrée par L03f (PC31), reportée ici par L00f.** Réinitialisations `rt1` en attente de nouvelle pose pour ce runtime : `{ "items": [{ threadId, userId, delegationId, resetAt }], "nextCursor": "<opaque>" \| null }` (100 par défaut ; curseur opaque, inconnu → `400 invalid_body`). Mêmes règles que la repose (salon de l'org, délégant non banni et ayant accès, délégation active vers ce runtime : `activeReposers`, `synco_api/src/services/aiRuntime/threadEnvelopeReset.ts:59`, `:197`). **Ajout L00f** : seulement les délégants dont la délégation active est `mode = auto` et autorisée (12 §10.4) | L03f, L03g |

**Compléments de L03d (2026-11-21 ; porte C ; `synco_api/vibe/features/SYNCOAI_REFONTE_FEATURE.md` §14.1 et §14.2)** :

- `GET /authorizations?state=active` : curseur = `(createdAt, id)` de l'autorisation `after`, lue parmi
  celles du runtime et de l'org appelants **sans** filtre d'activité (une autorisation révoquée entre deux
  pages reste un curseur valide). Sont servies : non révoquée, non expirée, encore l'autorisation active de
  sa conversation, délégation `active` non expirée du même runtime et de la même org, utilisateur membre de
  l'org et non banni (mêmes conditions que le second verrou, §3.2). Ordre de création ; la page est lue
  **puis** filtrée : elle peut compter moins de `limit` éléments, seul `next = null` marque la fin.
- `displayName` (`GET /delegations` et `GET /authorizations`, rien d'autre : l'annuaire reste limité aux
  utilisateurs qui ont une délégation vers ce runtime) : `User.name`, sinon `User.pseudo`, en écartant toute
  valeur qui contient `@` ou égale l'e-mail (le realm a `username == email` et `name` retombe sur l'e-mail
  sans prénom ni nom) ; caractères de contrôle remplacés, 128 caractères au plus ; sinon `null` (le
  dashboard affiche alors l'identifiant). **Jamais l'e-mail.** Le runtime ignore déjà les champs inconnus
  (`DelegationRecord`, `crates/runtime-protocol/src/api.rs`).
- **État côté runtime au moment de ce report** (relu dans le code) : le superviseur **n'appelle pas encore**
  `GET /authorizations` (il réconcilie toujours par conversation, `reconcile_authorizations`,
  `crates/supervisor/src/runtime.rs`) et `DelegationRecord` ne porte pas `displayName` : l'API est livrée,
  l'adoption par le runtime et le dashboard (11 §5) reste à faire. Lot : **ouvert** (non planifié dans ce
  report).

**Compléments de L00f (2026-11-21 ; 12 §12.2)** : `GET /delegations` ajoute `mandateVersion` (`1` ou `2`),
`mode` (`plan` | `auto` ; `plan` pour un v1) et `ownerRsaSpkiHex` (`null` pour un v1). Le runtime
reconstruit le mandat selon 03 §4.1 et se fie au mode **vérifié**.

### 4.2 Au nom d'un utilisateur (conversation) (révisé après L03c, 2026-11-20)

`:sessionId` est toujours la conversation de l'autorisation.

| Méthode et chemin | Auth | Rôle | Lot |
|---|---|---|---|
| `GET /conversations/:sessionId` | S+A | `{ id, title, messages, rev, status, pendingToolCall, encryptionScheme, leaseEpoch, lastErrorCode, awaitingKey }` (champs chiffrés `gcm1:`) | L03 |
| `POST /conversations/:sessionId/lease` | S+A | Corps vide (ou `{}`) = **prendre** le bail ; `{ leaseEpoch }` = le **renouveler** (07 §4) → `{ leaseEpoch, expiresAt }` (`expiresAt` ISO 8601) ou `409 lease_conflict` | L03 |
| `DELETE /conversations/:sessionId/lease` | S+A | Rendre le bail, corps `{ leaseEpoch }` → `204`, ou `409 lease_conflict` | L03 |
| `PUT /conversations/:sessionId/transcript` | S+A | `{ leaseEpoch, baseRev, messages, title?, status, pendingToolCall, consumedInbox: [id], error?, awaitingKey?, events? }` → `{ rev }` ou `409 rev_conflict` / `lease_conflict` (07 §4) | L03 |
| `POST /conversations/:sessionId/status` | S+A | `{ leaseEpoch, status, error?, awaitingKey?, events? }` (changement d'état sans réécrire l'historique ; `error` = code de 08 §6) | L03 |
| `GET /conversations/:sessionId/inbox?after=<curseur>` | S+A | Éléments non consommés (messages, décisions, annulations) déposés par le client via l'API ou par le runtime (05 §6) → `{ "items": [{ id, kind, source, createdAt, payload }] }`, 100 au plus par page, ordre de dépôt ; `payload` = trame sans `v` ni `t` (`null` si illisible) ; curseur = `id` du dernier élément lu | L03 |
| `POST /conversations/:sessionId/inbox` | S+A | Le runtime rend durable un élément reçu par WebSocket **avant** d'en accuser réception au client (idempotent par `id`). Corps = la trame de 05 §6.2 **sans `v`** (`{ t, … }`, strict) → `201 { id, status }` (nouvel élément) ou `200 { id, status }` (doublon) ; `429 inbox_full`, `429 rt_rate_limited` (20 / 10 s par conversation), `409 not_runtime` | L03 |
| `GET /conversations/:sessionId/tools` | S+A | Manifeste des outils (même contenu que `GET /api/orgs/:orgId/ai/tools`, `aiChat.ts:216-226`) : `[{ name, description, category, mutating, interactive, parameters }]`, `parameters` en JSON Schema | L03 |
| `POST /conversations/:sessionId/tools/:name/execute` | S+A | Outil `server` (§5), corps **`{ leaseEpoch, args? }`** | L03 |
| `POST /conversations/:sessionId/push` | S+A | `{ type }` ∈ `AI_TURN_DONE`, `AI_AWAITING_CONFIRMATION`, `AI_AWAITING_KEY`, `AI_AWAITING_USER`, `AI_FAILED` ; titre et corps construits par l'API, **sans contenu** ; **une notification par entrée dans l'état annoncé**, plafond de sécurité 6 / min par conversation (`429 rt_rate_limited`) → `202 { sent: true \| false }` (voir « Notifications » ci-dessous ; révisé par L03d, Q19) | L03, L03d |
| `POST /tickets/llm` | S+A | Ticket `sgt1` pour l'utilisateur de l'autorisation, `rt` renseigné (02 §4) → `{ ticket, expiresAt, url }` ; `409 gateway_not_configured` | L02 |
| `POST /conversations/:sessionId/plans` | S+A | **Ajoutée par L00f (12 §12.2).** Écrit le transcript (statut `awaiting_confirmation`, `pendingToolCall` `propose_actions`, 12 §3.4) **et** crée la ligne `AiActionPlan` dans une transaction : `{ leaseEpoch, baseRev, messages, title?, pendingToolCall, consumedInbox, events?, plan: { planId, toolCallId, actionCount, createdAt, expiresAt, serverDigests: [{ n, sha256Hex }] } }` → `201 { rev, planId }` ; `400 invalid_body`, `409 plan_exists`, `rev_conflict`, `lease_conflict` | L03g |
| `GET /conversations/:sessionId/plans/:planId` | S+A | **Ajoutée par L00f.** `PlanView` (12 §12.1), sans contenu | L03g |

Contraintes des écritures du worker (révisé après la vague B, 2026-11-19 ;
`synco_api/src/services/aiRuntime/conversationLease.ts:172-207`, `conversationValidation.ts:44-68`) :

- `status` ∈ `running`, `idle`, `awaiting_confirmation`, `awaiting_user`, `awaiting_key`, `failed`,
  `cancelled` : **`queued` est réservé à l'API** ;
- `awaitingKey` = `"thread:<id>"` ou `"space:<id>"`, **obligatoire** avec `awaiting_key` et
  **interdit** sinon (`400 invalid_body`) : c'est ainsi que le runtime transmet la clé attendue (08 §2) ;
- `error` ∈ codes de 08 §6, écrit dans `lastErrorCode` (`null` s'il est absent) ;
- `transcript` : `messages` au format chiffré (tout champ de contenu en `gcm1:`, ≤ 20 000 messages,
  ≤ 8 Mio sérialisés), `title` `gcm1:` ≤ 1 024 caractères, `consumedInbox` ≤ 200 identifiants ;
- un conflit est classé après coup : bail encore détenu → `rev_conflict`, sinon `lease_conflict` ;
- **`events` (révisé après L03c, 2026-11-20 ; Q15 = A, 00 §5)** : facultatif, `[{ type, code? }]` ;
  `type` ∈ `tool_unknown_outcome`, `lease_lost` ; `code` facultatif `^[a-z0-9_]{1,64}$` (nom d'outil,
  epoch…) ; objets stricts, 20 au plus (sinon `400 invalid_body`). Écrits en `AiChatSessionEvent`
  (`actor: "runtime"`, `fromState` / `toState` nuls) **seulement** si l'écriture qui les porte réussit :
  dans la même transaction que le transcript, et, pour `POST …/status`, statut et `events` dans la
  même transaction (un échec n'écrit ni l'un ni l'autre). Champ absent : inchangé. Les `events`
  exigent le bail courant : un worker qui l'a perdu ne peut pas écrire son propre `lease_lost`, c'est
  le worker suivant qui le constate et l'écrit ; **rétention de 90 jours** des `AiChatSessionEvent`
  (L03d, Q20 ; 07 §5) en plus de leur suppression avec la conversation. Source : `synco_api/src/services/aiRuntime/conversationLease.ts:186-228`,
  `SYNCOAI_REFONTE_FEATURE.md` §13.6, §13.6 bis (M4).

**Notifications `POST …/push` (L03d, Q19 / PC21 ; `SYNCOAI_REFONTE_FEATURE.md` §14.6)** : chaque type est
lié à l'état qu'il annonce (`AI_TURN_DONE` ↔ `idle`, `AI_AWAITING_CONFIRMATION` ↔ `awaiting_confirmation`,
`AI_AWAITING_USER` ↔ `awaiting_user`, `AI_AWAITING_KEY` ↔ `awaiting_key`, `AI_FAILED` ↔ `failed`). La
limite de « 1 / 30 s par conversation, tous types » est **remplacée** : elle faisait perdre la
notification d'une question posée moins de 30 s après une autre. Désormais :

- état courant ≠ celui du type, ou doublon de la **même entrée** dans l'état → `202 { "sent": false }` ;
- plafond de sécurité **6 / min par conversation** → `429 rt_rate_limited` ;
- envoi → `202 { "sent": true }`. Ordre des contrôles : plafond d'abord, puis jeton « une fois » par
  entrée ; un doublon rend sa place dans le plafond ; si l'envoi lève (`500 internal`), le jeton et la
  place sont rendus, donc le nouvel essai du runtime est notifié ;
- l'API émet aussi l'évènement socket `notification:push` (le centre de notifications d'un client ouvert
  se met à jour sans rechargement ; `data` porte aussi `type`).

Chaîne vérifiée par L03d : worker → `POST …/push` → `sendPush` → `createAndSendNotification`
(notification persistée, FCM web et Android, APNS iOS, préférences `push` / `mentionsOnly` / `sound`
respectées, e-mail seulement en mode « tout »). Côté worker (relu, `crates/worker/src/agent.rs:655`) : la
réponse du `POST …/push` est ignorée, donc `sent` n'est pas lu et rien n'est à changer.

Après **chaque** écriture du worker qui change l'état, l'API applique aux éléments restés non
consommés la transition « au dépôt » de 08 §2 à partir du **nouvel** état (`inboxTransition`) et
réveille le runtime si la conversation repasse `queued` (`afterWorkerWrite`,
`conversationLease.ts:228-273` ; 08 §2.1).

### 4.3 Données E2EE de l'org (dans le périmètre de la délégation) (révisé après L03c, 2026-11-20 ; après L03d, 2026-11-21)

Toutes **S+A**, **sauf** `POST /e2ee/threads/:threadId/key-envelope/repose` (**S** seule, voir plus bas). En plus de §3.2, chaque route vérifie : la ressource appartient à l'org de
l'autorisation ; l'utilisateur y a accès **maintenant** (`getPermission`, mêmes services que les routes
HTTP de l'utilisateur) ; la délégation active contient l'entrée de la clé nécessaire (sinon
`403 key_not_delegated`, pour ne pas servir de chiffré inutilisable). Jamais de DM, de support, ni
d'autre org : ces routes n'existent pas.

| Méthode et chemin | Équivalent utilisateur | Rôle | Lot |
|---|---|---|---|
| `GET /e2ee/threads/:threadId/messages?before=&limit=` | `GET /api/messages/threads/:threadId` | Messages chiffrés d'un salon | L03 |
| `GET /e2ee/search-index/workspace/:workspaceId` | `GET /api/search-index/workspace/:workspaceId` (`searchIndex.ts:20`) | Index chiffrés, **sans** `threadKeys` (le runtime les a par la délégation) | L03 |
| `GET /e2ee/members/keys[?spaceId=<id>]` | annuaire des membres, `GET /api/spaces/:spaceId/members-keys` | Clés publiques RSA et de signature des membres de l'org (ou, avec `spaceId`, des membres de cet espace : L03d, PC5, voir ci-dessous), pour sceller une nouvelle clé ; bornes (clé RSA ≥ 2048 bits et ≤ 8192, sinon le membre est écarté ; plus de 300 destinataires refusé, `too_many_recipients`, 06 §9). **Épinglage TOFU par le superviseur (L05b, Q25 réalisée)** : la réponse 2xx est comparée à `member-rsa-pins.json` **avant** que le worker la voie ; une clé changée sans chaîne d'identité valide remplace la réponse entière par `409 member_key_changed` (06 §4.3) | L03 |
| `POST /e2ee/threads` | `POST /api/threads/org/:orgId`, `/api/threads/space/:spaceId` (`threads.ts`) | Créer un salon : mêmes champs que `createThreadSchema` (`validators/index.ts:125-144`), **dont `categoryId` désormais facultatif** (L03d, Q23 a), + `spaceId?` + **`leaseEpoch`** ; `creatorId` = `rt1:<delegationId>` posé par l'API (03 §10) | L03b |
| `POST /e2ee/threads/:threadId/key-envelope` | — | Pose a posteriori de l'enveloppe `rt1` d'un salon créé par le runtime (03 §10.1, Q11 = B). **Refuse** désormais les `ThreadKey` réinitialisées (`envelopeResetAt` non nul) : un seul chemin de repose, la route S ci-dessous | L03c, L03d |
| `POST /e2ee/threads/:threadId/key-envelope/repose` | — (**S** seule) | **Nouvelle pose** de l'enveloppe `rt1` après une réinitialisation par l'utilisateur (Q21 ; 03 §10.1, détail ci-dessous). Déclenchée par la trame `thread.envelope_reset` (§6) | L03d |
| `POST /delegations/:delegationId/entries` | — | Le runtime ajoute l'entrée d'une clé qu'il a créée (03 §10) | L03 |
| `POST /e2ee/cdn/uploads` | `POST /api/cdn/transfers/uploads` (`cdnTransferRoutes.ts:66`) | Ouvrir un envoi CDN pour l'utilisateur (outil `create_file`), destination **un espace seulement**. **Non utilisée par le runtime v1** : le CDN est injoignable du worker, `create_file` est retiré de la liste d'outils et refusé (`tool_unavailable_in_runtime`, 06 §9) | L03b |

Formes réelles (révisé après la vague B, 2026-11-19 ; `synco_api/src/routes/runtimeInternal/e2ee.ts`,
`synco_api/src/services/aiRuntime/conversationE2ee.ts`). Codes communs : salon ou espace d'une autre
org ou inconnu → `403 out_of_scope` ; accès refusé par les services de l'utilisateur → `403 forbidden` ;
entrée de clé absente de la délégation → `403 key_not_delegated`.

| Route | Requête | Contrôles propres | Succès |
|---|---|---|---|
| `GET /e2ee/threads/:threadId/messages` | `before` = id d'un message du salon (inconnu → `400 invalid_body`), `limit` 1 à 100 (50 par défaut) | permission `READ` sur le salon ; entrée `thread:<threadId>` | `{ "messages": [{ id, threadId, senderId, content, nonce, iv, replyToId, edited, createdAt, updatedAt }] }`, du plus ancien au plus récent |
| `GET /e2ee/search-index/workspace/:workspaceId` | — | accès à l'espace ; entrée `space:<workspaceId>` (toute version) | `{ "indexes": [{ id, workspaceId, threadId, type, resourceId, encryptedBlob, iv, createdAt, updatedAt }] }` |
| `GET /e2ee/members/keys` | — | — | `{ "members": [{ userId, publicKey, publicSignKey }] }` (membres de l'org de l'autorisation) |
| `POST /e2ee/threads` | champs de `createThreadSchema` + `spaceId?` + `leaseEpoch` + `commitment?` (`b64` de 32 octets) et `signature?` (`b64` de 64 octets, P1363), **ensemble ou absents** ; corps strict (aucun `creatorId`) | porte d'outil `create_thread` (§5 : `ai_disabled`, `tool_denied_by_policy`, `lease_conflict`) ; `spaceId` de l'org ; puis le **même** service que la route HTTP (`createThread`) avec l'utilisateur de l'autorisation et `creatorId = rt1:<delegationId de l'autorisation>` ; refus du service 403 → `forbidden`, 404 → `not_found`, 429 → `rate_limited`, autre → `invalid_body` | `201` + `Thread` (forme de `POST /api/threads/…`) ; `thread:created` émis comme pour HTTP |
| `POST /e2ee/cdn/uploads` | `{ leaseEpoch, orgId?, workspaceId, folderId?, fileName, size, partSize, mimeType?, encryptedFileKey, keyVersion, iv }`, strict | `orgId` absent ou = org de l'autorisation (`out_of_scope`) ; porte d'outil `create_file` ; espace de l'org ; accès à l'espace ; entrée `space:<workspaceId>` **de version `keyVersion`** ; puis le **même** service que la route HTTP (`openCreateTransfer` : membre, dossier de l'espace, module Fichiers, quota) | `201 { tid, fileId, cdnUrl, ticket, expiresAt, size, partSize, partCount }` |

**`POST /e2ee/threads/:threadId/key-envelope` (révisé après L03c, 2026-11-20 ; Q11 = B ;
`synco_api/src/routes/runtimeInternal/e2ee.ts:119`, `conversationE2ee.ts:266-288`,
`SYNCOAI_REFONTE_FEATURE.md` §13.3)** : S+A, ajoutée à la liste fermée. Corps strict (tout champ
inconnu → `400 invalid_body`) :

```json
{ "leaseEpoch": 3, "ctx": "thread:<threadId>", "version": 1,
  "commitment": "<b64 de 32 octets>", "signature": "<b64 de 64 octets, ECDSA P-256 P1363>" }
```

Contrôles, dans l'ordre (après le second verrou et `loadAuthorizedConversation`) :

| # | Contrôle | Refus |
|---|---|---|
| 1 | `:threadId` au format 00 §3.2 ; corps ; `ctx = "thread:" + :threadId` ; `version = 1` (une `ThreadKey` n'a qu'une version) | `400 invalid_body` |
| 2 | Porte de l'outil `create_thread` : module IA ; D5 `deny` ; bail courant (`leaseEpoch`) | `403 ai_disabled`, `403 tool_denied_by_policy`, `409 lease_conflict` |
| 3 | Salon de l'org de l'autorisation (inconnu ou autre org : même réponse) | `403 out_of_scope` |
| 4 | L'utilisateur de l'autorisation a accès au salon **maintenant** (`requireThreadAccess`) | `403 forbidden` |
| 5 | Au moins une `ThreadKey` du salon de `creatorId = "rt1:" + delegationId de l'autorisation` (salon d'un membre, d'un autre utilisateur ou d'une délégation remplacée : rien à poser) | `403 forbidden` |
| 6 | Une `ThreadKey` `rt1:` de ce salon porte déjà une enveloppe **différente** | `409 envelope_exists` |
| 7 | Signature vérifiée avec la clé `csk` du certificat du runtime sur les octets de 03 §10 (`synco-key-envelope-rt-v1`, `ctx`, `version`, `commitment`, `delegationId`) | `400 invalid_body` |
| 8 | Écriture **une fois** : `updateMany` conditionné (`threadId`, `creatorId`, `commitment = null`, `signature = null`) ; course perdue contre une autre enveloppe | `409 envelope_exists` |

`commitment` et `signature` doivent être en base64 **canonique** (`decodeB64Exact` : longueur exacte,
bits de fin nuls, comme `from_b64` de la crate) ; la même exigence s'applique désormais aux champs
`commitment` / `signature` de `POST /e2ee/threads`. Succès : `200 { "threadId": "<id>", "updated":
<nombre de ThreadKey écrites> }` ; la même enveloppe reposée → `200` avec `updated: 0` (idempotent :
reprise après coupure réseau). Aucune entrée de délégation n'est exigée (ordre libre avec
`POST /delegations/:delegationId/entries`). **Limite** : l'API n'a pas la clé du salon, elle ne vérifie
pas `commitment` ; la pose est définitive **sauf réinitialisation par un humain puis nouvelle pose** (L03d, Q21 : « Compléments de L03d » ci-dessous ; 03 §10.1). Journalisation :
gabarit `/e2ee/threads/:id/key-envelope` (§7).

**Révisé après L07 (2026-11-20)** : en pratique le runtime n'exécute que `create_thread` par ces
routes ; `create_file` (CDN injoignable du worker) et `create_folder` (aucune route du canal) sont
**retirés** de la liste donnée au modèle et refusés par le worker (`tool_unavailable_in_runtime`,
06 §9), comme les outils de documentation. Le worker pose la signature `rt1` et l'entrée de
délégation d'un salon créé avec l'aide du superviseur (`created_key`, 06 §3.3). **`create_thread` était
bloqué en réel** faute de (a) une catégorie par défaut côté API et (b) des membres d'un espace sur le
canal. **Les deux sont livrés par L03d (2026-11-21, PC5, Q23)** : voir « Compléments de L03d » plus bas.
**Reste ouvert** : le worker n'a pas encore adopté ces deux ajouts (il ne transmet `categoryId` que s'il
figure dans les arguments, appelle `GET /e2ee/members/keys` sans `spaceId` et ne scelle la clé d'un salon
d'espace que pour le propriétaire, `crates/worker/src/tools/threads.rs`) : tant qu'il ne les adopte pas,
le comportement décrit dans ce paragraphe vaut encore côté runtime. Lot d'adoption : **ouvert** (non
planifié dans ce report). Ces routes sont les
points d'exécution des outils `create_thread` et `create_file` (catégorie
`client` du registre : la cryptographie est faite par le worker) ; comme `tools/:name/execute`, seul
le worker qui détient le bail courant fait agir l'utilisateur, et un outil `deny` n'agit jamais.
Aucune autre destination d'envoi (DM, support, message, tâche) n'existe sur le canal. Le plafond de
corps de 256 Kio limite `POST /e2ee/threads` à environ 300 destinataires de clé RSA-4096, alors que
`createThreadSchema` en admet 500 (09 §4). Signature `rt1` d'un salon créé par le runtime : route de pose ci-dessus (Q11 = B).

**Compléments de L03d (2026-11-21 ; PC5, PC23, PC26 ; `SYNCOAI_REFONTE_FEATURE.md` §14.4 et §14.8)** :

- **`categoryId` facultatif** (`POST /e2ee/threads`, Q23 a) : absent, l'API prend la première catégorie
  **visible de la cible** dans l'ordre d'affichage de l'app (`index`, puis `createdAt`, puis `id`) : à
  l'accueil de l'org, toutes ses catégories (comme `GET /api/categories/org/:orgId`) ; dans un espace, les
  catégories de l'espace dont l'utilisateur est membre (`membersId`, comme `GET /api/categories/space/:spaceId`).
  Pour un espace, l'accès est vérifié **avant** (`403 forbidden`, rien n'est appris de ses catégories).
  Aucune catégorie visible → **`409 no_default_category`** (nouveau code, §8). Fourni : inchangé, contrôlé par
  le service HTTP.
- **`GET /e2ee/members/keys?spaceId=<id>`** (Q23 b ; S+A) : espace de l'org de l'autorisation (`403
  out_of_scope` sinon, espace inconnu compris), utilisateur membre de l'espace **maintenant**
  (`requireSpaceAccess`, `403 forbidden`), puis le **même service** que `GET /api/spaces/:spaceId/members-keys`
  (`spaceMemberKeysService.ts` ; la route HTTP est inchangée) ; seuls les membres encore membres de l'org.
  Sans `spaceId` : inchangé (membres de l'org). Paramètre inconnu ou `spaceId` mal formé → `400 invalid_body`.
  Même forme de réponse `{ "members": [{ userId, publicKey, publicSignKey }] }`. **Doute signalé, non tranché** :
  le garde d'épinglage du superviseur (06 §4.3) compare `req.path` coupé avant `?` à `MEMBER_KEYS_PATH`
  (`crates/supervisor/src/workers.rs:801`), donc il s'appliquerait aussi à la variante `?spaceId=` ; non
  testé avec cette variante.
- **Réinitialisation d'une enveloppe `rt1` fausse (Q21, PC23, PC26)**. Côté **utilisateur** (hors du canal du
  runtime, donc hors liste fermée, mais le runtime en reçoit l'effet) :
  `POST /api/orgs/:orgId/ai/runtime/threads/:threadId/key-envelope/reset`, corps vide. Autorisés :
  administrateur de l'org (propriétaire ou `ORG_AI`) ou délégant créateur (une `ThreadKey` `rt1:<sa
  délégation de CETTE org>`), **dans les deux cas avec l'accès ACTUEL au salon** (PC26), vérifié en premier :
  salon inconnu, d'une autre org ou inaccessible → la même réponse `403 forbidden` (aucun oracle d'existence).

  | Réponse | Cas |
  |---|---|
  | `200 { threadId, reset, envelopeResetAt }` | enveloppe retirée |
  | `403 forbidden` | salon inconnu, d'une autre org, ou sans accès actuel (admin compris) ; ou ni admin ni délégant créateur |
  | `404 not_found` | salon accessible mais non créé par un runtime |
  | `409 envelope_not_set` | aucune enveloppe posée, ou course perdue |
  | `409 repose_unavailable` | refus préalable : runtime créateur désappairé (statut ≠ `active` ou autre org), ou aucune délégation `active` non expirée du délégant vers lui ; rien n'est modifié |

  Effets, dans une transaction : `commitment`, `signature`, `envelopeDelegationId` remis à null,
  `envelopeResetAt` / `envelopeResetBy` posés, évènement `AiThreadEnvelopeEvent` (`type: "reset"`,
  `actor: "user"`) ; puis socket `thread:key-envelope-reset { orgId, threadId, resetAt, resetBy }` vers les
  clients et trame **`thread.envelope_reset { threadId, userId, delegationId }`** au runtime créateur (§6).
- **`POST /e2ee/threads/:threadId/key-envelope/repose`** (runtime ; **S seule** : la trame arrive hors de toute
  conversation, donc ni autorisation de session, ni bail, ni politique D5). Corps strict :
  `{ "delegationId": "<délégation ACTIVE>", "ctx": "thread:<threadId>", "version": 1, "commitment": "<b64 de 32
  octets>", "signature": "<b64 de 64 octets, P1363>" }`.

  | # | Contrôle | Refus |
  |---|---|---|
  | 1 | `:threadId`, corps, `ctx`, `version = 1` | `400 invalid_body` |
  | 2 | `delegationId` = délégation `active` non expirée de CE runtime dans SON org | `404 not_found` |
  | 3 | salon de l'org | `403 out_of_scope` |
  | 4 | utilisateur de la délégation non banni, accès au salon maintenant | `403 forbidden` |
  | 5 | `ThreadKey` **réinitialisées** (`envelopeResetAt` non nul) dont `creatorId` est une délégation du **même utilisateur** vers **ce runtime** dans **cette org** | `403 forbidden` |
  | 6 | enveloppe différente déjà reposée | `409 envelope_exists` (même enveloppe : `200`, `updated: 0`) |
  | 7 | signature `csk` du runtime sur `synco-key-envelope-rt-v1|ctx|version|commitment|delegationId` | `400 invalid_body` |
  | 8 | écriture conditionnée (`commitment` / `signature` nuls) + évènement `AiThreadEnvelopeEvent` (`type: "repose"`, `actor: "runtime"`, `delegationId`) dans une transaction | `409 envelope_exists` |

  Succès `200 { threadId, updated }`. **`creatorId` ne change jamais** ; la délégation signataire est notée dans
  `ThreadKey.envelopeDelegationId` (null = enveloppe posée par la délégation de `creatorId`, ou aucune) ; la
  règle d'entrée de délégation (`POST /delegations/:delegationId/entries`) reste fondée sur `creatorId`.
  Champs servis aux clients avec la `ThreadKey` : `envelopeResetAt`, `envelopeDelegationId` (socket
  `get-thread-access`, jeton LiveKit) ; `GET /api/search-index/workspace/:id` et `GET /api/spaces/:id/keys`
  renvoient la ligne complète (`envelopeResetAt`, `envelopeResetBy`, `envelopeDelegationId` compris).
- **État côté runtime au moment de ce report** (relu dans le code) : aucune trace de `thread.envelope_reset`
  (la trame tombe dans `ApiEvent::Unknown`, `crates/runtime-protocol/src/stream.rs`) ni de la route `repose`.
  De plus, le relais du worker signe toujours avec `x-synco-auth` (« toutes les routes du worker sont S+A »,
  `crates/worker/src/api.rs`) alors que `repose` est **S seule** : **doute signalé, non tranché** sur la voie
  que prendra le runtime (superviseur ou worker). Lot d'adoption (PC23 : « runtime lot ultérieur ») :
  **ouvert**, non planifié dans ce report.

**Compléments de L00f (2026-11-21 ; 12 §10.4, §8.3)** : `POST /e2ee/threads` (créateur `rt1:`),
`POST /e2ee/threads/:threadId/key-envelope` et `POST /e2ee/threads/:threadId/key-envelope/repose` exigent
en plus une délégation `mode = auto` (celle de l'autorisation, ou le `delegationId` du corps pour la
repose ; sinon `403 autonomy_required`) et `isFeatureAllowed(autonomous_mode)` (sinon
`403 feature_not_allowed`), contrôlés après les contrôles existants et avant toute écriture.
`POST /e2ee/threads` accepte `plan?: { planId, n }` et applique le verrou de 12 §8.3 quand la politique
effective de `create_thread` est `ask` (`403 action_not_accepted`, `409 action_state_conflict`). En mode
plan, le runtime ne crée aucun salon : c'est l'appareil (12 §4).

Extensions prévues (à spécifier ici par L14/L15 avant d'être codées) : lecture de fichiers (ticket
`down`), envoi de message dans un salon, documentation.

## 5. Outils `server` exécutés pour le runtime

`POST /conversations/:sessionId/tools/:name/execute` reprend exactement la logique de
`POST /api/orgs/:orgId/ai/tools/:name/execute` (`aiChat.ts:254-292`) : module IA actif,
`getPermission(userId, { orgId })`, outil de catégorie `server` avec `execute`, puis
`spec.execute({ orgId, userId, args })`. `userId` et `orgId` viennent **de l'autorisation**, jamais du
corps. Le résultat est renvoyé en clair au runtime (comme aujourd'hui à la passerelle) ; c'est le
worker qui le chiffre avant de l'enregistrer.

Forme réelle (révisé après la vague B, 2026-11-19 ; `synco_api/src/routes/runtimeInternal/conversations.ts:159-174`,
`synco_api/src/services/aiRuntime/conversationTools.ts:38-98`) : corps strict
**`{ leaseEpoch, args? }`**. Porte commune à toute action d'outil pour le runtime (`checkToolGate`),
dans l'ordre : module IA actif (`403 ai_disabled`) ; `aiConfig.runtime.toolPolicy[name] === "deny"`
→ `403 tool_denied_by_policy`, **sans exécution** (D5 appliquée aussi par l'API ; `ask` reste du
ressort du worker, l'API ne voit pas la décision de l'utilisateur) ; le worker détient le bail
**courant** (`leaseEpoch` égal, bail non expiré, même runtime) → sinon `409 lease_conflict`. Puis
membre de l'org (`403 forbidden`), outil connu de catégorie `server` avec `execute` (sinon
`404 not_found`). Réponse `200` : `{ "ok": true, "data": … }`, ou `{ "ok": false, "status": <n>,
"message": "…" }` pour une erreur métier destinée au modèle.

**Verrou des actions `ask` (L00f, PC38 ; 12 §8.3).** Corps étendu : **`{ leaseEpoch, args?, plan?: { planId, n } }`**.
Après `checkToolGate`, si la politique effective de l'outil est `ask` (`toolPolicy[name]`, sinon `ask`
pour un outil `mutating` : même règle que le worker), `plan` est obligatoire et vérifié (ligne de cette
conversation et de cet utilisateur, statut `accepted` ou `executing`, action `n` acceptée et `pending`,
`serverDigests[n]` = SHA-256 de `JCS({ tool: name, args })`) ; sinon **`403 action_not_accepted`**, sans
exécution. L'action passe `executing` (`updateMany` conditionné, sinon `409 action_state_conflict`), puis
`done` (`ok: true`) ou `failed` (`ok: false`) dans la même requête ; `AiChatSessionEvent`
`type: "plan_action"`, `actor: "runtime"`, `code: "<planId>.<n>"`. Auparavant l'API n'appliquait que `deny`.

Route de bascule (côté utilisateur, L03), rappelée ici car elle crée l'autorisation :

- `POST /api/orgs/:orgId/ai/sessions/:sessionId/switch-to-runtime` — corps
  `{ runtimeId, delegationId, baseRev, messages, title, convKey: { encryptedKey, commitment, signature }, convEntry: { kind: "conv", ref, version, ciphertext } }` :
  propriétaire seulement, délégation active du même utilisateur vers ce runtime, `encryptionScheme`
  devient `conv-gcm1-v1` (transition autorisée depuis `null`, `gateway-aes-gcm-v1` ou
  `conv-gcm1-v1`), crée l'autorisation, journalise (`AiChatSessionEvent`), notifie le runtime.
- `POST /api/orgs/:orgId/ai/sessions/:sessionId/switch-to-local` : révoque l'autorisation, supprime
  l'entrée `conv` de la délégation, rend le bail, régime `client`, notifie le runtime
  (`conversation.revoked`).

Réponses réelles (révisé après la vague B, 2026-11-19 ; `synco_api/src/services/aiRuntime/conversationLifecycle.ts:156-395`) :

- `switch-to-runtime` : `convKey` facultatif si une `CK` existe déjà pour (conversation,
  utilisateur), `commitment` et `signature` facultatifs ; `convEntry.ref` = `:sessionId` et
  `version` = 1 ; historique ≤ 8 Mio. Dans une transaction : délégation revérifiée active (verrou par
  `updateMany`), conversation écrite par `updateMany` conditionné (`rev = baseRev`, schéma inchangé,
  régime non `runtime`), `rev` + 1, **`leaseEpoch` + 1**, statut `idle`. Succès
  `200 { sessionId, regime: "runtime", status: "idle", rev, runtimeId, authId, encryptionScheme,
  expiresAt }`. Refus : `invalid_body`, `not_found`, `already_runtime`, `session_busy` (statut
  `awaiting_*` du régime `server`), `encryption_scheme_conflict`, `rev_conflict`,
  `runtime_unavailable`, `delegation_expired` / `delegation_revoked`, `delegation_not_allowed`,
  `ai_disabled`, `forbidden`.
- `switch-to-local` : `200 { sessionId, regime: "client", status: "idle" }` ; `404 not_found`,
  `409 not_runtime`. La sortie (`exitRuntimeRegime`, `:83-150`) incrémente `leaseEpoch`, vide
  `pendingToolCall` et `awaitingKey`, pose `lastErrorCode = "revoked"` sauf pour
  `switched_to_local` et `session_deleted`, notifie `conversation.revoked` puis
  `delegation.entries_removed` pour l'entrée `conv`, et émet `ai:session-status` (avec `regime`).

## 6. Flux de notifications (WebSocket sortant) (révisé après L03c/L05, 2026-11-20)

`GET /api/runtime/v1/stream` avec en-tête `Upgrade: websocket`, signé comme une requête `GET` de
corps vide (§2). Serveur : bibliothèque `ws` (déjà résolue dans `synco_api`, version 8.21.3 via
`overrides` de `package.json`) sur le serveur HTTP de l'API. Une seule connexion par runtime ; une
nouvelle connexion ferme la précédente.

- **API → runtime** : trames texte JSON `{ "v": 1, "type": "<type>", ... }`, sans contenu chiffré :

| `type` | Champs | Effet attendu du runtime |
|---|---|---|
| `hello` | `orgId`, `serverTime` | Contrôle d'horloge (écart > 30 s → alerte dashboard) |
| `conversation.authorized` | `sessionId`, `userId`, `authId` | Mémoriser l'autorisation |
| `conversation.wake` | `sessionId`, `authId`, `reason` (`inbox` \| `decision` \| `keys`) | Lancer ou réveiller le worker |
| `conversation.revoked` | `sessionId`, `reason` | Arrêter le worker, oublier `CK`, fermer les WebSocket clients (`4403`) |
| `delegation.updated` | `userId`, `delegationId` | Recharger la délégation (03 §9) |
| `delegation.entries_added` | `delegationId`, `after` | Lire les nouvelles entrées |
| `delegation.entries_removed` | `delegationId`, `entries: [{kind, ref, version}]` | Effacer ces clés |
| `delegation.revoked` | `userId`, `delegationId`, `reason` | Effacer `DK` et les clés ; arrêter les workers de l'utilisateur |
| `thread.envelope_reset` | `threadId`, `userId`, `delegationId` | **Ajoutée par L03d (Q21).** Un humain a réinitialisé l'enveloppe `rt1` d'un salon créé par ce runtime. `delegationId` = délégation **active** du délégant avec laquelle reposer. Attendu : vérifier **avant de signer** (voir ci-dessous) puis `POST /e2ee/threads/:threadId/key-envelope/repose` (§4.3). Le runtime actuel ne la traite pas encore (`ApiEvent::Unknown`) |
| `user.revoked` | `userId`, `until` | Liste de révocation des tickets (02 §8). **Émis** après `delegation.revoked` (raisons et `until` : 02 §8 ; révisé après L03c, Q13 = A) |
| `runtime.unpaired` | — | 01 §9 |
| `ping` | — | Répondre `pong` |

**`thread.envelope_reset` : ce que le runtime doit faire** (le serveur n'est pas de confiance ;
`SYNCOAI_REFONTE_FEATURE.md` §14.8) : vérifier **avant de signer** qu'il a lui-même créé ce salon (registre
local des salons créés, comme les garde-fous `created_key` de 03 §10.1) et qu'il détient la clé du salon
(entrée `thread:<id>` déchiffrée de la délégation active) ; **recalculer** `commitment` depuis la clé réelle,
jamais depuis une valeur servie par l'API ; signer pour le `delegationId` de la trame. **Contrainte** : si
aucun processus du runtime ne détient plus la clé (délégation renouvelée sans l'entrée, redémarrage avant
la synchro P11), la repose attend la prochaine synchro du délégant ; l'API n'y peut rien. Le choix de
laisser un humain décider (plutôt qu'un remplacement automatique) tient à ce que l'API ne sait pas si un
client a épinglé, et qu'un runtime fautif pourrait remplacer en boucle ; la sécurité ne dépend pas de l'API :
la nouvelle enveloppe reste signée par la `csk` du runtime certifié et les clients vérifient `commitment` ;
un serveur malveillant peut seulement réinitialiser (déni de service), jamais forger.

**Compléments de L00f** : `conversation.wake.reason = "decision"` couvre aussi `plan_decision` (refus) et
`plan_result` (12 §9) ; `delegation.revoked.reason` peut valoir `autonomy_withdrawn` (12 §11.4).

- **Runtime → API** : uniquement `{ "v": 1, "type": "pong" }` et `{ "v": 1, "type": "presence", "workers": <n> }` (≤ 1 / 30 s).
- Présence : le runtime est « en ligne » tant que la connexion est ouverte (`AiRuntime.lastSeenAt`
  mis à jour), exposée aux membres (`GET /api/orgs/:orgId/ai/runtime` → `online: boolean`).
- Ping toutes les 25 s ; sans `pong` en 60 s, l'API ferme. Reconnexion du runtime : backoff
  exponentiel 1 s → 60 s avec gigue ; après reconnexion il relit `GET /delegations` et
  `GET /conversations?state=pending` (les notifications ne sont pas rejouées : elles ne sont que des
  « réveils »).

Comportement réel du flux (révisé après la vague B, 2026-11-19 ;
`synco_api/src/services/aiRuntime/runtimeStream.ts:16-31`, `:90-240`) :

- **Refus après la poignée de main** : la mise à niveau est toujours acceptée, puis la connexion est
  fermée avec le code **`4000 + statut HTTP`** du code machine et ce code en raison (`4401
  rt_sig_invalid`, `4401 rt_clock_skew`, `4404 rt_unknown`, `4403 ai_disabled`, `4429
  rt_rate_limited`, `4503 runtime_disabled`, `4400 invalid_body` pour une méthode autre que `GET`…),
  comme le WebSocket client (05 §7). Raison : sous Bun, une réponse HTTP écrite sur la socket d'une
  mise à niveau `node:http` n'est jamais acheminée ; le runtime ne verrait qu'une coupure sans cause.
- Limiteur d'échecs de mise à niveau : 30 / min par adresse client, dérivée comme Express
  (`TRUST_PROXY_HOPS`, `runtimeHttpPolicy.ts:225-244`), pour ne pas compter l'adresse du proxy.
- Fermetures en cours de connexion : **`4409 replaced`** (nouvelle connexion du même runtime),
  **`4408 pong_timeout`**, **`4401 rt_revoked`** (désappairé, après la trame `runtime.unpaired`),
  **`4403 ai_disabled`** (module IA coupé ou org bannie), **`1008 invalid_frame`** (trame binaire,
  illisible, inconnue ou mal formée).
- **Revérification périodique** : à chaque ping (25 s), l'API relit le statut du runtime, le module
  IA et le bannissement de l'org.
- Trames ≤ 4 Kio (`maxPayload`). `hello.serverTime` en secondes Unix. `pong` strict `{ v: 1, type: "pong" }` ;
  `presence` strict `{ v: 1, type: "presence", workers }` (entier 0 à 100 000), au-delà d'une par
  30 s **ignorée** (pas de fermeture).
- `lastSeenAt` écrit à l'ouverture, au plus une fois par minute sur `pong`, et à la fermeture ;
  `ai:runtime-changed` (`change: "presence"`) à l'ouverture et à la fermeture.
- `delegation.revoked.reason` ∈ raisons de 03 §8.1 (dont `expired`) ; `conversation.revoked.reason`
  ∈ `switched_to_local`, `delegation_revoked`, `delegation_expired`, `runtime_unpaired`,
  `member_left`, `session_deleted`. `conversation.wake.reason` : `inbox` pour un message, `decision`
  pour `confirm` / `answer` / `upload` / `cancel`, `keys` pour une clé arrivée.

## 7. Journaux

Ni l'API ni le runtime ne journalisent : corps des requêtes du canal, `wrap`, `mandateSignature`,
entrées, valeurs `gcm1:`, arguments ou résultats d'outils, tickets. Seuls : méthode, gabarit de route
(`/conversations/:sessionId/transcript`), `runtimeId`, code de résultat, durée, taille.

Réalisation (révisé après la vague B, 2026-11-19) : `morgan` journalise pour `/api/runtime/v1` un
gabarit où tout segment non fixe devient `:id`, sans chaîne de requête (`runtimeChannelLogPath`,
`synco_api/src/services/aiRuntime/runtimeHttpPolicy.ts:190-209`, `synco_api/src/index.ts:184`) ; les
erreurs serveur ne journalisent que nom et code de l'exception, jamais son `message` (Prisma y
recopie les valeurs ; `errorTag`, `conversationResult.ts`).

## 8. Codes d'erreur (révisé après la vague B, 2026-11-19 ; révisé après L03c, 2026-11-20)

Réponses d'erreur : `{ "error": "<code>" }`. Contrat : `synco_api/src/services/aiRuntime/runtimeAuthContract.ts:47-93`
et `conversationResult.ts` (L03).

| Code | HTTP | Sens |
|---|---|---|
| `runtime_disabled` | 503 | Module runtime de l'API non configuré (02 §2) |
| `rt_sig_missing` | 401 | En-têtes de signature absents ou mal formés |
| `rt_clock_skew` | 401 | Horodatage hors fenêtre de ±60 s |
| `rt_unknown` | 404 | Runtime inconnu (non appairé) |
| `rt_revoked` | 401 | Runtime désappairé |
| `rt_sig_invalid` | 401 | Signature invalide |
| `rt_replay` | 401 | Nonce déjà vu |
| `rt_rate_limited` | 429 | Débit du runtime (50 / s, rafale 200), ensemble de nonces du runtime plein, échecs ou lectures de corps simultanées par adresse IP, `POST /metrics` (1 / min), dépôt de boîte (20 / 10 s), push (plafond de 6 / min par conversation ; révisé après L03d) |
| `auth_invalid` | 403 | Autorisation inconnue, d'un autre runtime, ou utilisateur plus autorisé (non membre, politique, **banni de la plateforme** : révisé après L03c) |
| `auth_revoked` / `auth_expired` | 403 | Autorisation révoquée / expirée |
| `delegation_expired` / `delegation_revoked` | 403 | Délégation plus active |
| `out_of_scope` | 403 | Ressource hors de l'autorisation (autre conversation, autre org) |
| `key_not_delegated` | 403 | La clé nécessaire n'est pas dans la délégation |
| `forbidden` | 403 | Permission de l'utilisateur refusée par le service métier |
| `tool_denied_by_policy` | 403 | Outil `deny` dans `aiConfig.runtime.toolPolicy` (D5), jamais exécuté |
| `lease_conflict` | 409 | Bail détenu par un autre worker, ou `leaseEpoch` périmé |
| `rev_conflict` | 409 | `baseRev` ≠ révision courante |
| `not_runtime` | 409 | La conversation n'est plus en régime `runtime` (dépôt de boîte) |
| `gateway_not_configured` | 409 | `POST /tickets/llm` sans fournisseur `gateway` configuré |
| `invalid_body` | 400 | Corps invalide, trop gros ou lu trop lentement ; requête mal formée |
| `ai_disabled` | 403 | Module IA désactivé ou org bannie |
| `envelope_exists` | 409 | `POST /e2ee/threads/:threadId/key-envelope` ou `…/repose` : une enveloppe différente est déjà posée, ou course perdue (§4.3 ; révisé après L03c et L03d) |
| `no_default_category` | 409 | `POST /e2ee/threads` sans `categoryId` : aucune catégorie visible de la cible (§4.3 ; L03d, Q23) |
| `envelope_not_set` | 409 | Route **utilisateur** `POST /api/orgs/:orgId/ai/runtime/threads/:threadId/key-envelope/reset` : aucune enveloppe posée, ou course perdue (L03d, Q21) |
| `repose_unavailable` | 409 | Route **utilisateur** `…/key-envelope/reset` : runtime créateur désappairé, ou aucune délégation `active` non expirée du délégant vers lui ; rien n'est modifié (L03d, Q21) |
| `not_found` | 404 | Route absente de la liste fermée, ressource absente, outil inconnu ou non `server` |
| `inbox_full` | 429 | 100 éléments non consommés dans la boîte |
| `rate_limited` | 429 | Refus de débit d'un service HTTP partagé (création de salon, envoi CDN) |
| `upgrade_required` | 426 | `GET /stream` sans mise à niveau WebSocket |
| `action_not_accepted` | 403 | Outil `ask` (ou `create_thread` `ask`) appelé sans action acceptée par l'utilisateur, ou condensat différent (L00f, 12 §8.3) |
| `action_state_conflict` | 409 | Action déjà exécutée ou non `pending` (12 §7.2) |
| `autonomy_required` | 403 | Route `rt1` sous une délégation qui n'est pas `mode = auto` (12 §10.4) |
| `feature_not_allowed` | 403 | Politique d'org `autonomous_mode` (12 §11) |
| `plan_exists` | 409 | `POST …/plans` avec un `planId` déjà utilisé |
